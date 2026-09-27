/* 任务4 · SELinux 解决与规则注入
 *
 * ---------------------------------------------------------------------------
 * 这一层要解决的核心问题：**时机**，其次才是引擎
 * ---------------------------------------------------------------------------
 * 任务3 的 `boss sepolicy apply` 挂在 boot 的 post-fs-data 阶段。这在
 * enforcing 下有个绕不过去的顺序问题：
 *
 *   init 的 selinux_setup 阶段会做两件事——① 加载策略到内核 ② restorecon。
 *   file_contexts 里引用的 type 必须在①之后就已经存在，否则 init 打标签时
 *   会报 unknown type。也就是说：
 *      先有 type（策略）→ 才能打标签 → 才能有正确的域
 *   而 post-fs-data 在 selinux_setup 之后很久，此时：
 *       · /boss 已经被打成了 u:object_r:rootfs:s0（manifest 现在的写法）；
 *       · /data/adb/boss 下的文件是无标签或默认 data 标签；
 *       · live patch 即使成功，已存在进程/文件的 SID 也不会自动重算。
 *
 * 所以任务4 的正确做法是**两条路径**：
 *   路径 A（主）：早期注入。在 init 的 selinux_setup 阶段（策略加载之前）
 *                 patch 策略文件 → 让 init 加载我们已经打好补丁的策略。
 *                 → `boss selinux patch <in> <out>` + `boss selinux load <out>`
 *                 这是 su 侧 v0.2 的 cmd_stage2 在收到 selinux_setup 时要调的。
 *   路径 B（辅）：运行时注入。/data 已挂载后的模块规则（sepolicy.rule）。
 *                 → `boss selinux live [rulefile]` / `boss selinux pending`
 *
 * 引擎后端（按可靠性排序）：
 *   1. libsepol 内置后端  —— 需 vendor libsepol（BOSS_HAVE_SEPOL），最快最准
 *   2. 外部引擎           —— magiskpolicy / sepolicy-inject / supolicy
 *   3. 无引擎             —— 规则进 pending 队列，返回 2，绝不假装成功
 *
 * ---------------------------------------------------------------------------
 * 为什么策略内容内嵌（boss_rules.h）
 * ---------------------------------------------------------------------------
 * 早期注入时 /data 还没挂载，磁盘上的 policy/boss.rule 读不到。
 * 所以策略内容由 tools/gen_rules_h.py 编进二进制。
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "boss.h"
#include "boss_rules.h"

#define SELINUX_FS_DIR       "/sys/fs/selinux"
#define SELINUX_ENFORCE      SELINUX_FS_DIR "/enforce"
#define SELINUX_POLICY       SELINUX_FS_DIR "/policy"
#define SELINUX_LOAD         SELINUX_FS_DIR "/load"
#define SELINUX_POLICYVERS   SELINUX_FS_DIR "/policyvers"

#define BOSS_PENDING_FILE    BOSS_DIR "/sepolicy.pending"
#define BOSS_PATCHED_POLICY  BOSS_DIR "/sepolicy.patched"

/* 单批规则数：一次 exec 传太多规则会撞 ARG_MAX，也会让"哪条失败"定位困难 */
#define RULES_PER_BATCH      64
#define MAX_RULE_LEN         512
#define CMD_CAP              (64 * 1024)

/* 返回码（与任务3 的 sepolicy 保持同一套语义，调用方不用改判断） */
#define RC_OK        0   /* 全部应用 */
#define RC_FAIL      1   /* 致命错误：读不了策略 / 引擎全挂且落不了盘 */
#define RC_NO_ENGINE 2   /* 没有可用引擎，规则已进 pending（不是成功） */
#define RC_PARTIAL   3   /* 部分应用：有规则被跳过或拒绝（尽力而为的正常结果） */

struct inject_result {
    int applied;   /* 确认应用成功 */
    int skipped;   /* 目标 type/class 不存在等"可容忍"失败 */
    int failed;    /* 真正的错误 */
};

/* ---- libsepol 内置后端（vendor 之后才有） ----
 * src/sepol_backend.c 由 tools/vendor-sepol.sh 拉取 libsepol 后编译。
 * 没有 vendor 时这里退化成"不支持"，引擎自动走外部引擎后端。 */
#ifdef BOSS_HAVE_SEPOL
int sepol_builtin_apply(const char *in, const char *out, const char **rules,
                        int n, int live, struct inject_result *res);
#else
static int sepol_builtin_apply(const char *in, const char *out, const char **rules,
                               int n, int live, struct inject_result *res)
{
    (void)in; (void)out; (void)rules; (void)n; (void)live; (void)res;
    return -1;   /* 未编译进本二进制 */
}
#endif

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

static int read_int_file(const char *path, int *out)
{
    char buf[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return -1;
    buf[r] = '\0';
    *out = atoi(buf);
    return 0;
}

/* SELinux 是否被编译进内核：/sys/fs/selinux 目录存在即为有 */
static int selinux_available(void)
{
    struct stat st;
    return stat(SELINUX_FS_DIR, &st) == 0;
}

/* 返回 1 enforcing / 0 permissive / -1 不可知 */
static int selinux_enforcing(void)
{
    int v = 0;
    if (read_int_file(SELINUX_ENFORCE, &v) != 0) return -1;
    return v ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* 策略源定位                                                          */
/* ------------------------------------------------------------------ */

/* 磁盘上的候选（早期注入用：要能读成文件、patch 后写成文件） */
static const char *file_sources[] = {
    "/system/etc/selinux/precompiled_sepolicy",   /* Android 9+ 主流 */
    "/vendor/etc/selinux/precompiled_sepolicy",   /* vendor 预编译 */
    "/sepolicy",                                  /* Android 8 及更早 */
    "/system/etc/selinux/sepolicy",
    "/data/adb/boss/sepolicy.patched",            /* 我们上一轮 patch 的产物 */
    NULL
};

/* 运行时策略（live patch 用） */
static const char *live_sources[] = {
    SELINUX_POLICY,
    NULL
};

static const char *find_policy(int live)
{
    const char **cands = live ? live_sources : file_sources;
    for (int i = 0; cands[i]; i++) {
        if (access(cands[i], R_OK) == 0) return cands[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 外部引擎                                                            */
/* ------------------------------------------------------------------ */

/* 顺序即优先级：BOSS 自己的 bin 最先（App 释放），其次是已有的 root 生态 */
static const char *engine_paths[] = {
    "/data/adb/boss/bin/magiskpolicy",
    "/data/adb/magisk/magiskpolicy",
    "/data/adb/boss/bin/sepolicy-inject",
    "/data/adb/boss/bin/supolicy",
    "/sbin/magiskpolicy",
    NULL
};

static const char *find_engine(void)
{
    for (int i = 0; engine_paths[i]; i++) {
        if (access(engine_paths[i], X_OK) == 0) return engine_paths[i];
    }
    return NULL;
}

static int is_magisk_style(const char *engine)
{
    return strstr(engine, "magiskpolicy") != NULL;
}
static int is_inject_style(const char *engine)
{
    return strstr(engine, "sepolicy-inject") != NULL;
}

/* 单引号包裹 + 转义内部的单引号。
 * 规则来自文件（模块作者写的），不能假设它干净——这里不做转义就是命令注入。 */
static size_t shquote(char *dst, size_t off, size_t cap, const char *s)
{
    size_t i = off;
    if (i + 1 >= cap) return i;
    dst[i++] = '\'';
    for (const char *p = s; *p && i + 3 < cap; p++) {
        if (*p == '\'') {
            memcpy(dst + i, "'\\''", 4);
            i += 4;
        } else {
            dst[i++] = *p;
        }
    }
    if (i + 1 < cap) dst[i++] = '\'';
    if (i < cap) dst[i] = '\0';
    return i;
}

/* 拼一条外部引擎命令。返回 0 表示拼好了。 */
static int build_cmd(const char *engine, const char **rules, int n,
                     const char *in, const char *out, int live,
                     char *cmd, size_t cap)
{
    size_t o = 0;
    o += (size_t)snprintf(cmd + o, cap - o, "%s", engine);

    if (is_magisk_style(engine)) {
        /* magiskpolicy：--live 与 --load/--save 互斥；
         * 不带 --live 时默认从 /sys/fs/selinux/policy 读。
         * in/out 也走 shquote：命令行参数不该被当 shell 语法解释。 */
        if (live) {
            o += (size_t)snprintf(cmd + o, cap - o, " --live");
        } else {
            if (in) {
                o += (size_t)snprintf(cmd + o, cap - o, " --load ");
                o = shquote(cmd, o, cap, in);
            }
            if (out) {
                o += (size_t)snprintf(cmd + o, cap - o, " --save ");
                o = shquote(cmd, o, cap, out);
            }
        }
        for (int i = 0; i < n && o + MAX_RULE_LEN + 4 < cap; i++) {
            cmd[o++] = ' ';
            o = shquote(cmd, o, cap, rules[i]);
        }
        return 0;
    }

    if (is_inject_style(engine)) {
        /* sepolicy-inject 一次只能处理一条 allow/deny，且只认 -s/-t/-c/-p */
        if (n != 1) return -1;
        char s[128] = { 0 }, t[128] = { 0 }, c[128] = { 0 };
        if (sscanf(rules[0], "allow %127s %127[^:]:%127s", s, t, c) != 3 &&
            sscanf(rules[0], "deny %127s %127[^:]:%127s", s, t, c) != 3)
            return -1;
        /* 权限串在 class 之后，sscanf 的 %127s 已经截断到 class，
         * 所以这里把整条规则的权限部分单独取出来 */
        const char *perm = strchr(rules[0], ':');
        if (perm) perm = strchr(perm + 1, ' ');
        const char *p = perm ? perm + 1 : "*";
        char tgt[128];
        snprintf(tgt, sizeof(tgt), "%s", t);
        char *colon = strchr(tgt, ':');
        if (colon) *colon = '\0';
        snprintf(cmd + o, cap - o, "%s -s %s -t %s -c %s -p %s -P %s%s%s",
                 engine, s, tgt, c, p,
                 in ? in : SELINUX_POLICY,
                 out ? " -o " : "", out ? out : "");
        return 0;
    }

    /* supolicy：只用于 live，逐条 */
    if (!live) return -1;
    o += (size_t)snprintf(cmd + o, cap - o, " --live");
    for (int i = 0; i < n && o + MAX_RULE_LEN + 4 < cap; i++) {
        cmd[o++] = ' ';
        o = shquote(cmd, o, cap, rules[i]);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 规则注入                                                            */
/* ------------------------------------------------------------------ */

/*
 * 尽力而为语义（这是任务4 最重要的一条设计决定）：
 *
 * Android 各版本/各厂商的 type、class、perm 集合都不一样。同一份规则
 * 在 A 机型上全部生效，在 B 机型上可能有 30 条"目标不存在"。
 * 如果因此判定整份策略失败，BOSS 就起不来；所以：
 *   · 批量尝试 → 全过最好（一次 exec，快）
 *   · 批量失败 → 逐条重试，把"哪些规则没生效"定位出来
 *   · 逐条里的"目标不存在/不支持"记为 skipped，不记为 failed
 * 这样 post-fs-data 阶段既不会因为一条规则失败而中断开机，
 * 也不会假装全部成功——调用方能从返回值与日志里看到真实情况。
 */
static int inject_rules(const char *in, const char *out, int live,
                        const char **rules, int n, struct inject_result *res)
{
    memset(res, 0, sizeof(*res));

    /* 1) 内置 libsepol 后端优先：不 fork、不写临时文件，快且准 */
    if (sepol_builtin_apply(in, out, rules, n, live, res) == 0)
        return RC_OK;

    /* 2) 外部引擎 */
    const char *engine = find_engine();
    if (!engine) return RC_NO_ENGINE;

    char *cmd = malloc(CMD_CAP);
    if (!cmd) return RC_FAIL;

    /* sepolicy-inject 一次只能吃一条，步长就是 1 */
    int step = is_inject_style(engine) ? 1 : RULES_PER_BATCH;

    for (int start = 0; start < n; start += step) {
        int cnt = n - start;
        if (cnt > step) cnt = step;

        if (build_cmd(engine, rules + start, cnt, in, out, live, cmd, CMD_CAP) != 0) {
            res->skipped += cnt;
            continue;
        }
        int rc = system(cmd);
        if (rc == 0) {
            res->applied += cnt;
            continue;
        }
        if (cnt == 1) {
            /* 区分"可容忍"与"真错误"：未知 type/class 是前者，
             * 引擎本身跑不起来（126/127）是后者 */
            int st = (rc == -1) ? 127 : WEXITSTATUS(rc);
            if (rc == -1 || st == 126 || st == 127) res->failed++;
            else res->skipped++;
            fprintf(stderr, "selinux: 规则未生效: %s\n", rules[start]);
            continue;
        }
        /* 批量失败 → 拆成逐条，定位到底哪条不行 */
        for (int i = 0; i < cnt; i++) {
            if (build_cmd(engine, rules + start + i, 1, in, out, live,
                          cmd, CMD_CAP) != 0) {
                res->skipped++;
                continue;
            }
            int rc1 = system(cmd);
            if (rc1 == 0) {
                res->applied++;
            } else {
                int st = (rc1 == -1) ? 127 : WEXITSTATUS(rc1);
                if (rc1 == -1 || st == 126 || st == 127) res->failed++;
                else res->skipped++;
                fprintf(stderr, "selinux: 规则未生效: %s\n", rules[start + i]);
            }
        }
    }

    free(cmd);

    if (res->failed > 0) return RC_FAIL;
    if (res->skipped > 0) return RC_PARTIAL;
    return RC_OK;
}

/* 把规则落进 pending 队列：这是"没做成"的明确表达，不是成功 */
static int queue_pending(const char **rules, int n)
{
    FILE *fp = fopen(BOSS_PENDING_FILE, "ae");
    if (!fp) return -1;
    for (int i = 0; i < n; i++) fprintf(fp, "%s\n", rules[i]);
    fclose(fp);
    chmod(BOSS_PENDING_FILE, 0600);
    return 0;
}

/* 读规则文件（与任务3 的 sepolicy.c 同样的规范化口径） */
static char **parse_rule_file(const char *file, int *count)
{
    FILE *fp = fopen(file, "re");
    if (!fp) return NULL;

    static const char *ops[] = { "allow", "deny", "type", "typeattribute",
                                 "permissive", "type_transition", "type_change",
                                 "dontaudit", "auditallow", NULL };
    char **out = calloc(BOSS_BUILTIN_RULES_N + 4096, sizeof(char *));
    if (!out) { fclose(fp); return NULL; }

    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), fp) && n < 4096) {
        /* 去注释 + 压缩空白 + 去尾分号 */
        char norm[MAX_RULE_LEN];
        size_t j = 0;
        for (size_t i = 0; line[i] && line[i] != '#' && line[i] != '\n' && line[i] != '\r'; i++) {
            char c = line[i];
            int sp = (c == ' ' || c == '\t' || c == '\r');
            if (!sp || (j > 0 && norm[j - 1] != ' ')) {
                if (j + 1 < sizeof(norm)) norm[j++] = sp ? ' ' : c;
            }
        }
        while (j > 0 && (norm[j - 1] == ';' || norm[j - 1] == ' ')) j--;
        norm[j] = '\0';
        if (j == 0) continue;

        int known = 0;
        for (int k = 0; ops[k]; k++) {
            size_t l = strlen(ops[k]);
            if (!strncmp(norm, ops[k], l) && (norm[l] == ' ' || norm[l] == '\0')) {
                known = 1; break;
            }
        }
        if (!known) {
            fprintf(stderr, "selinux: 无法识别的规则，已跳过: %s\n", norm);
            continue;
        }
        out[n] = strdup(norm);
        if (!out[n]) break;
        n++;
    }
    fclose(fp);
    *count = n;
    return out;
}

static void free_rules(char **rules, int n)
{
    for (int i = 0; i < n; i++) free(rules[i]);
    free(rules);
}

/* ------------------------------------------------------------------ */
/* 打标签：boss selinux label                                          */
/* ------------------------------------------------------------------ */

/*
 * 直接写 security.selinux xattr，不用 libselinux。
 * 理由和接力须知 4.4 一样：Android 静态二进制里 dlopen 不可用，
 * libselinux 的 setfilecon 拿不到；而 setxattr 是系统调用，随时可用。
 */
static int set_label(const char *path, const char *ctx)
{
    if (setxattr(path, "security.selinux", ctx, strlen(ctx) + 1, 0) != 0) {
        /* 内核拒绝陌生 context 会返回 EINVAL/ENOTSUP：这类要报出来，
         * 因为往往意味着策略里还没定义这个 type（顺序红线的典型症状） */
        fprintf(stderr, "selinux: 给 %s 打标签失败: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int label_tree(const char *root, const char *ctx, int *done, int *fail)
{
    if (set_label(root, ctx) == 0) (*done)++; else (*fail)++;

    DIR *d = opendir(root);
    if (!d) return 0;      /* 不是目录就到这儿 */

    struct dirent *e;
    char path[4096];
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        int len = snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        if (len < 0 || (size_t)len >= sizeof(path)) continue;

        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            /* 符号链接要用 lsetxattr，否则会跟到目标上去 */
            if (lsetxattr(path, "security.selinux", ctx, strlen(ctx) + 1, 0) == 0) (*done)++;
            else (*fail)++;
            continue;
        }
        label_tree(path, ctx, done, fail);
    }
    closedir(d);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 命令实现                                                            */
/* ------------------------------------------------------------------ */

static int cmd_status(void)
{
    printf("selinux: %s\n", selinux_available() ? "内核支持" : "未挂载 selinuxfs（无 SELinux）");

    int enf = selinux_enforcing();
    printf("mode:    %s\n", enf < 0 ? "(读不到 enforce)" : (enf ? "enforcing" : "permissive"));

    int vers = 0;
    if (read_int_file(SELINUX_POLICYVERS, &vers) == 0)
        printf("policy version: %d\n", vers);

    const char *f = find_policy(0);
    const char *l = find_policy(1);
    printf("policy(file): %s\n", f ? f : "(未找到)");
    printf("policy(live): %s\n", l ? l : "(未找到)");

    const char *e = find_engine();
#ifdef BOSS_HAVE_SEPOL
    printf("engine:  libsepol 内置后端（优先）\n");
#else
    printf("engine:  %s\n", e ? e : "(无内置 libsepol，也无外部引擎)");
#endif
    if (e) printf("engine(外部可用): %s\n", e);

    printf("builtin rules: %u 条（BOSS_RULES_VERSION %d）\n",
           (unsigned)BOSS_BUILTIN_RULES_N, BOSS_RULES_VERSION);

    struct stat st;
    printf("pending: %s\n",
           stat(BOSS_PENDING_FILE, &st) == 0 ? BOSS_PENDING_FILE : "(空)");
    return 0;
}

static int cmd_source(int argc, char **argv)
{
    int live = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--live")) live = 1;
    }
    const char *p = find_policy(live);
    if (!p) {
        fprintf(stderr, "selinux: 找不到%s策略源\n", live ? "运行时" : "文件");
        return 1;
    }
    printf("%s\n", p);
    return 0;
}

static int cmd_rules(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--count")) {
            printf("%u\n", (unsigned)BOSS_BUILTIN_RULES_N);
            return 0;
        }
    }
    for (size_t i = 0; i < BOSS_BUILTIN_RULES_N; i++)
        printf("%s\n", boss_builtin_rules[i]);
    return 0;
}

/* boss selinux patch <in> <out> [rulefile]
 * 早期注入用：读策略文件 → 注入 → 写出。不碰内核。 */
static int cmd_patch(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "用法: boss selinux patch <策略输入> <输出> [额外规则文件]\n");
        return 1;
    }
    const char *in = argv[1], *out = argv[2];
    const char *extra = argc >= 4 ? argv[3] : NULL;

    if (access(in, R_OK) != 0) {
        fprintf(stderr, "selinux: 读不了策略文件 %s\n", in);
        return RC_FAIL;
    }

    /* 内嵌规则 + 可选额外规则文件 */
    const char **rules = calloc(BOSS_BUILTIN_RULES_N + 4096, sizeof(char *));
    if (!rules) return RC_FAIL;
    int n = 0;
    for (size_t i = 0; i < BOSS_BUILTIN_RULES_N; i++)
        rules[n++] = boss_builtin_rules[i];

    char **ex = NULL;
    int exn = 0;
    if (extra) {
        ex = parse_rule_file(extra, &exn);
        if (!ex) {
            fprintf(stderr, "selinux: 读不了规则文件 %s\n", extra);
            free(rules);
            return RC_FAIL;
        }
        for (int i = 0; i < exn; i++) rules[n++] = ex[i];
    }

    struct inject_result res;
    int rc = inject_rules(in, out, 0, rules, n, &res);

    printf("selinux: patch %d 条 → 应用 %d / 跳过 %d / 失败 %d\n",
           n, res.applied, res.skipped, res.failed);

    if (rc == RC_NO_ENGINE) {
        /* 内置 + 额外的都要落盘，只存内置会静默丢掉模块的规则 */
        if (queue_pending(rules, n) == 0)
            fprintf(stderr, "selinux: 无注入引擎，%d 条规则已存入 %s\n", n, BOSS_PENDING_FILE);
        rc = RC_NO_ENGINE;
    }

    if (ex) free_rules(ex, exn);
    free(rules);
    return rc;
}

/* boss selinux load <file>
 * 把 patch 好的策略写进内核。只在早期注入路径里用（selinux_setup 阶段）。
 * 之后 exec 真实 init 的 second_stage——不能再让它跑 selinux_setup，
 * 否则它会用原始策略覆盖掉我们的补丁。 */
static int cmd_load(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "用法: boss selinux load <patched-policy>\n");
        return 1;
    }
    const char *file = argv[1];
    int in = open(file, O_RDONLY | O_CLOEXEC);
    if (in < 0) {
        fprintf(stderr, "selinux: 读不了 %s: %s\n", file, strerror(errno));
        return RC_FAIL;
    }
    int out = open(SELINUX_LOAD, O_WRONLY | O_CLOEXEC);
    if (out < 0) {
        fprintf(stderr, "selinux: 写不了 %s: %s（内核可能禁止重载策略）\n",
                SELINUX_LOAD, strerror(errno));
        close(in);
        return RC_FAIL;
    }

    char buf[65536];
    ssize_t r;
    int rc = RC_OK;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        if (boss_write_full(out, buf, (size_t)r) < 0) {
            fprintf(stderr, "selinux: 写入内核失败: %s\n", strerror(errno));
            rc = RC_FAIL;
            break;
        }
    }
    close(in);
    close(out);
    if (rc == RC_OK) printf("selinux: 已加载 %s\n", file);
    return rc;
}

/* boss selinux live [rulefile]
 * 运行时注入：从内核当前策略读 → 注入 → 写回内核。
 * 没有规则文件时：消费 pending 队列（任务3 攒下的模块规则）。 */
static int cmd_live(int argc, char **argv)
{
    const char *file = argc >= 2 ? argv[1] : NULL;

    const char **rules = NULL;
    int n = 0;
    char **parsed = NULL;

    if (file) {
        parsed = parse_rule_file(file, &n);
        if (!parsed) {
            fprintf(stderr, "selinux: 读不了 %s\n", file);
            return RC_FAIL;
        }
        rules = (const char **)parsed;
    } else {
        parsed = parse_rule_file(BOSS_PENDING_FILE, &n);
        if (!parsed || n == 0) {
            /* 没有 pending 就用内置规则集兜底：让 BOSS 至少在自己的域里。
             * 注意先 free 再改 n——n 是 free_rules 的长度依据，顺序反了会越界 */
            if (parsed) free_rules(parsed, n);
            parsed = NULL;
            n = (int)BOSS_BUILTIN_RULES_N;
            rules = (const char **)boss_builtin_rules;
        } else {
            rules = (const char **)parsed;
        }
    }

    struct inject_result res;
    int rc = inject_rules(NULL, NULL, 1, rules, n, &res);
    printf("selinux: live %d 条 → 应用 %d / 跳过 %d / 失败 %d\n",
           n, res.applied, res.skipped, res.failed);

    if (rc == RC_NO_ENGINE) {
        if (queue_pending(rules, n) == 0)
            fprintf(stderr, "selinux: 无注入引擎，规则已存入 %s\n", BOSS_PENDING_FILE);
    } else if (rc != RC_FAIL && file == NULL) {
        /* 消费成功才清队列：清早了会丢规则 */
        unlink(BOSS_PENDING_FILE);
    }

    if (parsed) free_rules(parsed, n);
    return rc;
}

/* boss selinux pending —— 只消费队列，不做别的 */
static int cmd_pending(void)
{
    int n = 0;
    char **rules = parse_rule_file(BOSS_PENDING_FILE, &n);
    if (!rules || n == 0) {
        printf("selinux: pending 为空\n");
        if (rules) free_rules(rules, n);
        return 0;
    }

    struct inject_result res;
    int rc = inject_rules(NULL, NULL, 1, (const char **)rules, n, &res);
    printf("selinux: pending %d 条 → 应用 %d / 跳过 %d / 失败 %d\n",
           n, res.applied, res.skipped, res.failed);

    if (rc == RC_NO_ENGINE) {
        /* 明确返回 2：一条都没应用成功就是没做成，不能让调用方以为过了 */
        fprintf(stderr, "selinux: 仍无注入引擎，%d 条规则留在 %s\n", n, BOSS_PENDING_FILE);
        free_rules(rules, n);
        return RC_NO_ENGINE;
    }
    if (rc != RC_FAIL) unlink(BOSS_PENDING_FILE);
    free_rules(rules, n);
    return rc == RC_FAIL ? RC_FAIL : 0;
}

/* boss selinux label [path] [ctx]
 * 给 /data/adb/boss 递归打标签。/data 挂载之后才能跑。 */
static int cmd_label(int argc, char **argv)
{
    const char *path = argc >= 2 ? argv[1] : BOSS_DIR;
    const char *ctx  = argc >= 3 ? argv[2] : "u:object_r:boss_file:s0";

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "selinux: %s 不存在\n", path);
        return 1;
    }
    int done = 0, fail = 0;
    label_tree(path, ctx, &done, &fail);
    printf("selinux: 打标签 %s → %s：成功 %d / 失败 %d\n", path, ctx, done, fail);
    return fail > 0 ? RC_PARTIAL : RC_OK;
}

/* 给任务3 的 sepolicy 工具用的注入入口（声明见 boss.h）。
 *
 * 为什么要有它：sepolicy 是"工具"，负责解析规则文件；真正改策略的是任务4。
 * 两边分工保持在一条线上——sepolicy 只管把规范化后的规则递进来，
 * 引擎选择、尽力而为语义、pending 降级都在本文件里，调用方不用关心。
 * 返回值与 sepolicy 原有语义一致（2 = 无引擎、规则已进 pending）。 */
/* boss selinux setup —— 早期注入的一键入口
 *
 * 这是"时机"问题的落地点，供 su 侧 v0.2 在 cmd_stage2 收到
 * `selinux_setup` 参数时调用（init 加载策略之前的那一次执行）：
 *
 *   1. 定位磁盘上的策略源（precompiled_sepolicy 等）
 *   2. 注入内置规则集，patch 成一份新策略
 *   3. 把 patch 后的策略写进内核
 *
 * ⚠️ 调用方随后 exec 真实 init 时**必须传 second_stage，不能再传 selinux_setup**。
 *    否则 init 会拿原始策略再加载一次，把我们的补丁整个盖掉——
 *    症状是"注入明明成功了但 BOSS 仍在 init 域里"，极难排查。
 *
 * patch 产物放 /dev：早期 /data 还没解密挂载，只有 tmpfs 可写。
 */
static int cmd_setup(void)
{
    const char *src = find_policy(0);
    if (!src) {
        fprintf(stderr, "selinux: 找不到策略源，放弃早期注入（等 /data 挂载后走运行时注入）\n");
        return RC_FAIL;
    }

    const char *out = "/dev/sepolicy.patched";
    struct inject_result res;
    int rc = inject_rules(src, out, 0, (const char **)boss_builtin_rules,
                          (int)BOSS_BUILTIN_RULES_N, &res);
    boss_log_line("selinux: setup src=%s applied=%d skipped=%d failed=%d rc=%d",
                  src, res.applied, res.skipped, res.failed, rc);

    if (rc == RC_NO_ENGINE) {
        if (queue_pending((const char **)boss_builtin_rules,
                          (int)BOSS_BUILTIN_RULES_N) == 0)
            fprintf(stderr, "selinux: 无注入引擎，%u 条规则已存入 %s\n",
                    (unsigned)BOSS_BUILTIN_RULES_N, BOSS_PENDING_FILE);
        return RC_NO_ENGINE;
    }
    if (rc == RC_FAIL) return RC_FAIL;

    char *largv[] = { (char *)"load", (char *)out, NULL };
    int rc2 = cmd_load(2, largv);
    if (rc2 == 0)
        printf("selinux: 早期注入完成（%s → %s → 内核）\n", src, out);
    return rc2;
}

int boss_selinux_inject(const char *in, const char *out, int live,
                        const char **rules, int n)
{
    struct inject_result res;
    int rc = inject_rules(in, out, live, rules, n, &res);
    boss_log_line("selinux: inject n=%d applied=%d skipped=%d failed=%d rc=%d",
                  n, res.applied, res.skipped, res.failed, rc);
    if (rc == RC_NO_ENGINE) {
        if (queue_pending(rules, n) == 0)
            fprintf(stderr, "selinux: 无注入引擎，%d 条规则已存入 %s\n",
                    n, BOSS_PENDING_FILE);
    }
    return rc;
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss selinux <命令>\n"
        "  status                 显示 enforcing 状态、策略源、引擎、内嵌规则数\n"
        "  source [--live]        定位策略源（默认找磁盘文件，--live 找内核策略）\n"
        "  rules [--count]        打印内嵌的 BOSS 规则集\n"
        "  patch <in> <out> [规则文件]   离线注入：读策略→加规则→写文件（早期注入用）\n"
        "  setup                  早期注入一键：定位策略→注入→写进内核（selinux_setup 阶段）\n"
        "  load  <file>           把 patch 好的策略写进内核（selinux_setup 阶段用）\n"
        "  live  [规则文件]       运行时注入；不给文件则消费 pending 队列\n"
        "  pending                只消费 pending 队列\n"
        "  label [path] [ctx]     递归打标签（默认 " BOSS_DIR " → boss_file）\n"
        "\n"
        "返回码：0 全部应用 / 2 无引擎（规则进了 pending，不是成功）/\n"
        "        3 部分应用（有规则被跳过） / 1 失败\n");
}

int boss_selinux_main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "status"))  return cmd_status();
    if (!strcmp(cmd, "source"))  return cmd_source(argc - 1, argv + 1);
    if (!strcmp(cmd, "rules"))   return cmd_rules(argc - 1, argv + 1);
    if (!strcmp(cmd, "patch"))   return cmd_patch(argc - 1, argv + 1);
    if (!strcmp(cmd, "setup"))   return cmd_setup();
    if (!strcmp(cmd, "load"))    return cmd_load(argc - 1, argv + 1);
    if (!strcmp(cmd, "live"))    return cmd_live(argc - 1, argv + 1);
    if (!strcmp(cmd, "pending")) return cmd_pending();
    if (!strcmp(cmd, "label"))   return cmd_label(argc - 1, argv + 1);

    usage();
    return 1;
}
