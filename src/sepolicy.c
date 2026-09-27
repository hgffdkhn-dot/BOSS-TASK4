/* C1 · sepolicy 补丁工具
 *
 * 定位：这是**工具**，不是策略。任务4（SELinux）用它来改策略，
 * 策略内容本身不归我们定义（见 docs/SELINUX-REQUIREMENTS.md）。
 *
 * 提供三件事：
 *   1. 解析规则文件（模块里的 sepolicy.rule），规范化成一条条规则
 *   2. 定位当前系统的策略文件（/sys/fs/selinux/policy 等）
 *   3. 把规则应用上去：优先调用现成的注入引擎（magiskpolicy / sepolicy-inject），
 *      没有引擎时把规则落进待应用队列，绝不假装成功
 *
 * 为什么不自研 policydb 二进制重写：完整反序列化 + 重排 avtab/条件表达式
 * 是 libsepol 的活（几千行，且高度依赖 policy 版本），交出一个没在真机
 * 上验过的二进制改写器，比没有更危险。工具层的正确做法是把"输入规范化 +
 * 可靠执行 + 明确失败"做到位。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boss.h"

#define MAX_RULE   2048
#define MAX_RULES  4096

/* Magisk 风格的规则文件语法（我们完全兼容它，模块生态直接可用）：
 *   allow source target:class perm;
 *   deny  source target:class perm;
 *   type name [attribute]
 *   typeattribute name attr
 *   permissive domain
 *   type_transition source target:class default
 * 行内 '#' 之后是注释，';' 结尾可有可无。
 */
struct rule {
    char text[MAX_RULE];
};

static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* 去掉注释、两端空白、行尾分号；空行跳过 */
static int normalize_line(const char *in, char *out, size_t n)
{
    size_t i = 0, j = 0;
    while (in[i] && in[i] != '#' && in[i] != '\n' && in[i] != '\r') {
        if (!is_space(in[i]) || (j > 0 && !is_space(out[j - 1]))) {
            if (j + 1 < n) out[j++] = in[i];
        }
        i++;
    }
    out[j] = '\0';
    /* 行尾分号去掉（规则文件里可有可无），空白与 CR 一并清掉 */
    while (j > 0 && (out[j - 1] == ';' || is_space(out[j - 1]))) out[--j] = '\0';
    return j > 0;
}

static const char *op_of(const char *r)
{
    static const char *ops[] = { "allow", "deny", "type", "typeattribute",
                                 "permissive", "type_transition", "type_change",
                                 "dontaudit", "auditallow", NULL };
    for (int i = 0; ops[i]; i++) {
        size_t l = strlen(ops[i]);
        if (!strncmp(r, ops[i], l) && (r[l] == ' ' || r[l] == '\0')) return ops[i];
    }
    return NULL;
}

/* 规则文件 → 规范化规则数组 */
static int parse_rules(const char *file, struct rule **out)
{
    FILE *fp = fopen(file, "re");
    if (!fp) return -1;
    struct rule *rs = calloc(MAX_RULES, sizeof(struct rule));
    if (!rs) { fclose(fp); return -1; }

    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), fp) && n < MAX_RULES) {
        char norm[MAX_RULE];
        if (!normalize_line(line, norm, sizeof(norm))) continue;
        if (!op_of(norm)) {
            fprintf(stderr, "sepolicy: 无法识别的规则，已跳过: %s\n", norm);
            continue;
        }
        snprintf(rs[n].text, sizeof(rs[n].text), "%s", norm);
        n++;
    }
    fclose(fp);
    *out = rs;
    return n;
}

/* 引擎探测：按可靠性排序 */
static const char *engines[] = {
    "/data/adb/boss/bin/magiskpolicy",
    "/data/adb/magisk/magiskpolicy",
    "/data/adb/boss/bin/sepolicy-inject",
    "/data/adb/boss/bin/supolicy",
    NULL
};

static const char *find_engine(void)
{
    for (int i = 0; engines[i]; i++) {
        if (access(engines[i], X_OK) == 0) return engines[i];
    }
    return NULL;
}

/* 任务4 接入后，真正的注入不再由本文件拼命令完成——
 * 引擎选择、尽力而为语义、无引擎时的 pending 降级都收敛在 src/selinux.c 的
 * boss_selinux_inject() 里。本文件只负责它擅长的两件事：解析规范化 + 说明白。
 * 这里保留 find_engine 只为了 cmd_info 能显示"当前有没有引擎可用"。 */

static int cmd_info(void)
{
    static const char *cands[] = {
        "/sys/fs/selinux/policy",
        "/sepolicy",
        "/vendor/etc/selinux/precompiled_sepolicy",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        struct stat st;
        if (stat(cands[i], &st) != 0) continue;
        int fd = open(cands[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        uint32_t magic = 0;
        ssize_t r = read(fd, &magic, sizeof(magic));
        close(fd);
        printf("%-48s %8ld bytes  magic=0x%08x%s\n", cands[i], (long)st.st_size,
               magic, (r == 4 && magic == 0xf97cff8cu) ? " (SELinux policy)" : "");
    }
    const char *e = find_engine();
    printf("engine: %s\n", e ? e : "(未找到注入引擎，规则将进入待应用队列)");
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss sepolicy <命令>\n"
        "  check <file>       解析规则文件并打印规范化结果\n"
        "  apply  <file>      应用规则（--print 只看命令）\n"
        "  info               定位策略文件与注入引擎\n");
}

int boss_sepolicy_main(int argc, char **argv)
{
    /* argv[0] 是 applet 名（"sepolicy"），子命令从 argv[1] 取 */
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "info")) return cmd_info();

    if (!strcmp(cmd, "check") || !strcmp(cmd, "apply")) {
        if (argc < 3) { usage(); return 1; }
        const char *file = argv[2];
        int dry = !strcmp(cmd, "check");
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--print")) dry = 1;
        }

        struct rule *rs = NULL;
        int n = parse_rules(file, &rs);
        if (n < 0) { fprintf(stderr, "sepolicy: 读不了 %s: %s\n", file, strerror(errno)); return 1; }

        if (dry) {
            for (int i = 0; i < n; i++) printf("%s\n", rs[i].text);
            free(rs);
            return 0;
        }

        if (geteuid() != 0) {
            fprintf(stderr, "sepolicy: 应用策略需要 root 权限（当前 euid=%u）\n",
                    (unsigned)geteuid());
            free(rs);
            return 1;
        }

        /* 注入统一交给任务4（内置 libsepol → 外部引擎 → pending 三级降级）。
         * sepolicy 自己不再拼命令，避免两处各写一套引擎适配逻辑。 */
        const char **vec = calloc((size_t)(n > 0 ? n : 1), sizeof(char *));
        if (!vec) { free(rs); return 1; }
        for (int i = 0; i < n; i++) vec[i] = rs[i].text;

        int rc = boss_selinux_inject(NULL, NULL, 1, vec, n);
        free(vec);
        free(rs);

        /* 语义保持不变，boot.c 的 apply_module_rules 依赖这三个值：
         *   2 = 无引擎，规则已进 pending（不是成功，但不该中断开机）
         *   3 = 部分应用（尽力而为的正常结果，同样不该中断开机）
         *   1 = 真正的失败 */
        if (rc == 2) return 2;
        return rc == 1 ? 1 : 0;
    }

    usage();
    return 1;
}
