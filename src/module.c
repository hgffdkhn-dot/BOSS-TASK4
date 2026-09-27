/* B2 · 模块 / overlay 挂载   +   D1 · 关键文件格式约定
 *
 * 目标效果很朴素：把模块的 $MODPATH/system 递归合并进真实 /system——
 * 已有文件被替换，新文件被添加，/system 分区一个字节都不改。
 *
 * 技术选型：先做 Magic Mount（bind mount + tmpfs），不做 overlayfs 首发。
 *   理由：BOSS 主打日用，兼容性优先；Magic Mount 能直接吃 Magisk 模块生态；
 *   overlayfs 依赖 CONFIG_OVERLAY_FS 且 4.19+ 需要 xattr 递归补丁，
 *   部分设备直接不支持。等挂载逻辑稳定后再加 overlayfs 后端。
 *
 * Magic Mount 的关键难点：把 tmpfs 挂到目标目录后，目录里的原始内容就被
 * 遮盖了，再也 bind 不回来。解法（与 Magisk 同源）：先把真实分区 bind 到
 * 一个"镜像"目录（BOSS_DIR/tmp/mirror），之后所有"还原原文件"的动作都
 * 从镜像里取，而不是从被遮盖的目标路径取。
 *
 * 必须处理的两个细节（不处理会导致改动静默失效）：
 *   1. .replace：模块目录里放 .replace 空文件 → 该目录整体替换，不合并。
 *   2. 分区可能是 symlink 也可能是原生目录：/system/vendor、/system/product
 *      在不同设备形态不同。这里统一 realpath 解析到真实挂载根。
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boss.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_KIDS 512
#define BOSS_PATH_MAX (PATH_MAX + 64)

/* ---------------- D1：模块元数据 ---------------- */

struct boss_module {
    char id[256];
    char name[256];
    char version[64];
    char author[128];
    char desc[512];
    char path[BOSS_PATH_MAX];
    int  skip_mount;
    int  disabled;
};

static void prop_get(const char *file, const char *key, char *out, size_t n)
{
    out[0] = '\0';
    FILE *fp = fopen(file, "re");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *t = v + strlen(v) - 1;
        while (t > v && (*t == ' ' || *t == '\t' || *t == '\r')) *t-- = '\0';
        if (!strcmp(k, key)) { snprintf(out, n, "%s", v); break; }
    }
    fclose(fp);
}

/* ---------------- 合并树 ---------------- */

struct mnode {
    char name[256];
    int  is_dir;
    int  replace;              /* 该目录整体替换（.replace） */
    char src[BOSS_PATH_MAX];        /* 模块里的真实来源（仅文件） */
    int  order;                /* 模块顺序，大的覆盖小的 */
    struct mnode **kids;
    int  nkids, cap;
};

static struct mnode *node_new(const char *name, int is_dir)
{
    struct mnode *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    snprintf(n->name, sizeof(n->name), "%s", name);
    n->is_dir = is_dir;
    n->cap = 8;
    n->kids = calloc((size_t)n->cap, sizeof(struct mnode *));
    return n;
}

static struct mnode *node_child(struct mnode *n, const char *name)
{
    for (int i = 0; i < n->nkids; i++) {
        if (!strcmp(n->kids[i]->name, name)) return n->kids[i];
    }
    return NULL;
}

static struct mnode *node_add(struct mnode *n, const char *name, int is_dir)
{
    struct mnode *c = node_child(n, name);
    if (c) return c;
    if (n->nkids == n->cap) {
        n->cap *= 2;
        struct mnode **nk = realloc(n->kids, (size_t)n->cap * sizeof(struct mnode *));
        if (!nk) return NULL;
        n->kids = nk;
    }
    c = node_new(name, is_dir);
    if (!c) return NULL;
    n->kids[n->nkids++] = c;
    return c;
}

/* 递归把模块的 system/ 内容插进树；目录里的 .replace 会提升为节点标记 */
static int scan_into(struct mnode *root, const char *dir, int order)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int replace_here = 0;
    char dotrep[BOSS_PATH_MAX];
    snprintf(dotrep, sizeof(dotrep), "%s/.replace", dir);
    if (access(dotrep, F_OK) == 0) replace_here = 1;

    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!strcmp(e->d_name, ".replace")) continue;      /* 标记文件，不挂载 */

        char full[BOSS_PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;

        int is_dir = S_ISDIR(st.st_mode);
        struct mnode *c = node_add(root, e->d_name, is_dir);
        if (!c) continue;

        if (!is_dir) {
            snprintf(c->src, sizeof(c->src), "%s", full);
            c->order = order;
        } else {
            if (replace_here) c->replace = 1;
            scan_into(c, full, order);
        }
    }
    closedir(d);
    if (replace_here) root->replace = 1;
    return 0;
}

/* ---------------- 挂载根：处理分区 symlink ---------------- */

static const char *part_names[] = {
    "vendor", "product", "system_ext", "odm", "odm_dlkm", "vendor_dlkm", NULL
};

static int is_partition(const char *n)
{
    for (int i = 0; part_names[i]; i++) {
        if (!strcmp(n, part_names[i])) return 1;
    }
    return 0;
}

/* 路径拼接。不用 snprintf 是为了避免两件事：
 *   1) -Werror -Wformat-truncation 对"两个变量拼接"的保守告警（CI 的 strict job
 *      用 -Werror 直接编 src 下的全部 .c，警告就是失败）
 *   2) 静默截断出半个路径——这里截断一律返回失败，让调用方跳过该条目 */
static int path_join(char *dst, size_t n, const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (n == 0) return -1;
    if (la >= n) return -1;
    memcpy(dst, a, la);
    size_t off = la;
    if (off + 1 >= n) { dst[off] = '\0'; return -1; }
    dst[off++] = '/';
    if (off + lb >= n) { dst[off] = '\0'; return -1; }
    memcpy(dst + off, b, lb);
    dst[off + lb] = '\0';
    return 0;
}

/* 同上，纯拷贝版（不带 '/'） */
static int path_copy(char *dst, size_t n, const char *src)
{
    size_t l = strlen(src);
    if (l >= n) return -1;
    memcpy(dst, src, l);
    dst[l] = '\0';
    return 0;
}

/* /system/vendor 可能是目录也可能是 symlink（指向 /vendor）。
 * 统一解析成真实挂载根；解析不出来就用 /system/<name>。 */
static void resolve_root(const char *name, char *out, size_t n)
{
    char p[BOSS_PATH_MAX];
    if (path_join(p, sizeof(p), "/system", name) < 0) {
        path_copy(out, n, name);
        return;
    }
    char resolved[BOSS_PATH_MAX];
    if (realpath(p, resolved) != NULL) {
        path_copy(out, n, resolved);
    } else {
        path_copy(out, n, p);
    }
}

/* ---------------- 目录条目枚举 ---------------- */

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/* 从"镜像"路径读目录条目：返回排序后的名字数组。
 * 镜像不存在时退回读目标路径（此时它还没被遮盖）。 */
static int list_dir(const char *path, char ***out)
{
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    int cap = 16, n = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) { closedir(d); return 0; }
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (n == cap) {
            cap *= 2;
            char **nl = realloc(list, (size_t)cap * sizeof(char *));
            if (!nl) break;
            list = nl;
        }
        list[n++] = strdup(e->d_name);
    }
    closedir(d);
    if (n > 1) qsort(list, (size_t)n, sizeof(char *), cmp_str);
    *out = list;
    return n;
}

static void free_list(char **l, int n)
{
    for (int i = 0; i < n; i++) free(l[i]);
    free(l);
}

/* ---------------- 挂载动作（dry-run 只打印） ---------------- */

static int act_mount(const char *src, const char *tgt, const char *type,
                     unsigned long flags, int dry)
{
    if (dry) {
        printf("%-8s %-8s %s -> %s\n",
               type ? type : "bind", "", src, tgt);
        return 0;
    }
    if (mount(src, tgt, type, flags, NULL) != 0) {
        fprintf(stderr, "module: mount %s -> %s 失败: %s\n", src, tgt, strerror(errno));
        return -1;
    }
    return 0;
}

static int act_mkdir(const char *path, int dry)
{
    if (dry) { printf("%-8s %s\n", "mkdir", path); return 0; }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "module: mkdir %s 失败: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* 递归挂载：父先处理，子目录骨架先建好 */
static int mount_node(struct mnode *n, const char *target, const char *mirror,
                      int dry, int depth)
{
    if (depth > 32) return 0;

    int has_file = 0;
    for (int i = 0; i < n->nkids; i++) {
        if (!n->kids[i]->is_dir) { has_file = 1; break; }
    }
    int need_tmpfs = has_file || n->replace;

    if (need_tmpfs) {
        /* 1) 原始条目：一律从镜像读（镜像 = 真实分区的 bind，不会被遮盖） */
        char **ents = NULL;
        int nent = list_dir(mirror, &ents);
        if (nent == 0) {
            /* 镜像不可用时退而求其次：读目标路径（此刻尚未遮盖） */
            nent = list_dir(target, &ents);
        }

        /* 2) tmpfs 覆盖目标目录 */
        if (dry && n->replace)
            printf("# replace  %s（整体替换，不还原原内容）\n", target);
        if (act_mount("tmpfs", target, "tmpfs", 0, dry) < 0) {
            free_list(ents, nent);
            return -1;
        }

        /* 3) 把原始内容 bind 回来（被模块覆盖的、或整体替换的除外） */
        for (int i = 0; i < nent; i++) {
            if (n->replace) continue;                    /* 整体替换：不还原任何原内容 */
            struct mnode *k = node_child(n, ents[i]);
            if (k && !k->is_dir) continue;               /* 文件被模块覆盖，跳过 */
            if (k && k->is_dir && k->replace) continue;  /* 子目录整体替换，跳过 */

            char s[BOSS_PATH_MAX], t[BOSS_PATH_MAX];
            snprintf(s, sizeof(s), "%s/%s", mirror, ents[i]);
            snprintf(t, sizeof(t), "%s/%s", target, ents[i]);
            act_mount(s, t, NULL, MS_BIND, dry);
        }

        /* 4) 模块文件覆盖上去 */
        for (int i = 0; i < n->nkids; i++) {
            struct mnode *k = n->kids[i];
            if (k->is_dir || !k->src[0]) continue;
            char t[BOSS_PATH_MAX];
            snprintf(t, sizeof(t), "%s/%s", target, k->name);
            act_mount(k->src, t, NULL, MS_BIND, dry);
        }
        free_list(ents, nent);
    }

    /* 5) 递归子目录：先确保骨架存在，再进去处理 */
    for (int i = 0; i < n->nkids; i++) {
        struct mnode *k = n->kids[i];
        if (!k->is_dir) continue;
        char ct[BOSS_PATH_MAX], cm[BOSS_PATH_MAX];
        snprintf(ct, sizeof(ct), "%s/%s", target, k->name);
        snprintf(cm, sizeof(cm), "%s/%s", mirror, k->name);

        struct stat st;
        if (stat(ct, &st) != 0 && !dry) act_mkdir(ct, dry);
        else if (dry && stat(ct, &st) != 0) act_mkdir(ct, dry);

        mount_node(k, ct, cm, dry, depth + 1);
    }
    return 0;
}

/* ---------------- 模块扫描 ---------------- */

static int cmp_mod(const void *a, const void *b)
{
    const struct boss_module *x = a, *y = b;
    return strcmp(x->id, y->id);
}

static int load_modules(struct boss_module **out)
{
    DIR *d = opendir(BOSS_MODULE_DIR);
    if (!d) return 0;
    struct dirent *e;
    int cap = 8, n = 0;
    struct boss_module *ms = calloc((size_t)cap, sizeof(struct boss_module));
    if (!ms) { closedir(d); return 0; }

    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char dir[BOSS_PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/%s", BOSS_MODULE_DIR, e->d_name);
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        /* remove 标记：上次开机被标记移除，这里真正删掉 */
        char f[BOSS_PATH_MAX + 64];
        if (path_join(f, sizeof(f), dir, "remove") < 0) continue;
        if (access(f, F_OK) == 0) {
            /* 递归删除目录内容（模块不大，借 shell 一把） */
            char cmd[BOSS_PATH_MAX + 160];
            snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
            if (system(cmd) != 0) { /* 删不掉就留着，不阻断启动 */ }
            continue;
        }

        if (path_join(f, sizeof(f), dir, "module.prop") < 0) continue;
        if (access(f, F_OK) != 0) continue;      /* 没有 module.prop 不是模块 */

        if (n == cap) {
            cap *= 2;
            struct boss_module *nm = realloc(ms, (size_t)cap * sizeof(*nm));
            if (!nm) break;
            ms = nm;
        }
        struct boss_module *m = &ms[n];
        memset(m, 0, sizeof(*m));
        path_copy(m->path, sizeof(m->path), dir);
        prop_get(f, "id", m->id, sizeof(m->id));
        if (!m->id[0]) snprintf(m->id, sizeof(m->id), "%s", e->d_name);
        prop_get(f, "name", m->name, sizeof(m->name));
        prop_get(f, "version", m->version, sizeof(m->version));
        prop_get(f, "author", m->author, sizeof(m->author));
        prop_get(f, "description", m->desc, sizeof(m->desc));

        if (path_join(f, sizeof(f), dir, "skip_mount") == 0)
            m->skip_mount = (access(f, F_OK) == 0);
        if (path_join(f, sizeof(f), dir, "disable") == 0)
            m->disabled = (access(f, F_OK) == 0);
        n++;
    }
    closedir(d);
    if (n > 1) qsort(ms, (size_t)n, sizeof(*ms), cmp_mod);
    *out = ms;
    return n;
}

/* 给 boot 流程用：启用的模块目录，按 id 排序（保证属性/规则应用顺序稳定）。
 * 返回数量；调用方负责 free 每个元素与数组本身。 */
int boss_module_dirs(char ***out)
{
    struct boss_module *ms = NULL;
    int n = load_modules(&ms);
    if (n <= 0) { *out = NULL; return 0; }

    char **dirs = calloc((size_t)n, sizeof(char *));
    if (!dirs) { free(ms); *out = NULL; return 0; }
    int k = 0;
    for (int i = 0; i < n; i++) {
        if (ms[i].disabled) continue;
        dirs[k] = strdup(ms[i].path);
        if (dirs[k]) k++;
    }
    free(ms);
    *out = dirs;
    return k;
}

/* ---------------- 命令 ---------------- */

static int cmd_list(struct boss_module *ms, int n)
{
    printf("%-24s %-10s %-6s %s\n", "ID", "VERSION", "MOUNT", "NAME");
    for (int i = 0; i < n; i++) {
        printf("%-24s %-10s %-6s %s%s\n",
               ms[i].id, ms[i].version[0] ? ms[i].version : "-",
               ms[i].disabled ? "off" : (ms[i].skip_mount ? "script" : "mount"),
               ms[i].name[0] ? ms[i].name : ms[i].id,
               ms[i].desc[0] ? "" : "");
    }
    if (n == 0) printf("(无模块)\n");
    return 0;
}

/* 汇总所有模块的 system.prop / sepolicy.rule：开机流程里交给 resetprop 与 sepolicy */
static int cmd_dump(struct boss_module *ms, int n, const char *what)
{
    const char *fname = !strcmp(what, "props") ? "system.prop" : "sepolicy.rule";
    for (int i = 0; i < n; i++) {
        if (ms[i].disabled) continue;
        char f[PATH_MAX + 64];
        snprintf(f, sizeof(f), "%s/%s", ms[i].path, fname);
        FILE *fp = fopen(f, "re");
        if (!fp) continue;
        printf("# ---- %s ----\n", ms[i].id);
        char line[2048];
        while (fgets(line, sizeof(line), fp)) fputs(line, stdout);
        fclose(fp);
    }
    return 0;
}

static int do_mount(int dry)
{
    struct boss_module *ms = NULL;
    int n = load_modules(&ms);

    /* 每个分区一棵树：system 之外的分区要解析真实挂载根 */
    struct mnode *roots[8];
    char root_base[8][BOSS_PATH_MAX];
    int nroot = 0;

    for (int p = 0; part_names[p]; p++) {
        roots[nroot] = node_new("", 1);
        resolve_root(part_names[p], root_base[nroot], BOSS_PATH_MAX);
        nroot++;
    }
    roots[nroot] = node_new("", 1);
    path_copy(root_base[nroot], BOSS_PATH_MAX, "/system");
    int sys_root = nroot;
    nroot++;

    int order = 0;
    for (int i = 0; i < n; i++) {
        if (ms[i].disabled || ms[i].skip_mount) continue;
        char sysdir[BOSS_PATH_MAX + 64];
        if (path_join(sysdir, sizeof(sysdir), ms[i].path, "system") < 0) continue;
        if (access(sysdir, F_OK) != 0) continue;

        /* 先看有没有分区子目录，有就按分区分流 */
        DIR *d = opendir(sysdir);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char sub[BOSS_PATH_MAX + 64];
            if (path_join(sub, sizeof(sub), sysdir, e->d_name) < 0) continue;
            struct stat st;
            if (lstat(sub, &st) != 0) continue;

            int target = sys_root;
            if (S_ISDIR(st.st_mode) && is_partition(e->d_name)) {
                for (int p = 0; part_names[p]; p++) {
                    if (!strcmp(part_names[p], e->d_name)) { target = p; break; }
                }
            }
            if (S_ISDIR(st.st_mode)) {
                struct mnode *c = node_add(roots[target], e->d_name, 1);
                scan_into(c, sub, order);
            } else {
                struct mnode *c = node_add(roots[target], e->d_name, 0);
                path_copy(c->src, sizeof(c->src), sub);
                c->order = order;
            }
        }
        closedir(d);
        order++;
    }

    /* 建立镜像：所有"还原原文件"的动作都从这里取源 */
    char mirror_base[BOSS_PATH_MAX];
    path_join(mirror_base, sizeof(mirror_base), BOSS_TMP_DIR, "mirror");
    if (!dry) {
        /* 只给"模块真的要动"的分区建镜像：无脑给 7 个分区都建，
         * 在不存在的分区上会刷一屏 mount 失败，掩盖真正的错误。 */
        int need_mirror = 0;
        for (int r = 0; r < nroot; r++) {
            if (roots[r]->nkids > 0) { need_mirror = 1; break; }
        }
        if (need_mirror) boss_mkdirs(mirror_base, 0700);
        for (int r = 0; r < nroot && need_mirror; r++) {
            if (roots[r]->nkids == 0) continue;
            char mdir[BOSS_PATH_MAX + 64];
            const char *leaf = strrchr(root_base[r], '/');
            leaf = leaf ? leaf + 1 : root_base[r];
            if (path_join(mdir, sizeof(mdir), mirror_base, leaf) < 0) continue;
            boss_mkdirs(mdir, 0755);
            if (mount(root_base[r], mdir, NULL, MS_BIND, NULL) != 0) {
                fprintf(stderr, "module: 建立 %s 镜像失败: %s\n",
                        root_base[r], strerror(errno));
            }
        }
    }
    if (dry) printf("# mirror: %s\n", mirror_base);

    int rc = 0;
    for (int r = 0; r < nroot; r++) {
        if (roots[r]->nkids == 0) continue;
        char mdir[BOSS_PATH_MAX + 64];
        const char *leaf = strrchr(root_base[r], '/');
        leaf = leaf ? leaf + 1 : root_base[r];
        if (path_join(mdir, sizeof(mdir), mirror_base, leaf) < 0) continue;
        if (dry) printf("# partition %s -> root %s\n", leaf, root_base[r]);
        if (mount_node(roots[r], root_base[r], mdir, dry, 0) < 0) rc = 1;
    }

    free(ms);
    return rc;
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss module <命令>\n"
        "  list              列出模块\n"
        "  info <id>         显示模块详情\n"
        "  plan              只打印挂载计划，不执行（可离线验证）\n"
        "  mount             执行 Magic Mount\n"
        "  dump props|rules  汇总模块的 system.prop / sepolicy.rule\n");
}

int boss_module_main(int argc, char **argv)
{
    /* argv[0] 是 applet 名（"module"），子命令从 argv[1] 取 */
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }

    struct boss_module *ms = NULL;
    int n = load_modules(&ms);

    int rc = 0;
    if (!strcmp(cmd, "list")) {
        rc = cmd_list(ms, n);
    } else if (!strcmp(cmd, "info")) {
        if (argc < 3) { usage(); rc = 1; }
        else {
            int found = 0;
            for (int i = 0; i < n; i++) {
                if (!strcmp(ms[i].id, argv[2])) {
                    printf("id:      %s\nname:    %s\nversion: %s\nauthor:  %s\n"
                           "path:    %s\nmount:   %s\ndesc:    %s\n",
                           ms[i].id, ms[i].name, ms[i].version, ms[i].author,
                           ms[i].path,
                           ms[i].disabled ? "disabled" : (ms[i].skip_mount ? "script-only" : "yes"),
                           ms[i].desc);
                    found = 1;
                }
            }
            if (!found) { fprintf(stderr, "module: 没有 %s\n", argv[2]); rc = 1; }
        }
    } else if (!strcmp(cmd, "dump")) {
        if (argc < 3) { usage(); rc = 1; }
        else rc = cmd_dump(ms, n, argv[2]);
    } else if (!strcmp(cmd, "plan")) {
        rc = do_mount(1);           /* dry run：不需要特权，CI 上也能验 */
    } else if (!strcmp(cmd, "mount")) {
        if (geteuid() != 0) {
            fprintf(stderr, "module: 挂载需要 root 权限（当前 euid=%u）\n",
                    (unsigned)geteuid());
            rc = 1;
        } else {
            rc = do_mount(0);
        }
    } else {
        usage();
        rc = 1;
    }

    free(ms);
    return rc;
}
