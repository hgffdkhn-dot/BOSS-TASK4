/* 任务4 · libsepol 内置后端（src/selinux.c 引擎链的第一级）
 *
 * ---------------------------------------------------------------------------
 * 这一级为什么必须存在
 * ---------------------------------------------------------------------------
 * src/selinux.c 的三级降级链是：
 *     ① 内置 libsepol（本文件） → ② 外部引擎 magiskpolicy/... → ③ pending 队列
 *
 * 第 ② 级在真机上远没有想象中可靠：早期注入（路径 A）发生在 init 的
 * selinux_setup 阶段，那时 /data 还没挂载、PATH 里什么都没有，
 * magiskpolicy 这类"恰好存在的文件"大概率不存在。也就是说——
 * **没有第 ① 级，路径 A 在很多机型上等于没有**。
 * 这不是锦上添花的优化，是"早期注入能不能成立"的前提。
 *
 * ---------------------------------------------------------------------------
 * 为什么敢写（与文档第 3.1 节那条红线不冲突）
 * ---------------------------------------------------------------------------
 * 3.1 节说"不自研 policydb 二进制改写器"，理由是几千行 + 强依赖版本 + 写错变砖。
 * 这条我们原样遵守：格式的反序列化与序列化**全部交给 libsepol**
 * （policydb_read / policydb_write），我们只在内存里改 symtab 与 avtab。
 * 自己写的只有"规则文本 → policydb 对象操作"这层映射，
 * 它不涉及任何字节序 / 版本 / 段顺序问题。
 *
 * ---------------------------------------------------------------------------
 * 四个从 libsepol 源码核出来、但文档里看不到的坑
 * ---------------------------------------------------------------------------
 * 1) **permissive 的位索引是 1 基，其它 ebitmap 全是 0 基。**
 *    expand.c 写 permissive_map 用的是 `new_type->s.value`（1 基），
 *    而 attribute 成员表 type->types、role_trans 等一律用 `value - 1`（0 基）。
 *    混用不会报错，只会让 permissive 悄悄作用在错误的 type 上。
 * 2) **kernel policy 不通过 type 属性写 permissive。**
 *    write.c 的 type_write 里有 `p->policy_type != POLICY_KERN` 的判断——
 *    只有 permissive_map（一张 ebitmap）会被写出去。所以光设 type->flags 不够。
 * 3) **新增 type 必须自己维护三张并行表。**
 *    symtab_insert 只做 hashtab_insert + nprim++，它不管：
 *      · type_val_to_struct[]  —— write.c 按 nprim 遍历它
 *      · type_attr_map[]       —— write.c 按 nprim 逐个 ebitmap_write 出去
 *      · attr_type_map[]       —— 不写出，但内部一致性依赖它
 *    少扩一个，写出的策略要么越界读，要么读回来 attribute 关系全丢。
 * 4) **typeattribute 要同时改两张表。**
 *    attribute 的成员集合（attr->types）和 type→attribute 映射（type_attr_map）
 *    都会被写出去，只改前者的话，注入后 avtab 里规则在，但 `id -Z` 之外的
 *    类型归属关系会不一致。
 *
 * ---------------------------------------------------------------------------
 * 未 vendor libsepol 时（未定义 BOSS_HAVE_SEPOL）
 * ---------------------------------------------------------------------------
 * 整个文件退化成返回 -1 的桩，selinux.c 自动落到第 ② 级，行为与 vendor 之前
 * 完全一致。所以这个文件可以无条件编译进 SRCS，不用给 SRCS 加条件。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "boss.h"

#ifdef BOSS_HAVE_SEPOL
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/sepol.h>
#endif

/* 返回码：与 src/selinux.c 的 RC_* 同一套契约，调用方判断方式不变 */
#define SP_OK       0   /* 全部应用 */
#define SP_FAIL     1   /* 硬错误：读不了策略 / 写不回 */
#define SP_NOENGINE 2   /* 本后端不可用（未 vendor），让下一级接管 */
#define SP_PARTIAL  3   /* 部分应用：有规则被跳过（尽力而为的正常结果） */

/* 单条规则的结果 */
#define SP_R_APPLIED 0
#define SP_R_FAILED  1
#define SP_R_SKIPPED 2

#define SP_MAX_TOK      32
#define SP_RULE_BUF     1024
#define SP_SELINUX_LOAD "/sys/fs/selinux/load"
#define SP_SELINUX_POL  "/sys/fs/selinux/policy"

/* 单条规则允许展开出的 avtab 条目上限。
 * `allow * * *` 展开是 O(N²×C) 量级，Android 上 type 数两千起步，
 * 不设闸会把早期注入的内存打爆（早期没有 OOM killer 兜底，直接开机失败）。
 * 正常规则远达不到这个量级，触发它说明规则本身写错了。 */
#define SP_MAX_AVTAB_INSERT 500000u

#ifndef BOSS_HAVE_SEPOL

/* ---- 桩：没有 vendor libsepol，让 selinux.c 走外部引擎 ---- */
int sepol_builtin_apply(const char *in, const char *out, const char **rules,
                        int n, int live, struct inject_result *res)
{
    (void)in; (void)out; (void)rules; (void)n; (void)live; (void)res;
    return -1;
}

#else /* BOSS_HAVE_SEPOL */

/* 磁盘策略源候选（顺序与 src/selinux.c 的 file_sources 保持一致）。
 * 只在内置后端分支里用到，所以放在 #ifdef 内——放到外面会让不带
 * BOSS_HAVE_SEPOL 的构建撞上 -Werror=unused-variable（CI 的 strict job
 * 就是逐个 -std 开 -Werror 编的）。 */
static const char *sp_file_sources[] = {
    "/system/etc/selinux/precompiled_sepolicy",
    "/vendor/etc/selinux/precompiled_sepolicy",
    "/sepolicy",
    "/system/etc/selinux/sepolicy",
    BOSS_DIR "/sepolicy.patched",
    NULL
};

/* ================================================================== */
/* 小工具                                                             */
/* ================================================================== */

static void *sp_zalloc(size_t n)
{
    return calloc(1, n);
}

static int sp_read_all(const char *path, char **buf, size_t *len)
{
    FILE *fp = fopen(path, "re");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);

    char *b = malloc((size_t)sz + 1);
    if (!b) { fclose(fp); return -1; }
    size_t got = fread(b, 1, (size_t)sz, fp);
    fclose(fp);
    b[got] = '\0';
    *buf = b;
    *len = got;
    return 0;
}

static int sp_write_all(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const char *)data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static int sp_tok(char *s, char **tv, int max)
{
    int n = 0;
    char *p = strtok(s, " \t\r\n");
    while (p && n < max) {
        tv[n++] = p;
        p = strtok(NULL, " \t\r\n");
    }
    return n;
}

/* ================================================================== */
/* 名字 → policydb 内部对象                                           */
/* ================================================================== */

static type_datum_t *sp_type(policydb_t *pol, const char *name)
{
    return (type_datum_t *)hashtab_search(pol->p_types.table, name);
}

static class_datum_t *sp_class(policydb_t *pol, const char *name)
{
    return (class_datum_t *)hashtab_search(pol->p_classes.table, name);
}

/* 名字 → type value 数组
 *   · 普通 type：单值
 *   · attribute：展开成全部成员（成员 ebitmap 是 0 基，见文件头坑 1）
 *   · "*"：全部非 attribute 的 type
 * 成功返回 0（*out 由调用方 free），找不到返回 -1。
 */
static int sp_type_values(policydb_t *pol, const char *name,
                          uint32_t **out, int *nout)
{
    *out = NULL;
    *nout = 0;

    uint32_t nprim = pol->p_types.nprim;
    if (nprim == 0) return -1;

    uint32_t *v = sp_zalloc(sizeof(uint32_t) * nprim);
    if (!v) return -1;
    int k = 0;

    if (!strcmp(name, "*")) {
        for (uint32_t i = 1; i <= nprim; i++) {
            type_datum_t *t = pol->type_val_to_struct[i - 1];
            if (t && t->flavor != TYPE_ATTRIB) v[k++] = i;
        }
    } else {
        type_datum_t *t = sp_type(pol, name);
        if (!t) { free(v); return -1; }

        if (t->flavor == TYPE_ATTRIB) {
            /* 坑 5：attribute 的成员关系在 kernel policy 里是**靠 type_attr_map
             * 表达的**，attribute datum 自己的 types 字段根本不会被写出去
             * （write.c 只写 type_attr_map[i]）。所以从磁盘读进来的策略里
             * a->types 是空的——按它展开会得到"只有本进程刚加进去的那几个"，
             * 一条不报错，但规则大面积静默失效。
             * 真正可靠的是读策略时由 policydb_read 反建出来的 attr_type_map。 */
            ebitmap_t *members = NULL;
            if (pol->attr_type_map && t->s.value >= 1 && t->s.value <= nprim)
                members = &pol->attr_type_map[t->s.value - 1];

            /* 兜底：attr_type_map 缺失时（比如 policyvers < 20 的老策略）
             * 退回内存里的 types，至少不比什么都不做强 */
            if (!members || ebitmap_length(members) == 0) members = &t->types;

            ebitmap_node_t *node = NULL;
            unsigned int bit = 0;
            ebitmap_for_each_bit(members, node, bit) {
                if (!ebitmap_get_bit(members, bit)) continue;
                uint32_t val = bit + 1;          /* 0 基 bit → 1 基 value */
                if (val <= nprim) v[k++] = val;
            }
        } else {
            v[k++] = t->s.value;
        }
    }

    if (k == 0) { free(v); return -1; }
    *out = v;
    *nout = k;
    return 0;
}

static int sp_class_values(policydb_t *pol, const char *name,
                           uint32_t **out, int *nout)
{
    *out = NULL;
    *nout = 0;

    uint32_t nprim = pol->p_classes.nprim;
    if (nprim == 0) return -1;

    uint32_t *v = sp_zalloc(sizeof(uint32_t) * nprim);
    if (!v) return -1;
    int k = 0;

    if (!strcmp(name, "*")) {
        for (uint32_t i = 1; i <= nprim; i++) v[k++] = i;
    } else {
        class_datum_t *c = sp_class(pol, name);
        if (!c) { free(v); return -1; }
        v[k++] = c->s.value;
    }

    if (k == 0) { free(v); return -1; }
    *out = v;
    *nout = k;
    return 0;
}

/* 权限名 → 位掩码。"*" 取该 class 全部权限位。
 * class 自己的 permissions 表里找不到时，去 common 里找。
 */
static uint32_t sp_perm_mask(class_datum_t *cl, char **perms, int nperm, int *hit)
{
    uint32_t mask = 0;
    *hit = 0;

    for (int i = 0; i < nperm; i++) {
        if (!strcmp(perms[i], "*")) {
            unsigned int n = cl->permissions.nprim;
            if (n >= 32) mask |= 0xFFFFFFFFu;
            else if (n > 0) mask |= (1u << n) - 1u;
            *hit = 1;
            continue;
        }
        perm_datum_t *p = (perm_datum_t *)hashtab_search(cl->permissions.table,
                                                         perms[i]);
        if (!p && cl->comdatum)
            p = (perm_datum_t *)hashtab_search(cl->comdatum->permissions.table,
                                               perms[i]);
        if (!p) continue;
        if (p->s.value >= 1 && p->s.value <= 32) mask |= 1u << (p->s.value - 1);
        *hit = 1;
    }
    return mask;
}

/* ================================================================== */
/* type / attribute                                                   */
/* ================================================================== */

/* 把 type 加进 attribute。
 * 坑 4：两张表都要改——attr->types（写出去）与 type_attr_map（也写出去）。
 */
static int sp_typeattr_one(policydb_t *pol, const char *tname, const char *aname)
{
    type_datum_t *t = sp_type(pol, tname);
    type_datum_t *a = sp_type(pol, aname);
    if (!t || !a || a->flavor != TYPE_ATTRIB) return -1;

    /* a->types 是内存态（kernel policy 不序列化它，见 sp_type_values 里的坑 5），
     * 真正写出去的是下面两张 map。两个都设，保证本进程内与写盘后行为一致。 */
    if (ebitmap_set_bit(&a->types, t->s.value - 1, 1) != 0) return -1;

    if (pol->type_attr_map)
        ebitmap_set_bit(&pol->type_attr_map[t->s.value - 1], a->s.value - 1, 1);
    if (pol->attr_type_map)
        ebitmap_set_bit(&pol->attr_type_map[a->s.value - 1], t->s.value - 1, 1);
    return 0;
}

/* 扩展与 nprim 平行的三张表（见文件头坑 3）。new_value 是刚分配的 1 基 value。 */
static int sp_grow_type_arrays(policydb_t *pol, uint32_t new_value)
{
    uint32_t nprim = pol->p_types.nprim;
    if (new_value == 0 || new_value > nprim) return -1;

    type_datum_t **nv = realloc(pol->type_val_to_struct, sizeof(*nv) * nprim);
    if (!nv) return -1;
    pol->type_val_to_struct = nv;

    /* type_attr_map 会被 write.c 按 nprim 逐个 ebitmap_write 出去，
     * 不扩就是越界读——写出的是垃圾，而且编译期不报。 */
    if (pol->type_attr_map) {
        ebitmap_t *na = realloc(pol->type_attr_map, sizeof(*na) * nprim);
        if (!na) return -1;
        pol->type_attr_map = na;
        ebitmap_init(&pol->type_attr_map[new_value - 1]);
        /* 退化位：type 自己是自己的"属性"，libsepol 读策略时也会这么设 */
        ebitmap_set_bit(&pol->type_attr_map[new_value - 1], new_value - 1, 1);
    }
    if (pol->attr_type_map) {
        ebitmap_t *na = realloc(pol->attr_type_map, sizeof(*na) * nprim);
        if (!na) return -1;
        pol->attr_type_map = na;
        ebitmap_init(&pol->attr_type_map[new_value - 1]);
        ebitmap_set_bit(&pol->attr_type_map[new_value - 1], new_value - 1, 1);
    }
    return 0;
}

/* type <name> [attr...]：不存在则创建，已存在则复用 */
static int sp_do_type(policydb_t *pol, char **tv, int nt)
{
    if (nt < 2) return SP_R_SKIPPED;
    const char *name = tv[1];

    type_datum_t *t = sp_type(pol, name);
    if (!t) {
        if (pol->p_types.nprim >= 0xFFFFu) {
            fprintf(stderr, "sepol: type 数量已达上限，无法创建 %s\n", name);
            return SP_R_FAILED;
        }
        char *key = strdup(name);
        t = sp_zalloc(sizeof(*t));
        if (!key || !t) { free(key); free(t); return SP_R_FAILED; }

        t->primary = 1;
        t->flavor  = TYPE_TYPE;
        ebitmap_init(&t->types);

        uint32_t value = 0;
        int rc = symtab_insert(pol, SYM_TYPES, key, t, SCOPE_DECL, 0, &value);
        if (rc != 0) { free(key); free(t); return SP_R_FAILED; }

        /* symtab_insert **不会** 把 value 写回 datum，它只当出参给。
         * 漏了这一行，新 type 的 s.value 就是 0，后面加 attribute 时
         * `t->s.value - 1` 下溢成 0xffffffff，libsepol 只会打一行
         * "bitmap overflow" 然后什么都不做——规则看起来应用了，实际没生效。 */
        t->s.value = value;

        if (sp_grow_type_arrays(pol, value) != 0) {
            /* symtab 已经插进去了，这里失败意味着结构不一致。
             * 继续写下去更危险，直接判失败，让调用方降级到外部引擎。 */
            fprintf(stderr, "sepol: 扩展 type 索引表失败: %s\n", name);
            return SP_R_FAILED;
        }
    }

    /* 后面的是 attribute 列表；逐个尽力而为，不存在就跳过 */
    for (int i = 2; i < nt; i++) sp_typeattr_one(pol, name, tv[i]);
    return SP_R_APPLIED;
}

static int sp_do_typeattr(policydb_t *pol, char **tv, int nt)
{
    if (nt < 3) return SP_R_SKIPPED;
    return sp_typeattr_one(pol, tv[1], tv[2]) == 0 ? SP_R_APPLIED : SP_R_SKIPPED;
}

/* permissive / enforce <type> */
static int sp_do_permissive(policydb_t *pol, const char *name, int on)
{
    if (pol->policyvers < POLICYDB_VERSION_PERMISSIVE) {
        fprintf(stderr, "sepol: policy 版本 %u 不支持 permissive，跳过 %s\n",
                pol->policyvers, name);
        return SP_R_SKIPPED;
    }
    type_datum_t *t = sp_type(pol, name);
    if (!t) return SP_R_SKIPPED;

    if (on) t->flags |= TYPE_FLAGS_PERMISSIVE;
    else    t->flags &= ~TYPE_FLAGS_PERMISSIVE;

    /* 坑 1：permissive_map 用 1 基 value；坑 2：kernel policy 只认这张表 */
    if (ebitmap_set_bit(&pol->permissive_map, t->s.value, on ? 1 : 0) != 0)
        return SP_R_FAILED;
    return SP_R_APPLIED;
}

/* ================================================================== */
/* avtab 操作                                                         */
/* ================================================================== */

/* 插入 / 合并一条 av 规则。返回 0 表示确实改动了。 */
static int sp_avtab_set(policydb_t *pol, uint32_t src, uint32_t tgt,
                        uint32_t cls, uint16_t specified, uint32_t mask,
                        int is_deny)
{
    avtab_key_t key;
    memset(&key, 0, sizeof(key));
    key.source_type  = (uint16_t)src;
    key.target_type  = (uint16_t)tgt;
    key.target_class = (uint16_t)cls;
    key.specified    = specified;

    avtab_ptr_t node = avtab_search_node(&pol->te_avtab, &key);

    if (is_deny) {
        /* deny = 去掉这些权限位。节点不存在 = 本来就没这些权限，
         * 按"无需改动"处理，不算失败（尽力而为）。 */
        if (!node) return 1;
        uint32_t before = node->datum.data;
        node->datum.data &= ~mask;
        return (node->datum.data != before) ? 0 : 1;
    }

    if (node) {
        uint32_t before = node->datum.data;
        node->datum.data |= mask;
        return (node->datum.data != before) ? 0 : 1;   /* 已存在也算满足 */
    }

    avtab_datum_t d;
    memset(&d, 0, sizeof(d));
    d.data = mask;
    return avtab_insert(&pol->te_avtab, &key, &d);
}

/* allow / auditallow / dontaudit / deny
 * 两种写法都收：op src tgt:class perm...  与  op src tgt class perm...
 */
static int sp_do_av(policydb_t *pol, const char *op,
                    const char *src, const char *tgt,
                    const char *cls, char **perms, int nperm)
{
    uint16_t specified;
    int is_deny = 0;
    if (!strcmp(op, "allow"))           specified = AVTAB_ALLOWED;
    else if (!strcmp(op, "auditallow")) specified = AVTAB_AUDITALLOW;
    else if (!strcmp(op, "dontaudit"))  specified = AVTAB_AUDITDENY;
    else { specified = AVTAB_ALLOWED; is_deny = 1; }   /* deny */

    uint32_t *srcs = NULL, *tgts = NULL, *clss = NULL;
    int nsrc = 0, ntgt = 0, ncls = 0;

    if (sp_type_values(pol, src, &srcs, &nsrc) != 0) goto skip;
    if (sp_type_values(pol, tgt, &tgts, &ntgt) != 0) goto skip;
    if (sp_class_values(pol, cls, &clss, &ncls) != 0) goto skip;

    /* 规模保护：见 SP_MAX_AVTAB_INSERT 的说明 */
    if ((double)nsrc * (double)ntgt * (double)ncls > (double)SP_MAX_AVTAB_INSERT) {
        fprintf(stderr, "sepol: 规则展开量过大(%d×%d×%d)，已拒绝: %s %s %s %s\n",
                nsrc, ntgt, ncls, op, src, tgt, cls);
        free(srcs); free(tgts); free(clss);
        return SP_R_FAILED;
    }

    {
        int any = 0;
        for (int c = 0; c < ncls; c++) {
            class_datum_t *cd = pol->class_val_to_struct[clss[c] - 1];
            if (!cd) continue;
            int hit = 0;
            uint32_t mask = sp_perm_mask(cd, perms, nperm, &hit);
            if (!hit || mask == 0) continue;    /* 这个 class 没有这些权限 */

            for (int s = 0; s < nsrc; s++)
                for (int t = 0; t < ntgt; t++) {
                    sp_avtab_set(pol, srcs[s], tgts[t], clss[c],
                                 specified, mask, is_deny);
                    any = 1;
                }
        }
        free(srcs); free(tgts); free(clss);
        return any ? SP_R_APPLIED : SP_R_SKIPPED;
    }

skip:
    free(srcs); free(tgts); free(clss);
    return SP_R_SKIPPED;
}

/* type_transition / type_change：op src tgt class default */
static int sp_do_type_rule(policydb_t *pol, const char *op,
                           const char *src, const char *tgt,
                           const char *cls, const char *dflt)
{
    uint16_t specified = (strcmp(op, "type_change") == 0)
                       ? AVTAB_CHANGE : AVTAB_TRANSITION;

    uint32_t *srcs = NULL, *tgts = NULL, *clss = NULL;
    int nsrc = 0, ntgt = 0, ncls = 0;

    if (sp_type_values(pol, src, &srcs, &nsrc) != 0) goto skip;
    if (sp_type_values(pol, tgt, &tgts, &ntgt) != 0) goto skip;
    if (sp_class_values(pol, cls, &clss, &ncls) != 0) goto skip;

    {
        type_datum_t *dt = sp_type(pol, dflt);
        if (!dt) goto skip;

        int any = 0;
        for (int s = 0; s < nsrc; s++)
            for (int t = 0; t < ntgt; t++)
                for (int c = 0; c < ncls; c++) {
                    avtab_key_t key;
                    memset(&key, 0, sizeof(key));
                    key.source_type  = (uint16_t)srcs[s];
                    key.target_type  = (uint16_t)tgts[t];
                    key.target_class = (uint16_t)clss[c];
                    key.specified    = specified;

                    avtab_datum_t d;
                    memset(&d, 0, sizeof(d));
                    d.data = dt->s.value;

                    avtab_ptr_t node = avtab_search_node(&pol->te_avtab, &key);
                    if (node) node->datum.data = d.data;
                    else if (avtab_insert(&pol->te_avtab, &key, &d) != 0) continue;
                    any = 1;
                }
        free(srcs); free(tgts); free(clss);
        return any ? SP_R_APPLIED : SP_R_SKIPPED;
    }

skip:
    free(srcs); free(tgts); free(clss);
    return SP_R_SKIPPED;
}

/* ================================================================== */
/* 规则分派                                                           */
/* ================================================================== */

static int sp_apply_rule(policydb_t *pol, const char *rule)
{
    char buf[SP_RULE_BUF];
    char *tv[SP_MAX_TOK];

    snprintf(buf, sizeof(buf), "%s", rule);
    int nt = sp_tok(buf, tv, SP_MAX_TOK);
    if (nt < 2) return SP_R_SKIPPED;

    const char *op = tv[0];

    if (!strcmp(op, "allow") || !strcmp(op, "deny") ||
        !strcmp(op, "auditallow") || !strcmp(op, "dontaudit")) {
        if (nt < 4) return SP_R_SKIPPED;
        char *src = tv[1], *tgt, *cls, **perms;
        int nperm;
        char *colon = strchr(tv[2], ':');
        if (colon) {
            *colon = '\0';
            tgt = tv[2];
            cls = colon + 1;
            perms = &tv[3];
            nperm = nt - 3;
        } else {
            if (nt < 5) return SP_R_SKIPPED;
            tgt = tv[2];
            cls = tv[3];
            perms = &tv[4];
            nperm = nt - 4;
        }
        if (nperm <= 0) return SP_R_SKIPPED;
        return sp_do_av(pol, op, src, tgt, cls, perms, nperm);
    }

    if (!strcmp(op, "type"))          return sp_do_type(pol, tv, nt);
    if (!strcmp(op, "typeattribute")) return sp_do_typeattr(pol, tv, nt);
    if (!strcmp(op, "permissive"))    return sp_do_permissive(pol, tv[1], 1);
    if (!strcmp(op, "enforce"))       return sp_do_permissive(pol, tv[1], 0);

    if (!strcmp(op, "type_transition") || !strcmp(op, "type_change")) {
        if (nt < 4) return SP_R_SKIPPED;
        char *src = tv[1], *tgt, *cls, *dflt;
        char *colon = strchr(tv[2], ':');
        if (colon) {
            *colon = '\0';
            tgt = tv[2];
            cls = colon + 1;
            dflt = tv[3];
        } else {
            if (nt < 5) return SP_R_SKIPPED;
            tgt = tv[2];
            cls = tv[3];
            dflt = tv[4];
        }
        return sp_do_type_rule(pol, op, src, tgt, cls, dflt);
    }

    /* 不认识的 op：交给"尽力而为"处理，跳过但不算失败 */
    return SP_R_SKIPPED;
}

/* ================================================================== */
/* 入口                                                               */
/* ================================================================== */

/* 定位输入策略：live 走内核，否则落到磁盘候选 */
static const char *sp_locate(const char *in, int live)
{
    if (in) return in;
    if (live) return SP_SELINUX_POL;

    struct stat st;
    for (int i = 0; sp_file_sources[i]; i++)
        if (stat(sp_file_sources[i], &st) == 0) return sp_file_sources[i];
    return NULL;
}

int sepol_builtin_apply(const char *in, const char *out, const char **rules,
                        int n, int live, struct inject_result *res)
{
    if (res) { res->applied = 0; res->skipped = 0; res->failed = 0; }
    if (!rules || n <= 0) return SP_OK;

    /* 运行时总开关：BOSS_SEPOL=0 可临时关掉内置后端，退回外部引擎。
     * 真机排查用得上——内置后端在某一台机器上出问题时，不用重刷包
     * 就能对比"外部引擎是否也失败"，快速定位是后端还是规则的问题。
     * 测试也靠它验证"无引擎仍能进 pending"这条降级契约。 */
    const char *off = getenv("BOSS_SEPOL");
    if (off && (!strcmp(off, "0") || !strcmp(off, "off"))) {
        fprintf(stderr, "sepol: 内置后端已被 BOSS_SEPOL=0 关闭，交给外部引擎\n");
        return -1;
    }

    const char *src = sp_locate(in, live);
    if (!src) {
        fprintf(stderr, "sepol: 找不到策略源\n");
        return SP_FAIL;
    }

    char *buf = NULL;
    size_t len = 0;
    if (sp_read_all(src, &buf, &len) != 0 || len == 0) {
        fprintf(stderr, "sepol: 读不到策略源 %s\n", src);
        free(buf);
        return SP_FAIL;
    }

    policydb_t pol;
    if (policydb_init(&pol) != 0) { free(buf); return SP_FAIL; }

    policy_file_t pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = buf;
    pf.len  = len;

    if (policydb_read(&pol, &pf, 0) != 0) {
        /* 最常见的原因：设备 policy 版本高于本 libsepol 的上限。
         * 明确报出来，别让调用方误以为是"规则写错了"。 */
        fprintf(stderr, "sepol: 解析策略失败 %s（多半是 policy 版本高于本 libsepol 上限）\n", src);
        policydb_destroy(&pol);
        free(buf);
        return SP_FAIL;
    }

    /* avtab_init 只把 htable 置 NULL，真正的桶是 avtab_read 里 alloc 出来的。
     * 若策略本身 avtab 为空（极少数），这里不 alloc 的话第一条规则就会插入失败，
     * 而且报出来的是 ENOMEM，非常容易误判成"内存不够"。 */
    if (!pol.te_avtab.htable && avtab_alloc(&pol.te_avtab, 256) != 0) {
        fprintf(stderr, "sepol: 无法初始化 avtab\n");
        policydb_destroy(&pol);
        free(buf);
        return SP_FAIL;
    }

    for (int i = 0; i < n; i++) {
        int r = sp_apply_rule(&pol, rules[i]);
        if (r == SP_R_APPLIED) {
            if (res) res->applied++;
        } else if (r == SP_R_FAILED) {
            if (res) res->failed++;
            fprintf(stderr, "sepol: 规则失败: %s\n", rules[i]);
        } else {
            if (res) res->skipped++;
            fprintf(stderr, "sepol: 规则未生效（目标不存在，已跳过）: %s\n", rules[i]);
        }
    }

    /* 序列化。
     * 关键：PF_USE_MEMORY **不会** 帮你分配缓冲区——put_entry 里是
     * `if (bytes > fp->len) return 0`，data=NULL/len=0 会在第一次写入就失败，
     * 而且不报错，只表现为 "policydb_write 返回 -1"。
     * 所以必须两趟：先 PF_LEN 只统计长度，再按这个长度分配后真正写。 */
    policy_file_t lenpf;
    policy_file_init(&lenpf);
    lenpf.type = PF_LEN;
    lenpf.len  = 0;
    if (policydb_write(&pol, &lenpf) != 0) {
        fprintf(stderr, "sepol: 计算策略长度失败\n");
        policydb_destroy(&pol);
        free(buf);
        return SP_FAIL;
    }

    size_t cap = lenpf.len;
    char *obuf = malloc(cap ? cap : 1);
    if (!obuf) {
        policydb_destroy(&pol);
        free(buf);
        return SP_FAIL;
    }

    policy_file_t opf;
    policy_file_init(&opf);
    opf.type = PF_USE_MEMORY;
    opf.data = obuf;
    opf.len  = cap;

    int rc = SP_OK;
    if (policydb_write(&pol, &opf) != 0) {
        fprintf(stderr, "sepol: 序列化策略失败\n");
        rc = SP_FAIL;
    } else if (live) {
        int fd = open(SP_SELINUX_LOAD, O_WRONLY);
        if (fd < 0) {
            fprintf(stderr, "sepol: 打不开 %s（内核多半禁止运行时重载）: %s\n",
                    SP_SELINUX_LOAD, strerror(errno));
            rc = SP_FAIL;
        } else {
            /* 注意用 cap：写入过程中 opf.len 会被 put_entry 递减到 0 */
            ssize_t w = write(fd, obuf, cap);
            if (w != (ssize_t)cap) {
                fprintf(stderr, "sepol: 写 %s 不完整（%zd/%zu）: %s\n",
                        SP_SELINUX_LOAD, w, cap, strerror(errno));
                rc = SP_FAIL;
            }
            close(fd);
        }
    } else if (out) {
        if (sp_write_all(out, obuf, cap, 0644) != 0) {
            fprintf(stderr, "sepol: 写不出 %s: %s\n", out, strerror(errno));
            rc = SP_FAIL;
        }
    } else {
        fprintf(stderr, "sepol: 既不是 live 也没给输出路径\n");
        rc = SP_FAIL;
    }

    free(obuf);
    policydb_destroy(&pol);
    free(buf);

    if (rc != SP_OK) return rc;
    if (res && res->failed > 0) return SP_FAIL;
    if (res && res->skipped > 0) return SP_PARTIAL;
    return SP_OK;
}

#endif /* BOSS_HAVE_SEPOL */
