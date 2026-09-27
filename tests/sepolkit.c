/* tests/sepolkit.c —— libsepol 内置后端的端到端验证工具
 *
 * 这个文件**不进主构建**（不在 Makefile 的 SRCS 里），只在需要验证
 * src/sepol_backend.c 时单独编译：
 *
 *   cc -std=gnu11 -Iexternal/libsepol/include -Iexternal/libsepol/src \
 *      -o build/sepolkit tests/sepolkit.c external/libsepol/src/ 下的全部 .c
 *
 * 它解决的是"没真机怎么验"的问题：沙盒/CI 上没有 Android 设备的
 * precompiled_sepolicy，也没有 checkpolicy 可以拿 .te 现编一个。
 * 所以这里用 libsepol 自己的 API 手工搭一个最小但能被
 * policydb_read 读回的 kernel policy，让注入链路能真的跑起来。
 *
 * 用法：
 *   sepolkit make  <out>        造策略（含 domain/file_type 等 attribute）
 *   sepolkit dump  <policy> <type>   打印该 type 的属性归属 / permissive / av 规则
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/handle.h>

static void *zalloc(size_t n) { return calloc(1, n); }

/* ---------------- 构造 ---------------- */

/* 维护 type_attr_map / attr_type_map：write.c 在 policyvers>=20 时按 nprim
 * 逐个 ebitmap_write 出去，NULL 会直接崩，所以构造阶段就得建好。 */
static int grow_maps(policydb_t *pol)
{
    uint32_t n = pol->p_types.nprim;
    ebitmap_t *ta = realloc(pol->type_attr_map, sizeof(*ta) * n);
    if (!ta) return -1;
    pol->type_attr_map = ta;
    ebitmap_t *at = realloc(pol->attr_type_map, sizeof(*at) * n);
    if (!at) return -1;
    pol->attr_type_map = at;
    ebitmap_init(&pol->type_attr_map[n - 1]);
    ebitmap_init(&pol->attr_type_map[n - 1]);
    ebitmap_set_bit(&pol->type_attr_map[n - 1], n - 1, 1);
    ebitmap_set_bit(&pol->attr_type_map[n - 1], n - 1, 1);
    return 0;
}

static int perm_add(class_datum_t *cl, const char *name)
{
    perm_datum_t *p = zalloc(sizeof(*p));
    char *key = strdup(name);
    if (!p || !key) { free(p); free(key); return -1; }
    p->s.value = ++cl->permissions.nprim;
    if (hashtab_insert(cl->permissions.table, key, p) != 0) {
        free(key); free(p);
        return -1;
    }
    return 0;
}

static int class_add(policydb_t *pol, const char *name,
                     const char **perms, int np)
{
    class_datum_t *cl = zalloc(sizeof(*cl));
    if (!cl) return -1;
    if (symtab_init(&cl->permissions, 1u << 8) != 0) { free(cl); return -1; }
    for (int i = 0; i < np; i++)
        if (perm_add(cl, perms[i]) != 0) return -1;

    uint32_t val = ++pol->p_classes.nprim;
    cl->s.value = val;
    if (hashtab_insert(pol->p_classes.table, strdup(name), cl) != 0)
        return -1;
    class_datum_t **nv = realloc(pol->class_val_to_struct,
                                 sizeof(*nv) * pol->p_classes.nprim);
    if (!nv) return -1;
    pol->class_val_to_struct = nv;
    pol->class_val_to_struct[val - 1] = cl;
    return 0;
}

static int type_add(policydb_t *pol, const char *name, int is_attr)
{
    type_datum_t *t = zalloc(sizeof(*t));
    if (!t) return -1;
    t->primary = 1;
    t->flavor = is_attr ? TYPE_ATTRIB : TYPE_TYPE;
    ebitmap_init(&t->types);

    uint32_t val = ++pol->p_types.nprim;
    t->s.value = val;
    if (hashtab_insert(pol->p_types.table, strdup(name), t) != 0)
        return -1;
    type_datum_t **nv = realloc(pol->type_val_to_struct,
                                sizeof(*nv) * pol->p_types.nprim);
    if (!nv) return -1;
    pol->type_val_to_struct = nv;
    pol->type_val_to_struct[val - 1] = t;
    if (grow_maps(pol) != 0) return -1;
    return (int)val;
}

static type_datum_t *type_find(policydb_t *pol, const char *name)
{
    return (type_datum_t *)hashtab_search(pol->p_types.table, name);
}

static int attr_member(policydb_t *pol, const char *aname, const char *tname)
{
    type_datum_t *a = type_find(pol, aname);
    type_datum_t *t = type_find(pol, tname);
    if (!a || !t || a->flavor != TYPE_ATTRIB) return -1;
    ebitmap_set_bit(&a->types, t->s.value - 1, 1);
    ebitmap_set_bit(&pol->type_attr_map[t->s.value - 1], a->s.value - 1, 1);
    ebitmap_set_bit(&pol->attr_type_map[a->s.value - 1], t->s.value - 1, 1);
    return 0;
}

static int role_add(policydb_t *pol, const char *name)
{
    /* policydb_init 可能已经预置了 object_r 这类保留 role，重复插入会拿到
     * SEPOL_EEXIST(-17)，这里先查再插。 */
    if (hashtab_search(pol->p_roles.table, name)) return 0;
    role_datum_t *rd = zalloc(sizeof(*rd));
    if (!rd) return -1;
    ebitmap_init(&rd->dominates);
    ebitmap_init(&rd->types.types);
    ebitmap_init(&rd->cache);
    ebitmap_init(&rd->roles);

    uint32_t val = ++pol->p_roles.nprim;
    rd->s.value = val;
    if (hashtab_insert(pol->p_roles.table, strdup(name), rd) != 0)
        return -1;
    role_datum_t **nv = realloc(pol->role_val_to_struct,
                                sizeof(*nv) * pol->p_roles.nprim);
    if (!nv) return -1;
    pol->role_val_to_struct = nv;
    pol->role_val_to_struct[val - 1] = rd;
    return 0;
}

static int user_add(policydb_t *pol, const char *name)
{
    if (hashtab_search(pol->p_users.table, name)) return 0;
    user_datum_t *ud = zalloc(sizeof(*ud));
    if (!ud) return -1;
    ebitmap_init(&ud->roles.roles);
    ebitmap_init(&ud->cache);

    uint32_t val = ++pol->p_users.nprim;
    ud->s.value = val;
    if (hashtab_insert(pol->p_users.table, strdup(name), ud) != 0)
        return -1;
    user_datum_t **nv = realloc(pol->user_val_to_struct,
                                sizeof(*nv) * pol->p_users.nprim);
    if (!nv) return -1;
    pol->user_val_to_struct = nv;
    pol->user_val_to_struct[val - 1] = ud;
    /* 让这个 user 能用 object_r / r */
    role_datum_t *rr = (role_datum_t *)hashtab_search(pol->p_roles.table, "r");
    role_datum_t *orole = (role_datum_t *)hashtab_search(pol->p_roles.table, "object_r");
    if (rr) ebitmap_set_bit(&ud->roles.roles, rr->s.value - 1, 1);
    if (orole) ebitmap_set_bit(&ud->roles.roles, orole->s.value - 1, 1);
    return 0;
}


/* 插一条 av 规则。
 * 不能省：avtab_read 见到 0 条会直接报 "table is empty" 并拒绝整个策略，
 * 所以造出来的基础策略至少要有一条规则才读得回来（真机策略从来不会是空的）。 */
static int seed_av(policydb_t *pol, const char *src, const char *tgt,
                   const char *cls, const char *perm)
{
    type_datum_t *s = type_find(pol, src);
    type_datum_t *t = type_find(pol, tgt);
    class_datum_t *c = (class_datum_t *)hashtab_search(pol->p_classes.table, cls);
    if (!s || !t || !c) return -1;
    perm_datum_t *p = (perm_datum_t *)hashtab_search(c->permissions.table, perm);
    if (!p) return -1;

    avtab_key_t key;
    memset(&key, 0, sizeof(key));
    key.source_type  = (uint16_t)s->s.value;
    key.target_type  = (uint16_t)t->s.value;
    key.target_class = (uint16_t)c->s.value;
    key.specified    = AVTAB_ALLOWED;

    /* avtab_init 只把 htable 置 NULL，必须先 alloc 才能插入 */
    if (!pol->te_avtab.htable && avtab_alloc(&pol->te_avtab, 64) != 0) return -1;

    avtab_datum_t d;
    memset(&d, 0, sizeof(d));
    d.data = 1u << (p->s.value - 1);
    return avtab_insert(&pol->te_avtab, &key, &d);
}

static int cmd_make(const char *out)
{
    policydb_t pol;
    if (policydb_init(&pol) != 0) { fprintf(stderr, "policydb_init 失败\n"); return 1; }

    pol.policy_type = POLICY_KERN;
    pol.policyvers  = 29;
    pol.mls = 0;
    pol.handle_unknown = ALLOW_UNKNOWN;

    /* ---- object classes（挑 boss.rule 实际会用到的那些） ---- */
    static const char *fp[] = {"read","write","open","getattr","execute","map",
                               "ioctl","lock","append","create","unlink","rename"};
    static const char *dp[] = {"search","read","open","getattr","write","add_name","remove_name"};
    static const char *fsp[] = {"mount","remount","unmount","getattr","relabelfrom"};
    static const char *pp[] = {"transition","fork","execmem","sigchld","setcurrent","getattr"};
    static const char *sp[] = {"read","write","connect","bind","listen","accept","getattr","setopt"};
    static const char *psp[] = {"set"};
    static const char *dap[] = {"search","read","open","getattr"};

    if (class_add(&pol, "file", fp, 12) != 0) return 1;
    if (class_add(&pol, "dir", dp, 7) != 0) return 1;
    if (class_add(&pol, "lnk_file", fp, 12) != 0) return 1;
    if (class_add(&pol, "sock_file", fp, 12) != 0) return 1;
    if (class_add(&pol, "fifo_file", fp, 12) != 0) return 1;
    if (class_add(&pol, "filesystem", fsp, 5) != 0) return 1;
    if (class_add(&pol, "process", pp, 6) != 0) return 1;
    if (class_add(&pol, "unix_stream_socket", sp, 8) != 0) return 1;
    if (class_add(&pol, "property_service", psp, 1) != 0) return 1;
    if (class_add(&pol, "capability", fsp, 5) != 0) return 1;
    if (class_add(&pol, "capability2", dap, 4) != 0) return 1;

    /* ---- attributes ---- */
    static const char *attrs[] = {"domain","file_type","exec_type","data_file_type",
                                  "mlstrustedobject","mlstrustedsubject"};
    for (unsigned i = 0; i < sizeof(attrs)/sizeof(attrs[0]); i++)
        if (type_add(&pol, attrs[i], 1) < 0) return 1;

    /* ---- 具体 type ---- */
    static const char *ts[] = {"init","kernel","shell","toolbox","untrusted_app",
                               "properties_data_file","system_file","vendor_file",
                               "rootfs","init_exec"};
    for (unsigned i = 0; i < sizeof(ts)/sizeof(ts[0]); i++)
        if (type_add(&pol, ts[i], 0) < 0) return 1;

    /* ---- attribute 成员关系（attribute 展开测试的靶子） ---- */
    const char *in_domain[] = {"init","kernel","shell","toolbox","untrusted_app"};
    for (unsigned i = 0; i < 5; i++) attr_member(&pol, "domain", in_domain[i]);

    const char *in_ft[] = {"properties_data_file","system_file","vendor_file","rootfs","init_exec"};
    for (unsigned i = 0; i < 5; i++) attr_member(&pol, "file_type", in_ft[i]);

    attr_member(&pol, "exec_type", "init_exec");
    attr_member(&pol, "data_file_type", "properties_data_file");
    attr_member(&pol, "mlstrustedobject", "properties_data_file");

    /* ---- roles / users ---- */
    if (role_add(&pol, "r") != 0) return 1;
    if (role_add(&pol, "object_r") != 0) return 1;
    if (user_add(&pol, "u") != 0) return 1;

    /* ---- 种子规则（avtab 不能为空，否则读不回来） ---- */
    if (seed_av(&pol, "init", "init", "process", "fork") != 0)
        return 1;

    /* ---- 写盘 ---- */
    /* 两趟写：PF_LEN 先算长度，再分配后真正写。
     * （PF_USE_MEMORY 不负责分配，这个坑在 sepol_backend.c 里一样存在。） */
    policy_file_t lp;
    policy_file_init(&lp);
    lp.type = PF_LEN;
    lp.len = 0;
    lp.handle = sepol_handle_create();
    if (policydb_write(&pol, &lp) != 0) {
        fprintf(stderr, "计算长度失败\n");
        return 1;
    }
    size_t cap = lp.len;
    char *ob = malloc(cap ? cap : 1);
    if (!ob) { fprintf(stderr, "OOM\n"); return 1; }

    policy_file_t pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = ob;
    pf.len = cap;
    pf.handle = sepol_handle_create();
    if (policydb_write(&pol, &pf) != 0) {
        fprintf(stderr, "policydb_write 失败\n");
        return 1;
    }
    FILE *f = fopen(out, "we");
    if (!f) { fprintf(stderr, "写不出 %s: %s\n", out, strerror(errno)); return 1; }
    if (fwrite(ob, 1, cap, f) != cap) { fclose(f); return 1; }
    fclose(f);

    printf("已生成 %s（%zu 字节，policyvers=%u，types=%u，classes=%u）\n",
           out, cap, pol.policyvers, pol.p_types.nprim, pol.p_classes.nprim);
    policydb_destroy(&pol);
    free(ob);
    return 0;
}

/* ---------------- 读取校验 ---------------- */

struct perm_names { const char *n[40]; unsigned char used; };

static int perm_collect(hashtab_key_t k, hashtab_datum_t d, void *args)
{
    struct perm_names *pn = args;
    perm_datum_t *p = (perm_datum_t *)d;
    if (p->s.value >= 1 && p->s.value <= 40) {
        pn->n[p->s.value - 1] = (const char *)k;
        pn->used = 1;
    }
    return 0;
}

struct find_ctx { hashtab_datum_t want; char name[128]; };

static int find_by_datum(hashtab_key_t k, hashtab_datum_t d, void *args)
{
    struct find_ctx *c = args;
    if (d == c->want) { snprintf(c->name, sizeof(c->name), "%s", (const char *)k); return 1; }
    return 0;
}

static void name_by_value(policydb_t *pol, uint32_t val, char *out, size_t n)
{
    if (val == 0 || val > pol->p_types.nprim) { snprintf(out, n, "?"); return; }
    struct find_ctx c;
    c.want = (hashtab_datum_t)pol->type_val_to_struct[val - 1];
    c.name[0] = '\0';
    hashtab_map(pol->p_types.table, find_by_datum, &c);
    snprintf(out, n, "%s", c.name[0] ? c.name : "?");
}

/* 列出某个 attribute 的全部成员。
 * attribute 展开是注入里最容易静默出错的一环（成员少一个不会报错），
 * 必须有办法直接看到"这个 attribute 到底有几个人"。 */
static int cmd_attr(const char *path, const char *aname)
{
    char *buf = NULL; size_t len = 0;
    FILE *f = fopen(path, "re");
    if (!f) { fprintf(stderr, "读不到 %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    buf = malloc((size_t)sz + 1);
    len = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    policydb_t pol;
    policydb_init(&pol);
    policy_file_t pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = buf;
    pf.len = len;
    if (policydb_read(&pol, &pf, 0) != 0) { fprintf(stderr, "解析失败\n"); return 1; }

    type_datum_t *a = type_find(&pol, aname);
    if (!a) { printf("ATTR %s (不存在)\n", aname); return 0; }
    if (a->flavor != TYPE_ATTRIB) { printf("ATTR %s 不是 attribute\n", aname); return 0; }

    printf("ATTR %s value=%u members:", aname, a->s.value);
    char nm[128];
    ebitmap_node_t *node = NULL;
    unsigned int bit = 0;
    ebitmap_for_each_bit(&a->types, node, bit) {
        if (!ebitmap_get_bit(&a->types, bit)) continue;
        name_by_value(&pol, bit + 1, nm, sizeof(nm));
        printf(" %s", nm);
    }
    printf("\n");
    return 0;
}

static int cmd_dump(const char *path, const char *who)
{
    char *buf = NULL; size_t len = 0;
    FILE *f = fopen(path, "re");
    if (!f) { fprintf(stderr, "读不到 %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    buf = malloc((size_t)sz + 1);
    len = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    policydb_t pol;
    if (policydb_init(&pol) != 0) return 1;
    policy_file_t pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = buf;
    pf.len = len;
    if (policydb_read(&pol, &pf, 0) != 0) {
        fprintf(stderr, "解析 %s 失败（说明它是个坏策略）\n", path);
        return 1;
    }

    printf("POLICY vers=%u types=%u classes=%u\n",
           pol.policyvers, pol.p_types.nprim, pol.p_classes.nprim);

    type_datum_t *t = type_find(&pol, who);
    if (!t) {
        printf("TYPE %s (不存在)\n", who);
        policydb_destroy(&pol);
        free(buf);
        return 0;
    }
    printf("TYPE %s value=%u flavor=%s\n", who, t->s.value,
           t->flavor == TYPE_ATTRIB ? "attribute" : "type");

    /* attribute 归属 */
    printf("ATTRS");
    char nm[128];
    if (pol.type_attr_map) {
        ebitmap_node_t *node = NULL;
        unsigned int bit = 0;
        ebitmap_for_each_bit(&pol.type_attr_map[t->s.value - 1], node, bit) {
            if (!ebitmap_get_bit(&pol.type_attr_map[t->s.value - 1], bit)) continue;
            name_by_value(&pol, bit + 1, nm, sizeof(nm));
            if (strcmp(nm, who)) printf(" %s", nm);
        }
    }
    printf("\n");

    /* permissive */
    int perm = 0;
    if (ebitmap_get_bit(&pol.permissive_map, t->s.value)) perm = 1;
    printf("PERMISSIVE %s\n", perm ? "yes" : "no");

    /* av 规则：source == 该 type，按 tgt/class 打印权限名 */
    for (uint32_t i = 0; i < pol.te_avtab.nslot; i++) {
        for (avtab_ptr_t cur = pol.te_avtab.htable[i]; cur; cur = cur->next) {
            if (cur->key.source_type != t->s.value) continue;
            if (cur->key.specified != AVTAB_ALLOWED) continue;
            if (cur->datum.data == 0) continue;

            char tn[128], cn[128];
            name_by_value(&pol, cur->key.target_type, tn, sizeof(tn));

            class_datum_t *cd = NULL;
            if (cur->key.target_class >= 1 &&
                cur->key.target_class <= pol.p_classes.nprim)
                cd = pol.class_val_to_struct[cur->key.target_class - 1];
            snprintf(cn, sizeof(cn), "%s", cd ? "?" : "?");
            if (cd) {
                struct find_ctx fc;
                fc.want = (hashtab_datum_t)cd;
                fc.name[0] = '\0';
                hashtab_map(pol.p_classes.table, find_by_datum, &fc);
                snprintf(cn, sizeof(cn), "%s", fc.name[0] ? fc.name : "?");
            }

            struct perm_names pn;
            memset(&pn, 0, sizeof(pn));
            if (cd) hashtab_map(cd->permissions.table, perm_collect, &pn);

            printf("AV %s %s", tn, cn);
            for (int b = 0; b < 32; b++) {   /* 权限位最大 32，超过就是移位回绕的假命中 */
                if (cur->datum.data & (1u << b)) {
                    if (b < 40 && pn.n[b]) printf(" %s", pn.n[b]);
                    else printf(" bit%d", b);
                }
            }
            printf("\n");
        }
    }

    policydb_destroy(&pol);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "用法:\n"
                "  %s make <out>\n"
                "  %s dump <policy> <type>\n"
                "  %s attr <policy> <attribute>\n", argv[0], argv[0], argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "make")) return cmd_make(argv[2]);
    if (!strcmp(argv[1], "attr") && argc >= 4) return cmd_attr(argv[2], argv[3]);
    if (!strcmp(argv[1], "dump") && argc >= 4) return cmd_dump(argv[2], argv[3]);
    fprintf(stderr, "未知子命令: %s\n", argv[1]);
    return 2;
}
