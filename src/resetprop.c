/* B1 · resetprop —— 属性改写
 *
 * 为什么必须自己写：init 的 property_service 会拒绝两件事
 *   1) 改 ro.* 开头的只读属性
 *   2) 删除属性
 * 而任务5「无修改系统逻辑 + 特典逻辑」的弹药几乎全是这两件事。
 *
 * 原理（已对照 AOSP bionic 源码核实，不是猜的）：
 *   init 把属性放在 /dev/__properties__ 下的一组 128KB 共享内存文件里，
 *   每块是一个 prop_area，内部是 hybrid trie（按 '.' 分段建 trie，
 *   同层兄弟用二叉搜索树）。普通进程只能走 socket 求 property_service；
 *   我们直接 mmap 这块内存并改 prop_info，绕开 property_service。
 *
 * 核对过的关键常量（bionic/libc/system_properties/prop_area.cpp）：
 *   PA_SIZE          = 128 * 1024
 *   PROP_AREA_MAGIC  = 0x504f5250
 *   PROP_AREA_VERSION= 0xfc6ed0ab
 *   serial 编码      = (value_len << 24) | (serial & 0xffffff)，bit0 是 dirty 位
 *   prop_info        = 96 字节（serial 4 + value 92）+ 变长 name
 *
 * 三个开关的语义（别搞混，混了会死锁开机）：
 *   默认    走 property_service（先删再设）→ 会触发 on property: 事件
 *   -n      直写 prop_area           → 不触发事件，post-fs-data 阶段必须用
 *   -p      同时作用于 /data/property 持久化存储（配合 persist.*）
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "boss.h"

/* bionic 的 property_service 入口。弱符号：静态链接 / 非 Android 上可能为 NULL，
 * 那时自动退化成直写（见 setprop_with_trigger）。 */
extern int __system_property_set(const char *name, const char *value)
    __attribute__((weak));

#define PA_SIZE          (128u * 1024u)
#define PA_MAGIC         0x504f5250u
#define PA_VERSION       0xfc6ed0abu
#define PROP_VALUE_MAX   92
#define PROP_NAME_MAX    32
#define PA_HEADER_SIZE   128          /* sizeof(struct prop_area) */
#define PA_MAX_AREAS     64
#define SERIAL_DIRTY(s)  ((s) & 1)
#define SERIAL_LEN(s)    ((s) >> 24)

struct prop_area {
    uint32_t bytes_used_;
    uint32_t serial_;
    uint32_t magic_;
    uint32_t version_;
    uint32_t reserved_[28];
    char data_[];
};

struct prop_trie_node {
    uint32_t namelen;
    uint32_t prop;
    uint32_t left;
    uint32_t right;
    uint32_t children;
    char name[];
};

struct prop_info {
    uint32_t serial;
    char value[PROP_VALUE_MAX];
    char name[];
};

/* 布局断言：这三个结构是与 init 共享内存的二进制契约，尺寸不对不会崩溃，
 * 而是**静默读错值**——最坏的一类 bug。所以放在编译期拦。
 * bionic 侧原话：static_assert(sizeof(prop_info) == 96)。
 * 用 typedef char[N] 而不是 _Static_assert，是为了 c99 也能编（CI 逐个标准跑）。 */
typedef char boss_assert_prop_info_96[(sizeof(struct prop_info) == 96) ? 1 : -1];
typedef char boss_assert_trie_node_20[(sizeof(struct prop_trie_node) == 20) ? 1 : -1];
typedef char boss_assert_pa_header_128[(sizeof(struct prop_area) == 128) ? 1 : -1];

struct pa_map {
    char path[384];
    char ctx[320];              /* 文件名即 SELinux context */
    struct prop_area *pa;
    size_t size;
    int rw;
};

struct prop_ctx {
    struct pa_map maps[PA_MAX_AREAS];
    int n;
    struct pa_map *serial;      /* properties_serial：全局 serial 在这里 */
};

/* ---------------- 基础存取（全部按 AOSP 语义） ---------------- */

static size_t pa_data_size(const struct pa_map *m)
{
    return m->size > PA_HEADER_SIZE ? m->size - PA_HEADER_SIZE : 0;
}

static void *pa_obj(const struct pa_map *m, uint32_t off)
{
    if (off == 0) return NULL;
    if (off > pa_data_size(m)) return NULL;      /* 越界保护：坏偏移不能解引用 */
    return m->pa->data_ + off;
}

static struct prop_trie_node *pa_node(const struct pa_map *m, uint32_t off)
{
    return (struct prop_trie_node *)pa_obj(m, off);
}

static struct prop_info *pa_info(const struct pa_map *m, uint32_t off)
{
    return (struct prop_info *)pa_obj(m, off);
}

static struct prop_trie_node *pa_root(const struct pa_map *m)
{
    return (struct prop_trie_node *)m->pa->data_;   /* root_node() = data_ + 0 */
}

static uint32_t ld32(const uint32_t *p)
{
    return __atomic_load_n((uint32_t *)p, __ATOMIC_RELAXED);
}

static void st32(uint32_t *p, uint32_t v)
{
    __atomic_store_n(p, v, __ATOMIC_RELAXED);
}

/* AOSP cmp_prop_name：先比长度，再 strncmp */
static int cmp_name(const char *a, uint32_t alen, const char *b, uint32_t blen)
{
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return strncmp(a, b, alen);
}

/* 在二叉搜索树里找 token 节点 */
static struct prop_trie_node *find_trie_node(const struct pa_map *m,
                                             struct prop_trie_node *trie,
                                             const char *name, uint32_t namelen)
{
    struct prop_trie_node *cur = trie;
    while (cur) {
        int r = cmp_name(name, namelen, cur->name, cur->namelen);
        if (r == 0) return cur;
        uint32_t off = r < 0 ? ld32(&cur->left) : ld32(&cur->right);
        cur = pa_node(m, off);
    }
    return NULL;
}

/* AOSP find_property：按 '.' 分段，每段在 children 的 BST 里找 */
static struct prop_info *find_property(const struct pa_map *m, const char *name)
{
    const char *remaining = name;
    struct prop_trie_node *cur = pa_root(m);

    while (1) {
        const char *sep = strchr(remaining, '.');
        int want_subtree = (sep != NULL);
        uint32_t seg = want_subtree ? (uint32_t)(sep - remaining)
                                    : (uint32_t)strlen(remaining);
        if (seg == 0) return NULL;

        uint32_t children_off = ld32(&cur->children);
        struct prop_trie_node *root = pa_node(m, children_off);
        if (!root) return NULL;

        cur = find_trie_node(m, root, remaining, seg);
        if (!cur) return NULL;

        if (!want_subtree) break;
        remaining = sep + 1;
    }

    return pa_info(m, ld32(&cur->prop));
}

/* ---------------- 区域管理 ---------------- */

static int map_one(struct prop_ctx *c, const char *dir, const char *fname)
{
    if (c->n >= PA_MAX_AREAS) return -1;
    struct pa_map *m = &c->maps[c->n];
    snprintf(m->path, sizeof(m->path), "%s/%s", dir, fname);
    snprintf(m->ctx, sizeof(m->ctx), "%s", fname);

    int fd = open(m->path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fd = open(m->path, O_RDONLY | O_CLOEXEC);   /* 只读兜底：至少能读 */
        if (fd < 0) return -1;
        m->rw = 0;
    } else {
        m->rw = 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)PA_HEADER_SIZE) { close(fd); return -1; }
    m->size = (size_t)st.st_size;

    void *p = mmap(NULL, m->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return -1;

    struct prop_area *pa = (struct prop_area *)p;
    if (ld32(&pa->magic_) != PA_MAGIC || ld32(&pa->version_) != PA_VERSION) {
        munmap(p, m->size);
        return -1;
    }

    m->pa = pa;
    c->n++;
    if (!strcmp(fname, BOSS_PROP_SERIAL)) c->serial = m;
    return 0;
}

static int ctx_open(struct prop_ctx *c, const char *dir)
{
    memset(c, 0, sizeof(*c));
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        /* 只认普通文件：目录/链接不参与 */
        char full[384];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        map_one(c, dir, e->d_name);
    }
    closedir(d);
    return c->n > 0 ? 0 : -1;
}

static void ctx_close(struct prop_ctx *c)
{
    for (int i = 0; i < c->n; i++) {
        if (c->maps[i].pa) munmap(c->maps[i].pa, c->maps[i].size);
    }
    c->n = 0;
    c->serial = NULL;
}

static struct pa_map *ctx_find(struct prop_ctx *c, const char *name,
                               struct prop_info **out)
{
    for (int i = 0; i < c->n; i++) {
        struct prop_info *pi = find_property(&c->maps[i], name);
        if (pi) {
            if (out) *out = pi;
            return &c->maps[i];
        }
    }
    return NULL;
}

/* ---------------- 写入（严格照抄 AOSP Update 的顺序） ---------------- */

/* 全局 serial 区域（properties_serial）：改完属性要自增它，读者才会醒 */
static struct pa_map *c_serial_pa;

static void futex_wake(volatile uint32_t *addr)
{
#ifdef SYS_futex
    syscall(SYS_futex, (void *)addr, 1 /*FUTEX_WAKE*/, 0x7fffffff, NULL, NULL, 0);
#else
    (void)addr;
#endif
}

/* 把值写进 prop_info，并按约定更新 serial。
 * len==0 就是"删除"：读侧拿到的长度为 0，等价于属性不存在。 */
static int pi_update(struct pa_map *m, struct prop_info *pi, const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len >= PROP_VALUE_MAX) {
        fprintf(stderr, "resetprop: 值过长（%zu >= %d），已截断\n", len, PROP_VALUE_MAX);
        len = PROP_VALUE_MAX - 1;
    }

    uint32_t serial = ld32(&pi->serial);
    uint32_t old_len = SERIAL_LEN(serial);
    char *dirty = m->pa->data_ + sizeof(struct prop_trie_node);   /* dirty_backup_area */

    /* 1) 老值先备份到 dirty area，读者看到 dirty 位就去那儿取 */
    if (old_len >= PROP_VALUE_MAX) old_len = PROP_VALUE_MAX - 1;
    memcpy(dirty, pi->value, old_len + 1);
    __atomic_thread_fence(__ATOMIC_RELEASE);

    /* 2) 置 dirty 位再写值 */
    st32(&pi->serial, serial | 1u);
    if (len) memcpy(pi->value, value, len);
    pi->value[len] = '\0';
    __atomic_thread_fence(__ATOMIC_RELEASE);

    /* 3) 新 serial = (len << 24) | (((serial|1) + 1) & 0xffffff)
     * 注意 AOSP 这里的 serial 是"已经置过 dirty 位"的那个值：
     *   serial |= 1; 之后再 +1，正好把 dirty 位清掉。
     * 直接用原始 serial + 1 会算出一个奇数（dirty 仍为 1），
     * 读侧就会一直去 dirty backup area 取旧值——表现为"改了但读回来还是老的"。 */
    uint32_t new_serial = ((uint32_t)len << 24) | (((serial | 1u) + 1u) & 0xffffffu);
    st32(&pi->serial, new_serial);
    futex_wake(&pi->serial);

    /* 4) 全局 serial 自增，让等属性的读者醒来 */
    if (m->pa) st32(&m->pa->serial_, ld32(&m->pa->serial_) + 1u);
    if (c_serial_pa) st32(&c_serial_pa->pa->serial_, ld32(&c_serial_pa->pa->serial_) + 1u);
    return 0;
}

/* ---------------- 新增属性（属性原本不存在） ---------------- */

/* 属性该落哪个区域，由 property_contexts 决定：放错区域 = 读不到。
 * 这里做一个务实的最长匹配：精确 > 最长通配。 */
struct pc_rule { char pat[PROP_NAME_MAX * 4]; char ctx[320]; };

static int pc_match(const char *pat, const char *name)
{
    /* 只支持 AOSP property_contexts 常用的三种形态：
     *   精确：ro.foo
     *   前缀：ro.foo.     （AOSP 里以 '.' 结尾表示前缀）
     *   通配：* .* ro.*    */
    size_t pl = strlen(pat);
    if (pl == 0) return 0;

    if (pat[pl - 1] == '.') {
        return strncmp(name, pat, pl) == 0 ? (int)pl : 0;
    }
    if (!strcmp(pat, "*") || !strcmp(pat, ".*")) return 1;

    if (strchr(pat, '*') == NULL && strchr(pat, '.') == pat + pl - 1) return 0;

    /* 简化通配：把 '*' 当任意串，'.' 当字面点 */
    size_t i = 0, j = 0;
    while (i < pl && name[j]) {
        if (pat[i] == '*') {
            /* 单个 '*' 吞到下一个能匹配的位置 */
            i++;
            if (i == pl) return 1;
            while (name[j] && name[j] != pat[i]) j++;
            if (!name[j]) return 0;
        } else if (pat[i] == name[j]) {
            i++; j++;
        } else {
            return 0;
        }
    }
    while (i < pl && pat[i] == '*') i++;
    return (i == pl && !name[j]) ? 1 : 0;
}

static const char *pc_files[] = {
    "/system/etc/selinux/plat_property_contexts",
    "/system_ext/etc/selinux/system_ext_property_contexts",
    "/product/etc/selinux/product_property_contexts",
    "/vendor/etc/selinux/vendor_property_contexts",
    "/odm/etc/selinux/odm_property_contexts",
    "/property_contexts",
    NULL
};

/* 返回适合该属性名的区域；找不到就给"兜底区域"（第一个非 serial 区域） */
static struct pa_map *pick_area(struct prop_ctx *c, const char *name)
{
    char want[320] = { 0 };
    int best = -1;

    for (int f = 0; pc_files[f]; f++) {
        FILE *fp = fopen(pc_files[f], "re");
        if (!fp) continue;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            char *h = strchr(line, '#');
            if (h) *h = '\0';
            char pat[256] = { 0 }, ctx[320] = { 0 };
            if (sscanf(line, "%255s %191s", pat, ctx) != 2) continue;
            int score = pc_match(pat, name);
            if (score > 0 && (best < 0 || score > best)) {
                best = score;
                snprintf(want, sizeof(want), "%s", ctx);
            }
        }
        fclose(fp);
    }

    if (want[0]) {
        for (int i = 0; i < c->n; i++) {
            if (!strcmp(c->maps[i].ctx, want)) return &c->maps[i];
        }
    }
    for (int i = 0; i < c->n; i++) {
        if (strcmp(c->maps[i].ctx, BOSS_PROP_SERIAL) != 0)
            return &c->maps[i];
    }
    return c->n > 0 ? &c->maps[0] : NULL;
}

/* 在区域尾部追加对象（照抄 allocate_obj：4 字节对齐 + 容量检查） */
static void *pa_alloc(struct pa_map *m, size_t size, uint32_t *off)
{
    size_t aligned = (size + 3u) & ~((size_t)3u);
    uint32_t used = ld32(&m->pa->bytes_used_);
    if ((size_t)used + aligned > pa_data_size(m)) return NULL;
    *off = used;
    st32(&m->pa->bytes_used_, used + (uint32_t)aligned);
    char *p = m->pa->data_ + used;
    memset(p, 0, aligned);
    return p;
}

/* 建一个新的 trie 节点（name 段），并挂到 parent 的 children 或兄弟 BST 上 */
static struct prop_trie_node *pa_new_node(struct pa_map *m, const char *seg,
                                          uint32_t seglen, uint32_t *off)
{
    struct prop_trie_node *n = pa_alloc(m, sizeof(struct prop_trie_node) + seglen + 1, off);
    if (!n) return NULL;
    n->namelen = seglen;
    memcpy(n->name, seg, seglen);
    n->name[seglen] = '\0';
    return n;
}

static struct prop_info *pa_add(struct prop_ctx *c, struct pa_map *m,
                                const char *name, const char *value)
{
    (void)c;
    if (!m->rw) {
        fprintf(stderr, "resetprop: 区域 %s 不可写，无法新增属性\n", m->ctx);
        return NULL;
    }

    struct prop_trie_node *cur = pa_root(m);
    const char *remaining = name;

    while (1) {
        const char *sep = strchr(remaining, '.');
        int want_subtree = (sep != NULL);
        uint32_t seg = want_subtree ? (uint32_t)(sep - remaining)
                                    : (uint32_t)strlen(remaining);
        if (seg == 0) return NULL;

        uint32_t children_off = ld32(&cur->children);
        struct prop_trie_node *root = pa_node(m, children_off);

        if (!root) {
            uint32_t noff;
            root = pa_new_node(m, remaining, seg, &noff);
            if (!root) return NULL;
            st32(&cur->children, noff);
            cur = root;
        } else {
            /* 走 BST：找到位置后挂上去 */
            struct prop_trie_node *p = root;
            while (1) {
                int r = cmp_name(remaining, seg, p->name, p->namelen);
                if (r == 0) { cur = p; break; }
                uint32_t *slot = (r < 0) ? &p->left : &p->right;
                uint32_t off = ld32(slot);
                if (off == 0) {
                    uint32_t noff;
                    struct prop_trie_node *nn = pa_new_node(m, remaining, seg, &noff);
                    if (!nn) return NULL;
                    st32(slot, noff);
                    cur = nn;
                    break;
                }
                p = pa_node(m, off);
                if (!p) return NULL;
            }
        }

        if (!want_subtree) break;
        remaining = sep + 1;
    }

    uint32_t ioff;
    struct prop_info *pi = pa_alloc(m, sizeof(struct prop_info) + strlen(name) + 1, &ioff);
    if (!pi) return NULL;
    strcpy(pi->name, name);
    st32(&cur->prop, ioff);

    /* 首次写入：长度先置 0，再走正常 update 流程，保证 serial 递增语义正确 */
    st32(&pi->serial, 0);
    pi_update(m, pi, value);
    return pi;
}

/* ---------------- persist 持久化 ----------------
 * 三条路都走，互相兜底：
 *   1) /data/property/persistent_properties（protobuf，Android 8+）
 *   2) /data/property/<name>（legacy，一属性一文件）
 *   3) BOSS 自己的 persist.props 快照，由 post-fs-data 重放
 * 第 3 条是我们能保证生效的一条：前两条都依赖 init 的实现细节，
 * 而"快照 + 每次开机重放"在任何设备上都成立。
 */

static int pb_get_varint(const uint8_t *p, size_t len, size_t *i, uint32_t *out)
{
    uint32_t v = 0; int shift = 0;
    while (*i < len && shift < 32) {
        uint8_t b = p[(*i)++];
        v |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) { *out = v; return 0; }
        shift += 7;
    }
    return -1;
}

static void pb_put_varint(char *buf, size_t *n, uint32_t v)
{
    while (v >= 0x80) { buf[(*n)++] = (char)((v & 0x7f) | 0x80); v >>= 7; }
    buf[(*n)++] = (char)v;
}

/* 改写 persistent_properties：删掉同名记录，若给了 value 再追加一条。
 * 文件格式（已核对 AOSP persistent_properties.proto）：
 *   message PersistentProperties { repeated PersistentPropertyRecord properties = 1; }
 *   message PersistentPropertyRecord { optional string name = 1; optional string value = 2; } */
static int persist_db_update(const char *name, const char *value)
{
    FILE *fp = fopen(BOSS_PERSIST_DB, "re");
    if (!fp) return -1;
    char *buf = NULL; size_t len = 0;
    /* 简单读全文件 */
    {
        char tmp[4096]; size_t r;
        while ((r = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
            char *nb = realloc(buf, len + r + 1);
            if (!nb) { free(buf); fclose(fp); return -1; }
            buf = nb; memcpy(buf + len, tmp, r); len += r;
        }
    }
    fclose(fp);

    char out[65536]; size_t on = 0;
    const uint8_t *p = (const uint8_t *)buf;
    size_t i = 0;
    while (i < len) {
        uint32_t tag;
        size_t save = i;
        if (pb_get_varint(p, len, &i, &tag) < 0) break;
        if ((tag >> 3) != 1 || (tag & 7) != 2) break;      /* 结构不认识：放弃改写 */
        uint32_t rlen;
        if (pb_get_varint(p, len, &i, &rlen) < 0 || i + rlen > len) break;
        const uint8_t *rp = p + i;
        size_t ri = 0, rsize = rlen;
        char rname[PROP_NAME_MAX * 4] = { 0 };
        int keep = 1;
        while (ri < rsize) {
            uint32_t rtag;
            if (pb_get_varint(rp, rsize, &ri, &rtag) < 0) { keep = -1; break; }
            uint32_t slen;
            if (pb_get_varint(rp, rsize, &ri, &slen) < 0 || ri + slen > rsize) { keep = -1; break; }
            if ((rtag >> 3) == 1) snprintf(rname, sizeof(rname), "%.*s", (int)slen, rp + ri);
            ri += slen;
        }
        if (keep < 0) break;
        if (rname[0] && !strcmp(rname, name)) keep = 0;
        if (keep && on + (i - save) < sizeof(out)) {
            memcpy(out + on, buf + save, i - save); on += (i - save);
        }
        i += rlen;
    }
    free(buf);

    /* 追加新记录（protobuf 允许重复字段放在任意位置） */
    if (value) {
        char rec[1024];
        size_t rn = 0;
        size_t nl = strlen(name), vl = strlen(value);
        if (nl + vl + 32 < sizeof(rec)) {
            pb_put_varint(rec, &rn, (1u << 3) | 2u);            /* name: field1, LEN */
            pb_put_varint(rec, &rn, (uint32_t)nl);
            memcpy(rec + rn, name, nl); rn += nl;
            pb_put_varint(rec, &rn, (2u << 3) | 2u);            /* value: field2, LEN */
            pb_put_varint(rec, &rn, (uint32_t)vl);
            memcpy(rec + rn, value, vl); rn += vl;

            if (on + rn + 16 < sizeof(out)) {
                pb_put_varint(out, &on, (1u << 3) | 2u);        /* properties: field1, LEN */
                pb_put_varint(out, &on, (uint32_t)rn);
                memcpy(out + on, rec, rn); on += rn;
            }
        }
    }

    char tmp[384];
    snprintf(tmp, sizeof(tmp), "%s.tmp", BOSS_PERSIST_DB);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (boss_write_full(fd, out, on) < 0) { close(fd); return -1; }
    close(fd);
    return rename(tmp, BOSS_PERSIST_DB) == 0 ? 0 : -1;
}

/* 去掉行尾空白与 CR。属性名带一个尾随空格会让整条设置写到另一个属性上，
 * 表现为"导入了但目标属性没变"——这类 bug 在真机上极难排查。 */
static void rstrip(char *s)
{
    size_t l = strlen(s);
    while (l > 0 && (s[l - 1] == ' ' || s[l - 1] == '\t' || s[l - 1] == '\r')) s[--l] = '\0';
}

/* 取快照一行的属性名："!name" 或 "name=value" */
static void snapshot_key(const char *line, char *out, size_t n)
{
    const char *k = (*line == '!') ? line + 1 : line;
    const char *eq = strchr(k, '=');
    size_t len = eq ? (size_t)(eq - k) : strlen(k);
    if (len >= n) len = n - 1;
    memcpy(out, k, len);
    out[len] = '\0';
}

/* BOSS 快照：name=value 重放设置，!name 重放删除 */
static int snapshot_mark(const char *name, const char *value)
{
    if (strncmp(name, "persist.", 8) != 0) return 0;

    FILE *fp = fopen(BOSS_PERSIST_FILE, "re");
    char out[65536]; size_t on = 0;
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
            rstrip(line);
            char key[PROP_NAME_MAX * 4];
            snapshot_key(line, key, sizeof(key));
            if (!strcmp(key, name)) continue;      /* 覆盖掉同一属性的旧记录 */
            if (on + strlen(line) + 2 < sizeof(out)) {
                on += (size_t)snprintf(out + on, sizeof(out) - on, "%s\n", line);
            }
        }
        fclose(fp);
    }
    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp", BOSS_PERSIST_FILE);
    FILE *w = fopen(tmp, "we");
    if (!w) return -1;
    fwrite(out, 1, on, w);
    if (value) fprintf(w, "%s=%s\n", name, value);
    else       fprintf(w, "!%s\n", name);
    fclose(w);
    chmod(tmp, 0600);
    return rename(tmp, BOSS_PERSIST_FILE) == 0 ? 0 : -1;
}

static void persist_apply(const char *name, const char *value, int verbose)
{
    if (strncmp(name, "persist.", 8) != 0) return;

    /* 1) protobuf 库 */
    if (persist_db_update(name, value) == 0 && verbose)
        fprintf(stderr, "resetprop: 已更新 %s 中的 %s\n", BOSS_PERSIST_DB, name);

    /* 2) legacy 单文件 */
    char path[384];
    snprintf(path, sizeof(path), "%s/%s", BOSS_PERSIST_DIR, name);
    unlink(path);
    if (value) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0) { boss_write_full(fd, value, strlen(value)); close(fd); }
    }

    /* 3) BOSS 快照（保证生效的那条） */
    snapshot_mark(name, value);
}

/* ---------------- 命令实现 ---------------- */

static void usage(void)
{
    fprintf(stderr,
        "用法: boss resetprop [选项] NAME [VALUE]\n"
        "  NAME          只给名字 = 读取\n"
        "  NAME VALUE    设置\n"
        "  -n            直写属性区，不触发 on property: 事件（post-fs-data 必用）\n"
        "  -p            同时作用于 persist 持久化存储（配合 persist.*）\n"
        "  -d, --delete  删除属性\n"
        "  -v            啰嗦输出\n"
        "      --file F  从文件批量读取 key=value（模块 system.prop 用）\n"
        "      --dir D   指定属性区目录（默认 %s，测试用）\n", BOSS_PROP_DIR);
}

static int do_set(struct prop_ctx *c, const char *name, const char *value,
                  int no_event, int persist, int verbose)
{
    struct prop_info *pi = NULL;
    struct pa_map *m = ctx_find(c, name, &pi);

    /* 触发 rc 事件的路径：先直写把老值清掉，再走 property_service 设置。
     * 这样 on property:foo=bar 一定会收到一次"变化"。 */
    if (!no_event && __system_property_set) {
        if (m && pi) pi_update(m, pi, "");     /* 直写清空，不触发 */
        if (__system_property_set(name, value) == 0) {
            if (verbose) fprintf(stderr, "resetprop: 经 property_service 设置 %s\n", name);
            if (persist) persist_apply(name, value, verbose);
            return 0;
        }
        if (verbose)
            fprintf(stderr, "resetprop: property_service 拒绝（%s），回退直写\n", name);
    }

    if (!m) {
        /* 属性不存在：必须放到 property_contexts 指定的区域，否则读不到 */
        struct pa_map *target = pick_area(c, name);
        if (!target) { fprintf(stderr, "resetprop: 没有可用的属性区\n"); return 1; }
        pi = pa_add(c, target, name, value);
        if (!pi) { fprintf(stderr, "resetprop: 属性区已满，无法新增 %s\n", name); return 1; }
        if (verbose) fprintf(stderr, "resetprop: 新增 %s 于 %s\n", name, target->ctx);
    } else {
        if (!m->rw) { fprintf(stderr, "resetprop: 区域 %s 只读\n", m->ctx); return 1; }
        pi_update(m, pi, value);
    }

    if (persist) persist_apply(name, value, verbose);
    return 0;
}

static int do_delete(struct prop_ctx *c, const char *name, int persist, int verbose)
{
    struct prop_info *pi = NULL;
    struct pa_map *m = ctx_find(c, name, &pi);
    if (!m || !pi) {
        fprintf(stderr, "resetprop: 属性不存在: %s\n", name);
        return 1;
    }
    if (!m->rw) { fprintf(stderr, "resetprop: 区域 %s 只读\n", m->ctx); return 1; }

    /* 删除 = 把值长度写成 0：读侧拿到长度 0，等价于属性不存在 */
    pi_update(m, pi, "");
    if (verbose) fprintf(stderr, "resetprop: 已删除 %s\n", name);

    if (persist) persist_apply(name, NULL, verbose);
    return 0;
}

static int do_get(struct prop_ctx *c, const char *name)
{
    struct prop_info *pi = NULL;
    struct pa_map *m = ctx_find(c, name, &pi);
    if (!m || !pi) return 1;

    uint32_t serial = ld32(&pi->serial);
    char value[PROP_VALUE_MAX + 1];
    /* dirty 位被置起时，正确的值在 dirty backup area（照 bionic 的读法） */
    if (SERIAL_DIRTY(serial)) {
        char *dirty = m->pa->data_ + sizeof(struct prop_trie_node);
        snprintf(value, sizeof(value), "%s", dirty);
    } else {
        snprintf(value, sizeof(value), "%s", pi->value);
    }
    if (SERIAL_LEN(serial) == 0) return 1;      /* 已删除 */
    printf("[%s]: [%s]\n", name, value);
    return 0;
}

/* system.prop 批量导入（模块用）。每轮复用同一个 ctx，避免反复 mmap。 */
static int do_file(struct prop_ctx *c, const char *file, int no_event,
                   int persist, int verbose)
{
    FILE *fp = fopen(file, "re");
    if (!fp) { perror("resetprop: --file"); return 1; }
    char line[1024];
    int rc = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *h = strchr(line, '#'); if (h) *h = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *name = line, *value = eq + 1;
        while (*name == ' ' || *name == '\t') name++;
        rstrip(name);                                   /* "ro.foo = 1" 的尾随空格 */
        rstrip(value);
        while (*value == ' ' || *value == '\t') value++;
        if (!*name) continue;
        if (do_set(c, name, value, no_event, persist, verbose) != 0) rc = 1;
    }
    fclose(fp);
    return rc;
}

int boss_resetprop_main(int argc, char **argv)
{
    int no_event = 0, persist = 0, del = 0, verbose = 0;
    const char *file = NULL;
    const char *dir = BOSS_PROP_DIR;
    const char *name = NULL, *value = NULL;

    /* 从 i=1 开始：argv[0] 是 applet 名（两种调用方式下都是），
     * 从 0 开始会把它当成属性名——表现为"命令跑成功但什么都没发生"。 */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-n")) no_event = 1;
        else if (!strcmp(a, "-p")) persist = 1;
        else if (!strcmp(a, "-d") || !strcmp(a, "--delete")) del = 1;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) verbose = 1;
        else if (!strcmp(a, "--file")) { if (i + 1 < argc) file = argv[++i]; }
        else if (!strcmp(a, "--dir"))  { if (i + 1 < argc) dir = argv[++i]; }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (a[0] == '-' && a[1] != '\0') { fprintf(stderr, "resetprop: 未知选项 %s\n", a); usage(); return 1; }
        else if (!name) name = a;
        else if (!value) value = a;
        else { fprintf(stderr, "resetprop: 多余参数 %s\n", a); return 1; }
    }

    /* 特权校验放在这里而不是 applet 表：--dir 指向的如果是合成属性区（离线测试/
     * 校验用），没有特权可言；只有操作设备真实属性区 /dev/__properties__ 才需要
     * root。不能只按"有没有 --dir"放行——那样非 root 就能用 --dir 指回真实目录
     * 绕过校验。 */
    int real_area = (strcmp(dir, BOSS_PROP_DIR) == 0);
    if (real_area && geteuid() != 0) {
        fprintf(stderr, "resetprop: 改设备属性区需要 root 权限（当前 euid=%u）\n",
                (unsigned)geteuid());
        return 1;
    }

    struct prop_ctx c;
    if (ctx_open(&c, dir) < 0) {
        fprintf(stderr, "resetprop: 打不开属性区 %s: %s\n", dir, strerror(errno));
        return 1;
    }
    c_serial_pa = c.serial;

    int rc = 0;
    if (file) {
        rc = do_file(&c, file, no_event, persist, verbose);
    } else if (!name) {
        usage();
        rc = 1;
    } else if (del) {
        rc = do_delete(&c, name, persist, verbose);
    } else if (value) {
        rc = do_set(&c, name, value, no_event, persist, verbose);
    } else {
        rc = do_get(&c, name);
    }

    c_serial_pa = NULL;
    ctx_close(&c);
    return rc;
}
