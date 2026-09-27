/* A1 · applet 多调用分发框架
 *
 * 两种调用方式必须行为一致：
 *   1) symlink 调用：/data/adb/boss/bin/resetprop -> boss   → argv[0]="resetprop"
 *      此时 argv[1] 才是第一个参数，传给 applet 的是 (argc-1, argv+1)。
 *   2) 子命令调用：boss resetprop foo bar                   → argv[0]="boss"
 *      此时 argv[2] 才是第一个参数，传给 applet 的是 (argc-2, argv+2)。
 *
 * 这里统一在一处做偏移，避免每个 applet 各写各的（老 main.c 就是各写各的，
 * 扩表时必错）。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "boss.h"
#include "applet.h"

static int cmd_daemon(int argc, char **argv);
static int cmd_su(int argc, char **argv);
static int cmd_init(int argc, char **argv);
static int cmd_ping(int argc, char **argv);
static int cmd_version(int argc, char **argv);
static int cmd_help(int argc, char **argv);

/* 表即文档：boss --list 直接由它生成 */
static const struct boss_applet applets[] = {
    /* name          fn             root  summary */
    { "su",          cmd_su,         0, "请求 root（等价于 su）" },
    { "resetprop",   boss_resetprop_main, 0, "属性改写：改 ro.* / 删除属性 / persist（改真实属性区需 root）" },
    { "sepolicy",    boss_sepolicy_main,  0, "SELinux 策略补丁工具（应用规则需 root）" },
    { "selinux",     boss_selinux_main,   0, "SELinux 解决与规则注入：状态/早期注入/live/打标签（注入需 root）" },
    { "boot",        boss_boot_main,     1, "开机阶段编排（落盘→属性→规则→挂载→脚本）" },
    { "script",      boss_script_main,    0, "boot 阶段脚本执行器（三阶段）" },
    { "module",      boss_module_main,    0, "模块管理、overlay 挂载计划与执行（真挂载需 root）" },
    { "sh",          boss_sh_main,        0, "standalone busybox shell（脚本兼容用）" },
    { "applet",      boss_applet_main,    1, "管理 /data/adb/boss/bin 下的 applet symlink" },
    { "policy",      boss_policy_main,    0, "su 授权策略" },
    { "init",        cmd_init,       1, "init 阶段助手（install / start / stage2）" },
    /* daemon **不**设 needs_root：非 root 环境（GitHub runner 就是普通用户）
     * 也得起得来，否则整条 su 链路在 CI 上根本验不到——它只是无法提权，
     * 目标身份会自动降级为自身（见 daemon.c）。真机上由 rc 以 root 拉起。 */
    { "daemon",      cmd_daemon,     0, "运行 bossd（常驻；非 root 下提权降级为自身）" },
    { "ping",        cmd_ping,       0, "探活 bossd" },
    { "version",     cmd_version,    0, "打印版本" },
    { "help",        cmd_help,       0, "打印帮助" },
    { NULL, NULL, 0, NULL }
};

/* 历史别名：v0.1 的 main.c 就认这些名字，payload 的 rc 也可能按老名字调。
 * 别删——删了老布局上会直接报"未知 applet"。 */
static const struct { const char *alias; const char *target; } aliases[] = {
    { "bossd",     "daemon" },
    { "bossinit",  "init"   },
    { "boss-static", "boss" },   /* make static 的产物名，CI 会拿它跑 -V */
    { "--daemon",    "daemon" },  /* 历史写法：bossinit 早期传的是 --daemon */
    { NULL, NULL }
};

const struct boss_applet *boss_applet_find(const char *name)
{
    for (size_t i = 0; applets[i].name; i++) {
        if (!strcmp(applets[i].name, name)) return &applets[i];
    }
    for (size_t i = 0; aliases[i].alias; i++) {
        if (!strcmp(aliases[i].alias, name)) {
            /* "boss" 是特例：它不是表里的一项，交给 dispatch 走子命令分支 */
            if (!strcmp(aliases[i].target, "boss")) return NULL;
            return boss_applet_find(aliases[i].target);
        }
    }
    return NULL;
}

/* 名字是不是"boss 本体的某个变体"（boss / boss-static / boss-pie ...）：
 * build-ndk.sh 会产出不同名字的产物，CI 也会直接拿产物跑 -V。 */
static int is_boss_self(const char *name)
{
    if (!strcmp(name, "boss")) return 1;
    if (!strncmp(name, "boss-", 5)) return 1;
    return 0;
}

const struct boss_applet *boss_applet_find_by_index(int i)
{
    int k = 0;
    for (size_t j = 0; applets[j].name; j++) {
        if (k++ == i) return &applets[j];
    }
    return NULL;
}

void boss_applet_list(void)
{
    printf("BOSS applets:\n");
    for (size_t i = 0; applets[i].name; i++) {
        printf("  %-11s %s%s\n", applets[i].name, applets[i].summary,
               applets[i].needs_root ? "  [root]" : "");
    }
}

/* 返回 basename：/data/adb/boss/bin/resetprop → resetprop */
static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* 真正执行一个 applet：needs_root 的组件在非 root 下必须明确报错，
 * 不能静默失败——静默失败在开机脚本里会表现为"功能没生效"的幽灵 bug。 */
static int run_applet(const struct boss_applet *a, int argc, char **argv)
{
    if (a->needs_root && geteuid() != 0) {
        fprintf(stderr, "boss: %s 需要 root 权限（当前 euid=%u）\n",
                a->name, (unsigned)geteuid());
        return 1;
    }
    return a->fn(argc, argv);
}

int boss_applet_dispatch(int argc, char **argv)
{
    if (argc <= 0 || !argv[0]) return 1;

    const char *self = base_name(argv[0]);

    /* 方式 1：symlink 调用（argv[0] 已经是 applet 名，不偏移） */
    if (!is_boss_self(self)) {
        const struct boss_applet *a = boss_applet_find(self);
        if (a) return run_applet(a, argc, argv);
        /* 名字不认识，但显然是当工具用的：不要退化成 su，报清楚 */
        fprintf(stderr, "boss: 未知的 applet '%s'\n", self);
        return 1;
    }

    if (argc < 2) {
        /* 裸 boss → 当 su 用（沿用 v0.1 行为） */
        return run_applet(boss_applet_find("su"), argc, argv);
    }

    const char *a1 = argv[1];

    /* --list / -h 这类元命令优先 */
    if (!strcmp(a1, "--list") || !strcmp(a1, "-l")) { boss_applet_list(); return 0; }
    if (!strcmp(a1, "-h") || !strcmp(a1, "--help")) return cmd_help(argc, argv);
    if (!strcmp(a1, "-V") || !strcmp(a1, "--version")) return cmd_version(argc, argv);

    /* 方式 2：子命令调用。偏移 1 使 applet 看到的 argv[0] 仍是自己的名字，
     * 这样两种调用下 applet 内部的解析起点完全一致。 */
    const struct boss_applet *a = boss_applet_find(a1);
    if (a) return run_applet(a, argc - 1, argv + 1);

    fprintf(stderr, "boss: 未知命令 '%s'，用 boss --list 看可用组件\n", a1);
    return 1;
}

/* ---- 下面是原来 main.c 里的内置命令，搬到表里 ---- */

static int cmd_daemon(int argc, char **argv)
{
    return boss_daemon_main(argc, argv);
}

static int cmd_su(int argc, char **argv)
{
    return boss_su_main(argc, argv);
}

static int cmd_init(int argc, char **argv)
{
    /* boss init post-fs-data 这种写法：把子命令拼回 argv[1] 位置 */
    if (argc >= 1) return boss_init_main(argc, argv);
    return boss_init_main(argc, argv);
}

static int cmd_ping(int argc, char **argv)
{
    (void)argc; (void)argv;
    int fd = boss_connect();
    if (fd < 0) { printf("bossd: down\n"); return 1; }
    int status_sock = boss_send_handshake(fd);
    struct boss_request req;
    memset(&req, 0, sizeof(req));
    req.magic = BOSS_MAGIC;
    req.version = BOSS_PROTO_VER;
    req.flags = BOSS_F_PING;
    struct boss_response rep;
    memset(&rep, 0, sizeof(rep));
    int ok = 0;
    if (boss_write_full(fd, &req, sizeof(req)) == 0 &&
        boss_read_full(fd, &rep, sizeof(rep)) == 0)
        ok = (rep.code == BOSS_OK);
    if (status_sock >= 0) close(status_sock);
    close(fd);
    printf("bossd: %s (proto v%d)\n", ok ? "up" : "error", BOSS_PROTO_VER);
    return ok ? 0 : 1;
}

static int cmd_version(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("BOSS %s (proto v%d)\n", BOSS_VERSION, BOSS_PROTO_VER);
    return 0;
}

static int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("BOSS — 单二进制多入口（symlink 或子命令两种调用方式等价）\n\n");
    boss_applet_list();
    printf("\n用法：\n"
           "  boss <applet> [args]       子命令调用\n"
           "  /data/adb/boss/bin/<applet> [args]   symlink 调用\n");
    return 0;
}
