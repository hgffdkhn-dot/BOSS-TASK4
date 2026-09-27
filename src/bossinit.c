#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "boss.h"

/* ------------------------------------------------------------------
 * bossinit：init 阶段的助手（v0.1 骨架 + v0.2 的落点）
 *
 * 为什么需要它：Android 10+ 的两段式 init（2SI）会在第一阶段结束时
 * SwitchRoot——把 / 下的挂载递归移动到 /system 并 chroot 进去，
 * ramdisk 从此消失。也就是说：
 *   · 放在 ramdisk 里的 rc / 二进制，在第二阶段 init 看来不存在；
 *   · 第二阶段 init 只解析 /system/etc/init/hw/init.rc（AOSP LoadBootScripts），
 *     除非用 androidboot.init_rc 整体改写。
 * 因此"su 能不能日用"，取决于能不能在切根前后重新拿到执行权。
 *
 * v0.1：提供 install / start / post-fs-data，覆盖 ramdisk 不被丢弃的布局
 *       （非 2SI、vendor_boot 布局，以及已经由 BOSS App 触发的场景）。
 * v0.2：stage2 + hijack-prep 完成 SwitchRoot 劫持（见 docs 中的方案说明），
 *       做到 /system 零落盘修改。
 * ------------------------------------------------------------------ */

static int copy_self_to(const char *dst)
{
    char self[256] = { 0 };
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n < 0) return -1;

    int in = open(self, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (out < 0) { close(in); return -1; }

    char buf[65536];
    ssize_t r;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        if (boss_write_full(out, buf, (size_t)r) < 0) { close(in); close(out); return -1; }
    }
    close(in);
    close(out);
    chmod(dst, 0755);
    return 0;
}

/* 把 BOSS 落到持久分区：ramdisk 会消失，/data 不会。
 * 幂等，boot 流程与 init 流程都会调它。 */
int boss_install(void)
{
    if (boss_mkdirs(BOSS_DIR, 0700) < 0) return -1;
    chmod(BOSS_DIR, 0700);
    policy_ensure_file(BOSS_POLICY_PATH);
    if (access(BOSS_BIN_PATH, X_OK) != 0 && copy_self_to(BOSS_BIN_PATH) < 0) return -1;
    return 0;
}

static int daemon_alive(void)
{
    int fd = boss_connect();
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int start_daemon(void)
{
    const char *bin = access(BOSS_BIN_PATH, X_OK) == 0 ? BOSS_BIN_PATH : NULL;
    if (!bin) return -1;

    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        execl(bin, bin, "daemon", (char *)NULL);
        _exit(127);
    }
    for (int i = 0; i < 20; i++) {
        usleep(50 * 1000);
        if (daemon_alive()) return 0;
    }
    return daemon_alive() ? 0 : -1;
}

static int cmd_start(void)
{
    if (boss_install() < 0) return 1;
    if (daemon_alive()) return 0;
    return start_daemon() < 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * 早期阶段怎么留日志
 * ------------------------------------------------------------------
 * init 在 selinux_setup 之前就把 stdio 指向了 /dev/null，printf/fprintf
 * 在这个阶段**一个字节都看不到**。/dev/kmsg 是唯一还能写的地方，
 * 真机上 `dmesg | grep boss` 就是这条链路唯一的线索。
 * 开机排障时"没有任何输出"比"报错"难查得多，所以这里必须留。 */
static void kmsg_log(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t w = write(fd, buf, strlen(buf));
    (void)w;   /* 写不进去就算了，别拿日志失败去影响开机 */
    close(fd);
}

/* 早期注入的总开关（读 kernel cmdline）。
 *
 * 为什么用 cmdline 而不是环境变量：selinux_setup 阶段我们对进程的
 * 环境没有控制权（init 传下来的环境几乎是空的），env 在这里不可靠。
 * /proc/cmdline 是 veritpath 的 cmdline_append 能写的，且早期一定可读。
 *
 * 这条退路的价值：早期注入一旦在某机型上导致开不了机，不用重新刷包
 * 就能退回原厂路径（加 boss_selinux=0 即可），否则每次试错都要进
 * recovery 刷回原厂镜像——自救路径的成本直接影响能不能迭代下去。 */
static int cmdline_says_off(const char *key)
{
    char buf[4096] = { 0 };
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;

    for (char *p = buf; *p;) {
        while (*p == ' ' || *p == '\t') p++;
        char *tok = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if (*p) *p++ = '\0';
        if (!strcmp(tok, key)) return 1;
    }
    return 0;
}

/* 真实 init 的位置。
 * BOSS_INIT_REAL 只给离机验证用（tools/stage2_test.sh）：真机上 init
 * 传下来的环境是空的，这个变量不可能被意外带上，等于 inert。
 * 有了它，这条"上机就是砖、沙盒又验不到"的链路才有一个可回归的测试。 */
static const char *real_init_path(void)
{
    const char *ov = getenv("BOSS_INIT_REAL");
    if (ov && access(ov, X_OK) == 0) return ov;
    if (access("/init.real", X_OK) == 0) return "/init.real";
    if (access("/system/bin/init.real", X_OK) == 0) return "/system/bin/init.real";
    return NULL;
}

/* init 会传给"第二阶段 init"的阶段参数 */
static int is_stage_arg(const char *s)
{
    return !strcmp(s, "selinux_setup") || !strcmp(s, "second_stage") ||
           !strcmp(s, "subcontext");
}

/* 早期注入：在 init 加载策略之前把 BOSS 的规则打进去。
 *
 * 用 **fork + waitpid**，不用 execl 也不直接调用：
 *   · execl 会替换整个进程——一旦成功就再也回不到下面"exec 真实 init"
 *     那一步，表现是开机挂死。交接文档里的示例代码正是这么写的，
 *     照抄就是砖。
 *   · 直接在本进程调用则注入一旦崩溃就没有补救机会。
 *   · fork 之后子进程崩了也只是子进程没了，父进程照常把执行权还给 init。
 * 开机路径上"任何一步失败都必须还能继续开机"，这是本项目的一贯取舍。 */
static int early_sepol_inject(void)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        char *sv[] = { (char *)"selinux", (char *)"setup", NULL };
        _exit(boss_selinux_main(2, sv));
    }

    int st = 0;
    while (waitpid(p, &st, 0) < 0 && errno == EINTR) ;
    if (!WIFEXITED(st)) return -1;

    int rc = WEXITSTATUS(st);
    /* 0 全应用 / 3 部分应用都算成功：策略已经进内核了，
     * 少几条规则只会让某个功能没权限，不该让它拖住开机。 */
    return (rc == 0 || rc == 3) ? 0 : -1;
}

/* v0.2：二阶段劫持入口。
 * 被 SwitchRoot 绑到 /system/bin/init 上后，内核/init 会把我们当 init
 * 执行起来，argv[1] 是阶段参数（selinux_setup / second_stage）。
 *
 * 两种调用约定都要认：
 *   /system/bin/init selinux_setup      阶段参数在 argv[1]（真机 2SI 的写法）
 *   boss init stage2 second_stage       阶段参数在 argv[2]（手动/脚本调用）
 * 以前固定从 argv[2] 开始转发，真机那种写法下阶段参数会被**整个丢掉**——
 * 真实 init 收不到 second_stage 就会重跑 FirstStageMain，直接死循环。
 */
static int cmd_stage2(int argc, char **argv)
{
    /* 阶段参数的起点：argv[1] 是 stage2 本身时从 2 开始，否则就是 1 */
    int start = 1;
    if (argc >= 2 && (!strcmp(argv[1], "stage2") || !strcmp(argv[1], "--stage2")))
        start = 2;

    int is_setup = 0, any_stage = 0;
    for (int i = start; i < argc; i++) {
        if (!strcmp(argv[i], "selinux_setup")) is_setup = 1;
        if (is_stage_arg(argv[i])) any_stage = 1;
    }

    int injected = 0;
    if (is_setup) {
        /* 只有 selinux_setup 这一趟才做早期注入，也只有这一趟不能做别的：
         * 此时 /data 还没解密挂载，boss_install() 往 /data/adb 建目录
         * 要么失败、要么落在还没解密的挂载点上留下垃圾。落盘和拉 daemon
         * 留给随后那一趟 second_stage。 */
        if (cmdline_says_off("boss_selinux=0")) {
            kmsg_log("boss: 早期注入已被 boss_selinux=0 关闭，走原厂路径\n");
        } else {
            injected = (early_sepol_inject() == 0);
            kmsg_log("boss: 早期注入 %s\n", injected ? "成功" : "失败（退回原厂路径）");
        }
    } else {
        boss_install();
        start_daemon();
    }

    const char *real = real_init_path();
    if (!real) {
        /* 真实 init 找不到了：这是致命情况，别硬 exec 自己造成死循环 */
        fprintf(stderr, "bossinit: real init not found\n");
        kmsg_log("boss: 找不到真实 init，放弃（绝不 exec 自己）\n");
        return 127;
    }

    char *nargv[8];
    int n = 0;
    nargv[n++] = (char *)real;

    if (is_setup) {
        /* 这一行是整个任务4 的落点：
         *   · 注入成功 → 传 second_stage。策略已经由我们写进内核了，
         *     再让真实 init 跑 selinux_setup，它会拿原始策略再加载一次，
         *     把补丁整个盖掉（症状是"注入明明成功、BOSS 仍在 init 域"）。
         *   · 注入失败 → 传 selinux_setup，让真实 init 走原厂流程。
         *     这样最坏情况只是 BOSS 没有早期规则，开机本身不受影响，
         *     规则会进 pending 等 /data 挂载后由运行时注入兜底。 */
        nargv[n++] = injected ? (char *)"second_stage" : (char *)"selinux_setup";
        kmsg_log("boss: exec %s %s\n", real, nargv[n - 1]);
    } else {
        for (int i = start; i < argc && n < 7; i++) nargv[n++] = argv[i];
        /* 一个阶段参数都没传就 exec 真实 init，它会跑 FirstStageMain——
         * 又是一轮开机循环。既然是当 stage2 调用的，就按 second_stage 兜底。 */
        if (!any_stage) {
            nargv[n++] = (char *)"second_stage";
            kmsg_log("boss: 没有阶段参数，按 second_stage 兜底\n");
        }
    }
    nargv[n] = NULL;

    execv(real, nargv);
    return 127;
}

/* v0.2：为 SwitchRoot 劫持做现场布置。
 * 原理（与 Magisk 同源）：init 的 SwitchRoot 会把 / 下的挂载递归移动到
 * /system；我们提前把 /storage/self/primary 指向 /system/system/bin/init，
 * 再把 bossinit 挂到 /sdcard 上，切根后它就会落到 /system/bin/init，
 * 从而接管第二阶段——全程不写 /system 一个字节。 */
static int cmd_hijack_prep(void)
{
    (void)boss_mkdirs("/storage/self", 0755);
    (void)unlink("/storage/self/primary");
    if (symlink("/system/system/bin/init", "/storage/self/primary") != 0) { /* 已存在 */ }

    if (access("/sdcard", F_OK) != 0) {
        int fd = open("/sdcard", O_CREAT | O_RDONLY | O_CLOEXEC, 0700);
        if (fd >= 0) close(fd);
    }
    /* 真正的 bind mount 由第一阶段的 bossinit 完成（见 docs）：
     *   mount --bind <bossinit> /sdcard
     * 这里只负责把符号链接铺好。 */
    return 0;
}

int boss_init_main(int argc, char **argv)
{
    if (argc < 2) {
        /* 兜底：当我们被当成 /init 启动但没有子命令时，
         * 绝不自己充当 init，直接把执行权还给真实 init，避免变砖。 */
        execv("/init.real", argv);
        return 127;
    }

    const char *cmd = argv[1];
    if (!strcmp(cmd, "install") || !strcmp(cmd, "--install"))
        return boss_install() < 0 ? 1 : 0;
    if (!strcmp(cmd, "start") || !strcmp(cmd, "--start") || !strcmp(cmd, "post-fs-data"))
        return cmd_start();
    if (!strcmp(cmd, "stage2") || !strcmp(cmd, "--stage2") || !strcmp(cmd, "second_stage"))
        return cmd_stage2(argc, argv);
    /* init 的第一阶段最后 exec 的是 `/system/bin/init selinux_setup`。
     * 不接这一条，它会落到下面"未知参数"分支原样转发给真实 init——
     * 于是真实 init 用原始策略完成 selinux_setup，我们的早期注入一次
     * 都不会发生（症状是"代码写完了但从不执行"）。 */
    if (!strcmp(cmd, "selinux_setup"))
        return cmd_stage2(argc, argv);
    if (!strcmp(cmd, "hijack-prep") || !strcmp(cmd, "--hijack-prep"))
        return cmd_hijack_prep();
    if (!strcmp(cmd, "alive"))
        return daemon_alive() ? 0 : 1;

    /* 未知参数：同样交还给真实 init */
    execv("/init.real", argv);
    return 127;
}
