#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* v0.2：二阶段劫持入口。
 * 被 SwitchRoot 绑到 /system/bin/init 上后，内核/init 会以
 * "second_stage" 或 "selinux_setup" 参数把我们执行起来；
 * 这里先确保 bossd 在跑，再把执行权交回真实 init。 */
static int cmd_stage2(int argc, char **argv)
{
    boss_install();
    start_daemon();

    const char *real = "/init.real";
    if (access(real, X_OK) != 0) real = "/system/bin/init.real";
    if (access(real, X_OK) != 0) {
        /* 真实 init 找不到了：这是致命情况，别硬 exec 自己造成死循环 */
        fprintf(stderr, "bossinit: real init not found\n");
        return 127;
    }

    char *nargv[8];
    int n = 0;
    nargv[n++] = (char *)real;
    for (int i = 2; i < argc && n < 7; i++) nargv[n++] = argv[i];
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
    if (!strcmp(cmd, "hijack-prep") || !strcmp(cmd, "--hijack-prep"))
        return cmd_hijack_prep();
    if (!strcmp(cmd, "alive"))
        return daemon_alive() ? 0 : 1;

    /* 未知参数：同样交还给真实 init */
    execv("/init.real", argv);
    return 127;
}
