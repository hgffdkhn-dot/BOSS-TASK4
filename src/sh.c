/* A2 · 工具集与 standalone shell
 *
 * 为什么不自己写 busybox：工作量无底洞，且别人已经做得更好。
 * 我们的价值在两件事：
 *   1. `boss sh`：busybox ash --standalone，让脚本里的命令解析到 busybox
 *      而不是被系统 toybox 截走——这是老模块脚本兼容性的关键
 *      （standalone 模式只在我们的 shell 里开，不污染全局）
 *   2. `boss applet`：把单二进制的多入口变成真正的命令（symlink）
 *      ——少落文件 = 少痕迹
 *
 * ramdisk 体积是硬约束：busybox（几百 KB ~ 1MB+）绝对不能塞进 payload，
 * 它由 App 释放到 /data/adb/boss/bin，或随 Release 分发。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boss.h"
#include "applet.h"

static const char *busybox_candidates[] = {
    BOSS_BIN_DIR "/busybox",
    "/data/adb/magisk/busybox",
    NULL
};

static const char *find_busybox(void)
{
    for (int i = 0; busybox_candidates[i]; i++) {
        if (access(busybox_candidates[i], X_OK) == 0) return busybox_candidates[i];
    }
    return NULL;
}

int boss_sh_main(int argc, char **argv)
{
    (void)argc;
    const char *bb = find_busybox();

    /* PATH 前置 BOSS_BIN_DIR：先找到我们的 applet 再找系统的 */
    const char *old = getenv("PATH");
    char path[2048];
    snprintf(path, sizeof(path), "%s%s%s", BOSS_BIN_DIR,
             (old && *old) ? ":" : "", (old && *old) ? old : "");
    setenv("PATH", path, 1);
    setenv("BOSS_DIR", BOSS_DIR, 1);
    setenv("ASH_STANDALONE", "1", 1);

    if (!bb) {
        fprintf(stderr, "boss sh: 未找到 busybox（应放在 %s），退化为系统 shell\n",
                BOSS_BIN_DIR "/busybox");
        execv(BOSS_DEFAULT_SHELL, argv);
        return 127;
    }

    /* --standalone 是重点：让 busybox 优先解析自己的 applet */
    char *nargv[16];
    int n = 0;
    nargv[n++] = (char *)bb;
    nargv[n++] = (char *)"ash";
    nargv[n++] = (char *)"--standalone";
    for (int i = 0; i < argc && n < 15; i++) nargv[n++] = argv[i];
    nargv[n] = NULL;

    execv(bb, nargv);
    perror("boss sh: execv");
    return 127;
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss applet <命令>\n"
        "  install          为所有 applet 建立 symlink -> boss\n"
        "  install-busybox  让 busybox 自己装它的 applet 到 " BOSS_BIN_DIR "\n"
        "  list             列出已安装的 symlink\n"
        "  clean            清掉指向 boss 的 symlink\n");
}

static int cmd_install(void)
{
    if (boss_mkdirs(BOSS_BIN_DIR, 0755) < 0) {
        fprintf(stderr, "applet: 建目录失败 %s\n", BOSS_BIN_DIR);
        return 1;
    }
    /* boss 本体必须在 bin 里，symlink 才指得过去 */
    char self[512] = { 0 };
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n < 0) {
        /* 拿不到就按约定路径用 */
        snprintf(self, sizeof(self), "%s", BOSS_BIN_PATH);
    }

    int made = 0;
    for (int i = 0; ; i++) {
        const struct boss_applet *a = boss_applet_find_by_index(i);
        if (!a) break;
        char link[PATH_MAX];
        snprintf(link, sizeof(link), "%s/%s", BOSS_BIN_DIR, a->name);
        unlink(link);
        if (symlink(self, link) == 0) made++;
        else fprintf(stderr, "applet: %s -> %s 失败: %s\n", link, self, strerror(errno));
    }
    printf("applet: %d 个已安装到 %s\n", made, BOSS_BIN_DIR);
    return made > 0 ? 0 : 1;
}

static int cmd_list(void)
{
    printf("（applet 表见 boss --list）\n");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls -l %s 2>/dev/null", BOSS_BIN_DIR);
    return system(cmd) == 0 ? 0 : 1;
}

static int cmd_clean(void)
{
    /* 只删指向 boss 的软链，别误伤 busybox 自己的 applet */
    char cmd[768];
    snprintf(cmd, sizeof(cmd),
             "for f in %s/*; do "
             "  [ -L \"$f\" ] || continue; "
             "  t=$(readlink \"$f\"); "
             "  case \"$t\" in *boss*) rm -f \"$f\";; esac; "
             "done", BOSS_BIN_DIR);
    return system(cmd) == 0 ? 0 : 1;
}

static int cmd_busybox(void)
{
    const char *bb = find_busybox();
    if (!bb) {
        fprintf(stderr, "applet: 未找到 busybox\n");
        return 1;
    }
    boss_mkdirs(BOSS_BIN_DIR, 0755);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "'%s' --install -s '%s'", bb, BOSS_BIN_DIR);
    return system(cmd) == 0 ? 0 : 1;
}

int boss_applet_main(int argc, char **argv)
{
    if (argc < 1) { usage(); return 1; }
    const char *c = argv[0];
    if (!strcmp(c, "install")) return cmd_install();
    if (!strcmp(c, "install-busybox")) return cmd_busybox();
    if (!strcmp(c, "list")) return cmd_list();
    if (!strcmp(c, "clean")) return cmd_clean();
    usage();
    return 1;
}
