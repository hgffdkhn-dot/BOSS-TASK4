/* 开机阶段编排器
 *
 * 为什么必须有它：rc 里的 exec_background 是并发的，几条命令之间没有先后保证。
 * 而开机这几件事的顺序错了就会出问题：
 *   1. BOSS 落盘 + 拉起守护进程（后面所有步骤都靠它）
 *   2. 模块属性（system.prop）   —— 必须在挂载之前，因为挂载决策可能读属性
 *   3. 模块 SELinux 规则        —— 必须在挂载之前，否则挂载会被策略拦
 *   4. 模块挂载                 —— 必须在脚本之前，脚本常常依赖挂载后的文件
 *   5. 用户/模块脚本
 * 所以用一条命令把顺序固定下来，而不是靠 rc 里罗列一堆 exec_background。
 *
 * 这条命令也是"执行权拿到之后跑什么"的答案：v0.2 拿到 init 执行权后，
 * 只要在各阶段调 `boss boot <stage>` 即可，组件不用改。
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "boss.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define BOSS_PATH_MAX (PATH_MAX + 64)

/* 调自己的另一个 applet。走 fork/exec 而不是内部函数调用：
 * 每个组件独立进程，一个组件崩了不会带塌整条开机流程。 */
static int run_tool(char *const argv[], int timeout_sec)
{
    const char *bin = access(BOSS_BIN_PATH, X_OK) == 0 ? BOSS_BIN_PATH : NULL;
    if (!bin) {
        fprintf(stderr, "boot: %s 不存在，跳过 %s\n", BOSS_BIN_PATH, argv[1]);
        return 1;
    }

    pid_t p = fork();
    if (p < 0) return 1;
    if (p == 0) {
        execv(bin, argv);
        _exit(127);
    }

    int status = 0;
    if (timeout_sec > 0) {
        /* post-fs-data 是阻塞阶段：整体约 40s 上限，单步超时必须留余量 */
        long ticks = (long)timeout_sec * 10;
        for (long i = 0; i < ticks; i++) {
            if (waitpid(p, &status, WNOHANG) == p) goto done;
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        kill(p, SIGTERM);
        usleep(300 * 1000);
        kill(p, SIGKILL);
        waitpid(p, &status, 0);
        fprintf(stderr, "boot: %s 超时（%ds），已终止\n", argv[1], timeout_sec);
        return 1;
    }
    if (waitpid(p, &status, 0) != p) return 1;

done:
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

static int has_file(const char *dir, const char *name, char *out, size_t n)
{
    size_t dl = strlen(dir), nl = strlen(name);
    if (dl + 1 + nl + 1 > n) return 0;
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl);
    out[dl + 1 + nl] = '\0';
    return access(out, F_OK) == 0;
}

/* 模块属性：必须 -n（直写属性区）。
 * post-fs-data 是阻塞阶段，这里走 property_service 会直接死锁开机流程。 */
static int apply_module_props(void)
{
    char **dirs = NULL;
    int n = boss_module_dirs(&dirs);
    int rc = 0;

    for (int i = 0; i < n; i++) {
        char f[BOSS_PATH_MAX + 64];
        if (!has_file(dirs[i], "system.prop", f, sizeof(f))) continue;
        char *a[] = { (char *)BOSS_BIN_PATH, (char *)"resetprop", (char *)"-n",
                      (char *)"--file", f, NULL };
        if (run_tool(a, 10) != 0) rc = 1;
    }
    for (int i = 0; i < n; i++) free(dirs[i]);
    free(dirs);
    return rc;
}

/* 模块 SELinux 规则：这是"尽力而为"的一步——没有注入引擎时 sepolicy 会把规则
 * 存进待应用队列并返回 2，不该因此中断开机。 */
static int apply_module_rules(void)
{
    char **dirs = NULL;
    int n = boss_module_dirs(&dirs);

    for (int i = 0; i < n; i++) {
        char f[BOSS_PATH_MAX + 64];
        if (!has_file(dirs[i], "sepolicy.rule", f, sizeof(f))) continue;
        char *a[] = { (char *)BOSS_BIN_PATH, (char *)"sepolicy", (char *)"apply", f, NULL };
        int rc = run_tool(a, 15);
        if (rc != 0 && rc != 2)
            fprintf(stderr, "boot: %s 的规则应用失败 rc=%d\n", dirs[i], rc);
    }
    for (int i = 0; i < n; i++) free(dirs[i]);
    free(dirs);
    return 0;      /* 规则失败不影响开机 */
}

/* 每一步都留痕：真机上"开机慢 40 秒"或"某个模块没生效"的排查，
 * 靠的就是这段日志——没有它只能靠猜。 */
static int step(const char *name, char *argv[], int timeout)
{
    boss_log_line("boot: step begin %s", name);
    int rc = run_tool(argv, timeout);
    boss_log_line("boot: step end   %s rc=%d", name, rc);
    return rc;
}

static int stage_post_fs_data(void)
{
    boss_log_line("boot: post-fs-data begin");

    /* 1) 落盘 + 守护进程（幂等）。落盘失败后面都没意义，直接失败。 */
    if (boss_install() < 0) {
        fprintf(stderr, "boot: BOSS 落盘失败\n");
        boss_log_line("boot: install FAILED");
        return 1;
    }
    char *start[] = { (char *)BOSS_BIN_PATH, (char *)"init", (char *)"start", NULL };
    if (step("daemon", start, 15) != 0) {
        /* bossd 没起来不该中断开机：属性、挂载、脚本仍要跑，
         * 只是那些需要 bossd 的能力降级。 */
        fprintf(stderr, "boot: bossd 未起来，后续步骤继续\n");
    }

    /* 2) 模块属性（必须早于挂载：挂载决策可能读属性）
     * 3) 模块规则（必须早于挂载：否则挂载被策略拦） */
    apply_module_props();
    apply_module_rules();

    /* 4) 挂载 */
    char *mount[] = { (char *)BOSS_BIN_PATH, (char *)"module", (char *)"mount", NULL };
    if (step("module-mount", mount, 20) != 0)
        fprintf(stderr, "boot: 模块挂载失败，继续跑脚本\n");

    /* 5) 脚本 */
    char *sc[] = { (char *)BOSS_BIN_PATH, (char *)"script", (char *)"post-fs-data", NULL };
    int rc = step("script", sc, 20);
    boss_log_line("boot: post-fs-data end rc=%d", rc);
    return rc;
}

static int stage_service(void)
{
    char *sc[] = { (char *)BOSS_BIN_PATH, (char *)"script", (char *)"service", NULL };
    return step("script-service", sc, 0);   /* 非阻塞阶段：不设超时 */
}

static int stage_completed(void)
{
    char *sc[] = { (char *)BOSS_BIN_PATH, (char *)"script", (char *)"boot-completed", NULL };
    return step("script-boot-completed", sc, 0);
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss boot <stage>\n"
        "  post-fs-data   落盘 → 拉起守护 → 模块属性 → 规则 → 挂载 → 脚本（阻塞阶段）\n"
        "  service        late_start 之后的脚本（非阻塞）\n"
        "  completed      开机完成后的脚本（非阻塞）\n");
}

int boss_boot_main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }
    const char *st = argv[1];

    if (!strcmp(st, "post-fs-data"))  return stage_post_fs_data();
    if (!strcmp(st, "service"))       return stage_service();
    if (!strcmp(st, "completed") || !strcmp(st, "boot-completed"))
        return stage_completed();

    usage();
    return 1;
}
