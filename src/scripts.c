/* B3 · boot 阶段脚本执行器
 *
 * 三个阶段的时机与语义完全不同，选错时机是这类组件 bug 的第一大来源：
 *   post-fs-data    /data 挂载后、模块挂载前、Zygote 前 —— 阻塞，约 40s 上限
 *   service         late_start 之后          —— 非阻塞，绝大多数脚本的默认选择
 *   boot-completed  开机完成                 —— 非阻塞，依赖系统服务就绪
 *
 * 执行器要点：按文件名排序、每条脚本有超时、单条失败不影响后续、结果写日志。
 * 另外：post-fs-data 阶段必须保证脚本里用的 resetprop 带 -n（阻塞阶段用 setprop
 * 会死锁开机）——执行器在环境里给出 BOSS_STAGE，脚本自己判断，我们也在日志里提示。
 */
#define _GNU_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "boss.h"

struct stage {
    const char *name;
    const char *dir;
    int default_timeout;   /* 秒 */
    int blocking;
};

static const struct stage stages[] = {
    { "post-fs-data",  BOSS_POSTFS_DIR,   20, 1 },
    { "service",       BOSS_SERVICE_DIR,  60, 0 },
    { "boot-completed", BOSS_BOOTCOMP_DIR, 60, 0 },
    { NULL, NULL, 0, 0 }
};

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/* 只收 *.sh，按文件名排序（qsort 保证跨设备顺序一致）。
 *
 * 有意**不检查可执行位**：模块脚本在打包/解压过程中丢掉 +x 是常态，
 * 严格检查 X_OK 的后果是大量模块脚本静默不跑——用户只会看到"模块没生效"，
 * 极难排查。Magisk 也是直接执行不检查权限，我们对齐它的行为。
 * 只按后缀筛，是为了避免把 README、.bak 之类无关文件当脚本跑。 */
static int is_script_name(const char *name)
{
    size_t l = strlen(name);
    return (l >= 4 && strcmp(name + l - 3, ".sh") == 0);
}

static int collect(const char *dir, char ***out)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int cap = 8, n = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) { closedir(d); return 0; }

    while ((e = readdir(d)) != NULL) {
        if (!is_script_name(e->d_name)) continue;
        if (n == cap) {
            cap *= 2;
            char **nl = realloc(list, (size_t)cap * sizeof(char *));
            if (!nl) break;
            list = nl;
        }
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        list[n++] = strdup(p);
    }
    closedir(d);
    if (n > 1) qsort(list, (size_t)n, sizeof(char *), cmp_str);
    *out = list;
    return n;
}

/* 跑一条脚本：fork + exec，超时先 SIGTERM 再 SIGKILL，整组进程一起收 */
static int run_one(const char *script, int timeout, const char *stage)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setpgid(0, 0);
        /* 环境：脚本要靠这些变量找到 BOSS 与工具集 */
        setenv("BOSS_DIR", BOSS_DIR, 1);
        setenv("BOSS_STAGE", stage, 1);
        setenv("ASH_STANDALONE", "1", 1);
        if (getenv("PATH")) {
            char p[1024];
            snprintf(p, sizeof(p), "%s:%s", BOSS_BIN_DIR, getenv("PATH"));
            setenv("PATH", p, 1);
        }
        execl(BOSS_DEFAULT_SHELL, BOSS_DEFAULT_SHELL, script, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    /* 每 100ms 探一次，最多等 timeout*10 次 */
    long ticks = (long)timeout * 10;
    long waited = 0;
    while (waited < ticks) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0) break;
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        waited++;
    }
    if (waited < ticks) {
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return -1;
    }
    if (waited >= timeout) {
        kill(-pid, SIGTERM);
        usleep(500 * 1000);
        kill(-pid, SIGKILL);
        waitpid(pid, &status, 0);
        boss_log_line("script: TIMEOUT %s (%ds)", script, timeout);
        return -2;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static int run_stage(const struct stage *s, int timeout, int verbose)
{
    char **list = NULL;
    int n = collect(s->dir, &list);
    if (n == 0) {
        if (verbose) printf("script: %s 无脚本\n", s->name);
        return 0;
    }
    if (timeout <= 0) timeout = s->default_timeout;

    boss_log_line("script: stage %s begin (%d scripts, timeout=%ds%s)",
             s->name, n, timeout, s->blocking ? ", blocking" : "");

    int failed = 0;
    for (int i = 0; i < n; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = run_one(list[i], timeout, s->name);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 +
                         (t1.tv_nsec - t0.tv_nsec) / 1000000);

        if (rc == 0) {
            boss_log_line("script: OK   %s (%ldms)", list[i], ms);
        } else {
            /* 单条失败不阻断后续：这是日用可靠性的关键 */
            failed++;
            boss_log_line("script: FAIL %s rc=%d (%ldms)", list[i], rc, ms);
            fprintf(stderr, "script: %s 失败 rc=%d: %s\n", s->name, rc, list[i]);
        }
        if (verbose) printf("script: %s rc=%d %ldms %s\n", list[i], rc, ms, list[i]);
    }
    for (int i = 0; i < n; i++) free(list[i]);
    free(list);

    boss_log_line("script: stage %s end (%d failed)", s->name, failed);
    return failed > 0 ? 1 : 0;
}

static void usage(void)
{
    fprintf(stderr,
        "用法: boss script <stage> [选项]\n"
        "  stage: post-fs-data | service | boot-completed | all\n"
        "  --timeout N   单条脚本超时秒数\n"
        "  -v            打印执行明细\n");
}

int boss_script_main(int argc, char **argv)
{
    /* argv[0] 是 applet 名（"script"），阶段从 argv[1] 取 */
    if (argc < 2) { usage(); return 1; }

    const char *want = argv[1];
    int timeout = 0, verbose = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--timeout")) {
            if (i + 1 < argc) timeout = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else if (argv[i][0] == '-') {
            usage(); return 1;
        }
    }

    if (strcmp(want, "post-fs-data") == 0 && timeout <= 0) {
        /* 阻塞阶段留足余量：整体上限约 40s，脚本默认只给 20s */
        timeout = 20;
    }

    boss_mkdirs(BOSS_DIR, 0700);

    int rc = 0;
    if (!strcmp(want, "all")) {
        for (int i = 0; stages[i].name; i++) {
            if (run_stage(&stages[i], timeout, verbose) != 0) rc = 1;
        }
    } else {
        const struct stage *s = NULL;
        for (int i = 0; stages[i].name; i++) {
            if (!strcmp(stages[i].name, want)) { s = &stages[i]; break; }
        }
        if (!s) { fprintf(stderr, "script: 未知阶段 %s\n", want); usage(); return 1; }
        rc = run_stage(s, timeout, verbose);
    }
    return rc;
}
