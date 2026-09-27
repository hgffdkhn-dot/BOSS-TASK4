#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "boss.h"

/* ------------------------------------------------------------------
 * bossd：唯一的特权实体。
 *  - 只在抽象命名空间监听，文件系统无节点；
 *  - 用 SO_PEERCRED 取调用者 uid（内核给，不可伪造）；
 *  - 授权通过后自己 fork + 开 pty + 切 uid/selinux 再 exec，
 *    客户端全程只是一个没有特权的"管道"。
 * ------------------------------------------------------------------ */

static int g_listen_fd = -1;

static int listen_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t nlen = strlen(BOSS_SOCK_NAME);
    memcpy(addr.sun_path + 1, BOSS_SOCK_NAME, nlen);
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nlen);

    if (bind(fd, (struct sockaddr *)&addr, alen) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

static void respond(int sock, uint32_t code, uint32_t uid)
{
    struct boss_response r;
    memset(&r, 0, sizeof(r));
    r.code = code;
    r.target_uid = uid;
    (void)boss_write_full(sock, &r, sizeof(r));
}

/* SELinux 上下文切换：两条路，都不成就放弃（仍以 root 身份执行）。
 *
 * 1) dlopen libselinux → setexeccon_raw/setexeccon
 *    动态链接时可用；NDK 没有官方头文件，所以不直接链接。
 * 2) 直接写 /proc/self/attr/exec
 *    setexeccon 的底层就是这个接口。静态二进制（bionic 与 glibc 都不支持
 *    dlopen）只能走这条路，所以 BOSS 的 Android 产物是静态的，必须有它。
 *
 * 只在调用方显式传 --context 时才触发，默认不切域。 */
static void apply_selinux_context(const char *ctx)
{
    if (!ctx || !ctx[0]) return;

#ifndef BOSS_NO_DLOPEN
    void *h = dlopen("libselinux.so", RTLD_NOW | RTLD_LOCAL);
    if (h) {
        int (*setexeccon_raw)(const char *) = NULL;
        *(void **)&setexeccon_raw = dlsym(h, "setexeccon_raw");
        if (!setexeccon_raw) *(void **)&setexeccon_raw = dlsym(h, "setexeccon");
        if (setexeccon_raw) {
            if (setexeccon_raw(ctx) != 0)
                boss_log("selinux: setexeccon(%s) failed", ctx);
            return;   /* 故意不 dlclose：映射要保留到 exec */
        }
    }
#endif

    int fd = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        boss_log("selinux: %s unavailable (%s)", ctx, strerror(errno));
        return;
    }
    if (boss_write_full(fd, ctx, strlen(ctx)) < 0)
        boss_log("selinux: write attr/exec(%s) failed", ctx);
    close(fd);
}

static void build_envp(char **envp, int max, const struct boss_request *req,
                       const char *env_blob, size_t env_len)
{
    int n = 0;
    char tmp[4096];

    if ((req->flags & BOSS_F_KEEPENV) && env_blob && env_len) {
        size_t off = 0;
        while (n < max && boss_blob_next(env_blob, env_len, &off, tmp, sizeof(tmp)))
            envp[n++] = strdup(tmp);
    } else {
        const char *shell = req->shell[0] ? req->shell : BOSS_DEFAULT_SHELL;
        snprintf(tmp, sizeof(tmp), "PATH=%s", BOSS_DEFAULT_PATH); envp[n++] = strdup(tmp);
        snprintf(tmp, sizeof(tmp), "HOME=%s", req->target_uid == 0 ? BOSS_DEFAULT_HOME : "/"); envp[n++] = strdup(tmp);
        envp[n++] = strdup("USER=root");
        envp[n++] = strdup("LOGNAME=root");
        snprintf(tmp, sizeof(tmp), "SHELL=%s", shell); envp[n++] = strdup(tmp);
        snprintf(tmp, sizeof(tmp), "TMPDIR=%s", BOSS_DEFAULT_TMP); envp[n++] = strdup(tmp);
        envp[n++] = strdup("TERM=xterm-256color");
        envp[n++] = strdup("ANDROID_ROOT=/system");
        envp[n++] = strdup("ANDROID_DATA=/data");
        envp[n++] = strdup("ANDROID_STORAGE=/storage");
        /* 从调用方环境变量里只挑回 TERM，既干净又不丢终端能力 */
        if (env_blob && env_len) {
            size_t off = 0;
            while (boss_blob_next(env_blob, env_len, &off, tmp, sizeof(tmp))) {
                if (!strncmp(tmp, "TERM=", 5)) {
                    envp[n - 1] = strdup(tmp);
                    break;
                }
            }
        }
    }
    envp[n] = NULL;
}

static void child_exec(const struct boss_request *req, const char *env_blob,
                       size_t env_len, int slave)
{
    setsid();
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) close(slave);

    /* 目标身份：先 gid 后 uid。补充组保持不变（root shell 需要 sdcard_rw 等） */
    if (setgid((gid_t)req->target_gid) != 0)
        dprintf(STDERR_FILENO, "boss: setgid failed\n");
    if (setuid((uid_t)req->target_uid) != 0)
        dprintf(STDERR_FILENO, "boss: setuid failed\n");

    apply_selinux_context(req->context);

    const char *shell = req->shell[0] ? req->shell : BOSS_DEFAULT_SHELL;
    char *envp[BOSS_MAX_ENVP + 1];
    build_envp(envp, BOSS_MAX_ENVP, req, env_blob, env_len);

    char *argv[8];
    int a = 0;
    argv[a++] = (char *)shell;
    if (req->command[0]) {
        argv[a++] = (char *)"-c";
        argv[a++] = (char *)req->command;
    } else if (req->flags & BOSS_F_LOGIN) {
        argv[a++] = (char *)"-";            /* 登录式 shell */
    }
    argv[a] = NULL;

    execve(shell, argv, envp);
    /* 到这说明 exec 失败 */
    dprintf(STDERR_FILENO, "boss: exec %s: %s\n", shell, strerror(errno));
    _exit(127);
}

/* sock <-> pty master 双向搬运。
 * 任一端结束就收工：master 结束 = 子进程退出；sock 结束 = 客户端消失
 * （此时由调用方把子进程收掉，避免残留一个孤儿 root shell）。 */
static void relay(int sock, int master)
{
    char buf[8192];
    int sock_open = 1, master_open = 1;

    while (sock_open && master_open) {
        struct pollfd fds[2];
        fds[0].fd = sock_open ? sock : -1;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = master_open ? master : -1;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int r = poll(fds, 2, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return;
        }

        if (sock_open && (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(sock, buf, sizeof(buf));
            if (n <= 0) sock_open = 0;                     /* 客户端不再给输入 */
            else if (boss_write_full(master, buf, (size_t)n) < 0) master_open = 0;
        }
        if (master_open && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(master, buf, sizeof(buf));
            if (n <= 0) master_open = 0;                   /* 子进程结束 */
            else if (boss_write_full(sock, buf, (size_t)n) < 0) sock_open = 0;
        }
    }
}

static void handle_client(int sock)
{
    uid_t uid = (uid_t)-1;
    pid_t pid = -1;
    if (boss_peer_uid(sock, &uid, &pid) < 0) { close(sock); return; }

    /* fd 握手是可选的（探活请求就不带）：给它一个短超时，
     * 免得对端不发 fd 时整个 handler 卡死。 */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int status_fd = boss_recv_fd(sock);

    /* 之后的读写给一个宽松的整体超时，避免半开连接把 handler 拖住 */
    tv.tv_sec = 10; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct boss_request req;
    memset(&req, 0, sizeof(req));
    if (boss_read_full(sock, &req, sizeof(req)) < 0) {
        if (status_fd >= 0) close(status_fd);
        close(sock);
        return;
    }

    char *env_blob = NULL, *arg_blob = NULL;

    if (req.magic != BOSS_MAGIC || req.version != BOSS_PROTO_VER) {
        respond(sock, BOSS_ERR, 0);
        goto done;
    }

    if (req.env_len && req.env_len <= BOSS_MAX_BLOB) {
        env_blob = malloc(req.env_len);
        if (env_blob && boss_read_full(sock, env_blob, req.env_len) < 0) {
            free(env_blob); env_blob = NULL;
        }
    }
    if (req.arg_len && req.arg_len <= BOSS_MAX_BLOB) {
        arg_blob = malloc(req.arg_len);
        if (arg_blob && boss_read_full(sock, arg_blob, req.arg_len) < 0) {
            free(arg_blob); arg_blob = NULL;
        }
    }
    (void)arg_blob;   /* v1 协议里 command 已覆盖 -c 场景，参数数组留给 v2 */

    struct boss_policy pol;
    if (policy_load(&pol, BOSS_POLICY_PATH) < 0) {
        policy_ensure_file(BOSS_POLICY_PATH);
        policy_load(&pol, BOSS_POLICY_PATH);
    }
    int decision = policy_decide(&pol, uid);

    /* 非 root 运行的降级（主机 CI / 桌面调试用）：
     * daemon 自己没有特权时，setuid(0) 必然失败，把目标身份降为自身，
     * 这样除"提权"以外的整条链路（鉴权/pty/退出码/策略/日志）都能被测到。
     * 真机上 daemon 永远是 root，这条分支不会进入。 */
    if (geteuid() != 0) {
        if (req.target_uid == 0) req.target_uid = (uint32_t)geteuid();
        if (req.target_gid == 0) req.target_gid = (uint32_t)getegid();
    }

    char caller[256] = { 0 };
    boss_proc_cmdline(pid, caller, sizeof(caller));

    if (!(req.flags & BOSS_F_NOLOG)) {
        boss_log("uid=%u pid=%d caller='%s' target=%u cmd='%s' ctx='%s' -> %s",
                 (unsigned)uid, (int)pid, caller, req.target_uid,
                 req.command[0] ? req.command : "<interactive>",
                 req.context,
                 decision == BOSS_DECISION_ALLOW ? "allow" : "deny");
    }

    if (req.flags & BOSS_F_PING) { respond(sock, BOSS_OK, req.target_uid); policy_free(&pol); goto done; }

    if (decision != BOSS_DECISION_ALLOW) {
        respond(sock, decision == BOSS_DECISION_PROMPT ? BOSS_PROMPT : BOSS_DENIED, req.target_uid);
        policy_free(&pol);
        goto done;
    }

    int master = -1, slave = -1;
    char sname[128];
    if (boss_pty_open(&master, &slave, sname, sizeof(sname)) < 0) {
        boss_log("pty open failed: %s", strerror(errno));
        respond(sock, BOSS_ERR, req.target_uid);
        policy_free(&pol);
        goto done;
    }
    boss_pty_setup(master, req.rows, req.cols);

    respond(sock, BOSS_OK, req.target_uid);

    pid_t child = fork();
    if (child < 0) {
        respond(sock, BOSS_ERR, req.target_uid);
        close(master); close(slave);
        policy_free(&pol);
        goto done;
    }
    if (child == 0) {
        close(master);
        close(g_listen_fd);
        if (status_fd >= 0) close(status_fd);
        child_exec(&req, env_blob, env_blob ? req.env_len : 0, slave);
        _exit(127);
    }

    close(slave);
    relay(sock, master);

    /* 客户端断开/子进程结束：收尾，并把退出码通过 side channel 回传 */
    int status = 0, reaped = 0;
    for (int i = 0; i < 20; i++) {
        if (waitpid(child, &status, WNOHANG) == child) { reaped = 1; break; }
        usleep(50 * 1000);
    }
    if (!reaped) {
        /* 客户端没了但 shell 还在跑：先 TERM 再 KILL，绝不留孤儿 root 进程 */
        kill(child, SIGTERM);
        usleep(200 * 1000);
        if (waitpid(child, &status, WNOHANG) != child) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
        }
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    if (status_fd >= 0) {
        uint32_t ec = (uint32_t)code;
        (void)boss_write_full(status_fd, &ec, sizeof(ec));
        close(status_fd);
    }
    close(master);
    policy_free(&pol);

done:
    free(env_blob);
    if (status_fd >= 0) close(status_fd);
    close(sock);
}

int boss_daemon_main(int argc, char **argv)
{
    int foreground = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-f")) foreground = 1;
        else if (!strcmp(argv[i], "--log=0")) boss_set_log(0);
        else if (!strcmp(argv[i], "--log=1")) boss_set_log(1);
    }

    if (boss_mkdirs(BOSS_DIR, 0700) < 0) {
        fprintf(stderr, "bossd: cannot create %s: %s\n", BOSS_DIR, strerror(errno));
        return 1;
    }
    policy_ensure_file(BOSS_POLICY_PATH);
    chmod(BOSS_DIR, 0700);

    struct boss_policy pol;
    if (policy_load(&pol, BOSS_POLICY_PATH) < 0) {
        pol.log_enabled = 1;
        pol.default_decision = BOSS_DECISION_DENY;
        pol.rules = NULL;
        pol.nrules = 0;
    }
    boss_log_init(BOSS_LOG_PATH, pol.log_enabled);
    policy_free(&pol);

    if (!foreground && boss_daemonize() < 0) {
        fprintf(stderr, "bossd: fork failed\n");
        return 1;
    }

    g_listen_fd = listen_socket();
    if (g_listen_fd < 0) {
        boss_log("listen failed: %s", strerror(errno));
        return 1;
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    boss_log("bossd up (proto v%d, sock @%s)", BOSS_PROTO_VER, BOSS_SOCK_NAME);

    for (;;) {
        int c = accept(g_listen_fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            usleep(100 * 1000);
            continue;
        }
        pid_t p = fork();
        if (p < 0) {
            close(c);
        } else if (p == 0) {
            close(g_listen_fd);
            signal(SIGCHLD, SIG_DFL);   /* 需要 waitpid 自己的子进程 */
            handle_client(c);
            _exit(0);
        } else {
            close(c);
        }
    }
    return 0;
}
