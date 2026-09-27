#define _GNU_SOURCE 1
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "boss.h"

extern char **environ;

static void usage(void)
{
    fprintf(stderr,
        "usage: su [-c <command>] [-s <shell>] [-u <uid>] [-g <gid>]\n"
        "          [-l|--login] [-p|--preserve-environment]\n"
        "          [--context <selinux-domain>] [-V|--version]\n");
}

static void send_blob(int sock, const char *buf, size_t len)
{
    if (len && boss_write_full(sock, buf, len) < 0) { /* 对端提前关闭 */ }
}

/* 协议第一步：用 SCM_RIGHTS 把"退出码回传通道"交给 daemon。
 * 所有连接（含探活）都必须先走这一步——否则 daemon 的 recvmsg 会
 * 把请求体的第一个字节当握手吃掉，后面整条流全部错位。 */
int boss_send_handshake(int sock)
{
    int sv[2] = { -1, -1 };
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    if (boss_send_fd(sock, sv[1]) < 0) { close(sv[0]); close(sv[1]); return -1; }
    close(sv[1]);
    return sv[0];
}

int boss_su_main(int argc, char **argv)
{
    struct boss_request req;
    memset(&req, 0, sizeof(req));
    req.magic = BOSS_MAGIC;
    req.version = BOSS_PROTO_VER;
    req.target_uid = 0;
    req.target_gid = 0;

    /* -c 之后的全部内容拼成一条命令，避免被 shell 再切一次 */
    int i = 1;
    int cmd_mode = 0;
    char cmd[BOSS_MAX_CMD] = { 0 };

    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("BOSS su 0.1.0 (proto v%d)\n", BOSS_PROTO_VER);
            return 0;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage();
            return 0;
        } else if (!strcmp(a, "-c") && i + 1 < argc) {
            cmd_mode = 1;
            i++;
            boss_copy(cmd, sizeof(cmd), argv[i]);
        } else if (!strcmp(a, "-s") && i + 1 < argc) {
            i++;
            boss_copy(req.shell, sizeof(req.shell), argv[i]);
        } else if (!strcmp(a, "-u") && i + 1 < argc) {
            i++;
            req.target_uid = (uint32_t)atoi(argv[i]);
        } else if (!strcmp(a, "-g") && i + 1 < argc) {
            i++;
            req.target_gid = (uint32_t)atoi(argv[i]);
        } else if (!strcmp(a, "--context") && i + 1 < argc) {
            i++;
            boss_copy(req.context, sizeof(req.context), argv[i]);
        } else if (!strcmp(a, "-l") || !strcmp(a, "--login") || !strcmp(a, "-")) {
            req.flags |= BOSS_F_LOGIN;
        } else if (!strcmp(a, "-p") || !strcmp(a, "--preserve-environment")) {
            req.flags |= BOSS_F_KEEPENV;
        } else if (!strcmp(a, "-mm") || !strcmp(a, "-m")) {
            req.flags |= BOSS_F_KEEPENV;
        } else if (a[0] != '-') {
            /* 目标用户名/参数：v1 忽略，留给 v2 的参数透传 */
        }
    }
    boss_copy(req.command, sizeof(req.command), cmd);
    (void)cmd_mode;

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        req.rows = ws.ws_row;
        req.cols = ws.ws_col;
    }

    /* 环境变量 blob（daemon 端只在 KEEPENV 时整体使用，否则只取 TERM） */
    size_t env_len = 0;
    for (char **e = environ; *e; e++)
        env_len = boss_blob_add(NULL, env_len, 0, *e);
    char *env_blob = NULL;
    if (env_len) {
        env_blob = calloc(1, env_len + 8);
        size_t off = 0;
        for (char **e = environ; *e && off < env_len; e++)
            off = boss_blob_add(env_blob, off, env_len, *e);
        req.env_len = (uint32_t)off;
    }

    int sock = boss_connect();
    if (sock < 0) {
        fprintf(stderr, "su: bossd 未运行或 BOSS 未安装\n");
        free(env_blob);
        return 1;
    }

    /* side channel：让 daemon 能把子进程的退出码回传，
     * 不占用主数据通道，避免退出码被当成输出打印出来。 */
    int status_sock = boss_send_handshake(sock);

    if (boss_write_full(sock, &req, sizeof(req)) < 0) {
        fprintf(stderr, "su: 与 bossd 通信失败\n");
        close(sock);
        free(env_blob);
        return 1;
    }
    if (req.env_len) send_blob(sock, env_blob, req.env_len);

    struct boss_response rep;
    memset(&rep, 0, sizeof(rep));
    if (boss_read_full(sock, &rep, sizeof(rep)) < 0) {
        fprintf(stderr, "su: 无响应\n");
        close(sock);
        free(env_blob);
        return 1;
    }
    if (rep.code != BOSS_OK) {
        const char *why = rep.code == BOSS_DENIED ? "策略拒绝" :
                          (rep.code == BOSS_PROMPT ? "等待 BOSS 前端授权" : "内部错误");
        fprintf(stderr, "su: %s (uid=%u)\n", why, (unsigned)getuid());
        close(sock);
        free(env_blob);
        return 1;
    }

    /* 交互式：把自己的终端切成 raw，让 ^C / 补全等直接透传 */
    struct termios saved;
    int tty = isatty(STDIN_FILENO);
    int restored = 0;
    if (tty && tcgetattr(STDIN_FILENO, &saved) == 0) {
        struct termios raw = saved;
        raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON | ISIG | IEXTEN);
        raw.c_iflag &= ~(tcflag_t)(ICRNL | IXON);
        raw.c_oflag &= ~(tcflag_t)(OPOST);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        restored = 1;
    }

    char buf[8192];
    int exit_code = 0, got_code = 0;
    struct pollfd fds[3];
    int stdin_open = 1;

    while (1) {
        int nfd = 0;
        fds[nfd].fd = sock;      fds[nfd].events = POLLIN; fds[nfd].revents = 0; nfd++;
        fds[nfd].fd = status_sock >= 0 ? status_sock : -1; fds[nfd].events = POLLIN; fds[nfd].revents = 0; nfd++;
        if (stdin_open) { fds[nfd].fd = STDIN_FILENO; fds[nfd].events = POLLIN; fds[nfd].revents = 0; nfd++; }

        int r = poll(fds, (nfds_t)nfd, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(sock, buf, sizeof(buf));
            if (n <= 0) break;
            (void)boss_write_full(STDOUT_FILENO, buf, (size_t)n);
        }
        if (fds[1].fd >= 0 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            uint32_t ec = 0;
            ssize_t n = read(fds[1].fd, &ec, sizeof(ec));
            if (n == (ssize_t)sizeof(ec)) { exit_code = (int)ec; got_code = 1; }
            break;
        }
        if (stdin_open && (fds[2].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                /* 注意：这里不能 shutdown(sock, SHUT_WR)。
                 * 一旦把写方向关掉，daemon 会认为客户端消失而杀掉子进程，
                 * 导致 -c 的输出还没吐完就被截断。保持连接即可。 */
                stdin_open = 0;
            } else if (boss_write_full(sock, buf, (size_t)n) < 0) {
                break;
            }
        }
    }

    /* 数据结束到退出码到达有一点时间差，等一下再收 */
    if (!got_code && status_sock >= 0) {
        struct pollfd p = { .fd = status_sock, .events = POLLIN };
        if (poll(&p, 1, 300) > 0) {
            uint32_t ec = 0;
            if (read(status_sock, &ec, sizeof(ec)) == (ssize_t)sizeof(ec)) exit_code = (int)ec;
        }
    }

    if (restored) tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    if (status_sock >= 0) close(status_sock);
    close(sock);
    free(env_blob);
    return exit_code;
}
