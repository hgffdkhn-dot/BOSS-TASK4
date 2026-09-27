#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "boss.h"

static int  g_log_fd = -1;
static int  g_log_on = 0;
static char g_log_path[256] = BOSS_LOG_PATH;

void boss_set_log(int on) { g_log_on = on; }

void boss_log_init(const char *path, int enabled)
{
    if (path) boss_copy(g_log_path, sizeof(g_log_path), path);
    g_log_on = enabled;
    if (!enabled) {
        if (g_log_fd >= 0) { close(g_log_fd); g_log_fd = -1; }
        return;
    }
    if (g_log_fd < 0)
        g_log_fd = open(g_log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

void boss_log_line(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    int fd = open(BOSS_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    char buf[1200];
    int n = snprintf(buf, sizeof(buf), "%s\n", msg);
    if (n > 0) (void)boss_write_full(fd, buf, (size_t)n);
    close(fd);
}

void boss_log(const char *fmt, ...)
{
    if (!g_log_on || g_log_fd < 0) return;

    char line[1024];
    int n = 0;
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    n = snprintf(line, sizeof(line), "[%04d-%02d-%02d %02d:%02d:%02d] ",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);

    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (n >= (int)sizeof(line)) n = (int)sizeof(line) - 1;
    line[n++] = '\n';
    ssize_t w = write(g_log_fd, line, (size_t)n);
    (void)w;
}

int boss_write_full(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += w; len -= (size_t)w;
    }
    return 0;
}

int boss_read_full(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len > 0) {
        ssize_t r = read(fd, p, len);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;   /* EOF */
        p += r; len -= (size_t)r;
    }
    return 0;
}

/* 抽象命名空间：sun_path[0] = '\0'，不产生任何文件节点 */
int boss_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t nlen = strlen(BOSS_SOCK_NAME);
    memcpy(addr.sun_path + 1, BOSS_SOCK_NAME, nlen);
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nlen);

    if (connect(fd, (struct sockaddr *)&addr, alen) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int boss_peer_uid(int fd, uid_t *uid, pid_t *pid)
{
    struct ucred cr;
    socklen_t len = sizeof(cr);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0) return -1;
    if (uid) *uid = cr.uid;
    if (pid) *pid = cr.pid;
    return 0;
}

size_t boss_blob_add(char *buf, size_t off, size_t cap, const char *s)
{
    size_t l = strlen(s) + 1;
    if (!buf) return off + 4 + l;             /* 只测量 */
    if (off + 4 + l > cap) return off;        /* 容量不足，丢弃该项 */
    uint32_t n = (uint32_t)l;
    memcpy(buf + off, &n, 4);
    memcpy(buf + off + 4, s, l);
    return off + 4 + l;
}

void boss_copy(char *dst, size_t n, const char *src)
{
    if (n == 0) return;
    snprintf(dst, n, "%s", src);
}

int boss_proc_cmdline(pid_t pid, char *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len - 1);
    close(fd);
    if (r <= 0) return -1;
    buf[r] = '\0';
    for (ssize_t i = 0; i < r; i++)
        if (buf[i] == '\0') buf[i] = ' ';
    return 0;
}

int boss_send_fd(int sock, int fd)
{
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    char dummy = 'F';
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));

    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

int boss_recv_fd(int sock)
{
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    char dummy;
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    if (recvmsg(sock, &msg, 0) < 0) return -1;

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

int boss_mkdirs(const char *path, mode_t mode)
{
    char tmp[256];
    boss_copy(tmp, sizeof(tmp), path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
            struct stat st;
            if (stat(tmp, &st) < 0 || !S_ISDIR(st.st_mode)) return -1;
        }
        *p = '/';
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
        struct stat st;
        if (stat(tmp, &st) < 0 || !S_ISDIR(st.st_mode)) return -1;
    }
    return 0;
}

int boss_daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);            /* 父进程立刻退出，适配 init 的 oneshot */

    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
    return 0;
}
