#define _GNU_SOURCE 1
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "boss.h"

/* 打开一对 pty。Android 的 /dev/ptmx + /dev/pts 走标准 posix_openpt，
 * 不需要 devpts 的额外 hack（老设备多实例 pts 问题放在 v0.2 处理）。 */
int boss_pty_open(int *master, int *slave, char *name, size_t namelen)
{
    int m = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (m < 0) return -1;
    if (grantpt(m) < 0 || unlockpt(m) < 0) { close(m); return -1; }

    char sname[128];
    if (ptsname_r(m, sname, sizeof(sname)) != 0) { close(m); return -1; }

    int s = open(sname, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (s < 0) { close(m); return -1; }

    if (name && namelen) boss_copy(name, namelen, sname);
    *master = m;
    *slave = s;
    return 0;
}

/* 关键：关掉 ONLCR，否则 -c 的每条输出都会被塞进 '\r'，
 * 脚本解析（很多 root 应用直接读 stdout）会被污染。 */
void boss_pty_setup(int master, int rows, int cols)
{
    struct termios tio;
    if (tcgetattr(master, &tio) == 0) {
        /* 关回显（避免把命令回传给客户端）与 ONLCR（避免 '\r' 污染输出）。
         * 保留 ISIG，让交互式 shell 里的 Ctrl-C 仍然可用。 */
        tio.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        tio.c_oflag &= ~(tcflag_t)(ONLCR | OCRNL | ONOCR | ONLRET);
        tio.c_iflag &= ~(tcflag_t)(ICRNL);
        tcsetattr(master, TCSANOW, &tio);
    }
    if (rows > 0 && cols > 0) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_row = (unsigned short)rows;
        ws.ws_col = (unsigned short)cols;
        ioctl(master, TIOCSWINSZ, &ws);
    }
}
