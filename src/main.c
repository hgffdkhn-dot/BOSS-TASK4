#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>

#include "boss.h"
#include "applet.h"

/* 单二进制多入口：boss / su / bossd / init(顶替时) 以及任务3 的全部组件
 *  · 少落文件 = 少痕迹（隐蔽目标）
 *  · payload manifest 只需要声明一个二进制（ramdisk 体积是硬约束）
 *
 * 分发逻辑全部在 applet.c：这里只负责把 argv 交出去。
 * 两种调用方式等价：
 *   /data/adb/boss/bin/resetprop ro.foo bar     （symlink 调用）
 *   boss resetprop ro.foo bar                   （子命令调用）
 */
int main(int argc, char **argv)
{
    return boss_applet_dispatch(argc, argv);
}
