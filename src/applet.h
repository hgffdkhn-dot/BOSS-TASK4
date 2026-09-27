#ifndef BOSS_APPLET_H
#define BOSS_APPLET_H

/* A1 · applet 分发框架的内部接口（表定义见 applet.c） */
const struct boss_applet *boss_applet_find(const char *name);
const struct boss_applet *boss_applet_find_by_index(int i);   /* 遍历用，末尾返回 NULL */

#endif
