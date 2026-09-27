#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boss.h"

/* ------------------------------------------------------------------
 * 策略文件：纯文本，避免引入 sqlite 依赖（BOSS 量产版可换成 sqlite，
 * 接口保持 policy_load / policy_decide 不变即可）。
 *
 *   default = deny | allow
 *   log     = 0 | 1
 *   uid  <uid>   <allow|deny|prompt>    精确 uid（root=0, shell=2000）
 *   app  <appid> <allow|deny|prompt>    跨用户匹配（uid % 100000 == appid）
 *   user <uid>   <allow|deny|prompt>    整个 Android 用户（uid / 100000）
 *
 * 匹配优先级：uid > app > user > default（越具体越优先）。
 * ------------------------------------------------------------------ */

static const char *kDefaultPolicy =
    "# BOSS policy v1\n"
    "# default: deny | allow\n"
    "default = deny\n"
    "# log: 0 | 1（日用场景建议 0）\n"
    "log = 1\n"
    "# 规则示例（按注释按需打开）：\n"
    "# uid 0 allow          root / userdebug 的 adb\n"
    "# uid 2000 allow       adb shell\n"
    "# app 1000 allow       所有用户下的 system 应用\n"
    "uid 0 allow\n"
    "uid 2000 allow\n";

static int parse_decision(const char *s)
{
    if (!strcmp(s, "allow")) return BOSS_DECISION_ALLOW;
    if (!strcmp(s, "prompt")) return BOSS_DECISION_PROMPT;
    return BOSS_DECISION_DENY;
}

static const char *decision_name(int d)
{
    switch (d) {
    case BOSS_DECISION_ALLOW:  return "allow";
    case BOSS_DECISION_PROMPT: return "prompt";
    default:                   return "deny";
    }
}

/* 解析 "key = value" / "kind id decision"，容错空格 */
static int split_kv(char *line, char **a, char **b, char **c)
{
    *a = *b = *c = NULL;
    char *p = strchr(line, '#');
    if (p) *p = '\0';

    char *tok = strtok(line, " \t=\r\n");
    if (!tok) return 0;
    *a = tok;
    tok = strtok(NULL, " \t=\r\n");
    if (!tok) return 1;
    *b = tok;
    tok = strtok(NULL, " \t=\r\n");
    if (tok) *c = tok;
    return (*c) ? 3 : 2;
}

int policy_load(struct boss_policy *p, const char *path)
{
    memset(p, 0, sizeof(*p));
    p->log_enabled    = 1;
    p->default_decision = BOSS_DECISION_DENY;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    int cap = 16;
    p->rules = calloc((size_t)cap, sizeof(struct boss_rule));
    if (!p->rules) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f)) {
        char *a, *b, *c;
        int n = split_kv(line, &a, &b, &c);
        if (n < 2) continue;

        if (!strcmp(a, "default")) {
            p->default_decision = parse_decision(b);
        } else if (!strcmp(a, "log")) {
            p->log_enabled = atoi(b) ? 1 : 0;
        } else if (n == 3 && (!strcmp(a, "uid") || !strcmp(a, "app") || !strcmp(a, "user"))) {
            if (p->nrules == cap) {
                cap *= 2;
                struct boss_rule *nr = realloc(p->rules, (size_t)cap * sizeof(struct boss_rule));
                if (!nr) break;
                p->rules = nr;
            }
            struct boss_rule *r = &p->rules[p->nrules++];
            r->type = !strcmp(a, "uid") ? 0 : (!strcmp(a, "app") ? 1 : 2);
            r->id = atoi(b);
            r->decision = parse_decision(c);
        }
    }
    fclose(f);
    return 0;
}

void policy_free(struct boss_policy *p)
{
    free(p->rules);
    p->rules = NULL;
    p->nrules = 0;
}

int policy_decide(const struct boss_policy *p, uid_t uid)
{
    int best = -1, best_type = 99;
    for (int i = 0; i < p->nrules; i++) {
        const struct boss_rule *r = &p->rules[i];
        int match = 0;
        switch (r->type) {
        case 0: match = ((uid_t)r->id == uid); break;
        case 1: match = ((int)(uid % 100000) == r->id); break;
        case 2: match = ((int)(uid / 100000) == r->id); break;
        }
        if (match && r->type <= best_type) {  /* 0=uid 最具体；同级后写覆盖先写 */
            best_type = r->type;
            best = r->decision;
        }
    }
    return best < 0 ? p->default_decision : best;
}

int policy_ensure_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 0; }
    f = fopen(path, "w");
    if (!f) return -1;
    fputs(kDefaultPolicy, f);
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* ---------------- CLI: boss policy ... ---------------- */
int boss_policy_main(int argc, char **argv)
{
    const char *path = BOSS_POLICY_PATH;
    if (argc < 2) {
        fprintf(stderr,
                "usage: boss policy <cmd>\n"
                "  show\n"
                "  set default <deny|allow>\n"
                "  set log <0|1>\n"
                "  add  <uid|app|user> <id> <allow|deny|prompt>\n"
                "  del  <uid|app|user> <id>\n");
        return 2;
    }

    if (!strcmp(argv[1], "show")) {
        struct boss_policy p;
        if (policy_load(&p, path) < 0) { fprintf(stderr, "no policy file\n"); return 1; }
        printf("path    : %s\n", path);
        printf("default : %s\n", decision_name(p.default_decision));
        printf("log     : %d\n", p.log_enabled);
        for (int i = 0; i < p.nrules; i++) {
            const char *kind = p.rules[i].type == 0 ? "uid" : (p.rules[i].type == 1 ? "app" : "user");
            printf("rule    : %s %d %s\n", kind, p.rules[i].id, decision_name(p.rules[i].decision));
        }
        policy_free(&p);
        return 0;
    }

    if (!strcmp(argv[1], "set") && argc == 4) {
        struct boss_policy p;
        if (policy_load(&p, path) < 0) { policy_ensure_file(path); policy_load(&p, path); }
        int v = !strcmp(argv[3], "allow") ? BOSS_DECISION_ALLOW : atoi(argv[3]);
        if (!strcmp(argv[2], "default")) p.default_decision = v;
        else if (!strcmp(argv[2], "log")) p.log_enabled = v ? 1 : 0;
        else { fprintf(stderr, "unknown key %s\n", argv[2]); return 2; }
        /* 回写：整文件重写，保持人类可读与无外部依赖 */
        FILE *f = fopen(path, "w");
        if (!f) return 1;
        fprintf(f, "# BOSS policy v1\n# generated by boss policy\n");
        fprintf(f, "default = %s\n", decision_name(p.default_decision));
        fprintf(f, "log = %d\n", p.log_enabled);
        for (int i = 0; i < p.nrules; i++) {
            const char *kind = p.rules[i].type == 0 ? "uid" : (p.rules[i].type == 1 ? "app" : "user");
            fprintf(f, "%s %d %s\n", kind, p.rules[i].id, decision_name(p.rules[i].decision));
        }
        fclose(f);
        chmod(path, 0600);
        policy_free(&p);
        return 0;
    }

    if ((!strcmp(argv[1], "add") && argc == 5) || (!strcmp(argv[1], "del") && argc == 4)) {
        int add = !strcmp(argv[1], "add");
        FILE *f = fopen(path, "a");
        if (!f) { policy_ensure_file(path); f = fopen(path, "a"); }
        if (!f) return 1;
        if (add)
            fprintf(f, "%s %s %s\n", argv[2], argv[3], argv[4]);
        else
            fprintf(f, "# removed: %s %s\n", argv[2], argv[3]);
        fclose(f);
        return 0;
    }

    fprintf(stderr, "boss policy: unknown command\n");
    return 2;
}
