#!/usr/bin/env python3
"""把 policy/boss.rule 编成 C 数组 src/boss_rules.h。

为什么必须内嵌：早期注入发生在 init 的 selinux_setup 阶段，那时 /data
还没挂载，磁盘上的 policy/boss.rule 根本读不到。策略内容只能编进二进制。

policy/boss.rule 是"源"，src/boss_rules.h 是"产物"。改了前者必须重新生成
本文件（make rules 会跑它；CI 里还会反向校验两者一致，避免有人手改产物）。

规范化逻辑刻意与 src/sepolicy.c 的 normalize_line 保持一致：
  · '#' 之后是注释
  · 行尾分号可有可无
  · 空白压缩、两端 strip
这样"文件里看到的"和"引擎真正拿到的"是同一份东西，排查时不用猜。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "policy", "boss.rule")
DST = os.path.join(ROOT, "src", "boss_rules.h")

OPS = ("allow", "deny", "type", "typeattribute", "permissive",
       "type_transition", "type_change", "dontaudit", "auditallow")


def is_space(c):
    return c in " \t\r\n"


def normalize(line):
    """与 sepolicy.c 的 normalize_line 同构：去注释、压缩空白、去尾分号。"""
    out = []
    for c in line:
        if c == '#' or c in '\r\n':
            break
        if is_space(c):
            if out and not is_space(out[-1]):
                out.append(c)
        else:
            out.append(c)
    while out and (out[-1] == ';' or is_space(out[-1])):
        out.pop()
    return "".join(out).strip()


def op_of(rule):
    for op in OPS:
        if rule == op or rule.startswith(op + " "):
            return op
    return None


def collect(path):
    rules = []
    with open(path, "r", encoding="utf-8") as fp:
        for lineno, raw in enumerate(fp, 1):
            rule = normalize(raw)
            if not rule:
                continue
            if op_of(rule) is None:
                # 与 sepolicy.c 的态度一致：认不出来的跳过并提示，不静默丢
                print("gen_rules_h: 第 %d 行无法识别，已跳过: %s" % (lineno, rule),
                      file=sys.stderr)
                continue
            rules.append(rule)
    return rules


def cstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def main():
    if not os.path.exists(SRC):
        print("gen_rules_h: 找不到 %s" % SRC, file=sys.stderr)
        return 1
    rules = collect(SRC)
    if not rules:
        print("gen_rules_h: %s 里没有有效规则" % SRC, file=sys.stderr)
        return 1

    lines = []
    lines.append("/* 自动生成，请勿手改 —— 改 policy/boss.rule 后跑 `make rules` */")
    lines.append("/*")
    lines.append(" * 任务4 的核心策略内容，以 C 数组形式内嵌。")
    lines.append(" * 为什么内嵌：init 的 selinux_setup 阶段 /data 还没挂载，")
    lines.append(" * 读不到磁盘上的规则文件。早期注入只能用这份。")
    lines.append(" *")
    lines.append(" * 由 tools/gen_rules_h.py 从 policy/boss.rule 生成。")
    lines.append(" */")
    lines.append("#ifndef BOSS_RULES_H")
    lines.append("#define BOSS_RULES_H")
    lines.append("")
    lines.append("#define BOSS_RULES_VERSION 1")
    lines.append("")
    lines.append("static const char *const boss_builtin_rules[] = {")
    for r in rules:
        lines.append("    %s," % cstr(r))
    lines.append("};")
    lines.append("")
    lines.append("#define BOSS_BUILTIN_RULES_N "
                 "(sizeof(boss_builtin_rules) / sizeof(boss_builtin_rules[0]))")
    lines.append("")
    lines.append("#endif /* BOSS_RULES_H */")
    lines.append("")

    with open(DST, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("gen_rules_h: %d 条规则 -> %s" % (len(rules), DST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
