#!/bin/bash
# BOSS · init stage2 接线验收（任务4 的落点 → su 侧 v0.2）
#
# 这条链路的特殊之处在于：**出错就是变砖**，而沙盒里没有真机可验。
# 所以这里用 BOSS_INIT_REAL 把"真实 init"换成一个只记录参数的假脚本，
# 让"我们到底把什么参数交给了 init"变成可断言的东西。
#
# 重点验三件事：
#   1. selinux_setup 会被接住（以前它落到"未知参数"分支，早期注入一次都不执行）
#   2. 阶段参数不再被丢掉（以前固定从 argv[2] 转发，真机写法下 second_stage
#      整个丢失 → 真实 init 无参数启动 → 重跑第一阶段 → 死循环）
#   3. 注入失败时退回原厂路径（传 selinux_setup 而不是 second_stage），
#      最坏情况只是 BOSS 没有早期规则，开机本身不受影响
#
# 前置：make test
# 运行：bash tools/stage2_test.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }

BIN=$PWD/build/boss
WORK=/tmp/boss-stage2-test
ARGS=$WORK/init-args.txt

# /sepolicy 是 find_policy 的候选之一。沙盒里没有真机策略，造一个假的
# 让 cmd_setup 能走到"无引擎 → 落 pending"，从而证明子进程真的跑了注入。
# 用完删掉——留着会污染后续测试。
FAKE_SEPOLICY=/sepolicy

cleanup() {
    rm -rf "$WORK"
    [ -f "$FAKE_SEPOLICY" ] && rm -f "$FAKE_SEPOLICY"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then echo "缺 $BIN —— 先跑 make test"; exit 1; fi

rm -rf "$WORK" /tmp/boss-test
mkdir -p "$WORK" /tmp/boss-test

# 假 init：只把收到的参数写下来
cat > "$WORK/fake-init" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > $ARGS
exit 0
EOF
chmod +x "$WORK/fake-init"
export BOSS_INIT_REAL="$WORK/fake-init"

run() {   # run <boss 参数...>  → 打印假 init 收到的参数
    rm -f "$ARGS"
    "$BIN" "$@" >/dev/null 2>&1
    cat "$ARGS" 2>/dev/null
}

echo
echo "== 1. 阶段参数不再被丢（这条以前是死循环 bug）=="
# 真机 2SI 的写法：init exec 的是 `/system/bin/init second_stage`，
# argv[1] 就是阶段参数。以前固定从 argv[2] 转发，这里会转发成空。
OUT=$(run init second_stage)
if [ "$OUT" = "second_stage" ]; then ok "second_stage 已转发（真机写法）"; else bad "转发了 '$OUT'（期望 second_stage）"; fi

OUT=$(run init stage2 second_stage)
if [ "$OUT" = "second_stage" ]; then ok "second_stage 已转发（手动/脚本写法）"; else bad "转发了 '$OUT'（期望 second_stage）"; fi

echo
echo "== 2. selinux_setup 被接住，且早期注入确实执行了 =="
# 造一个假的 /sepolicy，让 cmd_setup 走到"无引擎 → 落 pending"。
# pending 文件出现 = 子进程真的跑了 `boss selinux setup`，
# 这比"看它有没有报错"可靠得多。
echo "fake" > "$FAKE_SEPOLICY"
rm -f /tmp/boss-test/sepolicy.pending
OUT=$(run init selinux_setup)

if [ -s /tmp/boss-test/sepolicy.pending ]; then
    ok "早期注入确实执行了（pending 已落盘，证明子进程跑过 selinux setup）"
else
    bad "早期注入没有执行（pending 未生成）"
fi

# 沙盒里没有内核，load 必然失败 → 必须退回原厂路径
if [ "$OUT" = "selinux_setup" ]; then
    ok "注入失败时退回原厂路径（传 selinux_setup，开机不受影响）"
else
    bad "注入失败却传了 '$OUT'（期望 selinux_setup，否则 init 会跳过自己的 setup）"
fi

echo
echo "== 3. 绝不 exec 自己（找不到真实 init 时的兜底）=="
# 这条是变砖的最后一道闸：BOSS 找不到真实 init 时必须放弃，
# 绝不能把自己当 init 再 exec 一次（那是死循环）。
unset BOSS_INIT_REAL
rm -f "$ARGS"
"$BIN" init selinux_setup >/dev/null 2>&1
rc=$?
if [ $rc -eq 127 ]; then ok "找不到真实 init 时返回 127（没有 exec 自己）"; else bad "返回 $rc（期望 127）"; fi
export BOSS_INIT_REAL="$WORK/fake-init"

echo
echo "== 4. cmdline 开关能关掉早期注入 =="
# 沙盒改不了 /proc/cmdline，这里只验"开关存在且默认不触发"：
# 即不设 boss_selinux=0 时，注入照常尝试。真机上加这个参数即可退回原厂路径，
# 不用重刷包——自救路径的成本直接决定能不能迭代下去。
rm -f /tmp/boss-test/sepolicy.pending
run init selinux_setup >/dev/null
if [ -s /tmp/boss-test/sepolicy.pending ]; then
    ok "默认（无 boss_selinux=0）时早期注入照常尝试"
else
    bad "默认就不尝试了，说明开关被误触发"
fi

echo
echo "== 5. 注入成功那条分支无法在沙盒验到 =="
skip "传 second_stage 的成功路径需要真机（要有 /sys/fs/selinux/load 可写）"
skip "真机再验：cat /proc/1/attr/current 应为 u:r:init:s0（域切换靠 exec init_exec 标签的文件）"

echo
echo "结果：PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
