#!/bin/bash
# BOSS · 任务4（SELinux）验收测试
#
# 与 smoke_test / component_test 同样的两条原则：
#   · root 与非 root 两种身份都要能跑（CI runner 是普通用户）
#   · 需要 root 的检查明确标 SKIP，绝不静默通过
#
# 这里验的重点是**降级链与尽力而为语义**：真机上的策略内容沙盒验不了
# （没有真实 sepolicy），但"规则怎么递给引擎、失败怎么表达、无引擎时
# 会不会假装成功"这些恰恰是最容易写错、也最难在真机上排查的部分。
#
# 运行：bash tools/selinux_test.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望 '$3' 实际 '$2')"; fi; }

UID_NOW=$(id -u)
TEST_DIR=/tmp/boss-test
ENGINE_DIR=/data/adb/boss/bin
ENGINE="$ENGINE_DIR/magiskpolicy"
WORK=/tmp/boss-selinux-test

echo "== 构建 =="
make test >/dev/null 2>&1 || { echo "构建失败"; exit 1; }
BIN=./build/boss

rm -rf "$WORK" "$TEST_DIR" 2>/dev/null
mkdir -p "$WORK" "$TEST_DIR"

echo
echo "== 1. 策略内容是内嵌的，且与源文件一致 =="
# 早期注入时 /data 还没挂载，读不到磁盘文件，所以规则必须编进二进制。
# 但内嵌产物和 policy/boss.rule 走岔了会变成"改了没生效"，必须守住。
SRC_N=$(grep -cvE '^\s*(#|$)' policy/boss.rule)
BIN_N=$("$BIN" selinux rules --count)
echo "  源规则行 $SRC_N / 内嵌 $BIN_N（源文件含注释，内嵌数应 <= 源行数且 > 0）"
if [ "$BIN_N" -gt 0 ] && [ "$BIN_N" -le "$SRC_N" ]; then
    ok "内嵌规则数与源同量级"
else
    bad "内嵌规则数异常（源 $SRC_N / 内嵌 $BIN_N）"
fi

# 重新生成后产物不应变化（证明 src/boss_rules.h 没有被人手改过）
cp src/boss_rules.h "$WORK/rules.before" 2>/dev/null
python3 tools/gen_rules_h.py >/dev/null 2>&1
if diff -q "$WORK/rules.before" src/boss_rules.h >/dev/null 2>&1; then
    ok "产物与源同步（未手改 src/boss_rules.h）"
else
    bad "src/boss_rules.h 与 policy/boss.rule 不同步，请跑 make rules"
fi

echo
echo "== 2. 关键规则在位（模型完整性）=="
RULES=$("$BIN" selinux rules)
for r in "type boss domain" "type boss_file" "type boss_exec" "permissive boss" \
         "allow init boss process transition" "allow boss self unix_stream_socket bind"; do
    if echo "$RULES" | grep -qF "$r"; then ok "含 $r"; else bad "缺少 $r"; fi
done

echo
echo "== 3. status / source 在没 SELinux 的机器上不能崩 =="
"$BIN" selinux status >/dev/null 2>&1
check "status 返回 0（无 SELinux 也要能报）" "$?" "0"
"$BIN" selinux source >/dev/null 2>&1
RC=$?
# 沙盒没有 /sys/fs/selinux 也没有 precompiled_sepolicy，1 = 明确说找不到
if [ "$RC" -eq 1 ] || [ "$RC" -eq 0 ]; then ok "source 未崩溃（rc=$RC）"; else bad "source rc=$RC"; fi

echo
echo "== 4. 无引擎时必须进 pending 并返回 2（不能假装成功）=="
# 这是任务3 定下的契约，boot.c 的 apply_module_rules 依赖它：
# 2 = 没做成但不该中断开机；0 会被误判成"规则已生效"。
rm -f "$ENGINE" 2>/dev/null
echo "fake" > "$WORK/in.policy"
"$BIN" selinux patch "$WORK/in.policy" "$WORK/out.policy" >/dev/null 2>&1
check "patch 无引擎返回 2" "$?" "2"
if [ -f "$TEST_DIR/sepolicy.pending" ]; then
    ok "规则已落 pending 队列"
    check "pending 行数与内嵌一致" "$(wc -l < "$TEST_DIR/sepolicy.pending")" "$BIN_N"
else
    bad "pending 队列未生成"
fi

"$BIN" selinux pending >/dev/null 2>&1
check "pending 消费无引擎同样返回 2" "$?" "2"
if [ -f "$TEST_DIR/sepolicy.pending" ]; then ok "消费失败不清队列（不丢规则）"; else bad "队列被误清"; fi

echo
echo "== 5. 有引擎时：批量 → 失败降级逐条 → 统计正确 =="
# 这条验的是"尽力而为"：232 条规则里有一条在目标机型上不存在，
# 不该让整份策略失败，也不该被当成全成功。
if mkdir -p "$ENGINE_DIR" 2>/dev/null && cat > "$ENGINE" <<'EOF'
#!/bin/sh
echo "CALL: $@" >> /tmp/boss-selinux-test/engine.log
for a in "$@"; do
  case "$a" in
    *nonexistent_type*) exit 1 ;;
  esac
done
exit 0
EOF
chmod +x "$ENGINE" 2>/dev/null; then

    rm -f "$WORK/engine.log"
    printf 'allow boss boss_file:file read\nallow boss nonexistent_type:file read\nallow boss boss_file:dir search\n' > "$WORK/t.rule"

    OUT=$("$BIN" selinux live "$WORK/t.rule" 2>/dev/null)
    RC=$?
    check "部分应用返回 3" "$RC" "3"
    if echo "$OUT" | grep -q "应用 2 / 跳过 1 / 失败 0"; then
        ok "统计正确（应用 2 / 跳过 1）"
    else
        bad "统计不对: $OUT"
    fi
    # 先批量（一次 exec 传 3 条），失败后再逐条——省 exec 又保定位能力
    if [ -f "$WORK/engine.log" ]; then
        check "先批量调用" "$(head -1 "$WORK/engine.log" | grep -c 'file read allow')" "1"
        check "再逐条重试" "$(wc -l < "$WORK/engine.log")" "4"
    else
        bad "引擎未被调用"
    fi

    # 三号的工具层接到同一个引擎上
    RC=$("$BIN" sepolicy apply "$WORK/t.rule" >/dev/null 2>&1; echo $?)
    check "sepolicy apply 走任务4 引擎（部分应用算过）" "$RC" "0"

    rm -f "$ENGINE"
else
    skip "无法创建假引擎（需要 /data 写权限），降级链未验"
fi

echo
echo "== 6. 打标签 =="
if [ "$UID_NOW" -eq 0 ]; then
    mkdir -p "$TEST_DIR/sub"
    touch "$TEST_DIR/sub/f"
    "$BIN" selinux label "$TEST_DIR" "u:object_r:boss_file:s0" >/dev/null 2>&1
    check "label 返回 0 或 3" "$?" "0"
else
    skip "label（需要写 security.selinux xattr 的权限）"
fi

echo
echo "== 7. 命令分发 =="
"$BIN" selinux >/dev/null 2>&1
check "无子命令返回 1" "$?" "1"
"$BIN" selinux bogus >/dev/null 2>&1
check "未知子命令返回 1" "$?" "1"
if "$BIN" --list | grep -q "^  selinux"; then ok "applet 表已注册 selinux"; else bad "未注册"; fi

rm -rf "$WORK" 2>/dev/null
echo
echo "结果：PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
