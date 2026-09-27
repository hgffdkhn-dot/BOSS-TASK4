#!/bin/bash
# BOSS · 任务4 —— libsepol 内置后端验收
#
# tools/selinux_test.sh 验的是"降级链与尽力而为语义"（那部分不需要真策略）。
# 这份验的是**策略真的被改对了**：type 建出来没有、permissive 有没有落上、
# attribute 有没有展开、写出来的策略还能不能被 libsepol 读回来。
#
# 沙盒/CI 里没有真机的 precompiled_sepolicy，也没有 checkpolicy 能现编一个，
# 所以用 tests/sepolkit.c 搭一个最小但合法的 kernel policy 当靶子。
# 它小（十几个 type），所以 boss.rule 里大部分规则会"目标不存在"被跳过——
# 这是预期的，正好把"尽力而为"跑了一遍。要验的点用专门的规则文件打。
#
# 前置：bash tools/vendor-sepol.sh && make sepolkit && make sepol
# 运行：bash tools/sepol_backend_test.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
has()  { if grep -q -- "$2" <<<"$1"; then ok "$3"; else bad "$3（没找到 '$2'）"; fi; }
hasnt(){ if grep -q -- "$2" <<<"$1"; then bad "$3（不该出现 '$2'）"; else ok "$3"; fi; }

BIN=./build/boss-sepol
KIT=./build/sepolkit
WORK=/tmp/boss-sepol-test

if [ ! -x "$BIN" ]; then
    echo "缺 $BIN —— 先跑：bash tools/vendor-sepol.sh && make sepol"; exit 1
fi
if [ ! -x "$KIT" ]; then
    echo "缺 $KIT —— 先跑：make sepolkit"; exit 1
fi

rm -rf "$WORK"; mkdir -p "$WORK"

echo
echo "== 1. 造靶子策略 =="
"$KIT" make "$WORK/base.policy" >/dev/null 2>&1
if [ -s "$WORK/base.policy" ]; then ok "基础策略已生成"; else bad "基础策略生成失败"; exit 1; fi
BASE_TYPES=$("$KIT" dump "$WORK/base.policy" init 2>/dev/null | sed -n 's/^POLICY.*types=\([0-9]*\).*/\1/p')
echo "  基础 type 数: $BASE_TYPES"

echo
echo "== 2. type 创建与 attribute 归属 =="
cat > "$WORK/r1.rule" <<'EOF'
type boss_test domain file_type
typeattribute boss_test mlstrustedobject
EOF
"$BIN" selinux patch "$WORK/base.policy" "$WORK/p1.policy" "$WORK/r1.rule" >/dev/null 2>&1
D=$("$KIT" dump "$WORK/p1.policy" boss_test 2>/dev/null)
has "$D" "TYPE boss_test" "新 type 已创建"
has "$D" "domain" "已归入 domain"
has "$D" "file_type" "已归入 file_type"
has "$D" "mlstrustedobject" "typeattribute 补的第三个 attribute 也生效"

echo
echo "== 3. permissive（最容易写错的一处） =="
# permissive_map 的位索引是 1 基，attribute 成员表是 0 基。
# 混用不会报错，只会让 permissive 落错 type——所以必须真的读回来验。
cat > "$WORK/r2.rule" <<'EOF'
type boss_perm domain
permissive boss_perm
EOF
"$BIN" selinux patch "$WORK/base.policy" "$WORK/p2.policy" "$WORK/r2.rule" >/dev/null 2>&1
D=$("$KIT" dump "$WORK/p2.policy" boss_perm 2>/dev/null)
has "$D" "PERMISSIVE yes" "permissive 位落到了目标 type 上"
DNEIGH=$("$KIT" dump "$WORK/p2.policy" kernel 2>/dev/null)
hasnt "$DNEIGH" "PERMISSIVE yes" "相邻 type 没有被误标 permissive（位索引没偏）"

echo
echo "== 4. attribute 展开 =="
# allow domain <tgt> 要展开成每个成员一条。
cat > "$WORK/r3.rule" <<'EOF'
type boss_x domain
allow domain boss_x process transition
EOF
"$BIN" selinux patch "$WORK/base.policy" "$WORK/p3.policy" "$WORK/r3.rule" >/dev/null 2>&1
D=$("$KIT" dump "$WORK/p3.policy" shell 2>/dev/null)
has "$D" "AV boss_x process transition" "attribute 源已展开到成员（shell）"
D2=$("$KIT" dump "$WORK/p3.policy" toolbox 2>/dev/null)
has "$D2" "AV boss_x process transition" "attribute 展开到另一个成员（toolbox）"
# rootfs 是 file_type 成员、不是 domain 成员，不该被展开到
D3=$("$KIT" dump "$WORK/p3.policy" rootfs 2>/dev/null)
hasnt "$D3" "AV boss_x process transition" "非成员没有被误展开"

echo
echo "== 5. 权限位与两种语法 =="
cat > "$WORK/r4.rule" <<'EOF'
type boss_y domain
allow boss_y boss_y file read open
allow boss_y boss_y:file write
EOF
"$BIN" selinux patch "$WORK/base.policy" "$WORK/p4.policy" "$WORK/r4.rule" >/dev/null 2>&1
D=$("$KIT" dump "$WORK/p4.policy" boss_y 2>/dev/null)
# 注意：dump 按权限位序输出（read/write/open 是 value 1/2/3），不是书写顺序，
# 所以这里逐权限判断，不要拿整串去比。
for pm in read write open; do
    has "$D" "$pm" "权限 $pm 已生效"
done
echo "  实际: $(grep 'AV boss_y file' <<<"$D")"

echo
echo "== 6. 通配权限 =="
cat > "$WORK/r5.rule" <<'EOF'
type boss_z domain
allow boss_z boss_z dir *
EOF
"$BIN" selinux patch "$WORK/base.policy" "$WORK/p5.policy" "$WORK/r5.rule" >/dev/null 2>&1
D=$("$KIT" dump "$WORK/p5.policy" boss_z 2>/dev/null)
if grep -q "AV boss_z dir" <<<"$D" && [ "$(grep -c 'AV boss_z dir' <<<"$D")" -ge 1 ]; then
    ok "通配权限已展开"
else
    bad "通配权限未展开"
fi
# dir 在这个靶子里有 7 个权限，全展开应该一次给全
N=$(grep 'AV boss_z dir' <<<"$D" | awk '{print NF-3}')
if [ "$N" -ge 7 ] 2>/dev/null; then ok "通配展开出全部 $N 个权限"; else bad "通配只展开出 $N 个（期望 >=7）"; fi

echo
echo "== 7. 写回的产物必须能被 libsepol 读回来 =="
# 这一条是整份交付的底线：注入后写出的策略如果读不回来，
# 就等于刷了个变砖的 sepolicy 进内核。
"$KIT" dump "$WORK/p5.policy" boss_z >/dev/null 2>&1
check_rc=$?
if [ $check_rc -eq 0 ]; then ok "patched 策略可被 libsepol 正常解析"; else bad "patched 策略解析失败（读不回来等于变砖）"; fi

echo
echo "== 8. 幂等：同一批规则注入两次不应出错 =="
"$BIN" selinux patch "$WORK/p5.policy" "$WORK/p6.policy" "$WORK/r5.rule" >/dev/null 2>&1
rc=$?
if [ $rc -eq 0 ] || [ $rc -eq 3 ]; then ok "二次注入未报错（rc=$rc）"; else bad "二次注入失败（rc=$rc）"; fi
"$KIT" dump "$WORK/p6.policy" boss_z >/dev/null 2>&1
if [ $? -eq 0 ]; then ok "二次注入产物仍可解析"; else bad "二次注入产物坏了"; fi

echo
echo "== 9. 尽力而为：目标不存在要跳过，不能整份失败 =="
cat > "$WORK/r7.rule" <<'EOF'
type boss_w domain
allow boss_w definitely_no_such_type file read
allow boss_w boss_w file read
EOF
OUT=$("$BIN" selinux patch "$WORK/base.policy" "$WORK/p7.policy" "$WORK/r7.rule" 2>/dev/null)
rc=$?
if [ $rc -eq 3 ]; then ok "部分应用返回 3（不是 1，不中断开机）"; else bad "返回 $rc（期望 3）"; fi
has "$OUT" "跳过" "日志里有跳过统计"
D=$("$KIT" dump "$WORK/p7.policy" boss_w 2>/dev/null)
has "$D" "AV boss_w file read" "同一批里那条正确的规则仍然生效"

echo
echo "== 10. BOSS_SEPOL=0 运行时关闭内置后端 =="
# 真机排查用：不用重刷包就能对比"外部引擎是否也失败"。
BOSS_SEPOL=0 "$BIN" selinux patch "$WORK/base.policy" "$WORK/p8.policy" "$WORK/r5.rule" >/dev/null 2>&1
rc=$?
if [ $rc -eq 2 ]; then ok "关闭后回落为无引擎（rc=2，规则进 pending）"; else bad "关闭后返回 $rc（期望 2）"; fi

echo
echo "== 11. 完整 boss.rule 注入不崩、产物可解析 =="
# 真机策略有上千 type，我们这个靶子只有十几个，所以绝大多数会被跳过。
# 这里验的是"整份跑下来不崩、不越界、写出来的还能读"。
OUT=$("$BIN" selinux patch "$WORK/base.policy" "$WORK/full.policy" 2>/dev/null)
rc=$?
if [ $rc -eq 0 ] || [ $rc -eq 3 ]; then ok "全量 255 条注入未崩溃（rc=$rc）"; else bad "全量注入 rc=$rc"; fi
echo "  $OUT"
"$KIT" dump "$WORK/full.policy" boss >/dev/null 2>&1
if [ $? -eq 0 ]; then ok "全量注入产物可被解析"; else bad "全量注入产物不可解析"; fi
FULL_TYPES=$("$KIT" dump "$WORK/full.policy" boss 2>/dev/null | sed -n 's/^POLICY.*types=\([0-9]*\).*/\1/p')
if [ -n "$FULL_TYPES" ] && [ "$FULL_TYPES" -gt "$BASE_TYPES" ] 2>/dev/null; then
    ok "type 数从 $BASE_TYPES 增到 $FULL_TYPES（boss 域已建）"
else
    bad "type 数没有增长（$BASE_TYPES → $FULL_TYPES）"
fi

echo
echo "结果：PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
