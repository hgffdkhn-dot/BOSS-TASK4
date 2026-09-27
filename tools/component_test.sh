#!/bin/bash
# BOSS 任务3 — 组件深度验收
#
# 与 smoke_test.sh 的分工：
#   smoke_test.sh    端到端链路（su 授权、daemon、任务3 主路径）——每次提交必跑
#   本脚本          任务3 组件的**边界与语义细节**——改动组件时必跑
#
# 覆盖 smoke 没覆盖的场景：值的长度边界、多级属性名、删除后重建、多区域互不干扰、
# 批量导入的脏输入、persist 快照的去重语义、.replace、多模块覆盖顺序、
# skip_mount/disable、分区分流、脚本排序与阶段隔离、规则形式、needs_root 报错。
#
# 全部在**离线**下可验（合成属性区 + dry run），所以 GitHub runner 的普通用户也能跑。
# 需要 root 的路径会被明确标成 SKIP，绝不静默通过。
#
# 运行：bash tools/component_test.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1（$2）"; SKIP=$((SKIP+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望 '$3' 实际 '$2')"; fi; }

UID_NOW=$(id -u)
ROOT=$([ "$UID_NOW" -eq 0 ] && echo 1 || echo 0)
TEST_DIR=/tmp/boss-test

# make test 不会覆盖已存在的 build/boss——跑着"另一个 BOSS_DIR 的二进制"
# 而不自知是踩过的坑，所以先 clean。
make clean >/dev/null 2>&1
make test >/dev/null 2>&1 || { echo "构建失败"; exit 1; }
BIN=$PWD/build/boss

# 清不掉就明说：残留目录通常属于另一个用户（root 跑完再以普通用户跑），
# 后面每一项都会"莫名其妙地失败"，而不是在这里就报错。
# 与其给出一片假红，不如直接停下让人 rm -rf 后重试。
rm -rf "$TEST_DIR" 2>/dev/null
if [ -e "$TEST_DIR" ] && [ "$UID_NOW" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo rm -rf "$TEST_DIR" 2>/dev/null
fi
if [ -e "$TEST_DIR" ]; then
    echo "ERROR: 无法清理 $TEST_DIR（多半属于其他用户）：rm -rf $TEST_DIR 后重试" >&2
    exit 1
fi
mkdir -p "$TEST_DIR"

PROPDIR=/tmp/boss-props
rm -rf "$PROPDIR" 2>/dev/null
if [ -e "$PROPDIR" ] && [ "$UID_NOW" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo rm -rf "$PROPDIR" 2>/dev/null
fi
if [ -e "$PROPDIR" ]; then
    echo "ERROR: 无法清理 $PROPDIR：rm -rf $PROPDIR 后重试" >&2
    exit 1
fi

echo "== 0. 属性区布局（与 init 共享内存的二进制契约）=="
# mkprop.py 照 bionic 布局造区；resetprop 里有编译期断言（sizeof 96/20/128），
# 这里再确认"造出来的区"确实能被正确解析——两端对得上才算真的对齐。
python3 tools/mkprop.py "$PROPDIR" ro.a=1 persist.b=2 >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.a 2>/dev/null)
check "合成区可被解析" "$OUT" "[ro.a]: [1]"

echo "== 1. resetprop：值的长度边界 =="
# PROP_VALUE_MAX=92，所以可用长度是 91。超长必须截断而不是越界写。
V91=$(python3 -c "print('a'*91)")
$BIN resetprop -n --dir "$PROPDIR" ro.len91 "$V91" >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.len91 2>/dev/null | sed 's/^\[ro.len91\]: \[//; s/\]$//')
check "91 字符完整写入" "${#OUT}" "91"
V200=$(python3 -c "print('b'*200)")
$BIN resetprop -n --dir "$PROPDIR" ro.len200 "$V200" >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.len200 2>/dev/null | sed 's/^\[ro.len200\]: \[//; s/\]$//')
# 截断到 91 而不是崩、也不是写坏相邻属性
if [ "${#OUT}" -le 91 ]; then ok "超长值被截断（长度 ${#OUT}）"; else bad "超长值未截断（长度 ${#OUT}）"; fi
OUT=$($BIN resetprop --dir "$PROPDIR" ro.a 2>/dev/null)
check "写超长值不影响相邻属性" "$OUT" "[ro.a]: [1]"

echo "== 2. resetprop：属性名形态 =="
$BIN resetprop -n --dir "$PROPDIR" ro.deep.nested.name.here v >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.deep.nested.name.here 2>/dev/null)
check "多级属性名（深层 trie）" "$OUT" "[ro.deep.nested.name.here]: [v]"
$BIN resetprop -n --dir "$PROPDIR" singlename s >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" singlename 2>/dev/null)
check "单段属性名（无点号）" "$OUT" "[singlename]: [s]"
# 前缀关系：ro.a 与 ro.ab 不应互相干扰
$BIN resetprop -n --dir "$PROPDIR" ro.ab xyz >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.a 2>/dev/null)
check "前缀相近的属性互不干扰" "$OUT" "[ro.a]: [1]"

echo "== 3. resetprop：删除后重新新增 =="
$BIN resetprop -d --dir "$PROPDIR" ro.a >/dev/null 2>&1
$BIN resetprop --dir "$PROPDIR" ro.a >/dev/null 2>&1
check "删除后读不到" "$?" "1"
$BIN resetprop -n --dir "$PROPDIR" ro.a rebuilt >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.a 2>/dev/null)
check "删除后可重新新增" "$OUT" "[ro.a]: [rebuilt]"

echo "== 4. resetprop：多区域互不干扰 =="
# mkprop 按前缀分区域：ro.* 与 persist.* 在不同文件里
OUT=$($BIN resetprop --dir "$PROPDIR" persist.b 2>/dev/null)
check "另一区域的属性仍可读" "$OUT" "[persist.b]: [2]"
$BIN resetprop -n --dir "$PROPDIR" ro.a changed >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" persist.b 2>/dev/null)
check "改一个区域不影响另一区域" "$OUT" "[persist.b]: [2]"

echo "== 5. resetprop：批量导入的脏输入 =="
printf '\n# only comment\nno-equals-line\nro.dirty = dv\npersist.d = pv\n' > /tmp/dirty.prop
$BIN resetprop -n --dir "$PROPDIR" --file /tmp/dirty.prop >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.dirty 2>/dev/null)
check "空行/注释/无等号行不阻断导入" "$OUT" "[ro.dirty]: [dv]"
OUT=$($BIN resetprop --dir "$PROPDIR" persist.d 2>/dev/null)
check "脏输入后后续条目仍生效" "$OUT" "[persist.d]: [pv]"

echo "== 6. resetprop：persist 快照语义 =="
rm -f "$TEST_DIR/persist.props"
$BIN resetprop -n -p --dir "$PROPDIR" persist.snap one >/dev/null 2>&1
$BIN resetprop -n -p --dir "$PROPDIR" persist.snap two >/dev/null 2>&1
check "同属性重复设置只留一条" "$(wc -l < "$TEST_DIR/persist.props" | tr -d ' ')" "1"
check "保留的是最后一次的值" "$(cat "$TEST_DIR/persist.props")" "persist.snap=two"
$BIN resetprop -n -p --dir "$PROPDIR" -d persist.snap >/dev/null 2>&1
check "删除后快照变成删除标记" "$(cat "$TEST_DIR/persist.props")" "!persist.snap"
$BIN resetprop -n -p --dir "$PROPDIR" ro.notpersist x >/dev/null 2>&1
if grep -q 'ro.notpersist' "$TEST_DIR/persist.props" 2>/dev/null; then
    bad "非 persist 属性不该进快照"
else
    ok "非 persist 属性不进快照"
fi

echo "== 7. module：.replace 整体替换 =="
mkdir -p "$TEST_DIR/modules/rep/system/app/Demo"
printf 'id=rep\nname=Rep\nversion=1\n' > "$TEST_DIR/modules/rep/module.prop"
printf 'x' > "$TEST_DIR/modules/rep/system/app/Demo/a.apk"
: > "$TEST_DIR/modules/rep/system/app/Demo/.replace"
if $BIN module plan 2>/dev/null | grep -q '# replace'; then
    ok ".replace 在挂载计划中可见"
else
    bad ".replace 未在挂载计划中体现"
fi
# .replace 本身不能被挂载成一个文件
if $BIN module plan 2>/dev/null | grep -q '/\.replace'; then
    bad ".replace 被当成文件挂载了"
else
    ok ".replace 不会作为文件被挂载"
fi

echo "== 8. module：多模块的覆盖顺序 =="
mkdir -p "$TEST_DIR/modules/m1/system/bin" "$TEST_DIR/modules/m2/system/bin"
printf 'id=m1\nname=M1\nversion=1\n' > "$TEST_DIR/modules/m1/module.prop"
printf 'id=m2\nname=M2\nversion=1\n' > "$TEST_DIR/modules/m2/module.prop"
printf 'from-m1' > "$TEST_DIR/modules/m1/system/bin/tool"
printf 'from-m2' > "$TEST_DIR/modules/m2/system/bin/tool"
# 按 id 排序，m2 在后，应覆盖 m1
N=$($BIN module plan 2>/dev/null | grep -c 'system/bin/tool ->')
check "同一文件只挂载一次" "$N" "1"
if $BIN module plan 2>/dev/null | grep 'system/bin/tool ->' | grep -q 'm2'; then
    ok "后序模块覆盖先序模块"
else
    bad "覆盖顺序不对"
fi

echo "== 9. module：skip_mount / disable =="
mkdir -p "$TEST_DIR/modules/skipmod/system/bin" "$TEST_DIR/modules/offmod/system/bin"
printf 'id=skipmod\nname=S\nversion=1\n' > "$TEST_DIR/modules/skipmod/module.prop"
printf 'id=offmod\nname=O\nversion=1\n' > "$TEST_DIR/modules/offmod/module.prop"
printf 's' > "$TEST_DIR/modules/skipmod/system/bin/sk"
printf 'o' > "$TEST_DIR/modules/offmod/system/bin/off"
: > "$TEST_DIR/modules/skipmod/skip_mount"
: > "$TEST_DIR/modules/offmod/disable"
if $BIN module plan 2>/dev/null | grep -q 'skipmod'; then bad "skip_mount 模块不该被挂载"; else ok "skip_mount 模块不挂载"; fi
if $BIN module plan 2>/dev/null | grep -q 'offmod'; then bad "disable 模块不该被挂载"; else ok "disable 模块不挂载"; fi
# 两个模块都还应该在列表里（挂载与列表是两回事）
N=$($BIN module list 2>/dev/null | grep -cE 'skipmod|offmod')
check "两者仍在模块列表中" "$N" "2"

echo "== 10. module：分区分流 =="
mkdir -p "$TEST_DIR/modules/partmod/system/vendor/lib"
printf 'id=partmod\nname=P\nversion=1\n' > "$TEST_DIR/modules/partmod/module.prop"
printf 'v' > "$TEST_DIR/modules/partmod/system/vendor/lib/v.so"
if $BIN module plan 2>/dev/null | grep -q 'partition vendor'; then
    ok "system/vendor 分流到 vendor 分区"
else
    bad "system/vendor 未分流"
fi

echo "== 11. script：文件筛选与执行顺序 =="
mkdir -p "$TEST_DIR/service.d"
printf '#!/bin/sh\necho A\n' > "$TEST_DIR/service.d/01-a.sh"
printf '#!/bin/sh\necho B\n' > "$TEST_DIR/service.d/02-b.sh"
printf '#!/bin/sh\necho C\n' > "$TEST_DIR/service.d/03-c.sh"
printf '#!/bin/sh\necho NO\n' > "$TEST_DIR/service.d/notsh.txt"
printf '#!/bin/sh\necho NO\n' > "$TEST_DIR/service.d/nonexec.sh"
chmod +x "$TEST_DIR/service.d/01-a.sh" "$TEST_DIR/service.d/02-b.sh" "$TEST_DIR/service.d/03-c.sh"
: > "$TEST_DIR/boss.log"
$BIN script service --timeout 5 >/dev/null 2>&1
ORDER=$(grep -oE '(OK|FAIL)   .*/(0[0-9]-[a-c]\.sh)' "$TEST_DIR/boss.log" | grep -oE '0[0-9]-[a-c]' | tr '\n' ',')
check "按文件名排序执行" "$ORDER" "01-a,02-b,03-c,"
if grep -q 'notsh.txt' "$TEST_DIR/boss.log"; then
    bad "非 .sh 文件被执行了"
else
    ok "非 .sh 文件被忽略"
fi
# 有意的设计：丢掉可执行位是模块脚本的常态，严格检查会让大量脚本静默不跑
if grep -q 'nonexec.sh' "$TEST_DIR/boss.log"; then
    ok "无可执行位的 .sh 仍执行（对齐 Magisk，兼容性优先）"
else
    bad "无可执行位的 .sh 未执行（会破坏模块生态兼容）"
fi

echo "== 12. script：阶段隔离 =="
mkdir -p "$TEST_DIR/post-fs-data.d" "$TEST_DIR/boot-completed.d"
printf '#!/bin/sh\nearly\n' > "$TEST_DIR/post-fs-data.d/01-early.sh"
printf '#!/bin/sh\nlate\n' > "$TEST_DIR/boot-completed.d/01-late.sh"
chmod +x "$TEST_DIR/post-fs-data.d/01-early.sh" "$TEST_DIR/boot-completed.d/01-late.sh"
: > "$TEST_DIR/boss.log"
$BIN script boot-completed --timeout 5 >/dev/null 2>&1
if grep -q '01-early.sh' "$TEST_DIR/boss.log"; then bad "boot-completed 阶段跑了 post-fs-data 的脚本"; else ok "阶段之间不串台"; fi
if grep -q '01-late.sh' "$TEST_DIR/boss.log"; then ok "本阶段脚本被执行"; else bad "本阶段脚本未执行"; fi

echo "== 13. sepolicy：规则形式覆盖 =="
cat > "$TEST_DIR/rules.txt" <<'EOF'
allow a b:file read;
deny a b:file write;
type boss_file
typeattribute boss_file mlstrustedobject
permissive boss
type_transition a b:process c
this is not a rule
EOF
OUT=$($BIN sepolicy check "$TEST_DIR/rules.txt" 2>/dev/null)
N=$(printf '%s\n' "$OUT" | grep -c .)
check "6 条合法规则 + 1 条非法" "$N" "6"
if printf '%s\n' "$OUT" | grep -q 'not a rule'; then bad "非法规则未被过滤"; else ok "非法规则被过滤"; fi
if printf '%s\n' "$OUT" | grep -q ';$'; then bad "分号未清理"; else ok "分号已清理"; fi

echo "== 14. needs_root 组件在非 root 下要明确报错 =="
if [ "$ROOT" -eq 0 ]; then
    OUT=$($BIN boot post-fs-data 2>&1)
    if printf '%s' "$OUT" | grep -q '需要 root'; then
        ok "boot 在非 root 下明确报错"
    else
        bad "boot 在非 root 下没报错（静默失败最危险）"
    fi
else
    skip "needs_root 报错" "当前是 root，该分支不进入"
fi

echo "== 15. boot 编排：每步都留痕 =="
if [ "$ROOT" -eq 1 ]; then
    : > "$TEST_DIR/boss.log"
    $BIN boot post-fs-data >/dev/null 2>&1
    if grep -q 'boot: step begin' "$TEST_DIR/boss.log"; then
        ok "编排步骤写入日志（真机排查靠它）"
    else
        bad "编排步骤没有日志"
    fi
else
    skip "boot 编排日志" "需要 root"
fi

echo "== 16. daemon 不得要求 root（踩过的坑）=="
# 曾经把 daemon 标成 needs_root，结果 GitHub runner（普通用户）上
# `boss daemon` 直接报错退出 → 整条 su 链路 7 项全红。
# daemon 在非 root 下只是无法提权（目标身份降级为自身），不该拦在门外。
N=$($BIN --list 2>/dev/null | grep -E '^[[:space:]]+daemon' | grep -c '\[root\]')
check "daemon 不标 [root]" "$N" "0"
$BIN daemon >/dev/null 2>&1
for i in $(seq 1 24); do $BIN ping >/dev/null 2>&1 && break; sleep 0.25; done
check "daemon 在当前身份下能起来" "$($BIN ping >/dev/null 2>&1; echo $?)" "0"
pkill -x boss 2>/dev/null; sleep 0.2

echo
echo "结果：PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ $FAIL -eq 0 ] || exit 1
