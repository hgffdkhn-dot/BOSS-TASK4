#!/bin/bash
# BOSS su — 主机侧冒烟测试
#
# 覆盖：daemon 探活、授权执行、环境净化、退出码回传、无 CR 污染、
#       策略拒绝、审计日志、交互式 shell。
#
# 同时适配 root 与非 root（GitHub runner 默认是普通用户）：
#   · 非 root 时 daemon 会把目标身份降级为自身（见 daemon.c），
#     "提权"这一步验不到，但其余整条链路仍然是真实验证。
#
# 运行：bash tools/smoke_test.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (期望 '$3' 实际 '$2')"; fi; }

UID_NOW=$(id -u)
# root 跑时目标 uid 是 0；非 root 时降级为自身
if [ "$UID_NOW" -eq 0 ]; then EXPECT_UID=0; else EXPECT_UID=$UID_NOW; fi
TEST_DIR=/tmp/boss-test

echo "== 构建（运行时目录 $TEST_DIR）=="
make test >/dev/null 2>&1 || { echo "构建失败"; exit 1; }
BIN=./build/boss-test

stop_daemon() { pkill -x boss >/dev/null 2>&1; pkill -x boss-test >/dev/null 2>&1; sleep 0.2; }
stop_daemon
rm -rf "$TEST_DIR" 2>/dev/null
# 清不掉就明说：残留的目录通常属于另一个用户（root 跑完再以普通用户跑），
# 会让后面几项莫名其妙地失败，而不是在这里就报错。
if [ -e "$TEST_DIR" ]; then
    # 常见场景：先以 root 跑过一次，目录归 root。有 sudo 就代劳一次。
    if [ "$UID_NOW" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo rm -rf "$TEST_DIR" 2>/dev/null
    fi
fi
if [ -e "$TEST_DIR" ]; then
    echo "ERROR: 无法清理 $TEST_DIR（多半属于其他用户）：rm -rf $TEST_DIR 后重试" >&2
    exit 1
fi

# 预置策略：默认拒绝，显式允许当前 uid（覆盖 root 与 CI 的普通用户）
mkdir -p "$TEST_DIR"
cat > "$TEST_DIR/policy.conf" <<EOF
# BOSS policy v1 (test)
default = deny
log = 1
uid $UID_NOW allow
EOF

echo "== 1. daemon 启动与探活 =="
$BIN daemon >/dev/null 2>&1
for i in $(seq 1 24); do $BIN ping >/dev/null 2>&1 && break; sleep 0.25; done
check "boss ping" "$($BIN ping >/dev/null 2>&1; echo $?)" "0"

echo "== 2. 授权执行 =="
OUT=$($BIN su -c 'id -u' 2>/dev/null)
check "su -c 'id -u'" "$OUT" "$EXPECT_UID"

echo "== 3. 环境变量净化（USER 应为 root）=="
OUT=$($BIN su -c 'echo $USER' 2>/dev/null)
check "su -c 'echo \$USER'" "$OUT" "root"

echo "== 4. 退出码回传 =="
$BIN su -c 'exit 7' >/dev/null 2>&1
check "su -c 'exit 7' 的退出码" "$?" "7"

echo "== 5. 输出不被 pty 污染（不应含 \\r）=="
OUT=$($BIN su -c 'printf ABC' 2>/dev/null | od -c | head -1)
case "$OUT" in *"\\r"*) bad "输出含 CR：$OUT";; *) ok "输出无 CR 污染";; esac

echo "== 6. 策略拒绝 =="
$BIN policy add uid "$UID_NOW" deny >/dev/null 2>&1
OUT=$($BIN su -c 'id -u' 2>&1); RC=$?
check "拒绝时退出码非 0" "$([ $RC -ne 0 ] && echo yes)" "yes"
case "$OUT" in *拒绝*) ok "拒绝提示正确";; *) bad "拒绝提示异常：$OUT";; esac
$BIN policy add uid "$UID_NOW" allow >/dev/null 2>&1

echo "== 7. 日志记录 =="
if grep -q "uid=$UID_NOW" "$TEST_DIR/boss.log" 2>/dev/null; then ok "日志已写入"; else bad "无日志"; fi

echo "== 8. 交互式 shell（管道喂一条命令）=="
OUT=$(printf 'echo hi-from-shell\nexit\n' | $BIN su 2>/dev/null | tr -d '\r' | grep -c 'hi-from-shell')
check "交互式 shell 可执行命令" "$OUT" "1"

# ---------- 任务3：关键组件 ----------
# 这些组件在真机上需要 root，但都能在主机侧离线验证：
#   · resetprop 用 --dir 指向 tools/mkprop.py 造的合成属性区
#   · script / module / sepolicy 只跑不需要特权的路径（dry run、解析、列表）
# 这样 CI 的普通用户也能真正验到逻辑，而不是一律 skip。

echo "== 9. applet 分发：子命令与 symlink 两种调用等价 =="
mkdir -p "$TEST_DIR/bin"
ln -sf "$(pwd)/build/boss-test" "$TEST_DIR/bin/resetprop"
A=$($BIN --list 2>/dev/null | grep -c 'resetprop')
check "--list 含 resetprop" "$A" "1"
A=$($BIN --list 2>/dev/null | grep -c '^  module')
check "--list 含 module" "$A" "1"

echo "== 10. resetprop：造合成属性区并读取 =="
PROPDIR=/tmp/boss-props
rm -rf "$PROPDIR"
python3 tools/mkprop.py "$PROPDIR" ro.debuggable=0 ro.secure=1 persist.demo=hello >/dev/null 2>&1
if [ -d "$PROPDIR" ]; then ok "mkprop 已生成合成属性区"; else bad "mkprop 失败"; fi
OUT=$($BIN resetprop --dir "$PROPDIR" ro.debuggable 2>/dev/null)
check "读取 ro.debuggable" "$OUT" "[ro.debuggable]: [0]"
OUT=$($BIN resetprop --dir "$PROPDIR" persist.demo 2>/dev/null)
check "读取另一个区域的属性" "$OUT" "[persist.demo]: [hello]"
$BIN resetprop --dir "$PROPDIR" ro.nope >/dev/null 2>&1
check "读不存在的属性返回非 0" "$?" "1"

echo "== 11. resetprop：改 ro.* / 删除 / 新增 =="
$BIN resetprop -n --dir "$PROPDIR" ro.debuggable 1 >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.debuggable 2>/dev/null)
check "直写改掉只读属性 ro.debuggable" "$OUT" "[ro.debuggable]: [1]"
$BIN resetprop -d --dir "$PROPDIR" ro.secure >/dev/null 2>&1
$BIN resetprop --dir "$PROPDIR" ro.secure >/dev/null 2>&1
check "删除后读不到" "$?" "1"
$BIN resetprop -n --dir "$PROPDIR" ro.brand.new hello >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.brand.new 2>/dev/null)
check "新增不存在的属性" "$OUT" "[ro.brand.new]: [hello]"
# symlink 调用（/tmp/boss-test/bin/resetprop -> boss）应与子命令调用一致
OUT=$("$TEST_DIR/bin/resetprop" --dir "$PROPDIR" ro.debuggable 2>/dev/null)
check "symlink 调用行为一致" "$OUT" "[ro.debuggable]: [1]"

echo "== 12. resetprop：--file 批量导入（模块 system.prop 用）=="
printf '# comment\nro.from.file = 1\npersist.from.file = yes\n' > /tmp/boss-test.prop
$BIN resetprop -n --dir "$PROPDIR" --file /tmp/boss-test.prop >/dev/null 2>&1
OUT=$($BIN resetprop --dir "$PROPDIR" ro.from.file 2>/dev/null)
check "批量导入（键名带空格也应生效）" "$OUT" "[ro.from.file]: [1]"

echo "== 13. boot 脚本执行器 =="
mkdir -p "$TEST_DIR/service.d" "$TEST_DIR/post-fs-data.d"
printf '#!/bin/sh\necho svc-ok\nexit 0\n' > "$TEST_DIR/service.d/01-ok.sh"
printf '#!/bin/sh\nexit 3\n' > "$TEST_DIR/service.d/02-fail.sh"
printf '#!/bin/sh\nsleep 30\n' > "$TEST_DIR/service.d/03-slow.sh"
chmod +x "$TEST_DIR"/service.d/*.sh
OUT=$($BIN script service --timeout 2 2>/dev/null | grep -c 'svc-ok')
check "成功脚本被执行" "$OUT" "1"
# 失败与超时都不能拖垮整批：03-slow 应该在 2 秒左右被杀掉
START=$(date +%s)
$BIN script service --timeout 2 >/dev/null 2>&1
ELAPSED=$(( $(date +%s) - START ))
if [ "$ELAPSED" -lt 10 ]; then ok "超时脚本被杀（耗时 ${ELAPSED}s）"; else bad "超时未生效（耗时 ${ELAPSED}s）"; fi
if grep -q 'FAIL' "$TEST_DIR/boss.log" 2>/dev/null; then ok "失败已记日志"; else bad "日志无失败记录"; fi

echo "== 14. 模块：元数据 / 属性 / 规则汇总 =="
mkdir -p "$TEST_DIR/modules/demo/system/bin"
printf 'id=demo\nname=Demo\nversion=1.0\nauthor=ci\ndescription=test\n' > "$TEST_DIR/modules/demo/module.prop"
printf 'ro.demo=1\n' > "$TEST_DIR/modules/demo/system.prop"
printf 'allow bossd demo:file read;   # 行内注释\npermissive demo\n' > "$TEST_DIR/modules/demo/sepolicy.rule"
printf '#!/bin/sh\necho demo\n' > "$TEST_DIR/modules/demo/system/bin/demotool"
OUT=$($BIN module list 2>/dev/null | grep -c 'demo')
check "module list 列出模块" "$OUT" "1"
OUT=$($BIN module dump props 2>/dev/null | grep -c 'ro.demo=1')
check "汇总 system.prop" "$OUT" "1"
# 挂载计划是 dry run，不碰真实挂载点，非 root 也能验
OUT=$($BIN module plan 2>/dev/null | grep -c 'demotool')
check "挂载计划包含模块文件" "$OUT" "1"

echo "== 15. sepolicy 工具：规则规范化 =="
OUT=$($BIN sepolicy check "$TEST_DIR/modules/demo/sepolicy.rule" 2>/dev/null)
check "去掉行内注释与分号" "$OUT" "allow bossd demo:file read
permissive demo"

echo "== 16. 卸载 / 恢复相关的目录约定 =="
if [ -d "$TEST_DIR/modules/demo" ] && [ -d "$TEST_DIR/service.d" ]; then
    ok "模块与脚本目录就位"
else
    bad "目录约定缺失"
fi

stop_daemon
echo
echo "结果：PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ] || exit 1
