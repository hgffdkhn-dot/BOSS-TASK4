# BOSS su — 构建
#   make                 主机构建（Linux），用于逻辑验证与冒烟测试
#   make test            同上，但把运行时目录指向 /tmp/boss-test
#   make android-arm64   交叉编译（需要 NDK，见 build/build-ndk.sh）
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter
LDLIBS  ?= -ldl
EXTRA_CFLAGS ?=

SRCS := src/main.c src/util.c src/policy.c src/pty.c \
        src/daemon.c src/client.c src/bossinit.c \
        src/applet.c src/resetprop.c src/scripts.c src/module.c \
        src/sepolicy.c src/sh.c src/boot.c src/selinux.c src/sepol_backend.c
OUT  := build/boss
STATIC_OUT := build/boss-static
# 内置 libsepol 用独立产物名：它是**另一个**二进制（多带一份 libsepol）。
# 与 build/boss 共用一个名字的话，跑着"上一个目标留下的产物"而不自知
# （接力须知 4.6），症状只在日志路径、引擎类型这类地方诡异地对不上。
SEPOL_OUT  := build/boss-sepol

all: $(OUT)

$(OUT): $(SRCS) src/boss.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(SRCS) $(LDLIBS)

# 主机侧冒烟测试用：把 /data/adb/boss 换成临时目录。
#
# ⚠️ 必须**无条件重新链接**，不能写成 `test: $(OUT)` 那种带依赖的形式。
# make 看不出 target-specific 的 EXTRA_CFLAGS 变了：只要 build/boss 存在且比源码新，
# 它就一句"已是最新"跳过——于是你跑着上一次 `make` 留下的、BOSS_DIR 指向
# /data/adb/boss 的二进制，症状是日志和 pending 写去了奇怪的路径，极难联想。
# 代价只是每次多一次链接，换来"产物一定对得上当前目标"。
#
# 产物名保持 build/boss：CI 的 payload job 与 components.yml 都按这个名字取件，
# 改名的代价是 CI 直接红。
test: EXTRA_CFLAGS += -DBOSS_DIR='"/tmp/boss-test"'
test:
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $(OUT) $(SRCS) $(LDLIBS)

# 全静态：静态二进制里 dlopen 不可用，关掉它，SELinux 改走 /proc/self/attr/exec。
# 用独立产物名——和 build/boss 混用会让人跑着"另一个 BOSS_DIR 的二进制"而不自知。
static: EXTRA_CFLAGS += -DBOSS_NO_DLOPEN
static: LDLIBS =
static: CC += -static-pie
static: $(STATIC_OUT)

$(STATIC_OUT): $(SRCS) src/boss.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(SRCS) $(LDLIBS)

# 交叉编译：显式传入 clang 即可
#   make android-arm64 ANDROID_CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
ANDROID_CC ?=
android-arm64:
	@test -n "$(ANDROID_CC)" || (echo "用法: make android-arm64 ANDROID_CC=<ndk-clang>"; exit 1)
	@mkdir -p build/out
	$(ANDROID_CC) -O2 -std=c11 -Wall -Wextra -static -fPIE -pie \
	    -DBOSS_DIR='"/data/adb/boss"' -o build/out/boss $(SRCS) \
	    -ldl -lm
	@echo "产物: build/out/boss"

# 交叉编译 + 内置 libsepol：真机上真正想要的就是这一份。
# 没有内置后端时，早期注入（selinux_setup）只能靠"设备上恰好有 magiskpolicy"，
# 而那个阶段 /data 还没挂载，等于没有——所以带 sepol 的产物才是路径 A 的本体。
#
# ⚠️ 体积：内置 libsepol 会让二进制变大（主机侧实测 +224KB）。
#    ramdisk 体积是硬约束（接力须知 8.3），上真机前务必确认 boot/init_boot
#    分区放得下；放不下就退回不带 sepol 的产物，功能不残，只是路径 A 不可靠。
android-sepol:
	@test -n "$(ANDROID_CC)" || (echo "用法: make android-sepol ANDROID_CC=<ndk-clang>"; exit 1)
	@test -d $(SEPOL_DIR)/src || { echo "先跑: bash tools/vendor-sepol.sh"; exit 1; }
	@mkdir -p build/out
	$(ANDROID_CC) -O2 -Wall -Wextra -static-pie \
	    $(SEPOL_CFLAGS) -DBOSS_DIR='"/data/adb/boss"' \
	    -o build/out/boss-sepol $(SRCS) $(SEPOL_SRCS) -lm
	@echo "产物: build/out/boss-sepol"
	@echo "别忘了过一遍 elf_fix.py + --check（接力须知 4.5 的两个加载门槛）"

# 任务4：把 policy/boss.rule 编进二进制（src/boss_rules.h）。
# 早期注入时 /data 还没挂载，读不到磁盘上的规则文件，所以策略内容必须内嵌。
# 改了 policy/boss.rule 就要跑这个；CI 的 strict job 会校验产物与源一致。
rules:
	python3 tools/gen_rules_h.py

# 任务4 的引擎链第一级：内置 libsepol。
# 前置：bash tools/vendor-sepol.sh（把 libsepol 拉到 external/libsepol）。
#
# 不加这个目标也能正常构建——此时 src/sepol_backend.c 是个返回 -1 的桩，
# 引擎自动落到外部引擎（magiskpolicy / sepolicy-inject / supolicy）。
# 只有需要"不依赖外部引擎"的早期注入时才需要它。
SEPOL_DIR  := external/libsepol
SEPOL_SRCS := $(wildcard $(SEPOL_DIR)/src/*.c)

# libsepol 是 AOSP 第三方源码，警告水平跟我们的代码不是一个量级，
# 单独降噪，别让它淹没 BOSS 自身的警告。
# -I.../src 不能省：libsepol 的 private.h 用尖括号 #include <dso.h>，
# 尖括号不会回退到当前文件目录，少了这一项就是满屏 "dso.h: No such file"。
# -std=gnu11 也不能省：libsepol 内部用了 typeof 这个 GNU 扩展，
# 在严格 -std=c11 下它不会被识别，最后变成 "undefined reference to `typeof'"。
SEPOL_CFLAGS := -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/src -DBOSS_HAVE_SEPOL \
                -std=gnu11 \
                -Wno-sign-compare -Wno-unused-function -Wno-unused-variable \
                -Wno-strict-prototypes -Wno-pointer-sign -Wno-maybe-uninitialized

# 同 `make test`：无条件重新链接，避免 build/boss-sepol 已存在时
# make 一句"已是最新"把上一份产物留给你。
sepol: EXTRA_CFLAGS += $(SEPOL_CFLAGS)
sepol: SRCS += $(SEPOL_SRCS)
sepol: LDLIBS =
sepol:
	@test -d $(SEPOL_DIR)/src || { echo "先跑: bash tools/vendor-sepol.sh"; exit 1; }
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $(SEPOL_OUT) $(SRCS) $(LDLIBS)
	@echo "产物: $(SEPOL_OUT)（已内置 libsepol 后端，engine 显示为 libsepol）"

# 测试专用小工具：造一个能被 policydb_read 读回的最小 kernel policy。
# 沙盒/CI 上没有真机的 precompiled_sepolicy，也没有 checkpolicy 能现编一个，
# 所以内置后端要端到端地验，只能自己搭。不进主构建。
sepolkit:
	@test -d $(SEPOL_DIR)/src || { echo "先跑: bash tools/vendor-sepol.sh"; exit 1; }
	@mkdir -p build
	$(CC) -std=gnu11 -O1 -w -I$(SEPOL_DIR)/include -I$(SEPOL_DIR)/src \
	    -o build/sepolkit tests/sepolkit.c $(SEPOL_SRCS)

# 只验 libsepol 后端本身能不能编过（CI 上最快的一道闸）
sepol-check: EXTRA_CFLAGS += $(SEPOL_CFLAGS)
sepol-check: SRCS += $(SEPOL_SRCS)
sepol-check:
	@test -d $(SEPOL_DIR)/src || { echo "先跑: bash tools/vendor-sepol.sh"; exit 1; }
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $(SEPOL_OUT) $(SRCS) $(LDLIBS)

clean:
	rm -rf build/boss build/boss-static build/boss-sepol build/sepolkit build/out

.PHONY: all test android-arm64 android-sepol rules sepol sepol-check sepolkit clean
