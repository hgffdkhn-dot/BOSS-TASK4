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
        src/sepolicy.c src/sh.c src/boot.c src/selinux.c
OUT  := build/boss
STATIC_OUT := build/boss-static

all: $(OUT)

$(OUT): $(SRCS) src/boss.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(SRCS) $(LDLIBS)

# 主机侧冒烟测试用：把 /data/adb/boss 换成临时目录
test: EXTRA_CFLAGS += -DBOSS_DIR='"/tmp/boss-test"'
test: $(OUT)

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

# 任务4：把 policy/boss.rule 编进二进制（src/boss_rules.h）。
# 早期注入时 /data 还没挂载，读不到磁盘上的规则文件，所以策略内容必须内嵌。
# 改了 policy/boss.rule 就要跑这个；CI 的 strict job 会校验产物与源一致。
rules:
	python3 tools/gen_rules_h.py

clean:
	rm -rf build/boss build/boss-static build/out

.PHONY: all test android-arm64 rules clean
