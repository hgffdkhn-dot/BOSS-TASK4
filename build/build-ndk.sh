#!/bin/bash
# BOSS · Android 交叉编译（4 个 ABI）+ Bionic 加载校验
#
# 这个脚本的职责不只是"编译通过"，而是**产出 Bionic 肯加载的二进制**。
# 两者不等价，历史上翻过车：一批产物编译、链接、上传全都"成功"，
# 只有 elf_fix.py --check 说它们上机起不来。所以这里的验收步骤不能删。
#
# 两个门槛（接力须知 4.5）：
#   1. 非 PIE（ET_EXEC）——Android 5+ 直接拒绝加载
#   2. PT_TLS 对齐 < 64——NDK 的 lld 对静态二进制只给 8，
#      设备上 "TLS segment is underaligned" 直接 abort
#
# 最坑的一点：-static -fPIE -pie **并不会**得到静态 PIE。链接器见到
# -static 就把 PIE 关掉，产出 ET_EXEC——CMake/Makefile 里最常见的写法，
# 也是最容易骗过 review 的写法。真正的静态 PIE 只有 -static-pie。
# 所以这里不赌某一个标志组合：按候选顺序试，每个候选都 patch + check，
# 取第一个产出 ET_DYN 的，并打印最终选择。全失败就报错，不交半成品。
#
# ⚠️ 这个文件住在 build/ 下，而 build/ 同时是构建产物目录。
#    `rm -rf build` 会把它一起删掉（CI 上就表现为 No such file）。
#    .gitignore 已用 `build/*` + `!build/build-ndk.sh` 保住它，
#    但清目录时别用整目录删除——脚本和产物混在一个目录里是既成事实。
#
# 用法：
#   bash build/build-ndk.sh                  # -> dist/boss-android-{arm64,arm,x86_64,x86}
#   MAKE_PAYLOAD=1 bash build/build-ndk.sh   # 顺带生成 build/payload/ 与 dist/boss-payload.zip
#   STRICT=1 bash build/build-ndk.sh         # 缺 NDK 时明确失败（CI 用这个）
#
# 环境变量：
#   STRICT=1        缺工具链就非零退出，而不是交出一个空目录
#   MAKE_PAYLOAD=1  顺带组装 payload
#   WITH_SEPOL=1    payload 里的 boss 内置 libsepol（早期注入需要，见下）
#   ABIS="arm64"    只编部分 ABI（本地自测用）
#   API=26          min_api（与 payload/manifest.json 保持一致）
#   NDK_BIN=<dir>   直接指定 toolchain 的 bin 目录（自测 / 非标准安装）
set -u
cd "$(dirname "$0")/.."

STRICT=${STRICT:-0}
MAKE_PAYLOAD=${MAKE_PAYLOAD:-0}
WITH_SEPOL=${WITH_SEPOL:-0}
ABIS=${ABIS:-"arm64 arm x86_64 x86"}
API=${API:-26}          # payload/manifest.json 的 min_api，改那边记得同步这里

SRCS="$(ls src/*.c)"
DIST=dist
WORK=build/ndk

# 静态候选中带 -DBOSS_NO_DLOPEN：静态二进制里没有 dlopen，
# SELinux 切换改走 /proc/self/attr/exec（接力须知 4.4）。
# 最后一个候选是动态兜底，它允许 dlopen，所以不加这个宏。
CANDIDATES=(
  "-static-pie|-DBOSS_NO_DLOPEN"
  "-static -fPIE -pie|-DBOSS_NO_DLOPEN"
  "-static -fPIE -pie -Wl,-pie|-DBOSS_NO_DLOPEN"
  "-fPIE -pie|"
)

say()  { printf '%s\n' "$*"; }
die()  { printf 'build-ndk: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------
# 1. 找工具链
# ---------------------------------------------------------------------
# 找不到就**不要**退回主机 cc：那会产出一个 x86_64 的 Linux ELF，
# 却顶着 boss-android-arm64 的名字被上传——比直接失败危险得多
# （它在 CI 上"成功"，在真机上 abort，而且很难联想到产物架构不对）。
PATH_CC=0
find_ndk_bin() {
    local roots=() d
    [ -n "${NDK_BIN:-}" ] && roots+=("$NDK_BIN")
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
               "$HOME/Android/Sdk" /opt/android-sdk /usr/local/lib/android/sdk; do
        [ -n "$sdk" ] || continue
        roots+=("$sdk"/ndk/*/toolchains/llvm/prebuilt/*/bin)
    done
    for nb in "${ANDROID_NDK_HOME:-}" "${NDK_HOME:-}" "${NDK_ROOT:-}"; do
        [ -n "$nb" ] || continue
        roots+=("$nb"/toolchains/llvm/prebuilt/*/bin)
    done
    for d in "${roots[@]}"; do
        [ -d "$d" ] || continue
        if [ -x "$d/aarch64-linux-android${API}-clang" ] ||
           [ -x "$d/aarch64-linux-android-clang" ]; then
            printf '%s' "$d"
            return 0
        fi
    done
    # 交叉 clang 已经在 PATH 上（有些镜像/容器这么装）
    if command -v "aarch64-linux-android${API}-clang" >/dev/null 2>&1 ||
       command -v "aarch64-linux-android-clang" >/dev/null 2>&1; then
        PATH_CC=1
        return 0
    fi
    return 1
}

NDK_BIN_DIR=$(find_ndk_bin) || NDK_BIN_DIR=""

if [ "$PATH_CC" = 0 ] && [ -z "$NDK_BIN_DIR" ]; then
    say "找不到 Android NDK 工具链。已查找："
    say "  \$ANDROID_HOME / \$ANDROID_SDK_ROOT / \$ANDROID_NDK_HOME / \$NDK_BIN / ~/Android/Sdk / /opt/android-sdk"
    say "  PATH 上的 aarch64-linux-android${API}-clang"
    say ""
    say "有 NDK 就设 ANDROID_HOME（或 ANDROID_SDK_ROOT）；"
    say "或是用 sdkmanager 装：sdkmanager --install 'ndk;27.0.12077973'"
    # 明确失败而不是交出空目录：upload-artifact 配了 if-no-files-found: error，
    # 空目录会在那一步才红，且看不到这里的原因。
    die "缺失工具链（宁可红，也不交假产物）"
fi

cc_for() {   # cc_for <triple> -> 打印编译器路径
    local t="$1" c
    if [ "$PATH_CC" = 1 ]; then
        if command -v "${t}${API}-clang" >/dev/null 2>&1; then printf '%s' "${t}${API}-clang"; return 0; fi
        if command -v "${t}-clang" >/dev/null 2>&1;         then printf '%s' "${t}-clang";       return 0; fi
        return 1
    fi
    for c in "${NDK_BIN_DIR}/${t}${API}-clang" "${NDK_BIN_DIR}/${t}-clang"; do
        [ -x "$c" ] && { printf '%s' "$c"; return 0; }
    done
    return 1
}

case_abi() {   # case_abi <abi> -> 打印 triple（**不带**结尾连字符，
               # cc_for 会自己拼 "${triple}${API}-clang"）
    case "$1" in
        arm64)  printf 'aarch64-linux-android' ;;
        arm)    printf 'armv7a-linux-androideabi' ;;
        x86_64) printf 'x86_64-linux-android' ;;
        x86)    printf 'i686-linux-android' ;;
        *)      return 1 ;;
    esac
}

# ---------------------------------------------------------------------
# 2. 内置 libsepol（可选）
# ---------------------------------------------------------------------
# 早期注入（selinux_setup 阶段）时 /data 还没挂载、PATH 是空的，
# 外部引擎那条退路大概率不存在——所以 ramdisk 里的这个 boss 要不要
# 自带 libsepol，直接决定路径 A 能不能成立（见 docs/TASK4 第 3.3 节）。
#
# 默认关：内置 libsepol 会让二进制变大（主机侧实测 +224KB），
# 而 ramdisk 体积是硬约束。要用就显式 WITH_SEPOL=1，
# 并先确认 boot / init_boot 分区放得下。
SEPOL_SRCS=""
SEPOL_CFLAGS=""
if [ "$WITH_SEPOL" = 1 ]; then
    if [ ! -d external/libsepol/src ]; then
        die "WITH_SEPOL=1 但缺 external/libsepol —— 先跑: bash tools/vendor-sepol.sh"
    fi
    SEPOL_SRCS="$(ls external/libsepol/src/*.c)"
    SEPOL_CFLAGS="-Iexternal/libsepol/include -Iexternal/libsepol/src -DBOSS_HAVE_SEPOL -std=gnu11 -w"
    say "内置 libsepol：开（WITH_SEPOL=1）"
fi

mkdir -p "$DIST" "$WORK"

# ---------------------------------------------------------------------
# 3. 逐个 ABI：试候选 → patch → check → 取第一个 ET_DYN
# ---------------------------------------------------------------------
build_one() {   # build_one <abi>
    local abi="$1" triple cc out base extra try_extra flags chosen=""
    triple=$(case_abi "$abi") || { say "  $abi: 未知 ABI"; return 1; }
    cc=$(cc_for "$triple") || { say "  $abi: 缺编译器 ${triple}${API}-clang"; return 1; }
    out="$DIST/boss-android-$abi"

    for cand in "${CANDIDATES[@]}"; do
        base="${cand%%|*}"
        extra="${cand##*|}"

        # Android 15+ 有 16KB 页设备。先试着按 16KB 对齐链接，
        # 链接器不支持（老 NDK、或非 lld）就退回默认页大小——
        # 这一步失败不算失败，只是拿不到 16KB 兼容。
        for try_extra in "-Wl,-z,max-page-size=16384" ""; do
            flags="$base $extra $try_extra"
            rm -f "$out"
            if ! $cc -O2 -std=c11 -Wall $flags $SEPOL_CFLAGS \
                    -DBOSS_DIR='"/data/adb/boss"' \
                    -o "$out" $SRCS $SEPOL_SRCS -lm >"$WORK/$abi.log" 2>&1; then
                continue
            fi
            # 先修 TLS 对齐，再验收：顺序反了会把"可修的问题"误判成废品
            python3 tools/elf_fix.py "$out" >/dev/null 2>&1
            if python3 tools/elf_fix.py --check "$out" >/dev/null 2>&1; then
                chosen="$flags"
                break 2
            fi
        done
    done

    if [ -z "$chosen" ]; then
        rm -f "$out"
        say "  $abi: ✗ 所有候选都没产出 ET_DYN（见 $WORK/$abi.log）"
        return 1
    fi

    local note=""
    case "$chosen" in *max-page-size*) note=" (16KB 页对齐)";; esac
    say "  $abi: ✓ [$chosen]$note → $out"
    return 0
}

say "== 交叉编译（API=$API, STRICT=$STRICT）=="
[ "$PATH_CC" = 0 ] && say "  工具链: $NDK_BIN_DIR"

FAILED=""
for abi in $ABIS; do
    build_one "$abi" || FAILED="$FAILED $abi"
done

if [ -n "$FAILED" ]; then
    say ""
    say "失败:$FAILED"
    say "全部候选都试过了仍不产出 ET_DYN —— 这通常是链接方式问题，不是源码问题。"
    say "手工逐个候选看 e_type："
    say "  for f in -static-pie '-static -fPIE -pie' '-fPIE -pie'; do ...; done"
    die "有 ABI 未产出可用产物（不交半成品）"
fi

# ---------------------------------------------------------------------
# 4. Bionic 加载校验（把结果打出来，失败就红）
# ---------------------------------------------------------------------
say ""
say "== Bionic 加载校验 =="
RC=0
for f in "$DIST"/boss-android-*; do
    [ -f "$f" ] || continue
    python3 tools/elf_fix.py --check "$f" || RC=1
done
[ "$RC" -eq 0 ] || die "有产物过不了 Bionic 校验"

# ---------------------------------------------------------------------
# 5. MAKE_PAYLOAD：顺带组装 payload
# ---------------------------------------------------------------------
if [ "$MAKE_PAYLOAD" = 1 ]; then
    say ""
    say "== 组装 payload =="
    # payload 里的 /boss 用 arm64：manifest 的 arch 列表以它为主，
    # 且它是绝大多数现役设备的架构。
    PAY_BIN="$DIST/boss-android-arm64"
    [ -f "$PAY_BIN" ] || die "缺 $PAY_BIN（MAKE_PAYLOAD 需要 arm64 产物，别用 ABIS 把它裁掉）"
    rm -rf build/payload
    mkdir -p build/payload
    cp -r payload/. build/payload/
    cp "$PAY_BIN" build/payload/boss
    chmod 0755 build/payload/boss
    ( cd build/payload && zip -qr "../../$DIST/boss-payload.zip" . )
    say "  build/payload/ 与 $DIST/boss-payload.zip 已生成（boss ← $PAY_BIN）"
fi

say ""
say "产物："
ls -l "$DIST" | sed 's/^/  /'
say ""
say "上机前记得：veritpath payload-check build/payload  再 inject/verify"
