#!/bin/bash
# BOSS · vendor libsepol（可选增强）
#
# 为什么需要它：src/selinux.c 的引擎链第一级是 libsepol 内置后端
# （-DBOSS_HAVE_SEPOL），它不 fork、不落临时文件，是注入最快最准的一条路。
# 它没被编进来的原因只有一个：libsepol 是 AOSP 的第三方源码，需要联网拉取。
#
# 当前默认走的是第二级（外部引擎 magiskpolicy 等），功能完整可用。
# 这个脚本只是把第一级补上——**不跑它也不影响 BOSS 正常工作**。
#
# 用法：bash tools/vendor-sepol.sh
set -u
cd "$(dirname "$0")/.."

DEST=external/libsepol
MIRROR=${SEPOL_MIRROR:-https://github.com/LineageOS/android_external_selinux}
BRANCH=${SEPOL_BRANCH:-lineage-22.2}
WORK=$(mktemp -d)

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 拉取 $MIRROR ($BRANCH) =="
if ! git clone --depth 1 -b "$BRANCH" "$MIRROR" "$WORK/selinux" 2>/dev/null; then
    echo "克隆失败。可选镜像："
    echo "  SEPOL_MIRROR=https://github.com/aosp-mirror/platform_external_selinux bash $0"
    exit 1
fi

SRC="$WORK/selinux/libsepol"
if [ ! -d "$SRC" ]; then
    echo "镜像里没有 libsepol 目录，请检查 SEPOL_MIRROR / SEPOL_BRANCH"
    exit 1
fi

echo "== 只取二进制 policy 读写需要的部分 =="
# kernel policy 的读 → 改 → 写不需要 .te 文本 parser，
# 所以 policy_parse.y / module 链接 / 反编译（kernel_to_cil 等）全部不取。
# 少了这一刀要多带 1MB+ 源码进 ramdisk 二进制。
mkdir -p "$DEST/src"
cp "$SRC"/src/*.h "$DEST/src/" 2>/dev/null

KEEP="policydb.c policydb_public.c policydb_convert.c avtab.c ebitmap.c \
hashtab.c conditional.c context.c mls.c polcaps.c hierarchy.c \
expand.c debug.c handle.c services.c roles.c"
for f in $KEEP; do
    if [ -f "$SRC/src/$f" ]; then
        cp "$SRC/src/$f" "$DEST/src/$f"
        echo "  + $f"
    else
        echo "  - $f（镜像里没有，跳过）"
    fi
done

mkdir -p "$DEST/include/sepol"
cp "$SRC"/include/sepol/*.h "$DEST/include/sepol/" 2>/dev/null
cp "$SRC"/include/*.h "$DEST/include/" 2>/dev/null

echo
echo "已放到 $DEST"
echo
echo "下一步（两步都要做）："
echo "  1) 补齐 src/sepol_backend.c —— 接口固定在 src/selinux.c："
echo "       int sepol_builtin_apply(const char *in, const char *out,"
echo "                              const char **rules, int n, int live,"
echo "                              struct inject_result *res);"
echo "     实现要点：policydb_read → 直接操作 avtab 插入 avtab_key_t /"
echo "     avtab_datum_t → policydb_write。可对照 Magisk 的 sepolicy crate。"
echo "  2) 编译时加 -DBOSS_HAVE_SEPOL，并把 $DEST/src/*.c 加进 SRCS。"
echo
echo "⚠️ 这部分必须在真机上验过再合入——理由见 docs/TASK4 第 3.1 节："
echo "   没验过的 policydb 改写器比没有更危险。"
