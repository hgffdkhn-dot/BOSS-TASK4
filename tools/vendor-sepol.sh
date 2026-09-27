#!/bin/bash
# BOSS · vendor libsepol（内置注入后端的依赖）
#
# 为什么需要它：src/selinux.c 的引擎链第一级是 libsepol 内置后端
# （-DBOSS_HAVE_SEPOL）。它不 fork 外部程序、不落临时文件，
# 而早期注入（init selinux_setup）时 /data 还没挂载、PATH 里什么都没有，
# 外部引擎那条退路大概率不存在——所以这一级是"早期注入能不能成立"的前提。
#
# 不跑它也能正常构建：此时 src/sepol_backend.c 是个返回 -1 的桩，
# 引擎自动落到外部引擎（magiskpolicy / sepolicy-inject / supolicy），
# 功能完整可用。这条退路必须一直保留。
#
# 用法：bash tools/vendor-sepol.sh && make sepol
set -u
cd "$(dirname "$0")/.."

DEST=external/libsepol
MIRROR=${SEPOL_MIRROR:-https://github.com/LineageOS/android_external_selinux}
# 注意：LineageOS 这个仓库的分支最高只到 lineage-17.1（Android 10）。
# 它没有 lineage-22.2 等新分支，写错分支 git 会直接失败而不是回退到默认分支，
# 所以这里给的就是实际存在的分支。libsepol 的二进制 policy 读写接口在
# 这些分支之间变化很小，Android 10 的源码足以覆盖到 Android 15 的 policy 版本。
BRANCH=${SEPOL_BRANCH:-lineage-17.1}
WORK=$(mktemp -d)

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 拉取 $MIRROR ($BRANCH) =="
if ! git clone --depth 1 -b "$BRANCH" "$MIRROR" "$WORK/selinux" 2>/dev/null; then
    echo "克隆失败。可选镜像："
    echo "  SEPOL_MIRROR=https://github.com/aosp-mirror/platform_external_selinux bash $0"
    echo "  若当前分支不存在：SEPOL_BRANCH=<分支名> bash $0"
    exit 1
fi

SRC="$WORK/selinux/libsepol"
if [ ! -d "$SRC" ]; then
    echo "镜像里没有 libsepol 目录，请检查 SEPOL_MIRROR / SEPOL_BRANCH"
    exit 1
fi

echo "== 只取二进制 policy 读→改→写需要的部分 =="
# 不需要 .te 文本 parser（policy_parse.y）、module 链接（link.c）、
# 反编译（kernel_to_cil.c / kernel_to_conf.c 等）。少了这一刀要多带 1MB+ 源码。
mkdir -p "$DEST/src"
cp "$SRC"/src/*.h "$DEST/src/" 2>/dev/null

# 这份清单是**链接实测**出来的，不是照着目录猜的：
# 先放 policydb.c 等核心，再按 ld 报的 undefined reference 逐个补齐。
# 每一组都有它非取不可的理由，改动前请先看注释，别为了"瘦身"删掉。
KEEP="
policydb.c policydb_public.c policydb_convert.c
write.c
avtab.c ebitmap.c hashtab.c
conditional.c context.c context_record.c
mls.c polcaps.c hierarchy.c
expand.c avrule_block.c symtab.c constraint.c
debug.c handle.c services.c roles.c
util.c sidtab.c assertion.c kernel_to_common.c
"
for f in $KEEP; do
    if [ -f "$SRC/src/$f" ]; then
        cp "$SRC/src/$f" "$DEST/src/$f"
        echo "  + $f"
    else
        echo "  - $f（镜像里没有，跳过）"
    fi
done

# 头文件要整棵拷贝：include/sepol/policydb/*.h 之间用尖括号互相引用，
# 只拷顶层会满屏 "No such file or directory"。
mkdir -p "$DEST/include"
cp -r "$SRC"/include/sepol "$DEST/include/" 2>/dev/null
cp "$SRC"/include/*.h "$DEST/include/" 2>/dev/null

echo
echo "已放到 $DEST（$(ls "$DEST"/src/*.c 2>/dev/null | wc -l) 个 .c）"
echo
echo "下一步：make sepol"
echo "  产物是 build/boss-sepol（独立名字，避免与 build/boss 互相顶掉）"
echo
echo "验证：bash tools/sepol_backend_test.sh"
echo "  （脚本会自己造一个最小 kernel policy 当靶子，端到端验 type 创建 /"
echo "   permissive / attribute 展开 / 写回后能否被 libsepol 读回）"
echo
echo "⚠️ 内置后端**已在合成策略上验过**，但还没有真机 precompiled_sepolicy 的验证。"
echo "   真机上万一它出问题，用 BOSS_SEPOL=0 可以临时关掉，退回外部引擎对比排查。"
