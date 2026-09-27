# BOSS · 任务3 交付说明（其他关键文件与重要组件）

> 给下一位接力的同学（任务 4 SELinux / 任务 5 无修改系统逻辑 / 任务 6 客户端）。
> 这份写的是**已经落地的东西**：组件清单、关键决策、踩过的坑、以及你们能怎么用。

---

## 1. 一句话

任务2 交付了「拿到 root 的能力」，任务3 交付了「拿到 root 之后能干什么」：
属性改写、模块挂载、开机脚本、策略工具、工具集，以及把它们串起来的开机编排。

---

## 2. 组件清单与当前状态

| # | 组件 | 入口 | 状态 | 说明 |
|---|---|---|---|---|
| A1 | applet 分发框架 | `boss --list` | ✅ | 一张表 + 两种调用方式（symlink / 子命令） |
| A2 | 工具集 / standalone shell | `boss sh`、`boss applet` | ✅ | busybox 不进 ramdisk，走 `/data` |
| B1 | resetprop | `boss resetprop` | ✅ | 改 `ro.*`、删属性、persist、批量导入 |
| B2 | 模块 / overlay 挂载 | `boss module` | ✅ | Magic Mount，`plan` 可离线验 |
| B3 | boot 脚本执行器 | `boss script` | ✅ | 三阶段、带超时、失败不阻断 |
| C1 | sepolicy 工具 | `boss sepolicy` | ✅ | 工具层：解析 + 规范化 + 调引擎 |
| D1 | 文件格式约定 | `/data/adb/boss/modules/...` | ✅ | 对齐 Magisk，便于吃生态 |
| — | 开机编排 | `boss boot <stage>` | ✅ | 固定顺序，避免 rc 并发乱序 |

**没做、也不该做的**（边界）：
- init 接管（2SI SwitchRoot 劫持）→ su 侧 v0.2，`src/bossinit.c` 的 `stage2` / `hijack-prep`
- SELinux 策略内容本身 → 任务4，我只出工具
- 隐藏 / denylist / Integrity 绕过 → 任务5、6，我只出能力

---

## 3. 关键决策（以及为什么）

### 3.1 挂载选 Magic Mount，不是 overlayfs
BOSS 主打日用，**兼容性优先**。overlayfs 依赖 `CONFIG_OVERLAY_FS=y`，4.19+ 还要
xattr 递归补丁，部分设备直接不支持；而 Magic Mount 能直接吃 Magisk 模块生态。
等挂载逻辑在真机上稳了再加 overlayfs 后端（接口已按"可切换"设计）。

**Magic Mount 的核心难点**：tmpfs 挂到目标目录后，目录里的原始内容被遮盖，
再也 bind 不回来。解法是先把真实分区 bind 到镜像目录
`/data/adb/boss/tmp/mirror/`，之后所有"还原原文件"都从镜像取。

### 3.2 模块目录用 `/data/adb/boss/modules`，不用 `/data/adb/modules`
`/data/adb/modules` 是 root 检测的高频特征点，不符合 BOSS 的隐蔽定位。
但**模块格式完全对齐 Magisk**（`module.prop` / `system/` / `system.prop` /
`sepolicy.rule` / `skip_mount` / `remove`），兼容生态的成本只有一个目录重定向。

### 3.3 sepolicy 只出工具，不自研二进制改写
完整反序列化 + 重排 avtab / 条件表达式是 libsepol 的活（几千行，强依赖 policy
版本）。交出一个没在真机验过的改写器比不做更危险。所以工具层做到三件事：
输入规范化 → 可靠执行 → **失败要说明白**。没有注入引擎时，规则进
`/data/adb/boss/sepolicy.pending` 并返回 2，绝不假装成功。

### 3.4 busybox 不进 ramdisk
ramdisk 撑爆分区会变砖，这是硬约束。busybox 由 App 释放到
`/data/adb/boss/bin/`，或随 Release 分发。

---

## 4. 给你们的三份接口契约

### 4.1 给任务4（SELinux）
- 工具：`boss sepolicy check|apply|info`
- 权限清单：见 **`docs/SELINUX-REQUIREMENTS.md`**（随代码维护）
- 参考模型（Magisk 的成熟做法）：`boss` domain（permissive）/
  `boss_file`（unrestricted）/ `boss_exec` + `boss_client`（8.0+ 收紧模型）

### 4.2 给任务5（无修改系统逻辑）
你能用的弹药只有两件：**resetprop**（改属性不改文件）+ **挂载覆盖**（换文件不改分区）。
如果某个玩法需要写 `/system` 才能实现，那是需求越界，请打回。

### 4.3 给任务6（BOSS 客户端）
- CLI：`boss <applet>`，退出码统一（0 成功 / 非 0 失败）
- 状态：`boss --list`、`boss module list`、`boss ping`、日志 `/data/adb/boss/boss.log`
- 文件：`/data/adb/boss/` 下的目录约定就是 App 的读写契约（见 D1）
- **协议**：扩展 `struct boss_request` 时必须同时升 `BOSS_PROTO_VER`，否则新旧二进制静默错位

---

## 5. 踩过的坑（别再踩）

1. **serial 的 dirty 位**。属性值的 serial 编码是 `(len << 24) | (serial & 0xffffff)`，
   bit0 是 dirty 位。AOSP 的更新顺序是 `serial |= 1` 之后**再 +1**，
   正好把 dirty 位清掉；直接用原始 `serial + 1` 会算出奇数，读侧就一直去
   dirty backup area 取旧值——表现为"改了但读回来还是老的"。我在 `pi_update()` 里
   按 AOSP 原样实现，并写了注释。
2. **argv 偏移**。symlink 调用和子命令调用的偏移不同，现在统一成
   **applet 看到的 argv[0] 永远是自己的名字**，两种调用解析起点完全一致。
   各组件从 `argv[1]` 开始取子命令。
3. **属性名尾随空格**。`ro.foo = 1` 这种写法会把属性名写成 `ro.foo `（带空格），
   结果是"导入了但目标属性没变"。`--file` 导入现在会 strip 两端。
4. **post-fs-data 必须用 `resetprop -n`**。这是阻塞阶段，走 property_service
   会死锁开机（约 40s 后强制放行，所以症状常是"开机莫名慢 40 秒"而不是卡死）。
   `boss boot post-fs-data` 内部全部用 `-n`。
5. **rc 里的 exec_background 是并发的**。模块属性/规则/挂载/脚本的顺序不能靠 rc
   罗列保证，必须走 `boss boot`。
6. **镜像别给无关分区建**。早期实现给 7 个分区都建镜像，在分区形态不同的设备上
   会刷一屏 mount 失败，把真正的错误淹没。现在只给"模块真的要动"的分区建。
7. **daemon 不能被标成 needs_root**。组件表化时我顺手给 daemon 加了 root 要求，
   结果 GitHub runner（普通用户）上 `boss daemon` 直接报错退出，整条 su 链路
   **7 项全红**，而本地 root 下跑是全绿的——因为本地一直是 root。
   daemon 在非 root 下只是无法提权（目标身份自动降级为自身），不该拦在门外。
   已加回归测试（`component_test.sh` 第 16 项）守住这条。
   教训：**两套测试都要在非 root 下跑一遍再看结论**，root 全绿不代表 CI 能过。
8. **make 目标共用产物名**。`make test` 在 `build/boss` 已存在时不会重建，
   于是会跑着"另一个 BOSS_DIR 的二进制"而不自知（日志写到别处，测试诡异失败）。
   新增构建目标务必用独立产物名；本地验完记得 `make clean`。

---

## 6. 验证情况（已跑通）

主机侧 `bash tools/smoke_test.sh`：**28 项全过**，其中任务3 相关 20 项。
覆盖：applet 两种调用、resetprop 读/改/删/新增/批量/persist、脚本执行器的
成功-失败-超时、模块元数据与挂载计划、sepolicy 规则规范化。

属性区是**离线可验的**：`tools/mkprop.py` 会照 bionic 的二进制布局造一个
合成 prop_area，`boss resetprop --dir <dir>` 直接对它操作。这样不依赖真机
就能验到 trie 查找、serial 更新、多区域这些最容易写错的地方。

注入链路也跑通了：veritpath `payload-check` → `inject` → `verify` → 解包确认
（`/boss`、`/init.boss.rc`、`import` 钩子都在）。

组件还有一份**深度验收**（`bash tools/component_test.sh`，34 项），覆盖 smoke
没覆盖的边界：值的长度截断、多级/单段属性名、删除后重建、多区域互不干扰、
批量导入的脏输入、persist 快照去重、`.replace`、多模块覆盖顺序、
`skip_mount`/`disable`、分区分流、脚本排序与阶段隔离、规则形式、needs_root 报错。
**root 与非 root 两种身份都要全过**（CI runner 是非 root，需要 root 的检查会明确标 SKIP，
绝不静默通过）。

属性区布局有三条编译期断言（`sizeof(prop_info)==96` / `trie_node==20` / `pa_header==128`），
`components.yml` 里还有一个**负向测试** job：故意把结构改坏，确认编译真的被拦住
——防止断言变成摆设。

**还没验的**：真机。属性区结构、分区 symlink 形态、SELinux 都是设备相关的，
至少要在 1 台 2SI + 1 台非 2SI 设备上各验一遍。

---

## 7. 上手路径

```bash
bash tools/smoke_test.sh              # 28 项，本地先跑这个
bash tools/component_test.sh          # 34 项，改动组件时跑这个
python3 tools/mkprop.py /tmp/props ro.debuggable=0   # 造合成属性区
./build/boss resetprop -n --dir /tmp/props ro.debuggable 1
./build/boss module plan              # 只看挂载计划，不真挂
./build/boss sepolicy check <file>    # 规则规范化
./build/boss boot post-fs-data        # 完整开机编排（真机上跑）
```
