# BOSS · 任务3 接力文档（其他关键文件与重要组件开发）

> 给第三位接力的开发者。这份文档假设你已经读过：
> - `docs/BOSS-su-方案解析与设计.md`（启动链事实与 su 架构）
> - `docs/HANDOFF-接力须知.md`（任务2 踩过的坑与架构红线）
>
> 这里只写任务3 专属的东西：**范围怎么划、组件按什么顺序做、每个组件的关键决策与致命坑、以及和任务 4/5/6 的接口契约。**

---

## 0. 一句话定位

任务2 交付的是「**拿到 root 权限的能力**」。任务3 要交付的是「**拿到 root 之后，能干什么、且干得漂亮**」。

Magisk 的对应关系很直接：任务2 ≈ `magiskd + su`，任务3 ≈ `resetprop + magic mount + busybox + 模块系统 + boot 脚本 + magiskpolicy`。
没有任务3，用户拿到的只是一个能 `su -c id` 的空壳——改不了 ro 属性、挂不了模块、改不了分区内容，日用价值接近于零。

---

## 1. 你的范围：做什么 / 不做什么

### 1.1 归你做的（按优先级，见第 3 节）

| # | 组件 | 为什么必须有 |
|---|---|---|
| A1 | applet 多调用分发框架 | 所有组件的组织方式；也是"少落文件=少痕迹"的前提 |
| A2 | 工具集（busybox 风格） | `su -c` 里跑的脚本依赖 coreutils，Android 自带 toybox 功能不全 |
| B1 | resetprop（属性改写） | 改 `ro.*`、删属性——**任务5「无修改系统逻辑」的核心弹药** |
| B2 | 模块 / overlay 挂载 | 不改分区而替换系统文件——**任务5 的另一半弹药** |
| B3 | boot 阶段脚本执行器 | 让用户/模块的脚本能在正确时机跑起来 |
| C1 | sepolicy 补丁工具 | **任务4 的输入工具**（读取/修改/回写 sepolicy） |
| D1 | 关键文件格式约定 | 模块元数据、system.prop、sepolicy.rule 的落点与解析 |

### 1.2 **不归你做的**（划错边界会返工）

| 事项 | 归属 | 为什么 |
|---|---|---|
| **2SI 设备的 init 接管**（SwitchRoot 劫持 / hexpatch） | **su 侧 v0.2**，`src/bossinit.c` 的 `stage2` / `hijack-prep` 已留好入口 | 这是"拿到执行权"的问题，不是组件问题。你重复做会跟 su 打架 |
| SELinux 策略本身（domain 定义、allow 规则集） | 任务4 | 你只提供**工具**（C1），不定义策略内容 |
| systemless 的实际玩法（隐藏、denylist、Integrity 绕过） | 任务5 / 任务6 | 你提供**能力**，他们决定怎么用 |
| BOSS App / 前端 | 任务6 | 你提供 CLI 与文件约定 |

### 1.3 ⚠️ 顺序陷阱：这是你现在最该担心的事

**任务3 的 B2/B3（模块挂载、boot 脚本执行器）依赖"启动链执行权"，而执行权在 Android 10+ 主流 2SI 设备上目前还不存在。**

具体说：
- `payload/init.boss.rc` 只在 ramdisk 存活的布局（非 2SI、vendor_boot 布局）上会被执行；
- 2SI 设备切根后 ramdisk 消失，rc 根本不会被解析（详见接力须知 2.2）；
- 所以你在 2SI 真机上做完 B2/B3，**会发现它们一次都没被触发**，而你会误以为是自己的 bug。

**正确顺序**（第 3 节按这个排的批次）：
1. 先做 **A 批 + C1 + B1**：这些能用 `su -c` 手动调用验证，不依赖启动链；
2. 再做 **B2/B3**：先在非 2SI 设备或手动 `su -c 'boss init post-fs-data'` 验证逻辑，等 su 侧 v0.2 落地后自然接上。

---

## 2. 开工前必读的三条硬约束

### 2.1 权限与 SELinux 依赖
你的组件全都要 root + 能干挂载/改属性的 SELinux 权限。任务4 完成前：
- 调试用 `androidboot.selinux=permissive`（veritpath 的 `--permissive` / manifest 的 `selinux` 字段都支持）；
- **不要为了让功能跑通就去写一堆 allow 规则**，那是任务4 的活。你只需要把"需要哪些权限"列清楚交给任务4。

### 2.2 隐蔽红线（沿用任务2）
- **不写 `/system`**，一个字节都不行——所有改动走属性改写或挂载覆盖；
- 运行时目录统一 `/data/adb/boss/`（`BOSS_DIR`，`src/boss.h`）；
- IPC 沿用抽象套接字；新增常驻进程前先问"能不能复用 bossd"。

### 2.3 ramdisk 体积是硬约束
`init_boot` / `boot` 分区大小固定，注入后的镜像撑爆分区会直接变砖。
**所以：ramdisk 里只放 `boss` 一个二进制**（这是任务2 的单二进制多入口设计的原因）。
busybox 这类大件（几百 KB ~ 1MB+）**绝对不要塞进 payload**，应该：
- 由 BOSS App 首次启动时释放到 `/data/adb/boss/bin/`；或
- 从网络下载；或
- 编译成独立文件随 Release 分发，由 App 侧 push。

---

## 3. 组件清单与实施顺序

### 第一批（先做，可独立验证，不依赖启动链）

#### A1 · applet 多调用分发框架

现状：`src/main.c` 已有一个雏形——用 `basename(argv[0])` 判断 `su` / `bossd` / `init` / `bossinit`，再加 `boss <cmd>` 的子命令。

**要做的是把它升级成一张表**，同时支持两种调用方式：
- symlink 调用：`/data/adb/boss/bin/resetprop -> boss`，此时 `argv[0]` 是 `resetprop`
- 子命令调用：`boss resetprop ...`，此时 `argv[0]` 是 `boss`，`argv[1]` 是 `resetprop`

```c
struct boss_applet {
    const char *name;
    int (*fn)(int argc, char **argv);
    int needs_root;      /* 非 root 调用时直接报"需要 root"，不要静默失败 */
    const char *summary; /* boss --list 用 */
};
```

坑：**两种调用的 argv 偏移不同**。symlink 方式下 `argv[1]` 才是第一个参数；子命令方式下 `argv[2]` 才是。现在 `main.c` 里用的是 `argc - 1, argv + 1` 的写法，扩表时统一处理，别各写各的。

另一个坑：applet 名字如果和 shell 内建或系统命令重名（比如 `mount`），务必保证只在我们的 PATH 前置目录里出现，别污染全局。

#### A2 · 工具集

Android 自带的 toybox 缺不少东西（完整 `awk` / `sed`、`mount` 的部分选项、`tar`、`curl` 等），root 脚本几乎都依赖 busybox。

决策建议：
- **不要自己写**（工作量无底洞），集成一份 busybox，静态编译；
- 放在 `/data/adb/boss/bin/busybox`，按需创建 symlink；
- 提供 `boss sh` 作为"开箱即用 shell"：`busybox ash --standalone` 起，**standalone 模式**让脚本里的命令优先解析到 busybox 的 applet，而不是被系统的 toybox 截走——这是 Magisk 的做法，也是脚本兼容性（尤其老模块）的关键；
- 注意 standalone 模式会覆盖命令查找顺序，只在我们自己的 shell 里开，不要影响全局。

#### B1 · resetprop（属性改写）

**原理（已核实）**：init 把属性存在共享内存 `/dev/__properties__`（每块 128KB，8.0+ 按 `property_contexts` 分成多个区域，内部是 hybrid trie + `prop_info` 叶子）。
普通进程改属性只能通过 unix socket 请求 init 的 property_service，而 **init 会拒绝 `ro.*` 修改和属性删除**。
resetprop 的做法是**直接 mmap 并改 prop_area 内存**，绕开 property_service。

**必须实现的语义**（三个开关，语义别搞混）：

| 开关 | 行为 | 什么时候必须用 |
|---|---|---|
| 默认 | 走 property_service（先删再设），**会触发** `on property:foo=bar` | 需要触发 rc 事件时 |
| `-n` | 直接改 prop_area，**不触发**任何 rc 事件 | **post-fs-data 阶段必用**，否则死锁开机 |
| `-p` | 对 `persist.*` 同时作用于 `/data/property` 持久化存储 | 删除 persist 属性想永久生效时 |

**致命坑（会变砖，务必记住）**：
- post-fs-data 是**阻塞阶段**，此阶段用 `setprop`（走 property_service）会**直接死锁开机流程**。官方明确要求改用 `resetprop -n`。
- 该阶段有约 40 秒上限后会强制放行——所以你的 bug 可能表现为"开机莫名慢 40 秒"而不是"卡死"，别被误导。
- persist 属性默认删除**只改内存**，重启后恢复。要永久删除必须 `-p`。

实现提示：不必从零写，AOSP 的 `system_properties.cpp` 是现成参考（Magisk 也是这么干的：抽出来 + 打补丁允许直写）。注意 8.0+ 的**多区域**——按 `property_contexts` 的前缀匹配找到对应区域，别只改第一个区域。

#### C1 · sepolicy 补丁工具

这是**工具**，不是策略。任务4 会用你来改策略，所以要提供的是：
- 加载 sepolicy（从 `/sepolicy`、vendor 预编译、或 split policy 合并）
- 增删规则（`allow` / `type` / `type_transition` / `typeattribute` / `permissive`）
- 回写并让系统加载（Magisk 的做法：patch 后 dump 到 `/sepolicy` 或 `/dev/.se`，并 patch init / libselinux.so 强制加载）
- 支持规则文件输入（即 D1 里的 `sepolicy.rule`）

给任务4 的接口提示（Magisk 的成熟模型，可直接借鉴）：
- 定义一个 `boss` domain，设成 permissive（daemon 与 root shell 跑在里面）；
- 定义一个 `boss_file` 类型，允许被所有 domain 访问（unrestricted file context）；
- Android 8.0+ 的收紧模型：二进制标 `boss_exec`，允许的 su client domain 执行它时通过 `type_transition` 转到 `boss_client`；**只允许 boss domain 给文件标 `boss_exec`**，且**禁止直连 daemon socket**，唯一入口是 `boss_client` 进程。

### 第二批（依赖启动链，等 su 侧 v0.2 或先在非 2SI 设备验）

#### B3 · boot 阶段脚本执行器

三个阶段，时机和语义完全不同，**选错时机是组件 bug 的第一大来源**：

| 阶段 | 时机 | 是否阻塞 | 用途 |
|---|---|---|---|
| `post-fs-data` | /data 解密挂载后、模块挂载前、Zygote 前 | **阻塞**（约 40s 上限） | 赶在挂载前做的决策（如按属性决定是否挂载） |
| `late_start`（service） | 启动大部队之后 | 非阻塞，后台 | **绝大多数脚本的默认选择** |
| `boot-completed` | 开机完成 | 非阻塞 | 依赖系统服务就绪的操作 |

约定目录（建议）：
```
/data/adb/boss/post-fs-data.d/*.sh
/data/adb/boss/service.d/*.sh
/data/adb/boss/boot-completed.d/*.sh
```
执行器要点：按文件名排序执行、每条脚本有超时、失败不影响后续、结果写日志。

#### B2 · 模块 / overlay 挂载

最终效果很朴素：把模块的 `$MODPATH/system` **递归合并**进真实 `/system`——已有文件被替换，新文件被添加。

**技术选型（这是你最重要的一个决定）**：

| 方案 | 优点 | 风险 |
|---|---|---|
| **Magic Mount（bind mount + tmpfs）** | 兼容性最好；与 Magisk 模块生态直接兼容 | 文件多了开销大；对目录合并逻辑要求高 |
| **OverlayFS** | 单次挂载，性能好 | 依赖 `CONFIG_OVERLAY_FS=y`；4.19+ 需要 xattr 递归补丁；部分设备/内核不支持 |

**建议：先做 Magic Mount，overlayfs 留成可切换的可选项。** 理由：BOSS 主打日用，兼容性优先；且 Magic Mount 能直接吃 Magisk 模块生态，这是"实用"的捷径。等挂载逻辑稳定后再加 overlayfs 后端。

必须处理的细节：
- **`.replace` 语义**：模块目录里放一个名为 `.replace` 的空文件，该目录整体替换而不是合并（换掉整个系统 app 时很有用）。
- **分区可能是 symlink 也可能是原生目录**：`/system/vendor`、`/system/product`、`/system/system_ext` 在不同设备上形态不同。Magisk 的 `handle_partition()` 逻辑是：原生目录就移到 `$MODPATH/{partition}` 并在 `$MODPATH/system/{partition}` 建符号链接；symlink 就保持原位。**不处理会导致 vendor/product 的改动静默失效。**

### 第三批

#### D1 · 关键文件格式约定

```
/data/adb/boss/
├── boss                      二进制本体（单文件多入口）
├── policy.conf               su 授权策略（任务2 已定）
├── boss.log                  审计日志
├── bin/                      busybox 与 applet symlink（App 释放）
├── modules/<id>/             模块
│   ├── module.prop           id / name / version / author / description
│   ├── system/               要覆盖进 /system 的内容
│   ├── system.prop           模块属性（加载时 resetprop）
│   ├── sepolicy.rule         SELinux 规则（交给 C1 应用）
│   ├── post-fs-data.sh / service.sh / ...
│   ├── skip_mount            存在则不挂载（只跑脚本）
│   └── remove                存在则下次开机移除
└── post-fs-data.d/ service.d/ boot-completed.d/
```

一个要你拍板的决策：模块目录用 `/data/adb/modules`（**直接兼容 Magisk 模块生态**）还是 `/data/adb/boss/modules`（**更隐蔽**）？
我的建议是**内部用 `/data/adb/boss/modules`，但模块格式（module.prop / system / system.prop / sepolicy.rule / 脚本名）完全对齐 Magisk**，这样兼容生态的成本只是一个目录重定向，而 `/data/adb/modules` 这个路径本身是 root 检测的高频特征点——不符合 BOSS 的隐蔽定位。

---

## 4. 与后续任务的接口契约

### 给任务4（SELinux）
- 工具：`boss sepolicy`（C1）
- 你需要告诉任务4 的**权限清单**（建议随代码维护一份 `docs/SELINUX-REQUIREMENTS.md`）：
  - 挂载：`mount` / `remount` / 对 tmpfs 与 overlay 的操作
  - 属性：读写 `/dev/__properties__` 的能力
  - 文件：对 `/data/adb/boss` 下所有内容的访问
  - 进程：bossd 与目标 domain 之间的 transition
- 参考模型：boss domain（permissive）/ boss_file（unrestricted）/ boss_exec + boss_client（8.0+）

### 给任务5（无修改系统逻辑）
你能提供的弹药就两件：**resetprop**（改属性不改文件）+ **挂载覆盖**（换文件不改分区）。
任务5 的所有"特典逻辑"都应该建立在这两个能力之上——如果任务5 提出需要改 `/system` 才能实现的玩法，那是需求越界，要打回。

### 给任务6（BOSS 客户端）
- CLI 面：`boss <applet>` 全量可调用，退出码语义统一（0 成功 / 非 0 失败）
- 文件面：第 3 节 D1 的目录约定就是 App 的读写契约
- 状态面：`boss ping`（已有）、`boss --list`（applet 清单）、日志 `/data/adb/boss/boss.log`
- 协议面：扩展 `struct boss_request` 时**必须同时升 `BOSS_PROTO_VER`**，否则新旧二进制静默错位

---

## 5. 验收清单（真机）

```
第一批（现在就能验，用 su -c 手动调用）
[ ] boss --list 列出所有 applet
[ ] symlink 调用与子命令调用两种方式行为一致
[ ] boss sh 进入 standalone shell，命令解析到 busybox 而非 toybox
[ ] resetprop ro.debuggable 1 → getprop 读回为新值
[ ] resetprop -n ro.foo bar → 不触发任何 on property: 事件
[ ] resetprop --delete ro.foo → getprop 读不到
[ ] resetprop -p --delete persist.foo → 重启后仍不恢复
[ ] boss sepolicy 能加载并回写一份 patched policy（先 permissive 下验）

第二批（需启动链，等 v0.2 或先用非 2SI 设备）
[ ] post-fs-data 阶段用 resetprop -n，开机不卡 40 秒
[ ] /data/adb/boss/service.d/ 下的脚本在开机后确实执行过（看日志）
[ ] 一个带 system/ 的模块挂载后，目标文件被替换
[ ] 带 .replace 的模块目录整体替换生效
[ ] vendor / product 是原生目录的设备上，模块改动仍生效
[ ] 模块 skip_mount 存在时不挂载但脚本照跑

隐蔽性回归（每批都要）
[ ] /system 的内容 hash 与刷机前一致
[ ] 未引入新的可被检测的属性（getprop 全量 diff）
[ ] /data/adb/boss 权限为 0700，日志可关
[ ] 刷回原厂镜像仍能开机（自救路径必须留）
```

---

## 6. 别浪费时间的地方

- **别去自己实现 busybox**。集成现成的，把时间花在 applet 分发和 standalone shell 上。
- **别在 payload 里塞大文件**。ramdisk 撑爆分区会变砖（见 2.3）。
- **别在 post-fs-data 里用 setprop**。这条会让你 debug 一整天（见 B1）。
- **别把 overlayfs 当首选**。先 Magic Mount，稳了再说。
- **别去定义 SELinux 策略内容**。你只出工具，策略是任务4 的。
- **别信"本地能跑就等于真机能跑"**。属性区结构、分区 symlink 形态、SELinux 都是设备相关的，至少在 1 台 2SI + 1 台非 2SI 设备上各验一遍。
- **别碰 init 接管**。那是 su 侧 v0.2，重复做必然冲突（见 1.2）。

---

## 7. 上手路径（建议的第一天）

```bash
# 1. 理清现状
bash tools/smoke_test.sh          # 确认 su 链路是通的
cat src/main.c                    # 看现有 applet 分发雏形
cat src/boss.h                    # 看 BOSS_DIR 等运行时约定

# 2. 从 A1 开始：把 main.c 的 if-else 换成 applet 表
#    先加一个最简的测试 applet，验证 symlink 与子命令两种调用

# 3. 做 B1 resetprop：这是最能体现 BOSS 价值的组件，
#    且能用 su -c 立刻验证，不依赖启动链

# 4. 每做完一个组件，补一条 tools/smoke_test.sh 的检查项，
#    CI 会在你 push 时替你把关（ci.yml 的 smoke / strict 两个 job）
```
