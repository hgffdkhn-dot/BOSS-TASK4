# BOSS · 任务4：SELinux 解决与规则注入

> 给任务 5（无修改系统逻辑）、任务 6（客户端），以及回看这份文档的 su 侧 v0.2。
> 前置阅读：`docs/HANDOFF-接力须知.md`（红线与坑）、`docs/SELINUX-REQUIREMENTS.md`（权限清单）、
> `docs/TASK3-组件交付与接力.md`（工具层边界）。
>
> 这里只写**从别处看不出来**的东西：为什么时机比引擎重要、策略内容怎么定的、
> 哪几处我做了保守选择、还有哪些没验。

---

## 0. 一句话

任务3 交给我的是一把**工具**（`boss sepolicy`：解析规则 → 找引擎 → 没引擎就攒队列）。
任务4 补上的是工具背后缺的那两样：**策略内容**（BOSS 到底要哪些权限）和**注入时机**（什么时候打进去才有用）。

其中第二样是这份文档最想说的一件事——**在 post-fs-data 做 live patch 是次优解，正确的时机在 init 加载策略之前。**

---

## 1. 现状盘点：接手时有什么、缺什么

| 部分 | 状态 | 谁做的 |
|---|---|---|
| 规则文件解析与规范化 | ✅ | 任务3（`src/sepolicy.c`，兼容 Magisk `sepolicy.rule` 语法） |
| 外部引擎适配（magiskpolicy / sepolicy-inject / supolicy） | ✅（粗糙） | 任务3 |
| 无引擎时的 pending 队列 | ✅ | 任务3 |
| **策略内容**（boss 域、需要哪些 allow） | ❌ → ✅ | **任务4**（`policy/boss.rule`） |
| **注入引擎的分层与尽力而为语义** | ❌ → ✅ | **任务4**（`src/selinux.c`） |
| **注入时机**（策略加载之前） | ❌ → ✅（接口） | **任务4**（`boss selinux setup`，落点仍在 su 侧 v0.2） |
| 文件标签（file_contexts / setfilecon） | ❌ → ✅ | **任务4**（`policy/boss_file_contexts` + `boss selinux label`） |
| libsepol 内置后端 | ⚠️ 接口已定，未 vendor | 任务4（见第 3.3，这是本任务唯一的未完成项） |

任务3 在 `TASK3-组件交付与接力.md` 3.3 里明确写了"不自研 policydb 二进制改写器"，理由是"交出一个没在真机验过的改写器比不做更危险"。**这个判断我接受**，所以引擎选型走的是第 3 节那条路，而不是自己重写 libsepol。

---

## 2. 核心判断：时机 > 引擎

### 2.1 一条绕不过去的顺序红线

init 的 `selinux_setup` 阶段（`SetupSelinux`，Android 10+ 由第一阶段 init 以 `selinux_setup` 参数触发）做两件事，顺序固定：

1. **加载策略到内核**
2. **restorecon**（按 file_contexts 给文件打标签）

而 file_contexts 里写的 type，必须在第 ① 步之后就已经存在。于是：

```
策略里有 boss_exec  ──►  /boss 才能被打成 boss_exec  ──►  才能跑在 boss 域
```

**如果标签先引用、type 后定义，init 打标签时就是 unknown type**——要么报错，要么静默退化成默认类型。

### 2.2 由此推出的两句结论

- **post-fs-data 阶段的 live patch 天生晚了。** 它发生在 `selinux_setup` 之后很久：此时 `/boss` 早已被打成 `u:object_r:rootfs:s0`（manifest 现在的写法），`/data/adb/boss` 是无标签或默认 data 标签；而且**内核重载策略不会重算已存在进程和文件的 SID**，live patch 打完还要额外 restorecon 才见效。
- **注入必须赶在 init 加载策略之前。** 也就是 su 侧 v0.2 的 `cmd_stage2` 收到 `selinux_setup` 的那一次执行——这个参数接力须知 5.2 已经点名了，只是当时还没往里放东西。

### 2.3 因此任务4 是两条路径，不是一条

| 路径 | 时机 | 命令 | 负责的内容 |
|---|---|---|---|
| **A · 早期注入（主）** | init `selinux_setup`，策略加载前 | `boss selinux setup` | BOSS 自己的域、type 定义、标签前提 |
| **B · 运行时注入（辅）** | post-fs-data 及之后 | `boss selinux live` / `boss selinux pending` / `boss sepolicy apply` | 模块带来的动态规则（`sepolicy.rule`） |

路径 A 覆盖了"BOSS 自己是谁"，路径 B 覆盖"模块想要什么"。两者用同一个引擎、同一套尽力而为语义，只是时机不同。

**路径 A 失败不会让 BOSS 起不来**：它失败时规则进 pending 队列，等 `/data` 挂载后由路径 B 兜底（此时 BOSS 会跑在 init 域而非 boss 域，功能不受影响，只是标签不够干净）。这个降级关系是刻意的——**开机安全优先于标签优雅**。

---

## 3. 引擎选型

### 3.1 为什么不自研 policydb 二进制改写器

完整反序列化 + 重排 avtab / 条件表达式，本质是 libsepol 的活：几千行、强依赖 policy 版本（Android 8.0+ 常见 30/31/32/33，各家还有自己的 patch）。写错一个 section 顺序就是变砖，而且**编译期完全不报错**（这个项目的接力须知 4.5 已经吃过一次"编译通过但上机起不来"的亏）。

结论：**不自研**。改策略这件事交给经过真机验证的实现。

### 3.2 三级降级链（`src/selinux.c` 的 `inject_rules()`）

```
① libsepol 内置后端     -DBOSS_HAVE_SEPOL 时启用，不 fork、不落临时文件
        │ 未 vendor / 失败
        ▼
② 外部引擎              magiskpolicy（首选）→ sepolicy-inject → supolicy
        │ 都不存在
        ▼
③ pending 队列          写 /data/adb/boss/sepolicy.pending，返回 2
```

**返回 2 是"没做成"的明确表达，不是成功**——这是任务3 定下的契约，`boot.c` 的 `apply_module_rules` 依赖它：2 不该中断开机，0 会被误判成"规则已生效"。我原样保留了这个语义。

### 3.3 关于 libsepol 内置后端（本任务唯一未完成项）

接口已固定在 `src/selinux.c`：

```c
int sepol_builtin_apply(const char *in, const char *out, const char **rules,
                        int n, int live, struct inject_result *res);
```

没有 vendor 时它是个返回 -1 的桩，引擎自动落到外部引擎。**当前默认路径（外部引擎 magiskpolicy）已经能覆盖真实使用场景**——这也是 Magisk 生态里最常用的一条路。

要真正内置，需要 vendor libsepol（`tools/vendor-sepol.sh` 给出文件清单）并补齐 `src/sepol_backend.c`：核心是 `policydb_read` → 直接操作 avtab 插入 `avtab_key_t`/`avtab_datum_t` → `policydb_write`。这部分强依赖 libsepol 内部结构，且必须在真机上验；**我没把一份没验过的实现塞进来**，理由同 3.1。

### 3.4 尽力而为（这是策略注入最容易写错的一处）

Android 各版本、各厂商的 type / class / perm 集合都不一样。同一份规则在 A 机型全生效，在 B 机型上可能有 30 条"目标不存在"。

处理方式：

```
一次 exec 批量传 ≤64 条  ──成功──►  记 applied，结束（快）
        │ 失败
        ▼
拆成逐条重试  ──►  定位到具体哪条不行
                ──►  "目标 type/class 不存在"记为 skipped（可容忍）
                ──►  引擎本身跑不起来（126/127）记为 failed（真错误）
```

返回码：`0` 全应用 / `3` 部分应用 / `1` 失败 / `2` 无引擎。

**部分应用是正常结果，不是错误。** 它让 post-fs-data 不会因为一条规则失效而中断开机，同时调用方又能从返回值和日志里看到真实情况——既不假装成功，也不小题大做。

---

## 4. 策略内容（`policy/boss.rule`，255 条）

这份文件是任务4 独占的产出——任务3 反复强调"我只出工具，策略内容归任务4"。

### 4.1 域模型

沿用 `SELINUX-REQUIREMENTS.md` 第 2 节的模型（Magisk 的成熟做法）：

| type | 用途 |
|---|---|
| `boss` | 守护进程域。**架构红线第 1 条**：daemon 是唯一的特权实体 |
| `boss_file` | `/data/adb/boss` 下的数据文件，标成 unrestricted（所有域可访问） |
| `boss_exec` | BOSS 二进制，带 `exec_type`，收紧模型下可当 transition 目标 |
| `boss_client` | su 客户端域（无特权），8.0+ 收紧模型才用 |

### 4.2 权限覆盖（对照 `SELINUX-REQUIREMENTS.md` 的 5 类）

| 需求 | 覆盖情况 |
|---|---|
| resetprop | 属性区多区域文件的 `read/write/map/execute`（mmap 可写映射需要 execute，这是 resetprop 最常见的 denied）、`/data/property`、persist 快照 |
| 模块挂载 | `sys_admin` 等 capability + `filesystem mount/remount/unmount` + 各分区 `mounton` |
| boot 脚本 | fork/exec、pty、日志写入 |
| sepolicy 自身 | 读写 `selinuxfs`（`/sys/fs/selinux/load`）、读策略源文件、执行引擎 |
| daemon IPC | 抽象命名空间套接字全部操作（无 `/dev/socket` 节点，符合红线）+ SCM_RIGHTS |
| **init 拉起 BOSS** | `allow init boss process transition` + `allow init boss_exec file execute` |

最后一行是我在集成时补的，值得单独说一句：**如果 `init.boss.rc` 里写 `seclabel u:r:boss:s0`，而策略里没有 init → boss 的 transition 许可，那条命令要么被拒（BOSS 起不来），要么静默退化成 init 域（能起来但权限不对）**。这是"看着像策略问题、实际是启动问题"的典型。

### 4.3 两个我做了保守选择的地方

**（1）`permissive boss` 保留。**
只作用于 BOSS 自己的域，不影响系统任何其他域。规则集要覆盖全部功能需要逐机型验证，而 permissive 让 BOSS 在任何机型上都能先跑起来——**日用优先**。等真机上把 denied 日志收集完整、规则补齐，再去掉收紧（文件里有明确标注和做法）。Magisk 长期也是这么做的。

**（2）8.0+ 收紧模型默认不启用。**
`SELINUX-REQUIREMENTS.md` 建议 `boss_exec` + `boss_client` 的 type_transition 模型。它会把"哪些 app 能调 su"变成策略可见，但兼容性面很大（各版本 app domain 名字不同：`untrusted_app` / `_25` / `_27` / `_29` / `_30` / `_32`，还有 `isolated_app` / `ephemeral_app` / `sdk_sandbox`）。
折中：**规则全部写好放在第 10 组，默认注释掉**，真机验过再按机型补齐 app domain 列表放开。

### 4.4 版本适配

不搞版本分支——靠"尽力而为 + 通配"消化差异：

- 需要 MLS 的 `mlstrustedsubject` / `mlstrustedobject`：存在就生效，不存在跳过；
- 分区相关（`system_file` / `vendor_file` / `product_file` / `system_ext_file` / `odm_file`）：逐条尽力而为；
- 每条规则在文件里标了 `[必需]` / `[尽力]`，收集真机日志时按这个优先级补。

---

## 5. 文件标签

`policy/boss_file_contexts` 给两份用途：

- **ramdisk 阶段**：veritpath 把匹配 `/boss` 的条目写进 ramdisk 的 `/file_contexts`（manifest 的 `files[].context`）；
- **/data 阶段**：`boss selinux label` 递归给 `/data/adb/boss` 打标签。

后者用 **setxattr 直接写 `security.selinux`**，不碰 libselinux——理由和接力须知 4.4 一样：Android 静态二进制里 `dlopen` 不可用，而 `setxattr` 是系统调用。符号链接走 `lsetxattr`，否则会跟到目标文件上去。

⚠️ **顺序不能颠倒**：file_contexts 是首次匹配优先，具体的（`/boss`、`bin/`）必须排在通配（`/data/adb/boss(/.*)?`）之前，否则具体条目永远轮不到。

---

## 6. 给 su 侧 v0.2 的接入点（唯一的跨任务改动）

`bossinit.c` 的 `cmd_stage2` 现在对 `selinux_setup` 只是原样转发参数。要接上早期注入，加两处：

```c
/* 1) 在 cmd_stage2 开头，判断当前是不是 selinux_setup 阶段 */
if (argc >= 2 && !strcmp(argv[1], "selinux_setup")) {
    /* 策略还没加载——这是我们唯一能改它的窗口 */
    execl(BOSS_SELF, BOSS_SELF, "selinux", "setup", (char *)NULL);
    /* 失败不致命：规则会进 pending，等 /data 挂载后由运行时注入兜底 */
}

/* 2) exec 真实 init 时，把参数换成 second_stage */
```

**第 2 点是这条链路里最容易踩的坑**：patch 完之后如果还把 `selinux_setup` 原样传给真实 init，它会拿**原始（未打补丁的）策略再加载一次**，把我们的补丁整个盖掉。症状是"注入明明返回成功，但 BOSS 仍在 init 域里"——极难排查。

所以流程是：

```
BOSS patch 策略 → BOSS 写进内核 → exec 真实 init second_stage（跳过其 selinux_setup）
```

`boss selinux setup` 已经把前三步封装成一条命令（定位策略源 → 注入 → 加载），su 侧只需要调它。patch 产物放 `/dev`：早期 `/data` 还没解密挂载，只有 tmpfs 可写。

---

## 7. 给后续任务的接口

- **任务5（无修改系统逻辑）**：你能用的仍然是 resetprop + 挂载这两件。enforcing 下它们现在有策略覆盖了（第 4.2 节前两行）。如果某个玩法需要新权限，往 `policy/boss.rule` 加，跑 `make rules` 重新内联。
- **任务6（客户端）**：
  - CLI：`boss selinux <子命令>`，返回码统一（0/1/2/3）
  - 状态展示：`boss selinux status` 一行出 enforcing 状态、策略源、引擎、内嵌规则数、pending
  - 想让 BOSS 跑在干净的 boss 域：早期注入成功后改 `init.boss.rc` 的 `seclabel`，见第 8 节
- **任务3 的工具层**：`boss sepolicy apply` 已改走任务4 的引擎（`boss_selinux_inject`），语义不变（2 = 无引擎、3 = 部分应用都不中断开机）。两边不再各写一套引擎适配。

---

## 8. 真机验收清单

```
早期注入（路径 A）
[ ] init 以 selinux_setup 调起 BOSS，boss selinux setup 返回 0
[ ] exec 真实 init 时传的是 second_stage（不是 selinux_setup）
[ ] 冷启动后 id -Z 看到 BOSS 相关进程在 u:r:boss:s0
[ ] /boss 的标签是 u:object_r:boss_exec:s0（不是 rootfs）

运行时注入（路径 B）
[ ] 带 sepolicy.rule 的模块，规则在 enforcing 下生效
[ ] 部分规则失效时返回 3，开机不中断，日志写明哪条没生效
[ ] 无引擎时返回 2，pending 队列有内容且不被清

功能（enforcing 下，对应 SELINUX-REQUIREMENTS 第 4 节）
[ ] resetprop 能改 ro.* 并读回新值
[ ] resetprop -n 不触发任何 on property: 事件
[ ] 模块挂载在 enforcing 下成功（不再依赖 permissive）
[ ] post-fs-data 阶段开机不卡 40 秒
[ ] bossd 仍在跑（boss ping 返回 up）

隐蔽性回归（每批都要）
[ ] /system 的 hash 与刷机前一致
[ ] 没有引入新的可被检测的属性
[ ] 刷回原厂镜像仍能开机（自救路径必须留）
```

**早期注入验稳之后的收尾动作**（现在故意没做，见 4.3）：

1. `payload/manifest.json` 的 `context`：`u:object_r:rootfs:s0` → `u:object_r:boss_exec:s0`
2. `payload/init.boss.rc` 的 `seclabel`：`u:r:init:s0` → `u:r:boss:s0`

现在不改是有意的：万一早期注入在某机型上没成，而 file_contexts 已经引用了 `boss_exec`，init 打标签就会撞上 unknown type（第 2.1 节的红线）。**先保证能开机，再换正式标签。**

---

## 9. 已知风险与没验的部分

诚实列出来，避免下一位把"没验过"当成"验过"：

| 项 | 状态 | 说明 |
|---|---|---|
| 策略内容（255 条） | **未上真机** | 语法与模型对齐 Magisk，但每条在各机型上是否都存在没验过。靠 `permissive boss` 兜底 |
| 早期注入链路 | **未上真机** | 命令与接口就绪，落点在 su 侧 v0.2（第 6 节） |
| libsepol 内置后端 | **未 vendor** | 接口已定，当前走外部引擎（第 3.3 节） |
| `boss selinux load` | 视内核而定 | 部分内核/厂商锁死了 `/sys/fs/selinux/load`，写不了会明确报错并返回 1，不会静默 |
| 8.0+ 收紧模型 | 默认关闭 | 第 10 组，需按机型补 app domain（第 4.3 节） |

**沙盒里已经验到的**（`bash tools/selinux_test.sh`，24 项）：内嵌规则与源同步、模型完整性、无引擎降级返回 2 且不清队列、批量→逐条降级与统计、sepolicy 工具接入、applet 注册。

---

## 10. 上手路径

```bash
make rules                          # 改了 policy/boss.rule 后重新内联
make test && bash tools/selinux_test.sh
./build/boss selinux status         # enforcing 状态 / 策略源 / 引擎 / 内嵌规则数
./build/boss selinux rules          # 看内嵌的 255 条
./build/boss selinux setup          # 早期注入（真机 selinux_setup 阶段）
./build/boss selinux live <file>    # 运行时注入
./build/boss selinux label          # 给 /data/adb/boss 打标签
```

新增/改动的文件：

```
policy/boss.rule              策略内容（255 条，带 [必需]/[尽力] 标注）
policy/boss_file_contexts     文件标签
src/selinux.c                 引擎层：策略源定位 + 三级降级 + 尽力而为 + 打标签
src/boss_rules.h              由 policy/boss.rule 生成（tools/gen_rules_h.py），勿手改
src/sepolicy.c                apply 改走 boss_selinux_inject（语义不变）
src/boss.h / src/applet.c     声明与注册
tools/selinux_test.sh         24 项验收
tools/gen_rules_h.py          规则内联
tools/vendor-sepol.sh         libsepol vendor 步骤（可选增强）
```
