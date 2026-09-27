# BOSS · su 打造方案（任务 2）

> 范围：接住 veritpath（任务 1）的注入成果，把「su」做成可用、可审计、可长期演进的组件。
> 本文同时是**方案解析**与**实现说明**：前半部分讲清楚 su 为什么必须长这样，后半部分是已经落地的代码。

---

## 0. 先给结论

| 问题 | 结论 |
|---|---|
| veritpath 给我们什么 | 布局判断 + 文件落位 + rc 注入 + 镜像重建。**它不提供任何 su 实现** |
| su 能不能只靠 ramdisk 里的 rc 活下来 | **不能**（Android 10+ 主流 2SI 设备）：ramdisk 在第一阶段结束后被 SwitchRoot 丢弃 |
| 那 su 靠什么起来 | 必须拿回「切根前后」的执行权 → init 接管（v0.2）。v0.1 先在 ramdisk 存活的布局上跑通全链路 |
| 本次交付 | bossd + su 客户端 + 策略引擎 + pty + init 助手；代码可编译、主机侧 9/9 冒烟通过、payload 通过 veritpath 实际注入与校验 |

---

## 1. 前辈工具的分析：veritpath 到底交付了什么

读 `README.zh-CN.md` / `docs/DEVELOPERS.md` / `src/*.c` 后的契约摘要：

**它做的（我们的前置依赖）**
- 解析 `boot.img` / `init_boot.img` / `vendor_boot.img`，判出 `arch`、`android_version`、`ramdisk_layout`、`system_as_root`、`gki`、`already_patched`。
- 按布局决定注入对象：

  | 布局 | 典型设备 | ramdisk 位置 | 注入对象 |
  |---|---|---|---|
  | `init_boot` | Android 13+ GKI | init_boot.img | 只改 init_boot（boot.img 只有内核，别碰） |
  | `vendor_boot` | Android 11/12 GKI 1.0 | vendor_boot 的 vendor_ramdisk | 改 vendor ramdisk |
  | `boot` | Android ≤12 非 GKI | boot.img | 直接改 boot.img |

- 多段 ramdisk（`first_stage_ramdisk` 先加载）时，payload 必须进**主段**（默认选标签 `main`，可用 `--segment` 指定）。
- payload = 一个目录 + `manifest.json`；支持 `files[]`（src/dest/mode/uid/gid/context/backup_as/symlink/required）、`rc`（file/content 或 content_file/import_into/append_to）、`cmdline_append`、`selinux`。
- 注入后写 `/veritpath.json` 留痕（payload 名、版本、注入时间、布局），重复注入会告警。
- `verify` 用退出码当 CI 闸门（OK=0 / INCOMPLETE=1）。

**它不做的（这就是我们的活）**
- 明确声明「**不提供任何 su 实现**」。
- 不做 SELinux 策略合并（只帮你往 `file_contexts` 写标签，或 cmdline 加 permissive）。
- 不做运行时：没有 daemon、没有授权、没有 IPC。

**对我们最关键的一条提示**（`plan` 的 notes 里原样输出）：
> `system-as-root: ramdisk files vanish after init switches root to /system`

这一句直接决定了 BOSS 的架构走向。

---

## 2. 启动链硬事实（决定 su 长什么样）

这几条不是推测，是从 AOSP 源码与 Magisk 实现里核出来的：

1. **两段式 init（2SI）**：第一阶段 init 跑在 ramdisk 里，结束时做 `SwitchRoot`——把 `/` 下的挂载**递归移动**到 `/system`，然后 `chroot` 进 `/system`。ramdisk 就此消失。[AOSP `init.cpp` + Magisk `native/src/init/twostage.rs` 注释]
2. **第二阶段 init 固定是 `/system/bin/init`**，它解析的是 **`/system/etc/init/hw/init.rc`**，不是 ramdisk 里的 `/init.rc`。[AOSP `LoadBootScripts()`]
   ```c
   std::string bootscript = GetProperty("ro.boot.init_rc", "");
   if (bootscript.empty()) {
       parser.ParseConfig("/system/etc/init/hw/init.rc");
       ...
   } else { parser.ParseConfig(bootscript); }
   ```
3. **唯一的官方后门**：`ro.boot.init_rc`（来自 cmdline `androidboot.init_rc`）可整体改写 boot script。veritpath 的 `cmdline_append` 刚好能写它——但路径必须活到第二阶段，所以仍需一个持久落点（`/data`）。
4. **Magisk 的真实做法**（`twostage.rs`）：利用 init 自己的 SwitchRoot，把 magiskinit 绑到 `/system/bin/init` 上接管第二阶段；若 rootfs 可写则退化成 hexpatch `/init`（把字符串 `/system/bin/init` 替换成 `/data/magiskinit`）。全程不在 `/system` 落盘。

**推论（各布局下 ramdisk rc 是否生效）**

| 布局 | 切根后 ramdisk | ramdisk 里的 `/init.boss.rc` | su 启动方式 |
|---|---|---|---|
| 非 2SI / ramdisk 保留 | 存活 | **会被执行** | rc 直接拉起（v0.1 覆盖） |
| Android 10+ 2SI（绝大多数） | 消失 | 不会被执行 | 必须 init 接管（v0.2） |
| 任意布局 + `androidboot.init_rc` | — | 可强制解析 | 需文件在 `/data`（v0.2 备选） |

**所以：su 的"能不能日用"，瓶颈不在 su 本身，而在能不能在切根后拿回执行权。** 这一条建议直接同步进任务 5（无修改系统逻辑）。

---

## 3. su 的落点与 BOSS 架构

### 3.1 组件

| 组件 | 形态 | 职责 |
|---|---|---|
| `bossd` | `boss --daemon` | **唯一的特权实体**：监听、鉴权、fork、pty、切 uid/SELinux、审计 |
| `su`（客户端） | `boss su` / `su` | 无特权"管道"：打包请求、搬运 stdio、收退出码 |
| `bossinit` | `boss init ...` | init 阶段助手：自复制、拉起 daemon、二阶段劫持（v0.2） |
| `boss policy` | CLI | 策略增删改查 |

运行时只落一个目录：`/data/adb/boss/{boss, policy.conf, boss.log}`。

### 3.2 为什么必须 daemon 化

- **单点鉴权**：uid 由内核 `SO_PEERCRED` 给，客户端伪造不了；如果 su 是 setuid 二进制，就得自己防各种提权路径（历史上 su 的漏洞几乎全在这）。
- **单点审计**：所有提权动作集中在一处记录，日志可关（日用）/可开（排障）。
- **可挂前端**：拒绝/允许/询问三种决策由策略文件决定，后续换成 App 弹窗只需改 `policy_decide()`。

### 3.3 数据流

```
app / adb shell
     │  ① AF_UNIX 抽象套接字 @bossd（文件系统无节点）
     ▼
  su 客户端 ──② 握手：SCM_RIGHTS 送"退出码通道"──┐
     │  ③ struct boss_request + env blob          │
     ▼                                            │
  bossd ──④ SO_PEERCRED 取 uid → 查策略 → 记日志   │
     │  ⑤ 拒绝：回 DENIED，结束                    │
     │  ⑤ 允许：openpty → fork → 子进程           │
     │        setsid / TIOCSCTTY / dup2           │
     │        setgid+setuid / setexeccon(ctx)      │
     │        execve(sh, ["-c", cmd])              │
     │  ⑥ 父进程 relay(sock ⇄ pty master)          │
     └────────────────────────────────────────────┘
     ⑦ 子进程结束 → 退出码经 side channel 回传客户端
```

### 3.4 协议（v1）

```c
struct boss_request {
    uint32_t magic, version;          /* 0xB0550001 / 1 */
    uint32_t target_uid, target_gid;  /* 默认 0 */
    uint32_t flags;                   /* LOGIN / KEEPENV / NOLOG / PING */
    uint32_t env_len, arg_len;
    uint16_t rows, cols;              /* 窗口尺寸 */
    char shell[64], command[1024], context[64];
};
```

- **连接第一步必须是 SCM_RIGHTS 握手**（送一个 socketpair 端），否则 daemon 的 `recvmsg` 会把请求体的第一个字节当握手吃掉——这个坑已经踩过并修掉了，探活请求也必须握手。
- 退出码走独立 side channel，避免被当成输出混进 stdout。

---

## 4. 关键决策与取舍

| 决策 | 选择 | 理由 |
|---|---|---|
| 子进程 stdio | pty（`/dev/ptmx`） | 交互式 shell 需要 tty（作业控制、^C）；关掉 `ONLCR`/`ECHO` 保证 `-c` 输出干净，脚本解析不被 `\r` 污染 |
| IPC 地址 | 抽象命名空间 `bossd` | `/dev/socket` 下无节点，文件系统零痕迹；配合 `SO_PEERCRED` 鉴权 |
| 二进制形态 | 单文件多入口（boss/su/bossd/init） | 少落文件 = 少痕迹；manifest 只需声明一个文件 |
| 策略存储 | 纯文本 `policy.conf` | 零依赖；`policy_decide()` 接口稳定，量产后换 sqlite 不影响调用方 |
| 客户端 stdin EOF | **不** `shutdown(SHUT_WR)` | 一旦关写方向，daemon 会判"客户端消失"并杀子进程，`-c` 的输出会被截断（已修） |
| 客户端消失 | daemon 收尾 SIGTERM→SIGKILL | 绝不留孤儿 root shell |
| 环境变量 | 默认净化（PATH/HOME/USER/SHELL/TERM…） | `-p` 才保留；从调用方只挑回 `TERM`，兼顾干净与终端能力 |
| SELinux | 运行时 `dlopen("libselinux.so")` | NDK 无官方头文件；缺失时自动跳过，保证无策略支持也能用 |

---

## 5. 隐蔽与日用

已做的低痕迹设计：
- 抽象套接字，文件系统不可见；
- 全部文件在 `/data/adb/boss`，`/system` 一个字节不改；
- 默认不产生 `/su`、`/system/bin/su` 这类传统特征路径（需要兼容老 app 时，由 BOSS 前端按需挂载）；
- 日志可关（`policy.conf` 的 `log = 0`），关闭后连 `open` 都不做；
- 单二进制、无第三方依赖。

留给前端/后续的低痕迹项（本次不实现）：包名随机化、App 侧 deny 列表（隐藏 su 给指定进程）、zygote 注入。

---

## 6. SELinux 边界（交给任务 4 的接口）

su 只依赖三个能力，任务 4 只要保证这三条，其它全部沿用现有 domain：

1. `bossd` 自身运行域（v0.1 暂用 `u:r:init:s0`，调试期可 `--permissive`）；
2. `bossd` → 目标域的 `transition`/`dyntransition` 许可（`setexeccon` 要能用）；
3. 我们的文件在 `/data/adb/boss` 上的 type 与 `file_contexts` 标签（manifest 里已按 `u:object_r:rootfs:s0` 写，后续替换成正式 type 即可）。

代码侧已经把切换点收敛成一个函数 `apply_selinux_context()`，策略成熟后不用动调用方。

---

## 7. 分期路线

| 版本 | 内容 | 状态 |
|---|---|---|
| v0.1 | bossd + su + 策略 + pty + 日志 + init 助手骨架 + payload；覆盖 ramdisk 存活的布局 | **已交付并实测** |
| v0.2 | init 接管（`boss init stage2` / `hijack-prep`）：SwitchRoot 劫持 + hexpatch 回退，2SI 设备上 post-fs-data 必然拉起 bossd | 设计已完成，代码留钩子 |
| v0.3 | BOSS 前端对接（授权弹窗/超时/通知）、包名随机化、deny 列表 | 待任务 6 |

> 任务3（关键组件：resetprop / 模块挂载 / boot 脚本执行器 / sepolicy 工具 / 工具集）
> 与 su 并行推进，不占 v0.x 编号，交接说明见 `docs/HANDOFF-TASK3-关键组件.md`。

---

## 8. 落地：构建 / 注入 / 验证

```bash
# 1. 编译（NDK；无 NDK 时 build-ndk.sh 会退回自带 clang）
bash build/build-ndk.sh                       # -> dist/boss-android-{arm64,arm,x86_64,x86}

# 2. 组装 payload
MAKE_PAYLOAD=1 bash build/build-ndk.sh        # -> build/payload/ 与 dist/boss-payload.zip

# 3. 交给 veritpath（不碰镜像先自检）
veritpath payload-check build/payload
veritpath plan --init-boot init_boot.img -p build/payload --permissive
veritpath inject --init-boot init_boot.img -p build/payload --permissive -o out/
veritpath verify out/init_boot.veritpath.img -p build/payload   # 退出码当闸门

# 4. 刷入
fastboot flash init_boot out/init_boot.veritpath.img
fastboot --disable-verity --disable-verification flash vbmeta vbmeta.img
```

**本次实测记录**（不是预期，是跑出来的结果）：
- `payload-check` → `VERDICT:OK`
- `inject` → `/boss`、`/veritpath/boss`、`/init.boss.rc`、`/veritpath.json` 全部 added
- `verify` → `VERDICT:OK`，`/init.rc` 出现 `import /init.boss.rc`，cmdline 追加 `androidboot.boss=1`
- 主机侧冒烟 `bash tools/smoke_test.sh` → **9/9 PASS**（探活、授权执行、环境净化、退出码 7、无 CR 污染、策略拒绝、日志、交互式 shell）

---

## 9. 已验证 / 未验证（诚实清单）

**已验证**
- 协议握手、鉴权、pty 搬运、退出码回传、策略拒绝、日志、交互式 shell（主机 Linux，root 身份）
- payload 被 veritpath 正确注入并校验（合成 init_boot 镜像）

**未验证（需要真机）**
- Android/bionic 下的实际运行（NDK 静态编译产物未经真机验证）
- SELinux enforcing 下的 `setexeccon` 行为（依赖任务 4 的策略）
- 2SI 设备上的自动拉起（v0.1 尚未接管 init）
- 多用户 / 多段 ramdisk / vendor_boot 布局的实际落位

---

## 10. 风险与已知限制

1. **v0.1 在 2SI 设备上不会自启**——这是最大的已知限制，必须靠 v0.2 的 init 接管闭环。
2. **pty 的 pts 多实例问题**：部分老内核/厂商修改过的 devpts 上，多实例 pts 可能受限；`pty.c` 已预留改造点。
3. **客户端消失即杀子进程**：符合预期，但若 app 在 `-c` 执行中被杀，命令会中断。
4. **`su -c 'cat'` 这类读 stdin 的用法**：客户端 stdin EOF 后未向 pty 送 EOF（避免误杀子进程），可能挂住。v2 协议会加显式的 stdin-EOF 控制消息。
5. **策略文件当前按"后写覆盖先写"**（同级规则），前端写入时要注意顺序语义。
6. `SO_PEERCRED` 只保证 uid 真实；包名到 uid 的映射需要前端配合（读取 `/data/system/packages.list`），当前策略以 uid/appId 为准。
