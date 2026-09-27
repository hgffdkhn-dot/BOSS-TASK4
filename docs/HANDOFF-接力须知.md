# BOSS · 给下一位接力的开发者

> 这份文档是给你省时间的。它只写**从别处看不出来**的东西：哪些结论是拿源码核过的、
> 哪些坑已经踩过并修掉了、哪些地方看着可疑但其实别去动。
> 工程背景与设计推演看 `docs/BOSS-su-方案解析与设计.md`，这份是操作手册。

---

## 1. 你现在接的是什么

| 部分 | 状态 | 说明 |
|---|---|---|
| `bossd` 守护进程 | ✅ 可用 | 抽象套接字监听、`SO_PEERCRED` 鉴权、fork + pty + 切身份、审计日志 |
| `su` 客户端 | ✅ 可用 | `-c / -s / -u / -g / -l / -p / --context`，退出码独立回传 |
| 策略引擎 | ✅ 可用 | 纯文本 `policy.conf`，uid / app / user 三级规则，默认拒绝 |
| payload（veritpath 用） | ✅ 已实测注入 | `payload-check` / `inject` / `verify` 全过 |
| CI / Release | ✅ 已配好 | 见第 8 节 |
| **2SI 设备自动拉起** | ❌ **没做** | v0.2 的 init 接管，见第 5 节。**这是当前最大缺口** |
| SELinux 正式策略 | ❌ 没做 | 依赖任务 4，接口已收敛在一个函数 |
| BOSS 前端授权 | ❌ 没做 | 依赖任务 6，接口是 `policy_decide()` |

**一句话**：su 的"内核与用户态链路"已经闭环，但它在 Android 10+ 主流机型上**还不会自己起来**。
接手后第一优先级是第 5 节，不是打磨 su 本身。

---

## 2. 开工前必须知道的三件事

### 2.1 veritpath 只管"放哪"，不管"怎么跑"
它明确声明不提供任何 su 实现。它给你的保证只有：判断布局、把文件放进**正确的 ramdisk 段**、写 rc 钩子、重建镜像。
所以**不要把 su 的行为假设建立在 ramdisk 上**。

### 2.2 ramdisk 里的 rc 在主流机型上不会被执行
Android 10+ 两段式 init（2SI）第一阶段结束会 `SwitchRoot`：把 `/` 下的挂载递归移动到 `/system` 并 chroot。
ramdisk 从此消失，第二阶段 init 只解析 `/system/etc/init/hw/init.rc`。

这不是推测，是两处源码都能对上：
- AOSP `init.cpp` 的 `LoadBootScripts()`：`bootscript` 为空时固定解析 `/system/etc/init/hw/init.rc`
- Magisk `native/src/init/twostage.rs`：注释写明"第二阶段 init 永远是 `/system/bin/init`"，并用 SwitchRoot 做劫持

**`payload/init.boss.rc` 因此只在 ramdisk 存活的布局（非 2SI、vendor_boot 布局）上生效。**
veritpath 的 `plan` 自己会打这行提示：`system-as-root: ramdisk files vanish after init switches root to /system`。

### 2.3 改 `/system` 是红线
BOSS 主打隐蔽与日用，任何往 `/system` 落文件的方案（改 init.rc、塞 `/system/bin/su`）都违背目标。
Magisk 能做到 `/system` 零落盘，我们也能——第 5 节给的劫持方案就是零落盘的。

---

## 3. 不能破坏的五条架构红线

1. **daemon 是唯一的特权实体**。su 客户端永远无特权。别为了"方便"给客户端加 setuid 或直接 fork——历史上 su 的漏洞几乎全出在这条上。
2. **身份只信内核**。`SO_PEERCRED` 拿 uid，不接受客户端自报。
3. **客户端消失必须收掉子进程**（`daemon.c` 的 SIGTERM→SIGKILL 收尾）。否则会残留孤儿 root shell。
4. **不写 `/system`**，不在 `/dev/socket` 留节点（用的是抽象命名空间 `@bossd`）。
5. **协议第一步必须是 SCM_RIGHTS 握手**。任何新增的连法都要先走 `boss_send_handshake()`。理由见第 4.1 条。

---

## 4. 已经踩过并修掉的坑（别再踩一遍）

### 4.1 握手顺序错位
**现象**：`boss ping` 永远超时，其它命令时好时坏。
**原因**：daemon 建连后第一件事是 `recvmsg` 收 SCM_RIGHTS；客户端如果不先送这个 fd，`recvmsg` 会把**请求体的第一个字节**当成握手数据吃掉，后面整条流全部错位。
**修法**：所有连接（**包括探活**）第一步都调 `boss_send_handshake()`（`client.c` / `main.c` 里已统一）。

### 4.2 stdin EOF 触发 shutdown，输出被截断
**现象**：`su -c 'cmd'` 偶发输出不全。
**原因**：客户端读到 stdin EOF 后 `shutdown(sock, SHUT_WR)`，daemon 判"客户端消失"→ 杀掉子进程 → 剩下的输出没了。
**修法**：客户端 stdin 结束**只置标志位，不关 socket**（`client.c` 里有注释）。daemon 端判断"子进程结束"只看 pty master。

### 4.3 manifest 的 `symlink` 不是"给这个文件建别名"
`files[].symlink` 的语义是**额外创建一个指向 dest 的符号链接**。我最初写成 `dest:/boss, symlink:/su`，
结果是 ramdisk 里 `/boss` 变成了指向 `/su` 的软链（`boss -> /su`），而 `/su` 根本不存在——`verify` 直接报 `/boss MISSING`。
**修法**：payload 里不要用它。要兼容老 app 的 `/su` 路径，等 BOSS 前端按需挂载，别在注入阶段造。

### 4.4 静态二进制里 dlopen 不可用
Android（bionic）与 glibc 的**静态**链接都不支持 `dlopen`。
原实现只用 `dlopen("libselinux.so")` 切域，静态产物上必然失效。
**修法**：`apply_selinux_context()` 改成两级——先 `dlopen`，失败则直接写 `/proc/self/attr/exec`（`setexeccon` 的底层就是这个接口）。
用 `-DBOSS_NO_DLOPEN` 可彻底关掉 dlopen 路径（`make static` 已这么做）。

### 4.5 Android 静态二进制的两个加载门槛（CI 真机翻过车）
编译通过 ≠ 能跑。Bionic 会拒绝：
- **非 PIE**（Android 5+ 直接不加载）
- **PT_TLS 对齐 < 64**（NDK 的 lld 对静态二进制只给 8，设备上 `TLS segment is underaligned` 直接 abort）

**最坑的一点：`-static -fPIE -pie` 并不会得到静态 PIE。**
链接器见到 `-static` 就把 PIE 关掉了，产出的是 `ET_EXEC`——CMake/Makefile 里最常见的写法，也是最容易骗过 review 的写法。真正的静态 PIE 只有 `-static-pie`。

所以 `build/build-ndk.sh` **不赌某个标志组合**：它按顺序尝试 `-static-pie` → `-static -fPIE -pie` → `-static -fPIE -pie -Wl,-pie` → `-fPIE -pie`（动态兜底），每个候选都先 `elf_fix.py` 修 TLS 再用 `--check` 验收，取第一个产出 `ET_DYN` 的，并打印最终选择。全失败就报错，不交半成品。

**别删这个校验步骤。** 它在 CI 上真的拦下过一批全部 `ET_EXEC` 的产物——那批二进制编译、链接、上传全都"成功"，只有 `--check` 说它们上机起不来。

顺带两个点：
- 静态候选带 `-DBOSS_NO_DLOPEN`：静态二进制没有 `dlopen`，SELinux 切换走 `/proc/self/attr/exec`（见 4.4）。动态兜底才允许 `dlopen`。
- Android 15+ 有 16KB 页设备，脚本会尝试加 `-z max-page-size=16384`（链接器不支持就跳过）。

如果 CI 的 android job 红了，先跑它自带的「失败诊断」步骤——会把编译器路径和每个候选的 `e_type` 打出来，比从头查快得多。

### 4.6 `make test` 和 `make static` 曾共用同一个产物名
后果：跑着"另一个 `BOSS_DIR` 的二进制"而不自知——日志写去 `/data/adb/boss`，测试却在查 `/tmp/boss-test`，只有日志那一项诡异地失败。
**已修**：静态产物是 `build/boss-static`。**新增构建目标时务必用独立产物名。**

### 4.7 非 root 环境下 `setuid(0)` 必然失败
GitHub runner 是普通用户，冒烟测试会在"提权"这步全军覆没。
**修法**：daemon 在 `geteuid() != 0` 时把目标身份降级为自身（`daemon.c` 有注释），这样除提权外的整条链路仍被真实验证。
真机上 daemon 永远是 root，这条分支不会进入。

---

## 5. 你的第一件事：v0.2 init 接管

目标：**让 bossd 在 2SI 设备（Android 10+ 绝大多数机型）上，post-fs-data 阶段必然起来，且 `/system` 一个字节不改。**

`src/bossinit.c` 已经把两个入口铺好了，只差真实逻辑：

### 5.1 `boss init hijack-prep`（第一阶段，切根前执行）
原理（与 Magisk 同源，利用 init 自己的 SwitchRoot）：

```
切根前（我们还在 ramdisk 的 /）:
  mkdir /storage/self
  /storage/self/primary -> /system/system/bin/init     (符号链接)
  mount --bind <bossinit> /sdcard

init 执行 SwitchRoot:
  把 / 下的挂载递归移动到 /system
  → /sdcard 变成 /system/sdcard
  → /system/sdcard 是符号链接 → /storage/self/primary → /system/system/bin/init
  → chroot 后即 /system/bin/init

结果：第二阶段 init 变成我们的 bossinit，全程没写 /system
```

边界情况（都要处理）：
- **rootfs 可写** → 退化成 hexpatch：把 `/init` 里的字符串 `/system/bin/init` 原地替换成 `/data/adb/boss/boss`（长度必须对齐，Magisk 用的是 `/data/magiskinit`）。
- **用 2SI 但不切根的机型**（魅族等）→ 检查 ramdisk 里是否已有 `/sdcard`，有就走 hexpatch。
- **三星 RKP** → 从 rootfs bind mount 自己（`/sdcard` → `/sdcard`），失败再退 `/data/...`。
- **兜底**：`bossinit` 找不到真实 init 时**绝不 exec 自己**（会死循环变砖），直接放弃（`bossinit.c` 里已有这条保护，别删）。

### 5.2 `boss init stage2`（被当成第二阶段 init 执行时）
1. `boss_install()`：把自己复制到 `/data/adb/boss/boss`（持久分区，ramdisk 没了也在）
2. `start_daemon()`：拉起 bossd（内部先探活，幂等）
3. `execv("/init.real", argv)`：把执行权还给真实 init

**注意 `cmd_stage2` 现在的 argv 转发逻辑**：它会把 `argv[2..]` 传给真实 init。2SI 下 init 会以 `second_stage` / `selinux_setup` 之类的参数调我们，转发时必须**原样保留**，丢参数会导致 init 走错阶段。

### 5.3 另一条备选路：`androidboot.init_rc`
`ro.boot.init_rc`（来自 cmdline）可以整体改写 boot script，veritpath 的 `cmdline_append` 能写它。
但路径必须活到第二阶段 → 只能指向 `/data` 下的文件 → 依赖 `/data` 解密后可用，且部分厂商校验 cmdline。**仅当劫持方案在某机型上失效时再考虑。**

### 5.4 验证标准（真机）
- [ ] 冷启动后 `boss ping` 返回 up（说明 post-fs-data 起来过）
- [ ] `/system` 的 hash 与刷机前一致（`find /system -type f -exec sha256sum` 对比）
- [ ] `getprop` 里没有我们引入的新属性
- [ ] 进 recovery 再重启仍能正常起（验证没有破坏启动链）

---

## 6. 交给任务 4（SELinux）的接口

su 只依赖三个能力，其它一律沿用现有 domain，不要扩大：

1. `bossd` 自身的运行域（v0.1 暂用 `u:r:init:s0`，调试期可 cmdline 加 `androidboot.selinux=permissive`）
2. `bossd` → 目标域的 transition 许可（`setexeccon` / `/proc/self/attr/exec` 要能用）
3. `/data/adb/boss` 下文件的 type 与 `file_contexts` 标签（manifest 里目前是 `u:object_r:rootfs:s0`，正式 type 出来后替换即可）

代码侧切换点已收敛成 `apply_selinux_context()`，策略成熟后**不用动调用方**。

---

## 7. 交给任务 6（BOSS 客户端）的接口

- **授权决策**：改 `policy_decide()`（现在读文本文件）。加弹窗/超时/通知时保持"返回 allow / deny / prompt"三元语义。
- **运行时状态**：`boss ping` 已可探活；`/data/adb/boss/boss.log` 是审计源。
- **协议扩展**：`struct boss_request` 末尾加字段时**必须同时升 `BOSS_PROTO_VER`**，否则新旧版本二进制会静默错位。
- **v2 协议待办**：参数数组透传（`arg_len` 已预留但没用）、stdin-EOF 显式控制消息（解决第 4.2 遗留的 `su -c 'cat'` 挂住问题）。

---

## 8. 任务交接：下一位做什么

按计划表，任务3 是「其他关键文件以及重要组件开发」（resetprop / 模块挂载 /
boot 脚本执行器 / sepolicy 工具 / busybox 工具集 / applet 分发）。
**已单独写了 `docs/HANDOFF-TASK3-关键组件.md`**，那位同学应该先读那份。

这里只留三条跨任务的边界，避免两边打架：

1. **init 接管（2SI 劫持）归 su 侧 v0.2，不归任务3**。入口已在 `src/bossinit.c`
   的 `stage2` / `hijack-prep`。任务3 做的是"执行权拿到之后跑什么"，不是劫持本身。
2. **任务3 的模块挂载与 boot 脚本依赖启动链**。在 2SI 设备上，v0.2 落地前它们
   根本不会被触发——表现为"功能写完了但一次都没跑"，不是 bug。
   顺序上应先做能用 `su -c` 手动验证的组件（resetprop / applet / 工具集 / sepolicy 工具）。
3. **ramdisk 体积是硬约束**。payload 里只放 `boss` 一个二进制；
   busybox 这类大件走 `/data`，由 App 释放或随 Release 分发。塞进 ramdisk 可能撑爆分区。

## 9. CI 与出包

```bash
bash tools/smoke_test.sh     # 本地先跑这个，8 组端到端检查
git tag v0.1.0 && git push origin v0.1.0   # 打 tag 自动出 Release
```

四个 job，都只依赖 GitHub 官方 action：

| job | 作用 | 失败意味着 |
|---|---|---|
| `smoke` | 构建 + 端到端检查 | 逻辑回归 |
| `strict` | c99~gnu17 逐个 `-Werror` + 静态构建 + clang 复核 | 可移植性/头文件问题 |
| `payload` | clone 上游 veritpath，造合成镜像真的注入并 verify | manifest / rc 钩子写错 |
| `android` | NDK 四 ABI + 候选链接验收 + Bionic 加载校验 | 产物上机就起不来 |

`android` 是最容易红的一个（工具链差异大），但它**红了就是真的有问题**——
不要为了让 CI 变绿就去放宽校验，那等于把一个上机就 abort 的二进制发出去。

**Release 的一个坑（已经踩过）**：`release` job 以前只有 `download-artifact`，
没有 `checkout`，于是 `gh` 报 `fatal: not a git repository`。
`gh` 靠工作目录里的 `.git` 推断目标仓库——artifact 是从别的 job 下载的，
它压根不关心产物从哪来，**只认 `.git`**。所以发布 job 必须有 `checkout`。
已修，并在发布前加了一步自检（打印 TAG / 仓库 / remote、校验 `out` 非空）。

`payload` job 用的是合成镜像（上游 `tests/imgkit.py`），验的是**注入链路**，不代表真机可启动。
上游地址可用仓库变量 `VP_REPO` 指向镜像。

---

## 10. 拿到真机后按这个清单验

```
[ ] 各布局分别验：init_boot（13+ GKI）/ vendor_boot（11-12 GKI 1.0）/ boot（≤12 非 GKI）
[ ] veritpath analyze 的 target 字段确认注入对象，别打错分区（GKI 机器 boot.img 只有内核）
[ ] 多段 ramdisk：确认 payload 在 main 段，不在 first_stage_ramdisk（必要时 --segment）
[ ] 冷启动后 boss ping
[ ] su -c id → uid 0；su -c 'exit 7' → 退出码 7
[ ] SELinux enforcing 下 --context 切换是否生效
[ ] 日志开关：policy.conf 的 log = 0 后确认不再产生写入
[ ] 卸载：刷回原厂 init_boot 能正常开机（自救路径必须留）
```

---

## 11. 别浪费时间的地方

- **别去给 su 客户端加特权**。第 3.1 条。
- **别做 macOS / Windows 支持**。IPC 依赖 Linux 抽象命名空间（`sun_path[0]='\0'`），`SO_PEERCRED` 也是 Linux 专有，改的成本与收益不成比例。
- **别在注入阶段造 `/su`、`/system/bin/su`**。见第 4.3 条；兼容性留给前端按需挂载。
- **别用 sqlite 重写策略**（现在）。`policy_load` / `policy_decide` 接口稳定，等前端稳定了再换存储，调用方一行不用改。
- **别信"编译通过就行"**。第 4.5 条那两个门槛编译期完全不报。
