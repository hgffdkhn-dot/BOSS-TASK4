# BOSS · su + 关键组件（任务 2 / 任务 3）

Magisk 式 root 管理器 BOSS 的 su 子系统与关键组件：主打**隐蔽、日用、实用**。
镜像注入交给上游的 veritpath。

- 方案解析与设计说明：`docs/BOSS-su-方案解析与设计.md`
- **接力开发者先看**：`docs/HANDOFF-接力须知.md`（踩过的坑、架构红线、v0.2 实施手册）
- 任务3（关键组件）的**任务书**：`docs/HANDOFF-TASK3-关键组件.md`
- 任务3 的**交付说明**：`docs/TASK3-组件交付与接力.md`（已落地什么、怎么验、给下游的接口）
- 给任务4 的 SELinux 权限清单：`docs/SELINUX-REQUIREMENTS.md`
- 注入契约与真机流程：见文档第 8 节

## 目录

```
src/        boss.h / main.c / daemon.c / client.c / policy.c / pty.c / util.c / bossinit.c
            applet.c（分发）/ resetprop.c（属性改写）/ module.c（模块挂载）
            scripts.c（boot 脚本）/ boot.c（开机编排）/ sepolicy.c（策略工具）/ sh.c（工具集）
payload/    manifest.json + init.boss.rc（veritpath payload）
build/      build-ndk.sh（NDK 交叉编译 + 组装 payload）
tools/      smoke_test.sh（冒烟测试）、mkprop.py（造合成属性区）、elf_fix.py（修 PT_TLS 对齐）
.github/    ci.yml / release.yml
docs/       方案解析与设计、HANDOFF 接力须知、TASK3 交付说明、SELINUX 需求清单
```

## CI

两组工作流：

- `ci.yml`（4 个 job）：冒烟端到端（28 项）、多 `-std` `-Werror` 严格编译、
  payload 用 veritpath 实际注入校验、Android 四 ABI 交叉编译 + Bionic 加载校验
- `components.yml`（2 个 job）：任务3 组件的**深度验收** + 属性区布局断言自检

```bash
bash tools/smoke_test.sh        # 端到端主链路，28 项
bash tools/component_test.sh    # 任务3 边界与语义细节，34 项（root 与非 root 都过）
```

```bash
git tag v0.1.0 && git push origin v0.1.0    # 打 tag 自动出 Release（含 payload zip）
```

## 快速开始（主机验证，无需真机）

```bash
make test                     # 编译，运行时目录指向 /tmp/boss-test
bash tools/smoke_test.sh      # 28 项冒烟测试，应全部 PASS（root 与非 root 都过）
make static                   # 静态 PIE 产物 build/boss-static
./build/boss daemon           # 起 daemon（后台）
./build/boss su -c id         # 走一遍授权链路
./build/boss policy show      # 看策略
```

## 交叉编译（Android）

```bash
bash build/build-ndk.sh                  # -> dist/boss-android-{arm64,arm,x86_64,x86}
MAKE_PAYLOAD=1 bash build/build-ndk.sh   # 顺带生成 build/payload/ 与 dist/boss-payload.zip
WITH_SEPOL=1 bash build/build-ndk.sh     # 内置 libsepol（早期注入需要，先跑 vendor-sepol.sh）
```

> ⚠️ 这个脚本在 `build/` 下，而 `build/` 同时是构建产物目录。
> **别把 `build/` 整目录写进 `.gitignore`**——脚本会永远提交不上去，
> CI 第一步 `bash build/build-ndk.sh` 就 `No such file or directory`，
> 而本地一直是绿的（本地工作区里那个文件好端端躺着）。
> 这个坑真实发生过。现在的处理是 `build/*` + `!build/build-ndk.sh`。

`build-ndk.sh` 不赌某一个链接标志组合：`-static -fPIE -pie` 并**不会**得到
静态 PIE（链接器见到 `-static` 就关掉 PIE，产出 `ET_EXEC`）。它按候选顺序试
`-static-pie` → `-static -fPIE -pie` → `-static -fPIE -pie -Wl,-pie` → `-fPIE -pie`，
每个候选都先 `tools/elf_fix.py` 修 PT_TLS 对齐再 `--check` 验收，取第一个产出
`ET_DYN` 的。编译通过 ≠ 上机能跑，这道校验不能删。

## 注入（真机）

```bash
veritpath payload-check build/payload
veritpath inject --init-boot init_boot.img -p build/payload -o out/
veritpath verify out/init_boot.veritpath.img -p build/payload   # 非零退出就别刷
fastboot flash init_boot out/init_boot.veritpath.img
```

## 运行时布局

```
/data/adb/boss/boss                 bossd 与 su 本体（单二进制多入口）
/data/adb/boss/policy.conf          授权策略
/data/adb/boss/boss.log             日志（可关）
/data/adb/boss/bin/                 busybox 与 applet symlink（App 释放，不进 ramdisk）
/data/adb/boss/modules/<id>/        模块（module.prop / system / system.prop / sepolicy.rule …）
/data/adb/boss/post-fs-data.d/      阻塞阶段脚本
/data/adb/boss/service.d/           late_start 脚本（绝大多数脚本的默认选择）
/data/adb/boss/boot-completed.d/    开机完成后的脚本
/data/adb/boss/persist.props        persist 属性快照（每次开机重放）
@bossd                              AF_UNIX 抽象套接字（文件系统无节点）
```

## 关键组件常用命令

```bash
boss --list                         列出所有组件
boss resetprop ro.debuggable 1      改只读属性（默认走 property_service，会触发 rc 事件）
boss resetprop -n ro.foo bar        直写属性区，不触发事件（post-fs-data 阶段必用）
boss resetprop --delete ro.foo      删除属性
boss resetprop -p --delete persist.foo   删除 persist 属性且重启后不恢复
boss module list | plan | mount     模块列表 / 挂载计划（dry run）/ 真挂载
boss module dump props|rules        汇总模块的 system.prop / sepolicy.rule
boss script post-fs-data|service|boot-completed   按阶段跑脚本
boss boot post-fs-data|service|completed          开机编排（顺序已固定，rc 只调它）
boss sh                             standalone busybox shell（脚本兼容性）
boss sepolicy check|apply|info      SELinux 规则规范化 / 应用 / 定位策略文件
```

## 常用命令

```bash
boss su -c 'id'                 请求 root
boss su -s /system/bin/sh       指定 shell
boss su -u 0 -g 0 -c 'cmd'      指定目标 uid/gid
boss policy add uid 2000 allow  允许 adb shell
boss policy set default deny    默认拒绝
boss policy set log 0           关日志（日用）
boss init install | start       落地/拉起（供 rc 调用）
boss ping                       探活
```

## 当前状态（对应计划表）

| 计划项 | 状态 |
|---|---|
| 1. boot 分析与注入工具 | ✅ 上游 veritpath 已完成 |
| 2. su 打造 | ✅ v0.1 已交付；v0.2（2SI init 接管）待做 |
| 3. 其他关键文件与重要组件 | ✅ 已交付（resetprop / 模块挂载 / boot 脚本 / sepolicy 工具 / 工具集 / 开机编排） |
| 4. SELinux 解决 | ⬜ 工具已就绪（`boss sepolicy`），策略内容待做 |
| 5. 无修改系统逻辑与特典逻辑 | ⬜ 弹药已就绪（resetprop + 挂载覆盖） |
| 6. BOSS 客户端与对接修补 | ⬜ |
| 7. 长期开发 | ⬜ |

已知最大限制：**v0.1 在两段式 init（Android 10+）设备上不会自动拉起**，
因为 ramdisk 会在切根后消失；必须等 v0.2 的 init 接管。详见设计文档第 2、7 节。
