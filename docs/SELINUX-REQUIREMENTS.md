# BOSS · SELinux 需求清单（给任务4）

> 任务3 只提供**工具**（`boss sepolicy`），不定义策略内容。
> 这份清单回答的是：BOSS 的各个组件到底需要哪些权限，你在写规则时要覆盖哪些。
> 随代码维护——组件新增能力时，请同步更新这里。

---

## 1. 需要的权限（按组件）

### 1.1 resetprop（属性改写）
- 对 `/dev/__properties__` 下**各区域文件**的读写（`open` + `mmap` PROT_READ|PROT_WRITE）
- 属性文件的 type 通常是 `u:object_r:properties_data_file:s0` 一类，
  注意 8.0+ 是多区域，不能只给一个文件
- 对 `/data/property/persistent_properties`（protobuf 库）与 `/data/property/<name>` 的读写
- 对 BOSS 自己的 persist 快照 `/data/adb/boss/persist.props` 的读写

### 1.2 模块挂载（Magic Mount）
- `mount` / `remount`：tmpfs 挂载与 bind mount
- 对 `/data/adb/boss/tmp/mirror/**` 的读写（镜像目录，还原原文件用）
- 对 `/system`、`/vendor`、`/product`、`/system_ext`、`/odm` 等分区下
  被覆盖目录的挂载权限
- 对模块目录 `/data/adb/boss/modules/**` 的读取（挂载源）

### 1.3 boot 脚本执行器
- fork / exec 用户脚本（脚本通常跑在 `u:r:init:s0` 或我们自己的 domain）
- 对 `/data/adb/boss/{post-fs-data.d,service.d,boot-completed.d}/*.sh` 的执行
- 写审计日志 `/data/adb/boss/boss.log`

### 1.4 sepolicy 工具
- 读 `/sys/fs/selinux/policy`、`/sepolicy`、vendor 预编译策略
- 写回或让系统加载 patched policy
- 执行注入引擎（`/data/adb/boss/bin/magiskpolicy` 等）

### 1.5 守护进程（任务2 已有，这里补齐与任务3 相关的部分）
- 抽象命名空间套接字 `@bossd` 的监听与连接（**不落 `/dev/socket`**，这是隐蔽红线）
- `SO_PEERCRED` 取对端 uid（内核提供，不需要额外 allow）
- `setexeccon` / 写 `/proc/self/attr/exec` 做域切换
- 对 `/data/adb/boss/**` 全部内容的访问

---

## 2. 建议的模型（Magisk 的成熟做法，可直接借鉴）

```
# 1. BOSS 自己的域，调试期设 permissive
type boss, domain;
permissive boss;

# 2.  unrestricted file context：允许被所有 domain 访问
type boss_file, file_type;

# 3. Android 8.0+ 收紧模型
#    二进制标 boss_exec；允许的 su client 执行它时 type_transition 到 boss_client
type boss_exec, exec_type, file_type;
type boss_client, domain;
#    只允许 boss 域给文件标 boss_exec
#    禁止直连 daemon socket，唯一入口是 boss_client 进程
```

要点：
- **daemon 是唯一的特权实体**，su 客户端永远无特权（不该因为"方便"而放宽）
- 身份只信内核 `SO_PEERCRED`，不接受客户端自报——这条不该被策略绕过
- 不在 `/dev/socket` 留节点

---

## 3. 调试期怎么过

任务4 完成前，用 `androidboot.selinux=permissive` 或 `boss sepolicy` 的
permissive 路径把功能跑通：

```bash
boss sepolicy check /data/adb/boss/modules/<id>/sepolicy.rule   # 看规范化结果
boss sepolicy apply /data/adb/boss/modules/<id>/sepolicy.rule   # 应用（需引擎）
```

**没有注入引擎时**，`apply` 会把规则写进 `/data/adb/boss/sepolicy.pending`
并返回 2——这是明确的"没做成"，不是成功。你在接入引擎后可以一次性消费这个队列。

---

## 4. 验收（enforcing 下）

```
[ ] resetprop 能改 ro.* 并读回新值
[ ] resetprop -n 不触发任何 on property: 事件
[ ] 模块挂载在 enforcing 下成功（不再依赖 permissive）
[ ] post-fs-data 阶段开机不卡 40 秒
[ ] bossd 仍在跑（boss ping 返回 up）
[ ] /system 的 hash 与刷机前一致
```
