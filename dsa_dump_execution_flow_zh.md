# CRIU 当前 DSA Dump 执行流说明（基于现有代码语义）

本文严格对应当前代码实现，说明 DSA 在 dump 内存阶段的接入方式、关键逻辑与失败/回退语义。

## 1. 设计边界与总体结论

当前实现是“同步批处理”模型，而不是“跨命令异步会话”模型：

- 每个 DSA 批次都在一次 RPC 内完成：提交 + 轮询完成 + 返回结果。
- 主机侧在收到成功结果后，才把共享缓冲区数据写入 page-pipe。
- 未引入跨命令的 in-flight 状态持久化，不存在“上一命令提交、下一命令再收割”的会话状态机。

这保证了与 CRIU 原有 `drain_pages -> xfer_pages` 语义兼容：

- `drain_pages` 负责把页数据放入 page-pipe。
- `xfer_pages` 负责把 page-pipe 写入镜像。

## 2. 入口与命令扩展

### 2.1 parasite 命令号扩展

- 在 `criu/include/parasite.h` 中新增命令：
  - `PARASITE_CMD_DSA_DUMP_PAGES`

### 2.2 DSA 参数结构

- 在 `criu/include/parasite.h` 定义：
  - `struct dsa_dump_descriptor`
  - `struct parasite_dsa_dump_pages_args`
  - `pdpa_descriptors()`
- 关键字段分两类：
  - 输入：共享缓冲区信息、描述符数量、WQ 数量、WQ 策略、FD/路径模式
  - 输出：`op_ret`、`total_copied`、`completed_count`、`failed_idx`、`failed_status`、`new_buf_offset`

### 2.3 host 调用接口

- 在 `criu/include/parasite-syscall.h` 暴露：
  - `parasite_dsa_dump_pages_seized(...)`

## 3. dump 主流程中的接入点

### 3.1 原始主流程未改动的核心框架

`criu/mem.c` 中，`__parasite_dump_pages_seized()` 仍是主流程：

1. Step 1 生成 pagemap / iovs
2. Step 2 `drain_pages(...)`
3. Step 3 `xfer_pages(...)`
4. Step 4 清理

DSA 只接入 Step 2 的 `drain_pages(...)`，未改变 Step 3 行为。

### 3.2 drain_pages 的分流逻辑

`drain_pages(...)` 的逻辑为：

1. 先尝试 `drain_pages_dsa(...)`
2. 若返回 0：DSA 路径成功，直接返回
3. 若返回 < 0：认为已选择 DSA 且失败，直接失败返回
4. 若返回 1：认为 DSA 不可用，回退到 legacy `PARASITE_CMD_DUMPPAGES`

这与注释语义一致：

- `0` = DSA 成功
- `1` = DSA 不可用，走 legacy
- `<0` = DSA 失败

## 4. host 侧 DSA 逻辑（criu/mem.c）

函数：`drain_pages_dsa(...)`

### 4.1 开关与资源发现

- 开关：`CRIU_DSA_DUMP`，`>0` 才启用 DSA。
- 枚举 `/dev/dsa/wq*`，最多 `DSA_DUMP_MAX_WQ=16` 个，逐个 `open(O_RDWR|O_CLOEXEC)`。

若未启用或无可用 WQ，返回 `1`（回退 legacy）。

### 4.2 共享缓冲区

- 共享缓冲区大小固定：`DSA_SHARED_BUF_SIZE = 2MB`。
- 优先 `memfd_create(MFD_HUGETLB|MFD_HUGE_2MB)`，失败则回退普通 `memfd_create(MFD_CLOEXEC)`。
- `ftruncate` 到 2MB 后 `mmap(MAP_SHARED)`。

缓冲区用于 parasite 把源页 copy 到共享区，host 再把共享区内容写入 page-pipe 写端。

### 4.3 批构建（按 iov 切片）

对每个 `page_pipe_buf`：

- 从 `pargs_iovs(args)+args->off` 读取源 iov。
- 通过 `seg_off/seg_pos` 支持跨 iov 连续推进。
- 每批最多收集 `batch_limit` 个描述符；并受共享缓冲区剩余空间限制。
- 单描述符长度同时受 `UINT_MAX` 限制。

每批组织为可变长参数块：

- `struct parasite_dsa_dump_pages_args`
- 后接 `nr_descriptors` 个 `struct dsa_dump_descriptor`

### 4.4 每批执行与校验

每批调用 `parasite_dsa_dump_pages_seized(...)` 后，做严格校验：

- `dargs->total_copied == batch_bytes`
- `dargs->new_buf_offset == batch_bytes`

校验通过才将共享区前 `batch_bytes` 字节写入 `ppb->p[1]`。

在每批 RPC 之前，host 还支持可选预热：

- 当 `CRIU_DSA_POPULATE_READ>0` 时，host 尝试用
  `process_madvise(..., MADV_POPULATE_READ, ...)` 预触发本批源地址区间。
- 该步骤是“尽力而为”，失败不改变主流程语义：不会中止 DSA 批次，也不会改变回退边界。
- 该步骤不替代 parasite 侧预触页逻辑，只是额外优化手段。

### 4.5 自适应批大小（保持同步语义）

新增的是“批大小自适应”，不是异步会话：

- 统计每批 RPC 耗时（`CLOCK_MONOTONIC`）。
- 参数：
  - `CRIU_DSA_BATCH_TARGET_US`（默认 2000us）
  - `CRIU_DSA_BATCH_MIN_DESC`（默认 8）
- 规则：
  - `rpc_us > target`：`batch_limit` 减半（不低于最小值）
  - `rpc_us < target/2`：`batch_limit` 翻倍（不超过 128）

这个调整只影响“下一批描述符个数上限”，不改变每批必须完成后再写 pipe 的语义。

### 4.6 失败与回退边界

函数内用 `wrote_data` 记录是否已向 page-pipe 写入数据：

- 若 `ret < 0 && !wrote_data`：返回 `1`，允许上层回退 legacy。
- 其他失败：返回 `<0`，不再回退。

这避免“部分 DSA 数据已写入后再切 legacy”导致语义混乱。

## 5. host -> parasite RPC 与 FD 传递（criu/parasite-syscall.c）

函数：`parasite_dsa_dump_pages_seized(...)`

### 5.1 入参与共享参数区

- 校验 `wq_count`、`nr_descriptors`。
- `parasite_ensure_args_size()` 保证 parasite 参数区可容纳“头+描述符数组”。
- 使用 `compel_parasite_args_s()` 拿到参数区，复制头与描述符数组。

### 5.2 FD 模式的调用顺序

当 `use_wq_fd=1` 时，顺序为：

1. `compel_rpc_call(PARASITE_CMD_DSA_DUMP_PAGES)`
2. 可选发送 `shared_buf_fd`
3. 发送各个 `wq_fd`
4. `compel_rpc_sync(...)` 等待完成

### 5.3 异常时保持 RPC 通道一致

若发送 FD 失败，代码会先尝试 `compel_rpc_sync(...)` 再返回，避免 RPC 状态错位。

### 5.4 返回值语义

- 先看 RPC 传输层返回。
- 成功后再以 `args->op_ret` 作为本次 DSA 操作结果返回。

## 6. parasite 侧 DSA 执行（criu/pie/parasite.c）

### 6.1 命令分发

`parasite_daemon_cmd(...)` 增加：

- `PARASITE_CMD_DSA_DUMP_PAGES -> parasite_dsa_dump_pages(...)`

### 6.2 输入校验与资源准备

`parasite_dsa_dump_pages(...)` 会：

- 校验共享缓冲区参数、描述符数量、WQ 数量、写偏移边界。
- 如果 `use_shared_buf_fd=1`，先 `recv_fd` 再 `mmap(shared)`。
- 如果 `use_wq_fd=1`，从 RPC socket 逐个 `recv_fd`；否则按路径 `sys_open`。
- 为每个 WQ 尝试映射 portal，失败则退化用 `write()` 提交。

### 6.3 描述符准备

对每个描述符：

- 检查 `buf_write_offset + copy_len <= shared_buf_size`。
- 对源地址做预触页。
- 构建 `dsa_hw_desc`（`MEMMOVE` + completion record）。
- 目标地址是共享缓冲区对应偏移。

### 6.4 负载均衡策略

支持两种策略：

- `RR`：轮转分配
- `LPT`：按 `copy_len` 从大到小排序后，分配给当前累计负载最小的 WQ

当前 host 默认下发 `LPT`。

### 6.5 提交与轮询

- 提交阶段：
  - 有 portal 用 `enqcmd`
  - 无 portal 用 `write()`
  - 都有重试上限 `DSA_MAX_ENQ_RETRY`
- 轮询阶段：
  - 仅按 `submitted_idx[]` 轮询已提交描述符
  - 避免“按原索引轮询导致未提交项被误等”的逻辑错误
- 成功条件：所有已提交描述符完成且 completion 状态成功。

### 6.6 输出结果

成功时返回：

- `op_ret=0`
- `total_copied=total_size`
- `new_buf_offset=buf_write_offset`

失败时带上：

- `failed_idx`
- `failed_status`（DSA completion code）
- `op_ret`（负值错误码）

### 6.7 清理

统一清理：portal unmap、WQ fd 关闭、共享缓冲区 unmap/close。

## 7. 与 legacy 路径的语义关系

legacy 路径（`PARASITE_CMD_DUMPPAGES + send pipe fd + sync`）仍完整保留。

DSA 路径只是 `drain_pages` 的前置尝试分支，满足下列约束：

- DSA 完全成功：不走 legacy
- DSA 不可用：回退 legacy
- DSA 已进入并发生致命错误：直接失败，避免混合语义

因此，现状是“可选增强 + 可回退 + 不破坏原 dump 写像链路”。

## 8. 现状不包含的能力（重要）

当前代码没有实现以下机制：

- 跨命令异步会话（submit 一批后先返回，后续 poll）
- 多批 in-flight 生命周期管理
- slot 级复用协议

也就是说，当前“执行流切换”仍在“批次边界”发生，而不是“批次内部异步切换”。

## 9. 关键环境变量与默认值

- `CRIU_DSA_DUMP`
  - `>0` 启用 DSA dump 路径
- `CRIU_DSA_BATCH_TARGET_US`
  - 默认 `2000`
  - 自适应批大小目标耗时（微秒）
- `CRIU_DSA_BATCH_MIN_DESC`
  - 默认 `8`
  - 自适应批大小最小描述符个数
- `CRIU_DSA_POPULATE_READ`
  - 默认关闭
  - `>0` 时启用 host 侧 `process_madvise(MADV_POPULATE_READ)` 批前预热

## 10. 一句话总结

当前 DSA 集成在 CRIU dump 的 Step 2（drain_pages）中，以“同步批处理 + 共享 memfd + parasite 内部多 WQ 调度（默认 LPT）”完成页拷贝，并通过严格校验与受控回退机制保持与原有 dump 语义一致。

## 11. workspace 快照并行路径（新增）

本分支在 dump 主流程内新增了可选的 btrfs workspace 快照能力，核心目标是：

- 不增加 frozen window 的阻塞等待
- 快照失败时严格失败（不做静默降级）
- 不使用 root overlay/pivot_root，避免影响 /dev 与 /sys 语义

### 11.1 新增 CLI 选项

- `--workspace-snapshot`
- `--workspace-root <path>`
- `--workspace-snapshot-parent <path>`
- `--workspace-snapshot-dir <name>`（默认 `snaps`）
- `--workspace-snapshot-meta-dir <name>`（默认 `meta`）
- `--workspace-snapshot-strict`（默认开启，可用 `--no-workspace-snapshot-strict` 关闭）

### 11.2 目录拓扑约束

要求：

1. `workspace-root` 与 `workspace-snapshot-parent` 必须都在 btrfs 上。
2. 二者必须位于同一个 btrfs filesystem（fsid 一致）。
3. `workspace-snapshot-parent` 必须在 `workspace-root` 外部（不能是其子目录或同路径）。

推荐布局：

- source: `/path/workspace`
- snapshot parent: `/path/workspace_snap_parent`
- snapshots: `/path/workspace_snap_parent/snaps`
- metadata: `/path/workspace_snap_parent/meta`

### 11.3 dump 生命周期接入点

- 在 `collect_pstree()` 前初始化 snapshot worker 上下文。
- 在 `collect_pstree()` 成功后发出 worker start 信号。
- 在 unfreeze 前执行 non-blocking gate：
  - `DONE_OK` 才允许继续
  - `RUNNING/WAIT_START/DONE_ERR` 立即标记 dump 失败
- 在 unfreeze 后执行 join 与资源清理。

### 11.4 strict 检测语义

worker 串行执行：

1. pre-check：扫描 source tree 是否存在 nested subvolume
2. create snapshot
3. post-check：再次扫描 source tree

若出现“create 成功但 post-check 失败”，会尝试删除刚创建的 snapshot，并让 dump 失败。

### 11.5 启动包装（无 root 覆盖）

新增统一启动脚本：`test/zdtm/workspace-wrap.sh`，策略为：

- `unshare -m` 进入 mount namespace
- `mount --make-rprivate /`
- 可选 bind `/tmp`、`/var/tmp` 到 workspace 下临时目录
- 重定向 `TMPDIR/HOME/XDG_RUNTIME_DIR` 与工作目录

该策略不修改根文件系统视图，不覆盖 `/dev`、`/sys`，降低对 DSA 路径可见性的风险。

### 11.6 常见报错与处理

- `source workspace contains nested subvolumes`
  - 原因：strict 模式下 source 内存在嵌套子卷。
  - 处理：清理/迁移 nested subvolume，或显式关闭 strict。

- `Snapshot parent ... must be outside source workspace ...`
  - 原因：快照父目录在 source 内部。
  - 处理：将 snapshot parent 移到 source 外部兄弟路径。