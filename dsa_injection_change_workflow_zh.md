# CRIU-DSA DSA注入逻辑变更说明（中文）

## 1. 文档目的

本文档用于总结本次在 CRIU-DSA 中新增/调整的 DSA 拷贝注入逻辑，重点说明：

1. 添加了哪些逻辑。
2. 每个逻辑的具体工作流（workflow）。
3. 关键状态流转与错误回传链路。
4. 如何保证与 CRIU 现有体系（命名、结构、调用封装、返回约定）不冲突。

## 2. 改动总览

本次改动集中在 4 个文件：

1. criu/include/parasite.h
2. criu/include/parasite-syscall.h
3. criu/parasite-syscall.c
4. criu/pie/parasite.c

### 2.1 命令与参数协议层（共享头）

在 criu/include/parasite.h 中新增：

1. 命令 ID：PARASITE_CMD_DSA_COPY
2. 参数结构：struct parasite_dsa_copy_args

该结构同时被宿主侧和 parasite 侧使用，确保双方对命令参数、回传字段定义一致。

结构体字段分为两类：

1. 输入字段
- src_addr：源地址
- copy_len：拷贝长度
- use_wq_fd：是否通过 RPC 传入 WQ FD
- prefer_hugetlb：目标缓冲是否优先使用 hugetlb
- wq_path：WQ 设备路径

2. 输出/诊断字段
- op_ret：业务执行结果（0 成功，负值失败）
- stage：阶段号（便于定位失败点）
- detail：细节错误码
- dsa_status：硬件完成状态码
- bytes_completed：硬件记录的完成字节数
- used_hugetlb：是否使用 hugetlb
- checksum_before / checksum_after：源/目标校验值
- fault_addr：硬件故障地址
- comp_result：硬件 completion result

### 2.2 宿主侧调用接口层

在 criu/include/parasite-syscall.h 与 criu/parasite-syscall.c 中新增：

1. 函数声明：parasite_dsa_copy_seized(...)
2. 函数实现：parasite_dsa_copy_seized(...)

该函数是宿主侧统一入口，负责：

1. 将参数写入 compel_parasite_args 区域。
2. 按 use_wq_fd 选择 RPC 路径：
- 路径 A（use_wq_fd=1）：compel_rpc_call -> send_fd -> compel_rpc_sync
- 路径 B（use_wq_fd=0）：compel_rpc_call_sync
3. 将 parasite 回填结果拷回调用者 args。
4. 按 CRIU 习惯分层返回错误：
- 先返回 RPC 层错误
- RPC 成功后返回业务层 args->op_ret

### 2.3 Parasite 执行层（PIE）

在 criu/pie/parasite.c 中新增：

1. DSA 相关常量/辅助函数
- dsa_align_up
- dsa_memzero
- dsa_enqcmd_local
- dsa_cpu_relax
- dsa_prefault_range
- dsa_checksum32

2. 主执行函数
- parasite_dsa_copy(struct parasite_dsa_copy_args *a)

3. daemon 命令分发表注册
- 在 parasite_daemon_cmd 的 switch 中增加 PARASITE_CMD_DSA_COPY 分支

## 3. 端到端工作流（Host -> Parasite -> Host）

## 3.1 宿主侧 Workflow

入口函数：parasite_dsa_copy_seized

步骤：

1. 参数校验
- args 为空时直接返回 -EINVAL。

2. 参数下发
- 通过 compel_parasite_args 获取共享参数区并整体拷贝输入参数。

3. 命令发送
- use_wq_fd=1：先异步 call，再把 wq_fd 通过 SCM_RIGHTS 发送，再 sync。
- use_wq_fd=0：直接 call_sync。

4. 结果回收
- 把 parasite 侧回填后的参数整体拷回调用者。

5. 返回值策略
- 若 RPC 失败，返回 RPC 错误（通信层失败）。
- 若 RPC 成功，返回 args->op_ret（业务层成功/失败）。

## 3.2 Parasite 侧 Workflow

入口函数：parasite_dsa_copy

阶段流转（stage）如下：

1. stage=0：初始化输出字段。
2. stage=1：输入参数非法（src_addr/copy_len/wq_path）。
3. stage=2：use_wq_fd=1 时从 RPC socket 接收 WQ FD。
4. stage=3：use_wq_fd=0 时在目标进程上下文 open WQ。
5. stage=4：尝试 mmap DSA portal（先 MAP_POPULATE，失败再普通 MAP_SHARED）。
6. stage=5：portal mmap 失败，进入 write 提交回退路径。
7. stage=6：准备目标缓冲（可选 hugetlb）。
8. stage=7：hugetlb 失败时回退到普通 memfd + MADV_HUGEPAGE。
9. stage=8：预触发源页，计算源校验，清零目标缓冲。
10. stage=9：提交 descriptor
- 有 portal：enqcmd 提交
- 无 portal：write(wq_fd, desc) 提交
11. stage=10：提交重试耗尽（-EAGAIN）。
12. stage=11：轮询 completion。
13. stage=12：收到 completion，回填 dsa_status/bytes/fault/result；
- 成功状态时计算目标校验并比较
- 一致返回 0，不一致返回 -EBADMSG
- 失败状态返回 -(int)code
14. stage=13：轮询超时（-ETIMEDOUT）。

收尾：统一释放 dst/portal/memfd/wq_fd，保证资源不泄露。

## 4. 关键设计点与原DSA流程的一致性

对齐点如下：

1. 命令通道一致
- 仍使用 compel 的 RPC 命令通道。

2. WQ 获取策略一致
- 支持 FD 传递和 parasite 内 open 两种模式。

3. 提交策略一致
- 优先 portal + enqcmd。
- portal 失败自动回退 write 提交。

4. 内存策略一致
- 可选 hugetlb，失败自动回退普通共享内存。

5. 结果验证一致
- completion 状态码 + bytes + result + fault_addr 回传。
- 额外加入源/目标 checksum 比较，保证搬运结果可验证。

## 5. 与CRIU现有逻辑的兼容性说明

## 5.1 命名与结构

1. 命名遵循 parasite_ 前缀和现有风格。
2. 新增结构放在 parasite.h（宿主/parasite 共用头）符合 CRIU 习惯。
3. 未改变既有结构布局与旧命令语义。

## 5.2 调用与封装

1. 新增对外调用入口在 parasite-syscall.c，符合现有封装模式。
2. 未绕开既有感染流程（compel_infect）。
3. 未修改既有命令处理分支行为。

## 5.3 错误回传语义

保留双层错误语义：

1. RPC 层错误：通信/同步失败即返回。
2. 业务层错误：通过 op_ret/detail/stage/dsa_status 定位问题。

这种方式与 CRIU 现有 parasite 命令回传风格一致，不会和当前调用方错误处理逻辑冲突。

## 6. 关键字段解读（排障建议）

当调用失败时，建议按以下优先级看字段：

1. stage：先定位到哪一步失败。
2. op_ret/detail：看系统错误码或映射后的 DSA 错误。
3. dsa_status：定位硬件完成状态类型。
4. fault_addr：定位页错误/地址翻译问题。
5. bytes_completed：判断是否部分完成。
6. checksum_before/after：判断是否数据完整性问题。

## 7. 当前边界与下一步建议

当前已完成：

1. 协议定义
2. 宿主侧封装
3. parasite 执行逻辑
4. daemon 分发接入

建议下一步：

1. 在 CRIU-DSA 的具体业务路径中增加一次真实调用（例如实验入口或 dump 过程中的可控点）。
2. 增加最小化自测（小长度和 2MB 两档）并记录 stage/op_ret/dsa_status/fault_addr。
3. 根据平台特性决定默认 use_wq_fd / prefer_hugetlb 策略。

---

本文档仅描述本次改动的设计与流程，不改变 CRIU 主体现有 dump/restore 业务语义。