# AsterCode 产品规格（M0-M4 本地切片）

## 1. 定位

AsterCode 是一个 local-first、可恢复、可审计、权限受控的终端编程代理。它以 LangGraph 作为工作流编排层，由宿主运行时提供受策略约束的文件、进程、Git、SSH 和可选浏览器工具。模型只能提出结构化工具调用；所有副作用都由宿主重新解析、授权、执行和记录。

本文件保留 M0 目标和约束。当前 M0-M4 本地链路已扩展到 schema v8、stream/replay、dry-run、精确 session grants、带 Docker backend identity 的跨进程 process registry/kill 和记忆 edit/conflict；M5-M6 已有 deterministic fake 垂直切片。依赖真实 Provider、SSH transport、Playwright、外部插件进程或通用 OS egress 的能力仍为 blocked/live-unverified，绝不把 fake 测试写成真实集成完成。

## 2. 默认项目参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PRODUCT_NAME` | `AsterCode` | 现有项目名称未定义，采用默认名 |
| `PROJECT_ROOT` | `C:\\Users\\MT\\langgraph-agent` | 专用项目目录；见 ADR-0001 |
| `TARGET_OS` | Windows 11 + PowerShell 5.1/7 兼容；Linux + bash 目标 | 运行时检测并选择执行器 |
| `MODEL_PROVIDER` | OpenAI Responses API + OpenAI Agents SDK（适配器） | 模型接口必须配置化 |
| `MODEL_ID` | 配置/环境变量 | 禁止写死模型名或密钥 |
| `AUTHORIZED_ROOTS` | 仅 `PROJECT_ROOT` | 真实路径校验后仍须位于该根内 |
| `AUTHORIZED_SSH_HOSTS` | `[]` | 空列表在运行时拒绝所有真实 SSH |
| `NETWORK_MODE` | `deny_by_default` | 每个网络出口须单独授权 |
| `ENABLE_BROWSER_AUTOMATION` | `true`（能力开关） | 域名、下载目录和副作用仍受策略约束 |
| `ENABLE_NATIVE_DESKTOP_GUI` | `false` | 第一阶段不启用原生桌面控制 |
| `ENABLE_MULTI_AGENT` | `false` | 第一阶段不启用子代理 |
| `EXECUTION_MODE` | `inspect_then_implement` | 先观察、计划、策略检查，再执行 |

## 3. 目标

1. 阅读、搜索和理解授权工作区内的代码。
2. 创建、编辑、移动和删除授权工作区内的文件，并保留可审计 diff。
3. 受控执行 PowerShell/bash、构建、测试和开发服务器。
4. 通过安全包装器查看和操作 Git；提交、推送及危险操作分级审批。
5. 在明确配置和审批后连接受信任 SSH 主机并执行窄范围操作。
6. 提供隔离浏览器适配器；原生 GUI 默认关闭。
7. 提供短期、中期、长期记忆，以及 checkpoint、暂停审批和恢复。
8. 提供流式事件、取消、kill switch、审计、成本/Token/耗时统计。
9. 通过 deterministic fake provider/executor/replay fixture 在无凭据、无网络环境完成大多数测试。

## 4. 非目标

- 不复制或声称复制 Claude Code 的私有实现、品牌或未公开协议。
- 不绕过操作系统权限、MFA、SSH host key、安全软件或用户审批。
- 不承诺控制任意电脑；能力取决于实际适配器和授权。
- 第一阶段不构建 IDE、云平台或复杂 Web UI。
- 不把提示词、README、网页、日志或记忆当作安全边界。

## 5. 用户与核心流程

### CLI 入口

当前命令：`init`、`run`、`chat`、`resume`、`status`、`doctor`、`sessions`、`memory`、`config`、`permissions`、`audit`、`kill`，以及 fail-closed 的 `ssh hosts list/test`。CLI 支持流式事件、受限 replay、dry-run、持久化 checkpoint、单次/精确 session 审批、拒绝/恢复和带身份校验的进程回收。默认关闭的系统 OpenSSH 命令 transport 已实现，但正常 CLI 没有可信 SSH egress 证明且默认 allowlist 为空；真实会话、认证、SFTP 和回滚仍为 `LIVE SSH NOT VERIFIED`。

### 工作循环

每个任务沿着以下有限状态流转：

`OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT`

终态为 `COMPLETED`、`PARTIAL`、`BLOCKED`、`CANCELLED` 或 `FAILED`。每轮受最大轮数、工具数、Token、费用、时间和并发预算限制；有副作用的动作必须有 `action_id` 和幂等键。

### 权限等级

- **P0**：授权工作区只读分析，可自动执行。
- **P1**：工作区内可逆修改和无网络构建/测试，可自动执行但记录 diff。
- **P2**：依赖安装、指定网络、工作区外读取、长期进程、首次允许的 SSH 只读检查，需要精确指令或窄范围审批。
- **P3**：远程写入、push、发布、部署、数据库写入、sudo、服务启停、外部提交或敏感数据传输，逐项即时审批。
- **P4**：强制推送、递归删除、生产迁移、IAM/防火墙/认证变更、reboot 等默认拒绝；仅在目标、备份、验证和回滚均明确时逐项审批。

以下动作永远禁止：关闭审计或 host-key 校验、泄露秘密、未授权横向移动、隐藏后门、篡改审计证据、伪造测试结果或由项目内容替用户批准动作。

## 6. 验收原则

- 完成声明必须有真实命令、结果、变更文件和未验证项。
- Fake Provider 下必须能完成读取→修改→测试→diff→checkpoint→resume 的 E2E。
- 安全回归必须覆盖路径越界、symlink/junction、命令注入、秘密脱敏、审批绑定/过期、kill switch 和提示注入。
- 真实 Provider、SSH、GUI 若无凭据，只能标记 `LIVE INTEGRATION NOT VERIFIED`，不得伪造通过。
- 不自动 commit、push、发布、部署或连接真实主机。

## 7. 里程碑摘要

M0 需求/架构/威胁模型/ADR/计划；M1 CLI、配置、Provider 抽象、Fake Provider 和状态机；M2 文件/process/shell/Git 垂直链路；M3 策略、审批、沙箱、脱敏和 kill switch；M4 三层记忆、checkpoint、resume、有限上下文压缩；M5 SSH/SFTP；M6 浏览器、MCP/plugin、可选子代理；M7 跨平台硬化、打包、迁移、性能和安全回归。
