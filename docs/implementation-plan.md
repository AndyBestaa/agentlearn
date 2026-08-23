# AsterCode 实施计划与当前基线

本文件把“代码已存在”“离线 fake 已验证”和“真实 live 未验证”分开。没有 API key 时仍可推进离线部分；真实 Provider 不是后续本地安全工作的前置条件。仓库当前 `config.toml` 有意保留旧格式用于迁移兼容验证；`config migrate` 的预览/写入能力已实现，但本次文档同步不替换该用户配置文件。

## 当前状态总览

| 里程碑 | 状态 | 已交付 | 仍缺 |
| --- | --- | --- | --- |
| M0 需求与安全基线 | completed | product spec、architecture、threat model、ADR、AGENTS、runtime prompt、配置模板 | 持续审查文档与实现的一致性 |
| M1 CLI/Provider/状态机 | partial but runnable | Typer CLI、`aster` 无参持续对话入口、对话内精确审批、Pydantic 配置、LangGraph 状态机、Fake/replay、OpenAI Responses 与 DeepSeek Chat adapter；多轮 session 向模型渐进披露最近的用户/助手上下文但排除审批凭证；OpenAI/DeepSeek 固定官方 endpoint 且 HTTP `trust_env=false`；Provider 获得剩余时长/output cap、终态复核 usage，cost 不可跟踪时 fail-closed（input token 仅响应后核对）；三次 DeepSeek 只读 smoke；配置 `config_version=1` 迁移 | 真实 OpenAI smoke、更多 DeepSeek 账户/模型与故障回归 |
| M2 本地工具 | partial but runnable | fs、受控 process/shell、Git、artifact、原子写、唯一进程句柄、有界双流 capture；process/shell 禁止绕过 Git/SSH/network/delete；Git P0 拒绝外部 filter/diff/hooks/fsmonitor/attrs 并设 `GIT_NO_LAZY_FETCH=1`；artifact 准确标记未保存后缀；Windows Job 约束已实测 | 文件/网络 OS 沙箱、CPU rate/磁盘容量硬限额、跨进程 Job handle 恢复、完整 Linux/PowerShell 7/Windows symlink 矩阵 |
| M3 Policy/Approval | partial but enforceable | P0-P4 重判、审批 hash/nonce/TTL/单次消费/精确 session grant/撤销、dry-run、脱敏、kill switch、审计哈希链；SSH 审批绑定主机配置与 known_hosts SHA-256；`deny_by_default` 下 `allow_unsandboxed` 不能绕过未验证网络/沙箱边界；历史 smoke 暴露的 JSONL/SQLite 计数不一致已用审计镜像修复并回归（当时 `valid=true, entries=2693`；当前快照 `valid=true, entries=2707`） | 可验证 OS egress、完整文件系统 sandbox、管理员级不可篡改审计 |
| M4 Memory/Recovery | partial but usable | SQLite WAL/FTS5、schema v7 migrations/backups、三层 memory、edit/conflict/supersedes、字段保留型 checkpoint compaction、跨进程审批恢复、process registry/read-only reconcile、stream/replay；所有写入前 schema preflight 拒绝 future/gap/伪造版本、缺表列和非 FTS5 | 任意外部副作用的自动回滚、远程 reconcile、跨平台旧 PID 回收的 live 证明 |
| M5 SSH/SFTP | transport slice, live blocked | Fake SSH 全契约；默认关闭的系统 OpenSSH 命令通道；固定系统路径和结构化 argv；严格专用 known_hosts 与派生指纹一致性；agent/keychain-only；禁用密码、代理、转发、X11、复用；allowlist/网络证明双门槛；远端停止 unknown | 可信 SSH egress allowlist、首次指纹登记、真实主机、SFTP、远程 PID、备份/原子替换/回滚和现场验证 |
| M6 Browser/MCP/Plugin/Subagent/GUI | offline complete, engine slice verified | Fake Browser/MCP/Plugin；可选 Playwright + Edge 非持久化只读 context；每请求 allowlist/DNS/重定向检查；`about:blank` 零页面网络 smoke；Draft 2020-12 严格 schema；只读子代理双开关、原子父子预算 reservation/usage 合并、跨重启全额保守恢复、grant/parent/all 定向取消 | 浏览器 OS egress、外网导航/下载/提交仍 blocked；子代理仍同进程且 live delegation blocked；真实 MCP/plugin 隔离、GUI、生产调度 |
| M7 跨平台/发布 | partial | wheel、安装 smoke、README、配置和迁移备份、审计 verify、回归 fixture、Git Bash 兼容 smoke、本地性能基线 | Linux 实机、PowerShell 7、OS sandbox/egress、完整 live 集成矩阵 |

## 已完成的离线垂直链路

在不设置 `OPENAI_API_KEY` 或 `DEEPSEEK_API_KEY` 的情况下，以下链路可以通过 Fake Provider 或直接 fake adapter 测试：

1. CLI 创建 session，LangGraph 运行 `OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT`。
2. 文件读取/搜索/精确 patch 和 Git diff。
3. P1/P2/P3 审批暂停、拒绝、单次批准、撤销和跨进程 resume。
4. `aster` 在任意具体项目目录直接进入持续对话；`aster`、`astercode` 和模块入口都由宿主绑定唯一授权根，宽根/系统树/UNC 被拒绝，项目配置不能开启 live Provider、SSH、网络或外部状态路径；审批在终端单独采集，普通自然语言不能代替批准。
5. 大输出 artifact、秘密脱敏、审计 JSONL/SQLite 哈希链及 `audit verify`。
6. SQLite schema v1→v7 增量迁移和旧库备份；每次写入前只读 preflight 并在锁内复核 future/gap/伪造版本、缺表列和非 FTS5。
7. `config_version=1` 配置迁移预览与 `config migrate --write`：精确字节备份、原子替换、源文件冲突检测、future version/旧字段拒绝和环境变量不持久化。
8. 长期 memory propose/commit/edit/conflict/TTL/namespace/FTS5。
9. Fake SSH 的 host key 变化、主机配置/known_hosts hash 审批绑定、远程长任务、`ssh.start` 句柄语义、stop_all/close unknown、上传下载 SHA-256。
10. Fake Browser 的 allowlist、redirect/private/metadata/DNS rebinding、隔离下载和 P3 表单审批。
11. Fake MCP/Plugin 的精确 pin、Draft 2020-12 schema 严格校验、远程 ref 拒绝、结构预算和真实参数风险重判；无网络 runner。
12. 只读子代理的根目录、工具集合、深度、并发和预算继承。
13. 进程 registry 身份验证、同一运行时 kill switch 和安全状态记录。
14. Provider streaming interface、CLI 生命周期事件和 replay fixture。
15. Windows Job Object 父子进程树终止、`process.stop`、树级 active-process/job-memory/累计 CPU-time limit 和 assignment-failure marker；它只验证进程树/资源约束，不是文件/网络 sandbox。
16. process/shell 在未注入 verified sandbox/network policy 时 fail-closed，P2/`allow_unsandboxed` 审批不能越过该边界；deterministic 测试可显式注入两项 verified boundary。
17. 重复/并发进程获得独立 handle，并发预算不超限；大 stdout/stderr 持续排空且有界，超时后代持有管道时也在有限时间内返回。
18. OpenAI/DeepSeek endpoint 固定且 `trust_env=false`；Provider/tool 使用剩余时长与输出预算，未知费用 fail-closed，输入 token 响应后核对。
19. Git P0 禁外部驱动/hook/fsmonitor/attrs 和 lazy fetch；通用 process/shell 不能绕过 Git/SSH/network/delete；artifact 对未保留后缀明确不完整。
20. 离线只读子代理实时刷新父 usage、原子预扣并合并 child usage，重启对未结算额度保守全扣，支持定向取消和双开关；同进程/live 边界不变。

## 2026-08-23 现场验证（范围有限）

在当前 Windows 11 / Python 3.12 环境中，用户配置 `DEEPSEEK_API_KEY` 后运行了一次只读任务：

- 模型：`deepseek-v4-flash`，官方 Chat Completions endpoint。
- 结果：session `completed`；8 轮模型调用、12 次只读工具调用。
- 用量：148,994 tokens（输入与输出合计）；成本尚未从 DeepSeek 账单核对。
- 耗时：约 4 分 28 秒。
- 未覆盖：文件写入、Shell/Git 副作用、审批恢复、真实 SSH、浏览器、OpenAI Provider、长任务和错误重试。
- 发现：流式事件分片过细导致审计写放大，重复上下文造成 Token 使用过高；运行后 `astercode audit verify` 曾报 JSONL/SQLite 少一条记录。随后已完成 delta batching、context compaction、`status=running` 生命周期同步和审计镜像修复；`uv run astercode audit repair --root . --confirm` 追加 1 条 `audit.mirror_repaired` 后，当时 `audit verify` 实测 `valid=true, entries=2693`。这些是已修复并回归的历史问题；当前工作区快照再次核对为 `valid=true, entries=2707`（head `cf34941b...`），记录数会随正常运行增长，smoke 仍不代表完整 live 或性能通过。

修复后又在同一主机完成了第二次低预算、窄范围只读 smoke：

- session：`session_379c1fc09344409abb34c488d87a0bf3`，结果 `completed`。
- 任务边界：只读取 README 前 30 行并用三句话总结，不递归列目录；实际只调用 1 次 P0 `fs.read`，没有审批或副作用。
- 预算：最多 3 轮、2 次工具调用、20,000 总 tokens、16,000 输入 tokens、4,000 输出 tokens、180 秒。
- 实际：2 轮；12,601 输入、1,035 输出，共 13,636 tokens；约 12.2 秒；成本字段为 `null`。
- 对比：第一次为 148,994 tokens、约 4 分 28 秒，第二次观测值明显更低；但第二次任务被严格收窄，因此这不是同负载 A/B 测试，不能单独归因于修复，也不能外推为 SLA 或完整 live 验收。

同一主机还完成了 Windows Job Object 的本机验证：目标进程在 `CREATE_SUSPENDED` 状态先分配进 Job 再恢复，父子树在 Job close 与 `process.stop` 后退出，模拟 assignment 失败时目标 marker 不会创建。Job 配置包含 `KILL_ON_JOB_CLOSE`、树级 active-process/job-memory/累计 user-mode CPU-time limit，三类限额均有本机触发测试，但没有文件系统或网络隔离。AppContainer 目前只是候选方案；Windows Sandbox、Hyper-V、WSL、Docker/Podman 在当前非管理员环境中不可用或无法启用，因此生产 process/shell、SSH、Browser 和网络仍保持 `BLOCKED`。

## 后续执行顺序

### A. 先完成、无需 API key 的工作

- 已完成并回归 live smoke 暴露的审计一致性修复、delta batching、context compaction 和 `status=running` 生命周期同步；第二次低预算窄任务 smoke 已记录输入/输出 token，后续仍需用可比工作负载做回归并核对实际账单（若可见）。
- 在 Windows 上为测试账户准备 symlink/junction/reparse 权限并运行安全回归；无法提供权限就保持测试跳过并报告。
- Windows Job Object 父子树 close/stop 与 assignment-failure 已完成本机验证；继续增加 CLI Ctrl-C、跨进程 Job handle 恢复、超时 unknown、artifact 截断、SQLite 并发和恢复场景的 E2E 证据。
- 将 Fake SSH/Browser/MCP/Plugin/Subagent 测试纳入固定 CI 命令；所有 fixture 保证无网络和无秘密。
- 配置迁移、memory conflict/poisoning、audit tamper detection 的主要文档与回归已完成；后续仅维护迁移兼容性和更多损坏数据库 fixture。
- 在 Linux 或 PowerShell 7 主机上重复只读 doctor、pytest、ruff、mypy 和 CLI smoke。

### B. 具备独立安全证据后再做 live adapter

- 真实 OpenAI：确认当前安装 SDK 类型定义和账户模型 ID，使用一次性低预算 smoke；key 只来自 `OPENAI_API_KEY` 环境变量/secret broker。
- 真实 DeepSeek：已使用 `provider="deepseek"`、`DEEPSEEK_API_KEY`、`ASTERCODE_MODEL_ID=deepseek-v4-flash` 完成三次低风险 JSON decision smoke；其暴露的审计写放大、上下文重复和状态同步问题已修复并回归，后两次低预算窄任务均完成。第三次 session `session_01990918f5774f83aca1bffe08f3d529` 为 2 轮、1 次 `fs.read`、13,761 tokens、约 12.3 秒，且未复现重复 `test_status`。下一步是使用可比工作负载做回归、核对账单并覆盖故障路径。不要复用 Claude Code 的 `ANTHROPIC_*` 或 `[1m]` 模型别名。实现与官方[首次调用](https://api-docs.deepseek.com/zh-cn/)和[Chat API](https://api-docs.deepseek.com/api/create-chat-completion)对齐；除这些只读现场验证外，其余 DeepSeek live 能力仍未验证。
- OS sandbox/egress：Windows Job Object 只解决当前运行时的进程树与部分资源约束；下一步评估并实现可验证的文件系统与网络隔离。AppContainer 仅作为候选，未通过 adapter/egress 实测前不能启用；当前主机又没有可用的 Windows Sandbox、Hyper-V、WSL、Docker/Podman 路径。完成 Windows/Linux 隔离、CPU rate/磁盘容量与 Linux cgroup 等资源配额、DNS/IP/redirect 检查后，才能开放生产 process/network。
- SSH：加入真实 transport 依赖、known_hosts/指纹人工确认和精确 P3 审批；先只读 test，再做远程写流程。
- Browser：Playwright + Edge 非持久化 context 与离线 `about:blank` 已验证；下一步必须先实现独立 OS egress allowlist，再进行人工外网 allowlist 验证。真实下载、提交和登录态仍关闭。
- MCP/Plugin：固定来源/版本/hash，独立隔离进程和网络策略，不能把 manifest 的 read-only 声明当授权。
- GUI：保持默认关闭，完成窗口/区域 allowlist、前后截图、紧急停止和危险动作审批后再评审。

## 每次阶段验收命令

本轮最终全量回归为 `328 passed, 10 skipped`；另有历史本机 Edge 离线 smoke `1 passed, 5 deselected`。10 个 skip 保持为未满足的平台/权限或 live 条件，不计入已完成能力。

```powershell
uv run astercode doctor --root .
uv run astercode config validate --root .
uv run astercode config migrate --root .
uv run astercode audit verify --root .
uv run pytest -q
uv run ruff check src tests
uv run mypy src tests
uv lock --check
```

真实集成缺少凭据时，验收报告必须写 `LIVE INTEGRATION NOT VERIFIED`，不能把 fake/replay 的通过结果写成真实连接成功。

## 暂不做的事情

不自动 commit、push、发布、部署、连接生产主机或索取私钥/API key；不通过关闭安全策略来“解锁”未完成能力。任何 required-path 能力若没有可强制执行的宿主边界，就保持 `BLOCKED`。
