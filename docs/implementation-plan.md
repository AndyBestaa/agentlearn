# AsterCode 实施计划与当前基线

本文件把“代码已存在”“离线 fake 已验证”和“真实 live 未验证”分开。没有 API key 时仍可推进离线部分；真实 Provider 不是后续本地安全工作的前置条件。仓库当前 `config.toml` 有意保留旧格式用于迁移兼容验证；`config migrate` 的预览/写入能力已实现，但本次文档同步不替换该用户配置文件。

## 当前状态总览

| 里程碑 | 状态 | 已交付 | 仍缺 |
| --- | --- | --- | --- |
| M0 需求与安全基线 | completed | product spec、architecture、threat model、ADR、AGENTS、runtime prompt、配置模板 | 持续审查文档与实现的一致性 |
| M1 CLI/Provider/状态机 | partial but runnable | Typer CLI、`aster` 无参持续对话入口、对话内精确审批、Pydantic 配置、LangGraph 状态机、Fake/replay、OpenAI Responses 与 DeepSeek Chat adapter；多轮 session 向模型渐进披露最近的用户/助手上下文但排除审批凭证；非 Git 只读失败和执行前陈旧补丁拒绝可作为有界观察继续；OpenAI/DeepSeek 固定官方 endpoint 且 HTTP `trust_env=false`；Provider 获得剩余时长/output cap、终态复核 usage，cost 不可跟踪时 fail-closed（input token 仅响应后核对）；三次 DeepSeek 只读 smoke及非 Git 同会话双循环；配置 `config_version=1` 迁移 | 真实 OpenAI smoke、更多 DeepSeek 账户/模型与故障回归 |
| M2 本地工具 | runnable Docker build/export slice | fs、Git、artifact、原子写、唯一进程句柄、有界 capture；Windows Job；Docker 固定摘要、只读宿主源码、512 MiB 临时可写副本、无网络、非 root 构建、compileall；复制一致性；容器恢复；`process.exec_export` 仅在成功后按精确白名单/总大小上限导出普通文件并记录 SHA-256 | 更多语言镜像、跨进程 Job handle 恢复、Linux 原生与完整 symlink 矩阵 |
| M3 Policy/Approval | partial but enforceable | P0-P4、精确审批、脱敏、kill switch、哈希审计；Docker 只有主动 probe 通过才向 policy 提供 process/network attestation，配置/审批不能伪造；`doctor` 已独立报告镜像签名、SBOM、漏洞扫描工具是否可用；Windows 已安装并识别三项工具，Syft 本地镜像 smoke 通过 | 通用 allowlist egress、完整 Trivy 漏洞数据库扫描、可信 Cosign 签名证据、管理员级不可篡改审计 |
| M4 Memory/Recovery | partial but usable | SQLite WAL/FTS5、schema v8 migrations/backups、三层 memory、edit/conflict/supersedes、字段保留型 checkpoint compaction、跨进程审批恢复、process registry/read-only reconcile、Docker backend identity、stream/replay；所有写入前 schema preflight 拒绝 future/gap/伪造版本、缺表列和非 FTS5 | 任意外部副作用的自动回滚、远程 reconcile、Linux/POSIX 旧 PID 回收的 live 证明 |
| M5 SSH/SFTP | transport slice, live blocked | Fake SSH 全契约；默认关闭的系统 OpenSSH 命令通道；固定系统路径和结构化 argv；严格专用 known_hosts 与派生指纹一致性；agent/keychain-only；禁用密码、代理、转发、X11、复用；allowlist/网络证明双门槛；远端停止 unknown | 可信 SSH egress allowlist、首次指纹登记、真实主机、SFTP、远程 PID、备份/原子替换/回滚和现场验证 |
| M6 Browser/MCP/Plugin/Subagent/GUI | offline complete, engine slice verified | Fake Browser/MCP/Plugin；可选 Playwright + Edge 非持久化只读 context；每请求 allowlist/DNS/重定向检查；`about:blank` 零页面网络 smoke；Draft 2020-12 严格 schema；只读子代理双开关、原子父子预算 reservation/usage 合并、跨重启全额保守恢复、grant/parent/all 定向取消 | 浏览器 OS egress、外网导航/下载/提交仍 blocked；子代理仍同进程且 live delegation blocked；真实 MCP/plugin 隔离、GUI、生产调度 |
| M7 跨平台/发布 | partial | wheel、安装 smoke、README、配置和迁移备份、审计 verify、回归 fixture、Git Bash 兼容 smoke、本地性能基线；CLI Ctrl-C 显示及审批恢复中运行任务的进程树清理已回归；WSL2 Ubuntu 只读 compileall smoke 通过 | Linux 原生 OS sandbox/egress、完整终端信号矩阵和 live 集成矩阵 |

## 已完成的离线垂直链路

在不设置 `OPENAI_API_KEY` 或 `DEEPSEEK_API_KEY` 的情况下，以下链路可以通过 Fake Provider 或直接 fake adapter 测试：

1. CLI 创建 session，LangGraph 运行 `OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT`。
2. 文件读取/搜索/精确 patch 和 Git diff。
3. P1/P2/P3 审批暂停、拒绝、单次批准、撤销和跨进程 resume。
4. `aster` 在任意具体项目目录直接进入持续对话；`aster`、`astercode` 和模块入口都由宿主绑定唯一授权根，宽根/系统树/UNC 被拒绝，项目配置不能开启 live Provider、SSH、网络或外部状态路径；审批在终端单独采集，普通自然语言不能代替批准。
5. 大输出 artifact、秘密脱敏、审计 JSONL/SQLite 哈希链及 `audit verify`。
6. SQLite schema v1→v8 增量迁移和旧库备份；v8 保存进程 backend/container/image 身份。每次写入前只读 preflight 并在锁内复核 future/gap/伪造版本、缺表列和非 FTS5。
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
- 发现：流式事件分片过细导致审计写放大，重复上下文造成 Token 使用过高；运行后 `astercode audit verify` 曾报 JSONL/SQLite 少一条记录。随后已完成 delta batching、context compaction、`status=running` 生命周期同步和审计镜像修复；`uv run astercode audit repair --root . --confirm` 追加 1 条 `audit.mirror_repaired` 后，当时 `audit verify` 实测 `valid=true, entries=2693`。这些是已修复并回归的历史问题；当前工作区快照再次核对为 `valid=true, entries=2741`（head `a4436347...`），记录数会随正常运行增长，smoke 仍不代表完整 live 或性能通过。

修复后又在同一主机完成了第二次低预算、窄范围只读 smoke：

- session：`session_379c1fc09344409abb34c488d87a0bf3`，结果 `completed`。
- 任务边界：只读取 README 前 30 行并用三句话总结，不递归列目录；实际只调用 1 次 P0 `fs.read`，没有审批或副作用。
- 预算：最多 3 轮、2 次工具调用、20,000 总 tokens、16,000 输入 tokens、4,000 输出 tokens、180 秒。
- 实际：2 轮；12,601 输入、1,035 输出，共 13,636 tokens；约 12.2 秒；成本字段为 `null`。
- 对比：第一次为 148,994 tokens、约 4 分 28 秒，第二次观测值明显更低；但第二次任务被严格收窄，因此这不是同负载 A/B 测试，不能单独归因于修复，也不能外推为 SLA 或完整 live 验收。

同一主机还完成了 Windows Job Object 验证。随后新增固定 RepoDigest 的 Docker 临时构建沙箱：主动 probe 与现场测试证明只读 root/宿主源码、隐藏状态/VCS/本机依赖、512 MiB 临时可写副本、`--network none`、非 root、cap-drop/no-new-privileges、Python 执行、compileall、超时清理和 start/poll/stop。构建写入不会回传宿主；SSH、Browser 和其他 live 网络不继承该证明。

真实 DeepSeek 垂直 smoke `session_46f7633fc2fe4277937777c167fc4413` 验证了 `python --version`。临时构建第一次因复制 `.venv` 超时为 `unknown`，只读 reconcile 确认无残留；固定排除生成目录后，session `session_d8d98eaef8fe4e6882bf4691bfac7894` 在约 1.85 秒完成 `python -m compileall -q .`，退出码 0，证明 Function Call→精确审批→临时构建副本→结果证据链可用。

## 后续执行顺序

### A. 先完成、无需 API key 的工作

- 已完成并回归 live smoke 暴露的审计一致性修复、delta batching、context compaction 和 `status=running` 生命周期同步；第二次低预算窄任务 smoke 已记录输入/输出 token，后续仍需用可比工作负载做回归并核对实际账单（若可见）。
- 在 Windows 上为测试账户准备 symlink/junction/reparse 权限并运行安全回归；无法提供权限就保持测试跳过并报告。
- Windows Job Object 父子树 close/stop、assignment-failure，以及审批恢复中运行任务的 Ctrl-C 等价取消与完整进程树清理已完成本机验证；继续增加真实终端信号注入、跨进程 Job handle 恢复、超时 unknown、SQLite 并发和恢复场景的 E2E 证据。
- 将 Fake SSH/Browser/MCP/Plugin/Subagent 测试纳入固定 CI 命令；所有 fixture 保证无网络和无秘密。
- 配置迁移、memory conflict/poisoning、audit tamper detection 的主要文档与回归已完成；后续仅维护迁移兼容性和更多损坏数据库 fixture。
- 在 Linux 或 PowerShell 7 主机上重复只读 doctor、pytest、ruff、mypy 和 CLI smoke；本机 WSL2 Ubuntu 已完成 Python/bash、项目挂载和 `compileall` 只读 smoke，但不等同于 Linux 原生 Docker/CLI 全量验收。

### B. 具备独立安全证据后再做 live adapter

- 真实 OpenAI：确认当前安装 SDK 类型定义和账户模型 ID，使用一次性低预算 smoke；key 只来自 `OPENAI_API_KEY` 环境变量/secret broker。
- 真实 DeepSeek：已使用 `provider="deepseek"`、`DEEPSEEK_API_KEY`、`ASTERCODE_MODEL_ID=deepseek-v4-flash` 完成三次低风险只读 smoke，以及可复现的同会话受控写入 smoke。最终提交 `904cc6e` 上的 session `session_49c2fb8db498411880b8680b38bb89da` 包含聊天和两轮 `create → modify → delete`，实际为 7 个用户 turn、6 次单次精确审批、6 次副作用工具调用（4 次 `fs.apply_patch`、2 次 `fs.delete`）；宿主逐步按字节核对内容，最终测试文件不存在，审计链有效。该现场测试促成了非 SSH host 权威派生、Provider 结构错误有界重试、重复副作用抑制和可复现 live harness；仍需核对账单并覆盖 Shell、长任务及更多故障恢复路径。不要复用 Claude Code 的 `ANTHROPIC_*` 或 `[1m]` 模型别名。实现与官方[首次调用](https://api-docs.deepseek.com/zh-cn/)和[Chat API](https://api-docs.deepseek.com/api/create-chat-completion)对齐。
- OS sandbox/egress：Docker 临时副本、复制一致性、跨执行器容器清理和产物白名单导出已完成；Windows 已用 WinGet 安装并由固定路径识别 `cosign`、`syft`、`trivy`，Syft 本地镜像 SBOM smoke 已通过。Trivy 数据库首次下载因网络过慢未完成，Cosign 仍缺少可信签名身份/证据；仍需补齐供应链证据、跨进程 Windows Job handle/POSIX 恢复和真实终端信号矩阵。SSH/Browser 仍需各自独立 egress allowlist。
- SSH：加入真实 transport 依赖、known_hosts/指纹人工确认和精确 P3 审批；先只读 test，再做远程写流程。
- Browser：Playwright + Edge 非持久化 context 与离线 `about:blank` 已验证；下一步必须先实现独立 OS egress allowlist，再进行人工外网 allowlist 验证。真实下载、提交和登录态仍关闭。
- MCP/Plugin：固定来源/版本/hash，独立隔离进程和网络策略，不能把 manifest 的 read-only 声明当授权。
- GUI：保持默认关闭，完成窗口/区域 allowlist、前后截图、紧急停止和危险动作审批后再评审。

## 每次阶段验收命令

本轮最终全量回归为 `401 passed, 10 skipped`。新增回归覆盖受控产物导出、构建进程无法直接写导出目录、Fake 模型→精确审批→Docker 导出完整链路，以及审批恢复期间取消长任务后的进程树清理。最新真实 DeepSeek 非 Git 对话回归 session `session_c004966b009d4c479562b714e0d3c56a` 完成 7 个用户回合、6 次 consumed 单次审批、7 次工具调用和 6 次实际副作用，最终文件不存在；空 path 只读现场复测 session `session_0925077d608240018fdb47a936e29a8a` 也为 completed；内联代码恢复 session `session_038b35bb629348e4aa6f9ce66d30063e` 验证拒绝 `python -c` 后自动改用工作区文件并在 Docker sandbox 输出 `5`。本地 sessions `session_7d900a2b47fa47fabebcaf7f4752ba6a`、`session_39f6d00411c04cfb818d68768f36d7e4`、`session_6ca9afec1f89409c9a7efcd582f9b09b`、`session_64c92f4347234e82a332072a5eecfce1` 进一步覆盖纯聊天状态、双循环代码工作、Docker 执行与上下文解释、审批报告、缺失路径观察和拒绝后上下文隔离。另有历史本机 Edge 离线 smoke `1 passed, 5 deselected`。10 个 skip 保持为未满足的平台/权限或 live 条件，不计入已完成能力。

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

本轮最新全量回归为 `402 passed, 10 skipped`；新增镜像安全工具探测测试已包含在该数字中。

不自动 commit、push、发布、部署、连接生产主机或索取私钥/API key；不通过关闭安全策略来“解锁”未完成能力。任何 required-path 能力若没有可强制执行的宿主边界，就保持 `BLOCKED`。
