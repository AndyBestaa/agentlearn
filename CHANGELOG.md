# Changelog

本文件记录当前实现边界。项目尚未发布稳定版；`Unreleased` 中的 live 项目不能被解释为已验证功能。

## [Unreleased]

### Added

- Claude Code 风格的 `aster` 快捷入口：在具体项目目录无参数启动持续对话，显示并最终绑定唯一工作区；支持 `/help`、`/status`、`/new`、`/resume`、对话内精确审批和最近多轮用户/助手上下文。`aster`、`astercode` 和模块入口统一执行严格工作区边界，拒绝宽根/系统树/UNC，项目配置不能扩大 Provider、SSH、网络或状态路径权限。新项目配置名为 `astercode.toml`，旧版 AsterCode `config.toml` 继续兼容，其他应用的通用 `config.toml` 不会被误读。
- 交互与恢复硬化：流式/状态/审批显示转义终端控制和双向文本字符；恢复预算只能收窄当前上限；PRE_TOOL_CALL/TOOL_CALL 不能直接 resume；reconcile 路径重新授权；固定状态和项目配置拒绝 link、junction 与文件 hardlink。
- M0 产品规格、分层架构、威胁模型、ADR、AGENTS 约定、实施计划和运行时提示词 `prompts/coding_agent.md`。
- M1 Typer CLI、Pydantic 配置、LangGraph 状态机、预算、Fake Provider、replay fixture、OpenAI Agents SDK/Responses adapter 接口和脱敏流式事件。
- DeepSeek Provider：使用官方 `https://api.deepseek.com` 上的 OpenAI 兼容 Chat Completions、`json_object` 结构化决策和 `DEEPSEEK_API_KEY` 引用；固定当前 Chat 模型 allowlist，严格校验 usage/唯一终态，流式路径在完整秘密检查后转发并忽略 `reasoning_content`，同时拒绝 Claude Code 的 `[1m]` 模型别名与 Anthropic 端点。
- OpenAI 与 DeepSeek 的 SDK client 分别固定 `https://api.openai.com/v1` 和 `https://api.deepseek.com`，HTTP transport 使用 `trust_env=false`，拒绝环境 base URL/proxy 改写 Provider 网络路线；这不等于已实现通用 OS egress sandbox。
- M2 授权工作区文件工具、结构化 process/shell、受控 Git、原子写入、artifact、进程树取消和临时 Git E2E。
- M3 P0-P4 policy、精确审批绑定（action hash、路径/cwd、diff、nonce、TTL、单次消费）、撤销、secret redaction、kill switch 和哈希链审计。
- M4 SQLite WAL/FTS5、显式 schema migrations 与升级备份；当前 schema v7 包含 memory proposals、edit/conflict/supersedes、精确 session grants、runtime process registry、identity token 和 argv hash。
- 配置版本化迁移：严格 `config_version=1`，`config migrate` 默认只预览；`--write` 先做逐字节备份、源身份/SHA-256 冲突检查，再 fsync/原子替换并回读校验。future version、旧字段冲突和环境变量持久化均 fail-closed。
- 数据库 schema preflight：任何写连接、迁移锁或 DDL 前先只读检查，锁内再次复核；future/gap/伪造版本、关键表/列缺失和非 FTS5 `memory_fts` 不会触发迁移或写入。
- M4 跨进程 checkpoint/审批恢复、stream/replay、`audit verify`、process registry/reconcile、memory namespace/TTL/置信度/敏感等级和渐进式检索。
- M5 deterministic Fake SSH：host-key/known_hosts 逻辑、exec/start/poll/stop/stat/close、超时 unknown、上传下载 SHA-256 和 allowlist fail-closed。
- M5 默认关闭的系统 OpenSSH 命令通道：受信绝对路径、结构化 argv、干净环境、agent/keychain-only、专用 strict `known_hosts`、公钥派生指纹一致性，并禁用密码、用户配置、代理、转发、X11 和连接复用；只有配置启用、非空 allowlist 与宿主网络证明同时成立才装配。真实文件传输和远程写继续拒绝。
- SSH 审批绑定扩展：`ssh_target` 将已认证主机配置（hostname/port/user/指纹）及 known_hosts 真实路径和 SHA-256 纳入 action hash；`ssh.start` 只返回句柄，不声称完成，`stop_all`/`close` 对未确认的远端句柄保留并报告 `unknown`。
- M6 deterministic Fake Browser：隔离 fixture、域名/重定向/DNS/私网/metadata 规则、下载和 P3 表单模拟。
- M6 可选 Playwright + Microsoft Edge 只读后端：非持久化 context，不复用用户 profile，关闭 JavaScript、下载、权限和 Service Worker；每个请求/重定向复核 allowlist 与 DNS。本机 `about:blank` 离线 smoke 通过且页面网络请求为 0；没有独立 OS egress 证明时真实导航仍双层拒绝。
- M6 精确 pin 的 Fake MCP/Plugin runner、真实参数风险重判，以及继承父代理边界的只读子代理策略。
- 扩展 schema 安全：工具输入按 Draft 2020-12 严格校验，只允许文档内 `$ref`/`$dynamicRef`，拒绝远程引用并限制深度/节点数；递归/强制参数按 P3/P4 真实副作用重判，忽略 manifest 的 read-only 声明。
- 真实消费 Provider stream 的编排链路、SDK delta 适配、CLI `--stream`、受限 `--replay` 和 `--dry-run`。
- 审批支持单次凭证与仅限 P1/P2 的精确 session grant，并支持列出和撤销。
- 大输出脱敏性能修复、artifact 留存、审计链验证和带 PID 创建身份的跨进程 kill/reconcile。
- Artifact 完整性元数据：进程 capture 超过保留上限时准确记录 `source_complete=false`、丢弃字节数和 incomplete marker；未保留的输出后缀不写入 artifact，磁盘预算截断另以 `disk_complete=false` 标记。
- wheel 打包、配置模板、Windows/Linux 启动说明、离线测试说明和安全回归文档。
- 2026-08-23 现场 DeepSeek 只读 smoke：使用 `deepseek-v4-flash` 完成 `completed` session（8 轮、12 次只读工具调用、148,994 tokens、约 4 分 28 秒）。该记录只证明一次真实 Chat Completions 请求链路可用；成本未从账单核对，未覆盖写操作、长任务、真实 SSH 或其他 live 能力。
- 2026-08-23 第二次 DeepSeek 低预算只读 smoke：session `session_379c1fc09344409abb34c488d87a0bf3` 为 `completed`，严格按要求只读取 README 前 30 行且不递归；预算为 3 轮、2 次工具、20,000 总/16,000 输入/4,000 输出 tokens 和 180 秒，实际为 2 轮、1 次 P0 `fs.read`、12,601 输入/1,035 输出（共 13,636）tokens、约 12.2 秒、无审批，成本字段为 `null`。它比第一次窄且低很多，但两次任务范围不同，不构成受控性能基准，也不覆盖其他 live 能力。
- 2026-08-23 第三次 DeepSeek 低预算只读 smoke：session `session_01990918f5774f83aca1bffe08f3d529` 为 `completed`，只读取 README 前 10 行并用一句话总结；实际 2 轮、1 次 P0 `fs.read`、12,547 输入/1,214 输出（共 13,761）tokens、约 12.3 秒、无审批、成本字段为 `null`。`test_status` 只有一条对应记录，未复现此前的重复项。
- 修复该 smoke 暴露的重复验证记录：无新工具的最终模型轮次不再重复验证上一轮结果；`test_status` 以 `call_id` 幂等，任务完成证据也必须绑定最新工具调用。历史 session 的已写快照保持不变。
- smoke 后修复了过细流式分片的审计写放大（delta batching）、重复上下文（context compaction）和 `status=running` 生命周期同步问题。针对历史上少一条 JSONL/SQLite 记录，执行 `audit repair --confirm` 追加 1 条 `audit.mirror_repaired`，当时 `audit verify` 实测 `valid=true, entries=2693`；当前工作区快照核对为 `valid=true, entries=2707`，记录数会随正常运行增长。修复已完成并通过本地回归，不扩展为 OS 沙箱或其他 live 能力完成。
- Windows Job Object 进程树约束：目标进程用 `CREATE_SUSPENDED` 创建，成功 `AssignProcessToJobObject` 后才恢复；Job 启用 `KILL_ON_JOB_CLOSE`、树级 active-process、job-memory 和累计 user-mode CPU-time limit。本机父子树 Job close/`process.stop`、进程数/内存/CPU 限额与模拟分配失败 marker 测试已通过。该能力仅约束进程树生命周期/资源，不提供文件系统或网络沙箱。
- 进程输出和句柄可靠性：相同命令的每次启动使用独立 `proc_...` 生命周期句柄；stdout/stderr 由有界后台 capture 持续排空，记录 observed/retained/truncated/complete，超时、停止和后代持有管道的路径均使用有限等待。
- run 使用有限默认预算（40 rounds、100 tool calls、120,000 total tokens、100,000 input tokens、20,000 output tokens、3,600 秒），并支持 `--max-rounds`、`--max-tool-calls`、`--max-tokens`、`--max-input-tokens`、`--max-output-tokens` 和 `--max-elapsed-seconds` 的单次覆盖。
- Provider 调用下传剩余时长与剩余 total/output token 上限，并在响应后复核 usage；工具 timeout 取 spec、参数和 run 剩余时长的最小值。费用预算在 Provider 不支持可靠 cost tracking 时调用前 fail-closed；输入 token 只能响应后核对，文档不承诺请求前硬限制。
- 只读离线子代理采用父子预算 reservation/usage 合并、跨重启未结算 reservation 全额保守恢复、按 grant/parent/all 的定向取消，以及 feature+security 双开关。当前 runner 仍同进程，live delegation 和生产隔离保持 blocked。

### Fixed

- 修复 `fs.apply_patch` 对模型宣称支持标准 unified diff、但执行器只识别 AsterCode patch envelope 的契约错位；ToolSpec/schema 现在给出精确 `*** Begin Patch` 格式和新建文件示例，Policy 与 Executor 复用同一解析器，无法绑定真实路径的格式会在审批前 fail-closed。真实 DeepSeek 临时空项目回归已走通 `fs.list → 精确路径审批 → fs.apply_patch → fs.read`，创建并核对 `hello.py`。
- 修复 Windows 英文系统的旧终端代码页（例如 `cp1252`）无法输出中文欢迎语而崩溃的问题；所有公开 CLI 入口现在都会先规范化为 UTF-8，打包 smoke 会显式模拟 `cp1252` 回归。
- 普通自然语言不再可能越过待审批 interrupt：已有 `waiting_approval` 的 session 必须提交绑定 approval id/action hash/nonce 的宿主终端决策；批准文本不进入模型上下文。快捷对话也拒绝静默授权用户主目录或磁盘根目录，并将状态、artifact 和浏览器下载位置强制限制在启动工作区。
- 修复 `deny_by_default` 下 `allow_unsandboxed` 审批可能绕过未验证网络边界的问题。普通 process/shell 现在同时要求运行时证明进程沙箱和网络策略均已强制执行；审批不能替代任一 OS 边界。正常生产 CLI 不注入 verified boundary，只有 deterministic 测试或未来完成 attestation 的 host adapter 才能显式注入。
- 修复 `process.send_input`/`process.stop` 审批后错误接收启动专用参数、重复 `process.start` 句柄碰撞、`communicate()` 无界内存、并发启动突破计数预算，以及 Job 分配失败后的稀有清理遗漏。
- Git executor 拒绝仓库级 `include/includeIf` 配置，强制禁用 hooks、外部 diff、commit/tag GPG signing、credential helper 和 askpass；恶意仓库 signing 配置回归通过。
- Git P0 查询进一步拒绝 filter/diff/merge 外部驱动、fsmonitor 和外部 attributes/excludes 配置，设置 `GIT_NO_LAZY_FETCH=1` 并对 diff/show 禁用 external diff/textconv；通用 process/shell 也拒绝绕过受控 Git、SSH、network 和 delete 路径。
- 修复首次公开 CI 暴露的跨平台差异：Linux mypy 通过运行时检查访问 Windows-only API 并保持 fail-closed；Windows 8.3 临时目录别名改用文件身份比较；GitHub Actions 升级到 Node 24 action 版本。
- 最终全量回归：`328 passed, 10 skipped`；历史本机 Edge 离线 smoke 另为 `1 passed, 5 deselected`；skip 不视为能力通过。

### Not verified / still blocked

- 真实 OpenAI Provider/API smoke：当前没有凭据验证；没有 API key 时请使用 Fake 或 replay。
- 真实 DeepSeek Chat Completions：已完成三次本地只读 smoke（见 Added），但账户模型覆盖、实际成本、长任务、写操作和故障恢复仍未验证；不能据此宣称完整 live 集成完成。
- 系统 OpenSSH 命令 transport 已实现但默认关闭；真实 egress、主机、认证/MFA、SFTP 和远程写回滚仍为 `LIVE SSH NOT VERIFIED`。
- Playwright + Edge 无网络引擎启动已验证；真实网络 egress/SSRF 防护、外网导航、下载和提交仍为 `LIVE INTEGRATION NOT VERIFIED`。
- 原生桌面 GUI：默认关闭，未实现 live adapter。
- MCP/plugin 真实隔离进程、来源下载和网络策略：Fake runner 不是生产隔离边界。
- Windows Job Object 的树终止、active-process、job-memory 和累计 user-mode CPU-time limit 已在本机测试，但它不是文件/网络沙箱；CPU rate、磁盘容量、Linux namespace/cgroup 和 OS egress 仍未验证。AppContainer 只是候选方案，尚无 verified adapter；当前主机的 Windows Sandbox、Hyper-V、WSL、Docker/Podman 不可用或无法由非管理员账户启用。无强制边界的 process/network 保持 fail-closed。
- Linux bash、PowerShell 7、Windows junction/reparse point 完整实机矩阵、性能基线和完整 Ctrl-C 现场回归。
- 本次 DeepSeek smoke 历史上曾暴露流式分片审计写放大、重复上下文导致的高 Token 使用，以及运行后 JSONL/SQLite 少一条记录；上述问题已通过 delta batching、context compaction、状态同步和审计镜像修复完成并回归。该历史 smoke 的 Token 与耗时仍不是 SLA 或成本承诺。

### Safety notes

- `authorized_ssh_hosts = []` 时运行时代码拒绝真实 SSH，不因 prompt、README、memory 或插件声明而放行。
- 不自动 commit、push、发布、部署或连接生产主机；不在仓库、日志、配置示例或测试 fixture 保存秘密。
- fake/replay 通过不等于 live 集成通过；阶段报告必须分别列出 fake、live、blocked 和未运行项目。
- Provider 凭据严格分离：DeepSeek 只引用 `DEEPSEEK_API_KEY`，OpenAI 只引用 `OPENAI_API_KEY`；Claude Code 的 `ANTHROPIC_*` 不会直接配置 AsterCode。
