# AsterCode

AsterCode 是一个基于 LangGraph 的本地优先编程代理原型。模型只能提出结构化工具调用；路径校验、权限分级、审批、执行、审计和恢复由宿主程序完成。它不是 Claude Code 的私有实现或品牌复制品。

当前版本的重点仍是**不设置 API key 也能运行的离线垂直链路**：Fake Provider、文件/Git 工具、审批与恢复、SQLite WAL/FTS5、Fake SSH、Fake Browser、Fake MCP/Plugin、只读子代理、流式事件和 replay 都可以用自动化测试验证。Windows 本地进程已有实机验证的 Job Object **进程树约束**，但它不隔离文件系统或网络；生产 CLI 仍因缺少经过验证的 OS 沙箱和网络出口控制而 fail-closed。2026-08-23 在本机完成了三次真实 DeepSeek 只读 smoke（`deepseek-v4-flash`）：第一次为较宽的项目检查，8 轮、12 次只读工具调用、148,994 tokens、约 4 分 28 秒；第二次严格限定为读取 README 前 30 行且不递归，2 轮、1 次 `fs.read`、13,636 tokens、约 12.2 秒；第三次再次限制为 README 前 10 行和一句话摘要，2 轮、1 次 `fs.read`、13,761 tokens、约 12.3 秒。任务范围不同，不能据此得出严格性能或成本结论；它们也不代表所有模型、任务或 live 工具已经验证。真实 OpenAI、真实 SSH 会话、浏览器外网导航、GUI、插件进程隔离和 OS 级沙箱仍明确标记为 `LIVE INTEGRATION NOT VERIFIED` 或 `BLOCKED`。

## 安装与首次启动

要求 Python 3.12+ 和 uv：

```powershell
cd C:\Users\MT\langgraph-agent
uv sync --extra dev
uv run astercode init --root .
uv run astercode doctor --root .
```

Linux bash：

```bash
cd /path/to/langgraph-agent
uv sync --extra dev
uv run astercode init --root .
uv run astercode doctor --root .
```

状态文件默认在项目内 `.astercode/`，不会自动读取仓库 `.env`、PowerShell profile、bash rc 或个人 SSH 目录。

### 在任意 VS Code 项目中直接输入 `aster`

开发阶段可以把当前源码安装成全局可执行命令；`--editable` 会让后续源码修改立即生效：

```powershell
cd C:\Users\MT\langgraph-agent
uv tool install --editable . --force
uv tool update-shell
```

完全退出并重新打开 VS Code。随后在任意具体项目目录中运行：

```powershell
cd C:\path\to\my-project
aster
```

无参数 `aster` 会直接进入持续对话；`aster doctor`、`aster run "任务"` 等子命令仍然可用。首次进入尚未初始化的目录时，它会显示规范化后的工作区并询问是否创建 `.astercode/`，不会静默授权用户主目录、磁盘根、系统目录或 UNC，也不会自动向上扩大到 Git 根。`aster` 与兼容命令 `astercode` 都强制把启动目录绑定成唯一 `authorized_root`；项目配置或 `ASTERCODE_PROJECT_ROOT` 不能扩大边界，也不能自行开启 live Provider、SSH、网络、浏览器、插件或桌面控制。live Provider 和模型只能由当前进程继承的用户环境变量明确选择。

新项目配置使用 `astercode.toml`；旧版 AsterCode `config.toml` 仍兼容。普通项目中碰巧存在的同名 `config.toml` 不会再被误当成 AsterCode 配置。若希望任意新项目都默认使用 DeepSeek，可一次性保存非秘密的 Provider/模型选择（API key 仍单独保存在用户环境变量中）：

```powershell
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_PROVIDER", "deepseek", "User")
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_ID", "deepseek-v4-flash", "User")
```

设置后需要完全重启 VS Code，让新进程继承用户环境变量。对话支持 `/help`、`/status`、`/new`、`/resume SESSION_ID` 和 `/exit`。P1-P3 动作会在终端显示风险、真实路径、参数或补丁，再接受“单次批准 / 当前会话内同一精确动作 / 拒绝 / 暂存”；普通自然语言永远不会被解释为审批。多轮对话会保留最近的用户与助手上下文，但审批 nonce 和凭证不会进入模型上下文。流式输出和恢复状态在显示前会转义终端控制字符；恢复时，旧状态只能收窄当前预算，崩溃中断的动作必须先只读核对。

## 不设置 API key 的离线运行

可以先不设置 key。Fake Provider 不访问网络：

```powershell
uv run astercode run "读取项目结构并给出摘要" --root . --fake
```

也可以使用授权工作区内的确定性 replay fixture：

```powershell
uv run astercode run "读取示例文件" --root . --replay tests/fixtures/read_then_complete.json
```

Fake Provider 不会凭空生成真实修改；要演示修改，请使用测试 fixture 或明确的结构化工具调用测试。每个结果都应以文件、diff、退出码或测试输出为证据。

## API key 与真实模型（可选）

API key 不写入代码、TOML、日志、prompt 或命令行参数。配置只保存环境变量名：

### OpenAI

```powershell
$env:OPENAI_API_KEY = "由 OpenAI 控制台新生成的 key"
$env:ASTERCODE_MODEL_PROVIDER = "openai"
$env:ASTERCODE_MODEL_ID = "你的账户实际可用模型 ID"
uv run astercode run "检查代码并提出修复计划" --root .
```

Linux bash 使用 `export OPENAI_API_KEY=...`、`export ASTERCODE_MODEL_PROVIDER=openai` 和 `export ASTERCODE_MODEL_ID=...`。

### DeepSeek

配置示例中的 `[model]` 可记录非秘密说明，但公共 CLI 不允许项目文件替用户开启 live Provider：

```toml
[model]
provider = "deepseek"
api_key_env = "DEEPSEEK_API_KEY"
base_url = "https://api.deepseek.com"
```

再通过环境变量提供 key 和模型 ID：

```powershell
$env:DEEPSEEK_API_KEY = "由 DeepSeek 平台新生成的 key"
$env:ASTERCODE_MODEL_ID = "deepseek-v4-pro" # 也可以使用 deepseek-v4-flash
uv run astercode run "检查代码并提出修复计划" --root .
```

还必须设置 `$env:ASTERCODE_MODEL_PROVIDER = "deepseek"`。Linux bash 对应使用 `export DEEPSEEK_API_KEY=...`、`export ASTERCODE_MODEL_ID=deepseek-v4-pro` 和 `export ASTERCODE_MODEL_PROVIDER=deepseek`。

AsterCode 的 DeepSeek 适配器使用 OpenAI 兼容的 Chat Completions，而不是 OpenAI Responses 或 Anthropic 协议。它把 `base_url` 固定并重新校验为 `https://api.deepseek.com`，请求 `/chat/completions`，以 `response_format={"type":"json_object"}` 获取严格的内部编排决策。`reasoning` 仅接受 `none`、`low`、`high`、`max`。流式响应只消费最终答案的 `content`，明确忽略 `reasoning_content`；内容会先完整通过 JSON、秘密和终止状态校验，再作为 delta 交给 CLI，避免跨分块秘密绕过脱敏。以上接口选择对应 DeepSeek 官方的[首次调用 API](https://api-docs.deepseek.com/zh-cn/)和[创建对话补全](https://api-docs.deepseek.com/api/create-chat-completion)文档。

两个 live Provider 都不接受环境变量改写网络路线：OpenAI 固定 `https://api.openai.com/v1`，DeepSeek 固定 `https://api.deepseek.com`；底层 HTTP client 使用 `trust_env=false`，不读取 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY` 或 `OPENAI_BASE_URL`。这只是 Provider 目的地固定和环境代理隔离，不代表 process/browser/SSH 已获得 OS 级网络沙箱。

Claude Code 的 `ANTHROPIC_*` 环境变量、`https://api.deepseek.com/anthropic` 端点以及带 `[1m]` 的 Claude Code 模型别名不会直接用于 AsterCode。这里的模型 ID 必须写成 `deepseek-v4-flash` 或 `deepseek-v4-pro`，不要写成 `deepseek-v4-pro[1m]`，也不要把 `deepseek-v4-flash/pro` 当作一个字面模型名。

如果模型 ID 和对应 key 都未配置，程序继续使用离线 Fake Provider；如果只配置其中一项，live 配置会 fail-closed，而不是偷偷换用另一家 Provider 的凭据。DeepSeek 已有上述三次只读 smoke 证据，但真实 OpenAI 仍未验证；真实 SSH 会话、浏览器外网和其他 live 能力也未验证。第一次 smoke 曾暴露流式分片造成的审计写放大、上下文重复导致的 Token 使用过高，以及 JSONL/SQLite 少一条记录的不一致；随后已完成 delta batching、context compaction、`status=running` 生命周期同步和审计镜像修复。执行 `uv run astercode audit repair --root . --confirm` 追加补回 1 条缺失记录并写入 `audit.mirror_repaired`，当时 `uv run astercode audit verify --root .` 返回 `valid=true, entries=2693`；当前工作区快照为 `valid=true, entries=2707`。第二次低预算复测 session `session_379c1fc09344409abb34c488d87a0bf3` 为 `completed`：实际 2 轮、1 次 P0 `fs.read`、13,636 tokens、约 12.2 秒。第三次复测 session `session_01990918f5774f83aca1bffe08f3d529` 同样为 `completed`：实际 2 轮、1 次 P0 `fs.read`、12,547 输入/1,214 输出（共 13,761）tokens、约 12.3 秒，且 `test_status` 只有一条对应记录，未复现重复项。两次窄任务均无审批，Provider 成本字段为 `null`。这些仍只是窄范围 smoke，不代表 OS 沙箱或其他 live 能力已完成。曾经暴露过的 key 应先在对应提供商控制台撤销，再生成新 key。

## 配置版本与安全迁移

配置文件使用严格的 `config_version = 1`。旧版 `[product]`、`[budgets]`、`[approval]` 等字段可以先预览规范化结果；预览只读，不会把当前 PowerShell/bash 环境中的 API key、模型名或其他环境覆盖写回配置：

```powershell
uv run astercode config migrate --root .
```

确认预览内容后才使用 `--write`。写入会在同一项目锁内重新读取并比较源文件身份和 SHA-256；源文件被并行修改时直接冲突退出，不创建备份、不覆盖文件。通过检查后，程序先保存逐字节相同的 `.v0.<nonce>.bak` 备份，再用临时文件、flush/fsync 和原子替换写入规范配置，并重新解析和校验。已经是当前版本时不会重复创建备份。高于当前支持版本或混用旧字段的配置会 fail-closed。环境变量只用于运行时覆盖，永远不会被迁移持久化。

仓库当前的 `config.toml` 仍保留旧格式以便现场兼容验证；上面的预览会报告 `changed=true`，但不会改文件。需要切换到规范 v1 文件时，先审阅预览，再显式执行 `uv run astercode config migrate --root . --write`。

## CLI 命令

```text
init, doctor, run, chat, resume, status, kill
sessions list/show/delete/export/reconcile
memory list/show/search/export/reindex/propose/commit/edit/conflicts/add/forget
config show/validate/migrate
permissions show/revoke/grants/revoke-grant
audit verify
ssh hosts list/test
```

`run --stream/--no-stream` 输出经过脱敏的 provider/tool 生命周期事件；`--replay` 只接受授权根目录内的 JSON fixture，且拒绝疑似秘密。`--dry-run` 会完整走参数校验和权限判定，但不会调用工具 handler，也不会伪装成验证成功。

每次 run 默认都有有限预算：40 轮模型调用、100 次工具调用、120,000 total tokens、100,000 input tokens、20,000 output tokens 和 3,600 秒。可以在 `[budget]` 中修改默认值，也可以只覆盖本次 run：

```powershell
uv run astercode run "只读检查 README.md" --root . --max-rounds 3 --max-tool-calls 2 --max-tokens 20000 --max-input-tokens 16000 --max-output-tokens 4000 --max-elapsed-seconds 180
```

这些参数是上限，不是模型一定会使用的额度；命令行覆盖只对当前 run 生效。

每次 Provider 调用只获得当前 run 的剩余时长，以及剩余 total/output token 中更窄的输出上限；返回后宿主再核对实际 usage，超限即失败。输入 token 无法在请求前可靠获知，只能在响应后计入并核对，不能承诺绝不发生单次输入超调。每次工具调用的 host timeout 取工具声明、参数和 run 剩余时长中的最小值。若配置了费用上限而 Provider 不能可靠报告费用，任务会在调用前 fail-closed，而不是假定费用为零。

用户明确要求修改代码时，可以为当前 run 加 `--allow-workspace-writes`，它只自动放行 P1 可逆工作区修改；P2-P4 仍会审批或拒绝。

## 权限等级

- **P0**：授权工作区内读取、搜索和 Git 只读查询，自动允许。
- **P1**：工作区内可逆写入；记录 diff，默认要求审批。
- **P2**：安装、网络、长期进程、未沙箱进程或越过普通边界；精确审批。
- **P3**：远程写入、commit/push、部署、sudo、服务启停、外部提交和敏感数据传输；逐项审批。
- **P4**：递归删除、强制推送、生产迁移、IAM/防火墙、reboot 等；默认拒绝。

提示词不是安全边界。`PolicyEngine` 和 `LocalToolGateway` 会重新按真实参数判定风险，工具或项目文件不能自我授权。P2 审批也不能替代 OS 边界：即使用户批准 `allow_unsandboxed`，普通 process/shell 在缺少经过验证的进程沙箱或网络策略时仍会被运行时代码拒绝。

通用 `process.exec`/`process.start`/`shell.exec` 也不能代替受控工具：直接或经解释器、wrapper 调用 Git、SSH、网络/外部服务、删除、服务或机器控制命令会被重新判为 P4 并拒绝，必须走对应的窄工具和审批路径。

查看当前策略：

```powershell
uv run astercode permissions show --root .
```

工具暂停时，审批绑定 action id、规范化参数哈希、cwd、真实路径、diff/主机指纹、nonce 和过期时间。参数变化后旧审批失效。拒绝审批后不能换工具绕过。

撤销或恢复：

```powershell
uv run astercode permissions revoke APPROVAL_ID --root .
uv run astercode resume SESSION_ID --root . --approve
uv run astercode resume SESSION_ID --root . --approve-session
uv run astercode resume SESSION_ID --root . --deny
uv run astercode permissions grants --session SESSION_ID --root .
uv run astercode permissions revoke-grant GRANT_ID --root .
```

`--approve-session` 只适用于 P1/P2，并绑定同一 session、规范化动作哈希、路径、cwd、参数和到期时间；P3/P4 不能获得会话级授权。

## 会话、恢复与 kill switch

```powershell
uv run astercode sessions list --root .
uv run astercode sessions show SESSION_ID --root .
uv run astercode sessions reconcile SESSION_ID --root .
uv run astercode status --session SESSION_ID --root .
uv run astercode sessions export SESSION_ID session.json --root .
```

工具前后会写 SQLite checkpoint。审批中断可在另一个进程用 `resume` 恢复；跨进程 process registry 会记录代理启动的 PID、身份 token 和 argv hash。无法确认副作用时状态为 `unknown`，恢复先做只读核对，不盲目重放。

全局停止：

```powershell
uv run astercode kill --root .
uv run astercode kill --root . --clear
```

kill switch 会持久化并阻止新工具调用，尽力终止已登记的本地进程树；操作系统无法确认的进程会报告 `unknown`。Windows 上，目标进程以 `CREATE_SUSPENDED` 创建，先加入 Job Object 再恢复执行；Job 使用 `KILL_ON_JOB_CLOSE`、树级 active-process、job-memory 和累计 user-mode CPU-time limit。本机已通过父子进程树的 Job close/`process.stop`、进程数/内存/CPU 限额，以及“Job 分配失败时目标 marker 不得出现”的测试。每次启动返回独立 `proc_...` 句柄，stdout/stderr 会持续排空并仅保留有界前缀，避免重复命令句柄碰撞和输出撑满管道。这个机制只负责进程树生命周期和资源约束，不是文件系统或网络沙箱；远程句柄和 POSIX 等价现场矩阵仍未完整验证。

## 三层记忆

- 短期：当前 run/turn 的目标、消息和工具结果。
- 中期：session、checkpoint、计划、活动文件、测试状态和审批。
- 长期：带 namespace、来源、置信度、TTL、标签、敏感等级和 supersedes 的稳定事实。

长期写入必须经过 propose → review → commit：

```powershell
uv run astercode memory propose "项目使用 pytest 校验" --namespace project --root .
uv run astercode memory commit PROPOSAL_ID --root .
uv run astercode memory edit MEMORY_ID "更新后的事实" --root .
uv run astercode memory conflicts --root .
uv run astercode memory list --root .
uv run astercode memory forget MEMORY_ID --root .
```

编辑会保留原 namespace、来源、TTL、置信度、标签和敏感等级，并以 supersedes 形成新版本；并发编辑冲突会被标记，不会静默覆盖。记忆始终只是建议，不能授权网络、SSH、删除或提权，也不会保存 key、cookie、私钥或审批凭证。

## 网络、SSH、浏览器与 GUI

- 网络默认 `deny_by_default`；当前没有经过验证的 OS egress/allowlist 沙箱，因此外部网络工具 fail-closed。此前 `allow_unsandboxed` 审批可能在 `deny_by_default` 下越过未验证网络边界的问题已经修复：生产 CLI 不注入伪造的 verified boundary，process/shell 即使获批也不会在无沙箱、无网络强制策略时启动。自动化测试只能通过显式依赖注入 deterministic verified boundaries 来覆盖执行路径，该测试注入不是生产能力。
- P0 Git 查询使用固定 Git 可执行文件和干净环境，设置 `GIT_NO_LAZY_FETCH=1`，避免 partial/promisor clone 在 status/diff/log/show/branch 中隐式联网；仓库配置若请求 filter/diff/merge 外部驱动、hooks、fsmonitor、外部 attributes/excludes 文件或 include 会在启动 Git 前拒绝，diff/show 同时禁用 external diff/textconv。这不把 Git push 变成 P0；push 仍是 P3 且网络边界未验证时 blocked。
- 当前 Windows 主机上的 AppContainer API 只是候选方案，尚未形成可验证 adapter；Windows Sandbox、Hyper-V、WSL、Docker/Podman 在本机不可用或当前非管理员账户无法启用。SSH、浏览器和其他真实网络能力因此继续保持 `BLOCKED`。
- `authorized_ssh_hosts = []` 时，运行时代码拒绝所有真实 SSH。现已实现默认关闭的系统 OpenSSH 命令通道：只有 `security.ssh.enabled=true`、非空精确 allowlist 和宿主注入的可信网络边界同时满足时才会装配；它固定使用系统绝对路径、`BatchMode`、专用 strict `known_hosts`、SSH agent/keychain，并禁用密码、配置文件、代理跳转、转发、X11 和连接复用。配置指纹必须由专用 `known_hosts` 中唯一的精确 host:port 公钥推导一致。真实上传、下载、远程 stat 和原子写回滚尚未实现，真实主机也未连接验证，因此 live SSH 继续 `BLOCKED`。审批动作仍绑定完整主机配置与 `known_hosts` SHA-256；远端停止无法确认时报告 `unknown`。
- `BrowserTools` 现有可选的 Playwright + Microsoft Edge 只读后端，始终使用非持久化 context，不复用用户 profile，并关闭 JavaScript、下载、权限和 Service Worker。每个请求和重定向都做 allowlist、DNS 私网/metadata 复核，但这只是纵深防御，不是 OS egress sandbox。本机只验证了 `about:blank` 无网络启动；正常 CLI 默认 `engine="disabled"`，且没有宿主网络证明时 policy 和 executor 都拒绝外网导航。真实下载和表单提交仍关闭；Fake Browser 继续用于确定性测试。
- 原生桌面 GUI 默认关闭，当前没有可用 live 适配器。
- MCP/Plugin 必须精确 pin 来源、版本、sha256 和 capability；扩展工具输入 schema 在注册时按 Draft 2020-12 严格校验，拒绝无效 schema、远程 `$ref`/`$dynamicRef`，并限制 schema 深度和节点数。manifest 自报的 read-only/risk 不是授权：实际参数会重新分类，`recursive=true` 或 `force=true` 等递归/强制动作至少按 P4 处理，命令、上传、发布和外部写入按 P3 或更高风险处理。Fake runner 可离线测试，真实隔离子进程尚未提供。
- 子代理必须同时开启 `features.multi_agent` 和 `security.subagents.enabled`，当前只允许授权工作区内的文件/Git 只读工具。运行前以 reservation 原子预扣父代理并发/工具/token/时长预算，调用前合并父代理实时已用量，完成后把 child usage 计回 parent；重启恢复会把未能确认结算的 reservation 按完整额度保守扣除。取消可以按 grant、指定 parent session 或全部子任务定向传播并等待清理。当前 child 仍与父进程同进程，只支持 offline Provider；live model delegation 和生产级进程隔离保持 `BLOCKED`。

SSH 详细说明见 [docs/ssh-test-environment.md](docs/ssh-test-environment.md)。不要使用 `StrictHostKeyChecking=no`、agent forwarding、ProxyCommand 或把私钥传给模型。

## 架构与数据

LangGraph 状态机为 `OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT`，结束状态为 `completed/partial/blocked/cancelled/failed`。工具统一返回 stdout/stderr、退出码、artifact、截断标志、副作用和错误。若进程 capture 因内存保留上限丢弃了输出后缀，artifact 会明确标记 `complete=false`、记录丢弃字节数并写入 incomplete marker；未保留的后缀不会被伪称已保存。artifact 自身超过磁盘预算时也会独立标记 `disk_complete=false`。

SQLite 使用 WAL 和显式 schema migrations，当前 schema v7；包含 sessions、turns、messages、events、checkpoints、tool_calls、approvals、session grants、artifacts、memory、runtime_processes、ssh_hosts 和审计表。每次初始化在任何可写连接、迁移锁或 DDL 之前先用只读连接做 schema preflight，并在取得迁移锁后再次复核；future version、非连续/gap 历史、伪造版本记录、关键表或列缺失，以及 `memory_fts` 不是 FTS5 虚表都会直接拒绝且不改变数据库。JSONL/SQLite 审计带哈希链，可验证但不宣称能抵抗拥有操作系统管理员权限的外部修改：

```powershell
uv run astercode audit verify --root .
```

当前工作区审计只是一个随运行增长的快照：本次核对为 `valid=true, entries=2707`（head `cf34941b...`）；历史 smoke 修复时的 `entries=2693` 是当时的记录数，不是永久基线。

## 测试与质量检查

```powershell
uv run pytest -q
uv run ruff check src tests
uv run mypy src tests
uv lock --check
uv pip check --python .venv\Scripts\python.exe
```

测试不需要 API key、真实网络或 SSH；使用 deterministic Fake Provider、Fake SSH、Fake Browser、Fake MCP/Plugin、Fake 子代理、临时 Git 仓库和 replay fixture。Windows Job Object 已通过本机父子进程树终止、`process.stop` 和分配失败不执行目标代码测试；这只证明进程树约束，不证明文件/网络隔离。2026-08-23 的 DeepSeek 只读 smoke 已通过，但不替代自动化测试，也没有证明成本、长任务、写操作或真实工具权限安全。Playwright + 本机 Edge 的 `about:blank` 离线 smoke 已通过，但外网导航未运行。Linux 实机 bash、PowerShell 7、真实 OpenAI、真实 SSH、浏览器网络、GUI、MCP/plugin live runner 和 OS 沙箱仍需独立验证。

本轮最终全量回归结果为 `323 passed, 10 skipped`；另有历史本机 Edge 离线 smoke `1 passed, 5 deselected`。skip 仍代表缺少相应平台/权限或 live 条件，不应解释成已通过。

## 常见问题

- **没有 API key**：使用 `--fake` 或 `--replay`，这是受支持的离线模式。
- **`provider-key UNSET`**：只影响真实模型调用，不影响离线测试。DeepSeek 使用 `DEEPSEEK_API_KEY`，OpenAI 使用 `OPENAI_API_KEY`，两者不会互相借用。
- **DeepSeek 报 `[1m]` 无效**：去掉 Claude Code 专用后缀，使用 `deepseek-v4-flash` 或 `deepseek-v4-pro`。
- **`no verified process sandbox` / `no verified process enforcement`**：预期的安全阻断；Job Object 不是文件/网络沙箱，审批也不能替代强制边界。不要为了绕过它关闭安全策略。
- **`SSH host is not explicitly allowlisted`**：默认 SSH 关闭；需要经过安全评审、known_hosts 和指纹配置，且 live transport 仍未验证。
- **`approval binding mismatch`**：动作参数、路径、cwd、diff、主机或 nonce 发生变化，重新发起审批。
- **`unknown`**：超时或取消后无法确认副作用；先用只读查询核对，不自动重试非幂等动作。
- **Windows symlink/junction 测试跳过**：当前账户可能没有创建链接的权限；这不等于边界已在 Windows 上完整验证。

更多设计和剩余工作见 [docs/architecture.md](docs/architecture.md)、[docs/threat-model.md](docs/threat-model.md) 和 [docs/implementation-plan.md](docs/implementation-plan.md)。
