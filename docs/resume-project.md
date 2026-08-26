# AsterCode 简历项目说明

## 一句话项目描述

AsterCode 是一个基于 LangGraph 的 local-first 编程 Agent：通过结构化 Function Call 完成代码读取、最小修改、受控测试和 diff 验证，并由宿主实现权限分级、精确审批、Docker 隔离、checkpoint 恢复与审计。

## 推荐简历版本

**AsterCode｜本地优先、权限受控的编程 Agent**

技术栈：Python 3.12、LangGraph、Pydantic、Typer/Rich、SQLite WAL/FTS5、Docker、OpenAI Agents SDK/Responses API、DeepSeek Chat Completions、pytest

- 设计 `OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT` 状态机，将模型限制为结构化工具 proposal；宿主按真实路径和副作用执行 P0-P4 风险重判，审批绑定 action hash、cwd、diff、TTL 与一次性 nonce。
- 实现授权根内文件/Git 工具、原子 patch、秘密脱敏、工具前后 checkpoint、跨进程 resume、kill switch 与哈希链审计；使用 SQLite WAL/FTS5 管理 session、审批、三层记忆、artifact 和进程身份。
- 构建 Docker 本地执行边界：固定镜像 RepoDigest、只读宿主源码、临时可写副本、`--network none`、非 root、capabilities 清零及 CPU/memory/PID/tmpfs 限额；测试结果、退出码和 Git diff 作为完成证据。
- 建立 deterministic Fake/replay 与跨平台回归体系；上一已绑定 clean 候选（`833e3aaf...`）在 Windows 11 为 `472 passed, 5 skipped`，并通过 Ruff、mypy、lock、构建、packaged CLI smoke、clean preflight、固定 Docker Demo 和匹配 target SHA 的 GitHub Actions；当前未提交策略加固的本机结果为 `511 passed, 5 skipped`，尚未形成新的发布证据。独立 WSL2 矩阵尚未刷新，不能沿用历史数字，每个新候选仍以自身远端 CI 为最终证据。

## 30 秒口头介绍

> 这是我用 LangGraph 做的本地编程 Agent。和只做聊天或 Function Call Demo 不同，我把模型和执行权限拆开：模型只能提出结构化动作，宿主重新验证路径、风险和审批，再在受控工具或无网络 Docker 临时副本里执行。任务可以在审批点暂停、跨进程恢复，最终要靠测试退出码、diff 和审计链证明完成。我还做了 deterministic Provider 和 Windows/Ubuntu CI，现场可以用一个故障 calculator 项目演示从诊断、修改到沙箱测试的完整闭环。

## 面试可展开的工程难点

### 1. 为什么不让提示词做安全边界

仓库文件、网页、日志和工具输出都可能包含提示注入。AsterCode 不接受这些内容授权动作；Policy/Gateway 使用规范化后的真实参数重判风险，工具名或模型自报的 `read-only` 不能改变结果。

### 2. 审批为什么不能只弹一个 Yes/No

批准凭证绑定动作 hash、host、cwd、真实路径、diff/file hash、TTL 和单次 nonce。审批后替换参数、路径或补丁会立即失效；P3/P4 不能获得宽泛会话授权。

### 3. 如何区分“命令成功”和“任务完成”

统一 ToolResult 分离 stdout/stderr，记录退出码、artifact、截断和副作用；编排器还会核对测试、diff、状态和 checkpoint。超时且副作用不明时标为 `unknown`，恢复先做只读 reconcile，不盲目重试。

### 4. 如何让 Demo 可重复又不伪造结果

`scripts/resume_demo.py` 使用 deterministic Provider 固定工具决策，但默认通过真实 filesystem/Git/Docker adapter 产生结果。脚本先观察故障基线，再核对精确工具链、一次审批恢复、测试输出、最小 diff 和审计链；任何证据缺失都会失败。

## 现场演示命令

```powershell
cd C:\path\to\langgraph-agent
uv sync --extra dev
uv run python scripts/resume_demo.py --backend docker --cleanup
```

详细讲稿见 [demo-guide.md](demo-guide.md)。

## 证据边界

当前可合理表述：

- 本地文件修改、受控 Git、审批/resume、Docker 测试、checkpoint/audit 有真实实现与自动化验证。
- DeepSeek 有范围有限的真实只读、文件增删改和 Docker smoke。
- Fake SSH/Browser/MCP/Plugin 用于确定性协议和安全回归。

当前不要写成：

- “生产级通用电脑控制”或“可安全控制任意服务器”。
- “真实 SSH/SFTP、外网浏览器、GUI、插件隔离已全部上线”。
- “通过所有平台、所有模型、所有安全场景”。
- “OpenAI live 已验证”或把 DeepSeek smoke 外推为完整 Provider SLA/成本结论。

更准确的定位是：**可安装、可运行、可恢复、权限受控，并具备可复现本地代码闭环的工程化原型/作品集项目。**

## English resume bullets

- Built a local-first coding agent with LangGraph and schema-validated function calls; enforced P0-P4 policy decisions and hash-bound, single-use approvals in the host runtime instead of relying on prompts.
- Implemented workspace-scoped filesystem/Git tools, atomic patches, SQLite-backed checkpoints and memory, crash-safe resume, kill switch, redaction, and hash-chained audit evidence.
- Added an attested Docker execution slice with a pinned image digest, read-only host source, ephemeral writable workspace, no network, non-root execution, dropped capabilities, and resource limits.
- Developed deterministic replay/fake providers and cross-platform regression coverage; the previously bound clean candidate (`833e3aaf...`) passed 472 Windows tests with 5 platform skips, plus lint, typing, locked builds, packaged CLI smoke, clean preflight, the fixed Docker demo, and matching Windows/Ubuntu GitHub Actions. The current uncommitted hardening reruns at 511 passed and 5 skips locally but is not release evidence until a new clean target and CI run are bound. The standalone WSL matrix remains a separate unverified boundary; every new candidate is revalidated after push.
