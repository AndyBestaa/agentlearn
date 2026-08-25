# AsterCode 现场演示指南

本指南对应“可以写在简历上并现场演示的本地编程 Agent”目标。主演示是确定性、无凭据、可核验的本地闭环；真实 DeepSeek 对话仅作为可选加演，不是主演示成功的前提。

## 主演示：故障诊断到验证证据

### 前置条件

- Python 3.12+、uv、受信系统 Git。
- Docker Desktop 使用 Linux containers，且配置中的固定 Python RepoDigest 已存在。
- 不需要 API key，不需要 SSH，不需要外网浏览器。

先检查环境：

```powershell
cd C:\path\to\langgraph-agent
uv sync --extra dev
uv run astercode doctor --root .
```

然后运行唯一的固定入口：

```powershell
uv run python scripts/resume_demo.py --backend docker --cleanup
```

脚本会创建一个全新临时 Git 工作区，并且只在完整证据链成立时输出 `AsterCode resume demo: PASS`。`--cleanup` 只删除脚本自己在系统临时目录中创建且名称经过复核的目录，不会删除仓库或用户指定路径。

### 演示实际证明什么

1. `examples/resume_demo/` 的故障基线测试确实失败，而不是硬编码“先失败”。
2. deterministic Provider 依次提出 `fs.read → fs.read → fs.apply_patch → process.exec → git.diff → git.status`，模型本身不持有执行器。
3. 文件 patch 在授权工作区内真实落盘；进程动作进入精确 P3 审批并从持久化 checkpoint 恢复。
4. 回归测试在通过 attestation 的 Docker 边界中真实执行，要求只读宿主源码、临时可写副本和 `network=none` 等元数据。
5. 最终 diff 只能包含 `return left - right` 到 `return left + right` 的最小修复，Git status 只能报告 `calculator.py`。
6. SQLite/JSONL 审计链必须验证有效，并写出 `.astercode/resume-demo-evidence.json`。

deterministic Provider 固定的是“下一步提什么工具”，不是工具结果。文件内容、测试退出码、diff、Git status、沙箱元数据和审计链都由实际 adapter 产生并再次核验。

## 3 分钟讲解顺序

1. **问题**：LLM 能建议命令，但不能让提示词承担权限边界，也不能把“模型说成功”当成成功。
2. **架构**：LangGraph 负责可恢复循环；Provider 只返回结构化 proposal；宿主 Policy/Gateway 重新校验参数并执行。
3. **运行 Demo**：指出 baseline failed、一次精确 P3 approval/resume、Docker test passed、最小 Git diff 和 audit valid。
4. **安全边界**：Docker 证明只覆盖本地 process/shell；SSH、浏览器外网、GUI 和真实插件隔离仍然 blocked。
5. **工程证据**：展示 GitHub Actions badge、目标提交的 Windows/WSL 测试、Ruff、mypy、构建与 packaged CLI smoke。

建议现场原话：

> 我没有让模型直接拿 Shell。模型只提出 JSON 工具调用，宿主根据真实路径、参数和副作用重新分级；这里进程动作暂停为一次性审批，恢复后进入无网络 Docker 临时副本。最后不是看模型的总结，而是核对退出码、Git diff 和审计链。

## 保留工作区用于查看证据

不要加 `--cleanup`，脚本会在输出中显示临时工作区和 evidence JSON 的位置：

```powershell
uv run python scripts/resume_demo.py --backend docker
```

若要指定位置，该目标必须尚不存在，且不能同时使用 `--cleanup`：

```powershell
uv run python scripts/resume_demo.py --backend docker --workspace C:\Temp\astercode-resume-demo
```

可重点查看：

```powershell
git -C C:\Temp\astercode-resume-demo diff
Get-Content C:\Temp\astercode-resume-demo\.astercode\resume-demo-evidence.json
```

## 可选：真实模型对话

先只准备一份新的故障项目，不运行 deterministic Agent：

```powershell
uv run python scripts/resume_demo.py --prepare-only --workspace C:\Temp\astercode-live-demo
cd C:\Temp\astercode-live-demo
aster
```

随后输入：

```text
检查这个 calculator 项目，定位现有回归，做最小修复，运行最相关的测试并总结精确 diff。不要联网，不要 commit 或 push。
```

这一路径会使用当前终端显式配置的 Provider，并可能产生费用。不要把 API key 输入对话或写入项目；审批时逐项核对工具、路径、argv、cwd 和补丁。真实模型可能选择不同的安全步骤，因此它用于展示交互能力，不替代固定主演示的可复现验收。

## Fake fallback 的边界

Docker 暂不可用时可运行：

```powershell
uv run python scripts/resume_demo.py --backend fake --cleanup
```

该模式仍会真实创建临时 Git 仓库、应用文件 patch、生成 diff/status、执行审批恢复和验证审计，但测试执行器只核对固定 fixture 字节。输出和 JSON 会明确写 `SIMULATED` / `execution_simulated=true`；不得把它描述成真实进程或沙箱验证。

## 常见失败

- `attested Docker sandbox is unavailable`：Docker engine、固定镜像或主动 probe 未通过。运行 `uv run astercode doctor --root .`；不要通过关闭策略绕过。
- `refusing to overwrite an existing demo path`：换一个尚不存在的 `--workspace` 路径。
- baseline unexpectedly passed / fixture changed：示例 fixture 已被改动；先检查 Git diff，不要让 Demo 猜测新基线。
- 审批或工具链数量不匹配：说明运行时行为偏离固定验收，脚本应失败；先修复再演示，不能手工改 PASS 输出。

## 明确不演示

- 不连接真实 SSH 或生产主机。
- 不进行 Git push、发布、部署、sudo 或外部表单提交。
- 不声称 Fake SSH/Browser/MCP/Plugin 等于真实集成。
- 不展示、复制或记录 API key、SSH 私钥、cookie、审批 nonce。
