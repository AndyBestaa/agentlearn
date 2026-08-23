# ADR-0001：项目根目录与运行时边界

- 状态：Accepted（M0）
- 日期：2026-08-22
- 决策者：当前认证用户/项目维护者

## 背景

当前进程工作目录是 `C:\Users\MT`，但该目录是 Windows 用户 Home，含大量与本项目无关的脚本、日志、缓存、`.ssh` 等敏感或高风险内容；其 `.git` 只是无有效 Git 元数据的空目录，`git rev-parse`/`git status` 均失败。已有 LangGraph starter 位于 `C:\Users\MT\langgraph-agent`，包含 `pyproject.toml`、`uv.lock`、`.venv` 和最小示例，但尚无 AsterCode 的文档、CLI、测试或执行器。

## 决策

将 `C:\Users\MT\langgraph-agent` 作为 AsterCode 的 `PROJECT_ROOT` 和唯一默认 `AUTHORIZED_ROOTS`。所有新代码、配置、文档、数据库和测试均放在该目录内；运行时拒绝 canonical path 越出该目录。`C:\Users\MT` 不作为授权工作区。

运行时目标采用 Python 3.12+、asyncio、LangGraph StateGraph；Provider 通过抽象适配 OpenAI Responses/Agents SDK，模型 ID 和凭据配置化。Windows 11 + Windows PowerShell 为当前主验证平台，Linux + bash 作为兼容目标。`AUTHORIZED_SSH_HOSTS=[]`、网络 `deny_by_default`、原生 GUI 和多代理默认关闭。

## 备选方案

1. **把 Home (`C:\Users\MT`) 作为根**：拒绝。会扩大文件读取/写入边界，可能暴露 `.ssh`、凭据和无关工作；也无法提供清晰 Git 项目边界。
2. **在 Home 下新建另一个目录**：暂不采用。会丢失现有 starter 的锁文件和 venv，并增加迁移成本；若未来需要发布可再迁移并更新本 ADR。
3. **直接使用现有 starter 的脚本结构**：仅作为兼容入口保留。AsterCode 将逐步迁移到 `src/` 包和 CLI，旧示例不被当作生产执行器。

## 后果

正面：默认授权面最小、可审计，依赖和测试可复现，避免把 Home 下敏感文件带入工具上下文。负面：用户要操作根外文件必须经过 P2/P3 精确审批和额外能力；当前目录不是 Git 仓库，M7 前需决定是否初始化/迁移版本控制（未经用户明确指令不自动执行）。

## 迁移与回滚

若用户明确指定另一工作区，必须先读取其可信配置、重新 canonicalize 根路径、更新配置和会话隔离，并记录新的 ADR；旧会话不得自动继承新根的审批。恢复默认只需将 `PROJECT_ROOT`/`AUTHORIZED_ROOTS` 设回本目录并使旧审批失效。
