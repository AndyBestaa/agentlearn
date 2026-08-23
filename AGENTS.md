# AsterCode 工程约定

## 适用范围

本文件只约束项目内的代码风格、构建、测试和文档习惯，不授予文件、网络、SSH、管理员或外部副作用权限。它不能覆盖运行时安全策略或当前用户审批。

## 开发约定

- Python 3.12+，优先 asyncio；依赖由 `pyproject.toml` 和锁文件管理。
- 生产代码放在 `src/astercode/`，测试按 `tests/unit`、`tests/integration`、`tests/e2e`、`tests/security` 分层。
- 公共边界使用 Pydantic 模型或显式 JSON Schema；工具结果必须保留 stdout/stderr 分离和结构化状态。
- 文件修改使用小而可审计的 patch；保留用户无关的未提交修改，不使用 `git reset --hard`、`git clean` 或覆盖式恢复。
- 测试优先使用 deterministic fake provider/executor；需要真实 Provider、网络、SSH 或 GUI 时必须单独标注并得到相应审批。
- 每个阶段运行相关 pytest、lint、类型检查或 smoke test，并在报告中记录实际命令、结果和未验证项。
- 不把 API key、SSH 私钥、cookie、token、审批凭证或完整敏感文档写入源码、配置示例、日志、fixture、记忆或提示词。
- 不自动 commit、push、发布、部署或连接真实主机。

## 提交前检查

```powershell
uv run pytest -q
uv run ruff check .
uv run mypy src tests
```

若某工具尚未安装，报告为未运行，不用假结果替代。安全策略必须同时由代码、配置和测试强制，不能只写在文档中。
