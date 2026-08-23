# ADR-0002：LangGraph 外层状态机与 OpenAI Agents SDK 适配边界

## 状态

Accepted（2026-08-22）。

## 决策

- LangGraph `StateGraph` 是 AsterCode 的外层生命周期状态机，显式维护 `OBSERVE → PLAN → POLICY_CHECK → APPROVAL_GATE → TOOL_CALL → CAPTURE → VERIFY → CHECKPOINT`。
- OpenAI Agents SDK `0.22.0` 只作为可替换的 OpenAI Responses Provider；它只能返回结构化计划/工具提议，不能直接执行 AsterCode 的本地工具。
- 本地工具经宿主 `ToolRegistry → PolicyEngine → LocalToolGateway → Executor`，SDK 的 `needs_approval` 不被当作唯一安全边界。
- 使用 `langgraph-checkpoint-sqlite==3.1.1` 的 `AsyncSqliteSaver` 保存 LangGraph interrupt；产品自己的 SQLite 表使用独立数据库文件，避免与 checkpointer 的 `thread_id` schema 冲突。
- 使用 Pydantic 严格模型和 JSON Schema 校验工具输入，`jsonschema` 作为显式依赖。

## 理由

Agents SDK 当前提供 Agent/Runner、FunctionTool、RunState 审批恢复和 SQLiteSession，但 SDK Session 是会话历史，不是本产品的长期语义记忆。外层状态机便于把审批、预算、kill switch、审计和未知副作用恢复放在模型之外。

## 替代方案

- 只使用 Agents SDK：无法把产品级本地 checkpoint、跨工具策略和自有审计统一到一个可替换层。
- 只直接调用 Responses API：可以减少依赖，但放弃 Agents SDK 当前的结构化输出、Runner 和 HITL 适配能力，迁移成本更高。
- 共用产品 SQLite 表与 LangGraph saver：实际 schema 不兼容，已验证会产生 `no such column: thread_id`，因此拆分文件。

## 迁移与验证

升级 Agents SDK 时重新核对官方工具、HITL、Sessions、Tracing 文档和本机类型定义，并运行 `uv run pytest -q`、`uv run ruff check .`、`uv run mypy src tests`。本次实现前已读取本机 `openai-agents==0.22.0` 的 `Runner.run_streamed(...)` 签名、`RunResultStreaming.stream_events()` 和结果字段，并以完全离线 monkeypatch 测试验证 delta→严格最终结构化决策的转换。真实 Provider smoke test 仍需要用户提供当前有效凭据；本次未运行。

## 2026-08-22 官方资料复核

- 官方 [Running agents](https://openai.github.io/openai-agents-python/running_agents/) 文档仍将 `Runner.run_streamed()` 与 `RunResultStreaming.stream_events()` 作为流式执行接口；本机锁定版本的实际签名与当前适配器使用方式一致。
- 官方 [Human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/) 文档使用 `interruptions`、`RunState` 和 approve/reject 恢复暂停调用。AsterCode 不把 SDK 审批当作安全边界，仍由独立 policy/gateway 按真实动作复判并持久化精确凭证。
- 官方 [Sessions](https://openai.github.io/openai-agents-python/sessions/) 文档说明 SDK session 用于对话历史；因此本产品继续把 checkpoint、中期状态和长期语义记忆分开存储，不把 SDK session 冒充长期记忆。
- 官方 [Function Calling](https://developers.openai.com/api/docs/guides/function-calling) 文档建议 strict schema，并要求对象 `additionalProperties=false` 且字段全部 required（可选值用 nullable 表示）。当前 AsterCode 不把执行器直接暴露成 SDK function tools，而是接收结构化“工具提案”后在本地按每个 ToolSpec schema 再验证；未来若改为直接注册 function tools，必须先做 strict-schema 转换和回归测试。
- 官网内容可能领先于锁定的 SDK。生产实现以本机 `openai-agents==0.22.0` 类型定义为准，升级前不得直接照抄新文档接口。
