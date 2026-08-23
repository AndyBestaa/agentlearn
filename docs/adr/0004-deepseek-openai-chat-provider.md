# ADR 0004：DeepSeek 使用 OpenAI 兼容 Chat Completions

- 状态：Accepted
- 日期：2026-08-23
- 范围：Model Provider、配置、流式输出、凭据与 endpoint 边界

## 背景

AsterCode 已有基于 OpenAI Agents SDK/Responses API 的 Provider，但 DeepSeek 官方提供的是 OpenAI/Anthropic 兼容接口。AsterCode 需要支持 DeepSeek，同时保持已有原则：模型只能提出结构化编排决策，不能直接获得执行器；凭据不进入配置、prompt、日志或 memory；Provider 不能借任意 `base_url` 把 key 发送到仓库控制的服务。

DeepSeek 官方[首次调用 API](https://api-docs.deepseek.com/zh-cn/)列出 OpenAI 兼容根地址 `https://api.deepseek.com`、模型 `deepseek-v4-flash`/`deepseek-v4-pro` 和 `client.chat.completions.create` 用法；官方[创建对话补全](https://api-docs.deepseek.com/api/create-chat-completion)定义 `/chat/completions`、流式 delta、`reasoning_content` 与 `response_format={"type":"json_object"}`。

## 决策

1. 新增独立 `DeepSeekChatProvider`，配置值为 `provider="deepseek"`。它使用 OpenAI Python 客户端的 Chat Completions，而不是 OpenAI Responses/Agents SDK 编排路径。
2. key 只从配置引用的环境变量读取，默认是 `DEEPSEEK_API_KEY`；模型 ID 从 `model_id`、`ASTERCODE_MODEL_ID` 或 DeepSeek 专用兼容变量读取。DeepSeek Provider 不读取 `OPENAI_API_KEY` 或 Claude Code 的 `ANTHROPIC_*`。
3. `base_url` 在 Provider 内固定并规范化为 `https://api.deepseek.com`。拒绝 HTTP、凭据内嵌 URL、非官方主机、非默认端口、query/fragment、任意 path 和 `/anthropic`，防止 API key 被重定向到不可信目标。
4. 模型 ID 使用官方 Chat API 当前列出的 `deepseek-v4-flash` 或 `deepseek-v4-pro`。Claude Code 的 `[1m]` 后缀不是此 Provider 的字面模型 ID，配置时明确拒绝。
5. 请求把运行时系统提示词与 Provider request JSON 分为 system/user message，设置 `response_format={"type":"json_object"}`，要求恰好返回一个满足本地严格 schema 的编排决策。模型仍不直接执行工具；所有 proposal 继续经过 PolicyEngine、审批和 ToolGateway。
6. 非流式与流式响应都只接受完整、可解析的最终 JSON。流式路径缓冲 `delta.content`，忽略 `reasoning_content`，待完整 JSON、秘密扫描、严格 usage 与唯一 `stop` 终态全部校验后再转发 delta，不记录或向用户暴露隐藏思维链。缺失/矛盾 usage、重复终态、终态后内容、额外 choice、超长或无效 JSON 都 fail-closed。
7. 没有 key 时继续使用 Fake/replay 完成本地测试；只配置模型或只配置 key 的部分 live 配置必须 fail-closed。2026-08-23 已完成三次真实 `deepseek-v4-flash` 只读 smoke，以及一次同会话的两轮创建、修改、删除受控回归（session `session_d6dfa158b9ae42b188991116b77858bd`，7 个用户 turn、6 次单次审批、6 次副作用工具调用）；成本、Shell、长任务、故障恢复和其他模型仍未验证。

## 未采用方案

- **把 DeepSeek 塞入 OpenAI Responses Provider**：不采用。AsterCode 当前 OpenAI 路径依赖 Responses/Agents SDK，而 DeepSeek 文档契约是 Chat Completions；混用会掩盖请求/流式差异。
- **复用 Claude Code 的 Anthropic endpoint 与 `ANTHROPIC_*`**：不采用。Claude Code 的接入变量和 `[1m]` 别名属于另一客户端契约，不能直接推导为 AsterCode 配置。
- **允许任意 OpenAI-compatible `base_url`**：不采用。它会扩大网络目的地，并可能把 DeepSeek key 发送到不可信代理。
- **保存或输出 `reasoning_content`**：不采用。AsterCode 只保存简短可审计决策与证据，不采集隐藏思维链。

## 后果

正面：Provider/凭据边界清晰；DeepSeek 可复用成熟 OpenAI Chat 客户端；结构化 JSON 与现有 policy/gateway 对接；endpoint pin 降低 key 外传风险；Fake/replay 工作不依赖真实 key；一次真实只读 smoke 已验证基本请求链路。

代价：不能直接粘贴 Claude Code 的 `ANTHROPIC_*` 配置；不能使用 `[1m]` 别名或任意兼容代理；Chat 与 Responses 两条 Provider 路径需要分别维护与测试；一次 smoke 不能替代完整 live 验证。该 smoke 曾暴露流式审计写放大、重复上下文和 JSONL/SQLite 一条记录不一致问题，随后已通过 delta batching、context compaction、状态同步和审计镜像修复并回归。

## 验收要求

- 配置解析必须把 `provider="deepseek"` 默认绑定到 `DEEPSEEK_API_KEY` 和官方 base URL。
- 单元测试必须离线验证 endpoint pin、凭据隔离、模型别名拒绝、JSON decision 解析、stream content、`reasoning_content` 忽略、usage 和错误 fail-closed。
- 文档示例不得包含真实 key，也不得暗示 `ANTHROPIC_*` 可直接复用。
- 真实 smoke 仅在用户明确提供安全凭据与低预算授权后运行；已运行的 smoke 必须标注范围、token、耗时和成本是否核对，不能扩展为其他 live 能力的完成声明。历史 smoke 的审计不一致已通过 `audit repair --confirm` 和 `audit verify`（`valid=true, entries=2693`）修复并回归；管理员级审计防篡改和其他 OS/live 边界仍需独立验证。
