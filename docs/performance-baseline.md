# AsterCode 本地性能基线

基线日期：2026-08-23（审计一致性修复后）。环境：Windows 11、CPython 3.12.12、本地临时 SQLite WAL；不使用 API key、网络或 SSH。

运行命令：

```powershell
uv run python scripts/performance_smoke.py
```

本机一次实测：

| 项目 | 结果 |
|---|---:|
| 1 MiB 文本秘密脱敏 | 43.696 ms |
| 新建并迁移 schema v7 | 119.464 ms |
| 写入 100 个带 SQLite/JSONL 审计事件 | 6844.912 ms |
| 审计链验证 | 100 entries，valid=true |

该脚本是回归烟雾测试，不是跨机器性能承诺。它在临时目录运行，阈值为 1 MiB 脱敏小于 2 秒、100 个审计事件小于 10 秒且哈希链有效。真实 Provider、网络、SSH、Playwright 和 Linux 性能不在该基线内。

## 现场 DeepSeek 观察（不是性能基线）

2026-08-23 在 Windows 11 / Python 3.12.12 上完成了三次真实、只读的 DeepSeek smoke：

| 项目 | 第一次较宽项目检查 | 第二次低预算窄任务 | 第三次低预算复测 |
|---|---:|---:|---:|
| 模型 | `deepseek-v4-flash` | `deepseek-v4-flash` | `deepseek-v4-flash` |
| session 结果 | `completed` | `completed` | `completed` |
| session ID | 未在本基线记录 | `session_379c1fc09344409abb34c488d87a0bf3` | `session_01990918f5774f83aca1bffe08f3d529` |
| 模型轮数 | 8 | 2 | 2 |
| 只读工具调用 | 12 | 1 次 `fs.read` | 1 次 `fs.read` |
| 输入 Token | 未单独记录 | 12,601 | 12,547 |
| 输出 Token | 未单独记录 | 1,035 | 1,214 |
| 总 Token | 148,994 | 13,636 | 13,761 |
| 端到端耗时 | 约 4 分 28 秒 | 约 12.2 秒 | 约 12.3 秒 |
| API 成本 | 未从 DeepSeek 账单核对 | `null` | `null` |

第二次运行的预算为最多 3 轮、2 次工具调用、20,000 总 tokens、16,000 输入 tokens、4,000 输出 tokens 和 180 秒。任务明确限制为只读取 README 前 30 行、用三句话总结且不递归；运行实际遵守该边界，仅执行 P0 读取，无审批和副作用。第三次使用同样窄的 3 轮/2 工具预算，只读取 README 前 10 行并输出一句话；同样只有一次 P0 读取，且 `test_status` 只有一条对应记录。

第一次任务只读取 README 和项目结构，没有文件写入、Shell/Git 副作用、SSH、浏览器或外部提交。它曾暴露重复上下文和过细流式分片造成的高 Token 使用与审计写放大；运行结束后 `astercode audit verify` 还发现 JSONL/SQLite 少一条记录。随后已完成 delta batching、context compaction、`status=running` 生命周期同步和审计镜像修复：`audit repair --confirm` 追加 1 条 `audit.mirror_repaired` 后，当时 `audit verify` 实测 `valid=true, entries=2693`。当前工作区快照（2026-08-23）再次核对为 `valid=true, entries=2707`，这只是随运行增长的记录数，不是性能基线。

配置迁移和数据库 schema preflight 的安全检查未纳入上述性能数字：它们在任何写入前执行，只读拒绝 future/gap/伪造 schema、缺列或非 FTS5；配置写入还包含逐字节备份、冲突检测和原子替换，需要后续单独建立带磁盘/SQLite 版本矩阵的基准。

后两次的约 13.6k tokens 和 12 秒明显低于第一次的 148,994 tokens 和约 4 分 28 秒，但任务范围不同，后两次还有严格的轮数、工具和 Token 预算，因此不能把差异全部归因于实现优化。三次观察都不是 SLA、账单成本估算、受控 A/B 基准或完整 live/OS 能力证明。
