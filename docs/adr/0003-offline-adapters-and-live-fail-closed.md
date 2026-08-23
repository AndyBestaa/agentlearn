# ADR 0003：离线适配器与 live fail-closed

- 状态：Accepted
- 日期：2026-08-22
- 更新：2026-08-23（加入默认关闭的真实 transport 窄切片）
- 范围：M5 SSH、M6 Browser/MCP/Plugin/Subagent，以及尚未具备 OS 强制边界的网络/进程能力

## 背景

AsterCode 需要在没有 API key、真实 SSH、浏览器或外部网络的开发环境中持续建设和回归安全边界。直接把未验证的 live transport 接入生产工具集，会把“代码路径存在”误报成“安全能力可用”，也可能在测试期间读取秘密或连接真实主机。

## 决策

1. 为外部能力提供 deterministic fake/replay adapter：
   - Fake SSH 使用内存 host、命令、远程文件和固定指纹；测试 host-key 变化、超时、句柄和 SHA-256 传输。
   - Fake Browser 使用 allowlisted URL fixture，不打开网络；测试 redirect、DNS rebinding、私网/metadata、下载路径和表单审批。
   - Fake MCP/Plugin 使用精确 source/version/sha256/capability pin 与 deterministic runner；运行时按真实参数重分类风险。
   - Fake 子代理只允许父代理权限交集中的只读工具，并继承更窄的预算、根目录、深度和并发限制。
2. live adapter 必须独立报告验证状态，并在缺少强制边界时 fail-closed：
   - `authorized_ssh_hosts=[]` 直接拒绝真实 SSH。
   - 没有已验证 OS egress/sandbox 时，网络工具和未沙箱 process 不得通过配置或 prompt 放行。
   - Playwright + Edge 只读后端即使具备隔离 profile、域名 allowlist 和解析地址检查，没有独立 OS egress 证明时仍只返回 blocked。
   - 系统 OpenSSH 命令后端只有在配置启用、非空精确 allowlist 和宿主 SSH egress 证明同时存在时才装配；文件传输和远程写在原子回滚方案完成前硬拒绝。
   - 没有隔离子进程、固定来源和网络策略时，MCP/plugin live runner 只返回 blocked。
   - GUI 默认关闭。
3. fake 适配器不得被标记为生产隔离边界。测试结果必须在报告中标为 offline/fake；真实集成缺少凭据时标为 `LIVE INTEGRATION NOT VERIFIED`。
4. 将 schema v7、memory edit/conflict、session grants、stream/replay、process registry/kill 和 audit verify 作为本地安全垂直链路的一部分，先于 live 外部连接完成。

## 取舍与替代方案

- **把已安装的 OpenSSH/Playwright transport 直接视为安全边界**：拒绝。它们只解决 transport 或浏览器引擎，不自动解决 egress、DNS 竞态、host-key 登记、回滚、供应链 pin 或审批。允许实现和离线验证默认关闭的窄适配器，但正常 CLI 在缺少宿主证明时仍不装配或不执行网络动作。
- **只在 prompt 中声明“不要连接真实主机”**：拒绝。prompt 不是安全边界，运行时代码必须拒绝。
- **完全删除外部能力接口**：拒绝。保留严格 schema 和 fake contract，便于在独立评审后替换 adapter，而不让模型获得任意 Shell。

## 后果

正面：无需 API key 或网络即可运行大多数测试；安全回归可重复；真实集成状态不会被 fake 结果掩盖；未来 transport 可以在同一 policy/gateway 契约下替换。

代价：当前 CLI 不能声称可连接真实 SSH、浏览器或插件；网络和未沙箱 Shell 会被阻断；fake runner 不证明 OS 隔离、MFA、PTY、回滚或供应链安全。

## 验收证据

- `tests/security/test_ssh_fake.py`
- `tests/security/test_openssh_transport.py`
- `tests/integration/test_m6_offline_adapters.py`
- `tests/security/test_m6_extension_browser_boundaries.py`
- `tests/unit/test_playwright_browser.py`
- `tests/unit/test_storage_migrations_memory.py`
- `tests/integration/test_replay_cli.py`
- `tests/security/test_process_registry_kill.py`
- `uv run astercode audit verify --root .`

在真实 OpenAI、SSH 会话、浏览器外网、GUI、MCP/plugin runner、OS sandbox/egress 和 Linux/PowerShell 7 验证完成前，本 ADR 的 fail-closed 决策继续有效。系统 OpenSSH transport 代码与 Edge `about:blank` smoke 不改变这一结论。
