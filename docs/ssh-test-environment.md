# SSH 测试环境与边界

## 默认行为

真实 SSH 默认关闭：`security.authorized_ssh_hosts = []` 时，`SSHTools` 在运行时直接拒绝所有连接。当前发行版包含一个受限的系统 OpenSSH 命令 transport，但正常 CLI 不注入可信 SSH 网络边界，因此不会装配它。只有 `security.ssh.enabled=true`、非空精确 allowlist 和宿主运行时证明网络只能到达批准目标三者同时成立，才可能进入连接路径；这仍不等于真实连接已经验证。

不要把私钥、密码、token 或完整 `~/.ssh` 复制到项目、日志、prompt、replay 或 memory。禁止 `StrictHostKeyChecking=no`、`AutoAddPolicy`、agent forwarding、X11、端口转发、ProxyCommand 和共享 ControlMaster。

## 离线 Fake SSH

测试使用 `FakeSSHBackend` 和内存文件/命令，不打开 socket，也不读取真实 SSH agent。`tests/security/test_ssh_fake.py` 覆盖：

- 空 allowlist 即使注入 fake backend 也会拒绝。
- known_hosts/指纹匹配后进行 `test_connection`、`exec`、`start/poll/stop`、`stat`、`close`。
- host key 变化在命令前硬停止。
- 远程命令超时返回 `unknown`，不自动重试。
- 上传/下载检查大小与 SHA-256，并用本地临时文件原子替换。
- 本地传输路径不能越出 `AUTHORIZED_ROOTS`，symlink 路径被拒绝。

Fake backend 只是 deterministic test adapter；它不能证明真实 SSH、PTY、认证、MFA、网络策略或远程回滚已可用。

系统 OpenSSH 窄切片只支持命令 channel。它固定受信系统绝对路径和结构化 argv，使用 `-F none`、`BatchMode=yes`、`StrictHostKeyChecking=yes`、专用 `UserKnownHostsFile`，仅允许现有 SSH agent/keychain，并禁用密码、键盘交互、GSSAPI、agent/X11/端口转发、ProxyCommand/ProxyJump 和 ControlMaster。专用 known_hosts 必须只有一个精确 host:port 公钥条目，配置的 SHA-256 指纹必须由该 key blob 推导一致；文件在 session 内发生变化会硬停止。上传、下载、远程 stat 和写入全部继续拒绝。

## 安全 fixture 示例

fixture 只在测试代码中创建临时 `known_hosts` 和随机/固定测试指纹，不使用用户目录：

```python
host = SSHHostConfig(
    host_id="dev",
    hostname="example.test",
    port=22,
    user="tester",
    host_key_fingerprint="SHA256:offline-test-fingerprint",
    known_hosts=tmp_path / "known_hosts",
)
```

运行离线回归：

```powershell
uv run pytest tests/security/test_ssh_fake.py -q
uv run astercode ssh hosts list --root .
uv run astercode ssh hosts test example --root .
```

最后一条在默认空 allowlist 下应返回 blocked/failed，不会发起网络连接。

## 未来 live 验证前置条件

只有在独立安全评审后，才允许在**非生产、临时测试主机**上进行人工验证：

1. 使用一次性测试账户和测试密钥；密钥由 SSH agent 或 OS secret store 提供，不进入命令行和文件。
2. 在授权配置中填写准确 `host_id`、hostname、port、user、known_hosts 路径和指纹。主机必须通过可信渠道核对指纹；不能接受 banner 或模型提供的指纹。
3. 先运行只读 `ssh.test_connection`、`ssh.stat` 和无副作用命令，并在 P3 审批界面核对规范化 host/cwd/payload。
4. 远程写入必须先读取原始 hash/权限/属主，创建受控备份，上传同文件系统临时路径，校验 SHA-256，做语法检查/测试/diff，再原子替换并健康检查。
5. 超时或 channel 断开时标记 `unknown`，先 reconcile；不得自动重复非幂等命令。
6. 测试结束后关闭 session、停止远程句柄、删除临时数据并检查审计没有秘密。

在真实主机、认证/MFA、网络出口和回滚方案都没有证据之前，报告必须写 `LIVE SSH NOT VERIFIED`，相关工具保持 fail-closed。`AUTHORIZED_SSH_HOSTS` 非空本身不等于已经获得连接授权；transport 代码存在也不等于它会被正常 CLI 装配或已经连接成功。
