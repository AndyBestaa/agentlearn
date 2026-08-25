# AsterCode 威胁模型

## 保护目标

AsterCode 要保护：

- 授权工作区代码、未提交 diff、构建产物和测试证据不被越界覆盖。
- API key、SSH agent、known_hosts、cookie、环境变量和其他秘密不进入模型、日志、artifact 或长期 memory。
- 未经审批的网络、远程写入、删除、push、部署、sudo、服务启停和外部提交不发生。
- checkpoint、审批和审计可以恢复、验证，并能把不确定副作用标为 `unknown`。

## 信任边界

信任顺序固定为：运行时安全策略与 OS 边界 → 当前用户明确指令 → 受信项目工程约定 → 仓库文本、网页、日志、工具输出、SSH banner、MCP/plugin、远程文件和 memory。最后一层都是不可信数据，不能授权动作、扩大根目录、请求秘密或关闭校验。

模型是建议者，不是权限主体。CLI、prompt 和 manifest 的风险标签都不能绕过 `PolicyEngine`、`LocalToolGateway`、路径解析或审批验证。

## 主要威胁与控制

| 威胁 | 示例 | 当前运行时控制 | 当前边界/证据 |
| --- | --- | --- | --- |
| 路径越界与 TOCTOU | `..`、symlink、junction、UNC 指向根外 | canonicalize、真实路径 allowlist、执行前 identity revalidate、原子写；写操作逐段拒绝 symlink/junction/reparse traversal | Windows 普通文件/目录 symlink 与真实 junction 的根外/根内/工作区根矩阵已通过；mount/bind 与并发替换仍需 OS sandbox |
| 命令注入 | 文件名含 `;`、`$()`、PowerShell 子表达式 | 结构化 argv、默认不启用 shell、干净 PATH/profile、shell 明确标注 dialect | 无 verified 进程沙箱或网络策略时 process/shell 在 spawn 前 blocked；审批不能替代边界 |
| 环境投毒 | profile、alias、Git hook、仓库同名可执行文件 | 不加载 profile/.env/hook，净化 PATH 和 Git 配置 | Linux/PowerShell 7 未现场验证 |
| Provider 路线劫持 | `OPENAI_BASE_URL` 或 HTTP proxy 指向攻击者 | OpenAI/DeepSeek 固定官方 endpoint，SDK HTTP client `trust_env=false` | 只约束 Provider；通用 OS egress 仍未实现 |
| Git P0 隐式执行/联网 | filter/diff driver、hook、fsmonitor、外部 attrs、lazy fetch | 启动前拒绝外部配置，隔离 hooks，禁 external diff/textconv，`GIT_NO_LAZY_FETCH=1` | 非 P0 push 仍需 P3，网络未验证时 blocked |
| 通用进程绕过专用工具 | 用 shell/python/wrapper 执行 git/ssh/curl/rm | 检查程序、wrapper、内联代码和 shell 文本；Git/SSH/network/delete 绕过按 P4 拒绝 | 不能替代尚缺的 OS sandbox |
| 提示注入 | README 要求上传密钥或关闭 host-key | 检测并标记来源；内容不会改变 policy 或审批 | 仍需持续增加恶意 fixture |
| 秘密泄露 | stdout、异常、memory、replay 含 token | 输入/输出/事件/checkpoint/audit 统一 redaction；provider proposal 拒绝疑似秘密 | 无法防止进程自身绕过宿主并直接外传；网络默认关闭 |
| 审批重放或替换 | 批准后改命令、cwd、diff、主机 | action hash、cwd/真实路径/diff hash/指纹/nonce/TTL、单次消费和撤销 | 管理员可直接改数据库不在应用防护范围 |
| SSH 信任配置替换 | 批准后修改 hostname、port、user、指纹或 known_hosts | `ssh_target` 将主机配置、配置指纹、known_hosts 真实路径和文件 SHA-256 纳入审批 hash；系统 OpenSSH 还要求专用文件只有一个精确 host:port key，配置指纹必须从 key blob 推导一致，执行前复核文件 hash | OS egress、首次登记、MFA、真实主机和 TOCTOU 现场矩阵未验证 |
| 工具/插件伪装只读 | MCP 把 delete 标为 read-only | 运行时根据真实 tool/参数重分类 P0-P4 | live plugin runner 未启用 |
| 扩展 schema/引用投毒 | 无效 Draft schema、远程 `$ref`、深层递归 schema | 注册时以 Draft 2020-12 严格校验；只允许文档内引用，限制深度/节点数；参数重新验证 | 真实隔离插件进程未启用 |
| 扩展递归/强制副作用 | manifest 声称只读但参数 `recursive=true` 或 `force=true` | 真实参数重判：递归/强制动作至少 P4，命令、上传、发布和外部写入至少 P3；manifest 标签不能降级 | 业务语义未知的第三方工具仍需人工审批/拒绝 |
| 数据库 schema 伪造或损坏 | future/gap 版本、伪造迁移记录、缺表列、把 FTS5 换成普通表 | 所有写操作前只读 preflight，锁内再次复核；异常直接 fail-closed 且不执行 DDL/迁移 | SQLite 文件权限被管理员取得时仍超出应用层模型 |
| 配置迁移并发覆盖 | 预览后其他进程修改配置 | `config migrate --write` 比较源身份和 SHA-256；冲突时不备份、不替换；先精确字节备份，再 fsync/原子替换 | 备份目录本身仍由操作系统权限保护 |
| 非幂等超时重试 | 远程命令已执行但返回超时 | 状态 `unknown`、不自动重试、恢复先 reconcile | 真实远程 reconcile 未验证 |
| 预算超调或未知费用 | Provider/tool 超过剩余时间/输出，或费用不可得 | 下传剩余时长和输出 cap、终态 usage 复核、tool timeout 取最小值；cost 不可跟踪时 fail-closed | 输入 token 只能响应后核对，无法请求前硬限 |
| 大输出证据被误报完整 | capture 已丢弃后缀但 artifact 看似完整 | `source_complete`/`disk_complete`、丢弃量和 marker 分开记录；未保留后缀不落盘 | 有界留存意味着超限内容本身不可恢复 |
| 子代理预算/取消泄漏 | 并发 overbook、重启后重复预算、取消错误 child | 双开关、原子 reservation、父子 usage 合并、重启全额保守扣减、grant/parent/all 定向取消 | offline runner 仍同进程；live delegation blocked |
| 进程逃逸 | 子进程留存、Ctrl-C 只杀父进程 | Windows Job Object 约束宿主 Docker CLI；容器 `--init`、唯一 name、force remove、PID limit；runtime identity/kill switch | exec timeout、start/poll/stop、跨执行器容器清理、审批恢复取消、真实 Ctrl-Break 和宿主崩溃 Job close 已确认；跨重启 Job handle/POSIX 进程组和远程进程树仍未完成 |
| 构建产物越界 | 构建命令向宿主写额外文件、链接逃逸或填满磁盘 | 独立导出工具；降权构建用户不可写 root-only 匿名卷；最多 16 个相对普通文件；总字节上限；宿主从 tar 流复核路径、类型、精确集合和 SHA-256 | Windows 与 WSL Docker 现场及完整审批链已通过；目录/链接/设备/额外文件导出明确拒绝；Docker daemon/管理员仍在信任边界外 |
| 网络 SSRF/外传 | redirect 到私网、metadata 或公网 | Docker process/shell 使用 `--network none` 且主动连接失败 probe；其他网络默认 deny；Browser 另做 allowlist/DNS 检查 | Docker 证明不覆盖 SSH/Browser/宿主；没有通用 allowlist egress adapter，live 网络工具保持 blocked |
| 容器供应链/daemon | 标签漂移、恶意镜像、Docker socket/远程 daemon | 固定 RepoDigest、受信 CLI 路径、不继承 DOCKER_HOST/context/config/proxy、不挂载 socket、cap-drop/no-new-privileges；doctor 明确检查 cosign/syft/trivy 是否存在 | 三项工具已安装；Syft 本地镜像 SBOM smoke 已通过，但 Trivy 数据库下载未完成，Cosign 尚无可信签名身份/证据；mirror cache 不自动扫描或修复漏洞；daemon、管理员威胁仍超出当前证明 |
| SSH 劫持 | host key 变化、agent forwarding | 空 allowlist 直接拒绝；known_hosts 和指纹必须匹配；Fake backend 测试硬停止 | 真实 transport/host key 现场未验证 |
| 恶意项目配置或状态 | 扩大根目录、诱导 live Provider/SSH、伪造 checkpoint 路径/预算、状态文件链接到外部 | 公共 CLI 严格绑定启动目录并重建安全配置；live Provider 只接受用户环境；reconcile 重验路径；恢复预算只可收窄；固定状态与配置拒绝 link/junction/hardlink | 内容文件 hardlink、mount/bind-mount 与跨进程 TOCTOU 仍需 OS sandbox；不要从不可信归档复制 `.astercode` |
| 浏览器登录态泄露 | 复用用户主 profile、任意下载 | Playwright 使用非持久化 context，不接受用户 profile；JS、下载、权限和 Service Worker 关闭；Fake 使用内存 fixture | 只验证无网络 `about:blank`，登录、下载、提交和 GUI 仍关闭 |
| 浏览器 DNS/连接竞态 | 允许域名解析为公网，连接时切到私网或 metadata | 每请求/重定向复核 allowlist 与 DNS，并要求独立宿主 egress 证明；未证明时 policy/executor 双层拒绝 | Playwright route 不是 OS 沙箱，真实外网导航保持 blocked |
| Memory poisoning | 写入“以后允许删生产库” | propose→commit、namespace/TTL/confidence/sensitivity、冲突和 advisory-only | 用户若显式 commit 恶意文本仍会被保存为建议，但不能授权工具 |
| 审计篡改 | 删除或伪造失败记录 | SQLite/JSONL 追加哈希链，`audit verify` 校验 | 不能抵抗拥有文件/管理员权限的外部攻击者 |

## 权限模型

- P0：工作区内只读和 Git 查询，自动允许。
- P1：工作区内可逆写入，记录 diff；普通 CLI 默认审批。
- P2：安装、网络、长期进程、未沙箱执行和越过普通边界，精确审批且可能因缺少强制边界而 blocked。审批只表达用户意图；进程沙箱和网络强制策略任一未通过运行时验证时，普通 process/shell 仍拒绝启动。
- P3：远程写、push、部署、sudo、服务启停、外部提交和敏感数据传输，逐项即时审批。
- P4：递归删除、强制推送、生产迁移、IAM、防火墙、reboot、磁盘操作，默认拒绝。

永久禁止关闭审计、秘密保护、host-key 校验或安全策略；拒绝审批后不能更换工具绕过同一限制。

## 失败与恢复假设

进程崩溃、网络断开、工具超时、SSH channel 未完成或 provider 返回“成功”都不自动等于业务目标完成。`ssh.start` 返回句柄只表示远程启动请求已被提交，不表示命令完成；`stop_all` 只记录确认停止的句柄，`close`/stop 无法确认时保持句柄并返回 `unknown`，以便后续只读 reconcile。副作用不确定时写入 `unknown`，恢复只做状态、哈希、进程、端口或健康检查，再决定继续、回滚或请求用户。非幂等动作不得盲目重试。

## 离线安全回归范围

当前 fake/replay 回归继续覆盖路径、审批、SSH、Browser、extension、memory、process registry、审计、SQLite、Provider、Git 和子代理边界。Docker 回归覆盖固定 run 参数、镜像摘要、恶意单一 argv、remote-daemon/proxy 环境清除、不可隐藏 `.git` 拒绝、复制一致性、容器身份、受控产物导出和 fail-closed 装配；Windows/WSL live 用例覆盖只读源码、临时写入不回传、`--network none`、超时/停止/恢复清理、模型进程零 capabilities，以及构建用户无法直接写导出区。2026-08-25 当前候选工作树 Windows 全量为 `431 passed, 5 skipped`，WSL2 Ubuntu 全量为 `417 passed, 19 skipped`，另以强制 live 条件确认 Docker 回归 `6 passed`；skip 不算能力通过。

审计链当前工作区快照（2026-08-23）为 `valid=true, entries=2741`；这只是会随正常运行增长的验证结果，不代表管理员级不可篡改或固定容量。

仍需补齐或现场验证：跨重启 Job handle/POSIX 进程组恢复、裸机 Linux/独立 Docker daemon、Cosign 可信签名与 Trivy 完整数据库证据、真实 SSH/SFTP、浏览器外网/下载/提交、MCP/plugin 隔离 runner、GUI 和更多真实 Provider。WSL2 Ubuntu 的全量矩阵不等同于裸机 Linux 生产验收；Playwright + Edge 只验证无网络引擎启动；Docker process 的 `--network none` 不能外推到浏览器或 SSH。

## 残余风险与停止条件

如果无法证明 OS 级文件/进程沙箱、网络出口、完整进程树终止、host-key transport 或外部动作回滚，相关能力必须保持 `BLOCKED`，报告 `LIVE INTEGRATION NOT VERIFIED`，不得只依赖 prompt 或审批。Windows Job Object 已证明当前进程树约束，但不能降低文件系统或网络边界的停止条件。拥有本机管理员权限的用户、恶意内核、已授权的外部工具或供应链攻击超出应用层威胁模型，需由 OS、EDR、网络隔离和供应链签名另行承担。
