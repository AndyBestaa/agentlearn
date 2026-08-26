# ADR 0005：Docker 临时可写进程沙箱

- 状态：Accepted（M2/M3 Windows + WSL2 live slice）
- 日期：2026-08-23

## 背景

Windows Job Object 已证明进程树终止和部分资源限额，但不能隔离文件系统或网络。生产结构化 `process.exec` 因此需要容器 attestation；generic `shell.exec` 因缺少 dialect-specific constrained adapter 仍始终 fail-closed。当前主机已安装 WSL2、Docker Desktop Linux engine 和 PowerShell 7，可以实现并现场验证结构化 process 的容器边界。

## 决策

当 `security.process.sandbox_backend="container"` 时，运行时仅从固定安装位置发现 Docker CLI，不继承 `DOCKER_HOST`、context、用户 Docker config 或 proxy 覆盖。只有以下检查全部通过才装配 `DockerProcessTools`：

1. 可连接的 Linux engine。
2. 配置镜像已在本地且具有不可变 RepoDigest；摘要与配置一致。
3. 主动 probe 证明容器根和宿主源码挂载只读。
4. 固定复制器把源码复制到有 512 MiB 上限的 tmpfs；其中写入成功且不会回写宿主。
5. `.astercode`、`.git`、`.venv`、`node_modules` 和常见缓存不进入工作副本。
6. `--network none` 的连接失败探测通过。

每次运行还固定使用非 root 数字 uid/gid、`--cap-drop ALL`、`no-new-privileges`、只读根和源码挂载、隐藏状态/VCS、PID/memory/CPU 限额和有界 tmpfs。复制与启动由固定 Python 模板完成，最终使用 `os.execvp` 执行模型 argv；模型文本不进入宿主或容器 shell。任何探测失败都回退到 fail-closed executor，而不是根据配置名称自报已隔离。

本机镜像固定为：

`mirror.gcr.io/library/python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a`

选择 `mirror.gcr.io` 是因为本机访问 Docker Hub 发生 TLS EOF，而 Google Artifact Registry 官方缓存可达。缓存不提供镜像漏洞修复或扫描；不可变摘要只防标签漂移，不证明镜像无漏洞。

## 结果与边界

正面：通过结构化 `process.exec` 调用已审查的 Python/bash 工作区文件，可在无网络临时副本中运行需要写缓存/构建产物的命令；宿主源码保持只读；源目录复制前后和副本内容通过 SHA-256 清单核对；容器退出即丢弃副本；超时和 stop 会删除容器并终止宿主 Docker CLI 树；持久化的容器名/标签/镜像身份允许重启后精确清理；`doctor` 能显示实际 attestation。generic `shell.exec` 不因该 Docker 证明而自动启用。

受控导出：普通 `process.exec` 的临时写入仍全部丢弃。只有独立的 `process.exec_export` 在精确审批后允许列出最多 16 个相对普通文件。受信包装器只在读取 mode-0700 源快照、调整临时副本属主和降权时持有 `DAC_READ_SEARCH/CHOWN/SETUID/SETGID`；模型命令执行前显式清空并核验 effective/permitted/inheritable/ambient capabilities。成功后，包装器按总字节上限把白名单普通文件写入 root-only Docker 匿名卷。容器停止后宿主以 tar 流读取，不把容器直接写入宿主目录，并拒绝越界路径、链接、设备、重复或额外条目，计算 SHA-256 后原子发布。匿名卷随容器清理。

负面：固定排除目录可能不适合所有项目；清单核对增加两次源码哈希开销且不是底层文件系统快照；导出当前仅支持普通文件，不支持目录、链接或增量回写；镜像只保证 Python 和 bash；镜像签名/SBOM/完整漏洞扫描及 Docker daemon/管理员威胁仍未完成。Windows 真实 Ctrl-Break、宿主异常退出 Job close 和 WSL2 Docker 全量矩阵已通过，但跨重启 Job handle、POSIX 进程组、裸机 Linux、SSH、浏览器和宿主网络不继承此证明。
