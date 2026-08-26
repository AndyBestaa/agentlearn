# AsterCode 发布检查清单

本清单用于准备作品集/简历演示版本。旧提交的测试数字和绿色 CI 不能自动继承到新提交；每条完成项都必须绑定目标 commit 和实际命令输出。v0.1 的场景级验收定义与 fake/Docker 证据边界见 [v0.1 验收矩阵](v0.1-acceptance-matrix.md)，本清单中的发布门槛应与该矩阵保持一致。

本轮阶段 1–4 的本地候选实测记录见 [v0.1 RC 候选报告](v0.1-rc-report.md)。目标候选必须是 clean `HEAD`；以供应链 manifest 的 `target_commit` 和 GitHub Actions 的同 SHA `head_sha` 绑定本地 Docker、测试和供应链状态。每个新的目标提交仍必须重新执行 clean preflight、Docker、供应链和远端 CI，不能直接继承旧数字或状态。

## 1. 冻结范围

- [ ] 明确目标：local-first 代码读取/修改/测试/diff + policy/approval/resume/audit + Docker 演示。
- [ ] 通用 `shell.exec` 在 dialect-specific constrained adapter 验证前继续标记 `BLOCKED`；真实 SSH、外网 Browser、GUI、生产 MCP/Plugin 隔离继续标记 `LIVE INTEGRATION NOT VERIFIED` 或 `BLOCKED`。
- [ ] 不把 Fake adapter 结果写成真实连接，不把 Docker process 边界外推为 SSH/Browser egress。
- [ ] 不在本轮顺带加入部署、push、远程写或生产凭据。

## 2. 工作树与版本

```powershell
git status --short
git diff --check
git diff --stat
uv lock --check
```

- [ ] 审阅所有未提交文件，确认没有覆盖用户无关修改。
- [ ] `pyproject.toml`、包内版本、CHANGELOG 和计划发布名一致。
- [ ] README 的证据数字注明目标 commit，不保留未确认的远端状态、旧失败或旧测试总数。
- [ ] `AI_AGENT_START.md` 仍是稳定统一入口；`HANDOFF.md` 的里程碑快照、下一步和验证命令与 implementation plan 保持一致，下一代理不需要旧聊天记录。
- [ ] 不自动创建 tag/GitHub Release；只有用户明确批准后执行外部发布。

## 3. 秘密与仓库卫生

```powershell
rg -n --hidden --glob '!.git/**' --glob '!uv.lock' '(sk-[A-Za-z0-9_-]{12,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|DEEPSEEK_API_KEY\s*=\s*[''"][^$])' .
git status --ignored --short
```

- [ ] 仓库、fixture、日志和文档没有真实 API key、私钥、cookie、审批 nonce 或用户敏感路径数据。
- [ ] 已审阅所有可达 Git 历史/对象；source preflight 主要检查当前 index/worktree，不能单独证明历史从未包含秘密。
- [ ] `.astercode/`、临时 workspace、构建产物、wheelhouse 和真实 session 不进入提交。
- [ ] 配置示例只写环境变量名或占位符。

## 4. 跨设备公开迁移

- [ ] 已确认公司知识产权、保密、客户合同和设备管理政策允许公开源码；技术预检不代替授权。
- [ ] 迁移只通过获批的公开 Git commit/tag；不复制整个工作区、压缩包、网盘或 USB 内容。
- [ ] 不迁移 `.astercode/`、`config.toml`、公司 `astercode.toml`、`.env`、`.venv/`、意外 `%SystemDrive%/` 缓存、SSH/浏览器凭据、审计/session/记忆、内部 IP/域名/路径或公司数据。
- [ ] 公司电脑在 clean worktree 运行并保存结果：

```powershell
python scripts/portability_preflight.py --root . --profile source
python scripts/portability_preflight.py --root . --profile source --format json
```

- [ ] `--allow-dirty` 仅用于开发诊断，未被当作公开交接凭证。
- [ ] 个人电脑从公开 Git clean clone 同一 SHA，并从零生成 `.astercode/` 与配置。
- [ ] 个人电脑重新运行 `python scripts/portability_preflight.py --root . --profile demo`、doctor 和离线 Demo。
- [ ] 只持久化 `ASTERCODE_MODEL_PROVIDER`/`ASTERCODE_MODEL_ID`；离职后仍获授权的 key 通过隐藏输入或个人 secret broker 注入当前进程。
- [ ] 公司电脑环境变量按公司保留/清理政策处理，没有擅自删除审计证据或共享凭据。

完整步骤见 [windows-migration.md](windows-migration.md)。

## 5. Windows 质量门

```powershell
uv sync --extra dev --extra browser --frozen
uv run python -m compileall -q src tests scripts
uv run pytest -q
uv run ruff check .
uv run mypy src tests
uv lock --check
uv pip check --python .venv\Scripts\python.exe
uv build
uv run python scripts/package_smoke.py
```

- [ ] 记录目标 commit、Python/Windows 版本、passed/skipped 数字和 skip 原因。
- [ ] skipped 不计为通过能力。
- [ ] PowerShell 7、Windows Job Object、symlink/junction/reparse 的平台测试按当前机器能力实际运行；未满足时明确记录。

## 6. WSL/Linux 质量门

在已有的独立 Python 3.12 WSL 环境中运行同一锁定依赖和完整测试：

```bash
uv sync --extra dev --extra browser --frozen
uv run python -m compileall -q src tests scripts
uv run pytest -q
ASTERCODE_REQUIRE_LIVE_DOCKER=1 uv run pytest -q -rs tests/integration/test_docker_process_live.py
uv run ruff check .
uv run mypy src tests
uv lock --check
uv build
uv run python scripts/package_smoke.py
```

- [ ] 记录 distro、Python、Docker engine、passed/skipped 和 live Docker 数字。
- [ ] WSL + Docker Desktop 的结论不外推到裸机 Linux 或独立生产 daemon。

## 7. 固定作品集 Demo

```powershell
uv run astercode doctor --root .
uv run python scripts/resume_demo.py --backend docker --cleanup
```

- [ ] 终端实际输出 `AsterCode resume demo: PASS`。
- [ ] baseline 是预期失败；最终测试输出为 `calculator regression: 3 checks passed`。
- [ ] 工具链严格为 `fs.read → fs.read → fs.apply_patch → process.exec → git.diff → git.status`。
- [ ] 只有一次精确 P3 `process.exec` 审批，并成功跨 checkpoint resume。
- [ ] evidence JSON 报告 `execution_simulated=false`、Docker sandbox 元数据完整、audit valid。
- [ ] Git diff 只有一个算术操作符修复，Git status 不包含测试文件变化。

若只能运行 `--backend fake`，发布记录必须写明 simulated，且该项不能勾选为 Docker Demo 通过。

## 8. 可选 live Provider smoke

- [ ] 仅从当前用户环境/secret broker 读取 key；终端、日志和命令行不显示值。
- [ ] 使用新建临时工作区、低预算任务、明确的无网络/不 push 范围。
- [ ] 记录 Provider、模型、session、工具、审批、token（若 Provider 返回）、耗时和未验证项。
- [ ] DeepSeek smoke 不替代 OpenAI smoke；没有 OpenAI 凭据时写 `LIVE OPENAI NOT VERIFIED`。
- [ ] 不连接真实 SSH、生产服务或用户浏览器登录态。

## 9. 供应链与文档

- [ ] `doctor` 报告 Docker 固定镜像和 `cosign`/`syft`/`trivy` 可用性。
- [ ] 固定 RepoDigest 只表示内容寻址，不单独宣称签名可信、SBOM 或漏洞扫描通过。
- [ ] 若发布记录声称签名/SBOM/漏洞扫描，附实际命令、工具版本、离线/在线数据库状态和输出 artifact。
- [ ] `uv run astercode supply-chain verify --root .` 默认只使用本地 Docker daemon、精确 RepoDigest 和已有 Trivy DB；它不拉镜像、不更新 DB、不连接签名服务。
- [ ] 证据目录包含绑定目标 commit/config hash 的 `manifest.json`、分离的 stdout/stderr、SBOM、Trivy JSON（若运行）和 `SHA256SUMS`；四个 claim (`content_pinned`、`sbom_generated`、`vulnerability_policy_passed`、`signature_verified`) 独立记录。
- [ ] `--update-trivy-db` 只能作为单独获批的网络阶段；记录 DB 来源、更新时间、最大允许年龄、severity、unfixed 和退出策略。缺 DB 或过期必须为 `NOT VERIFIED/BLOCKED`。
- [ ] Trivy DB 必须有 `Version=2`、`UpdatedAt`/`DownloadedAt`/`NextUpdate`、`metadata.json` 和独立的 `trivy.db`；当前 trivy-db v2 可省略 `Type`，若兼容旧 producer 提供 `Type`/`type`，则必须是整数 `1`。记录两者 SHA-256/大小和扫描前后复核。该清单是本地 inventory，不是可信 DB provenance；没有另外批准的 provenance 策略时 `vulnerability_policy_passed=false`，发布门禁必须 `BLOCKED`。
- [ ] Cosign 必须绑定预先批准的公钥指纹，或精确 certificate identity + OIDC issuer + transparency-log/bundle 证据；没有信任锚时保持 `signature_verified=false`。
- [ ] 缺少签名或数据库可信 provenance 时默认命令返回非零；`--allow-unverified-signature` 仅可用于开发证据采集，不能勾选发布通过。
- [ ] 配置的 mirror reference、实际 RepoDigest 和 Cosign 查询 reference 分开记录；digest 相等不等于镜像已签名。
- [ ] README、HANDOFF、architecture、implementation-plan、threat-model、demo-guide、windows-migration、resume-project、CHANGELOG 相互一致。
- [ ] README 中的安装、doctor、Demo、测试和 packaged CLI 命令均已在目标提交运行。

## 10. GitHub 证据与发布

- [ ] 推送目标 commit 后，等待 `.github/workflows/ci.yml` 的 Windows/Ubuntu jobs 完成。
- [ ] Ubuntu required Docker regression 未被 skip；缺少镜像/attestation 时应使 job 失败。
- [ ] CI badge 指向当前仓库和 `ci.yml`，README 记录的是目标 commit 而不是旧快照。
- [ ] 审阅 GitHub diff，确认没有 secret、临时 artifact 或意外大文件。
- [ ] 经用户明确批准后再创建 tag/Release；Release notes 列出 verified、simulated、blocked 和 known limitations。

## 11. 发布证据模板

```text
target_commit: <sha>
version: <version>
windows: <passed/skipped + platform>
wsl_linux: <passed/skipped + distro>
github_actions: <run URL + Windows/Ubuntu result>
lint_type_lock_build: <actual results>
packaged_cli_smoke: <actual result>
resume_demo_docker: <PASS/FAIL + evidence path>
live_provider: <provider/model/session or NOT VERIFIED>
live_ssh_browser_gui: NOT VERIFIED / BLOCKED
supply_chain_manifest: <path + SHA-256>
container_image: <configured ref + resolved digest>
syft_sbom: <PASS/FAIL/NOT VERIFIED + format + artifact SHA/path>
trivy_scan: <PASS/FAIL/NOT VERIFIED + DB timestamp + policy + artifact SHA/path>
cosign_verify: <VERIFIED/NOT VERIFIED + identity/issuer or key fingerprint + tlog/bundle>
known_risks: <remaining risks>
```
