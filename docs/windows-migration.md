# AsterCode：公司 Windows 到个人 Windows 的安全迁移

本指南只迁移经过授权的公开源码。它不迁移公司电脑上的运行状态、凭据、审批、记忆、审计、虚拟环境或远程连接配置。迁移后的个人电脑从 clean clone 和全新 `.astercode/` 开始。

## 0. 先确认公司知识产权与保密授权

在执行任何复制或推送前，先确认公司知识产权、保密协议、客户合同、开源和设备管理政策明确允许公开和带走这些源码。重点审查：

- 是否包含公司时间/设备上产生且归公司所有的代码。
- 是否包含内部库、客户数据、模型、测试集、日志、路径、IP、域名、主机名或架构信息。
- Git 历史、Issue、Release、构建 artifact 是否同样可以公开。
- 是否需要主管、法务、开源办公室或 IT 的书面批准。

`portability_preflight.py` 只能检查技术可移植性和常见泄漏，不能授予知识产权或保密许可。若授权不明确，停止迁移；不要用压缩包、个人网盘、邮件、USB 或关闭 DLP 绕过公司控制。

## 1. 公司电脑：只准备公开 Git 源码

进入仓库并确认远端、分支和工作树：

```powershell
cd C:\path\to\langgraph-agent
git remote -v
git branch --show-current
git status --short --branch
git diff --check
git diff --cached --name-only
git log -1 --oneline
```

逐项审阅即将公开的 diff 和完整跟踪文件。以下内容不得迁移：

- `.astercode/` 下的数据库、checkpoint、审批、session、记忆、artifact 和审计 JSONL。
- `config.toml`、公司专用 `astercode.toml`、`.env`、`.env.*` 和 `.venv/`。
- `OPENAI_API_KEY`、`DEEPSEEK_API_KEY`、cookie、SSH 私钥、SSH agent、`known_hosts`、浏览器 profile 或其他 secret broker 数据。
- 公司内部路径、用户名、IP、域名、SSH host、网络 allowlist、源代码、日志、数据集或测试结果。
- Docker 本地状态、WSL 发行版、构建缓存和机器级环境变量。
- 意外生成的 `%SystemDrive%/` 等本机缓存目录；它们不是源码，必须由 source 预检拒绝。

`.gitignore` 只是纵深防御；已被 Git 跟踪或曾进入历史的秘密不会因后来加入 ignore 而消失。若 key 曾出现在提交、终端截图、聊天或日志中，应在对应 Provider 控制台撤销并重新生成。不要在终端中打印疑似 key 来“确认”它。

### 1.1 运行 source 预检

正式交接必须在干净工作树运行：

```powershell
python scripts/portability_preflight.py --root . --profile source
```

需要机器可读证据时：

```powershell
python scripts/portability_preflight.py --root . --profile source --format json
```

开发期间可用下列命令查看尚未提交改动的诊断：

```powershell
python scripts/portability_preflight.py --root . --profile source --allow-dirty
```

`--allow-dirty` 只放宽“工作树必须干净”这一开发检查，不代表改动已获公司授权、没有秘密或可以公开。正式迁移仍需 clean source profile 通过并由人工复核。

source preflight 检查当前 Git index 和未忽略的工作树内容，不等同于完整 Git 历史秘密扫描。正式公开前还要审阅所有可达提交/对象和远端历史；若历史中曾出现真实凭据，仅删除当前文件不够，必须按公司流程处理历史并撤销对应凭据。

### 1.2 仅推送获批的公开提交

使用正常的公司批准和代码审查流程提交、推送。记录获批的公开 commit SHA：

```powershell
git rev-parse HEAD
git status --short
```

个人电脑只从公开 Git URL clone 该提交或发布 tag。不要复制整个公司工作区，也不要复制 `.git` 目录、压缩包或忽略文件作为“快捷迁移”。

公司电脑上的 editable `aster` 安装绑定旧机器源码路径，不具有可移植性；个人电脑必须从新 clone 重新安装。旧 `config.toml` 也可能包含旧机器绝对路径，因此不得复用。

## 2. 公司电脑：交接结束后的环境清理

先遵循公司的留存、取证、审计和离职流程。不要擅自删除公司要求保存的 `.astercode`、审计记录、日志、设备数据或公司管理的凭据；这些数据只是不应迁移到个人电脑。

若这些变量由你在当前 PowerShell 或当前 Windows 用户范围内临时设置，并且公司政策允许清除，可在完成工作后执行：

```powershell
$names = @(
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "ASTERCODE_MODEL_PROVIDER",
    "ASTERCODE_MODEL_ID",
    "ASTERCODE_REASONING_EFFORT"
)

foreach ($name in $names) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    [Environment]::SetEnvironmentVariable($name, $null, "User")
}
```

这不会清除公司 secret broker、系统级策略或 Provider 控制台中的 key。公司管理的 key 应由授权管理员按公司流程轮换或撤销；不要自行破坏共享凭据或审计证据。

## 3. 个人电脑：准备全新环境

安装并验证个人电脑上的 Git for Windows、Python 3.12+、uv 和 PowerShell 7。真实 Docker 演示还需要 WSL2 与 Docker Desktop Linux containers：

```powershell
git --version
py -3.12 --version
uv --version
pwsh --version
wsl --status
docker version
```

Docker 不是 Fake/replay 或普通对话的前提；但没有通过 attestation 的 Docker 时，不能声称 process/shell 沙箱或 Docker Demo 已验证。

## 4. 个人电脑：从公开仓库 clean clone

```powershell
New-Item -ItemType Directory -Force "$HOME\source" | Out-Null
Set-Location "$HOME\source"
git clone https://github.com/AndyBestaa/agentlearn.git astercode
Set-Location .\astercode

git status --short
git rev-parse HEAD
```

将 SHA 与公司电脑记录的获批公开 SHA 或 release tag 对比。新 clone 不应包含公司 `.astercode`、配置、虚拟环境、SSH 文件或审计记录。

安装锁定依赖并创建个人电脑的全新状态：

```powershell
uv sync --extra dev --extra browser --frozen
uv run astercode init --root .
uv run astercode doctor --root .
```

此时生成的 `.astercode/` 属于个人电脑的新 session 空间，不是公司状态的恢复或延续。

## 5. 个人电脑：Demo 可移植性预检

```powershell
python scripts/portability_preflight.py --root . --profile demo
```

需要 JSON 证据时：

```powershell
python scripts/portability_preflight.py --root . --profile demo --format json
```

若 doctor 或预检报告固定镜像缺失，拉取配置中精确的 RepoDigest 后重新检查：

```powershell
docker pull mirror.gcr.io/library/python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
uv run astercode doctor --root .
python scripts/portability_preflight.py --root . --profile demo
```

## 6. 先做不需要 key 的离线验收

```powershell
uv run astercode run "只读检查 README.md，并概括项目用途" --root . --fake
uv run python scripts/resume_demo.py --backend docker --cleanup
```

Docker Demo 只有在实际输出 `AsterCode resume demo: PASS`，并包含失败基线、精确审批恢复、真实 Docker 测试、最小 diff 和有效审计链时才算通过。

Docker 暂不可用时可以诊断 Fake 路径：

```powershell
uv run python scripts/resume_demo.py --backend fake --cleanup
```

该输出会明确标记 `SIMULATED`，不能作为真实进程或沙箱证据。

## 7. 个人电脑：安装 `aster` 命令

开发阶段可安装 editable CLI：

```powershell
uv tool install --python 3.12 --editable . --force
uv tool update-shell
```

完全关闭并重新打开 VS Code/PowerShell，然后验证：

```powershell
aster --help
aster doctor --root .
```

## 8. 安全注入离职后仍获授权的 Provider key

项目的 Provider adapter 不需要因更换电脑或开发 Agent 而重写。个人电脑只使用离职后仍明确获授权的 key；若现有 key 属于公司或授权随离职结束，则改用个人账户新生成的 key，不导出或转发公司凭据。若现有 key 本来就属于个人且仍有效，可继续使用相同环境变量协议。只把非秘密的 Provider 和模型 ID 保存为用户环境变量；key 默认只注入当前 PowerShell 会话。

先定义隐藏输入辅助函数：

```powershell
function Set-AsterSessionSecret {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("OPENAI_API_KEY", "DEEPSEEK_API_KEY")]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Prompt
    )

    $secure = Read-Host $Prompt -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        Set-Item -LiteralPath "Env:$Name" -Value $plain
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        $plain = $null
    }
}
```

### 8.1 DeepSeek

```powershell
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_PROVIDER", "deepseek", "User")
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_ID", "deepseek-v4-flash", "User")

$env:ASTERCODE_MODEL_PROVIDER = "deepseek"
$env:ASTERCODE_MODEL_ID = "deepseek-v4-flash"
Set-AsterSessionSecret -Name "DEEPSEEK_API_KEY" -Prompt "请输入个人 DeepSeek API Key"
```

### 8.2 OpenAI

把模型占位符替换为个人账户实际可用的模型 ID：

```powershell
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_PROVIDER", "openai", "User")
[Environment]::SetEnvironmentVariable("ASTERCODE_MODEL_ID", "<个人账户可用模型ID>", "User")

$env:ASTERCODE_MODEL_PROVIDER = "openai"
$env:ASTERCODE_MODEL_ID = "<个人账户可用模型ID>"
Set-AsterSessionSecret -Name "OPENAI_API_KEY" -Prompt "请输入个人 OpenAI API Key"
```

不要把 key 本身传给 `[Environment]::SetEnvironmentVariable(..., "User")`、写入 PowerShell profile、TOML、`.env`、脚本或命令行。若使用个人密码管理器或 secret broker，应让它在启动 AsterCode 前向进程注入对应环境变量。

验证时 doctor 只应显示 `provider-key PRESENT`，绝不能显示实际值：

```powershell
uv run astercode doctor --root .
```

## 9. 低预算 live smoke

先使用只读 P0 任务，不安装依赖、不 push、不连接 SSH：

```powershell
uv run astercode run "只读取 README.md 前10行，并用一句话总结" `
    --root . `
    --no-stream `
    --max-rounds 3 `
    --max-tool-calls 2 `
    --max-tokens 20000 `
    --max-input-tokens 16000 `
    --max-output-tokens 4000 `
    --max-elapsed-seconds 180
```

记录 Provider、模型、session、工具调用、token（若 Provider 返回）和未验证项；不要把一次 smoke 外推为所有模型、成本或生产集成已经验证。

## 10. 在个人新项目验证 `aster`

```powershell
$project = "$HOME\source\aster-personal-smoke"
New-Item -ItemType Directory -Force $project | Out-Null
Set-Location $project
aster
```

首次启动只为这个新项目创建 `.astercode/`。建议依次验证：

1. 普通问候和 `/status`。
2. P0 只读目录检查。
3. 创建一个简单 Python 文件，逐字审阅 P1 patch 后批准。
4. Docker 可用时审阅并批准 `process.exec`，核对真实 exit code/stdout。
5. 退出后重新进入，验证 `/resume` 和 session 状态。

不要在对话里粘贴 key、私钥或公司内容；不要批准 push、远程连接、部署或工作区外写入。

## 11. 最终交接判据

- 公司知识产权和保密授权已有明确结论。
- 公司电脑的 clean `source` profile 通过，公开 commit SHA 已记录。
- 个人电脑从公开 Git clean clone 同一 SHA，没有复制任何公司状态或 secret。
- 个人电脑的 `demo` profile、doctor 和离线 Demo 按实际环境通过或诚实报告缺口。
- Provider/model 可以持久化；离职后仍获授权的 key 只由隐藏输入或个人 secret broker 注入当前进程。
- 低预算只读 live smoke 和新项目 `aster` 对话分别验证，并保留不含秘密的结果摘要。
- 公司电脑环境变量按公司留存/清理政策处理，没有擅自删除审计证据或共享凭据。
