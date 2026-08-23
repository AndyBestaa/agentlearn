"""Typer CLI for the AsterCode local coding agent."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import tempfile
import tomllib
import unicodedata
from pathlib import Path
from typing import Any, Coroutine, Mapping

import typer
from rich.console import Console
from rich.table import Table

from .config import (
    AppConfig,
    ConfigError,
    SandboxBackend,
    load_config,
    validate_strict_project_file,
    validate_strict_workspace_root,
)
from .config_migration import ConfigMigrationError, migrate_config_file
from .security import PathAuthorizationError, canonicalize_authorized_path, contains_probable_secret

app = typer.Typer(help="AsterCode: a local-first, policy-controlled coding agent", no_args_is_help=True)
sessions_app = typer.Typer(help="Inspect persisted sessions")
memory_app = typer.Typer(help="Inspect and manage long-term memory proposals")
config_app = typer.Typer(help="Validate and inspect configuration")
permissions_app = typer.Typer(help="Inspect runtime permission policy")
ssh_app = typer.Typer(help="Inspect explicitly authorized SSH hosts")
ssh_hosts_app = typer.Typer(help="SSH host operations")
audit_app = typer.Typer(help="Verify local append-only audit evidence")
app.add_typer(sessions_app, name="sessions")
app.add_typer(memory_app, name="memory")
app.add_typer(config_app, name="config")
app.add_typer(permissions_app, name="permissions")
app.add_typer(ssh_app, name="ssh")
app.add_typer(audit_app, name="audit")
ssh_app.add_typer(ssh_hosts_app, name="hosts")

console = Console()
_STRICT_SHORTCUT = False


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a CLI coroutine without replacing an existing host event loop."""

    with asyncio.Runner(loop_factory=asyncio.new_event_loop) as runner:
        return runner.run(coro)


def _root(value: Path | None) -> Path:
    candidate = value or Path.cwd()
    if _STRICT_SHORTCUT:
        try:
            return validate_strict_workspace_root(candidate)
        except ConfigError as exc:
            raise typer.BadParameter(str(exc)) from exc
    return candidate.expanduser().resolve()


def _terminal_safe(value: Any) -> str:
    """Render untrusted text without terminal control or bidi spoofing."""

    output: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        if character in {"\n", "\t"}:
            output.append(character)
        elif codepoint < 32 or codepoint == 127 or 128 <= codepoint <= 159:
            output.append(f"\\x{codepoint:02x}")
        elif unicodedata.category(character) == "Cf":
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


def _looks_like_astercode_config(path: Path) -> bool:
    """Recognize the legacy generic filename without swallowing another app's TOML."""

    try:
        if not path.is_file() or path.stat().st_size > 1_048_576:
            return False
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return False
    product = data.get("product")
    versioned = (
        type(data.get("config_version")) is int
        and data.get("config_version") == 1
        and str(data.get("product_name", "")).strip().casefold() == "astercode"
    )
    legacy = (
        isinstance(product, Mapping)
        and str(product.get("name", "")).strip().casefold() == "astercode"
        and all(isinstance(data.get(key), Mapping) for key in ("model", "security"))
    )
    return versioned or legacy


def _discover_config(root: Path) -> Path | None:
    state = root / ".astercode"
    state_is_junction = bool(getattr(state, "is_junction", lambda: False)())
    if state.is_symlink() or state_is_junction:
        raise ConfigError(f"state directory cannot be a link or junction: {state}")
    if state.exists() and not state.is_dir():
        raise ConfigError(f"state path must be a directory: {state}")
    for candidate in (root / "astercode.toml", root / ".astercode" / "config.toml"):
        is_junction = bool(getattr(candidate, "is_junction", lambda: False)())
        if candidate.is_symlink() or is_junction:
            raise ConfigError(f"project config cannot be a link or junction: {candidate}")
        if candidate.is_file():
            if candidate.stat(follow_symlinks=False).st_nlink > 1:
                raise ConfigError(f"project config cannot be hard-linked: {candidate}")
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ConfigError(f"project config escapes the workspace: {candidate}") from exc
            return resolved
    legacy = root / "config.toml"
    legacy_is_junction = bool(getattr(legacy, "is_junction", lambda: False)())
    if legacy.is_symlink() or legacy_is_junction:
        raise ConfigError(f"legacy project config cannot be a link or junction: {legacy}")
    if legacy.is_file() and legacy.stat(follow_symlinks=False).st_nlink > 1:
        raise ConfigError(f"legacy project config cannot be hard-linked: {legacy}")
    return legacy if _looks_like_astercode_config(legacy) else None


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Replace one project file without writing through an existing hard link."""

    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _config(root: Path, config_file: Path | None = None):
    if _STRICT_SHORTCUT:
        environment = dict(os.environ)
        environment.pop("ASTERCODE_PROJECT_ROOT", None)
        return load_config(
            config_file or _discover_config(root),
            project_root=root,
            environ=environment,
            strict_workspace=True,
        )
    selected = config_file or _discover_config(root)
    return load_config(selected, project_root=root)


def _chat_config(root: Path) -> AppConfig:
    """Bind the convenience shell to its launch directory as final authority."""

    environment = dict(os.environ)
    environment.pop("ASTERCODE_PROJECT_ROOT", None)
    config = load_config(
        _discover_config(root),
        project_root=root,
        environ=environment,
        strict_workspace=True,
    )
    return config


def _storage(cfg):
    from .storage import Storage

    return Storage(cfg.storage)


def _export_destination(output: Path, cfg: Any, *, allow_outside_root: bool, yes: bool) -> Path:
    """Bind exports to authorized roots unless the CLI user gives exact P3 consent."""

    try:
        return canonicalize_authorized_path(
            output,
            cfg.security.authorized_roots,
            cwd=cfg.project_root,
            must_exist=False,
            reject_unc=cfg.security.reject_unc_paths,
        ).resolved
    except PathAuthorizationError as exc:
        if not (allow_outside_root and yes):
            raise typer.BadParameter(
                "outside-root export requires both --allow-outside-root and --yes"
            ) from exc
        candidate = output.expanduser()
        if not candidate.is_absolute():
            candidate = cfg.project_root / candidate
        candidate = candidate.resolve(strict=False)
        if candidate.exists() and candidate.is_symlink():
            raise typer.BadParameter("export destination cannot be a symlink") from exc
        if not candidate.parent.is_dir():
            raise typer.BadParameter("outside-root export parent must already exist") from exc
        return candidate


def _write_json_export(path: Path, payload: Any) -> None:
    """Write a redacted export atomically beside its final destination."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            json.dump(payload, stream, ensure_ascii=False, indent=2, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


@app.command()
def init(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), force: bool = typer.Option(False, "--force")) -> None:
    """Create the local state directory and a safe example configuration."""
    root = _root(root)
    root.mkdir(parents=True, exist_ok=True)
    state = root / ".astercode"
    state_is_junction = bool(getattr(state, "is_junction", lambda: False)())
    if state.is_symlink() or state_is_junction:
        raise typer.BadParameter(".astercode must not be a link or junction")
    if state.exists() and not state.is_dir():
        raise typer.BadParameter(".astercode must be a real local directory")
    state.mkdir(exist_ok=True)
    config_path = _discover_config(root) or (root / "astercode.toml")
    if config_path.exists() and not force:
        typer.echo(f"已存在，未覆盖: {config_path}")
    elif not config_path.exists() or force:
        source_template = Path(__file__).resolve().parents[2] / "config.example.toml"
        packaged_template = Path(__file__).resolve().with_name("config.example.toml")
        template = source_template if source_template.exists() else packaged_template
        if template.exists():
            _atomic_write_bytes(config_path, template.read_bytes())
        else:
            _atomic_write_bytes(config_path, _minimal_config(root).encode("utf-8"))
        typer.echo(f"已创建: {config_path}")
    cfg = (
        _chat_config(root)
        if _STRICT_SHORTCUT
        else _config(root, config_path if config_path.exists() else None)
    )
    storage = _storage(cfg)
    storage.initialize()
    typer.echo(f"数据库: {cfg.storage.database_path}")


@app.command()
def doctor(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    """Check local runtime capabilities without contacting external services."""
    root = _root(root)
    checks: list[tuple[str, str, str]] = []
    checks.append(("project_root", "OK" if root.is_dir() else "FAIL", str(root)))
    checks.append(("python", "OK", sys.version.split()[0]))
    checks.append(("platform", "INFO", platform.platform()))
    checks.append(("git", "OK" if shutil.which("git") else "FAIL", shutil.which("git") or "not found"))
    from .tools.filesystem import _trusted_rg

    trusted_rg = _trusted_rg()
    path_rg = shutil.which("rg")
    if trusted_rg is not None:
        checks.append(("ripgrep", "OK", trusted_rg))
    elif path_rg is not None:
        checks.append(("ripgrep", "INFO", "PATH candidate is not at a trusted system location; using safe fallback search"))
    else:
        checks.append(("ripgrep", "INFO", "trusted binary not found; using safe fallback search"))
    checks.append(("PowerShell 7", "OK" if shutil.which("pwsh") else "NOT VERIFIED", shutil.which("pwsh") or "only Windows PowerShell may be available"))
    bash = shutil.which("bash")
    if bash is None and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        bash = str(candidate) if candidate.is_file() else None
    checks.append(("bash", "OK" if bash else "NOT VERIFIED", bash or "not found"))
    try:
        import langgraph

        checks.append(("langgraph", "OK", getattr(langgraph, "__version__", "installed")))
    except Exception as exc:
        checks.append(("langgraph", "FAIL", str(exc)))
    try:
        import agents

        checks.append(("openai-agents", "OK", getattr(agents, "__version__", "installed")))
    except Exception as exc:
        checks.append(("openai-agents", "FAIL", str(exc)))
    if os.name == "nt":
        try:
            from .windows_job import WindowsJobLimits, WindowsJobObject

            with WindowsJobObject(WindowsJobLimits(active_process_limit=1)) as job:
                active = job.active_process_count()
            checks.append(
                (
                    "process containment",
                    "AVAILABLE" if active == 0 else "FAIL",
                    "empty Windows Job Object probe passed; assign/kill/limits are separate tests, and this is not a filesystem/network sandbox",
                )
            )
        except Exception as exc:
            checks.append(
                (
                    "process containment",
                    "BLOCKED",
                    f"Windows Job Object probe failed ({type(exc).__name__})",
                )
            )
    else:
        checks.append(
            (
                "process containment",
                "NOT VERIFIED",
                "POSIX process groups are best-effort; no verified cgroup v2 backend",
            )
        )
    try:
        cfg = _config(root)
        checks.append(("config", "OK", f"network={cfg.security.network_mode.value}"))
        checks.append(("model-provider", "OK", cfg.model.provider))
        checks.append(("model-id", "SET" if cfg.model.model_id else "UNSET", cfg.model.model_id or "not configured"))
        if cfg.model.base_url is not None:
            checks.append(("model-base-url", "PINNED", cfg.model.base_url))
        process = cfg.security.process
        if process.sandbox_backend is SandboxBackend.CONTAINER:
            from .tools.docker_process import (
                DockerSandboxUnavailable,
                attest_docker_sandbox,
                discover_trusted_docker,
            )

            docker_cli = discover_trusted_docker()
            checks.append(
                (
                    "docker-cli",
                    "OK" if docker_cli is not None else "BLOCKED",
                    str(docker_cli) if docker_cli is not None else "trusted Docker CLI not found",
                )
            )
            try:
                attestation = attest_docker_sandbox(
                    configured_image=process.container_image,
                    user=process.container_user,
                    max_processes=process.max_processes,
                    max_memory_bytes=process.max_memory_bytes,
                    cpus=process.container_cpus,
                    tmpfs_bytes=process.container_tmpfs_bytes,
                    workspace_bytes=process.container_workspace_bytes,
                )
            except DockerSandboxUnavailable as exc:
                detail = str(exc)
                checks.append(("network enforcement", "BLOCKED", detail))
                checks.append(("sandbox", "BLOCKED", detail))
            else:
                digest_suffix = attestation.image_digest.rsplit("@", 1)[-1]
                detail = (
                    "Docker probe passed: network=none, read-only source, "
                    "ephemeral writable workspace, hidden agent state, "
                    f"image={digest_suffix}"
                )
                checks.append(("network enforcement", "ENFORCED", "Docker --network none probe passed"))
                checks.append(("sandbox", "ENFORCED", detail))
        else:
            checks.append(("network enforcement", "BLOCKED", "no runtime-attested OS egress sandbox/allowlist adapter"))
            checks.append(("sandbox", "BLOCKED", "sandbox_backend is not an attested container adapter"))
        if not cfg.security.authorized_ssh_hosts:
            ssh_detail = "allowlist is empty; the system OpenSSH transport cannot be assembled"
        elif not cfg.security.ssh.enabled:
            ssh_detail = "host allowlist exists but security.ssh.enabled=false"
        else:
            ssh_detail = "strict OpenSSH is configured, but no runtime-attested SSH egress policy or live test is available"
        checks.append(("ssh", "BLOCKED", ssh_detail))
        browser = cfg.security.browser
        if not cfg.features.browser_automation or not browser.enabled:
            browser_status = "DISABLED"
            browser_detail = "browser automation is disabled by configuration"
        elif browser.engine == "disabled":
            browser_status = "BLOCKED"
            browser_detail = "engine=disabled by default; the offline Fake Browser is test-only"
        else:
            browser_status = "BLOCKED"
            browser_detail = f"engine={browser.engine}; no runtime-attested browser egress policy"
        checks.append(("browser", browser_status, browser_detail))
        key_present = bool(os.getenv(cfg.model.api_key_env))
        checks.append(("provider-key", "PRESENT" if key_present else "UNSET", f"{cfg.model.api_key_env} (value never displayed)"))
    except ConfigError as exc:
        checks.append(("config", "FAIL", str(exc)))
    table = Table("check", "status", "details")
    for row in checks:
        table.add_row(*row)
    console.print(table)


@app.command("run")
def run_task(
    task: str = typer.Argument(..., help="Natural-language coding task"),
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    session_id: str | None = typer.Option(None, "--session"),
    fake: bool = typer.Option(False, "--fake", help="Use deterministic provider; no API key/network"),
    auto_approve: bool = typer.Option(False, "--allow-workspace-writes", "--auto-approve", help="Explicitly allow P1 reversible workspace writes for this run"),
    stream: bool = typer.Option(True, "--stream/--no-stream", help="Print redacted provider/tool lifecycle events"),
    replay: Path | None = typer.Option(None, "--replay", help="Authorized deterministic provider replay JSON"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Evaluate policy and tool arguments without executing handlers"),
    max_rounds: int | None = typer.Option(None, "--max-rounds", min=1, help="Override the model-round budget for this run"),
    max_tool_calls: int | None = typer.Option(None, "--max-tool-calls", min=1, help="Override the tool-call budget for this run"),
    max_tokens: int | None = typer.Option(None, "--max-tokens", min=1, help="Override the total-token budget for this run"),
    max_input_tokens: int | None = typer.Option(None, "--max-input-tokens", min=1, help="Override the input-token budget for this run"),
    max_output_tokens: int | None = typer.Option(None, "--max-output-tokens", min=1, help="Override the output-token budget for this run"),
    max_elapsed_seconds: float | None = typer.Option(None, "--max-elapsed-seconds", min=0.1, help="Override the elapsed-time budget for this run"),
) -> None:
    """Run one task through the LangGraph orchestrator."""
    budget_overrides = {
        key: value
        for key, value in {
            "max_rounds": max_rounds,
            "max_tool_calls": max_tool_calls,
            "max_tokens": max_tokens,
            "max_input_tokens": max_input_tokens,
            "max_output_tokens": max_output_tokens,
            "max_elapsed_seconds": max_elapsed_seconds,
        }.items()
        if value is not None
    }
    result = _run_task_impl(task, root=_root(root), session_id=session_id, fake=fake, auto_approve=auto_approve, stream=stream, replay=replay, dry_run=dry_run, budget_overrides=budget_overrides)
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if result.get("status") not in {"completed", "partial"}:
        raise typer.Exit(code=2)


def _run_task_impl(task: str, *, root: Path, session_id: str | None, fake: bool, auto_approve: bool, stream: bool = False, replay: Path | None = None, dry_run: bool = False, budget_overrides: dict[str, Any] | None = None, strict_workspace: bool = False) -> dict[str, Any]:
    """Synchronous boundary used by Typer and interactive chat."""

    return _run_sync(
        _run_task_async(
            task,
            root=root,
            session_id=session_id,
            fake=fake,
            auto_approve=auto_approve,
            stream=stream,
            replay=replay,
            dry_run=dry_run,
            budget_overrides=budget_overrides,
            strict_workspace=strict_workspace,
        )
    )


async def _run_task_async(task: str, *, root: Path, session_id: str | None, fake: bool, auto_approve: bool, stream: bool = False, replay: Path | None = None, dry_run: bool = False, budget_overrides: dict[str, Any] | None = None, strict_workspace: bool = False) -> dict[str, Any]:
    """Async task core; callers that already own a loop can await it directly."""

    root = _root(root)
    cfg = _chat_config(root) if strict_workspace else _config(root)
    from .provider import DeterministicFakeProvider
    from .runtime import Orchestrator, build_registry

    storage = _storage(cfg)
    storage.initialize()
    provider = None
    if replay is not None:
        try:
            checked = canonicalize_authorized_path(
                replay,
                cfg.security.authorized_roots,
                cwd=root,
                must_exist=True,
                reject_unc=cfg.security.reject_unc_paths,
            ).resolved
            if checked.stat().st_size > 1_048_576:
                raise typer.BadParameter("replay fixture exceeds 1 MiB")
            replay_data = json.loads(checked.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, PathAuthorizationError) as exc:
            raise typer.BadParameter(f"invalid replay fixture ({type(exc).__name__})") from exc
        if not isinstance(replay_data, list):
            raise typer.BadParameter("replay fixture must contain a JSON array")
        if contains_probable_secret(replay_data):
            raise typer.BadParameter("replay fixture contains secret-looking material")
        provider = DeterministicFakeProvider(replay_data)
    elif fake:
        provider = DeterministicFakeProvider()
    def show_event(event: Any) -> None:
        if not stream:
            return
        _print_stream_event(event)

    orchestrator = Orchestrator(
        cfg,
        provider=provider,
        registry=build_registry(cfg),
        storage=storage,
        auto_approve=auto_approve,
        dry_run=dry_run,
        event_sink=show_event,
    )
    try:
        return await orchestrator.run(
            task,
            session_id=session_id,
            budget=budget_overrides,
        )
    finally:
        await orchestrator.close()


def _print_stream_event(event: Any) -> None:
    """Render one untrusted provider/tool event without terminal controls."""

    event_type = str(event.get("event", "event")) if isinstance(event, dict) else "event"
    if event_type == "provider.delta" and isinstance(event, dict):
        console.print(
            _terminal_safe(event.get("delta", "")),
            end="",
            markup=False,
            highlight=False,
        )
        return
    if event_type == "provider.completed":
        console.print()
    details = {
        key: event[key]
        for key in ("tool", "attempt", "response_id")
        if isinstance(event, dict) and event.get(key) is not None
    }
    line = f"{event_type} {json.dumps(details, ensure_ascii=False, default=str)}"
    console.print(_terminal_safe(line), style="dim", markup=False, highlight=False)


def _prepare_chat_workspace(root: Path) -> None:
    try:
        root = validate_strict_workspace_root(root)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    state = root / ".astercode"
    is_junction = bool(getattr(state, "is_junction", lambda: False)())
    if state.is_symlink() or is_junction:
        raise typer.BadParameter(".astercode must not be a link or junction")
    if state.exists():
        if not state.is_dir():
            raise typer.BadParameter(".astercode must be a real local directory")
        return
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            f"workspace is not initialized; run 'aster init --root {root}' first"
        )
    console.print("Aster 将只在此目录保存状态并执行操作：")
    console.print(_terminal_safe(root), style="bold", markup=False)
    if not typer.confirm(_terminal_safe(f"创建 {state} 并进入对话？"), default=False):
        raise typer.Exit()
    state.mkdir(parents=False, exist_ok=False)


def _chat_help() -> None:
    console.print(
        "[bold]对话命令[/bold]\n"
        "  /help              显示帮助\n"
        "  /status            查看当前会话状态\n"
        "  /new               开始新会话\n"
        "  /resume SESSION_ID 切换到已有会话\n"
        "  /exit              退出（也支持 exit、quit、:q）"
    )


def _print_chat_result(result: Mapping[str, Any], seen_actions: set[str]) -> None:
    for item in result.get("tool_results", []) if isinstance(result.get("tool_results"), list) else []:
        if not isinstance(item, Mapping):
            continue
        action_id = str(item.get("action_id", ""))
        if action_id and action_id in seen_actions:
            continue
        if action_id:
            seen_actions.add(action_id)
        console.print(
            _terminal_safe(
                f"工具 {item.get('tool', 'unknown')}: {item.get('status', 'unknown')}"
            ),
            style="dim",
            markup=False,
        )
    messages = result.get("messages", [])
    if isinstance(messages, list) and messages:
        console.print("Aster> ", style="bold cyan", end="")
        console.print(_terminal_safe(messages[-1]), markup=False, highlight=False)
    status = str(result.get("status", "unknown"))
    if status not in {"completed", "running"}:
        console.print(
            _terminal_safe(f"状态：{status}"),
            style="yellow",
            markup=False,
        )
    blockers = result.get("blockers", [])
    if isinstance(blockers, list):
        for blocker in blockers[-3:]:
            console.print(_terminal_safe(f"提示：{blocker}"), style="yellow", markup=False)


def _prompt_approval(request: Mapping[str, Any]) -> dict[str, Any] | None:
    risk = str(request.get("risk", "unknown"))
    console.print("\n[bold yellow]需要你的审批[/bold yellow]")
    console.print(
        _terminal_safe(
            f"风险：{risk}    工具：{request.get('tool')}    主机：{request.get('host', 'local')}"
        ),
        markup=False,
    )
    if request.get("cwd"):
        console.print(_terminal_safe(f"目录：{request['cwd']}"), markup=False)
    paths = request.get("real_paths", [])
    if isinstance(paths, list) and paths:
        console.print(
            _terminal_safe("路径：" + ", ".join(str(item) for item in paths)),
            markup=False,
        )
    console.print(_terminal_safe(f"目的：{request.get('purpose', '')}"), markup=False)
    effects = request.get("side_effects", [])
    if isinstance(effects, list) and effects:
        console.print(
            _terminal_safe("副作用：" + ", ".join(str(item) for item in effects)),
            markup=False,
        )
    for label, key in (
        ("端口", "port"),
        ("用户", "user"),
        ("主机指纹", "host_fingerprint"),
        ("网络目标", "network_destination"),
        ("验证方式", "validation"),
        ("备份", "backup"),
        ("回滚", "rollback"),
        ("到期时间", "expires_at"),
        ("动作哈希", "action_hash"),
        ("补丁哈希", "diff_hash"),
    ):
        if request.get(key):
            console.print(_terminal_safe(f"{label}：{request[key]}"), markup=False)
    normalized = request.get("normalized_action")
    if isinstance(normalized, Mapping):
        arguments = normalized.get("arguments")
        if isinstance(arguments, Mapping) and isinstance(arguments.get("patch"), str):
            patch = str(arguments["patch"])
            console.print("[bold]拟应用的补丁：[/bold]")
            console.print(_terminal_safe(patch), markup=False, highlight=False)
        elif arguments is not None:
            console.print("动作参数：")
            console.print(
                _terminal_safe(json.dumps(arguments, ensure_ascii=False, default=str)),
                markup=False,
                highlight=False,
            )
    session_allowed = risk in {"P1", "P2"}
    choices = "[a] 仅批准这一次"
    if session_allowed:
        choices += "  [s] 本会话批准同一个精确动作"
    choices += "  [d] 拒绝  [q] 暂时保留"
    while True:
        try:
            choice = typer.prompt(choices, default="q").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return None
        if choice in {"q", "quit", "leave"}:
            return None
        if choice in {"a", "approve", "y", "yes"}:
            approved, scope = True, "once"
            break
        if session_allowed and choice in {"s", "session"}:
            approved, scope = True, "session"
            break
        if choice in {"d", "deny", "n", "no"}:
            approved, scope = False, "once"
            break
        console.print("请输入 a、s、d 或 q。")
    decision = {
        key: request[key]
        for key in ("approval_id", "action_id", "action_hash", "nonce")
    }
    decision.update(
        approved=approved,
        scope=scope,
        reason="interactive terminal decision",
        actor="authenticated_terminal_user",
    )
    return decision


def _resume_chat_session(root: Path, session_id: str, decision: Mapping[str, Any]) -> dict[str, Any]:
    from .runtime import Orchestrator

    cfg = _chat_config(root)
    storage = _storage(cfg)
    storage.initialize()
    return _run_sync(
        Orchestrator.resume_from_storage(cfg, storage, session_id, decision)
    )


def _chat_session_status(root: Path, session_id: str) -> Mapping[str, Any]:
    cfg = _chat_config(root)
    storage = _storage(cfg)
    storage.initialize()
    return storage.get_session(session_id)


def _reconcile_chat_session(root: Path, session_id: str) -> dict[str, Any]:
    from .runtime import Orchestrator

    cfg = _chat_config(root)
    storage = _storage(cfg)
    storage.initialize()
    return Orchestrator(cfg, storage=storage).reconcile(session_id)


@app.command()
def chat(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), fake: bool = typer.Option(False, "--fake")) -> None:
    """Interactive multi-turn shell with host-side approval prompts."""

    root = _root(root)
    _prepare_chat_workspace(root)
    cfg = _chat_config(root)
    key_present = bool(os.environ.get(cfg.model.api_key_env))
    if not fake and cfg.model.provider != "fake":
        missing: list[str] = []
        if not cfg.model.model_id:
            missing.append("model ID")
        if not key_present:
            missing.append(cfg.model.api_key_env)
        if missing:
            console.print(
                _terminal_safe(
                    "实时模型尚未就绪：缺少 " + ", ".join(missing)
                ),
                style="red",
                markup=False,
            )
            raise typer.Exit(code=2)
    console.print("[bold]AsterCode 对话模式[/bold]")
    console.print("工作区：", end="")
    console.print(_terminal_safe(root), style="bold", markup=False)
    console.print(
        _terminal_safe(
            f"授权范围：{', '.join(str(item) for item in cfg.security.authorized_roots)}"
        ),
        markup=False,
    )
    provider = "fake" if fake else cfg.model.provider
    console.print(
        _terminal_safe(
            f"模型：{provider}/{cfg.model.model_id or '未设置'}    "
            f"Key：{'PRESENT' if key_present else 'UNSET'}"
        ),
        markup=False,
    )
    console.print("输入 /help 查看命令；输入 /exit 或按 Ctrl-C 退出。\n")
    session_id: str | None = None
    session_locked = False
    seen_actions: set[str] = set()
    pending_result: dict[str, Any] | None = None
    while True:
        try:
            message = typer.prompt("你").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n已退出；不会启动新的工具调用。")
            return
        if not message:
            continue
        lowered = message.lower()
        if lowered in {"exit", "quit", ":q", "/exit", "/quit"}:
            return
        if lowered == "/help":
            _chat_help()
            continue
        if lowered == "/new":
            session_id = None
            session_locked = False
            pending_result = None
            seen_actions.clear()
            console.print("已开始新会话。")
            continue
        if lowered == "/status":
            if session_id is None:
                console.print("当前还没有会话。")
            else:
                console.print_json(
                    json.dumps(_chat_session_status(root, session_id), ensure_ascii=False, default=str)
                )
            continue
        if lowered.startswith("/resume "):
            candidate = message.split(maxsplit=1)[1].strip()
            try:
                record = _chat_session_status(root, candidate)
            except (KeyError, ValueError):
                console.print(_terminal_safe(f"未找到会话：{candidate}"), markup=False)
                continue
            session_id = candidate
            session_locked = False
            state = record.get("state", {})
            pending_result = dict(state) if isinstance(state, Mapping) else None
            console.print(
                _terminal_safe(f"已切换到会话 {candidate}（状态：{record.get('status')}）。"),
                markup=False,
            )
            if str(record.get("status")) not in {
                "completed",
                "partial",
                "blocked",
                "cancelled",
                "failed",
                "waiting_approval",
            }:
                pending_result = _reconcile_chat_session(root, candidate)
                session_locked = True
                _print_chat_result(pending_result, seen_actions)
                console.print("该会话必须先完成只读核对，当前不会接受新的自然语言动作。")
        else:
            if session_locked:
                console.print("当前会话因未确认的动作边界而锁定；请先审查证据，或输入 /new 开始新会话。")
                continue
            console.print("[dim]Aster 正在处理…[/dim]")
            try:
                pending_result = _run_task_impl(
                    message,
                    root=root,
                    session_id=session_id,
                    fake=fake,
                    auto_approve=False,
                    stream=False,
                    strict_workspace=True,
                )
            except (ConfigError, OSError, ValueError) as exc:
                console.print(_terminal_safe(f"本轮失败：{exc}"), style="red", markup=False)
                continue
            session_id = str(pending_result.get("session_id") or session_id or "") or None
            if isinstance(pending_result.get("reconcile"), Mapping):
                session_locked = True
            _print_chat_result(pending_result, seen_actions)
        while pending_result is not None and pending_result.get("status") == "waiting_approval":
            request = pending_result.get("approval_request")
            if not isinstance(request, Mapping) or session_id is None:
                console.print("[red]审批状态缺少完整绑定信息，已停止。[/red]")
                break
            decision = _prompt_approval(request)
            if decision is None:
                console.print(
                    _terminal_safe(f"审批仍待处理。稍后可输入 /resume {session_id}。"),
                    markup=False,
                )
                break
            pending_result = _resume_chat_session(root, session_id, decision)
            _print_chat_result(pending_result, seen_actions)


@app.command()
def resume(
    session_id: str,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    approve: bool = typer.Option(False, "--approve", help="Approve the exact persisted request"),
    approve_session: bool = typer.Option(False, "--approve-session", help="Grant this exact P1/P2 action for the current session until expiry"),
    deny: bool = typer.Option(False, "--deny", help="Deny the exact persisted request"),
) -> None:
    """Resume a persisted session after an approval or crash checkpoint."""
    root = _root(root)
    cfg = _config(root)
    from .runtime import Orchestrator

    storage = _storage(cfg)
    storage.initialize()
    if sum(bool(item) for item in (approve, approve_session, deny)) > 1:
        raise typer.BadParameter("--approve, --approve-session, and --deny are mutually exclusive")
    decision = None
    if approve or approve_session or deny:
        checkpoint = storage.latest_checkpoint(session_id)
        request = (checkpoint or {}).get("state", {}).get("approval_request") if checkpoint else None
        if not isinstance(request, dict):
            raise typer.BadParameter("no persisted approval request found")
        decision = {key: request[key] for key in ("approval_id", "action_id", "action_hash", "nonce")}
        decision["approved"] = approve or approve_session
        decision["scope"] = "session" if approve_session else "once"
        decision["reason"] = "CLI user decision"
    result = _run_sync(Orchestrator.resume_from_storage(cfg, storage, session_id, decision))
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))


@app.command()
def status(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), session_id: str | None = typer.Option(None, "--session")) -> None:
    """Show one session or the most recent persisted sessions."""
    cfg = _config(_root(root))
    storage = _storage(cfg); storage.initialize()
    rows = storage.get_session(session_id) if session_id else storage.list_sessions(limit=20)
    console.print_json(json.dumps(rows, ensure_ascii=False, default=str))


@sessions_app.command("list")
def sessions_list(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), limit: int = typer.Option(20, min=1, max=100)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.list_sessions(limit=limit), ensure_ascii=False, default=str))


@sessions_app.command("show")
def sessions_show(session_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.get_session(session_id), ensure_ascii=False, default=str))


@sessions_app.command("reconcile")
def sessions_reconcile(
    session_id: str,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
) -> None:
    """Read-only comparison of a crash-interrupted action and current state."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    from .runtime import Orchestrator

    result = Orchestrator(cfg, storage=storage).reconcile(session_id)
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))


@sessions_app.command("delete")
def sessions_delete(session_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        raise typer.BadParameter("session deletion requires --yes")
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    storage.delete_session(session_id)
    typer.echo("已删除会话")


@sessions_app.command("export")
def sessions_export(
    session_id: str,
    output: Path,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    allow_outside_root: bool = typer.Option(False, "--allow-outside-root"),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    output = _export_destination(output, cfg, allow_outside_root=allow_outside_root, yes=yes)
    _write_json_export(output, storage.export_session(session_id))
    typer.echo(str(output))


@memory_app.command("list")
def memory_list(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), namespace: str | None = typer.Option(None)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.list_memory(namespace=namespace), ensure_ascii=False, default=str))


@memory_app.command("show")
def memory_show(memory_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.get_memory(memory_id), ensure_ascii=False, default=str))


@memory_app.command("search")
def memory_search(query: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), namespace: str | None = typer.Option(None)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.search_memory(query, namespace=namespace), ensure_ascii=False, default=str))


@memory_app.command("export")
def memory_export(
    output: Path,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    allow_outside_root: bool = typer.Option(False, "--allow-outside-root"),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    output = _export_destination(output, cfg, allow_outside_root=allow_outside_root, yes=yes)
    _write_json_export(output, storage.export_memory())
    typer.echo(str(output))


@memory_app.command("reindex")
def memory_reindex(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.reindex_memory(); typer.echo("已重建记忆索引")


@memory_app.command("propose")
def memory_propose(content: str, namespace: str = "project", source: str = "user", ttl_days: int | None = None, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    proposal = storage.propose_memory(content=content, namespace=namespace, source=source, ttl_days=ttl_days)
    console.print_json(json.dumps(proposal, ensure_ascii=False, default=str))
    typer.echo("未自动提交：请使用 memory commit <proposal_id> 明确确认。", err=True)


@memory_app.command("commit")
def memory_commit(proposal_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.commit_memory(proposal_id), ensure_ascii=False, default=str))


@memory_app.command("edit")
def memory_edit(
    memory_id: str,
    content: str,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    yes: bool = typer.Option(False, "--yes", help="Commit this exact edit immediately"),
) -> None:
    """Propose an edit while preserving namespace, TTL and sensitivity."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    proposal = storage.propose_memory_edit(memory_id, content=content)
    result = storage.commit_memory(proposal["proposal_id"]) if yes else proposal
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if not yes:
        typer.echo("Not committed; review it, then run memory commit <proposal_id>.", err=True)


@memory_app.command("conflicts")
def memory_conflicts(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    """List edit proposals rejected because their base memory changed."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.list_memory_conflicts(), ensure_ascii=False, default=str))


@memory_app.command("add")
def memory_add(content: str, namespace: str = "project", source: str = "user", ttl_days: int | None = None, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), yes: bool = typer.Option(False, "--yes")) -> None:
    """Explicitly propose and commit one long-term memory entry."""
    if not yes:
        raise typer.BadParameter("memory add requires --yes because it persists long-term memory")
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    proposal = storage.propose_memory(content=content, namespace=namespace, source=source, ttl_days=ttl_days)
    console.print_json(json.dumps(storage.commit_memory(proposal["proposal_id"]), ensure_ascii=False, default=str))


@memory_app.command("forget")
def memory_forget(memory_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root)); storage = _storage(cfg); storage.forget_memory(memory_id); typer.echo("已删除")


@config_app.command("show")
def config_show(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), config_file: Path | None = typer.Option(None, "--file")) -> None:
    cfg = _config(_root(root), config_file)
    data = cfg.model_dump(mode="json")
    data.setdefault("model", {}).pop("api_key", None)
    console.print_json(json.dumps(data, ensure_ascii=False, default=str))


@config_app.command("validate")
def config_validate(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), config_file: Path | None = typer.Option(None, "--file")) -> None:
    cfg = _config(_root(root), config_file); typer.echo(f"OK: {cfg.project_root}")


@config_app.command("migrate")
def config_migrate(
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    config_file: Path | None = typer.Option(None, "--file"),
    write: bool = typer.Option(
        False,
        "--write",
        help="Atomically replace the source after an exact-byte backup",
    ),
) -> None:
    """Preview a versioned config migration; write only with --write."""

    project_root = _root(root)
    selected = config_file or _discover_config(project_root) or (project_root / "astercode.toml")
    if _STRICT_SHORTCUT:
        try:
            selected = validate_strict_project_file(selected, project_root)
        except ConfigError as exc:
            raise typer.BadParameter(str(exc)) from exc
    try:
        result = migrate_config_file(
            selected,
            project_root=project_root,
            write=write,
        )
    except ConfigMigrationError as exc:
        typer.echo(f"BLOCKED: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    payload = result.as_dict()
    canonical = payload.pop("canonical_text", None)
    console.print_json(json.dumps(payload, ensure_ascii=False, default=str))
    if canonical is not None:
        typer.echo("--- canonical preview (no file was changed) ---")
        typer.echo(canonical, nl=False)


@permissions_app.command("show")
def permissions_show(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root))
    console.print_json(json.dumps({"P0": "read-only local", "P1": "workspace reversible write", "P2": "boundary/unsandboxed/installation", "P3": "external side effect", "P4": "high risk default deny", "network_mode": cfg.security.network_mode.value, "authorized_roots": [str(p) for p in cfg.security.authorized_roots], "authorized_ssh_hosts": [h.host_id for h in cfg.security.authorized_ssh_hosts]}, ensure_ascii=False))


@permissions_app.command("revoke")
def permissions_revoke(approval_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    """Revoke one persisted approval before it is consumed."""
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.revoke_approval(approval_id), ensure_ascii=False, default=str))


@permissions_app.command("grants")
def permissions_grants(
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    session_id: str | None = typer.Option(None, "--session"),
) -> None:
    """List exact, expiring session-scoped P1/P2 grants."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.list_session_grants(session_id), ensure_ascii=False, default=str))


@permissions_app.command("revoke-grant")
def permissions_revoke_grant(
    grant_id: str,
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
) -> None:
    """Revoke one unexpired session-scoped grant."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    console.print_json(json.dumps(storage.revoke_session_grant(grant_id), ensure_ascii=False, default=str))


@audit_app.command("verify")
def audit_verify(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    """Verify the SQLite and JSONL audit hash chain without modifying it."""

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    result = storage.verify_audit_chain()
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if not result.get("valid"):
        raise typer.Exit(code=2)


@audit_app.command("repair")
def audit_repair(
    root: Path = typer.Option(Path.cwd(), "--root", file_okay=False),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Explicitly append DB-backed records missing from an untampered JSONL mirror.",
    ),
) -> None:
    """Append-only repair of a missing JSONL mirror record; never deletes evidence."""

    if not confirm:
        console.print(
            "Refusing to mutate audit evidence without --confirm. "
            "Run `audit verify` first; repair only appends exact DB-backed records.",
            style="yellow",
        )
        raise typer.Exit(code=2)
    from .storage import AuditIntegrityError

    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    try:
        repair = storage.repair_audit_mirror()
    except AuditIntegrityError as exc:
        console.print_json(
            json.dumps(
                {"repaired": False, "error": str(exc)},
                ensure_ascii=False,
            )
        )
        raise typer.Exit(code=2) from None
    verification = storage.verify_audit_chain()
    result = {"repair": repair, "verification": verification}
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if not verification.get("valid"):
        raise typer.Exit(code=2)


@ssh_hosts_app.command("list")
def ssh_hosts_list(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root))
    console.print_json(json.dumps([host.model_dump(mode="json") | {"fingerprint": "[configured]"} for host in cfg.security.authorized_ssh_hosts], ensure_ascii=False, default=str))


@ssh_hosts_app.command("test")
def ssh_hosts_test(host_id: str, root: Path = typer.Option(Path.cwd(), "--root", file_okay=False)) -> None:
    cfg = _config(_root(root))
    from .tools.ssh import SSHTools

    result = SSHTools(cfg.security.authorized_ssh_hosts, cfg.security.authorized_roots).test_connection(host_id)
    # Fingerprints and credentials are never echoed; the adapter returns a
    # bounded, redacted result with an explicit LIVE/blocked status.
    console.print_json(json.dumps(result.as_dict(), ensure_ascii=False, default=str))


@app.command()
def kill(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), clear: bool = typer.Option(False, "--clear")) -> None:
    """Engage or clear the process-independent kill switch."""
    cfg = _config(_root(root)); storage = _storage(cfg); storage.initialize()
    if clear:
        storage.clear_kill_switch(); typer.echo("kill switch cleared")
    else:
        from .tools.process import ProcessTools

        storage.set_kill_switch(reason="user command")
        stopped = 0
        unknown = 0
        for record in storage.list_active_processes():
            expected = record.get("identity_token")
            current = ProcessTools.process_identity(int(record["pid"]))
            verified_stopped = current == "missing" or (
                isinstance(expected, str)
                and isinstance(current, str)
                and current != expected
            )
            if not verified_stopped:
                verified_stopped = ProcessTools.terminate_registered(
                    int(record["pid"]), expected if isinstance(expected, str) else None
                )
            storage.mark_process_stopped(
                str(record["action_id"]),
                status="stopped" if verified_stopped else "unknown",
            )
            if verified_stopped:
                stopped += 1
            else:
                unknown += 1
        typer.echo(f"kill switch engaged; stopped={stopped}; unknown={unknown}")


def _minimal_config(root: Path) -> str:
    return f'''config_version = 1\nproduct_name = "AsterCode"\nproject_root = "{root.as_posix()}"\n\n[security]\nnetwork_mode = "deny_by_default"\nauthorized_roots = ["{root.as_posix()}"]\n\n[model]\nprovider = "openai"\n# model_id = "set explicitly; never hard-code a secret"\n'''


if __name__ == "__main__":
    # ``python -m astercode.cli`` is a public CLI path too; do not leave it as
    # an escape hatch around the strict workspace boundary.
    from .terminal import configure_utf8_output

    configure_utf8_output()
    _STRICT_SHORTCUT = True
    app()
