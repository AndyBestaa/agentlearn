"""Typer CLI for the AsterCode local coding agent."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Coroutine

import typer
from rich.console import Console
from rich.table import Table

from .config import ConfigError, load_config
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


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a CLI coroutine without replacing an existing host event loop."""

    with asyncio.Runner(loop_factory=asyncio.new_event_loop) as runner:
        return runner.run(coro)


def _root(value: Path | None) -> Path:
    return (value or Path.cwd()).expanduser().resolve()


def _config(root: Path, config_file: Path | None = None):
    selected = config_file
    if selected is None:
        candidate = root / "config.toml"
        if candidate.is_file():
            selected = candidate
    return load_config(selected, project_root=root)


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
    state.mkdir(exist_ok=True)
    config_path = root / "config.toml"
    if config_path.exists() and not force:
        typer.echo(f"已存在，未覆盖: {config_path}")
    elif not config_path.exists() or force:
        source_template = Path(__file__).resolve().parents[2] / "config.example.toml"
        packaged_template = Path(__file__).resolve().with_name("config.example.toml")
        template = source_template if source_template.exists() else packaged_template
        if template.exists():
            config_path.write_bytes(template.read_bytes())
        else:
            config_path.write_text(_minimal_config(root), encoding="utf-8")
        typer.echo(f"已创建: {config_path}")
    cfg = _config(root, config_path if config_path.exists() else None)
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
        checks.append(("network enforcement", "BLOCKED", "no runtime-attested OS egress sandbox/allowlist adapter"))
        checks.append(("sandbox", "BLOCKED", "no runtime-attested filesystem/process sandbox; launch tools fail closed even after approval"))
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


def _run_task_impl(task: str, *, root: Path, session_id: str | None, fake: bool, auto_approve: bool, stream: bool = False, replay: Path | None = None, dry_run: bool = False, budget_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
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
        )
    )


async def _run_task_async(task: str, *, root: Path, session_id: str | None, fake: bool, auto_approve: bool, stream: bool = False, replay: Path | None = None, dry_run: bool = False, budget_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Async task core; callers that already own a loop can await it directly."""

    root = _root(root)
    cfg = _config(root)
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
        event_type = str(event.get("event", "event")) if isinstance(event, dict) else "event"
        if event_type == "provider.delta" and isinstance(event, dict):
            console.print(str(event.get("delta", "")), end="", markup=False, highlight=False)
            return
        if event_type == "provider.completed":
            console.print()
        details = {
            key: event[key]
            for key in ("tool", "attempt", "response_id")
            if isinstance(event, dict) and event.get(key) is not None
        }
        console.print(f"[dim]{event_type} {json.dumps(details, ensure_ascii=False)}[/dim]")

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


@app.command()
def chat(root: Path = typer.Option(Path.cwd(), "--root", file_okay=False), fake: bool = typer.Option(False, "--fake")) -> None:
    """Interactive multi-turn shell; Ctrl-C exits without starting a new tool."""
    typer.echo("AsterCode chat；输入 exit/quit 结束。")
    session_id: str | None = None
    while True:
        try:
            message = typer.prompt("你")
        except (KeyboardInterrupt, EOFError):
            typer.echo("\n已取消")
            return
        if message.strip().lower() in {"exit", "quit", ":q"}:
            return
        # Reuse the one-shot path so every turn goes through the same policy.
        result = _run_task_impl(message, root=_root(root), session_id=session_id, fake=fake, auto_approve=False, stream=True)
        session_id = str(result.get("session_id") or session_id or "") or None
        console.print_json(json.dumps(result, ensure_ascii=False, default=str))


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
    selected = config_file or (project_root / "config.toml")
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
    app()
