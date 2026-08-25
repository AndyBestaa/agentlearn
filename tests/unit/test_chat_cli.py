from __future__ import annotations

import os
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from typer.testing import CliRunner

from astercode import cli
from astercode.config import AppConfig, SandboxBackend
from astercode.tools.docker_process import DockerSandboxAttestation


def _approval_request(root: Path) -> dict[str, Any]:
    return {
        "approval_id": "approval_test",
        "action_id": "action_test",
        "action_hash": "0" * 64,
        "nonce": "nonce_nonce_nonce_nonce",
        "tool": "fs.apply_patch",
        "risk": "P1",
        "purpose": "create hello.py",
        "host": "local",
        "port": 2222,
        "user": "git-user",
        "host_fingerprint": "SHA256:test-fingerprint",
        "cwd": str(root),
        "real_paths": [str(root / "hello.py")],
        "side_effects": ["file_write"],
        "normalized_action": {"arguments": {"patch": "*** Begin Patch\n*** Add File: hello.py\n+print('hello')\n*** End Patch"}},
    }


def test_terminal_safe_escapes_control_and_bidi_characters() -> None:
    value = "before\x1b[2J\rafter\u202e.txt"

    rendered = cli._terminal_safe(value)

    assert rendered == r"before\x1b[2J\x0dafter\u202e.txt"
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered


def test_doctor_separates_tool_detection_from_supply_chain_evidence(
    monkeypatch: pytest.MonkeyPatch,
    app_config: AppConfig,
) -> None:
    data = app_config.model_dump(mode="python")
    data["security"]["process"]["sandbox_backend"] = SandboxBackend.CONTAINER
    config = AppConfig.model_validate(data)
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None, width=220),
    )
    monkeypatch.setattr(cli, "_config", lambda _root: config)
    monkeypatch.setattr(
        "astercode.tools.docker_process.discover_trusted_docker",
        lambda: Path("C:/trusted/docker.exe"),
    )
    monkeypatch.setattr(
        "astercode.tools.docker_process.discover_trusted_image_tool",
        lambda name: Path(f"C:/trusted/{name}.exe"),
    )
    monkeypatch.setattr(
        "astercode.tools.docker_process.attest_docker_sandbox",
        lambda **_kwargs: DockerSandboxAttestation(
            executable=Path("C:/trusted/docker.exe"),
            configured_image=config.security.process.container_image,
            image_digest=config.security.process.container_image,
            image_id="sha256:" + "a" * 64,
        ),
    )

    cli.doctor(root=app_config.project_root)

    rendered = output.getvalue()
    assert "cosign executable" in rendered
    assert "syft executable" in rendered
    assert "trivy executable" in rendered
    assert rendered.count("DETECTED") >= 3
    assert "image signature verification" in rendered
    assert "SBOM generation" in rendered
    assert "vulnerability scanning" in rendered
    assert rendered.count("NOT VERIFIED") >= 3
    assert "executable detection is not operation evidence" in rendered


def test_stream_event_escapes_terminal_controls(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    cli._print_stream_event({"event": "provider.delta", "delta": "before\x1b[2J\u202eafter"})

    rendered = output.getvalue()
    assert r"before\x1b[2J\u202eafter" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered


def test_chat_progress_hides_model_json_and_renders_safe_lifecycle(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    cli._print_chat_event(
        {
            "event": "provider.delta",
            "delta": '{"internal":"must not be displayed"}',
        }
    )
    cli._print_chat_event({"event": "provider.started"})
    cli._print_chat_event({"event": "provider.retry", "attempt": 2})
    cli._print_chat_event(
        {"event": "tool.started", "tool": "fs.read\x1b[2J\u202e", "attempt": 1}
    )
    cli._print_chat_event(
        {"event": "tool.completed", "tool": "fs.read", "status": "completed"}
    )
    cli._print_chat_event({"event": "tool.retry", "tool": "fs.read", "attempt": 2})

    rendered = output.getvalue()
    assert "must not be displayed" not in rendered
    assert "正在分析任务" in rendered
    assert "模型响应异常" in rendered
    assert "执行 fs.read" in rendered
    assert "fs.read: completed" in rendered
    assert "fs.read 失败，正在重试" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert r"\x1b[2J\u202e" in rendered


def test_chat_result_uses_human_status_and_completion_labels(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    cli._print_chat_result(
        {
            "status": "completed",
            "messages": ["测试通过。"],
            "tool_results": [
                {
                    "action_id": "action_1",
                    "tool": "process.exec",
                    "status": "completed",
                }
            ],
            "blockers": [],
        },
        set(),
    )
    cli._print_chat_result(
        {
            "status": "blocked",
            "messages": [],
            "tool_results": [],
            "blockers": ["sandbox attestation failed"],
        },
        set(),
    )

    rendered = output.getvalue()
    assert "✓ 已完成" in rendered
    assert "已安全停止（blocked）" in rendered
    assert "原因：sandbox attestation failed" in rendered


def test_chat_result_deduplicates_tool_already_shown_by_live_progress(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    cli._print_chat_result(
        {
            "status": "completed",
            "messages": ["已验证。"],
            "tool_results": [{"action_id": "action_live", "tool": "fs.read", "status": "completed"}],
            "blockers": [],
        },
        set(),
        {"action_live"},
    )

    rendered = output.getvalue()
    assert "工具 fs.read" not in rendered
    assert "Aster> 已验证。" in rendered
    assert "✓ 已完成" in rendered


def test_chat_result_renders_bounded_plan_and_verification_handoff(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None, width=220),
    )

    cli._print_chat_result(
        {
            "status": "completed",
            "plan": ["inspect", "fix", "verify"],
            "completed": ["inspect", "fix"],
            "pending": ["verify"],
            "active_files": ["calculator.py"],
            "next_action": "run the focused test",
            "messages": ["已应用修复。"],
            "tool_results": [
                {"action_id": "action_read", "tool": "fs.read", "status": "completed"},
                {"action_id": "action_patch", "tool": "fs.apply_patch", "status": "completed"},
                {
                    "action_id": "action_diff",
                    "tool": "git.diff",
                    "status": "completed",
                    "stdout": "diff --git a/calculator.py b/calculator.py\n--- a/calculator.py\n+++ b/calculator.py\n-    return left - right\n+    return left + right\n",
                },
            ],
            "test_status": [
                {"action_id": "action_read", "status": "completed", "verified": True},
                {"action_id": "action_patch", "status": "failed", "verified": False},
            ],
            "blockers": [],
        },
        set(),
    )

    rendered = output.getvalue()
    assert "本轮摘要" in rendered
    assert "inspect → fix → verify" in rendered
    assert "已完成" in rendered
    assert "待处理" in rendered
    assert "calculator.py" in rendered
    assert "fs.read：通过" in rendered
    assert "fs.apply_patch：未通过（failed）" in rendered
    assert "差异" in rendered
    assert "1 个文件 · +1/-1 行" in rendered
    assert "run the focused test" in rendered
    assert "{\"action_id\"" not in rendered


def test_chat_summary_drops_complex_values_and_bounds_untrusted_text() -> None:
    values = cli._chat_summary_values([{"secret": "hidden"}, "ok\x1b" + ("x" * 300)])

    assert values == [r"ok\x1b" + ("x" * 173) + "…"]


def test_chat_status_is_a_compact_summary(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    cli._print_chat_status(
        {
            "session_id": "session_demo",
            "status": "waiting_approval",
            "goal": "修复 calculator",
            "state": {
                "usage": {"rounds": 2, "tool_calls": 3, "total_tokens": 1200},
                "budget": {"max_rounds": 12, "max_tool_calls": 64},
                "next_action": "review approval",
                "blockers": [],
            },
        }
    )

    rendered = output.getvalue()
    assert "session_demo" in rendered
    assert "等待审批（waiting_approval）" in rendered
    assert "轮次 2/12 · 工具 3/64 · Token 1200" in rendered
    assert "astercode status --session session_demo" in rendered
    assert '{"' not in rendered


def test_live_chat_fails_before_a_turn_when_key_is_missing(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    monkeypatch.setenv("ASTERCODE_MODEL_PROVIDER", "deepseek")
    monkeypatch.setenv("ASTERCODE_MODEL_ID", "deepseek-v4-flash")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(
        cli,
        "_run_task_impl",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("a model turn must not start without its key")),
    )

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path)],
        input="inspect README.md\n",
    )

    assert result.exit_code == 2
    assert "DEEPSEEK_API_KEY" in result.output


def test_discover_config_ignores_an_unrelated_generic_toml(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text("[application]\nname='other'\n", encoding="utf-8")

    assert cli._discover_config(tmp_path) is None

    (tmp_path / "config.toml").write_text(
        "config_version=1\nproduct_name='Other'\n[model]\nname='x'\n[security]\nmode='x'\n",
        encoding="utf-8",
    )
    assert cli._discover_config(tmp_path) is None

    (tmp_path / "astercode.toml").write_text(
        "config_version=1\nproduct_name='test'\n[model]\nprovider='fake'\n",
        encoding="utf-8",
    )
    assert cli._discover_config(tmp_path) == tmp_path / "astercode.toml"


def test_discover_config_keeps_the_legacy_astercode_schema(tmp_path: Path) -> None:
    legacy = tmp_path / "config.toml"
    legacy.write_text(
        "[product]\nname='AsterCode'\n[model]\nprovider='fake'\n[security]\nnetwork_mode='deny_by_default'\n",
        encoding="utf-8",
    )

    assert cli._discover_config(tmp_path) == legacy


def test_init_does_not_overwrite_an_unrelated_generic_config(tmp_path: Path) -> None:
    generic = tmp_path / "config.toml"
    original = "[application]\nname='other'\n"
    generic.write_text(original, encoding="utf-8")

    result = CliRunner().invoke(cli.app, ["init", "--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert generic.read_text(encoding="utf-8") == original
    assert (tmp_path / "astercode.toml").is_file()
    assert (tmp_path / ".astercode" / "astercode.db").is_file()


def test_init_rejects_a_hard_linked_project_config(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-config.toml"
    original = b"config_version=1\nproduct_name='AsterCode'\n[model]\nprovider='fake'\n"
    outside.write_bytes(original)
    config = tmp_path / "astercode.toml"
    try:
        try:
            os.link(outside, config)
        except OSError as exc:
            pytest.skip(f"hard links are unavailable on this host: {exc}")

        result = CliRunner().invoke(
            cli.app,
            ["init", "--root", str(tmp_path), "--force"],
        )

        assert result.exit_code != 0
        assert "hard-linked" in str(result.exception)
        assert outside.read_bytes() == original
    finally:
        config.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)


def test_aster_shortcut_init_uses_the_strict_workspace_boundary(tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    (tmp_path / "astercode.toml").write_text(
        "\n".join(
            (
                "config_version=1",
                "product_name='test'",
                "[model]",
                "provider='fake'",
                "[security]",
                f"authorized_roots=['{outside.as_posix()}']",
                "[storage]",
                f"database_path='{(outside / 'outside.db').as_posix()}'",
                f"audit_jsonl_path='{(outside / 'outside.jsonl').as_posix()}'",
                f"artifacts_dir='{(outside / 'artifacts').as_posix()}'",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_STRICT_SHORTCUT", True)

    result = CliRunner().invoke(cli.app, ["init", "--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / ".astercode" / "astercode.db").is_file()
    assert not outside.exists()


def test_chat_config_finally_binds_the_launch_directory(tmp_path: Path, monkeypatch) -> None:
    outside = (tmp_path.parent / f"{tmp_path.name}-does-not-exist").resolve()
    (tmp_path / "astercode.toml").write_text(
        "\n".join(
            (
                "config_version=1",
                "product_name='test'",
                f"project_root='{outside.as_posix()}'",
                "[model]",
                "provider='fake'",
                "[security]",
                f"authorized_roots=['{outside.as_posix()}']",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTERCODE_PROJECT_ROOT", str(outside))

    config = cli._chat_config(tmp_path.resolve())

    assert config.project_root == tmp_path.resolve()
    assert config.security.authorized_roots == [tmp_path.resolve()]
    assert config.storage.database_path.parent == tmp_path.resolve() / ".astercode"

    monkeypatch.setattr(cli, "_STRICT_SHORTCUT", True)
    shortcut_config = cli._config(tmp_path.resolve())
    assert shortcut_config.security.authorized_roots == [tmp_path.resolve()]


def test_chat_config_ignores_project_live_provider_and_ssh_authority(tmp_path: Path, monkeypatch) -> None:
    outside_known_hosts = tmp_path.parent / f"{tmp_path.name}-known-hosts"
    (tmp_path / "astercode.toml").write_text(
        "\n".join(
            (
                "config_version=1",
                "product_name='test'",
                "[model]",
                "provider='deepseek'",
                "model_id='deepseek-v4-flash'",
                "api_key_env='GITHUB_TOKEN'",
                "base_url='https://api.deepseek.com'",
                "[security]",
                "network_mode='allowlist'",
                "network_allowlist=['api.deepseek.com']",
                "[[security.authorized_ssh_hosts]]",
                "host_id='production'",
                "hostname='example.com'",
                "user='root'",
                "host_key_fingerprint='SHA256:project-controlled-value'",
                f"known_hosts='{outside_known_hosts.as_posix()}'",
                "[security.ssh]",
                "enabled=true",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("ASTERCODE_MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("ASTERCODE_MODEL_ID", raising=False)
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("ASTERCODE_API_KEY_ENV", raising=False)

    config = cli._chat_config(tmp_path.resolve())

    assert config.model.provider == "fake"
    assert config.model.model_id is None
    assert config.security.authorized_ssh_hosts == []
    assert config.security.network_allowlist == []
    assert config.security.ssh.enabled is False


def test_chat_config_accepts_live_provider_only_from_user_environment(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "astercode.toml").write_text(
        "config_version=1\nproduct_name='test'\n[model]\nprovider='fake'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTERCODE_MODEL_PROVIDER", "deepseek")
    monkeypatch.setenv("ASTERCODE_MODEL_ID", "deepseek-v4-flash")
    monkeypatch.setenv("ASTERCODE_API_KEY_ENV", "GITHUB_TOKEN")

    config = cli._chat_config(tmp_path.resolve())

    assert config.model.provider == "deepseek"
    assert config.model.model_id == "deepseek-v4-flash"
    assert config.model.api_key_env == "DEEPSEEK_API_KEY"
    assert config.model.base_url == "https://api.deepseek.com"


def test_named_project_config_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(
        "config_version=1\nproduct_name='test'\n[model]\nprovider='fake'\n",
        encoding="utf-8",
    )
    link = tmp_path / "astercode.toml"
    try:
        link.symlink_to(outside)
    except OSError:
        outside.unlink(missing_ok=True)
        pytest.skip("file symlinks are unavailable on this Windows host")
    try:
        with pytest.raises(cli.ConfigError, match="cannot be a link"):
            cli._discover_config(tmp_path.resolve())
    finally:
        link.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)


def test_dangling_state_symlink_is_rejected_before_initialization(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".astercode"
    try:
        state.symlink_to(tmp_path / "missing-state", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this Windows host")
    try:
        with pytest.raises(cli.ConfigError, match="state directory cannot be a link"):
            cli._discover_config(tmp_path.resolve())
        with pytest.raises(cli.typer.BadParameter, match="must not be a link"):
            cli._prepare_chat_workspace(tmp_path.resolve())
    finally:
        state.unlink(missing_ok=True)


def test_project_selected_live_provider_cannot_start_from_chat(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    (tmp_path / "astercode.toml").write_text(
        "\n".join(
            (
                "config_version=1",
                "product_name='test'",
                "[model]",
                "provider='deepseek'",
                "model_id='deepseek-v4-flash'",
                "base_url='https://api.deepseek.com'",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("ASTERCODE_MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("ASTERCODE_MODEL_ID", raising=False)
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path)],
        input="/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert "fake/" in result.output
    assert "Key：不需要（fake）" in result.output


def test_strict_shortcut_rejects_a_broad_home_workspace(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_STRICT_SHORTCUT", True)

    with pytest.raises(cli.typer.BadParameter, match="broad/system workspace"):
        cli._root(Path.home())


def test_strict_workspace_rejects_unc_before_resolution() -> None:
    with pytest.raises(cli.ConfigError, match="UNC or device"):
        cli.validate_strict_workspace_root(Path(r"\\server\share\project"))


def test_strict_workspace_rejects_a_linked_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-project"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this Windows host")
    try:
        with pytest.raises(cli.ConfigError, match="link or junction"):
            cli.validate_strict_workspace_root(link)
    finally:
        link.unlink(missing_ok=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX system-tree regression")
@pytest.mark.parametrize("path", [Path("/etc"), Path("/proc")])
def test_strict_workspace_rejects_posix_system_trees(path: Path) -> None:
    with pytest.raises(cli.ConfigError, match="broad/system workspace"):
        cli.validate_strict_workspace_root(path)


def test_strict_config_rejects_an_explicit_config_outside_workspace(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text("[model]\nprovider='fake'\n", encoding="utf-8")
    try:
        with pytest.raises(cli.ConfigError, match="escapes the strict workspace"):
            cli.load_config(
                outside,
                project_root=tmp_path,
                environ={},
                strict_workspace=True,
            )
    finally:
        outside.unlink(missing_ok=True)


def test_aster_shortcut_migration_cannot_write_an_external_config(tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    original = "[product]\nname='AsterCode'\n[model]\nprovider='fake'\n[security]\n"
    outside.write_text(original, encoding="utf-8")
    monkeypatch.setattr(cli, "_STRICT_SHORTCUT", True)
    try:
        result = CliRunner().invoke(
            cli.app,
            [
                "config",
                "migrate",
                "--root",
                str(tmp_path),
                "--file",
                str(outside),
                "--write",
            ],
        )

        assert result.exit_code != 0
        assert "escapes the strict workspace" in result.output
        assert outside.read_text(encoding="utf-8") == original
    finally:
        outside.unlink(missing_ok=True)


def test_chat_locks_a_reconciled_nonterminal_session(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    monkeypatch.setattr(
        cli,
        "_chat_session_status",
        lambda root, session_id: {
            "session_id": session_id,
            "status": "running",
            "state": {"session_id": session_id, "status": "running"},
        },
    )
    monkeypatch.setattr(
        cli,
        "_reconcile_chat_session",
        lambda root, session_id: {
            "session_id": session_id,
            "status": "blocked",
            "messages": [],
            "tool_results": [],
            "blockers": ["read-only reconcile required"],
            "reconcile": {"read_only": True},
        },
    )
    monkeypatch.setattr(
        cli,
        "_run_task_impl",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("a locked session must not start a new model turn")),
    )

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="/resume session_running\ncontinue now\n/new\n/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert "当前会话因未确认的动作边界而锁定" in result.output


def test_chat_clear_starts_a_fresh_session_context(tmp_path: Path, monkeypatch) -> None:
    """Claude Code-style ``/clear`` must discard the active session binding."""

    (tmp_path / ".astercode").mkdir()
    session_bindings: list[str | None] = []

    def fake_run(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args
        session_bindings.append(kwargs.get("session_id"))
        turn = len(session_bindings)
        return {
            "session_id": f"session_{turn}",
            "status": "completed",
            "messages": [f"turn {turn}"],
            "tool_results": [],
            "blockers": [],
        }

    monkeypatch.setattr(cli, "_run_task_impl", fake_run)

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="first task\n/clear\nsecond task\n/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert session_bindings == [None, None]
    assert "已清除当前会话上下文，开始新会话" in result.output


def test_chat_enables_compact_progress_without_raw_provider_output(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    run_options: list[dict[str, Any]] = []

    def fake_run(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args
        run_options.append(kwargs)
        return {
            "session_id": "session_progress",
            "status": "completed",
            "messages": ["done"],
            "tool_results": [],
            "blockers": [],
        }

    monkeypatch.setattr(cli, "_run_task_impl", fake_run)

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="inspect the project\n/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert len(run_options) == 1
    assert run_options[0]["stream"] is True
    assert run_options[0]["interactive_progress"] is True


def test_chat_collects_bound_approval_instead_of_treating_text_as_consent(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    request = _approval_request(tmp_path.resolve())
    decisions: list[dict[str, Any]] = []

    def fake_run(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        return {
            "session_id": "session_chat",
            "status": "waiting_approval",
            "messages": ["I need permission to edit hello.py."],
            "tool_results": [],
            "blockers": [],
            "approval_request": request,
        }

    def fake_resume(root: Path, session_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        del root, session_id
        decisions.append(decision)
        return {
            "session_id": "session_chat",
            "status": "completed",
            "messages": ["The change was denied."],
            "tool_results": [],
            "blockers": [],
        }

    monkeypatch.setattr(cli, "_run_task_impl", fake_run)
    monkeypatch.setattr(cli, "_resume_chat_session", fake_resume)

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="write hello.py\nyes, do it please\nd\n/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert "请输入 a、s、d 或 q" in result.output
    assert "2222" in result.output
    assert "git-user" in result.output
    assert "SHA256:test-fingerprint" in result.output
    assert decisions[0]["approved"] is False
    assert decisions[0]["scope"] == "once"
    assert decisions[0]["action_hash"] == request["action_hash"]


def test_chat_can_grant_the_exact_p1_action_for_the_session(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()
    request = _approval_request(tmp_path.resolve())
    decisions: list[dict[str, Any]] = []

    monkeypatch.setattr(
        cli,
        "_run_task_impl",
        lambda *args, **kwargs: {
            "session_id": "session_chat",
            "status": "waiting_approval",
            "messages": [],
            "tool_results": [],
            "blockers": [],
            "approval_request": request,
        },
    )

    def fake_resume(root: Path, session_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        del root, session_id
        decisions.append(decision)
        return {
            "session_id": "session_chat",
            "status": "completed",
            "messages": ["done"],
            "tool_results": [],
            "blockers": [],
        }

    monkeypatch.setattr(cli, "_resume_chat_session", fake_resume)

    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="write hello.py\ns\n/exit\n",
    )

    assert result.exit_code == 0, result.output
    assert decisions[0]["approved"] is True
    assert decisions[0]["scope"] == "session"


def test_chat_ctrl_c_during_a_running_turn_exits_after_cleanup_message(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()

    def interrupted(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_run_task_impl", interrupted)
    result = CliRunner().invoke(
        cli.app,
        ["chat", "--root", str(tmp_path), "--fake"],
        input="run a long test\n",
    )

    assert result.exit_code == 0, result.output
    assert "本轮已取消" in result.output
    assert "运行时清理完成后退出对话" in result.output


def test_run_ctrl_c_returns_signal_exit_code_without_traceback(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".astercode").mkdir()

    def interrupted(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_run_task_impl", interrupted)
    result = CliRunner().invoke(
        cli.app,
        ["run", "long task", "--root", str(tmp_path), "--fake"],
    )

    assert result.exit_code == 130
    assert "已触发运行时清理" in result.output
    assert "Traceback" not in result.output
