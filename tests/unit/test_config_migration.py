from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from astercode.cli import app
from astercode.config import AppConfig, _normalise_legacy_config, load_config
from astercode.config_migration import (
    ConfigMigrationConflict,
    migrate_config_file,
    render_config_toml,
)
from astercode.lock import InterProcessFileLock


def _legacy_config(root: Path) -> bytes:
    return (
        '[product]\n'
        'name = "AsterCode"\n'
        f'project_root = "{root.as_posix()}"\n'
        'execution_mode = "inspect_then_implement"\n'
        '\n[model]\n'
        'provider = "fake"\n'
        '\n[budgets]\n'
        'max_turns = 7\n'
        'max_tool_calls = 9\n'
        'max_wall_time_seconds = 120\n'
        '\n[security]\n'
        'network_mode = "deny_by_default"\n'
        'authorized_roots = ["."]\n'
        'max_output_bytes = 4096\n'
        'default_command_timeout_seconds = 30\n'
        'enable_browser_automation = false\n'
        '\n[storage]\n'
        'database_path = ".astercode/astercode.db"\n'
        'artifact_dir = ".astercode/artifacts"\n'
        'audit_log_path = ".astercode/audit.jsonl"\n'
        'wal = true\n'
        '\n[approval]\n'
        'persist_requests = true\n'
        'single_use = true\n'
        'default_expiry_seconds = 600\n'
    ).encode()


def test_legacy_config_conflicts_and_malformed_sections_fail_closed() -> None:
    with pytest.raises(ValueError, match="conflicts"):
        _normalise_legacy_config(
            {
                "budget": {"max_rounds": 7},
                "budgets": {"max_turns": 99},
            }
        )
    with pytest.raises(ValueError, match="must be a TOML table"):
        _normalise_legacy_config({"product": "malformed"})
    with pytest.raises(ValueError, match="newer than supported"):
        _normalise_legacy_config({"config_version": 999})
    with pytest.raises(ValueError, match="cannot contain legacy sections"):
        _normalise_legacy_config(
            {"config_version": 1, "budgets": {"max_turns": 2}}
        )
    with pytest.raises(ValueError, match="wal=false"):
        _normalise_legacy_config({"storage": {"wal": False}})
    with pytest.raises(ValueError, match="conflicts"):
        _normalise_legacy_config(
            {
                "execution_mode": "read_only",
                "security": {"allow_workspace_writes": True},
            }
        )


def test_config_migration_preview_is_read_only_and_ignores_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.toml"
    source = _legacy_config(tmp_path)
    config_path.write_bytes(source)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-must-never-be-persisted")
    monkeypatch.setenv("ASTERCODE_MODEL_ID", "deepseek-v4-flash")

    result = migrate_config_file(config_path, project_root=tmp_path)

    assert result.changed is True
    assert result.written is False
    assert result.backup_path is None
    assert config_path.read_bytes() == source
    assert result.canonical_text is not None
    assert "sk-must-never-be-persisted" not in result.canonical_text
    parsed = tomllib.loads(result.canonical_text)
    assert parsed["config_version"] == 1
    assert "product" not in parsed
    assert "budgets" not in parsed
    assert "approval" not in parsed
    assert parsed["budget"]["max_rounds"] == 7
    assert parsed["security"]["process"]["max_output_bytes"] == 4096
    assert not list(tmp_path.glob("config.toml.v*.bak"))


def test_config_migration_write_has_exact_backup_and_is_idempotent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    source = _legacy_config(tmp_path)
    config_path.write_bytes(source)

    first = migrate_config_file(config_path, project_root=tmp_path, write=True)

    assert first.written is True
    assert first.changed is True
    assert first.backup_path is not None
    assert Path(first.backup_path).read_bytes() == source
    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["config_version"] == 1
    assert load_config(config_path, project_root=tmp_path, environ={}).budget.max_rounds == 7

    second = migrate_config_file(config_path, project_root=tmp_path, write=True)

    assert second.changed is False
    assert second.written is False
    assert second.backup_path is None
    assert len(list(tmp_path.glob("config.toml.v*.bak"))) == 1


def test_config_migration_refuses_concurrent_source_change_before_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.toml"
    source = _legacy_config(tmp_path)
    config_path.write_bytes(source)
    original_acquire = InterProcessFileLock.acquire
    changed = False

    def racing_acquire(
        self: InterProcessFileLock, timeout_seconds: float = 30.0
    ) -> None:
        nonlocal changed
        if not changed:
            changed = True
            config_path.write_bytes(source + b"\n# concurrent edit\n")
        original_acquire(self, timeout_seconds)

    monkeypatch.setattr(InterProcessFileLock, "acquire", racing_acquire)

    with pytest.raises(ConfigMigrationConflict, match="changed after inspection"):
        migrate_config_file(config_path, project_root=tmp_path, write=True)

    assert config_path.read_bytes().endswith(b"# concurrent edit\n")
    assert not list(tmp_path.glob("config.toml.v*.bak"))


def test_config_migration_refuses_to_duplicate_inline_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    fake_secret = ("s" + "k-" + "1234567890abcdefghijklmnop").encode()
    config_path.write_bytes(
        _legacy_config(tmp_path) + b"\n# " + fake_secret + b"\n"
    )

    preview = CliRunner().invoke(
        app,
        ["config", "migrate", "--root", str(tmp_path), "--write"],
    )

    assert preview.exit_code == 2
    assert "probable inline secret" in preview.output
    assert not list(tmp_path.glob("config.toml.v*.bak"))


def test_config_migrate_cli_previews_then_writes(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    source = _legacy_config(tmp_path)
    config_path.write_bytes(source)
    runner = CliRunner()

    preview = runner.invoke(
        app,
        ["config", "migrate", "--root", str(tmp_path)],
    )
    assert preview.exit_code == 0, preview.output
    assert "canonical preview" in preview.output
    assert config_path.read_bytes() == source

    written = runner.invoke(
        app,
        ["config", "migrate", "--root", str(tmp_path), "--write"],
    )
    assert written.exit_code == 0, written.output
    assert '"written": true' in written.output.lower()
    assert tomllib.loads(config_path.read_text(encoding="utf-8"))["config_version"] == 1


def test_canonical_renderer_round_trips_arrays_of_tables(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "project_root": str(tmp_path),
            "model": {"provider": "fake"},
            "security": {
                "authorized_roots": [str(tmp_path)],
                "authorized_ssh_hosts": [
                    {
                        "host_id": "build-host",
                        "hostname": "build.example.com",
                        "port": 2222,
                        "user": "builder",
                        "host_key_fingerprint": "sha256:abcdefghijklmnop",
                    }
                ],
                "extensions": {
                    "mcp_enabled": True,
                    "mcp_pins": [
                        {
                            "extension_id": "example.tool",
                            "source": "https://example.invalid/tool",
                            "version": "1.2.3",
                            "sha256": "a" * 64,
                            "capabilities": ["read"],
                        }
                    ],
                },
            },
        }
    )
    rendered = render_config_toml(config)
    path = tmp_path / "canonical.toml"
    path.write_text(rendered, encoding="utf-8")

    assert "[[security.authorized_ssh_hosts]]" in rendered
    assert "[[security.extensions.mcp_pins]]" in rendered
    loaded = load_config(path, project_root=tmp_path, environ={})
    assert loaded.security.authorized_ssh_hosts[0].port == 2222
    assert loaded.security.extensions.mcp_pins[0].capabilities == frozenset({"read"})
