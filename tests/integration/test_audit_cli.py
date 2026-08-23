from __future__ import annotations

import json

from typer.testing import CliRunner

from astercode.cli import app


def _write_config(tmp_path) -> None:
    root = str(tmp_path)
    database_path = str(tmp_path / ".astercode" / "test.db")
    audit_jsonl_path = str(tmp_path / ".astercode" / "audit.jsonl")
    artifacts_dir = str(tmp_path / ".astercode" / "artifacts")
    lines = [
        'product_name = "AsterCode"',
        f"project_root = {json.dumps(root)}",
        "",
        "[model]",
        'provider = "fake"',
        "",
        "[security]",
        'network_mode = "deny_by_default"',
        f"authorized_roots = [{json.dumps(root)}]",
        "",
        "[storage]",
        f"database_path = {json.dumps(database_path)}",
        f"audit_jsonl_path = {json.dumps(audit_jsonl_path)}",
        f"artifacts_dir = {json.dumps(artifacts_dir)}",
    ]
    (tmp_path / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_audit_repair_requires_explicit_confirmation(tmp_path) -> None:
    _write_config(tmp_path)
    result = CliRunner().invoke(app, ["audit", "repair", "--root", str(tmp_path)])

    assert result.exit_code == 2
    assert "without --confirm" in result.stdout


def test_audit_repair_noop_verifies_an_empty_chain(tmp_path) -> None:
    _write_config(tmp_path)
    result = CliRunner().invoke(
        app,
        ["audit", "repair", "--root", str(tmp_path), "--confirm"],
    )

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert output["repair"]["repaired"] is False
    assert output["verification"]["valid"] is True
