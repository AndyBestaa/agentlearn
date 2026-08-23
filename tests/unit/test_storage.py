from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.storage import Storage


def test_storage_rejects_a_hard_linked_database_before_writing(
    app_config: AppConfig, tmp_path: Path
) -> None:
    state = app_config.storage.database_path.parent
    state.mkdir(parents=True, exist_ok=True)
    outside = tmp_path.parent / f"{tmp_path.name}-outside-state.db"
    outside.write_bytes(b"")
    try:
        try:
            os.link(outside, app_config.storage.database_path)
        except OSError as exc:
            pytest.skip(f"hard links are unavailable on this host: {exc}")

        with pytest.raises(RuntimeError, match="hard-linked"):
            Storage(app_config.storage).initialize()

        assert outside.stat().st_size == 0
    finally:
        app_config.storage.database_path.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)


def test_storage_enables_wal_and_fts5(app_config: AppConfig, storage: Storage) -> None:
    with sqlite3.connect(app_config.storage.database_path) as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        fts_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE name='memory_fts'"
        ).fetchone()

    assert journal_mode.lower() == "wal"
    assert fts_table == ("memory_fts",)


def test_memory_requires_proposal_before_commit_and_is_fts_indexed(
    app_config: AppConfig, storage: Storage
) -> None:
    proposal = storage.propose_memory(
        content="The project uses deterministic offline provider tests",
        namespace="project",
        source="unit-test",
        ttl_days=30,
        tags=["testing", "offline"],
    )

    assert storage.list_memory() == []
    committed = storage.commit_memory(proposal["proposal_id"])
    assert committed["namespace"] == "project"
    assert committed["content"] == proposal["content"]

    with sqlite3.connect(app_config.storage.database_path) as connection:
        rows = connection.execute(
            "SELECT memory_id FROM memory_fts WHERE memory_fts MATCH ?",
            ("deterministic",),
        ).fetchall()
    assert rows == [(committed["memory_id"],)]


def test_memory_rejects_probable_secrets(storage: Storage) -> None:
    with pytest.raises(ValueError, match="secret"):
        storage.propose_memory(
            content="sk-" + "F" * 24,
            namespace="project",
            source="unit-test",
        )


def test_persisted_events_and_audit_are_redacted(
    app_config: AppConfig, storage: Storage
) -> None:
    session = storage.create_session(str(app_config.project_root), "redaction test")
    fake_token = "sk-" + "R" * 24
    storage.save_event(session["session_id"], "tool.result", {"stdout": fake_token})

    events = storage.list_events(session["session_id"])
    audit_lines = app_config.storage.audit_jsonl_path.read_text(encoding="utf-8").splitlines()

    assert fake_token not in json.dumps(events)
    assert fake_token not in "\n".join(audit_lines)
    assert "[REDACTED]" in json.dumps(events)


def test_audit_chain_verifier_detects_jsonl_tampering(
    app_config: AppConfig, storage: Storage
) -> None:
    session = storage.create_session(str(app_config.project_root), "audit verify")
    storage.save_event(session["session_id"], "audit.fixture", {"value": "safe"})

    assert storage.verify_audit_chain()["valid"] is True

    path = app_config.storage.audit_jsonl_path
    content = path.read_text(encoding="utf-8")
    path.write_text(content.replace('"value":"safe"', '"value":"changed"'), encoding="utf-8")

    # Even if a textual replacement does not match formatting, deleting the
    # mirror still has to be detected against the authoritative DB chain.
    if storage.verify_audit_chain()["valid"]:
        path.write_text("", encoding="utf-8")
    result = storage.verify_audit_chain()
    assert result["valid"] is False
    assert "JSONL" in result["reason"]
