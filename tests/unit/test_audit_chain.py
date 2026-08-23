from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from astercode.config import AppConfig
from astercode.models import utc_now
from astercode.security import GENESIS_AUDIT_HASH, audit_entry_hash
from astercode.storage import AuditIntegrityError, Storage


def test_explicit_repair_recovers_a_failed_db_to_jsonl_window_without_rewrite(
    app_config: AppConfig, storage: Storage, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_append = storage._append_audit_jsonl_locked
    failures_remaining = 1

    def fail_first_mirror_write(records: list[dict[str, Any]]) -> None:
        nonlocal failures_remaining
        if failures_remaining:
            failures_remaining -= 1
            raise OSError("simulated mirror write failure")
        original_append(records)

    monkeypatch.setattr(storage, "_append_audit_jsonl_locked", fail_first_mirror_write)
    with pytest.raises(OSError, match="simulated mirror write failure"):
        storage.append_audit(event_type="audit.before_gap", payload={"sequence": 1})

    # Reproduce the observed failure shape: later evidence exists in JSONL,
    # while one authoritative DB record in the middle is absent.
    later_id = storage.append_audit(
        event_type="audit.after_gap", payload={"sequence": 2}
    )
    before_repair = app_config.storage.audit_jsonl_path.read_bytes()
    assert later_id.encode("utf-8") in before_repair
    assert storage.verify_audit_chain()["valid"] is False

    result = storage.repair_audit_mirror()

    after_repair = app_config.storage.audit_jsonl_path.read_bytes()
    assert after_repair.startswith(before_repair)
    assert result["repaired"] is True
    assert result["missing_entries"] == 1
    assert result["repair_audit_id"]
    assert storage.verify_audit_chain() == {
        "valid": True,
        "entries": 3,
        "head": json.loads(after_repair.splitlines()[-1])["entry_hash"],
    }

    with sqlite3.connect(app_config.storage.database_path) as connection:
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM audit_log ORDER BY rowid"
            ).fetchall()
        ]
    assert event_types == [
        "audit.before_gap",
        "audit.after_gap",
        "audit.mirror_repaired",
    ]


def test_repair_refuses_conflicting_jsonl_without_mutating_evidence(
    app_config: AppConfig, storage: Storage
) -> None:
    storage.append_audit(event_type="audit.original", payload={"value": "original"})
    path = app_config.storage.audit_jsonl_path
    item = json.loads(path.read_text(encoding="utf-8"))
    item["payload"]["value"] = "tampered"
    path.write_text(json.dumps(item, sort_keys=True) + "\n", encoding="utf-8")
    tampered_bytes = path.read_bytes()

    with sqlite3.connect(app_config.storage.database_path) as connection:
        count_before = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    with pytest.raises(AuditIntegrityError, match="hash mismatch"):
        storage.repair_audit_mirror()

    assert path.read_bytes() == tampered_bytes
    with sqlite3.connect(app_config.storage.database_path) as connection:
        count_after = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    assert count_after == count_before
    assert storage.verify_audit_chain()["valid"] is False


def test_verifier_rejects_a_validly_hashed_jsonl_branch(
    app_config: AppConfig, storage: Storage
) -> None:
    storage.append_audit(event_type="audit.canonical", payload={"value": 1})
    created_at = utc_now()
    branch: dict[str, Any] = {
        "audit_id": "audit_branch_fixture",
        "session_id": None,
        "action_id": None,
        "event_type": "audit.branch",
        "payload": {"value": 2},
        "previous_hash": GENESIS_AUDIT_HASH,
        "created_at": created_at.isoformat(),
    }
    branch["entry_hash"] = audit_entry_hash(
        previous_hash=GENESIS_AUDIT_HASH,
        audit_id=branch["audit_id"],
        event_type=branch["event_type"],
        payload=branch["payload"],
        created_at=created_at,
        session_id=None,
        action_id=None,
    )
    path = app_config.storage.audit_jsonl_path
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(branch, sort_keys=True) + "\n")

    result = storage.verify_audit_chain()

    assert result["valid"] is False
    assert result["reason"] == "branched JSONL audit chain"


def test_concurrent_storage_instances_serialize_db_and_jsonl(
    app_config: AppConfig,
) -> None:
    repositories = [Storage(app_config.storage) for _ in range(6)]
    for repository in repositories:
        repository.initialize()
    barrier = threading.Barrier(len(repositories))

    def append_batch(index: int) -> list[str]:
        barrier.wait(timeout=10)
        return [
            repositories[index].append_audit(
                event_type="audit.concurrent",
                payload={"writer": index, "sequence": sequence},
            )
            for sequence in range(10)
        ]

    with ThreadPoolExecutor(max_workers=len(repositories)) as pool:
        batches = list(pool.map(append_batch, range(len(repositories))))

    audit_ids = [audit_id for batch in batches for audit_id in batch]
    assert len(audit_ids) == len(set(audit_ids)) == 60
    assert repositories[0].verify_audit_chain()["valid"] is True
    assert repositories[0].verify_audit_chain()["entries"] == 60
