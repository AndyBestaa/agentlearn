"""Small reproducible local performance smoke; no API key or network required."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from astercode.config import AppConfig
from astercode.security import redact_secrets
from astercode.storage import Storage


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1_000, 3)


def main() -> int:
    payload = "x" * 1_048_576 + "\nsk-" + "P" * 24
    started = time.perf_counter()
    redacted = str(redact_secrets(payload))
    redaction_ms = elapsed_ms(started)
    if "[REDACTED]" not in redacted:
        raise RuntimeError("redaction smoke did not redact the synthetic token")

    with tempfile.TemporaryDirectory(prefix="astercode-perf-") as temporary:
        root = Path(temporary)
        config = AppConfig.model_validate(
            {
                "project_root": root,
                "model": {"provider": "fake"},
                "security": {"authorized_roots": [root], "network_mode": "deny_by_default"},
                "storage": {
                    "database_path": root / ".astercode" / "perf.db",
                    "audit_jsonl_path": root / ".astercode" / "audit.jsonl",
                    "artifacts_dir": root / ".astercode" / "artifacts",
                },
            }
        )
        storage = Storage(config.storage)
        started = time.perf_counter()
        storage.initialize()
        migration_ms = elapsed_ms(started)
        session = storage.create_session(str(root), "performance smoke")
        started = time.perf_counter()
        for index in range(100):
            storage.save_event(session["session_id"], "perf.event", {"index": index})
        event_write_ms = elapsed_ms(started)
        audit = storage.verify_audit_chain()

    result = {
        "redact_1_mib_ms": redaction_ms,
        "fresh_schema_migration_ms": migration_ms,
        "write_100_audited_events_ms": event_write_ms,
        "audit_entries": audit["entries"],
        "audit_valid": audit["valid"],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if redaction_ms < 2_000 and event_write_ms < 10_000 and audit["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
