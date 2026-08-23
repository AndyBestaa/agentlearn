from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from astercode.config import AppConfig
from astercode.storage import Storage


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    """Return a fully local configuration whose state never leaves tmp_path."""

    return AppConfig.model_validate(
        {
            "project_root": tmp_path,
            "model": {"provider": "fake", "model_id": None},
            "security": {
                "authorized_roots": [tmp_path],
                "authorized_ssh_hosts": [],
                "network_mode": "deny_by_default",
                "process": {
                    "sandbox_backend": "none",
                    "allow_unsandboxed_process": False,
                },
            },
            "storage": {
                "database_path": tmp_path / ".astercode" / "test.db",
                "audit_jsonl_path": tmp_path / ".astercode" / "audit.jsonl",
                "artifacts_dir": tmp_path / ".astercode" / "artifacts",
            },
        }
    )


@pytest.fixture
def storage(app_config: AppConfig) -> Storage:
    repository = Storage(app_config.storage)
    repository.initialize()
    return repository


@pytest.fixture
def replay_script() -> list[dict[str, Any]]:
    path = Path(__file__).parent / "fixtures" / "read_then_complete.json"
    return json.loads(path.read_text(encoding="utf-8"))
