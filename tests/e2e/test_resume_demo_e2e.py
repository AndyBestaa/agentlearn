from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest


def _load_demo() -> Any:
    path = Path(__file__).parents[2] / "scripts" / "resume_demo.py"
    spec = importlib.util.spec_from_file_location("_astercode_resume_demo_e2e", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load resume demo helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


DEMO = _load_demo()


@pytest.mark.asyncio
async def test_resume_demo_fake_backend_is_reproducible_and_credential_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The harness must remain deterministic even if the surrounding developer
    # shell happens to contain live credentials.  Values are never read into
    # provider decisions, tool output, or the evidence artifact.
    markers = ("deepseek-demo-secret-marker", "openai-demo-secret-marker")
    monkeypatch.setenv("DEEPSEEK_API_KEY", markers[0])
    monkeypatch.setenv("OPENAI_API_KEY", markers[1])
    workspace = tmp_path / "resume-project"
    fixture = DEMO.prepare_workspace(Path(__file__).parents[2], workspace)

    evidence = await DEMO.run_demo(fixture, "fake")

    assert evidence["status"] == "completed"
    assert evidence["api_key_used"] is False
    assert evidence["execution_backend"] == "fake"
    assert evidence["execution_simulated"] is True
    assert evidence["baseline"] == {"status": "failed", "exit_code": 1}
    assert evidence["tool_chain"] == [
        "fs.read",
        "fs.read",
        "fs.apply_patch",
        "process.exec",
        "git.diff",
        "git.status",
    ]
    assert evidence["approval"] == {"count": 1, "tool": "process.exec", "risk": "P3"}
    assert evidence["recovery"]["orchestrator_rebuilt"] is True
    assert evidence["recovery"]["persisted_status"] == "waiting_approval"
    assert evidence["recovery"]["checkpoint_phase"] == "POLICY_CHECK"
    assert evidence["audit"]["valid"] is True
    assert (workspace / "calculator.py").read_bytes() == fixture["fixed_source"]
    serialized = Path(evidence["evidence_path"]).read_text(encoding="utf-8")
    parsed = json.loads(serialized)
    assert parsed["execution_simulated"] is True
    assert all(marker not in serialized for marker in markers)
