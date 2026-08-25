"""Executable v0.1 acceptance scenarios.

The detailed contract lives in ``docs/v0.1-acceptance-matrix.md``.  These
tests deliberately use the deterministic resume fixture so that a passing
result means the host runtime produced the evidence, not that a model claimed
success.  The Docker case is allowed to skip when the local engine/image is
not available; a skip is an explicit live-evidence gap, never a fake pass.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry


def _load_resume_demo() -> Any:
    path = Path(__file__).parents[2] / "scripts" / "resume_demo.py"
    spec = importlib.util.spec_from_file_location("_astercode_v01_resume_demo", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load resume demo helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


DEMO = _load_resume_demo()


@pytest.mark.asyncio
async def test_v01_read_only_analysis_never_requests_side_effect(
    app_config, storage, tmp_path: Path
) -> None:
    """AC-01: a repository question stays inside the P0 read-only boundary."""

    readme = tmp_path / "README.md"
    original = "# fixture\n\nread-only acceptance\n"
    readme.write_text(original, encoding="utf-8")
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect README.md"],
                "message": "I inspected the requested file.",
                "tool_calls": [
                    {
                        "tool": "fs.read",
                        "arguments": {
                            "path": "README.md",
                            "start_line": 1,
                            "end_line": None,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "answer the read-only repository question",
                    }
                ],
                "outcome": "completed",
            }
        ]
    )
    orchestrator = Orchestrator(
        app_config,
        provider=provider,
        registry=build_registry(app_config),
        storage=storage,
    )
    try:
        result = await orchestrator.run("Read README.md and summarize it; do not modify files")
    finally:
        await orchestrator.close()

    assert result["status"] == "completed"
    assert result["approval_request"] is None
    assert [item["tool"] for item in result["tool_results"]] == ["fs.read"]
    assert result["tool_results"][0]["status"] == "completed"
    assert "read-only acceptance" in result["tool_results"][0]["stdout"]
    assert readme.read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_v01_fake_workflow_covers_failure_fix_approval_resume_and_evidence(
    tmp_path: Path,
) -> None:
    """AC-03/04/05/10: run the complete offline acceptance path.

    The fixture starts with a real failing regression.  The deterministic
    provider then reads, patches, requests an exact process approval, resumes
    in a rebuilt runtime, runs the test, captures the diff/status, and verifies
    the audit chain.
    """

    fixture = DEMO.prepare_workspace(
        Path(__file__).parents[2], tmp_path / "v01-fake-workspace"
    )
    evidence = await DEMO.run_demo(fixture, "fake")

    assert evidence["status"] == "completed"
    assert evidence["provider"] == "deterministic-fake"
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
    assert evidence["approval"] == {
        "count": 1,
        "tool": "process.exec",
        "risk": "P3",
    }
    assert evidence["recovery"]["orchestrator_rebuilt"] is True
    assert evidence["recovery"]["persisted_status"] == "waiting_approval"
    assert evidence["recovery"]["checkpoint_phase"] == "POLICY_CHECK"
    assert evidence["validation"]["status"] == "completed"
    assert evidence["validation"]["exit_code"] == 0
    assert evidence["validation"]["sandbox"]["execution_simulated"] is True
    assert "return left - right" in evidence["git_diff"]
    assert "return left + right" in evidence["git_diff"]
    assert "calculator.py" in evidence["git_status"]
    assert "test_calculator.py" not in evidence["git_status"]
    assert evidence["audit"]["valid"] is True


@pytest.mark.asyncio
async def test_v01_docker_workflow_when_attested(tmp_path: Path) -> None:
    """AC-09: exercise the same acceptance path in the real Docker backend.

    Docker is an environment-dependent evidence source.  Do not turn an
    unavailable engine/image into a passing fake result; report an explicit
    skip so CI and release notes can distinguish it from a verified sandbox.
    """

    fixture = DEMO.prepare_workspace(
        Path(__file__).parents[2], tmp_path / "v01-docker-workspace"
    )
    try:
        evidence = await DEMO.run_demo(fixture, "docker")
    except DEMO.DemoFailure as exc:
        message = str(exc)
        unavailable_markers = (
            "Docker sandbox is unavailable",
            "attested Docker sandbox is unavailable",
        )
        if any(marker in message for marker in unavailable_markers):
            pytest.skip(message)
        raise

    assert evidence["status"] == "completed"
    assert evidence["execution_backend"] == "docker"
    assert evidence["execution_simulated"] is False
    assert evidence["validation"]["status"] == "completed"
    sandbox = evidence["validation"]["sandbox"]
    assert sandbox["filesystem_sandbox"] is True
    assert sandbox["network_sandbox"] is True
    assert sandbox["host_workspace_read_only"] is True
    assert sandbox["ephemeral_workspace_writable"] is True
    assert sandbox["process_tree_containment"] == "docker_linux_container"
    assert str(sandbox["container_image_id"]).startswith("sha256:")
    assert sandbox["network_mode"] == "none"
    assert evidence["audit"]["valid"] is True
