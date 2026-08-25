from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest


def _load_demo() -> Any:
    path = Path(__file__).parents[2] / "scripts" / "resume_demo.py"
    spec = importlib.util.spec_from_file_location("_astercode_resume_demo_unit", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load resume demo helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


DEMO = _load_demo()


def test_prepare_workspace_creates_clean_intentional_bug_baseline(tmp_path: Path) -> None:
    repository_root = Path(__file__).parents[2]
    workspace = tmp_path / "resume-project"

    fixture = DEMO.prepare_workspace(repository_root, workspace)

    assert fixture["workspace"] == workspace.resolve()
    assert b"return left - right" in fixture["buggy_source"]
    assert b"return left + right" in fixture["fixed_source"]
    assert fixture["buggy_source"] != fixture["fixed_source"]
    status = DEMO._run_git(fixture["git"], workspace, "status", "--short")
    assert status.stdout == ""


def test_prepare_workspace_never_overwrites_an_existing_path(tmp_path: Path) -> None:
    existing = tmp_path / "already-here"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("user data", encoding="utf-8")

    with pytest.raises(DEMO.DemoFailure, match="refusing to overwrite"):
        DEMO.prepare_workspace(Path(__file__).parents[2], existing)

    assert marker.read_text(encoding="utf-8") == "user data"


def test_prepare_workspace_ignores_python_cache_in_the_template(tmp_path: Path) -> None:
    repository_root = Path(__file__).parents[2]
    cache = repository_root / "examples" / "resume_demo" / "__pycache__"
    cache.mkdir(exist_ok=True)
    marker = cache / "runtime-only.pyc"
    marker.write_bytes(b"not part of the fixture")
    try:
        fixture = DEMO.prepare_workspace(repository_root, tmp_path / "fixture")
    finally:
        marker.unlink(missing_ok=True)

    assert not (fixture["workspace"] / "__pycache__").exists()


def test_exact_demo_approval_rejects_a_widened_command(tmp_path: Path) -> None:
    request = {
        "approval_request": {
            "tool": "process.exec",
            "risk": "P3",
            "host": "local",
            "approval_id": "approval_test",
            "action_id": "action_test",
            "action_hash": "a" * 64,
            "nonce": "nonce-for-resume-demo",
            "normalized_action": {
                "arguments": {
                    "argv": ["python", "different.py"],
                    "cwd": str(tmp_path),
                }
            },
        }
    }

    with pytest.raises(DEMO.DemoFailure, match="unexpected or widened"):
        DEMO._exact_process_approval(request, tmp_path.resolve())


def test_fake_executor_discloses_simulation_and_checks_exact_fixture(tmp_path: Path) -> None:
    repository_root = Path(__file__).parents[2]
    fixture = DEMO.prepare_workspace(repository_root, tmp_path / "fixture")
    executor = DEMO.FixtureFakeProcessTools(
        fixture["workspace"],
        buggy_source=fixture["buggy_source"],
        fixed_source=fixture["fixed_source"],
        test_source=fixture["test_source"],
    )

    failed = executor.exec(
        list(DEMO.TEST_ARGV),
        str(fixture["workspace"]),
        allow_unsandboxed=True,
    )
    assert failed.status == "failed"
    assert failed.metadata["execution_simulated"] is True
    assert failed.metadata["filesystem_sandbox"] is False

    (fixture["workspace"] / "calculator.py").write_bytes(fixture["fixed_source"])
    completed = executor.exec(
        list(DEMO.TEST_ARGV),
        str(fixture["workspace"]),
        allow_unsandboxed=True,
    )
    assert completed.status == "completed"
    assert completed.stdout == DEMO.EXPECTED_TEST_STDOUT
