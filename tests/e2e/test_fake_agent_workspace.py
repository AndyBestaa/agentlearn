from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import ApprovalDecision
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage


def _git(git: str, cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [git, "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.asyncio
async def test_fake_agent_reads_edits_and_reports_git_diff(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable is unavailable")
    source = tmp_path / "calculator.py"
    source.write_text("def add(left, right):\n    return left - right\n", encoding="utf-8")
    (tmp_path / "test_calculator.py").write_text(
        "from calculator import add\n\nassert add(2, 3) == 5\nprint('calculator test passed')\n",
        encoding="utf-8",
    )
    _git(git, tmp_path, "init")
    _git(git, tmp_path, "config", "user.email", "tests@example.invalid")
    _git(git, tmp_path, "config", "user.name", "AsterCode Tests")
    _git(git, tmp_path, "add", "calculator.py", "test_calculator.py")
    _git(git, tmp_path, "commit", "-m", "fixture baseline")

    patch = """*** Begin Patch
*** Update File: calculator.py
-    return left - right
+    return left + right
*** End Patch"""
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["inspect", "fix", "run tests", "review diff"],
                "message": "Inspecting the implementation.",
                "tool_calls": [
                    {
                        "tool": "fs.read",
                        "arguments": {
                            "path": "calculator.py",
                            "start_line": 1,
                            "end_line": None,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "inspect the bug",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["fix", "run tests", "review diff"],
                "message": "Applying the minimal correction.",
                "tool_calls": [
                    {
                        "tool": "fs.apply_patch",
                        "arguments": {"patch": patch},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "correct the arithmetic operation",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["run tests", "review diff"],
                "message": "Running the focused offline test.",
                "tool_calls": [
                    {
                        "tool": "process.exec",
                        "arguments": {
                            "argv": [sys.executable, "test_calculator.py"],
                            "cwd": str(tmp_path),
                            "timeout": 30,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "run the local regression test without network",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": ["review diff"],
                "message": "Reviewing the exact workspace diff.",
                "tool_calls": [
                    {
                        "tool": "git.diff",
                        "arguments": {"cwd": str(tmp_path), "cached": False},
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "verify the minimal diff",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "The correction and diff verification are complete.",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    config_data = app_config.model_dump()
    config_data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(config_data)
    orchestrator = Orchestrator(
        config,
        provider=provider,
        registry=build_registry(
            config,
            verified_process_sandbox=True,
            verified_process_network_policy=True,
        ),
        storage=storage,
        auto_approve=True,
    )

    paused = await orchestrator.run("Fix add(), run its test, and show the resulting diff")
    assert paused["status"] == "waiting_approval"
    request = paused["approval_request"]
    result = await orchestrator.resume(
        paused["session_id"],
        ApprovalDecision(
            approval_id=request["approval_id"],
            action_id=request["action_id"],
            action_hash=request["action_hash"],
            nonce=request["nonce"],
            approved=True,
            actor="e2e-test",
        ).model_dump(mode="json"),
    )

    assert result["status"] == "completed"
    assert source.read_text(encoding="utf-8").endswith("return left + right\n")
    assert [item["tool"] for item in result["tool_results"]] == [
        "fs.read",
        "fs.apply_patch",
        "process.exec",
        "git.diff",
    ]
    assert "calculator test passed" in result["tool_results"][2]["stdout"]
    assert "return left + right" in result["tool_results"][-1]["stdout"]
    assert all(item["verified"] for item in result["test_status"])
    await orchestrator.close()
