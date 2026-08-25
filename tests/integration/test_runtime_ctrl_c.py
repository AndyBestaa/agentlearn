from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import ApprovalDecision
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage
from astercode.tools.process import ProcessTools


@pytest.mark.asyncio
async def test_cancel_during_approved_resume_stops_the_process_tree(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    marker = tmp_path / "child.pid"
    script = tmp_path / "wait.py"
    script.write_text(
        "import os, pathlib, time\n"
        f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    data = app_config.model_dump(mode="python")
    data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(data)
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["run the reviewed long task"],
                "message": "requesting execution",
                "tool_calls": [
                    {
                        "tool": "process.exec",
                        "arguments": {
                            "argv": [sys.executable, str(script)],
                            "cwd": str(tmp_path),
                            "timeout": 120,
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "exercise runtime cancellation",
                    }
                ],
                "outcome": "continue",
            }
        ]
    )
    orchestrator = Orchestrator(
        config,
        provider=provider,
        registry=build_registry(
            config,
            verified_process_sandbox=True,
            verified_process_network_policy=True,
        ),
        storage=storage,
    )
    paused = await orchestrator.run("run until cancelled")
    request = paused["approval_request"]
    decision = ApprovalDecision(
        approval_id=request["approval_id"],
        action_id=request["action_id"],
        action_hash=request["action_hash"],
        nonce=request["nonce"],
        approved=True,
        actor="integration-test",
    )

    resumed = asyncio.create_task(
        orchestrator.resume(paused["session_id"], decision.model_dump(mode="json"))
    )
    try:
        for _ in range(100):
            if marker.exists():
                break
            await asyncio.sleep(0.05)
        assert marker.exists(), "approved process did not start"
        pid = int(marker.read_text(encoding="utf-8"))

        resumed.cancel()
        result = await resumed

        assert result["status"] == "cancelled"
        for _ in range(100):
            if ProcessTools.process_identity(pid) == "missing":
                break
            await asyncio.sleep(0.05)
        assert ProcessTools.process_identity(pid) == "missing"
        assert storage.list_active_processes(paused["session_id"]) == []
    finally:
        if not resumed.done():
            resumed.cancel()
        await orchestrator.close()
