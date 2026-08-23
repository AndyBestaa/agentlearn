from __future__ import annotations

from pathlib import Path

import pytest

from astercode.provider import DeterministicFakeProvider, ProviderDecision, ProviderResponse, ToolProposal
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage


@pytest.mark.asyncio
async def test_approval_resume_survives_new_runtime_instance(app_config, storage, tmp_path: Path) -> None:
    target = tmp_path / "resume.txt"
    target.write_text("old\n", encoding="utf-8")
    response = ProviderResponse(
        decision=ProviderDecision(
            plan=["edit"],
            message="edit",
            outcome="continue",
            tool_calls=[
                ToolProposal(
                    tool="fs.apply_patch",
                    arguments={"patch": "*** Begin Patch\n*** Update File: resume.txt\n-old\n+new\n*** End Patch"},
                    host="local",
                    cwd=str(tmp_path),
                    purpose="test persisted approval",
                )
            ],
        )
    )
    first = Orchestrator(app_config, provider=DeterministicFakeProvider([response]), registry=build_registry(app_config), storage=storage)
    paused = await first.run("edit")
    request = paused["approval_request"]
    session_id = paused["session_id"]
    await first.close()

    decision = {key: request[key] for key in ("approval_id", "action_id", "action_hash", "nonce")}
    decision["approved"] = True
    second = Orchestrator(app_config, provider=DeterministicFakeProvider(), registry=build_registry(app_config), storage=Storage(app_config.storage))
    try:
        resumed = await second.resume(session_id, decision)
    finally:
        await second.close()
    assert resumed["status"] == "completed"
    assert target.read_text(encoding="utf-8") == "new\n"
