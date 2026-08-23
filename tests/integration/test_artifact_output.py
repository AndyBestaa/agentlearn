from __future__ import annotations

import sys

import pytest

from astercode.config import AppConfig
from astercode.gateway import LocalToolGateway
from astercode.models import ApprovalDecision, ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities
from astercode.runtime import build_registry
from astercode.storage import Storage
from astercode.tools.base import ToolResult, ToolSpec, new_action_id, timed_result
from astercode.tools.registry import ToolRegistry


class LargeOutputTools:
    specs = (
        ToolSpec(
            "test.large_output",
            "Return deterministic large output.",
            "test.read",
            schema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
    )

    def large_output(self) -> ToolResult:
        result = timed_result("test.large_output", new_action_id("test.large_output", {}))
        result.stdout = "x" * 70_000 + "\nsk-" + "S" * 24
        return result.finish()


@pytest.mark.asyncio
async def test_large_output_is_redacted_and_artifactized(app_config, storage, tmp_path) -> None:
    session_id = "session-large-output"
    storage.create_session(str(tmp_path), "large output", session_id=session_id)
    registry = ToolRegistry()
    registry.register_provider(LargeOutputTools())
    gateway = LocalToolGateway(registry, PolicyEngine(app_config, storage), storage)
    call = ToolCall(tool="test.large_output", arguments={}, cwd=str(tmp_path))
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-large-output",
        goal="capture large output",
        phase="POLICY_CHECK",
    )
    assert (await gateway.authorize(call, context)).outcome == "allow"

    result = await gateway.execute(call, context)

    assert result.status.value == "completed"
    assert result.truncated is True
    assert result.artifacts
    assert result.metadata["artifacts"]["stdout"]["complete"] is True
    assert "sk-" + "S" * 24 not in result.stdout
    artifact_files = list(app_config.storage.artifacts_dir.glob("*.txt"))
    assert len(artifact_files) == 1
    artifact = artifact_files[0].read_text(encoding="utf-8")
    assert len(artifact) > 65_536
    assert "[REDACTED]" in artifact
    assert "sk-" + "S" * 24 not in artifact


@pytest.mark.asyncio
async def test_discarded_process_suffix_produces_explicitly_incomplete_artifact(
    app_config: AppConfig, tmp_path
) -> None:
    retention_limit = 70_000
    sentinel = "SENTINEL_AFTER_DROPPED_PREFIX"
    emitted_bytes = 90_000 + len(sentinel)
    data = app_config.model_dump()
    data["security"]["process"]["allow_unsandboxed_process"] = True
    data["security"]["process"]["max_output_bytes"] = retention_limit
    config = AppConfig.model_validate(data)
    repository = Storage(config.storage)
    repository.initialize()
    session_id = "session-process-incomplete-artifact"
    repository.create_session(str(tmp_path), "process output integrity", session_id=session_id)
    gateway = LocalToolGateway(
        build_registry(
            config,
            verified_process_sandbox=True,
            verified_process_network_policy=True,
        ),
        PolicyEngine(
            config,
            repository,
            RuntimePolicyCapabilities(
                process_sandbox_enforced=True,
                process_network_policy_enforced=True,
            ),
        ),
        repository,
    )
    script = tmp_path / "emit_large_output.py"
    script.write_text(
        "import sys\n"
        f"sys.stdout.write('A' * 90000 + {sentinel!r})\n"
        "sys.stdout.flush()\n",
        encoding="utf-8",
    )
    call = ToolCall(
        tool="process.exec",
        arguments={
            "argv": [sys.executable, str(script)],
            "cwd": str(tmp_path),
            "timeout": 20,
        },
        cwd=str(tmp_path),
    )
    context = GatewayContext(
        session_id=session_id,
        turn_id="turn-process-incomplete-artifact",
        goal="verify bounded process capture integrity",
        phase="POLICY_CHECK",
    )
    pending = await gateway.authorize(call, context)
    assert pending.approval_request is not None
    request = pending.approval_request
    accepted = await gateway.authorize(
        call,
        context,
        ApprovalDecision(
            approval_id=request.approval_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            nonce=request.nonce,
            approved=True,
        ),
    )
    assert accepted.outcome == "allow"

    result = await gateway.execute(call, context)

    assert result.status.value == "completed", result.error
    assert result.truncated is True
    assert sentinel not in result.stdout
    capture = result.metadata["capture"]["stdout"]
    assert capture["observed_bytes"] == emitted_bytes
    assert capture["retained_bytes"] == retention_limit
    assert capture["discarded_bytes"] == emitted_bytes - retention_limit
    assert capture["content_complete"] is False
    artifact_meta = result.metadata["artifacts"]["stdout"]
    assert artifact_meta["complete"] is False
    assert artifact_meta["source_complete"] is False
    assert artifact_meta["disk_complete"] is True
    assert artifact_meta["source_discarded_bytes"] == emitted_bytes - retention_limit
    assert "capture_retention_limit" in artifact_meta["incomplete_reasons"]
    artifact_files = list(config.storage.artifacts_dir.glob("*.txt"))
    assert len(artifact_files) == 1
    artifact = artifact_files[0].read_text(encoding="utf-8")
    assert sentinel not in artifact
    assert artifact.startswith("A" * 1_024)
    assert artifact.endswith(
        "[artifact incomplete: process capture did not retain all output]\n"
    )
