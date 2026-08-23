from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from astercode.models import (
    RiskLevel,
    ToolCall,
    ToolError,
    ToolResult,
    ToolSpec,
    ToolStatus,
    utc_now,
)


def test_strict_models_reject_unknown_security_relevant_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ToolCall.model_validate(
            {
                "tool": "fs.read",
                "arguments": {},
                "unreviewed_override": True,
            }
        )


@pytest.mark.parametrize("name", ["read", "FS.read", "fs.Read", "fs-read.file"])
def test_tool_names_require_a_lowercase_namespace(name: str) -> None:
    with pytest.raises(ValidationError):
        ToolSpec(name=name, capability="filesystem.read")


def test_tool_spec_schema_and_risk_are_json_serialisable() -> None:
    spec = ToolSpec(
        name="fs.read",
        capability="filesystem.read",
        risk=RiskLevel.P0,
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )

    payload = spec.model_dump(mode="json")
    assert payload["risk"] == "P0"
    assert payload["input_schema"]["additionalProperties"] is False
    assert ToolSpec.model_json_schema()["additionalProperties"] is False


def test_uniform_tool_result_keeps_stdout_and_stderr_separate() -> None:
    started = utc_now()
    result = ToolResult(
        call_id="call_1",
        action_id="action_1",
        tool="process.exec",
        started_at=started,
        ended_at=started + timedelta(milliseconds=5),
        status=ToolStatus.FAILED,
        exit_code=7,
        stdout="ordinary output",
        stderr="diagnostic output",
        error=ToolError(code="nonzero_exit", message="command failed"),
    )

    payload = result.as_dict()
    assert payload["stdout"] == "ordinary output"
    assert payload["stderr"] == "diagnostic output"
    assert payload["status"] == "failed"
    assert result.duration_ms == 5


def test_completed_tool_result_cannot_carry_an_error() -> None:
    now = utc_now()
    with pytest.raises(ValidationError, match="completed result"):
        ToolResult(
            call_id="call_1",
            action_id="action_1",
            tool="fs.read",
            started_at=now,
            ended_at=now,
            status=ToolStatus.COMPLETED,
            error="not actually complete",
        )


def test_tool_result_rejects_backwards_timestamps() -> None:
    ended = utc_now()
    with pytest.raises(ValidationError, match="cannot precede"):
        ToolResult(
            call_id="call_1",
            action_id="action_1",
            tool="fs.read",
            started_at=ended + timedelta(seconds=1),
            ended_at=ended,
            status=ToolStatus.FAILED,
        )
