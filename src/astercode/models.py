"""Shared, serialisable contracts used by the AsterCode runtime."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return an aware UTC timestamp suitable for persisted records."""

    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Create a locally unique, log-friendly identifier."""

    return f"{prefix}_{uuid4().hex}"


class StrictModel(BaseModel):
    """Base model that rejects silently ignored, security-relevant fields."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )


class RiskLevel(str, Enum):
    """Runtime-enforced risk tiers, ordered from read-only to high risk."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        return int(self.value[1])

    def at_least(self, other: RiskLevel) -> bool:
        return self.rank >= other.rank


class SessionStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ToolStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class ToolError(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=8_192)
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ArtifactRef(StrictModel):
    artifact_id: str = Field(default_factory=lambda: new_id("artifact"))
    path: str
    media_type: str = "application/octet-stream"
    size: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


class ToolSpec(StrictModel):
    """Static declaration used by the registry and as policy input.

    ``risk`` is only the declared minimum.  The policy engine reclassifies the
    concrete arguments and may raise the effective tier.
    """

    name: str
    capability: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1_024)
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
    )
    side_effects: list[str] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.P0
    timeout: float = Field(default=30.0, gt=0, le=86_400)
    max_output: int = Field(default=65_536, ge=1, le=1_073_741_824)
    idempotent: bool = False
    requires_network: bool = False
    supports_dry_run: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _TOOL_NAME.fullmatch(value):
            raise ValueError("tool name must use a lowercase namespace.action form")
        return value


class ToolCall(StrictModel):
    call_id: str = Field(default_factory=lambda: new_id("call"))
    action_id: str = Field(default_factory=lambda: new_id("action"))
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    host: str = "local"
    cwd: str | None = None
    idempotency_key: str | None = None
    requested_at: datetime = Field(default_factory=utc_now)

    @field_validator("tool")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        if not _TOOL_NAME.fullmatch(value):
            raise ValueError("tool name must use a lowercase namespace.action form")
        return value


class ToolResult(StrictModel):
    """Uniform result envelope for all local and future remote executors."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    call_id: str
    action_id: str
    tool: str
    host: str = "local"
    cwd: str | None = None
    started_at: datetime
    ended_at: datetime
    status: ToolStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifacts: list[ArtifactRef | str] = Field(default_factory=list)
    truncated: bool = False
    side_effects: list[str] = Field(default_factory=list)
    error: ToolError | str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_timing_and_status(self) -> ToolResult:
        if self.ended_at < self.started_at:
            raise ValueError("ended_at cannot precede started_at")
        if self.status is ToolStatus.COMPLETED and self.error is not None:
            raise ValueError("a completed result cannot contain an error")
        return self

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any] | None = None,
        /,
        **values: Any,
    ) -> ToolResult:
        """Validate a mapping returned by an executor.

        Keyword values intentionally override mapping values so a gateway can
        bind authoritative IDs, host and cwd rather than trusting a plugin.
        """

        data = dict(payload or {})
        data.update(values)
        return cls.model_validate(data)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible envelope, including explicit nulls."""

        return self.model_dump(mode="json")

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.ended_at - self.started_at).total_seconds() * 1_000))


class ApprovalRequest(StrictModel):
    """Persistable request bound to one exact, normalised action."""

    approval_id: str = Field(default_factory=lambda: new_id("approval"))
    action_id: str
    tool: str
    risk: RiskLevel
    purpose: str = Field(min_length=1, max_length=4_096)
    normalized_action: dict[str, Any]
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=256)
    host: str = "local"
    port: int | None = Field(default=None, ge=1, le=65_535)
    user: str | None = None
    host_fingerprint: str | None = None
    cwd: str | None = None
    real_paths: list[str] = Field(default_factory=list)
    diff_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    network_destination: str | None = None
    side_effects: list[str] = Field(default_factory=list)
    validation: str | None = None
    backup: str | None = None
    rollback: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING

    @model_validator(mode="after")
    def validate_expiry(self) -> ApprovalRequest:
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiry must be later than creation time")
        return self


class ApprovalDecision(StrictModel):
    approval_id: str
    action_id: str
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=256)
    approved: bool
    scope: Literal["once", "session"] = "once"
    reason: str | None = Field(default=None, max_length=4_096)
    actor: str = Field(default="authenticated_user", min_length=1, max_length=256)
    decided_at: datetime = Field(default_factory=utc_now)


class SessionRecord(StrictModel):
    session_id: str = Field(default_factory=lambda: new_id("session"))
    workspace: str
    goal: str
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("workspace")
    @classmethod
    def normalize_workspace_text(cls, value: str) -> str:
        return str(Path(value))


class CheckpointRecord(StrictModel):
    checkpoint_id: str = Field(default_factory=lambda: new_id("checkpoint"))
    session_id: str
    turn_id: str | None = None
    phase: str
    state: dict[str, Any]
    action_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "ArtifactRef",
    "CheckpointRecord",
    "RiskLevel",
    "SessionRecord",
    "SessionStatus",
    "StrictModel",
    "ToolCall",
    "ToolError",
    "ToolResult",
    "ToolSpec",
    "ToolStatus",
    "new_id",
    "utc_now",
]
