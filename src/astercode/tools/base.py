"""Common tool contracts and output handling.

The model never receives a live Python object.  It only sees validated JSON
descriptions and redacted, bounded tool results produced by this module.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    capability: str
    side_effects: tuple[str, ...] = ()
    risk: str = "P0"
    timeout_seconds: float = 30.0
    max_output: int = 32_000
    idempotent: bool = True
    schema: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "capability": self.capability,
            "side_effects": list(self.side_effects),
            "risk": self.risk,
            "timeout_seconds": self.timeout_seconds,
            "max_output": self.max_output,
            "idempotent": self.idempotent,
            "parameters": dict(self.schema),
        }


@dataclass
class ToolResult:
    call_id: str
    action_id: str
    tool: str
    host: str = "local"
    cwd: str | None = None
    started_at: str = field(default_factory=utc_now)
    ended_at: str | None = None
    status: str = "completed"
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifacts: list[str] = field(default_factory=list)
    truncated: bool = False
    side_effects: list[str] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> "ToolResult":
        self.ended_at = utc_now()
        return self

    def bounded(self, max_output: int, redactor: Callable[[str], str] | None = None) -> "ToolResult":
        redactor = redactor or (lambda value: value)
        for attr in ("stdout", "stderr"):
            value = redactor(getattr(self, attr) or "")
            if len(value) > max_output:
                setattr(self, attr, value[:max_output] + "\n[output truncated]")
                self.truncated = True
            else:
                setattr(self, attr, value)
        if self.error:
            self.error = redactor(self.error)
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "action_id": self.action_id,
            "tool": self.tool,
            "host": self.host,
            "cwd": self.cwd,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": list(self.artifacts),
            "truncated": self.truncated,
            "side_effects": list(self.side_effects),
            "error": self.error,
            "metadata": dict(self.metadata),
        }

    def model_payload(self) -> str:
        """Small stable JSON payload suitable for the next model turn."""
        payload = self.as_dict()
        payload["stdout"] = self.stdout[-8_000:]
        payload["stderr"] = self.stderr[-8_000:]
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def new_action_id(tool: str, arguments: Mapping[str, Any]) -> str:
    canonical = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
    return f"act_{digest}"


def new_call_id() -> str:
    return f"call_{uuid.uuid4().hex}"


def timed_result(tool: str, action_id: str, cwd: str | None = None) -> ToolResult:
    return ToolResult(call_id=new_call_id(), action_id=action_id, tool=tool, cwd=cwd)
