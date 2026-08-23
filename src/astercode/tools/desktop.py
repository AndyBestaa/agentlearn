"""Fail-closed native desktop facade.

Native GUI control is not part of the M6 live surface.  Merely setting a
configuration boolean cannot prove window isolation, screenshot redaction or
an independent emergency stop, so the adapter always refuses live actions.
"""

from __future__ import annotations

from typing import Any, Mapping

from .base import ToolResult, ToolSpec, new_action_id, timed_result


class NativeDesktopTools:
    specs = (
        ToolSpec(
            "desktop.screenshot",
            "Capture an allowlisted application region.",
            "desktop.native.unverified",
            ("screen_capture",),
            "P3",
            schema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        ToolSpec(
            "desktop.click",
            "Click an allowlisted application region.",
            "desktop.native.unverified",
            ("native_input",),
            "P3",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}},
                "required": ["x", "y"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "desktop.type_text",
            "Type text into an allowlisted application window.",
            "desktop.native.unverified",
            ("native_input", "external_submit_possible"),
            "P3",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(self, *, enabled: bool = False) -> None:
        self.enabled = enabled

    def _blocked(self, tool: str, arguments: Mapping[str, Any]) -> ToolResult:
        result = timed_result(tool, new_action_id(tool, arguments))
        result.status = "failed"
        result.error = (
            "native desktop GUI is disabled"
            if not self.enabled
            else "LIVE NATIVE GUI NOT VERIFIED: application/window/region isolation and kill switch are unavailable"
        )
        result.metadata.update({"blocked": True, "live_integration_verified": False})
        return result.finish()

    def screenshot(self) -> ToolResult:
        return self._blocked("desktop.screenshot", {})

    def click(self, x: int, y: int) -> ToolResult:
        return self._blocked("desktop.click", {"x": x, "y": y})

    def type_text(self, text: str) -> ToolResult:
        return self._blocked("desktop.type_text", {"text": text})


__all__ = ["NativeDesktopTools"]
