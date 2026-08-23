from __future__ import annotations

import pytest

from astercode.gateway import LocalToolGateway
from astercode.models import ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine
from astercode.runtime import build_registry


@pytest.mark.asyncio
async def test_kill_switch_blocks_new_tool_calls(app_config, storage) -> None:
    gateway = LocalToolGateway(build_registry(app_config), PolicyEngine(app_config, storage), storage)
    storage.set_kill_switch("security test")
    call = ToolCall(tool="fs.list", arguments={"path": ".", "recursive": False}, cwd=str(app_config.project_root))
    result = await gateway.authorize(call, GatewayContext(session_id="s", turn_id="t", goal="inspect", phase="POLICY_CHECK"))
    assert result.outcome == "deny"
    assert "kill switch" in result.reason
