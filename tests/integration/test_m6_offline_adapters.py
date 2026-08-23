from __future__ import annotations

from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.extensions import (
    DeterministicFakeExtensionRunner,
    ExtensionKind,
    ExtensionManifest,
    ExtensionPin,
    ExtensionRegistry,
    ExtensionToolManifest,
    MCPTools,
    PluginTools,
)
from astercode.gateway import LocalToolGateway
from astercode.models import ToolCall
from astercode.orchestrator import GatewayContext
from astercode.policy import PolicyEngine
from astercode.storage import Storage
from astercode.tools.browser import BrowserFixture, FakeBrowserTools
from astercode.tools.registry import ToolRegistry


def _configured(app_config: AppConfig, **security_updates) -> AppConfig:
    payload = app_config.model_dump(mode="python")
    security = dict(payload["security"])
    security.update(security_updates)
    payload["security"] = security
    return AppConfig.model_validate(payload)


def _context() -> GatewayContext:
    return GatewayContext(session_id="session_m6", turn_id="turn_m6", goal="offline M6 test", phase="TOOL_CALL")


@pytest.mark.asyncio
async def test_fake_browser_runs_through_gateway_without_network(
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    config = _configured(
        app_config,
        browser={
            "enabled": True,
            "allowed_domains": ["example.com"],
            "download_dir": tmp_path / "downloads",
        },
    )
    browser = FakeBrowserTools(
        {"https://docs.example.com/": BrowserFixture(body="offline documentation")},
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )
    registry = ToolRegistry()
    registry.register_provider(browser)
    storage.create_session(str(tmp_path), "offline M6 test", session_id="session_m6")
    gateway = LocalToolGateway(registry, PolicyEngine(config, storage), storage)
    call = ToolCall(tool="browser.open", arguments={"url": "https://docs.example.com/"}, cwd=str(tmp_path))

    authorization = await gateway.authorize(call, _context())
    result = await gateway.execute(call, _context())

    assert authorization.outcome == "allow"
    assert result.status.value == "completed"
    assert result.stdout == "offline documentation"
    assert result.as_dict()["side_effects"] == []


def _extension_fixture(kind: ExtensionKind):
    extension_id = f"example.{kind.value}"
    source = f"https://packages.example.com/{extension_id}"
    pin = ExtensionPin(
        extension_id=extension_id,
        source=source,
        version="1.0.0",
        sha256="b" * 64,
        capabilities=frozenset({"workspace.read"}),
    )
    manifest = ExtensionManifest(
        extension_id=extension_id,
        kind=kind,
        source=source,
        version="1.0.0",
        sha256="b" * 64,
        capabilities=frozenset({"workspace.read"}),
        tools=(
            ExtensionToolManifest(
                name="files.read",
                capability="workspace.read",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
                declared_read_only=True,
            ),
        ),
    )
    return pin, manifest


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [ExtensionKind.MCP, ExtensionKind.PLUGIN])
async def test_fake_mcp_and_plugin_run_through_policy_gateway(
    kind: ExtensionKind,
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    pin, manifest = _extension_fixture(kind)
    extension_settings = {
        "mcp_enabled": kind is ExtensionKind.MCP,
        "plugins_enabled": kind is ExtensionKind.PLUGIN,
        "mcp_pins": [pin.model_dump(mode="python")] if kind is ExtensionKind.MCP else [],
        "plugin_pins": [pin.model_dump(mode="python")] if kind is ExtensionKind.PLUGIN else [],
    }
    config = _configured(app_config, extensions=extension_settings)
    runner = DeterministicFakeExtensionRunner(
        {(manifest.extension_id, "files.read"): {"stdout": f"offline {kind.value} result"}}
    )
    extension_registry = ExtensionRegistry(
        kind,
        [pin],
        authorized_roots=[tmp_path],
        runner=runner,
        enabled=True,
    )
    extension_registry.register(manifest)
    provider = MCPTools(extension_registry) if kind is ExtensionKind.MCP else PluginTools(extension_registry)
    tools = ToolRegistry()
    tools.register_provider(provider)
    storage.create_session(str(tmp_path), "offline M6 test", session_id="session_m6")
    gateway = LocalToolGateway(tools, PolicyEngine(config, storage), storage)
    source = tmp_path / "source.txt"
    source.write_text("fixture", encoding="utf-8")
    call = ToolCall(
        tool=f"{kind.value}.invoke",
        arguments={
            "extension_id": manifest.extension_id,
            "tool": "files.read",
            "arguments": {"path": str(source)},
        },
        cwd=str(tmp_path),
    )

    authorization = await gateway.authorize(call, _context())
    result = await gateway.execute(call, _context())

    assert authorization.outcome == "allow"
    assert result.status.value == "completed"
    assert result.stdout == f"offline {kind.value} result"
    assert runner.calls[0]["network_used"] is False


@pytest.mark.asyncio
async def test_browser_submit_is_p3_and_pauses_before_fake_side_effect(
    app_config: AppConfig,
    storage: Storage,
    tmp_path: Path,
) -> None:
    config = _configured(
        app_config,
        browser={
            "enabled": True,
            "allowed_domains": ["example.com"],
            "download_dir": tmp_path / "downloads",
        },
    )
    browser = FakeBrowserTools(
        {"https://example.com/": BrowserFixture(body="form")},
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )
    assert browser.open("https://example.com/").status == "completed"
    registry = ToolRegistry()
    registry.register_provider(browser)
    storage.create_session(str(tmp_path), "offline M6 test", session_id="session_m6")
    gateway = LocalToolGateway(registry, PolicyEngine(config, storage), storage)
    call = ToolCall(
        tool="browser.submit",
        arguments={"selector": "#send", "fields": {"message": "hello"}},
        cwd=str(tmp_path),
    )

    authorization = await gateway.authorize(call, _context())

    assert authorization.outcome == "require_approval"
    assert authorization.risk.value == "P3"
    assert browser.submissions == []
