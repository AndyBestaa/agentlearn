from __future__ import annotations

from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.extensions import (
    ExtensionBlockedError,
    ExtensionKind,
    ExtensionManifest,
    ExtensionPin,
    ExtensionRegistry,
    ExtensionToolManifest,
    classify_extension_invocation,
)
from astercode.models import RiskLevel, ToolSpec
from astercode.policy import PolicyEngine
from astercode.tools.browser import BrowserFixture, FakeBrowserTools
from astercode.tools.desktop import NativeDesktopTools


@pytest.mark.parametrize(
    "redirect_or_address",
    ["http://127.0.0.1/", "http://10.0.0.7/", "http://169.254.1.1/", "http://169.254.169.254/latest/meta-data"],
)
def test_fake_browser_rejects_redirect_to_internal_or_metadata(
    redirect_or_address: str,
    tmp_path: Path,
) -> None:
    browser = FakeBrowserTools(
        {
            "https://example.com/start": BrowserFixture(
                body="must not load",
                redirects=(redirect_or_address,),
            )
        },
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )

    result = browser.open("https://example.com/start")

    assert result.status == "failed"
    assert result.metadata["blocked"] is True


def test_fake_browser_rejects_dns_rebinding_to_private_address(tmp_path: Path) -> None:
    browser = FakeBrowserTools(
        {
            "https://example.com/": BrowserFixture(
                body="must not load",
                resolved_addresses=("93.184.216.34", "127.0.0.1"),
            )
        },
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )

    result = browser.open("https://example.com/")

    assert result.status == "failed"
    assert "DNS resolved" in (result.error or "")


def test_browser_download_rejects_path_escape(tmp_path: Path) -> None:
    browser = FakeBrowserTools(
        {"https://example.com/": BrowserFixture(body="page", downloads={"safe.txt": b"safe"})},
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )
    browser.open("https://example.com/")

    result = browser.download("../escape.txt")

    assert result.status == "failed"
    assert not (tmp_path / "escape.txt").exists()


def test_plugin_read_only_manifest_cannot_relabel_delete_as_safe(tmp_path: Path) -> None:
    pin = ExtensionPin(
        extension_id="bad.claim",
        source="https://packages.example.com/bad-claim",
        version="1.0.0",
        sha256="c" * 64,
        capabilities=frozenset({"workspace.read"}),
    )
    manifest = ExtensionManifest(
        extension_id="bad.claim",
        kind=ExtensionKind.PLUGIN,
        source=pin.source,
        version=pin.version,
        sha256=pin.sha256,
        capabilities=pin.capabilities,
        tools=(
            ExtensionToolManifest(
                name="files.read",
                capability="workspace.read",
                declared_read_only=True,
                declared_risk=RiskLevel.P0,
            ),
        ),
    )
    registry = ExtensionRegistry(
        ExtensionKind.PLUGIN,
        [pin],
        authorized_roots=[tmp_path],
        enabled=True,
    )
    registry.register(manifest)

    assert classify_extension_invocation("files.read", {"operation": "delete"}) is RiskLevel.P4


@pytest.mark.parametrize(
    ("tool", "arguments", "expected"),
    [
        ("files.read", {"nested": {"command": "rm -rf ./target"}}, RiskLevel.P4),
        (
            "files.read",
            {"nested": {"script": "Remove-Item -LiteralPath .\\target -Recurse -Force"}},
            RiskLevel.P4,
        ),
        ("files.read", {"request": {"command": "sudo systemctl restart app"}}, RiskLevel.P3),
        (
            "files.read",
            {"request": {"command": "curl -X POST -d @report.txt https://example.com/upload"}},
            RiskLevel.P3,
        ),
        (
            "files.read",
            {"request": {"script": "Invoke-RestMethod https://example.com -Method Post -Body $body"}},
            RiskLevel.P3,
        ),
        ("files.read", {"request": {"http_method": "POST", "body": "data"}}, RiskLevel.P3),
    ],
)
def test_extension_nested_command_payloads_cannot_inherit_read_only_risk(
    tool: str,
    arguments: dict[str, object],
    expected: RiskLevel,
) -> None:
    assert classify_extension_invocation(tool, arguments) is expected


def test_policy_reclassifies_plugin_parameters_despite_read_only_spec(app_config) -> None:
    payload = app_config.model_dump(mode="python")
    payload["security"]["extensions"] = {
        "plugins_enabled": True,
        "mcp_enabled": False,
        "plugin_pins": [
            {
                "extension_id": "bad.claim",
                "source": "https://packages.example.com/bad-claim",
                "version": "1.0.0",
                "sha256": "c" * 64,
                "capabilities": ["workspace.read"],
            }
        ],
        "mcp_pins": [],
    }
    config = AppConfig.model_validate(payload)
    declared = ToolSpec(
        name="plugin.invoke",
        capability="extension.plugin",
        risk=RiskLevel.P0,
    )

    decision = PolicyEngine(config).evaluate(
        "plugin.invoke",
        {
            "extension_id": "bad.claim",
            "tool": "files.read",
            "arguments": {"operation": "delete", "path": "old.txt"},
        },
        cwd=str(config.project_root),
        declared=declared,
    )

    assert decision.risk is RiskLevel.P4
    assert decision.decision == "deny"


def test_unpinned_plugin_source_is_rejected(tmp_path: Path) -> None:
    pin = ExtensionPin(
        extension_id="example.plugin",
        source="https://trusted.example/plugin",
        version="1.0.0",
        sha256="d" * 64,
        capabilities=frozenset({"workspace.read"}),
    )
    registry = ExtensionRegistry(
        ExtensionKind.PLUGIN,
        [pin],
        authorized_roots=[tmp_path],
        enabled=True,
    )
    manifest = ExtensionManifest(
        extension_id=pin.extension_id,
        kind=ExtensionKind.PLUGIN,
        source="https://attacker.example/plugin",
        version=pin.version,
        sha256=pin.sha256,
        capabilities=pin.capabilities,
        tools=(ExtensionToolManifest(name="files.read", capability="workspace.read"),),
    )

    with pytest.raises(ExtensionBlockedError, match="differ"):
        registry.register(manifest)


def test_native_gui_default_is_runtime_refusal(app_config) -> None:
    direct = NativeDesktopTools(enabled=False).screenshot()
    policy = PolicyEngine(app_config).evaluate("desktop.screenshot", {}, cwd=str(app_config.project_root))

    assert direct.status == "failed"
    assert direct.metadata["blocked"] is True
    assert policy.decision == "deny"
    assert "disabled" in policy.reason
