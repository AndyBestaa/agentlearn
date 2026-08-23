from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from astercode.config import AppConfig
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities
from astercode.runtime import build_registry
from astercode.tools.browser import BrowserTools, BrowserURLPolicy
from astercode.tools.playwright_browser import BrowserPage, PlaywrightEdgeBackend


class StubBackend:
    profile_isolated = True
    uses_user_profile = False
    profile_kind = "test_non_persistent_context"

    def __init__(self) -> None:
        self.open_calls = 0
        self.closed = False

    async def open(self, url: str, policy: BrowserURLPolicy) -> BrowserPage:
        self.open_calls += 1
        checked = policy.validate(url)
        return BrowserPage(checked.url, "safe page", "Safe", 200, 0)

    async def snapshot(self) -> BrowserPage:
        return BrowserPage("https://example.com/", "safe page", "Safe", None, 0)

    async def close(self) -> None:
        self.closed = True


class StubRequest:
    def __init__(self, url: str, redirected_from: StubRequest | None = None) -> None:
        self.url = url
        self.redirected_from = redirected_from


class StubRoute:
    def __init__(self, request: StubRequest) -> None:
        self.request = request
        self.aborted: str | None = None
        self.continued = False

    async def abort(self, reason: str) -> None:
        self.aborted = reason

    async def continue_(self) -> None:
        self.continued = True


@pytest.mark.asyncio
async def test_live_facade_requires_independent_egress_attestation() -> None:
    backend = StubBackend()
    browser = BrowserTools(
        enabled=True,
        allowlist=["example.com"],
        backend=backend,
        network_egress_enforced=False,
    )

    result = await browser.open("https://example.com/")

    assert result.status == "failed"
    assert "egress isolation is not attested" in (result.error or "")
    assert backend.open_calls == 0


@pytest.mark.asyncio
async def test_live_facade_uses_only_attested_isolated_backend() -> None:
    backend = StubBackend()
    browser = BrowserTools(
        enabled=True,
        allowlist=["example.com"],
        backend=backend,
        network_egress_enforced=True,
    )

    opened = await browser.open("https://example.com/")
    snapshot = await browser.snapshot()
    await browser.stop_all()

    assert opened.status == "completed"
    assert opened.stdout == "safe page"
    assert opened.metadata["uses_user_profile"] is False
    assert opened.metadata["network_egress_enforced"] is True
    assert snapshot.status == "completed"
    assert backend.closed is True


@pytest.mark.asyncio
async def test_route_guard_rejects_private_dns_and_redirect_target() -> None:
    policy = BrowserURLPolicy(["example.com"], max_redirects=1)
    private_backend = PlaywrightEdgeBackend(resolver=lambda _host, _port: ["127.0.0.1"])
    private_backend._policy = policy
    private_route = StubRoute(StubRequest("https://example.com/"))

    await private_backend._guard_route(private_route)

    assert private_route.aborted == "blockedbyclient"
    assert private_route.continued is False

    public_backend = PlaywrightEdgeBackend(resolver=lambda _host, _port: ["93.184.216.34"])
    public_backend._policy = policy
    redirect_route = StubRoute(
        StubRequest("https://attacker.example.net/", StubRequest("https://example.com/"))
    )
    await public_backend._guard_route(redirect_route)

    assert redirect_route.aborted == "blockedbyclient"
    assert redirect_route.continued is False


def test_policy_requires_both_browser_runtime_attestations(app_config: AppConfig) -> None:
    payload = app_config.model_dump(mode="python")
    payload["security"]["browser"] = {
        "enabled": True,
        "engine": "playwright_edge",
        "allowed_domains": ["example.com"],
        "download_dir": Path(app_config.project_root) / ".astercode" / "downloads",
        "max_redirects": 8,
        "max_download_bytes": 33_554_432,
        "isolated_profile_required": True,
    }
    config = AppConfig.model_validate(payload)
    declared = BrowserTools.specs[0]

    blocked = PolicyEngine(config).evaluate(
        "browser.open",
        {"url": "https://example.com/"},
        cwd=str(config.project_root),
        declared=declared,
    )
    approved_boundary = PolicyEngine(
        config,
        runtime_capabilities=RuntimePolicyCapabilities(
            browser_profile_isolated=True,
            browser_network_policy_enforced=True,
        ),
    ).evaluate(
        "browser.open",
        {"url": "https://example.com/"},
        cwd=str(config.project_root),
        declared=declared,
    )

    assert blocked.decision == "deny"
    assert approved_boundary.decision == "approval_required"


def test_runtime_assembles_configured_backend_but_not_egress_attestation(
    app_config: AppConfig,
) -> None:
    payload = app_config.model_dump(mode="python")
    payload["security"]["browser"] = {
        "enabled": True,
        "engine": "playwright_edge",
        "allowed_domains": ["example.com"],
        "download_dir": Path(app_config.project_root) / ".astercode" / "downloads",
        "max_redirects": 8,
        "max_download_bytes": 33_554_432,
        "isolated_profile_required": True,
    }
    config = AppConfig.model_validate(payload)

    provider = next(
        item for item in build_registry(config).providers() if isinstance(item, BrowserTools)
    )

    assert provider.profile_isolated is True
    assert provider.network_egress_enforced is False


@pytest.mark.asyncio
async def test_real_edge_about_blank_smoke_is_explicit_and_offline() -> None:
    if os.environ.get("ASTERCODE_LIVE_BROWSER_SMOKE") != "1":
        pytest.skip("set ASTERCODE_LIVE_BROWSER_SMOKE=1 for the local Edge smoke")
    pytest.importorskip("playwright.async_api")
    backend = PlaywrightEdgeBackend()
    try:
        result: dict[str, Any] = await backend.probe_about_blank()
    finally:
        await backend.close()

    assert result["url"] == "about:blank"
    assert result["uses_user_profile"] is False
    assert result["network_requests"] == 0
    assert result["network_egress_verified"] is False
