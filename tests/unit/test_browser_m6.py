from __future__ import annotations

from pathlib import Path

import pytest

from astercode.tools.browser import (
    BrowserFixture,
    BrowserSecurityError,
    BrowserTools,
    BrowserURLPolicy,
    FakeBrowserTools,
)


def test_fake_browser_uses_isolated_profile_and_never_network(tmp_path: Path) -> None:
    browser = FakeBrowserTools(
        {"https://docs.example.com/guide": BrowserFixture(body="offline guide")},
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
        profile_seed="repeatable",
    )

    opened = browser.open("https://docs.example.com/guide")
    snapshot = browser.snapshot()

    assert opened.status == "completed"
    assert opened.stdout == "offline guide"
    assert opened.metadata["network_used"] is False
    assert opened.metadata["uses_user_profile"] is False
    assert browser.profile_kind == "ephemeral_offline_fixture"
    assert snapshot.stdout == "offline guide"


def test_browser_url_policy_requires_allowlist_and_checks_dns_results() -> None:
    policy = BrowserURLPolicy(["example.com"])

    assert policy.validate("https://sub.example.com/path").host == "sub.example.com"
    with pytest.raises(BrowserSecurityError, match="not allowlisted"):
        policy.validate("https://example.net/")
    with pytest.raises(BrowserSecurityError, match="forbidden"):
        policy.validate_resolved_addresses(["169.254.169.254"])
    with pytest.raises(BrowserSecurityError, match="ports"):
        policy.validate("https://example.com:8443/")


def test_fake_browser_download_is_atomic_and_authorized(tmp_path: Path) -> None:
    browser = FakeBrowserTools(
        {
            "https://example.com/file": BrowserFixture(
                body="download page",
                downloads={"report.txt": b"offline report\n"},
            )
        },
        allowlist=["example.com"],
        authorized_roots=[tmp_path],
        download_dir=tmp_path / "downloads",
    )
    assert browser.open("https://example.com/file").status == "completed"

    result = browser.download("report.txt")

    assert result.status == "completed"
    assert (tmp_path / "downloads" / "report.txt").read_bytes() == b"offline report\n"
    assert len(result.metadata["sha256"]) == 64
    assert result.metadata["network_used"] is False


@pytest.mark.asyncio
async def test_live_browser_remains_explicitly_blocked_without_adapter() -> None:
    result = await BrowserTools(enabled=True, allowlist=["example.com"]).open("https://example.com/")

    assert result.status == "failed"
    assert result.metadata["blocked"] is True
    assert "no Playwright backend" in (result.error or "")
