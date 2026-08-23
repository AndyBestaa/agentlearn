"""Optional Playwright/Edge backend for the restricted browser facade.

This module deliberately does not claim that Playwright request routing is an
OS egress sandbox.  Routing is defence in depth; a trusted host adapter must
separately attest network enforcement before :class:`BrowserTools` permits an
HTTP navigation.  The backend always uses a non-persistent BrowserContext and
never accepts a user-data directory.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .browser import BrowserSecurityError, BrowserURLPolicy

AddressResolver = Callable[[str, int], Sequence[str]]


def resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve a host without consulting shell commands or repository files."""

    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return tuple(sorted({str(record[4][0]) for record in records}))


@dataclass(frozen=True, slots=True)
class BrowserPage:
    """Small, bounded-by-the-tool result from a read-only navigation."""

    url: str
    text: str
    title: str
    status_code: int | None
    redirect_count: int


class PlaywrightEdgeBackend:
    """Lazy async Microsoft Edge backend with an ephemeral browser context.

    JavaScript, downloads, permissions and service workers are disabled for
    this read-only slice.  Every routed HTTP(S) request is checked against the
    URL allowlist and a fresh DNS result.  That DNS check has an unavoidable
    resolution/connect race, so ``network_egress_enforced`` is intentionally
    not a property of this class and must come from an independent host policy.
    """

    profile_isolated = True
    uses_user_profile = False
    profile_kind = "playwright_non_persistent_context"

    def __init__(
        self,
        *,
        channel: str = "msedge",
        headless: bool = True,
        resolver: AddressResolver = resolve_addresses,
        navigation_timeout_ms: int = 30_000,
    ) -> None:
        if channel not in {"msedge", "msedge-beta", "msedge-dev"}:
            raise ValueError("only explicit Microsoft Edge channels are supported")
        if not 1_000 <= navigation_timeout_ms <= 120_000:
            raise ValueError("navigation timeout must be between 1 and 120 seconds")
        self.channel = channel
        self.headless = headless
        self._resolver = resolver
        self._navigation_timeout_ms = navigation_timeout_ms
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None
        self._policy: BrowserURLPolicy | None = None
        self._route_error: BrowserSecurityError | None = None
        self._network_requests: list[str] = []
        self._closed = False

    @property
    def available(self) -> bool:
        try:
            import playwright.async_api  # noqa: F401
        except ImportError:
            return False
        return True

    async def _start(self) -> None:
        if self._closed:
            raise BrowserSecurityError("isolated browser backend is closed")
        if self._page is not None:
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserSecurityError(
                "Playwright is not installed; install the locked 'browser' extra"
            ) from exc

        manager = async_playwright()
        playwright: Any | None = None
        try:
            playwright = await manager.start()
            browser = await playwright.chromium.launch(
                channel=self.channel,
                headless=self.headless,
                chromium_sandbox=True,
            )
            context = await browser.new_context(
                accept_downloads=False,
                service_workers="block",
                java_script_enabled=False,
                ignore_https_errors=False,
            )
            await context.clear_permissions()
            await context.route("**/*", self._guard_route)
            page = await context.new_page()
        except Exception:
            if playwright is not None:
                await playwright.stop()
            raise
        self._playwright = playwright
        self._browser = browser
        self._context = context
        self._page = page

    @staticmethod
    def _redirect_count(request: Any) -> int:
        count = 0
        current = request.redirected_from
        while current is not None:
            count += 1
            current = current.redirected_from
        return count

    async def _guard_route(self, route: Any) -> None:
        """Fail closed on every routable request, including redirect hops."""

        try:
            request = route.request
            self._network_requests.append(str(request.url))
            policy = self._policy
            if policy is None:
                raise BrowserSecurityError("network navigation is not armed")
            validated = policy.validate(request.url)
            if self._redirect_count(request) > policy.max_redirects:
                raise BrowserSecurityError("redirect limit exceeded")
            port = validated.port or (443 if validated.scheme == "https" else 80)
            addresses = await asyncio.to_thread(self._resolver, validated.host, port)
            policy.validate_resolved_addresses(addresses)
        except BrowserSecurityError as exc:
            self._route_error = exc
            await route.abort("blockedbyclient")
            return
        except Exception as exc:
            self._route_error = BrowserSecurityError(
                f"destination resolution failed ({type(exc).__name__})"
            )
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def open(self, url: str, policy: BrowserURLPolicy) -> BrowserPage:
        """Open one allowlisted HTTP(S) page after arming the route guard."""

        validated = policy.validate(url)
        self._policy = policy
        self._route_error = None
        self._network_requests.clear()
        await self._start()
        assert self._page is not None
        try:
            response = await self._page.goto(
                validated.url,
                wait_until="domcontentloaded",
                timeout=self._navigation_timeout_ms,
            )
        except Exception as exc:
            if self._route_error is not None:
                raise self._route_error from exc
            raise BrowserSecurityError(f"browser navigation failed ({type(exc).__name__})") from exc
        if self._route_error is not None:
            raise self._route_error
        final = policy.validate(self._page.url)
        title = await self._page.title()
        try:
            text = await self._page.locator("body").inner_text(timeout=5_000)
        except Exception:
            text = ""
        redirect_count = self._redirect_count(response.request) if response is not None else 0
        return BrowserPage(
            url=final.url,
            text=text,
            title=title,
            status_code=response.status if response is not None else None,
            redirect_count=redirect_count,
        )

    async def snapshot(self) -> BrowserPage:
        if self._page is None or self._policy is None:
            raise BrowserSecurityError("no isolated live browser page is active")
        final = self._policy.validate(self._page.url)
        title = await self._page.title()
        try:
            text = await self._page.locator("body").inner_text(timeout=5_000)
        except Exception:
            text = ""
        return BrowserPage(final.url, text, title, None, 0)

    async def probe_about_blank(self) -> dict[str, Any]:
        """Launch the real engine without opening a socket or arming network."""

        self._policy = None
        self._route_error = None
        self._network_requests.clear()
        await self._start()
        assert self._page is not None
        await self._page.goto("about:blank", wait_until="domcontentloaded")
        if self._page.url != "about:blank":
            raise BrowserSecurityError("offline engine probe navigated unexpectedly")
        if self._network_requests:
            raise BrowserSecurityError("offline engine probe observed a network request")
        return {
            "engine": "playwright-edge",
            "channel": self.channel,
            "url": self._page.url,
            "profile_kind": self.profile_kind,
            "uses_user_profile": False,
            "network_requests": 0,
            "network_egress_verified": False,
        }

    async def close(self) -> None:
        context, browser, playwright = self._context, self._browser, self._playwright
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        self._policy = None
        self._closed = True
        first_error: Exception | None = None
        for owner, method in (
            (context, "close"),
            (browser, "close"),
            (playwright, "stop"),
        ):
            if owner is None:
                continue
            try:
                await getattr(owner, method)()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise BrowserSecurityError(
                f"isolated browser cleanup failed ({type(first_error).__name__})"
            ) from first_error


__all__ = [
    "AddressResolver",
    "BrowserPage",
    "PlaywrightEdgeBackend",
    "resolve_addresses",
]
