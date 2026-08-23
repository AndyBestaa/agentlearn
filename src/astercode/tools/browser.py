"""Restricted browser facade and a deterministic, network-free fake.

The optional Playwright backend is injected into :class:`BrowserTools`; this
facade still fails closed until an independent host network policy is attested.
The fake adapter uses only in-memory fixtures.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

from ..security import (
    PathAuthorizationError,
    canonicalize_authorized_path,
    is_forbidden_network_address,
)
from .base import ToolResult, ToolSpec, new_action_id, timed_result

if TYPE_CHECKING:
    from .playwright_browser import BrowserPage


class BrowserBackend(Protocol):
    """Trusted-host injection point; implementations must be non-persistent."""

    profile_isolated: bool
    uses_user_profile: bool
    profile_kind: str

    async def open(self, url: str, policy: BrowserURLPolicy) -> BrowserPage: ...

    async def snapshot(self) -> BrowserPage: ...

    async def close(self) -> None: ...


class BrowserSecurityError(RuntimeError):
    """Raised when a URL/profile/download cannot be proven safe."""


def _normalise_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or "@" in domain:
        raise BrowserSecurityError("browser allowlist entries must be bare domains")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BrowserSecurityError("invalid internationalized domain") from exc
    if domain == "localhost" or is_forbidden_network_address(domain):
        raise BrowserSecurityError("loopback/private/link-local domains are forbidden")
    return domain


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    url: str
    scheme: str
    host: str
    port: int | None


class BrowserURLPolicy:
    """Exact/subdomain allowlist plus SSRF destination checks.

    A live adapter must call ``validate_resolved_addresses`` after each DNS
    resolution and redirect.  This class does not perform DNS itself, so the
    deterministic fake never creates network traffic.
    """

    def __init__(self, allowed_domains: Sequence[str], *, max_redirects: int = 8) -> None:
        self.allowed_domains = tuple(sorted({_normalise_domain(item) for item in allowed_domains}))
        if not self.allowed_domains:
            raise BrowserSecurityError("browser domain allowlist is empty")
        if not 0 <= max_redirects <= 32:
            raise ValueError("max_redirects must be between 0 and 32")
        self.max_redirects = max_redirects

    def validate(self, url: str) -> ValidatedURL:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise BrowserSecurityError(f"malformed URL: {exc}") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise BrowserSecurityError("only http/https browser URLs are permitted")
        if parsed.username is not None or parsed.password is not None:
            raise BrowserSecurityError("credentials in browser URLs are forbidden")
        if not parsed.hostname:
            raise BrowserSecurityError("browser URL has no hostname")
        try:
            host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise BrowserSecurityError("invalid URL hostname") from exc
        if host == "localhost" or host.endswith(".localhost") or is_forbidden_network_address(host):
            raise BrowserSecurityError("loopback/private/link-local/metadata destination is forbidden")
        if not any(host == domain or host.endswith(f".{domain}") for domain in self.allowed_domains):
            raise BrowserSecurityError(f"domain is not allowlisted: {host}")
        expected_port = 443 if parsed.scheme.lower() == "https" else 80
        if port is not None and port != expected_port:
            raise BrowserSecurityError("non-standard browser destination ports are forbidden")
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc = f"{netloc}:{port}"
        normalised = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        return ValidatedURL(normalised, parsed.scheme.lower(), host, port)

    def validate_redirect_chain(self, initial_url: str, redirects: Sequence[str]) -> tuple[ValidatedURL, ...]:
        if len(redirects) > self.max_redirects:
            raise BrowserSecurityError("redirect limit exceeded")
        return tuple(self.validate(item) for item in (initial_url, *redirects))

    def validate_resolved_addresses(self, addresses: Sequence[str]) -> None:
        if not addresses:
            raise BrowserSecurityError("DNS result is empty")
        forbidden = [address for address in addresses if is_forbidden_network_address(address)]
        if forbidden:
            raise BrowserSecurityError("DNS resolved to a forbidden private or metadata address")


@dataclass(frozen=True, slots=True)
class BrowserFixture:
    body: str
    status_code: int = 200
    redirects: tuple[str, ...] = ()
    resolved_addresses: tuple[str, ...] = ("93.184.216.34",)
    downloads: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an HTTP status")
        if any(not isinstance(value, bytes) for value in self.downloads.values()):
            raise TypeError("fake downloads must contain bytes")


def _blocked(tool: str, args: Mapping[str, Any], reason: str) -> ToolResult:
    result = timed_result(tool, new_action_id(tool, args))
    result.status = "failed"
    result.error = reason
    result.metadata.update({"blocked": True, "live_integration_verified": False})
    return result.finish()


class BrowserTools:
    """Read-only live facade guarded by host-attested egress isolation."""

    specs = (
        ToolSpec(
            "browser.open",
            "Open an allowlisted URL in an isolated profile.",
            "browser.live",
            ("network",),
            "P2",
            schema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "browser.snapshot",
            "Read isolated browser page text.",
            "browser.live",
            ("network",),
            "P2",
            schema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        ToolSpec(
            "browser.download",
            "Download an allowlisted fixture into the authorized download directory.",
            "browser.live",
            ("network", "filesystem_write"),
            "P2",
            schema={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "browser.submit",
            "Submit an external form; immediate exact approval is required.",
            "browser.live",
            ("network", "external_submit"),
            "P3",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "selector": {"type": "string"},
                    "fields": {"type": "object"},
                },
                "required": ["selector"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(
        self,
        *,
        enabled: bool = False,
        allowlist: Sequence[str] = (),
        max_redirects: int = 8,
        backend: BrowserBackend | None = None,
        network_egress_enforced: bool = False,
    ) -> None:
        self.enabled = enabled
        self.profile_id = f"isolated_{uuid.uuid4().hex}"
        self.uses_user_profile = False
        self._policy = BrowserURLPolicy(allowlist, max_redirects=max_redirects) if allowlist else None
        self._backend = backend
        # This is a trusted dependency-injection result, never loaded from TOML.
        self.network_egress_enforced = network_egress_enforced
        self.profile_isolated = bool(
            backend is not None
            and getattr(backend, "profile_isolated", False)
            and not getattr(backend, "uses_user_profile", True)
        )
        self._active = False

    async def open(self, url: str) -> ToolResult:
        if not self.enabled:
            return _blocked("browser.open", {"url": url}, "browser automation is disabled")
        if self._policy is None:
            return _blocked("browser.open", {"url": url}, "browser domain allowlist is empty")
        try:
            self._policy.validate(url)
        except BrowserSecurityError as exc:
            return _blocked("browser.open", {"url": url}, str(exc))
        if self._backend is None:
            return _blocked(
                "browser.open",
                {"url": url},
                "LIVE BROWSER BLOCKED: no Playwright backend is configured",
            )
        if not self.profile_isolated:
            return _blocked(
                "browser.open",
                {"url": url},
                "LIVE BROWSER BLOCKED: non-persistent profile isolation is not attested",
            )
        if not self.network_egress_enforced:
            return _blocked(
                "browser.open",
                {"url": url},
                "LIVE BROWSER BLOCKED: OS network egress isolation is not attested",
            )
        result = timed_result("browser.open", new_action_id("browser.open", {"url": url}))
        try:
            page = await self._backend.open(url, self._policy)
            self._active = True
            result.stdout = page.text
            result.metadata.update(
                {
                    "url": page.url,
                    "title": page.title,
                    "status_code": page.status_code,
                    "redirect_count": page.redirect_count,
                    "profile_kind": self._backend.profile_kind,
                    "uses_user_profile": False,
                    "network_used": True,
                    "network_egress_enforced": True,
                }
            )
            return result.finish()
        except Exception as exc:
            return _blocked(
                "browser.open",
                {"url": url},
                f"live browser navigation rejected ({type(exc).__name__})",
            )

    async def snapshot(self) -> ToolResult:
        if not self._active or self._backend is None:
            return _blocked("browser.snapshot", {}, "no verified isolated browser session is active")
        result = timed_result("browser.snapshot", new_action_id("browser.snapshot", {}))
        try:
            page = await self._backend.snapshot()
            result.stdout = page.text
            result.metadata.update(
                {
                    "url": page.url,
                    "title": page.title,
                    "profile_kind": self._backend.profile_kind,
                    "uses_user_profile": False,
                    "network_egress_enforced": self.network_egress_enforced,
                }
            )
            return result.finish()
        except Exception as exc:
            return _blocked(
                "browser.snapshot",
                {},
                f"live browser snapshot rejected ({type(exc).__name__})",
            )

    def download(self, name: str) -> ToolResult:
        return _blocked("browser.download", {"name": name}, "no verified isolated browser session is active")

    def submit(self, selector: str, fields: Mapping[str, Any] | None = None) -> ToolResult:
        return _blocked(
            "browser.submit",
            {"selector": selector, "fields": dict(fields or {})},
            "external browser submission requires P3 approval and a verified live adapter",
        )

    async def stop_all(self) -> None:
        self._active = False
        if self._backend is not None:
            await self._backend.close()


class FakeBrowserTools:
    """Deterministic browser that reads fixtures and never opens the network."""

    specs = (
        ToolSpec(
            "browser.open",
            "Open an allowlisted URL from deterministic offline fixtures.",
            "browser.fake.offline",
            ("offline_fixture_read",),
            "P0",
            schema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "browser.snapshot",
            "Read current deterministic fixture page text.",
            "browser.fake.offline",
            ("offline_fixture_read",),
            "P0",
            schema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        ToolSpec(
            "browser.download",
            "Write fixture bytes to the authorized isolated download directory.",
            "browser.fake.offline",
            ("filesystem_write",),
            "P1",
            schema={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "browser.submit",
            "Record a deterministic fake form submission; P3 approval remains mandatory.",
            "browser.fake.offline",
            ("external_submit_simulation",),
            "P3",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "minLength": 1},
                    "fields": {"type": "object"},
                },
                "required": ["selector"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(
        self,
        fixtures: Mapping[str, BrowserFixture | Mapping[str, Any]],
        *,
        allowlist: Sequence[str],
        authorized_roots: Sequence[str | Path],
        download_dir: str | Path,
        profile_seed: str = "default",
        max_download_bytes: int = 33_554_432,
    ) -> None:
        self._policy = BrowserURLPolicy(allowlist)
        self._authorized_roots = tuple(Path(root) for root in authorized_roots)
        checked_dir = canonicalize_authorized_path(
            download_dir,
            self._authorized_roots,
            must_exist=False,
        )
        checked_dir.resolved.mkdir(parents=True, exist_ok=True)
        self._download_dir = canonicalize_authorized_path(
            checked_dir.resolved,
            self._authorized_roots,
            must_exist=True,
        )
        self.profile_id = "fake_" + hashlib.sha256(profile_seed.encode("utf-8")).hexdigest()[:20]
        self.profile_kind = "ephemeral_offline_fixture"
        self.uses_user_profile = False
        if max_download_bytes < 1:
            raise ValueError("max_download_bytes must be positive")
        self._max_download_bytes = max_download_bytes
        self._fixtures: dict[str, BrowserFixture] = {}
        for raw_url, fixture in fixtures.items():
            url = self._policy.validate(raw_url).url
            self._fixtures[url] = fixture if isinstance(fixture, BrowserFixture) else BrowserFixture(**fixture)
        self._current_url: str | None = None
        self._current: BrowserFixture | None = None
        self.submissions: list[dict[str, Any]] = []
        self.closed = False

    def _failure(self, tool: str, arguments: Mapping[str, Any], exc: Exception) -> ToolResult:
        return _blocked(tool, arguments, f"{type(exc).__name__}: {exc}")

    def open(self, url: str) -> ToolResult:
        arguments = {"url": url}
        result = timed_result("browser.open", new_action_id("browser.open", arguments))
        try:
            if self.closed:
                raise BrowserSecurityError("isolated fake profile is closed")
            initial = self._policy.validate(url)
            fixture = self._fixtures.get(initial.url)
            if fixture is None:
                raise BrowserSecurityError("offline fixture not found; live network fallback is forbidden")
            chain = self._policy.validate_redirect_chain(initial.url, fixture.redirects)
            self._policy.validate_resolved_addresses(fixture.resolved_addresses)
            final = chain[-1]
            self._current_url = final.url
            self._current = fixture
            result.stdout = fixture.body
            result.metadata.update(
                {
                    "profile_id": self.profile_id,
                    "profile_kind": self.profile_kind,
                    "uses_user_profile": False,
                    "url": final.url,
                    "redirects": [item.url for item in chain[1:]],
                    "status_code": fixture.status_code,
                    "network_used": False,
                }
            )
            return result.finish()
        except (BrowserSecurityError, PathAuthorizationError) as exc:
            return self._failure("browser.open", arguments, exc)

    def snapshot(self) -> ToolResult:
        result = timed_result("browser.snapshot", new_action_id("browser.snapshot", {}))
        if self.closed or self._current is None:
            return _blocked("browser.snapshot", {}, "no offline fixture page is active")
        result.stdout = self._current.body
        result.metadata.update(
            {
                "profile_id": self.profile_id,
                "url": self._current_url,
                "network_used": False,
            }
        )
        return result.finish()

    def download(self, name: str) -> ToolResult:
        arguments = {"name": name}
        result = timed_result("browser.download", new_action_id("browser.download", arguments))
        temporary: str | None = None
        try:
            if self.closed or self._current is None:
                raise BrowserSecurityError("no offline fixture page is active")
            if not name or name != Path(name).name or name in {".", ".."}:
                raise BrowserSecurityError("download name must be one plain filename")
            payload = self._current.downloads.get(name)
            if payload is None:
                raise BrowserSecurityError("download is not present in the current fixture")
            if len(payload) > self._max_download_bytes:
                raise BrowserSecurityError("download exceeds the configured size limit")
            self._download_dir.revalidate(self._authorized_roots, must_exist=True)
            checked_target = canonicalize_authorized_path(
                self._download_dir.resolved / name,
                self._authorized_roots,
                must_exist=False,
            )
            if checked_target.resolved.parent != self._download_dir.resolved:
                raise BrowserSecurityError("download target escaped the configured directory")
            fd, temporary = tempfile.mkstemp(prefix=".astercode-download-", dir=self._download_dir.resolved)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            fresh_dir = canonicalize_authorized_path(
                self._download_dir.resolved,
                self._authorized_roots,
                must_exist=True,
            )
            if (
                fresh_dir.identity.device != self._download_dir.identity.device
                or fresh_dir.identity.inode != self._download_dir.identity.inode
            ):
                raise BrowserSecurityError("download directory identity changed")
            os.replace(temporary, checked_target.resolved)
            temporary = None
            digest = hashlib.sha256(payload).hexdigest()
            result.artifacts.append(str(checked_target.resolved))
            result.side_effects.append(f"created {checked_target.resolved}")
            result.metadata.update(
                {
                    "sha256": digest,
                    "size": len(payload),
                    "network_used": False,
                    "profile_id": self.profile_id,
                }
            )
            return result.finish()
        except (BrowserSecurityError, PathAuthorizationError, OSError) as exc:
            return self._failure("browser.download", arguments, exc)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def submit(self, selector: str, fields: Mapping[str, Any] | None = None) -> ToolResult:
        arguments = {"selector": selector, "fields": dict(fields or {})}
        result = timed_result("browser.submit", new_action_id("browser.submit", arguments))
        if self.closed or self._current is None:
            return _blocked("browser.submit", arguments, "no offline fixture page is active")
        if not selector.strip():
            return _blocked("browser.submit", arguments, "selector cannot be blank")
        record = {
            "selector": selector,
            "fields": dict(fields or {}),
            "url": self._current_url,
            "simulated": True,
        }
        self.submissions.append(record)
        result.stdout = "offline form submission recorded"
        result.side_effects.append("recorded external submission simulation")
        result.metadata.update({"network_used": False, "simulated": True, "profile_id": self.profile_id})
        return result.finish()

    def close(self) -> None:
        self._current = None
        self._current_url = None
        self.closed = True


__all__ = [
    "BrowserBackend",
    "BrowserFixture",
    "BrowserSecurityError",
    "BrowserTools",
    "BrowserURLPolicy",
    "FakeBrowserTools",
    "ValidatedURL",
]
