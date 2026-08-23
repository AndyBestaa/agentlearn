"""Read-only, budget-bounded subagent delegation.

M6 deliberately supports only an offline vertical slice.  A child receives a
strict intersection of the parent's roots/tools/budget, runs in an independent
session, and cannot register process, network, SSH, browser, or write tools.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import secrets
import threading
import time
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Protocol, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import RiskLevel, SessionStatus
from .security import canonical_json, canonicalize_authorized_path, contains_probable_secret, redact_secrets
from .tools.base import ToolResult, ToolSpec, new_action_id, timed_result

if TYPE_CHECKING:
    from .config import AppConfig
    from .provider import Provider
    from .storage import Storage


class SubagentBlockedError(RuntimeError):
    """A child request exceeds the parent's permissions or budget."""


READ_ONLY_TOOLS = frozenset(
    {
        "fs.list",
        "fs.stat",
        "fs.read",
        "fs.search",
        "git.status",
        "git.diff",
        "git.log",
        "git.show",
        "git.branch",
    }
)


class SubagentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)


class SubagentBudget(SubagentModel):
    max_tool_calls: int = Field(default=12, ge=1, le=1_000)
    max_tokens: int = Field(default=8_000, ge=1, le=10_000_000)
    max_elapsed_seconds: float = Field(default=300.0, gt=0, le=86_400)

    def within(self, parent: SubagentBudget) -> bool:
        return (
            self.max_tool_calls <= parent.max_tool_calls
            and self.max_tokens <= parent.max_tokens
            and self.max_elapsed_seconds <= parent.max_elapsed_seconds
        )

class ParentAuthority(SubagentModel):
    authority_id: str = Field(default_factory=lambda: f"subauth_{secrets.token_hex(16)}")
    parent_session_id: str = Field(default="offline-parent", min_length=1, max_length=256)
    authorized_roots: tuple[Path, ...] = Field(min_length=1)
    allowed_tools: frozenset[str]
    remaining_budget: SubagentBudget
    depth: int = Field(default=0, ge=0)
    max_depth: int = Field(default=1, ge=0, le=16)
    max_concurrency: int = Field(default=1, ge=1, le=32)
    active_children: int = Field(default=0, ge=0, le=32)

    @field_validator("authorized_roots")
    @classmethod
    def resolve_roots(cls, values: tuple[Path, ...]) -> tuple[Path, ...]:
        roots = tuple(value.resolve(strict=True) for value in values)
        if any(not root.is_dir() for root in roots):
            raise ValueError("subagent authorized roots must be existing directories")
        return roots


class SubagentRequest(SubagentModel):
    task: str = Field(min_length=1, max_length=16_384)
    workspace: Path
    requested_tools: frozenset[str] = Field(min_length=1)
    budget: SubagentBudget = Field(default_factory=SubagentBudget)


@dataclass(frozen=True, slots=True)
class SubagentGrant:
    grant_id: str
    binding_hash: str
    authority_id: str
    parent_session_id: str
    task: str
    workspace: Path
    allowed_tools: frozenset[str]
    budget: SubagentBudget
    depth: int
    read_only: bool = True


class ReadOnlySubagentPolicy:
    """Atomically reserve a strict subset of one parent's authority.

    The reservation, rather than a caller-maintained ``active_children``
    snapshot, is the concurrency and budget boundary.  Every grant is unique
    and its binding hash includes the exact delegated budget.
    """

    def __init__(self, *, enabled: bool = False) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()
        self._reservations: dict[str, SubagentGrant] = {}

    @staticmethod
    def _validate(parent: ParentAuthority, request: SubagentRequest) -> Path:
        if parent.depth >= parent.max_depth:
            raise SubagentBlockedError("subagent maximum depth reached")
        if contains_probable_secret(request.task):
            raise SubagentBlockedError("secret-looking task content cannot be delegated")
        forbidden = request.requested_tools - READ_ONLY_TOOLS
        if forbidden:
            raise SubagentBlockedError("subagents are restricted to read-only tools")
        if not request.requested_tools.issubset(parent.allowed_tools):
            raise SubagentBlockedError("subagent permissions cannot exceed parent permissions")
        checked = canonicalize_authorized_path(
            request.workspace,
            parent.authorized_roots,
            must_exist=True,
        )
        if not checked.resolved.is_dir():
            raise SubagentBlockedError("subagent workspace must be a directory")
        return checked.resolved

    def grant(self, parent: ParentAuthority, request: SubagentRequest) -> SubagentGrant:
        if not self.enabled:
            raise SubagentBlockedError("multi-agent delegation is disabled")
        workspace = self._validate(parent, request)
        with self._lock:
            active = [
                grant
                for grant in self._reservations.values()
                if grant.authority_id == parent.authority_id
            ]
            if parent.active_children + len(active) >= parent.max_concurrency:
                raise SubagentBlockedError("subagent concurrency budget is exhausted")
            # Account for all active reservations under the same lock; caller
            # snapshots cannot overbook these counters.
            available_tool_calls = (
                parent.remaining_budget.max_tool_calls
                - sum(item.budget.max_tool_calls for item in active)
            )
            available_tokens = (
                parent.remaining_budget.max_tokens
                - sum(item.budget.max_tokens for item in active)
            )
            available_elapsed = (
                parent.remaining_budget.max_elapsed_seconds
                - sum(item.budget.max_elapsed_seconds for item in active)
            )
            if (
                request.budget.max_tool_calls > available_tool_calls
                or request.budget.max_tokens > available_tokens
                or request.budget.max_elapsed_seconds > available_elapsed
            ):
                raise SubagentBlockedError("subagent budget exceeds parent remaining budget")
            grant_id = f"subgrant_{secrets.token_hex(16)}"
            binding = {
                "grant_id": grant_id,
                "authority_id": parent.authority_id,
                "parent_session_id": parent.parent_session_id,
                "task": request.task,
                "workspace": str(workspace),
                "allowed_tools": sorted(request.requested_tools),
                "budget": request.budget.model_dump(mode="json"),
                "depth": parent.depth + 1,
            }
            binding_hash = hashlib.sha256(canonical_json(binding).encode("utf-8")).hexdigest()
            grant = SubagentGrant(
                grant_id=grant_id,
                binding_hash=binding_hash,
                authority_id=parent.authority_id,
                parent_session_id=parent.parent_session_id,
                task=request.task,
                workspace=workspace,
                allowed_tools=frozenset(request.requested_tools),
                budget=request.budget,
                depth=parent.depth + 1,
            )
            self._reservations[grant_id] = grant
            return grant

    def assert_active(self, grant: SubagentGrant) -> None:
        with self._lock:
            stored = self._reservations.get(grant.grant_id)
            if stored != grant or self._binding_hash(grant) != grant.binding_hash:
                raise SubagentBlockedError("subagent grant is absent, released, or changed")

    @staticmethod
    def _binding_hash(grant: SubagentGrant) -> str:
        binding = {
            "grant_id": grant.grant_id,
            "authority_id": grant.authority_id,
            "parent_session_id": grant.parent_session_id,
            "task": grant.task,
            "workspace": str(grant.workspace),
            "allowed_tools": sorted(grant.allowed_tools),
            "budget": grant.budget.model_dump(mode="json"),
            "depth": grant.depth,
        }
        return hashlib.sha256(canonical_json(binding).encode("utf-8")).hexdigest()

    def release(self, grant_id: str) -> bool:
        with self._lock:
            return self._reservations.pop(grant_id, None) is not None

    def active_count(self, authority_id: str | None = None) -> int:
        with self._lock:
            if authority_id is None:
                return len(self._reservations)
            return sum(
                grant.authority_id == authority_id
                for grant in self._reservations.values()
            )


class SubagentRunner(Protocol):
    def run(self, grant: SubagentGrant) -> Any: ...


class BlockedSubagentRunner:
    def run(self, grant: SubagentGrant) -> Mapping[str, Any]:
        del grant
        raise SubagentBlockedError("LIVE SUBAGENT NOT VERIFIED: only an injected offline fake provider is allowed")


class DeterministicFakeSubagentRunner:
    """Small fixture runner retained for contract-level unit tests."""

    def __init__(self, responses: Mapping[str, Mapping[str, Any]]) -> None:
        self._responses = {task: dict(response) for task, response in responses.items()}
        self.runs: list[dict[str, Any]] = []

    def run(self, grant: SubagentGrant) -> Mapping[str, Any]:
        response = self._responses.get(grant.task)
        if response is None:
            raise SubagentBlockedError("deterministic subagent fixture is absent")
        used_tools = tuple(str(item) for item in response.get("used_tools", ()))
        if not set(used_tools).issubset(grant.allowed_tools):
            raise SubagentBlockedError("fake child attempted a tool outside its grant")
        tool_calls = int(response.get("tool_calls", len(used_tools)))
        tokens = int(response.get("tokens", 0))
        elapsed = float(response.get("elapsed_seconds", 0.0))
        if (
            tool_calls > grant.budget.max_tool_calls
            or tokens > grant.budget.max_tokens
            or elapsed > grant.budget.max_elapsed_seconds
        ):
            raise SubagentBlockedError("fake child exceeded its delegated budget")
        record = {
            "grant_id": grant.grant_id,
            "binding_hash": grant.binding_hash,
            "task": grant.task,
            "used_tools": used_tools,
            "tool_calls": tool_calls,
            "tokens": tokens,
            "elapsed_seconds": elapsed,
            "usage": {
                "rounds": 1,
                "tool_calls": tool_calls,
                "input_tokens": tokens,
                "output_tokens": 0,
                "total_tokens": tokens,
                "cost_usd": 0.0,
            },
            "read_only": True,
        }
        self.runs.append(record)
        return {**response, **record}


@dataclass(slots=True)
class _ActiveChild:
    parent_session_id: str
    child_session_id: str
    core: Any
    task: asyncio.Task[dict[str, Any]]


class OfflineReadOnlyAgentRunner:
    """Run a genuine child LangGraph loop with an offline provider only."""

    def __init__(self, config: AppConfig, storage: Storage, provider: Provider) -> None:
        self.config = config
        self.storage = storage
        self.provider = provider
        self._active: dict[str, _ActiveChild] = {}
        self._active_lock = asyncio.Lock()

    @staticmethod
    def _model_specs(registry: Any) -> list[Any]:
        from .models import ToolSpec as ModelToolSpec

        output: list[Any] = []
        for spec in registry.specs():
            output.append(
                ModelToolSpec(
                    name=spec.name,
                    capability=spec.capability,
                    description=spec.description,
                    input_schema=dict(spec.schema),
                    side_effects=list(spec.side_effects),
                    risk=RiskLevel(str(spec.risk)),
                    timeout=spec.timeout_seconds,
                    max_output=spec.max_output,
                    idempotent=spec.idempotent,
                )
            )
        return output

    @staticmethod
    def _registry(grant: SubagentGrant) -> Any:
        from .tools.filesystem import FilesystemTools
        from .tools.git import GitTools
        from .tools.registry import ToolRegistry

        registry = ToolRegistry()
        for provider in (FilesystemTools([grant.workspace]), GitTools([grant.workspace])):
            for spec in provider.specs:
                if spec.name not in grant.allowed_tools:
                    continue
                registry.register(spec, getattr(provider, spec.name.split(".", 1)[1]))
        if {spec.name for spec in registry.specs()} != set(grant.allowed_tools):
            raise SubagentBlockedError("a granted read-only tool is unavailable")
        return registry

    async def run(self, grant: SubagentGrant) -> Mapping[str, Any]:
        if self.provider.is_live:
            raise SubagentBlockedError("LIVE SUBAGENT NOT VERIFIED: live model delegation is disabled")
        from .gateway import LocalToolGateway
        from .orchestrator import AsterCodeOrchestrator
        from .policy import PolicyEngine

        registry = self._registry(grant)
        security = self.config.security.model_copy(
            update={
                "authorized_roots": [grant.workspace],
                "subagents": self.config.security.subagents.model_copy(update={"enabled": False}),
            }
        )
        child_config = self.config.model_copy(update={"project_root": grant.workspace, "security": security})
        gateway = LocalToolGateway(registry, PolicyEngine(child_config, self.storage), self.storage)
        core = AsterCodeOrchestrator(
            self.provider,
            gateway,
            tools=self._model_specs(registry),
            max_model_result_chars=8_192,
            max_model_context_chars=16_384,
            max_tool_retries=0,
        )
        child = self.storage.create_session(str(grant.workspace), str(redact_secrets(grant.task)))
        child_session_id = str(child["session_id"])
        turn_id = self.storage.save_turn(child_session_id, "user", str(redact_secrets(grant.task)))
        initial = core.initial_state(
            str(redact_secrets(grant.task)),
            session_id=child_session_id,
            turn_id=turn_id,
            budget={
                "max_rounds": max(2, grant.budget.max_tool_calls + 1),
                "max_tool_calls": grant.budget.max_tool_calls,
                "max_tokens": grant.budget.max_tokens,
                "max_input_tokens": grant.budget.max_tokens,
                "max_output_tokens": grant.budget.max_tokens,
                "max_elapsed_seconds": grant.budget.max_elapsed_seconds,
                "max_concurrency": 1,
            },
        )
        initial["assumptions"] = [
            f"parent_session_id={grant.parent_session_id}",
            f"grant_id={grant.grant_id}",
            "read_only_child=true",
        ]
        self.storage.update_session(child_session_id, status=SessionStatus.RUNNING, state=initial)
        self.storage.save_checkpoint(
            {
                "session_id": child_session_id,
                "turn_id": turn_id,
                "phase": "SUBAGENT_RESERVED",
                "state": {
                    "parent_session_id": grant.parent_session_id,
                    "grant_id": grant.grant_id,
                    "binding_hash": grant.binding_hash,
                    "budget": grant.budget.model_dump(mode="json"),
                    "allowed_tools": sorted(grant.allowed_tools),
                    "read_only": True,
                },
            }
        )
        child_task = asyncio.create_task(
            core.run(initial), name=f"astercode-{grant.grant_id}"
        )
        async with self._active_lock:
            self._active[grant.grant_id] = _ActiveChild(
                parent_session_id=grant.parent_session_id,
                child_session_id=child_session_id,
                core=core,
                task=child_task,
            )
        try:
            result = await asyncio.wait_for(
                child_task, timeout=grant.budget.max_elapsed_seconds
            )
            usage = result.get("usage", {})
            if (
                int(usage.get("tool_calls", 0)) > grant.budget.max_tool_calls
                or int(usage.get("total_tokens", 0)) > grant.budget.max_tokens
            ):
                raise SubagentBlockedError("child result exceeded its bound grant")
            status = str(result.get("status", SessionStatus.FAILED.value))
            self.storage.update_session(child_session_id, status=status, state=result)
            checkpoint_phase = (
                "SUBAGENT_COMPLETED"
                if status == SessionStatus.COMPLETED.value
                else f"SUBAGENT_{status.upper()}"
            )
            self.storage.save_checkpoint(
                {
                    "session_id": child_session_id,
                    "turn_id": result.get("turn_id", turn_id),
                    "phase": checkpoint_phase,
                    "state": {
                        "parent_session_id": grant.parent_session_id,
                        "grant_id": grant.grant_id,
                        "binding_hash": grant.binding_hash,
                        "status": status,
                        "usage": usage,
                        "read_only": True,
                    },
                }
            )
            messages = result.get("messages", [])
            summary = str(messages[-1]) if isinstance(messages, list) and messages else ""
            tool_results = result.get("tool_results", [])
            evidence = [
                {
                    "tool": item.get("tool"),
                    "call_id": item.get("call_id"),
                    "action_id": item.get("action_id"),
                    "status": item.get("status"),
                }
                for item in tool_results
                if isinstance(item, Mapping)
            ]
            return {
                "grant_id": grant.grant_id,
                "binding_hash": grant.binding_hash,
                "parent_session_id": grant.parent_session_id,
                "child_session_id": child_session_id,
                "status": status,
                "summary": str(redact_secrets(summary))[:16_384],
                "usage": usage,
                "evidence": evidence,
                "read_only": True,
            }
        except asyncio.CancelledError:
            if not child_task.done():
                child_task.cancel()
            await asyncio.gather(child_task, return_exceptions=True)
            await core.cancel(child_session_id)
            self.storage.update_session(child_session_id, status=SessionStatus.CANCELLED)
            self.storage.save_checkpoint(
                {
                    "session_id": child_session_id,
                    "turn_id": turn_id,
                    "phase": "SUBAGENT_CANCELLED",
                    "state": {
                        "parent_session_id": grant.parent_session_id,
                        "grant_id": grant.grant_id,
                        "budget": grant.budget.model_dump(mode="json"),
                        "status": SessionStatus.CANCELLED.value,
                        "read_only": True,
                    },
                }
            )
            raise
        except TimeoutError as exc:
            await asyncio.gather(child_task, return_exceptions=True)
            await core.cancel(child_session_id)
            self.storage.update_session(child_session_id, status=SessionStatus.FAILED)
            self.storage.save_checkpoint(
                {
                    "session_id": child_session_id,
                    "turn_id": turn_id,
                    "phase": "SUBAGENT_TIMEOUT",
                    "state": {
                        "parent_session_id": grant.parent_session_id,
                        "grant_id": grant.grant_id,
                        "budget": grant.budget.model_dump(mode="json"),
                        "status": "timeout",
                        "read_only": True,
                    },
                }
            )
            raise SubagentBlockedError("offline child exceeded its elapsed-time budget") from exc
        except Exception:
            if not child_task.done():
                child_task.cancel()
            await asyncio.gather(child_task, return_exceptions=True)
            self.storage.update_session(child_session_id, status=SessionStatus.FAILED)
            self.storage.save_checkpoint(
                {
                    "session_id": child_session_id,
                    "turn_id": turn_id,
                    "phase": "SUBAGENT_FAILED",
                    "state": {
                        "parent_session_id": grant.parent_session_id,
                        "grant_id": grant.grant_id,
                        "budget": grant.budget.model_dump(mode="json"),
                        "status": SessionStatus.FAILED.value,
                        "read_only": True,
                    },
                }
            )
            raise
        finally:
            async with self._active_lock:
                self._active.pop(grant.grant_id, None)

    async def cancel(self, grant_id: str) -> None:
        async with self._active_lock:
            item = self._active.get(grant_id)
        if item is not None:
            await self._cancel_items([item])

    async def cancel_parent(self, parent_session_id: str) -> None:
        async with self._active_lock:
            items = [
                item
                for item in self._active.values()
                if item.parent_session_id == parent_session_id
            ]
        await self._cancel_items(items)

    async def cancel_all(self) -> None:
        async with self._active_lock:
            items = list(self._active.values())
        await self._cancel_items(items)

    @staticmethod
    async def _cancel_items(items: Sequence[_ActiveChild]) -> None:
        for item in items:
            if not item.task.done():
                item.task.cancel()
        if items:
            await asyncio.gather(
                *(item.task for item in items), return_exceptions=True
            )
        for item in items:
            await item.core.cancel(item.child_session_id)


@dataclass(slots=True)
class _BoundParentAuthority:
    authority: ParentAuthority
    started_at_monotonic: float = field(default_factory=time.monotonic)
    recovered_tool_calls: int = 0
    recovered_tokens: int = 0
    recovered_elapsed_seconds: float = 0.0
    used_tool_calls: int = 0
    used_tokens: int = 0
    elapsed_seconds: float = 0.0

    def current(self) -> ParentAuthority:
        base = self.authority.remaining_budget
        tool_calls = base.max_tool_calls - self.recovered_tool_calls - self.used_tool_calls
        tokens = base.max_tokens - self.recovered_tokens - self.used_tokens
        elapsed = (
            base.max_elapsed_seconds
            - self.recovered_elapsed_seconds
            - self.elapsed_seconds
        )
        if tool_calls < 1 or tokens < 1 or elapsed <= 0:
            raise SubagentBlockedError("parent remaining budget cannot fund another child")
        return self.authority.model_copy(
            update={
                "remaining_budget": SubagentBudget(
                    max_tool_calls=tool_calls,
                    max_tokens=tokens,
                    max_elapsed_seconds=elapsed,
                )
            },
            deep=True,
        )


_PARENT_AUTHORITY: ContextVar[_BoundParentAuthority | None] = ContextVar(
    "astercode_subagent_parent_authority", default=None
)


def bind_parent_authority(
    authority: ParentAuthority,
    *,
    recovered_tool_calls: int = 0,
    recovered_tokens: int = 0,
    recovered_elapsed_seconds: float = 0.0,
) -> Token[_BoundParentAuthority | None]:
    return _PARENT_AUTHORITY.set(
        _BoundParentAuthority(
            authority=authority,
            recovered_tool_calls=max(0, recovered_tool_calls),
            recovered_tokens=max(0, recovered_tokens),
            recovered_elapsed_seconds=max(0.0, recovered_elapsed_seconds),
        )
    )


def update_parent_authority_usage(
    usage: Mapping[str, Any], *, started_at_monotonic: float | None = None
) -> None:
    binding = _PARENT_AUTHORITY.get()
    if binding is None:
        return
    binding.used_tool_calls = max(0, int(usage.get("tool_calls", 0)))
    binding.used_tokens = max(0, int(usage.get("total_tokens", 0)))
    started = (
        started_at_monotonic
        if started_at_monotonic is not None
        else binding.started_at_monotonic
    )
    binding.elapsed_seconds = max(0.0, time.monotonic() - started)


def reset_parent_authority(token: Token[_BoundParentAuthority | None]) -> None:
    _PARENT_AUTHORITY.reset(token)


class SubagentResearchTools:
    """Structured host tool exposing exactly one read-only delegation action."""

    specs = (
        ToolSpec(
            "subagent.research",
            "Run one offline, read-only child agent inside a narrowed workspace.",
            "subagent.read_only.offline",
            risk="P0",
            timeout_seconds=900,
            max_output=20_000,
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "task": {"type": "string", "minLength": 1, "maxLength": 16384},
                    "workspace": {"type": "string", "minLength": 1},
                    "requested_tools": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"type": "string", "enum": sorted(READ_ONLY_TOOLS)},
                    },
                    "budget": {
                        "type": "object",
                        "properties": {
                            "max_tool_calls": {"type": "integer", "minimum": 1, "maximum": 1000},
                            "max_tokens": {"type": "integer", "minimum": 1, "maximum": 10000000},
                            "max_elapsed_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": 86400},
                        },
                        "required": ["max_tool_calls", "max_tokens", "max_elapsed_seconds"],
                        "additionalProperties": False,
                    },
                },
                "required": ["task", "workspace", "requested_tools", "budget"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(self, policy: ReadOnlySubagentPolicy, runner: SubagentRunner) -> None:
        self.policy = policy
        self.runner = runner

    async def research(
        self,
        task: str,
        workspace: str,
        requested_tools: Sequence[str],
        budget: Mapping[str, Any],
    ) -> ToolResult:
        arguments = {
            "task": task,
            "workspace": workspace,
            "requested_tools": list(requested_tools),
            "budget": dict(budget),
        }
        result = timed_result(
            "subagent.research", new_action_id("subagent.research", arguments), workspace
        )
        grant: SubagentGrant | None = None
        try:
            binding = _PARENT_AUTHORITY.get()
            if binding is None:
                raise SubagentBlockedError("subagent tool requires a host-bound parent authority")
            authority = binding.current()
            request = SubagentRequest(
                task=task,
                workspace=Path(workspace),
                requested_tools=frozenset(requested_tools),
                budget=SubagentBudget.model_validate(budget),
            )
            grant = self.policy.grant(authority, request)
            self.policy.assert_active(grant)
            result.metadata = {
                "grant_id": grant.grant_id,
                "binding_hash": grant.binding_hash,
                "child_session_id": None,
                "budget": grant.budget.model_dump(mode="json"),
                "child_usage_charge": {
                    "rounds": grant.budget.max_tool_calls + 1,
                    "tool_calls": grant.budget.max_tool_calls,
                    "input_tokens": grant.budget.max_tokens,
                    "output_tokens": 0,
                    "total_tokens": grant.budget.max_tokens,
                    "cost_usd": None,
                },
                "read_only": True,
            }
            raw = self.runner.run(grant)
            if inspect.isawaitable(raw):
                raw = await raw
            safe = redact_secrets(dict(raw) if isinstance(raw, Mapping) else {"summary": str(raw)})
            result.stdout = json.dumps(safe, ensure_ascii=False, sort_keys=True)
            child_status = (
                str(safe.get("status", SessionStatus.COMPLETED.value))
                if isinstance(safe, Mapping)
                else SessionStatus.COMPLETED.value
            )
            child_usage = safe.get("usage", {}) if isinstance(safe, Mapping) else {}
            if isinstance(safe, Mapping) and not isinstance(child_usage, Mapping):
                child_usage = {}
            if isinstance(safe, Mapping) and not child_usage:
                # Contract fakes historically returned flat counters. Treat
                # them as trusted child accounting rather than silently
                # charging zero and allowing sequential budget reuse.
                flat_tokens = max(0, int(safe.get("tokens", 0)))
                child_usage = {
                    "rounds": 1,
                    "tool_calls": max(0, int(safe.get("tool_calls", 0))),
                    "input_tokens": flat_tokens,
                    "output_tokens": 0,
                    "total_tokens": flat_tokens,
                    "cost_usd": 0.0,
                }
            if (
                child_status == SessionStatus.COMPLETED.value
                and isinstance(child_usage, Mapping)
            ):
                result.metadata["child_usage_charge"] = {
                    "rounds": max(0, int(child_usage.get("rounds", 0))),
                    "tool_calls": min(
                        grant.budget.max_tool_calls,
                        max(0, int(child_usage.get("tool_calls", 0))),
                    ),
                    "input_tokens": max(0, int(child_usage.get("input_tokens", 0))),
                    "output_tokens": max(0, int(child_usage.get("output_tokens", 0))),
                    "total_tokens": min(
                        grant.budget.max_tokens,
                        max(0, int(child_usage.get("total_tokens", 0))),
                    ),
                    "cost_usd": child_usage.get("cost_usd"),
                }
            result.metadata = {
                **result.metadata,
                "grant_id": grant.grant_id,
                "binding_hash": grant.binding_hash,
                "child_session_id": safe.get("child_session_id") if isinstance(safe, Mapping) else None,
                "budget": grant.budget.model_dump(mode="json"),
                "read_only": True,
            }
            if child_status != SessionStatus.COMPLETED.value:
                result.status = "failed"
                result.error = f"child session ended with status {child_status}"
        except asyncio.CancelledError:
            if grant is not None:
                cancel = getattr(self.runner, "cancel", None)
                if cancel is not None:
                    value = cancel(grant.grant_id)
                    if inspect.isawaitable(value):
                        await value
            raise
        except Exception as exc:
            result.status = "failed"
            result.error = str(redact_secrets(f"subagent blocked ({type(exc).__name__}): {exc}"))
        finally:
            if grant is not None:
                self.policy.release(grant.grant_id)
        return result.finish().bounded(20_000, lambda value: str(redact_secrets(value)))

    async def stop_all(self) -> None:
        cancel_all = getattr(self.runner, "cancel_all", None)
        if cancel_all is not None:
            value = cancel_all()
            if inspect.isawaitable(value):
                await value

    async def stop_session(self, parent_session_id: str) -> None:
        cancel_parent = getattr(self.runner, "cancel_parent", None)
        if cancel_parent is not None:
            value = cancel_parent(parent_session_id)
            if inspect.isawaitable(value):
                await value


def make_parent_authority(
    *,
    authorized_roots: Sequence[str | Path],
    allowed_tools: Sequence[str],
    remaining_budget: SubagentBudget,
    parent_session_id: str = "offline-parent",
    authority_id: str | None = None,
    depth: int = 0,
    max_depth: int = 1,
    max_concurrency: int = 1,
    active_children: int = 0,
) -> ParentAuthority:
    values: dict[str, Any] = {
        "parent_session_id": parent_session_id,
        "authorized_roots": tuple(Path(item) for item in authorized_roots),
        "allowed_tools": frozenset(allowed_tools),
        "remaining_budget": remaining_budget,
        "depth": depth,
        "max_depth": max_depth,
        "max_concurrency": max_concurrency,
        "active_children": active_children,
    }
    if authority_id is not None:
        values["authority_id"] = authority_id
    return ParentAuthority.model_validate(values)


__all__ = [
    "BlockedSubagentRunner",
    "DeterministicFakeSubagentRunner",
    "OfflineReadOnlyAgentRunner",
    "ParentAuthority",
    "READ_ONLY_TOOLS",
    "ReadOnlySubagentPolicy",
    "SubagentBlockedError",
    "SubagentBudget",
    "SubagentGrant",
    "SubagentRequest",
    "SubagentResearchTools",
    "SubagentRunner",
    "bind_parent_authority",
    "make_parent_authority",
    "reset_parent_authority",
]
