"""Application assembly: configuration -> policy -> gateway -> LangGraph."""

from __future__ import annotations

import asyncio
import inspect
import math
from typing import Any, Callable, Literal, Mapping, cast

from .config import AppConfig, SandboxBackend
from .extensions import ExtensionKind, ExtensionRegistry, MCPTools, PluginTools
from .gateway import LocalToolGateway
from .models import RiskLevel, SessionStatus, ToolSpec
from .orchestrator import AsterCodeOrchestrator
from .policy import PolicyEngine, RuntimePolicyCapabilities
from .provider import (
    DeepSeekChatProvider,
    DeterministicFakeProvider,
    OpenAIAgentsProvider,
    Provider,
    ProviderConfigurationError,
)
from .security import redact_secrets
from .storage import Storage
from .subagents import (
    READ_ONLY_TOOLS,
    BlockedSubagentRunner,
    OfflineReadOnlyAgentRunner,
    ReadOnlySubagentPolicy,
    SubagentBudget,
    SubagentResearchTools,
    bind_parent_authority,
    make_parent_authority,
    reset_parent_authority,
)
from .tools.browser import BrowserBackend, BrowserTools
from .tools.desktop import NativeDesktopTools
from .tools.docker_process import (
    DockerProcessTools,
    DockerSandboxAttestation,
    DockerSandboxUnavailable,
    attest_docker_sandbox,
)
from .tools.filesystem import FilesystemTools
from .tools.git import GitTools
from .tools.openssh import OpenSSHBackend
from .tools.playwright_browser import PlaywrightEdgeBackend
from .tools.process import ProcessTools
from .tools.registry import ToolRegistry
from .tools.ssh import SSHTools


def _clamp_persisted_budget(
    configured: Mapping[str, Any],
    stored: Mapping[str, Any],
) -> dict[str, Any]:
    """Restore only valid limits that are no wider than current policy."""

    integer_fields = {
        "max_rounds",
        "max_tool_calls",
        "max_tokens",
        "max_input_tokens",
        "max_output_tokens",
        "max_concurrency",
    }
    result: dict[str, Any] = {}
    for key, ceiling in configured.items():
        candidate = stored.get(key)
        if candidate is None:
            result[key] = ceiling
            continue
        if key in integer_fields:
            valid = isinstance(candidate, int) and not isinstance(candidate, bool)
        else:
            valid = (
                isinstance(candidate, (int, float))
                and not isinstance(candidate, bool)
                and math.isfinite(float(candidate))
            )
        if not valid or candidate <= 0:
            result[key] = ceiling
        elif ceiling is None:
            result[key] = candidate
        else:
            result[key] = min(ceiling, candidate)
    return result


def build_registry(
    config: AppConfig,
    *,
    verified_process_sandbox: bool = False,
    verified_process_network_policy: bool = False,
    verified_ssh_network_policy: bool = False,
    verified_browser_network_policy: bool = False,
    browser_backend: BrowserBackend | None = None,
    docker_attestation: DockerSandboxAttestation | None = None,
) -> ToolRegistry:
    """Build host tools from configuration plus runtime-attested boundaries.

    The two ``verified_*`` values are dependency-injection points for a host
    adapter (and deterministic tests), not user configuration.  Normal CLI
    assembly leaves both false until an OS backend has actually probed and
    attested its filesystem/process and network isolation.
    """

    registry = ToolRegistry()
    registry.register_provider(FilesystemTools(config.security.authorized_roots))
    registry.register_provider(GitTools(config.security.authorized_roots))
    process = config.security.process
    process_tools: ProcessTools
    if (
        process.sandbox_backend is SandboxBackend.CONTAINER
        and not (verified_process_sandbox or verified_process_network_policy)
    ):
        try:
            attestation = docker_attestation or attest_docker_sandbox(
                configured_image=process.container_image,
                user=process.container_user,
                max_processes=process.max_processes,
                max_memory_bytes=process.max_memory_bytes,
                cpus=process.container_cpus,
                tmpfs_bytes=process.container_tmpfs_bytes,
                workspace_bytes=process.container_workspace_bytes,
            )
        except DockerSandboxUnavailable:
            # Configuration intent never widens authority.  Keep the existing
            # fail-closed host executor so policy and execution both refuse.
            process_tools = ProcessTools(
                config.security.authorized_roots,
                network_mode=config.security.network_mode.value,
                max_output=process.max_output_bytes,
                clean_path=process.clean_path,
                sandbox_enforced=False,
                network_policy_enforced=False,
                max_processes=process.max_processes,
                max_memory_bytes=process.max_memory_bytes,
                max_cpu_time_seconds=process.max_cpu_time_seconds,
                max_timeout=process.max_timeout_seconds,
            )
        else:
            process_tools = DockerProcessTools(
                config.security.authorized_roots,
                attestation=attestation,
                container_user=process.container_user,
                container_cpus=process.container_cpus,
                container_tmpfs_bytes=process.container_tmpfs_bytes,
                container_workspace_bytes=process.container_workspace_bytes,
                artifacts_dir=config.storage.artifacts_dir,
                artifact_max_bytes=config.security.artifact_max_bytes,
                network_mode=config.security.network_mode.value,
                max_output=process.max_output_bytes,
                max_processes=process.max_processes,
                max_memory_bytes=process.max_memory_bytes,
                max_cpu_time_seconds=process.max_cpu_time_seconds,
                max_timeout=process.max_timeout_seconds,
            )
    else:
        process_tools = ProcessTools(
            config.security.authorized_roots,
            network_mode=config.security.network_mode.value,
            max_output=process.max_output_bytes,
            clean_path=process.clean_path,
            sandbox_enforced=verified_process_sandbox,
            network_policy_enforced=verified_process_network_policy,
            max_processes=process.max_processes,
            max_memory_bytes=process.max_memory_bytes,
            max_cpu_time_seconds=process.max_cpu_time_seconds,
            max_timeout=process.max_timeout_seconds,
        )
    registry.register_provider(process_tools)
    # Configuration intent alone never opens SSH.  A trusted host adapter must
    # separately attest that its network boundary is restricted to the exact
    # configured targets before the system OpenSSH transport is assembled.
    ssh_backend = None
    if config.security.ssh.enabled and verified_ssh_network_policy:
        ssh_backend = OpenSSHBackend(
            connect_timeout=config.security.ssh.connect_timeout_seconds
        )
    registry.register_provider(
        SSHTools(
            config.security.authorized_ssh_hosts,
            config.security.authorized_roots,
            backend=ssh_backend,
        )
    )
    if config.features.browser_automation:
        if browser_backend is None and config.security.browser.engine == "playwright_edge":
            browser_backend = PlaywrightEdgeBackend()
        registry.register_provider(
            BrowserTools(
                enabled=config.security.browser.enabled,
                allowlist=config.security.browser.allowed_domains,
                max_redirects=config.security.browser.max_redirects,
                backend=browser_backend,
                network_egress_enforced=verified_browser_network_policy,
            )
        )
    if config.features.native_desktop_gui:
        registry.register_provider(NativeDesktopTools(enabled=True))
    extension_settings = config.security.extensions
    if extension_settings.mcp_enabled:
        mcp_registry = ExtensionRegistry(
            ExtensionKind.MCP,
            [pin.model_dump(mode="json") for pin in extension_settings.mcp_pins],
            authorized_roots=config.security.authorized_roots,
            enabled=True,
        )
        registry.register_provider(MCPTools(mcp_registry))
    if extension_settings.plugins_enabled:
        plugin_registry = ExtensionRegistry(
            ExtensionKind.PLUGIN,
            [pin.model_dump(mode="json") for pin in extension_settings.plugin_pins],
            authorized_roots=config.security.authorized_roots,
            enabled=True,
        )
        registry.register_provider(PluginTools(plugin_registry))
    return registry


def _model_specs(registry: ToolRegistry) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for item in registry.specs():
        if isinstance(item, ToolSpec):
            specs.append(item); continue
        risk = str(getattr(item, "risk", "P0"))
        if risk.startswith("RiskLevel."): risk = risk.split(".")[-1]
        specs.append(ToolSpec(name=item.name, capability=getattr(item, "capability", "unknown"), description=getattr(item, "description", ""), input_schema=getattr(item, "schema", {}), side_effects=list(getattr(item, "side_effects", ())), risk=RiskLevel(risk), timeout=float(getattr(item, "timeout_seconds", 30)), max_output=int(getattr(item, "max_output", 32_000)), idempotent=bool(getattr(item, "idempotent", False))))
    return specs


def _policy_capabilities(registry: ToolRegistry) -> RuntimePolicyCapabilities:
    """Derive policy evidence from the concrete trusted executor instance."""

    process_sandbox_enforced = False
    process_network_policy_enforced = False
    browser_profile_isolated = False
    browser_network_policy_enforced = False
    for provider in registry.providers():
        if isinstance(provider, ProcessTools):
            process_sandbox_enforced = provider.sandbox_enforced
            process_network_policy_enforced = provider.network_policy_enforced
        elif isinstance(provider, BrowserTools):
            browser_profile_isolated = provider.profile_isolated
            browser_network_policy_enforced = provider.network_egress_enforced
    return RuntimePolicyCapabilities(
        process_sandbox_enforced=process_sandbox_enforced,
        process_network_policy_enforced=process_network_policy_enforced,
        browser_profile_isolated=browser_profile_isolated,
        browser_network_policy_enforced=browser_network_policy_enforced,
    )


def _provider_from_config(config: AppConfig) -> Provider:
    """Select one explicit provider without cross-using credentials."""

    model = config.model
    if model.provider == "fake":
        return DeterministicFakeProvider()
    if model.provider == "deepseek":
        return DeepSeekChatProvider(
            model_id=model.model_id,
            api_key_env=model.api_key_env,
            base_url=model.base_url or DeepSeekChatProvider.OFFICIAL_BASE_URL,
            timeout_seconds=model.timeout_seconds,
            max_retries=model.max_retries,
            max_output_tokens=model.decision_max_tokens,
            reasoning_effort=model.reasoning,
        )
    if not config.live_provider_requested:
        # Preserve the original no-key offline default for OpenAI. DeepSeek is
        # never the implicit default, so selecting it above must fail closed
        # on missing model/key rather than silently pretending to be live.
        return DeterministicFakeProvider()
    if model.provider == "openai":
        reasoning = cast(
            Literal["none", "minimal", "low", "medium", "high"] | None,
            model.reasoning
            if model.reasoning in {"none", "minimal", "low", "medium", "high"}
            else None,
        )
        verbosity = cast(
            Literal["low", "medium", "high"] | None,
            model.verbosity if model.verbosity in {"low", "medium", "high"} else None,
        )
        return OpenAIAgentsProvider(
            model_id=model.model_id,
            api_key_env=model.api_key_env,
            timeout_seconds=model.timeout_seconds,
            reasoning_effort=reasoning,
            verbosity=verbosity,
        )
    raise ProviderConfigurationError(f"unsupported provider: {model.provider}")


class Orchestrator:
    """User-facing facade around the explicit LangGraph state machine."""

    def __init__(self, config: AppConfig, *, provider: Provider | None = None, registry: ToolRegistry | None = None, storage: Storage | None = None, auto_approve: bool = False, dry_run: bool = False, event_sink: Callable[[Mapping[str, Any]], Any] | None = None) -> None:
        self.config = config
        self.storage = storage or Storage(config.storage)
        self.storage.initialize()
        self.registry = registry or build_registry(config)
        if provider is None:
            provider = _provider_from_config(config)
        self.provider = provider
        self.subagents_enabled = bool(
            config.features.multi_agent and config.security.subagents.enabled
        )
        self.subagent_policy = ReadOnlySubagentPolicy(
            enabled=self.subagents_enabled
        )
        self.subagent_tools: SubagentResearchTools | None = None
        if self.subagents_enabled:
            runner = (
                BlockedSubagentRunner()
                if provider.is_live
                else OfflineReadOnlyAgentRunner(config, self.storage, provider)
            )
            self.subagent_tools = SubagentResearchTools(self.subagent_policy, runner)
            if "subagent.research" not in {spec.name for spec in self.registry.specs()}:
                self.registry.register_provider(self.subagent_tools)
        self.policy = PolicyEngine(
            config,
            self.storage,
            runtime_capabilities=_policy_capabilities(self.registry),
        )
        self.gateway = LocalToolGateway(self.registry, self.policy, self.storage, auto_approve=auto_approve, dry_run=dry_run)
        self.event_sink = event_sink
        self.core: AsterCodeOrchestrator | None = None
        self._checkpoint_connection: Any | None = None
        self._checkpointer: Any | None = None

    async def _ensure_core(self) -> AsterCodeOrchestrator:
        if self.core is not None:
            return self.core
        # Async nodes require AsyncSqliteSaver; the synchronous saver raises at
        # runtime when LangGraph calls aget_tuple().
        import aiosqlite
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        checkpoint_path = self.config.storage.database_path.with_name("langgraph-checkpoints.db")
        self.storage.guard_sqlite_path(checkpoint_path)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self._checkpoint_connection = await aiosqlite.connect(str(checkpoint_path))
        self._checkpointer = AsyncSqliteSaver(self._checkpoint_connection)
        await self._checkpointer.setup()
        self.core = AsterCodeOrchestrator(
            self.provider,
            self.gateway,
            tools=_model_specs(self.registry),
            checkpointer=self._checkpointer,
            max_model_result_chars=8_192,
            max_model_context_chars=24_576,
            max_tool_retries=self.config.model.max_retries,
            # Model-structure retries are separate from transport/tool retry
            # settings and are hard-capped to one attempt per decision.
            max_provider_retries=min(self.config.model.max_retries, 1),
            memory_lookup=lambda query: self.storage.search_memory(query, limit=8),
            event_sink=self._record_stream_event,
        )
        return self.core

    async def _record_stream_event(self, event: Mapping[str, Any]) -> None:
        session_id = str(event.get("session_id", ""))
        event_name = str(event.get("event", "stream.event"))
        if session_id:
            self.storage.save_event(session_id, event_name, dict(event))
        if self.event_sink is not None:
            value = self.event_sink(event)
            if inspect.isawaitable(value):
                await value

    async def run(self, goal: str, *, session_id: str | None = None, budget: Mapping[str, Any] | None = None) -> dict[str, Any]:
        safe_goal = str(redact_secrets(goal))
        session = self.storage.create_session(str(self.config.project_root), safe_goal, session_id=session_id) if session_id is None else self.storage.get_session(session_id)
        sid = session["session_id"]
        stored_state = session.get("state", {})
        if session_id is not None and str(session.get("status")) == SessionStatus.WAITING_APPROVAL.value:
            # A natural-language message is never an approval.  Preserve the
            # exact interrupt so the terminal UI can collect a bound decision.
            if isinstance(stored_state, Mapping):
                return dict(stored_state)
            return {
                "session_id": sid,
                "status": SessionStatus.WAITING_APPROVAL.value,
                "blockers": ["the session has an unresolved approval request"],
                "next_action": "approve, deny, or leave the exact request pending",
            }
        terminal_statuses = {
            SessionStatus.COMPLETED.value,
            SessionStatus.PARTIAL.value,
            SessionStatus.BLOCKED.value,
            SessionStatus.CANCELLED.value,
            SessionStatus.FAILED.value,
        }
        checkpoint = self.storage.latest_checkpoint(sid) if session_id is not None else None
        checkpoint_phase = (
            str(checkpoint.get("phase", "")).upper()
            if isinstance(checkpoint, Mapping)
            else ""
        )
        unresolved_boundary = checkpoint_phase in {"PRE_TOOL_CALL", "TOOL_CALL"}
        if session_id is not None and (
            str(session.get("status")) not in terminal_statuses or unresolved_boundary
        ):
            reconciled = self.reconcile(sid)
            reconciled["blockers"] = [
                *reconciled.get("blockers", []),
                "the existing session is non-terminal or has an unresolved action boundary; natural language cannot resume or overwrite it",
            ]
            return reconciled
        turn_id = self.storage.save_turn(sid, "user", safe_goal)
        core = await self._ensure_core()
        configured_budget: dict[str, Any] = {
            "max_rounds": self.config.budget.max_rounds,
            "max_tool_calls": self.config.budget.max_tool_calls,
            "max_tokens": self.config.budget.max_tokens,
            "max_elapsed_seconds": self.config.budget.max_elapsed_seconds,
            "max_input_tokens": self.config.budget.max_input_tokens,
            "max_output_tokens": self.config.budget.max_output_tokens,
            "max_cost_usd": self.config.budget.max_cost_usd,
            "max_concurrency": self.config.budget.max_concurrency,
        }
        if budget is not None:
            configured_budget.update(dict(budget))
        state = core.initial_state(
            safe_goal,
            session_id=sid,
            turn_id=turn_id,
            budget=configured_budget,
        )
        conversation: list[dict[str, str]] = []
        prior_action_denied = False
        if session_id is not None and isinstance(stored_state, Mapping):
            raw_approvals = stored_state.get("approvals", [])
            if isinstance(raw_approvals, list):
                prior_action_denied = any(
                    isinstance(item, Mapping) and item.get("approved") is False
                    for item in raw_approvals
                )
        if (
            session_id is not None
            and isinstance(stored_state, Mapping)
            and not prior_action_denied
        ):
            raw_conversation = stored_state.get("conversation", [])
            if isinstance(raw_conversation, list):
                for item in raw_conversation[-14:]:
                    if not isinstance(item, Mapping):
                        continue
                    role = str(item.get("role", ""))
                    if role not in {"user", "assistant"}:
                        continue
                    content = str(redact_secrets(str(item.get("content", ""))))[:4_000]
                    if content:
                        conversation.append({"role": role, "content": content})
        # A denied action closes that task's authority boundary. The next
        # natural-language turn starts from its own current instruction rather
        # than letting the model reinterpret the rejected historical request
        # as continuing authorization. Users can explicitly restate the task
        # (or start /new) if they genuinely want to try again.
        conversation.append({"role": "user", "content": safe_goal[:4_000]})
        state["conversation"] = conversation[-15:]
        # Persist a useful in-flight state before the first provider request.
        # Without this, a long reasoning call appears permanently "created"
        # to `status` even though the agent is actively running.
        persisted_state = dict(state)
        persisted_state["status"] = SessionStatus.RUNNING.value
        self.storage.update_session(
            sid,
            status=SessionStatus.RUNNING,
            state=persisted_state,
        )
        authority_token = self._bind_subagent_context(sid, configured_budget)
        try:
            try:
                result = await core.run(state)
            except asyncio.CancelledError:
                result = await core.cancel(sid)
        finally:
            reset_parent_authority(authority_token)
        self._persist_result(result)
        return result

    def _bind_subagent_context(
        self, session_id: str, configured_budget: Mapping[str, Any]
    ) -> Any:
        subagent_settings = self.config.security.subagents
        parent_max_tokens = configured_budget.get("max_tokens")
        parent_authority = make_parent_authority(
            parent_session_id=session_id,
            authority_id=f"subauth_{session_id}",
            authorized_roots=self.config.security.authorized_roots,
            allowed_tools=sorted(
                READ_ONLY_TOOLS.intersection(
                    {spec.name for spec in self.registry.specs()}
                )
            ),
            remaining_budget=SubagentBudget(
                max_tool_calls=min(
                    subagent_settings.max_tool_calls,
                    int(configured_budget["max_tool_calls"]),
                ),
                max_tokens=min(
                    subagent_settings.max_tokens,
                    int(parent_max_tokens)
                    if parent_max_tokens is not None
                    else subagent_settings.max_tokens,
                ),
                max_elapsed_seconds=min(
                    subagent_settings.max_elapsed_seconds,
                    float(configured_budget["max_elapsed_seconds"]),
                ),
            ),
            max_depth=subagent_settings.max_depth,
            max_concurrency=min(
                subagent_settings.max_concurrency,
                int(configured_budget["max_concurrency"]),
            ),
        )
        recovered = self.storage.list_subagent_reservations(session_id)
        recovered_tool_calls = 0
        recovered_tokens = 0
        recovered_elapsed = 0.0
        for item in recovered:
            budget = item.get("budget", {})
            if not isinstance(budget, Mapping):
                continue
            recovered_tool_calls += max(0, int(budget.get("max_tool_calls", 0)))
            recovered_tokens += max(0, int(budget.get("max_tokens", 0)))
            recovered_elapsed += max(
                0.0, float(budget.get("max_elapsed_seconds", 0.0))
            )
        return bind_parent_authority(
            parent_authority,
            recovered_tool_calls=recovered_tool_calls,
            recovered_tokens=recovered_tokens,
            recovered_elapsed_seconds=recovered_elapsed,
        )

    async def cancel(self, session_id: str) -> dict[str, Any]:
        core = await self._ensure_core()
        result = await core.cancel(session_id)
        self._persist_result(result)
        return result

    def reconcile(self, session_id: str) -> dict[str, Any]:
        """Read-only reconciliation for a crash-interrupted local action."""

        from .tools.process import ProcessTools

        session = self.storage.get_session(session_id)
        checkpoint = self.storage.latest_checkpoint(session_id)
        if checkpoint is None:
            return {
                "session_id": session_id,
                "status": SessionStatus.BLOCKED.value,
                "reconcile": {"state": "no_checkpoint"},
                "next_action": "inspect the session manually",
            }
        state = checkpoint.get("state", {}) if isinstance(checkpoint.get("state"), Mapping) else {}
        pre = state.get("pre_evidence", []) if isinstance(state, Mapping) else []
        paths = [item.get("path") for item in pre if isinstance(item, Mapping) and isinstance(item.get("path"), str)]
        current = self.gateway._path_evidence(paths)
        process_evidence: list[dict[str, Any]] = []
        for record in self.storage.list_active_processes(session_id=session_id):
            observed = ProcessTools.process_identity(int(record["pid"]))
            expected = record.get("identity_token")
            process_evidence.append(
                {
                    "action_id": record["action_id"],
                    "pid": record["pid"],
                    "expected_identity": expected,
                    "observed_identity": observed,
                    "same_process_running": bool(expected and observed == expected),
                }
            )
        changed = pre != current if pre else None
        phase = str(checkpoint.get("phase", "unknown"))
        uncertain = phase == "PRE_TOOL_CALL" or bool(process_evidence)
        return {
            "session_id": session_id,
            "status": SessionStatus.BLOCKED.value if uncertain else str(session.get("status", SessionStatus.BLOCKED.value)),
            "reconcile": {
                "checkpoint_id": checkpoint.get("checkpoint_id"),
                "phase": phase,
                "action_id": checkpoint.get("action_id"),
                "pre_evidence": pre,
                "current_evidence": current,
                "paths_changed": changed,
                "processes": process_evidence,
                "read_only": True,
            },
            "next_action": (
                "review evidence, then explicitly continue or roll back; do not replay automatically"
                if uncertain
                else "no unresolved pre-action checkpoint found"
            ),
        }

    async def resume(self, session_id: str, decision: Mapping[str, Any]) -> dict[str, Any]:
        session = self.storage.get_session(session_id)
        checkpoint = self.storage.latest_checkpoint(session_id)
        checkpoint_phase = (
            str(checkpoint.get("phase", "")).upper()
            if isinstance(checkpoint, Mapping)
            else ""
        )
        stored_state = session.get("state", {})
        approval_request = (
            stored_state.get("approval_request")
            if isinstance(stored_state, Mapping)
            else None
        )
        checkpoint_state = (
            checkpoint.get("state", {})
            if isinstance(checkpoint, Mapping)
            else {}
        )
        checkpoint_request = (
            checkpoint_state.get("approval_request")
            if isinstance(checkpoint_state, Mapping)
            else None
        )
        if (
            str(session.get("status")) != SessionStatus.WAITING_APPROVAL.value
            or not isinstance(checkpoint, Mapping)
            or checkpoint_phase in {"PRE_TOOL_CALL", "TOOL_CALL"}
            or not isinstance(approval_request, Mapping)
            or not isinstance(checkpoint_request, Mapping)
            or dict(approval_request) != dict(checkpoint_request)
        ):
            result = self.reconcile(session_id)
            result["status"] = SessionStatus.BLOCKED.value
            result["blockers"] = [
                "resume is allowed only for an exact waiting approval; "
                "crash-interrupted actions require read-only reconciliation"
            ]
            return result
        core = await self._ensure_core()
        stored_budget = (
            stored_state.get("budget", {})
            if isinstance(stored_state, Mapping)
            else {}
        )
        configured_budget: dict[str, Any] = {
            "max_rounds": self.config.budget.max_rounds,
            "max_tool_calls": self.config.budget.max_tool_calls,
            "max_tokens": self.config.budget.max_tokens,
            "max_elapsed_seconds": self.config.budget.max_elapsed_seconds,
            "max_input_tokens": self.config.budget.max_input_tokens,
            "max_output_tokens": self.config.budget.max_output_tokens,
            "max_cost_usd": self.config.budget.max_cost_usd,
            "max_concurrency": self.config.budget.max_concurrency,
        }
        configured_budget = _clamp_persisted_budget(
            configured_budget,
            stored_budget if isinstance(stored_budget, Mapping) else {},
        )
        authority_token = self._bind_subagent_context(
            session_id, configured_budget
        )
        try:
            try:
                result = await core.resume(
                    session_id,
                    decision,
                    budget=configured_budget,
                )
            except asyncio.CancelledError:
                # Ctrl-C can arrive while an approved action is running after
                # an approval resume, not only during the initial run.  Route
                # both paths through the same host-side kill and checkpoint.
                result = await core.cancel(session_id)
            except Exception as exc:
                # A crash may leave only the LangGraph saver state (the product
                # checkpoint is written after a normal return).  Surface a safe
                # blocked/reconcile result instead of pretending the action can
                # be replayed.
                result = self.reconcile(session_id)
                result["blockers"] = [f"resume requires read-only reconcile ({type(exc).__name__})"]
        finally:
            reset_parent_authority(authority_token)
        self._persist_result(result)
        return result

    async def close(self) -> None:
        """Close the async SQLite connection and release Windows file handles."""
        if self.subagent_tools is not None:
            await self.subagent_tools.stop_all()
        connection = self._checkpoint_connection
        self._checkpoint_connection = None
        self._checkpointer = None
        self.core = None
        if connection is not None:
            await connection.close()

    def _persist_result(self, result: Mapping[str, Any]) -> None:
        sid = str(result["session_id"])
        status = str(result.get("status", SessionStatus.FAILED.value))
        self.storage.update_session(sid, status=status, state=dict(result))
        checkpoint = result.get("checkpoint")
        if status == SessionStatus.WAITING_APPROVAL.value:
            # A prior completed tool checkpoint may still be attached to the
            # interrupted state.  Persist the exact current approval state as
            # the newest product checkpoint so resume can bind both copies.
            request = result.get("approval_request")
            self.storage.save_checkpoint(
                {
                    "session_id": sid,
                    "turn_id": result.get("turn_id"),
                    "phase": "POLICY_CHECK",
                    "state": dict(result),
                    "action_id": (
                        request.get("action_id")
                        if isinstance(request, Mapping)
                        else None
                    ),
                },
                session_id=sid,
            )
        elif isinstance(checkpoint, Mapping):
            self.storage.save_checkpoint(checkpoint, session_id=sid)
        else:
            # LangGraph returns an interrupt state without traversing the
            # CHECKPOINT node. Persist that exact state so a later process can
            # reconcile the pending action instead of silently losing it.
            self.storage.save_checkpoint(
                {
                    "session_id": sid,
                    "turn_id": result.get("turn_id"),
                    "phase": result.get("phase", "POLICY_CHECK"),
                    "state": dict(result),
                    "action_id": (result.get("current_call") or {}).get("action_id") if isinstance(result.get("current_call"), Mapping) else None,
                },
                session_id=sid,
            )
        self.storage.save_event(sid, "run.completed" if status in {s.value for s in SessionStatus} else "run.updated", {"status": status, "next_action": result.get("next_action"), "blockers": result.get("blockers", [])})

    @classmethod
    async def resume_from_storage(cls, config: AppConfig, storage: Storage, session_id: str, decision: Mapping[str, Any] | None = None) -> dict[str, Any]:
        instance = cls(config, storage=storage)
        if decision is None:
            return instance.reconcile(session_id)
        try:
            return await instance.resume(session_id, decision)
        finally:
            await instance.close()


__all__ = ["Orchestrator", "build_registry"]
