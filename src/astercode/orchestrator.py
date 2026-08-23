"""LangGraph orchestration for AsterCode's host-controlled agent loop."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Callable, Literal, Protocol, TypedDict, runtime_checkable

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from pydantic import Field, ValidationError, model_validator

from .models import (
    ApprovalDecision,
    ApprovalRequest,
    CheckpointRecord,
    RiskLevel,
    SessionStatus,
    StrictModel,
    ToolCall,
    ToolError,
    ToolResult,
    ToolSpec,
    ToolStatus,
    new_id,
    utc_now,
)
from .provider import (
    Provider,
    ProviderConfigurationError,
    ProviderExecutionError,
    ProviderRequest,
    ProviderResponse,
    ProviderStreamEvent,
    ToolProposal,
)
from .security import contains_probable_secret, contains_prompt_injection, redact_secrets

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


TERMINAL_STATUSES = {
    SessionStatus.COMPLETED.value,
    SessionStatus.PARTIAL.value,
    SessionStatus.BLOCKED.value,
    SessionStatus.CANCELLED.value,
    SessionStatus.FAILED.value,
}


class RunBudget(StrictModel):
    """Hard limits checked by host code, independent of model instructions."""

    max_rounds: int = Field(default=12, ge=1, le=10_000)
    max_tool_calls: int = Field(default=64, ge=0, le=100_000)
    max_elapsed_seconds: float = Field(default=900.0, gt=0, le=604_800)
    max_tokens: int | None = Field(default=None, ge=1)
    max_input_tokens: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    max_cost_usd: float | None = Field(default=None, ge=0)
    max_concurrency: int = Field(default=1, ge=1, le=32)


class RunUsage(StrictModel):
    rounds: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    cost_usd: float | None = Field(default=0.0, ge=0)


class GatewayAuthorization(StrictModel):
    """A host policy decision for one concrete, normalised ``ToolCall``."""

    outcome: Literal["allow", "deny", "require_approval"]
    risk: RiskLevel
    reason: str = Field(min_length=1, max_length=8_192)
    approval_request: ApprovalRequest | None = None

    @model_validator(mode="after")
    def validate_approval_shape(self) -> GatewayAuthorization:
        if self.outcome == "require_approval" and self.approval_request is None:
            raise ValueError("require_approval needs an ApprovalRequest")
        if self.outcome != "require_approval" and self.approval_request is not None:
            raise ValueError("only require_approval may carry an ApprovalRequest")
        return self


class GatewayContext(StrictModel):
    session_id: str
    turn_id: str
    goal: str
    phase: str
    execution_timeout_seconds: float | None = Field(default=None, gt=0)


@runtime_checkable
class ToolGateway(Protocol):
    """Security boundary between model proposals and real side effects.

    Implementations must revalidate schemas, paths, policy, approval bindings,
    redaction, and the actual side effects.  Returning ``allow`` is the only
    route by which ``execute`` can be reached.
    """

    async def authorize(
        self,
        call: ToolCall,
        context: GatewayContext,
        decision: ApprovalDecision | None = None,
    ) -> GatewayAuthorization | Mapping[str, Any]: ...

    async def execute(
        self,
        call: ToolCall,
        context: GatewayContext,
    ) -> ToolResult | Mapping[str, Any]: ...


class AgentState(TypedDict, total=False):
    session_id: str
    turn_id: str
    goal: str
    status: str
    phase: str
    started_at: str
    updated_at: str
    budget: dict[str, Any]
    usage: dict[str, Any]
    assumptions: list[str]
    plan: list[str]
    completed: list[str]
    pending: list[str]
    active_files: list[str]
    test_status: list[dict[str, Any]]
    risks: list[str]
    approvals: list[dict[str, Any]]
    blockers: list[str]
    messages: list[str]
    conversation: list[dict[str, str]]
    tool_results: list[dict[str, Any]]
    pending_calls: list[dict[str, Any]]
    current_call: dict[str, Any] | None
    current_purpose: str | None
    policy_outcome: str | None
    policy_reason: str | None
    approval_request: dict[str, Any] | None
    raw_tool_result: dict[str, Any] | None
    action_executed: bool
    provider_outcome: str | None
    provider_response_id: str | None
    provider_events: list[dict[str, Any]]
    action_attempts: int
    retry_attempts: dict[str, int]
    cancellation_requested: bool
    checkpoint_seq: int
    checkpoint: dict[str, Any] | None
    phase_history: list[str]
    next_action: str


class OrchestratorError(RuntimeError):
    """Safe public error for invalid orchestration operations."""


class AsterCodeOrchestrator:
    """Explicit OBSERVE -> PLAN -> POLICY -> ACT -> VERIFY state machine."""

    def __init__(
        self,
        provider: Provider,
        gateway: ToolGateway,
        *,
        tools: Sequence[ToolSpec] = (),
        checkpointer: Any | None = None,
        max_model_result_chars: int = 8_192,
        max_model_context_chars: int = 24_576,
        max_tool_retries: int = 2,
        memory_lookup: Callable[[str], Sequence[Mapping[str, Any]]] | None = None,
        event_sink: Callable[[Mapping[str, Any]], Any] | None = None,
    ) -> None:
        if max_model_result_chars < 1_024:
            raise ValueError("max_model_result_chars must be at least 1024")
        if max_model_context_chars < max_model_result_chars:
            raise ValueError("max_model_context_chars must be at least max_model_result_chars")
        if not 0 <= max_tool_retries <= 8:
            raise ValueError("max_tool_retries must be between 0 and 8")
        self.provider = provider
        self.gateway = gateway
        self.tools = tuple(tools)
        self._tool_specs = {spec.name: spec for spec in self.tools}
        self.max_model_result_chars = max_model_result_chars
        self.max_model_context_chars = max_model_context_chars
        self.max_tool_retries = max_tool_retries
        self.memory_lookup = memory_lookup
        self.event_sink = event_sink
        self._cancel_events: dict[str, asyncio.Event] = {}
        self.graph = self._build_graph(checkpointer or InMemorySaver())

    def _build_graph(self, checkpointer: Any) -> Any:
        graph = StateGraph(AgentState)
        graph.add_node("OBSERVE", self._observe)
        graph.add_node("PLAN", self._plan)
        graph.add_node("POLICY_CHECK", self._policy_check)
        graph.add_node("APPROVAL_GATE", self._approval_gate)
        graph.add_node("TOOL_CALL", self._tool_call)
        graph.add_node("CAPTURE", self._capture)
        graph.add_node("VERIFY", self._verify)
        graph.add_node("CHECKPOINT", self._checkpoint)
        graph.add_edge(START, "OBSERVE")
        graph.add_edge("OBSERVE", "PLAN")
        graph.add_edge("PLAN", "POLICY_CHECK")
        graph.add_conditional_edges(
            "POLICY_CHECK",
            self._route_after_policy,
            {"approval": "APPROVAL_GATE", "tool": "TOOL_CALL"},
        )
        graph.add_edge("APPROVAL_GATE", "TOOL_CALL")
        graph.add_edge("TOOL_CALL", "CAPTURE")
        graph.add_edge("CAPTURE", "VERIFY")
        graph.add_edge("VERIFY", "CHECKPOINT")
        graph.add_conditional_edges(
            "CHECKPOINT",
            self._route_after_checkpoint,
            {"loop": "OBSERVE", "end": END},
        )
        return graph.compile(checkpointer=checkpointer, name="AsterCode")

    @staticmethod
    def initial_state(
        goal: str,
        *,
        session_id: str | None = None,
        turn_id: str | None = None,
        budget: RunBudget | Mapping[str, Any] | None = None,
    ) -> AgentState:
        if not goal.strip():
            raise ValueError("goal must not be empty")
        now = utc_now().isoformat()
        parsed_budget = budget if isinstance(budget, RunBudget) else RunBudget.model_validate(budget or {})
        safe_goal = str(redact_secrets(goal))
        return AgentState(
            session_id=session_id or new_id("session"),
            turn_id=turn_id or new_id("turn"),
            goal=safe_goal,
            status=SessionStatus.CREATED.value,
            phase="OBSERVE",
            started_at=now,
            updated_at=now,
            budget=parsed_budget.model_dump(mode="json"),
            usage=RunUsage().model_dump(mode="json"),
            assumptions=[],
            plan=[],
            completed=[],
            pending=[],
            active_files=[],
            test_status=[],
            risks=[],
            approvals=[],
            blockers=[],
            messages=[],
            conversation=[],
            tool_results=[],
            pending_calls=[],
            current_call=None,
            current_purpose=None,
            policy_outcome=None,
            policy_reason=None,
            approval_request=None,
            raw_tool_result=None,
            action_executed=False,
            provider_outcome=None,
            provider_response_id=None,
            provider_events=[],
            action_attempts=0,
            retry_attempts={},
            cancellation_requested=False,
            checkpoint_seq=0,
            checkpoint=None,
            phase_history=[],
            next_action="observe workspace state",
        )

    async def run(
        self,
        goal_or_state: str | AgentState,
        *,
        session_id: str | None = None,
        turn_id: str | None = None,
        budget: RunBudget | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        state = (
            self.initial_state(
                goal_or_state,
                session_id=session_id,
                turn_id=turn_id,
                budget=budget,
            )
            if isinstance(goal_or_state, str)
            else dict(goal_or_state)
        )
        sid = str(state["session_id"])
        self._cancel_events.setdefault(sid, asyncio.Event())
        return await self.graph.ainvoke(state, config=self._config(sid))

    async def resume(
        self,
        session_id: str,
        decision: ApprovalDecision | Mapping[str, Any],
        *,
        budget: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        parsed = decision if isinstance(decision, ApprovalDecision) else ApprovalDecision.model_validate(decision)
        config = self._config(session_id)
        if budget is not None:
            snapshot = await self.graph.aget_state(config)
            if snapshot.values:
                await self.graph.aupdate_state(config, {"budget": dict(budget)})
        return await self.graph.ainvoke(
            Command(resume=parsed.model_dump(mode="json")),
            config=config,
        )

    async def cancel(self, session_id: str) -> dict[str, Any]:
        """Trigger the host-side kill signal and wake a paused approval node."""

        event = self._cancel_events.setdefault(session_id, asyncio.Event())
        event.set()
        cancel_method = getattr(self.gateway, "cancel", None)
        if cancel_method is not None:
            value = cancel_method(session_id)
            if inspect.isawaitable(value):
                await value

        config = self._config(session_id)
        snapshot = await self.graph.aget_state(config)
        if snapshot.values:
            await self.graph.aupdate_state(
                config,
                {
                    "cancellation_requested": True,
                    "status": SessionStatus.CANCELLED.value,
                    "updated_at": utc_now().isoformat(),
                    "next_action": "none",
                },
            )
            if "APPROVAL_GATE" in snapshot.next:
                return await self.graph.ainvoke(Command(resume={"cancel": True}), config=config)
            updated = await self.graph.aget_state(config)
            return dict(updated.values)
        return {"session_id": session_id, "status": SessionStatus.CANCELLED.value}

    async def get_state(self, session_id: str) -> dict[str, Any]:
        snapshot = await self.graph.aget_state(self._config(session_id))
        return dict(snapshot.values)

    @staticmethod
    def _config(session_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": session_id}}

    def _is_cancelled(self, state: AgentState) -> bool:
        if state.get("cancellation_requested", False):
            return True
        event = self._cancel_events.get(str(state.get("session_id", "")))
        return bool(event and event.is_set())

    @staticmethod
    def _is_terminal(state: AgentState) -> bool:
        return state.get("status") in TERMINAL_STATUSES

    @staticmethod
    def _phase_update(state: AgentState, phase: str) -> dict[str, Any]:
        return {
            "phase": phase,
            "phase_history": [*state.get("phase_history", []), phase],
            "updated_at": utc_now().isoformat(),
        }

    def _stop_update(self, state: AgentState) -> dict[str, Any] | None:
        if self._is_cancelled(state):
            return {
                "status": SessionStatus.CANCELLED.value,
                "cancellation_requested": True,
                "next_action": "none",
                "updated_at": utc_now().isoformat(),
            }
        reason = self._budget_reason(state)
        if reason is None:
            return None
        prior_work = bool(state.get("completed") or state.get("tool_results"))
        return {
            "status": (SessionStatus.PARTIAL.value if prior_work else SessionStatus.BLOCKED.value),
            "blockers": [*state.get("blockers", []), reason],
            "next_action": "increase the exact run budget or narrow the task",
            "updated_at": utc_now().isoformat(),
        }

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value)

    def _budget_reason(self, state: AgentState) -> str | None:
        budget = RunBudget.model_validate(state.get("budget", {}))
        usage = RunUsage.model_validate(state.get("usage", {}))
        started = self._parse_time(state["started_at"])
        if (utc_now() - started).total_seconds() >= budget.max_elapsed_seconds:
            return "elapsed-time budget exhausted"
        if usage.rounds >= budget.max_rounds and not (state.get("current_call") or state.get("pending_calls")):
            return "model-round budget exhausted"
        if usage.tool_calls >= budget.max_tool_calls and (state.get("current_call") or state.get("pending_calls")):
            return "tool-call budget exhausted"
        if budget.max_tokens is not None and usage.total_tokens >= budget.max_tokens:
            return "token budget exhausted"
        if budget.max_input_tokens is not None and usage.input_tokens >= budget.max_input_tokens:
            return "input-token budget exhausted"
        if budget.max_output_tokens is not None and usage.output_tokens >= budget.max_output_tokens:
            return "output-token budget exhausted"
        if budget.max_cost_usd is not None:
            if usage.cost_usd is None:
                return "cost budget cannot be enforced because provider cost is unknown"
            if usage.cost_usd >= budget.max_cost_usd:
                return "cost budget exhausted"
        return None

    def _remaining_elapsed_seconds(self, state: AgentState) -> float:
        budget = RunBudget.model_validate(state.get("budget", {}))
        started = self._parse_time(state["started_at"])
        elapsed = max(0.0, (utc_now() - started).total_seconds())
        return max(0.0, budget.max_elapsed_seconds - elapsed)

    @staticmethod
    def _remaining_provider_tokens(
        state: AgentState,
    ) -> tuple[int | None, int | None]:
        """Return this call's output cap and remaining total-token budget."""

        budget = RunBudget.model_validate(state.get("budget", {}))
        usage = RunUsage.model_validate(state.get("usage", {}))
        total_remaining = None if budget.max_tokens is None else budget.max_tokens - usage.total_tokens
        output_remaining = None if budget.max_output_tokens is None else budget.max_output_tokens - usage.output_tokens
        candidates = [value for value in (total_remaining, output_remaining) if value is not None]
        output_cap = min(candidates) if candidates else None
        return output_cap, total_remaining

    def _gateway_context(self, state: AgentState, phase: str) -> GatewayContext:
        return GatewayContext(
            session_id=state["session_id"],
            turn_id=state["turn_id"],
            goal=state["goal"],
            phase=phase,
        )

    async def _emit(self, event: Mapping[str, Any]) -> None:
        """Emit a redacted lifecycle event without making UI failure fatal."""

        if self.event_sink is None:
            return
        safe = redact_secrets(dict(event))
        try:
            value = self.event_sink(safe if isinstance(safe, Mapping) else {"event": str(safe)})
            if inspect.isawaitable(value):
                await value
        except Exception:
            # Presentation/telemetry is deliberately outside the execution
            # safety boundary. A broken renderer must not replay an action.
            return

    async def _stream_provider(self, request: ProviderRequest) -> tuple[ProviderResponse, list[dict[str, Any]]]:
        """Consume the provider streaming contract and require one terminal response."""

        response: ProviderResponse | None = None
        events: list[dict[str, Any]] = []
        # The outer timeout is the host's final boundary.  It also constrains
        # fake/custom providers which do not implement an adapter timeout.
        async with asyncio.timeout(request.timeout_seconds):
            async for raw_event in self.provider.stream(request):
                event = raw_event if isinstance(raw_event, ProviderStreamEvent) else ProviderStreamEvent.model_validate(raw_event)
                item = {
                    "type": event.type,
                    "at": utc_now().isoformat(),
                    "response_id": event.response.response_id if event.response is not None else None,
                    "delta_chars": len(event.delta) if event.delta is not None else None,
                }
                events.append(item)
                emitted = {"event": f"provider.{event.type}", "session_id": request.session_id, **item}
                if event.delta is not None:
                    emitted["delta"] = event.delta
                await self._emit(emitted)
                if event.type == "completed" and event.response is not None:
                    if response is not None:
                        raise ProviderExecutionError("provider stream returned more than one terminal response")
                    response = event.response
        if response is None:
            raise ProviderExecutionError("provider stream ended without a terminal response")
        if request.max_output_tokens is not None and response.usage.output_tokens > request.max_output_tokens:
            raise ProviderExecutionError("provider reported output usage above the host request limit")
        if request.max_total_tokens is not None and response.usage.total_tokens > request.max_total_tokens:
            raise ProviderExecutionError("provider reported total usage above the remaining run budget")
        return response, events

    async def _observe(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "OBSERVE")
        if self._is_terminal(state):
            return update
        stopped = self._stop_update(state)
        if stopped:
            update.update(stopped)
            return update
        update.update(
            status=SessionStatus.RUNNING.value,
            next_action="ask provider for the next structured decision",
        )
        return update

    async def _plan(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "PLAN")
        if self._is_terminal(state):
            return update

        queued = list(state.get("pending_calls", []))
        if queued:
            first_raw, *rest = queued
            first = dict(first_raw)
            update.update(
                current_call=first,
                current_purpose=first.pop("_purpose", "execute proposed tool"),
                pending_calls=rest,
                next_action="policy-check queued tool proposal",
            )
            return update

        stopped = self._stop_update(state)
        if stopped:
            update.update(stopped)
            return update

        budget = RunBudget.model_validate(state.get("budget", {}))
        if budget.max_cost_usd is not None and not bool(getattr(self.provider, "supports_cost_tracking", False)):
            update.update(
                status=SessionStatus.BLOCKED.value,
                blockers=[
                    *state.get("blockers", []),
                    "cost budget cannot be enforced by the selected provider",
                ],
                next_action="remove the cost budget or select a cost-tracking provider",
            )
            return update

        remaining_elapsed = self._remaining_elapsed_seconds(state)
        output_cap, total_remaining = self._remaining_provider_tokens(state)
        if remaining_elapsed <= 0 or (output_cap is not None and output_cap <= 0):
            stopped = self._stop_update(state)
            if stopped is not None:
                update.update(stopped)
            else:  # Defensive against clock/rounding drift.
                update.update(
                    status=SessionStatus.BLOCKED.value,
                    blockers=[*state.get("blockers", []), "run budget exhausted before provider call"],
                    next_action="increase the exact run budget or narrow the task",
                )
            return update

        request = ProviderRequest(
            session_id=state["session_id"],
            turn_id=state["turn_id"],
            phase="PLAN",
            goal=state["goal"],
            context=self._provider_context(state),
            available_tools=list(self.tools),
            timeout_seconds=remaining_elapsed,
            max_output_tokens=output_cap,
            max_total_tokens=total_remaining,
        )
        try:
            response, stream_events = await self._stream_provider(request)
        except TimeoutError:
            prior_work = bool(state.get("completed") or state.get("tool_results"))
            update.update(
                status=(SessionStatus.PARTIAL.value if prior_work else SessionStatus.BLOCKED.value),
                blockers=[
                    *state.get("blockers", []),
                    "provider call exhausted the remaining elapsed-time budget",
                ],
                next_action="increase the exact run budget or narrow the task",
            )
            return update
        except ProviderConfigurationError as exc:
            update.update(
                status=SessionStatus.BLOCKED.value,
                blockers=[*state.get("blockers", []), str(exc)],
                next_action="configure the selected provider",
            )
            return update
        except ProviderExecutionError as exc:
            update.update(
                status=SessionStatus.FAILED.value,
                blockers=[*state.get("blockers", []), str(exc)],
                next_action="inspect the provider failure",
            )
            return update

        usage = self._add_provider_usage(state, response)
        try:
            calls = [
                self._proposal_to_call(state, proposal, index).model_dump(mode="json") | {"_purpose": str(redact_secrets(proposal.purpose))}
                for index, proposal in enumerate(response.decision.tool_calls)
            ]
        except ProviderExecutionError as exc:
            update.update(
                status=SessionStatus.FAILED.value,
                blockers=[*state.get("blockers", []), str(exc)],
                next_action="inspect the invalid provider tool proposal",
            )
            return update
        except (TypeError, ValueError) as exc:
            update.update(
                status=SessionStatus.FAILED.value,
                blockers=[
                    *state.get("blockers", []),
                    f"invalid provider tool proposal ({type(exc).__name__})",
                ],
                next_action="inspect the invalid provider tool proposal",
            )
            return update
        messages = list(state.get("messages", []))
        conversation = list(state.get("conversation", []))
        if response.decision.message:
            safe_message = str(redact_secrets(response.decision.message))
            messages.append(safe_message)
            conversation.append({"role": "assistant", "content": safe_message})
        update.update(
            usage=usage.model_dump(mode="json"),
            plan=[str(redact_secrets(item)) for item in response.decision.plan],
            messages=messages,
            conversation=conversation[-16:],
            provider_outcome=response.decision.outcome,
            provider_response_id=response.response_id,
            provider_events=[*state.get("provider_events", []), *stream_events][-128:],
        )
        if calls:
            first, *rest = calls
            purpose = first.pop("_purpose")
            update.update(
                current_call=first,
                current_purpose=purpose,
                pending_calls=rest,
                status=SessionStatus.RUNNING.value,
                next_action="policy-check proposed tool call",
            )
        elif response.decision.outcome == "completed":
            if self._completion_evidence(state):
                update.update(status=SessionStatus.COMPLETED.value, next_action="none")
            else:
                update.update(
                    status=SessionStatus.PARTIAL.value,
                    blockers=[
                        *state.get("blockers", []),
                        "provider reported completion without a verified tool/result evidence chain",
                    ],
                    next_action="inspect the partial result and provide a verifiable follow-up",
                )
        elif response.decision.outcome == "blocked":
            update.update(
                status=SessionStatus.BLOCKED.value,
                blockers=[
                    *state.get("blockers", []),
                    response.decision.message or "provider reported a blocker",
                ],
                next_action="resolve the reported blocker",
            )
        else:
            update.update(next_action="continue observation loop")
        return update

    def _proposal_to_call(self, state: AgentState, proposal: ToolProposal, index: int) -> ToolCall:
        if contains_probable_secret(proposal.arguments):
            raise ProviderExecutionError("provider proposed secret-looking tool arguments")
        if not _TOOL_NAME.fullmatch(proposal.tool):
            raise ProviderExecutionError("provider proposed an invalid namespace.action tool name")
        arguments = proposal.model_dump(mode="json")["arguments"]
        canonical = json.dumps(
            {
                "session_id": state["session_id"],
                "turn_id": state["turn_id"],
                "round": RunUsage.model_validate(state.get("usage", {})).rounds + 1,
                "index": index,
                "tool": proposal.tool,
                "arguments": arguments,
                "host": proposal.host,
                "cwd": proposal.cwd,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return ToolCall(
            call_id=f"call_{digest[:24]}",
            action_id=f"action_{digest[24:48]}",
            tool=proposal.tool,
            arguments=arguments,
            host=proposal.host,
            cwd=proposal.cwd,
            idempotency_key=digest,
        )

    @staticmethod
    def _add_provider_usage(state: AgentState, response: ProviderResponse) -> RunUsage:
        prior = RunUsage.model_validate(state.get("usage", {}))
        cost = None if prior.cost_usd is None or response.usage.cost_usd is None else prior.cost_usd + response.usage.cost_usd
        return RunUsage(
            rounds=prior.rounds + 1,
            tool_calls=prior.tool_calls,
            input_tokens=prior.input_tokens + response.usage.input_tokens,
            output_tokens=prior.output_tokens + response.usage.output_tokens,
            total_tokens=prior.total_tokens + response.usage.total_tokens,
            cost_usd=cost,
        )

    async def _policy_check(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "POLICY_CHECK")
        if self._is_terminal(state) or state.get("current_call") is None:
            return update
        stopped = self._stop_update(state)
        if stopped:
            update.update(stopped)
            return update
        call = ToolCall.model_validate(state["current_call"])
        try:
            raw = await self.gateway.authorize(call, self._gateway_context(state, "POLICY_CHECK"), None)
            auth = self._coerce_authorization(raw)
        except Exception as exc:
            update.update(
                status=SessionStatus.BLOCKED.value,
                blockers=[
                    *state.get("blockers", []),
                    f"policy gateway failed closed ({type(exc).__name__})",
                ],
                policy_outcome="deny",
                policy_reason="policy gateway failed closed",
                next_action="inspect the policy gateway",
            )
            return update
        update["risks"] = [*state.get("risks", []), auth.risk.value]
        update["policy_outcome"] = auth.outcome
        update["policy_reason"] = auth.reason
        if auth.outcome == "require_approval":
            request = auth.approval_request
            if request is None or request.action_id != call.action_id or request.tool != call.tool:
                update.update(
                    status=SessionStatus.BLOCKED.value,
                    policy_outcome="deny",
                    policy_reason="approval request did not bind the current action",
                    next_action="inspect the policy gateway",
                )
                return update
            update.update(
                status=SessionStatus.WAITING_APPROVAL.value,
                approval_request=request.model_dump(mode="json"),
                next_action="await exact user approval decision",
            )
        elif auth.outcome == "deny":
            update.update(next_action="capture policy denial")
        else:
            update.update(next_action="execute authorised tool call")
        return update

    @staticmethod
    def _coerce_authorization(
        value: GatewayAuthorization | Mapping[str, Any],
    ) -> GatewayAuthorization:
        return value if isinstance(value, GatewayAuthorization) else GatewayAuthorization.model_validate(value)

    @staticmethod
    def _route_after_policy(state: AgentState) -> Literal["approval", "tool"]:
        return "approval" if state.get("policy_outcome") == "require_approval" else "tool"

    async def _approval_gate(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "POLICY_CHECK")
        if self._is_cancelled(state):
            update.update(
                status=SessionStatus.CANCELLED.value,
                policy_outcome="deny",
                policy_reason="run cancelled",
                next_action="none",
            )
            return update
        call = ToolCall.model_validate(state["current_call"])
        request = ApprovalRequest.model_validate(state["approval_request"])
        resumed = interrupt(
            {
                "type": "approval_required",
                "request": request.model_dump(mode="json"),
            }
        )
        if isinstance(resumed, Mapping) and resumed.get("cancel") is True:
            update.update(
                status=SessionStatus.CANCELLED.value,
                cancellation_requested=True,
                policy_outcome="deny",
                policy_reason="run cancelled",
                next_action="none",
            )
            return update
        try:
            decision = ApprovalDecision.model_validate(resumed)
        except ValidationError:
            update.update(
                status=SessionStatus.BLOCKED.value,
                policy_outcome="deny",
                policy_reason="invalid approval decision",
                next_action="submit a complete bound approval decision",
            )
            return update
        if not self._decision_matches(request, decision):
            update.update(
                status=SessionStatus.BLOCKED.value,
                policy_outcome="deny",
                policy_reason="approval decision binding mismatch or expiry",
                next_action="request a new approval",
            )
            return update
        approvals = [*state.get("approvals", []), decision.model_dump(mode="json")]
        if not decision.approved:
            # A user denial is authoritative even if a buggy gateway says allow.
            try:
                await self.gateway.authorize(call, self._gateway_context(state, "POLICY_CHECK"), decision)
            except Exception as policy_exc:
                _ = policy_exc
            update.update(
                approvals=approvals,
                status=SessionStatus.RUNNING.value,
                policy_outcome="deny",
                policy_reason=decision.reason or "user denied approval",
                next_action="capture approval denial",
            )
            return update
        try:
            raw = await self.gateway.authorize(call, self._gateway_context(state, "POLICY_CHECK"), decision)
            auth = self._coerce_authorization(raw)
        except Exception as exc:
            update.update(
                approvals=approvals,
                status=SessionStatus.BLOCKED.value,
                policy_outcome="deny",
                policy_reason=f"approval revalidation failed ({type(exc).__name__})",
                next_action="request a new approval",
            )
            return update
        if auth.outcome != "allow":
            update.update(
                approvals=approvals,
                status=SessionStatus.BLOCKED.value,
                policy_outcome="deny",
                policy_reason="approval was not accepted by host policy",
                next_action="request a new approval",
            )
            return update
        update.update(
            approvals=approvals,
            status=SessionStatus.RUNNING.value,
            policy_outcome="allow",
            policy_reason=auth.reason,
            next_action="execute authorised tool call",
        )
        return update

    @staticmethod
    def _decision_matches(request: ApprovalRequest, decision: ApprovalDecision) -> bool:
        return bool(
            request.expires_at > utc_now()
            and decision.approval_id == request.approval_id
            and decision.action_id == request.action_id
            and decision.action_hash == request.action_hash
            and decision.nonce == request.nonce
        )

    async def _tool_call(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "TOOL_CALL")
        call_data = state.get("current_call")
        if call_data is None:
            return update
        call = ToolCall.model_validate(call_data)
        if call.tool == "subagent.research":
            # The host-bound delegation context must see the parent's live
            # counters immediately before reserving a child budget.
            from .subagents import update_parent_authority_usage

            update_parent_authority_usage(state.get("usage", {}))
        now = utc_now()
        if self._is_cancelled(state):
            result = self._synthetic_result(call, ToolStatus.CANCELLED, "cancelled", "run cancelled", now)
            update.update(raw_tool_result=result.as_dict(), action_executed=False)
            return update
        if state.get("policy_outcome") != "allow":
            result = self._synthetic_result(
                call,
                ToolStatus.CANCELLED,
                "policy_denied",
                state.get("policy_reason") or "policy denied the action",
                now,
            )
            update.update(raw_tool_result=result.as_dict(), action_executed=False)
            return update
        attempts = 0
        retry_attempts = dict(state.get("retry_attempts", {}))
        budget = RunBudget.model_validate(state.get("budget", {}))
        usage = RunUsage.model_validate(state.get("usage", {}))
        remaining_attempts = max(1, budget.max_tool_calls - usage.tool_calls)
        while True:
            attempts += 1
            execution_timeout = self._tool_execution_timeout(state, call)
            if execution_timeout <= 0:
                result = self._tool_timeout_result(
                    call,
                    "elapsed-time budget exhausted before tool execution",
                    now,
                )
                break
            try:
                context = self._gateway_context(state, "TOOL_CALL").model_copy(update={"execution_timeout_seconds": execution_timeout})
                raw = await asyncio.wait_for(
                    self.gateway.execute(call, context),
                    timeout=execution_timeout,
                )
                result = self._coerce_result(raw, call)
            except TimeoutError:
                result = self._tool_timeout_result(
                    call,
                    "tool exceeded its host-enforced execution timeout",
                    now,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                result = self._synthetic_result(
                    call,
                    ToolStatus.FAILED,
                    "gateway_error",
                    f"tool gateway failed ({type(exc).__name__})",
                    now,
                )
            if not self._may_retry(state, call, result, attempts, remaining_attempts):
                break
            retry_attempts[call.action_id] = attempts
            await self._emit(
                {
                    "event": "tool.retry",
                    "session_id": state["session_id"],
                    "call_id": call.call_id,
                    "action_id": call.action_id,
                    "tool": call.tool,
                    "attempt": attempts + 1,
                }
            )
            await asyncio.sleep(0)
        update.update(
            raw_tool_result=result.as_dict(),
            action_executed=True,
            action_attempts=attempts,
            retry_attempts=retry_attempts,
            next_action="capture tool result",
        )
        return update

    def _tool_execution_timeout(self, state: AgentState, call: ToolCall) -> float:
        """Narrow a tool call to spec, argument, and remaining run time."""

        remaining = self._remaining_elapsed_seconds(state)
        spec = self._tool_specs.get(call.tool)
        limits = [remaining]
        if spec is not None:
            limits.append(spec.timeout)
        proposed = call.arguments.get("timeout")
        if isinstance(proposed, (int, float)) and not isinstance(proposed, bool) and math.isfinite(float(proposed)) and float(proposed) > 0:
            limits.append(float(proposed))
        return max(0.0, min(limits))

    def _tool_timeout_result(
        self,
        call: ToolCall,
        message: str,
        started_at: datetime,
    ) -> ToolResult:
        spec = self._tool_specs.get(call.tool)
        possible_effects = bool(spec and spec.side_effects)
        return ToolResult(
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
            started_at=started_at,
            ended_at=utc_now(),
            status=ToolStatus.UNKNOWN if possible_effects else ToolStatus.TIMEOUT,
            side_effects=(["possible_unconfirmed_side_effect"] if possible_effects else []),
            error=ToolError(code="tool_timeout", message=message, retryable=False),
        )

    def _may_retry(
        self,
        state: AgentState,
        call: ToolCall,
        result: ToolResult,
        attempts: int,
        remaining_attempts: int,
    ) -> bool:
        """Retry only replay-safe transient failures with no observed effects."""

        spec = self._tool_specs.get(call.tool)
        return bool(
            attempts <= self.max_tool_retries
            and attempts < remaining_attempts
            and spec is not None
            and spec.idempotent
            and call.idempotency_key
            and result.status in {ToolStatus.FAILED, ToolStatus.TIMEOUT}
            and isinstance(result.error, ToolError)
            and result.error.retryable
            and not result.side_effects
            and not self._is_cancelled(state)
        )

    @staticmethod
    def _coerce_result(value: ToolResult | Mapping[str, Any], call: ToolCall) -> ToolResult:
        payload = value.as_dict() if isinstance(value, ToolResult) else dict(value)
        return ToolResult.from_payload(
            payload,
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
        )

    @staticmethod
    def _synthetic_result(
        call: ToolCall,
        status: ToolStatus,
        code: str,
        message: str,
        started_at: datetime,
    ) -> ToolResult:
        return ToolResult(
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
            started_at=started_at,
            ended_at=utc_now(),
            status=status,
            error=ToolError(code=code, message=message, retryable=False),
        )

    async def _capture(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "CAPTURE")
        raw = state.get("raw_tool_result")
        if raw is None:
            return update
        result = ToolResult.model_validate(raw)
        results = [*state.get("tool_results", []), result.as_dict()]
        usage = RunUsage.model_validate(state.get("usage", {}))
        if state.get("action_executed", False):
            usage.tool_calls += max(1, int(state.get("action_attempts", 1)))
        if result.tool == "subagent.research":
            child_usage = result.metadata.get("child_usage_charge")
            if isinstance(child_usage, Mapping):
                usage.rounds += max(0, int(child_usage.get("rounds", 0)))
                usage.tool_calls += max(0, int(child_usage.get("tool_calls", 0)))
                usage.input_tokens += max(0, int(child_usage.get("input_tokens", 0)))
                usage.output_tokens += max(0, int(child_usage.get("output_tokens", 0)))
                usage.total_tokens += max(0, int(child_usage.get("total_tokens", 0)))
                child_cost = child_usage.get("cost_usd")
                if child_cost is None:
                    usage.cost_usd = None
                elif usage.cost_usd is not None:
                    usage.cost_usd += max(0.0, float(child_cost))
        completed = list(state.get("completed", []))
        blockers = list(state.get("blockers", []))
        status = state.get("status", SessionStatus.RUNNING.value)
        prior_work = bool(state.get("completed") or state.get("tool_results"))
        if contains_prompt_injection({"stdout": result.stdout, "stderr": result.stderr}):
            blockers.append(f"possible prompt injection in untrusted output from {result.tool}")
            status = SessionStatus.BLOCKED.value
        if result.status is ToolStatus.COMPLETED:
            completed.append(f"{result.tool} ({result.action_id})")
        elif result.status is ToolStatus.UNKNOWN:
            blockers.append(f"unknown side-effect state for {result.action_id}")
            status = SessionStatus.BLOCKED.value
        elif result.status in {ToolStatus.FAILED, ToolStatus.TIMEOUT}:
            blockers.append(f"tool {result.tool} did not complete ({result.status.value})")
            status = SessionStatus.PARTIAL.value if prior_work else SessionStatus.FAILED.value
        elif result.status is ToolStatus.CANCELLED and not self._is_cancelled(state):
            blockers.append(state.get("policy_reason") or "tool call cancelled")
            status = SessionStatus.BLOCKED.value
        update.update(
            tool_results=results,
            usage=usage.model_dump(mode="json"),
            completed=completed,
            blockers=blockers,
            status=status,
            current_call=None,
            current_purpose=None,
            policy_outcome=None,
            policy_reason=None,
            approval_request=None,
            raw_tool_result=None,
            action_executed=False,
            action_attempts=0,
            next_action="verify captured result",
        )
        return update

    @staticmethod
    def _completion_evidence(state: AgentState) -> bool:
        """Only a verified, completed tool result can close a coding task."""
        results = state.get("tool_results", [])
        checks = state.get("test_status", [])
        if not results or not checks:
            return False
        latest = ToolResult.model_validate(results[-1])
        latest_check = checks[-1]
        if latest_check.get("call_id") != latest.call_id:
            return False
        if latest.status is not ToolStatus.COMPLETED or not bool(latest_check.get("verified")):
            return False
        if latest.tool == "process.start" and latest_check.get("running"):
            return False
        return True

    async def _verify(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "VERIFY")
        results = state.get("tool_results", [])
        if not results:
            return update
        result = ToolResult.model_validate(results[-1])
        prior_checks = list(state.get("test_status", []))
        if prior_checks and prior_checks[-1].get("call_id") == result.call_id:
            # Every graph round passes through VERIFY, including a final
            # model-only completion round. Verification is idempotent per
            # concrete tool call and must not duplicate the previous result.
            return update
        verification: dict[str, Any] = {
            "call_id": result.call_id,
            "action_id": result.action_id,
            "status": result.status.value,
            "verified": result.status is ToolStatus.COMPLETED,
        }
        verify_method = getattr(self.gateway, "verify", None)
        if verify_method is not None:
            try:
                value = verify_method(result, self._gateway_context(state, "VERIFY"))
                if inspect.isawaitable(value):
                    value = await value
                if isinstance(value, Mapping):
                    verification.update(dict(value))
            except Exception as exc:
                verification.update(
                    verified=False,
                    error=f"verification failed ({type(exc).__name__})",
                )
        update.update(
            test_status=[*prior_checks, verification],
            next_action=("reconcile unknown side effects read-only" if result.status is ToolStatus.UNKNOWN else "persist checkpoint"),
        )
        return update

    async def _checkpoint(self, state: AgentState) -> dict[str, Any]:
        update = self._phase_update(state, "CHECKPOINT")
        seq = state.get("checkpoint_seq", 0) + 1
        snapshot = self._checkpoint_state(state)
        action_id = None
        if state.get("tool_results"):
            action_id = str(state["tool_results"][-1].get("action_id") or "") or None
        record = CheckpointRecord(
            session_id=state["session_id"],
            turn_id=state["turn_id"],
            phase="CHECKPOINT",
            state=snapshot,
            action_id=action_id,
        )
        update.update(
            checkpoint_seq=seq,
            checkpoint=record.model_dump(mode="json"),
            next_action=("none" if self._is_terminal(state) else "continue agent loop"),
        )
        return update

    @staticmethod
    def _route_after_checkpoint(state: AgentState) -> Literal["loop", "end"]:
        return "end" if state.get("status") in TERMINAL_STATUSES else "loop"

    def _provider_context(self, state: AgentState) -> dict[str, Any]:
        # Older tool evidence is retained as metadata, while only the newest
        # two results may carry bounded stdout/stderr.  This preserves the
        # action/evidence chain without resending recursive directory listings
        # and other large observations on every model round.
        raw_results = list(state.get("tool_results", []))[-8:]
        results_reversed: list[dict[str, Any]] = []
        full_from = max(0, len(raw_results) - 2)
        remaining_output_chars = self.max_model_context_chars
        compact_keys = (
            "call_id",
            "action_id",
            "tool",
            "host",
            "cwd",
            "status",
            "exit_code",
            "artifacts",
            "truncated",
            "side_effects",
            "error",
        )
        for index in range(len(raw_results) - 1, -1, -1):
            source = dict(raw_results[index])
            if index < full_from or remaining_output_chars <= 0:
                compacted = {key: source.get(key) for key in compact_keys}
                compacted["compacted"] = True
                results_reversed.append(compacted)
                continue
            for key in ("stdout", "stderr"):
                value = str(source.get(key, ""))
                limit = min(self.max_model_result_chars, remaining_output_chars)
                if len(value) > limit:
                    suffix = "\n[model context truncated]"
                    if limit > len(suffix):
                        value = value[: limit - len(suffix)] + suffix
                    else:
                        value = value[:limit]
                    source["truncated"] = True
                else:
                    value = value[:limit]
                source[key] = value
                remaining_output_chars -= len(value)
            results_reversed.append(source)
        results = list(reversed(results_reversed))
        # Approval nonces/decisions are intentionally excluded from model input.
        memory: list[dict[str, Any]] = []
        if self.memory_lookup is not None:
            try:
                for memory_item in list(self.memory_lookup(str(state.get("goal", ""))))[:8]:
                    safe_value: Any = redact_secrets(dict(memory_item))
                    if isinstance(safe_value, Mapping):
                        safe_item: dict[str, Any] = dict(safe_value)
                        if safe_item.get("sensitivity") == "sensitive":
                            continue
                        safe_item["content"] = str(safe_item.get("content", ""))[:2_000]
                        memory.append(safe_item)
            except Exception:
                # Memory is advisory context; lookup failure must not widen
                # permissions or fail an otherwise safe local run.
                memory = []
        return {
            "status": state.get("status"),
            "assumptions": state.get("assumptions", []),
            "plan": state.get("plan", []),
            "completed": state.get("completed", []),
            "pending": state.get("pending", []),
            "active_files": state.get("active_files", []),
            "test_status": state.get("test_status", []),
            "risks": state.get("risks", []),
            "blockers": state.get("blockers", []),
            "messages": state.get("messages", [])[-8:],
            "conversation": state.get("conversation", [])[-16:],
            "tool_results": results,
            "budget": state.get("budget", {}),
            "usage": state.get("usage", {}),
            "long_term_memory": memory,
        }

    @staticmethod
    def _checkpoint_state(state: AgentState) -> dict[str, Any]:
        allowed = {
            "goal",
            "status",
            "phase",
            "assumptions",
            "plan",
            "completed",
            "pending",
            "active_files",
            "conversation",
            "tool_results",
            "test_status",
            "approvals",
            "blockers",
            "next_action",
            "budget",
            "usage",
            "current_call",
            "approval_request",
        }
        snapshot = {key: state.get(key) for key in sorted(allowed)}
        raw_results = list(state.get("tool_results", []))
        compacted: list[dict[str, Any]] = []
        full_from = max(0, len(raw_results) - 8)
        for index, raw in enumerate(raw_results):
            item = dict(raw)
            if index < full_from:
                item = {
                    key: item.get(key)
                    for key in (
                        "call_id",
                        "action_id",
                        "tool",
                        "host",
                        "cwd",
                        "status",
                        "exit_code",
                        "artifacts",
                        "truncated",
                        "side_effects",
                        "error",
                    )
                }
                item["compacted"] = True
            else:
                for output_key in ("stdout", "stderr"):
                    value = str(item.get(output_key, ""))
                    if len(value) > 8_192:
                        item[output_key] = value[:8_192] + "\n[checkpoint compacted]"
            compacted.append(item)
        snapshot["tool_results"] = compacted
        snapshot["test_status"] = list(state.get("test_status", []))[-64:]
        snapshot["approvals"] = list(state.get("approvals", []))[-32:]
        snapshot["compaction"] = {
            "tool_results_total": len(raw_results),
            "full_tool_results": min(8, len(raw_results)),
            "required_fields_preserved": True,
        }
        return snapshot


__all__ = [
    "AgentState",
    "AsterCodeOrchestrator",
    "GatewayAuthorization",
    "GatewayContext",
    "OrchestratorError",
    "RunBudget",
    "RunUsage",
    "ToolGateway",
]
