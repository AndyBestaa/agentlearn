"""Concrete host gateway joining registry, policy, storage and executors."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import math
import os
import tempfile
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .models import ApprovalDecision, ApprovalRequest, ApprovalStatus, RiskLevel, ToolCall, ToolError, ToolResult, ToolStatus, utc_now
from .orchestrator import GatewayAuthorization, GatewayContext
from .policy import PolicyEngine
from .security import (
    PathAuthorizationError,
    action_hash,
    canonical_json,
    canonicalize_authorized_path,
    redact_secrets,
    sha256_hex,
)
from .tools.base import ToolResult as HostToolResult
from .tools.filesystem import parse_patch
from .tools.registry import ToolRegistry


class LocalToolGateway:
    """Only route to registered host handlers after policy revalidation."""

    def __init__(
        self, registry: ToolRegistry, policy: PolicyEngine, storage: Any | None = None, *, auto_approve: bool = False, dry_run: bool = False
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.storage = storage
        self.auto_approve = auto_approve
        self.dry_run = dry_run
        self.artifact_max_bytes = int(policy.config.security.artifact_max_bytes)
        self._active: dict[str, Any] = {}
        # A successful approval creates a narrow, single-use lease.  The
        # execute phase must consume that lease rather than re-running policy
        # and generating a different nonce/action binding.
        self._approved_actions: dict[str, tuple[str, datetime]] = {}
        self._pending_requests: dict[str, ApprovalRequest] = {}

    async def authorize(self, call: ToolCall, context: GatewayContext, decision: ApprovalDecision | None = None) -> GatewayAuthorization:
        try:
            call = self._bind_call_cwd(call)
        except Exception as exc:
            return GatewayAuthorization(outcome="deny", risk=RiskLevel.P4, reason=f"cwd/path binding failed ({type(exc).__name__})")
        if self.storage is not None:
            try:
                self.storage.save_tool_call(
                    context.session_id,
                    call.call_id,
                    call.action_id,
                    call.tool,
                    call.arguments,
                    turn_id=context.turn_id,
                    status="policy_check",
                )
            except Exception as storage_exc:
                _ = storage_exc
        try:
            self.registry.validate_arguments(call.tool, call.arguments)
            spec, _ = self.registry.get(call.tool)
            evaluated = self.policy.evaluate(call.tool, call.arguments, host=call.host, cwd=call.cwd, declared=spec, purpose=context.goal)
        except Exception as exc:
            return GatewayAuthorization(outcome="deny", risk=RiskLevel.P4, reason=f"policy validation failed ({type(exc).__name__})")
        request = self._pending_requests.get(call.action_id) if decision is not None else evaluated.approval
        if request is None and decision is not None and self.storage is not None:
            persisted = self.storage.get_approval_by_action(call.action_id)
            if persisted is not None:
                persisted.pop("consumed_at", None)
                request = ApprovalRequest.model_validate(persisted)
        if request is not None and request.action_id != call.action_id:
            # Bind the policy-generated request to the orchestrator's stable
            # action id before the single persistence point below. Persisting
            # here and again in ``persist_request`` creates two identical
            # approval.requested audit events for one approval.
            request = request.model_copy(update={"action_id": call.action_id})
        if evaluated.decision == "deny":
            return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason=evaluated.reason)
        if self.dry_run:
            return GatewayAuthorization(outcome="allow", risk=evaluated.risk, reason="dry-run policy preview; execution is disabled")
        if evaluated.decision == "allow":
            return GatewayAuthorization(outcome="allow", risk=evaluated.risk, reason=evaluated.reason)
        if decision is None and self.storage is not None and evaluated.risk in {RiskLevel.P1, RiskLevel.P2}:
            grant = self.storage.find_session_grant(context.session_id, evaluated.action_hash)
            if grant is not None:
                self._approved_actions[call.action_id] = (
                    evaluated.action_hash,
                    datetime.fromisoformat(str(grant["expires_at"])),
                )
                return GatewayAuthorization(
                    outcome="allow",
                    risk=evaluated.risk,
                    reason=f"exact session grant accepted ({grant['grant_id']})",
                )
        if request is None:
            return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason="policy returned no approval request")
        if decision is not None:
            # The action hash is recomputed from the current concrete call;
            # the nonce/request itself must remain the original persisted one.
            if request is None or evaluated.action_hash != request.action_hash:
                if self.storage is not None and request is not None:
                    self.storage.update_approval_status(
                        request.approval_id,
                        ApprovalStatus.REVOKED,
                    )
                self._pending_requests.pop(call.action_id, None)
                return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason="action changed since approval request")
            if not self.policy.verify_decision(request, decision):
                return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason="approval binding, expiry, or nonce mismatch")
            if not decision.approved:
                if self.storage is not None:
                    self.storage.update_approval_status(request.approval_id, ApprovalStatus.DENIED)
                return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason=decision.reason or "user denied")
            if decision.scope == "session" and evaluated.risk not in {RiskLevel.P1, RiskLevel.P2}:
                return GatewayAuthorization(
                    outcome="deny",
                    risk=evaluated.risk,
                    reason="session grants are limited to exact P1/P2 actions",
                )
            if self.storage is not None:
                # Consume before the side effect. If the process crashes after
                # this point, recovery must reconcile an unknown action rather
                # than replay a one-time approval.
                self.storage.update_approval_status(request.approval_id, ApprovalStatus.CONSUMED)
                if decision.scope == "session":
                    self.storage.save_session_grant(context.session_id, request)
            elif decision.scope == "session":
                return GatewayAuthorization(outcome="deny", risk=evaluated.risk, reason="session grants require persistent storage")
            self._approved_actions[call.action_id] = (request.action_hash, request.expires_at)
            return GatewayAuthorization(outcome="allow", risk=evaluated.risk, reason="exact user approval accepted")
        if self.auto_approve and evaluated.risk.rank <= 1:
            self.policy.persist_request(request)
            self.policy.approve(request, actor="local-auto-approve-test")
            if self.storage is not None:
                self.storage.update_approval_status(request.approval_id, ApprovalStatus.CONSUMED)
            self._approved_actions[call.action_id] = (request.action_hash, request.expires_at)
            return GatewayAuthorization(outcome="allow", risk=evaluated.risk, reason="narrow local test auto-approval")
        self.policy.persist_request(request)
        self._pending_requests[call.action_id] = request
        return GatewayAuthorization(outcome="require_approval", risk=evaluated.risk, reason=evaluated.reason, approval_request=request)

    async def execute(self, call: ToolCall, context: GatewayContext) -> ToolResult:
        execution_started = False
        side_effectful = False
        real_paths: list[Any] = []
        try:
            call = self._bind_call_cwd(call)
            self.registry.validate_arguments(call.tool, call.arguments)
            spec, handler = self.registry.get(call.tool)
            # Re-resolve the concrete action, but honor only the exact
            # single-use lease created by authorize for P2+ side effects.
            try:
                evaluated = self.policy.evaluate(
                    call.tool,
                    call.arguments,
                    host=call.host,
                    cwd=call.cwd,
                    declared=spec,
                    purpose=context.goal,
                )
            except Exception as exc:
                return self._finalize_result(
                    call,
                    context,
                    self._failure(
                        call,
                        "policy_denied",
                        f"policy revalidation failed ({type(exc).__name__})",
                    ),
                )
            if self.dry_run:
                now = utc_now()
                return self._finalize_result(
                    call,
                    context,
                    ToolResult(
                        call_id=call.call_id,
                        action_id=call.action_id,
                        tool=call.tool,
                        host=call.host,
                        cwd=call.cwd,
                        started_at=now,
                        ended_at=utc_now(),
                        status=ToolStatus.COMPLETED,
                        stdout="dry-run: no handler was executed",
                        metadata={
                            "dry_run": True,
                            "effective_risk": evaluated.risk.value,
                            "normalized_action": evaluated.normalized_action,
                        },
                    ),
                )
            lease = self._approved_actions.get(call.action_id)
            approved_side_effect = False
            if lease is not None:
                expected_hash, expires_at = lease
                if expected_hash != evaluated.action_hash or datetime.now(UTC) >= expires_at:
                    self._approved_actions.pop(call.action_id, None)
                    return self._finalize_result(
                        call,
                        context,
                        self._failure(
                            call,
                            "approval_binding_mismatch",
                            "approved action changed or expired",
                        ),
                    )
                self._approved_actions.pop(call.action_id, None)
                approved_side_effect = True
            elif evaluated.decision != "allow":
                return self._finalize_result(
                    call,
                    context,
                    self._failure(
                        call,
                        "policy_denied",
                        "execute called without an accepted approval",
                    ),
                )
            arguments = dict(call.arguments)
            timeout_limits = [float(getattr(spec, "timeout_seconds", getattr(spec, "timeout", 30.0)))]
            if context.execution_timeout_seconds is not None:
                timeout_limits.append(context.execution_timeout_seconds)
            proposed_timeout = arguments.get("timeout")
            if proposed_timeout is not None:
                if (
                    not isinstance(proposed_timeout, (int, float))
                    or isinstance(proposed_timeout, bool)
                    or not math.isfinite(float(proposed_timeout))
                    or float(proposed_timeout) <= 0
                ):
                    return self._finalize_result(
                        call,
                        context,
                        self._failure(
                            call,
                            "invalid_timeout",
                            "tool timeout must be a positive finite number",
                        ),
                    )
                timeout_limits.append(float(proposed_timeout))
            effective_timeout = min(timeout_limits)
            if effective_timeout <= 0 or not math.isfinite(effective_timeout):
                return self._finalize_result(
                    call,
                    context,
                    self._failure(
                        call,
                        "invalid_timeout",
                        "tool timeout boundary is invalid",
                    ),
                )
            if "timeout" in arguments:
                # A lower runtime value is a safety narrowing of the already
                # authorised action; it cannot expand the approval scope.
                arguments["timeout"] = effective_timeout
            side_effectful = bool(getattr(spec, "side_effects", ()))
            workspace_effects = {
                "file_write",
                "directory_create",
                "path_move",
                "path_delete",
                "git_commit",
                "workspace_write",
            }
            workspace_write = bool(workspace_effects.intersection(getattr(spec, "side_effects", ()))) or call.tool in {
                "ssh.download",
                "browser.download",
            }
            if call.tool == "fs.apply_patch":
                # The tool schema keeps the patch payload small; cwd comes
                # from the already-normalised ToolCall envelope and cannot be
                # redirected by model-supplied arguments.
                arguments["cwd"] = call.cwd
            if call.tool in {"process.exec", "shell.exec", "process.start"} and approved_side_effect:
                # This flag is host-generated only after an exact process-launch approval;
                # it is never accepted from model-supplied arguments.
                arguments["allow_unsandboxed"] = True
            if self.storage is not None:
                normalized_paths = evaluated.normalized_action.get("real_paths", [])
                real_paths = normalized_paths if isinstance(normalized_paths, list) else []
                path_evidence = self._path_evidence(real_paths if isinstance(real_paths, list) else [])
                # This record is deliberately written before crossing the
                # side-effect boundary. A crash after this point is recovered
                # as unknown and must be reconciled read-only, never replayed.
                self.storage.save_checkpoint(
                    {
                        "session_id": context.session_id,
                        "turn_id": context.turn_id,
                        "phase": "PRE_TOOL_CALL",
                        "action_id": call.action_id,
                        "state": {
                            "call_id": call.call_id,
                            "action_id": call.action_id,
                            "tool": call.tool,
                            "host": call.host,
                            "cwd": call.cwd,
                            "status": "unknown" if side_effectful else "prepared",
                            "normalized_action": evaluated.normalized_action,
                            "pre_evidence": path_evidence,
                        },
                    }
                )
            lock = (
                self.storage.workspace_write_lock(
                    call.cwd,
                    timeout_seconds=effective_timeout,
                )
                if self.storage is not None and workspace_write and call.host == "local" and call.cwd
                else nullcontext()
            )
            raw: Any
            with lock:
                if approved_side_effect and lease is not None:
                    expected_hash, _expires_at = lease
                    current_normalized = self.policy.normalize(
                        call.tool,
                        call.arguments,
                        host=call.host,
                        cwd=call.cwd,
                    )
                    if action_hash(current_normalized) != expected_hash:
                        raw = self._failure(
                            call,
                            "approval_binding_mismatch",
                            "approved path state changed before execution",
                        )
                    else:
                        execution_started = True
                        async with asyncio.timeout(effective_timeout):
                            if inspect.iscoroutinefunction(handler):
                                raw = await handler(**arguments)
                            else:
                                # File/Git/process handlers are synchronous OS calls. Keep
                                # them off the event loop so cancellation and kill-switch
                                # signals remain responsive while a command is running.
                                raw = await asyncio.to_thread(handler, **arguments)
                            if inspect.isawaitable(raw):
                                raw = await raw
                else:
                    execution_started = True
                    async with asyncio.timeout(effective_timeout):
                        if inspect.iscoroutinefunction(handler):
                            raw = await handler(**arguments)
                        else:
                            raw = await asyncio.to_thread(handler, **arguments)
                        if inspect.isawaitable(raw):
                            raw = await raw
            result = self._coerce_result(raw, call)
            if (
                execution_started
                and side_effectful
                and isinstance(result.error, ToolError)
                and result.error.code == "invalid_tool_result"
            ):
                # Once a side-effect boundary has been crossed, an invalid
                # executor envelope cannot prove that nothing happened. Keep
                # the action unknown so recovery reconciles instead of retrying.
                result = self._unknown(
                    call,
                    "invalid_tool_result_state_unknown",
                    "side-effecting tool returned an invalid result; action state is unknown",
                )
            return self._finalize_result(
                call,
                context,
                result,
                real_paths=real_paths,
                side_effectful=side_effectful,
                execution_started=execution_started,
            )
        except asyncio.CancelledError:
            if execution_started and side_effectful:
                cancelled_result = self._unknown(
                    call,
                    "tool_cancelled_state_unknown",
                    "tool was cancelled after entering a side-effect boundary; action state is unknown",
                )
            else:
                now = utc_now()
                cancelled_result = ToolResult(
                    call_id=call.call_id,
                    action_id=call.action_id,
                    tool=call.tool,
                    host=call.host,
                    cwd=call.cwd,
                    started_at=now,
                    ended_at=utc_now(),
                    status=ToolStatus.CANCELLED,
                    error=ToolError(
                        code="tool_cancelled",
                        message="tool was cancelled before a side effect was confirmed",
                        retryable=False,
                    ),
                )
            self._finalize_result(
                call,
                context,
                cancelled_result,
                real_paths=real_paths,
                side_effectful=side_effectful,
                execution_started=execution_started,
            )
            raise
        except TimeoutError:
            if execution_started and side_effectful:
                result = self._unknown(
                    call,
                    "tool_timeout",
                    "tool timed out; side-effect state is unknown",
                )
            else:
                now = utc_now()
                result = ToolResult(
                    call_id=call.call_id,
                    action_id=call.action_id,
                    tool=call.tool,
                    host=call.host,
                    cwd=call.cwd,
                    started_at=now,
                    ended_at=utc_now(),
                    status=ToolStatus.TIMEOUT,
                    error=ToolError(
                        code="tool_timeout",
                        message="tool exceeded its host-enforced execution timeout",
                        retryable=False,
                    ),
                )
            return self._finalize_result(
                call,
                context,
                result,
                real_paths=real_paths,
                side_effectful=side_effectful,
                execution_started=execution_started,
            )
        except Exception as exc:
            if execution_started and side_effectful:
                result = self._unknown(
                    call,
                    "executor_state_unknown",
                    f"executor state is unknown ({type(exc).__name__})",
                )
            else:
                result = self._failure(
                    call,
                    "executor_error",
                    f"executor failed ({type(exc).__name__})",
                )
            return self._finalize_result(
                call,
                context,
                result,
                real_paths=real_paths,
                side_effectful=side_effectful,
                execution_started=execution_started,
            )

    def _finalize_result(
        self,
        call: ToolCall,
        context: GatewayContext,
        result: ToolResult,
        *,
        real_paths: list[Any] | None = None,
        side_effectful: bool = False,
        execution_started: bool = False,
    ) -> ToolResult:
        """Persist every terminal tool result, including pre-execution failures."""

        paths = real_paths or []
        try:
            self._track_process(call, context, result)
            self._artifactize(result, context.session_id)
        except Exception as exc:
            result = (
                self._unknown(
                    call,
                    "executor_state_unknown",
                    f"post-execution capture state is unknown ({type(exc).__name__})",
                )
                if execution_started and side_effectful
                else self._failure(
                    call,
                    "executor_error",
                    f"result capture failed ({type(exc).__name__})",
                )
            )
        if self.storage is None:
            return result
        try:
            self.storage.save_tool_call(
                context.session_id,
                call.call_id,
                call.action_id,
                call.tool,
                call.arguments,
                turn_id=context.turn_id,
                result=result.as_dict(),
                status=result.status.value,
                ended_at=result.ended_at.isoformat(),
            )
            self.storage.save_checkpoint(
                {
                    "session_id": context.session_id,
                    "turn_id": context.turn_id,
                    "phase": "POST_TOOL_CALL",
                    "action_id": call.action_id,
                    "state": {
                        "call_id": call.call_id,
                        "action_id": call.action_id,
                        "tool": call.tool,
                        "host": call.host,
                        "cwd": call.cwd,
                        "result": result.as_dict(),
                        "post_evidence": self._path_evidence(paths),
                    },
                }
            )
        except Exception:
            if execution_started and side_effectful:
                unknown = self._unknown(
                    call,
                    "checkpoint_failed",
                    "post-action checkpoint could not be persisted",
                )
                try:
                    self.storage.save_tool_call(
                        context.session_id,
                        call.call_id,
                        call.action_id,
                        call.tool,
                        call.arguments,
                        turn_id=context.turn_id,
                        result=unknown.as_dict(),
                        status=unknown.status.value,
                        ended_at=unknown.ended_at.isoformat(),
                    )
                except Exception:
                    pass
                return unknown
        return result

    async def verify(self, result: ToolResult, context: GatewayContext) -> Mapping[str, Any]:
        # Verification is intentionally evidence-based and does not infer
        # success from a model message.  Read-only tool results are already
        # complete; unknown process results remain unknown.
        evidence: dict[str, Any] = {"verified": result.status is ToolStatus.COMPLETED, "evidence": result.exit_code}
        if result.metadata.get("dry_run") is True:
            return {"verified": False, "dry_run": True, "evidence": "no handler executed"}
        if result.tool in {"process.start", "ssh.start"}:
            running = bool(result.error is None and result.status is ToolStatus.COMPLETED)
            evidence.update(
                verified=False,
                running=running,
                evidence="process handle returned; completion requires poll/stop",
            )
        return evidence

    async def cancel(self, session_id: str) -> None:
        executors = list(self._active.values())
        providers = getattr(self.registry, "providers", None)
        if callable(providers):
            executors.extend(providers())
        seen: set[int] = set()
        for process in executors:
            if id(process) in seen:
                continue
            seen.add(id(process))
            stop_session = getattr(process, "stop_session", None)
            if stop_session is not None:
                value = stop_session(session_id)
                if inspect.isawaitable(value):
                    await value
                continue
            stop = getattr(process, "stop_all", None)
            if stop is not None:
                value = stop()
                if inspect.isawaitable(value):
                    await value
        if self.storage is None:
            return
        for record in self.storage.list_active_processes(session_id=session_id):
            stopped = False
            if record.get("host") == "local":
                for executor in executors:
                    identity_reader = getattr(executor, "process_identity", None)
                    terminator = getattr(executor, "terminate_registered", None)
                    if identity_reader is None or terminator is None:
                        continue
                    current = identity_reader(int(record["pid"]))
                    expected = record.get("identity_token")
                    if current == "missing" or (isinstance(expected, str) and isinstance(current, str) and current != expected):
                        stopped = True
                    else:
                        stopped = bool(terminator(int(record["pid"]), expected))
                    break
            self.storage.mark_process_stopped(str(record["action_id"]), status="stopped" if stopped else "unknown")

    @staticmethod
    def _coerce_result(raw: Any, call: ToolCall) -> ToolResult:
        if isinstance(raw, ToolResult):
            return raw.model_copy(
                update={"call_id": call.call_id, "action_id": call.action_id, "tool": call.tool, "host": call.host, "cwd": call.cwd}
            )
        if isinstance(raw, HostToolResult):
            payload = raw.as_dict()
        elif isinstance(raw, Mapping):
            payload = dict(raw)
            supplied_status = payload.get("status")
            status_text = (
                supplied_status.value
                if isinstance(supplied_status, ToolStatus)
                else supplied_status
            )
            valid_statuses = {item.value for item in ToolStatus}
            missing_failure_evidence = (
                status_text
                in {
                    ToolStatus.FAILED.value,
                    ToolStatus.TIMEOUT.value,
                    ToolStatus.CANCELLED.value,
                }
                and payload.get("error") is None
            )
            if status_text not in valid_statuses or missing_failure_evidence:
                payload = {
                    "status": "failed",
                    "error": ToolError(
                        code="invalid_tool_result",
                        message="registered tool returned an invalid result mapping",
                        retryable=False,
                    ),
                }
        else:
            payload = {
                "status": "failed",
                "error": ToolError(
                    code="invalid_tool_result",
                    message=(
                        "registered tool returned an unsupported result type "
                        f"({type(raw).__name__})"
                    ),
                    retryable=False,
                ),
            }
        started = payload.get("started_at") or utc_now()
        ended = payload.get("ended_at") or utc_now()
        if isinstance(started, str):
            started = datetime.fromisoformat(started)
        if isinstance(ended, str):
            ended = datetime.fromisoformat(ended)
        status = payload.get("status", "completed")
        try:
            status = ToolStatus(status)
        except ValueError:
            status = ToolStatus.FAILED
        error = payload.get("error")
        if isinstance(error, str):
            error = ToolError(code="tool_error", message=redact_secrets(error), retryable=False)
        metadata = redact_secrets(payload.get("metadata", {}))
        return ToolResult(
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
            started_at=started,
            ended_at=ended,
            status=status,
            exit_code=payload.get("exit_code"),
            stdout=str(redact_secrets(payload.get("stdout", ""))),
            stderr=str(redact_secrets(payload.get("stderr", ""))),
            artifacts=payload.get("artifacts", []),
            truncated=bool(payload.get("truncated", False)),
            side_effects=list(payload.get("side_effects", [])),
            error=error,
            metadata=dict(metadata) if isinstance(metadata, Mapping) else {},
        )

    def _artifactize(self, result: ToolResult, session_id: str) -> None:
        if self.storage is None:
            return
        artifact_dir = self.storage.config.artifacts_dir
        self.storage.guard_artifacts_dir()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        for label in ("stdout", "stderr"):
            value = getattr(result, label)
            capture = result.metadata.get("capture")
            capture_stream = capture.get(label) if isinstance(capture, Mapping) else None
            source_complete = True
            incomplete_reasons: list[str] = []
            if isinstance(capture_stream, Mapping):
                drain_complete = capture_stream.get("complete") is True
                capture_truncated = capture_stream.get("truncated") is True
                content_complete = capture_stream.get("content_complete")
                source_complete = (
                    content_complete is True
                    if "content_complete" in capture_stream
                    else drain_complete and not capture_truncated and capture_stream.get("error") is None
                )
                discarded_bytes = capture_stream.get("discarded_bytes")
                discarded_chars = capture_stream.get("discarded_chars")
                if (isinstance(discarded_bytes, int) and not isinstance(discarded_bytes, bool) and discarded_bytes > 0) or (
                    isinstance(discarded_chars, int) and not isinstance(discarded_chars, bool) and discarded_chars > 0
                ):
                    incomplete_reasons.append("capture_retention_limit")
                elif capture_truncated:
                    incomplete_reasons.append("capture_truncated")
                if not drain_complete:
                    incomplete_reasons.append("capture_not_complete")
                if capture_stream.get("error") is not None:
                    incomplete_reasons.append("capture_error")
            if len(value) <= 65_536 and source_complete:
                continue
            safe = str(redact_secrets(value))
            encoded = safe.encode("utf-8")
            source_marker = b"\n[artifact incomplete: process capture did not retain all output]\n" if not source_complete else b""
            payload = encoded + source_marker
            disk_complete = len(payload) <= self.artifact_max_bytes
            marker = b"\n[artifact truncated by disk budget]\n"
            stored = payload if disk_complete else payload[: max(0, self.artifact_max_bytes - len(marker))] + marker
            complete = source_complete and disk_complete
            if not disk_complete:
                incomplete_reasons.append("artifact_disk_budget")
            digest = hashlib.sha256(stored).hexdigest()
            path = artifact_dir / f"{result.action_id}-{label}.txt"
            temporary: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=artifact_dir,
                    prefix=f".{path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as stream:
                    temporary = stream.name
                    stream.write(stored)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                temporary = None
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
            artifact_id = self.storage.save_artifact(session_id, str(path), len(stored), digest)
            result.artifacts.append(artifact_id)
            setattr(result, label, safe[:32_000] + "\n[output truncated; see artifact]")
            result.truncated = True
            result.metadata.setdefault("artifacts", {})[label] = {
                "complete": complete,
                "original_bytes": len(encoded),
                "captured_redacted_bytes": len(encoded),
                "stored_bytes": len(stored),
                "source_complete": source_complete,
                "disk_complete": disk_complete,
                "source_observed_bytes": (capture_stream.get("observed_bytes") if isinstance(capture_stream, Mapping) else len(encoded)),
                "source_retained_bytes": (capture_stream.get("retained_bytes") if isinstance(capture_stream, Mapping) else len(encoded)),
                "source_discarded_bytes": (capture_stream.get("discarded_bytes") if isinstance(capture_stream, Mapping) else 0),
                "incomplete_reasons": incomplete_reasons,
                "sha256": digest,
            }

    def _track_process(self, call: ToolCall, context: GatewayContext, result: ToolResult) -> None:
        """Persist long-running process identity for kill/reconcile across restarts."""

        if self.storage is None:
            return
        if call.tool == "process.start" and result.status in {
            ToolStatus.COMPLETED,
            ToolStatus.UNKNOWN,
        }:
            pid = result.metadata.get("pid")
            identity = result.metadata.get("identity_token")
            metadata_handle = result.metadata.get("process_handle")
            handle = metadata_handle if isinstance(metadata_handle, str) else result.stdout.strip()
            if isinstance(pid, int) and handle:
                self.storage.register_process(
                    handle,
                    context.session_id,
                    pid,
                    host=call.host,
                    identity_token=identity if isinstance(identity, str) else None,
                    argv_hash=sha256_hex(canonical_json(call.arguments)),
                )
        elif call.tool == "process.exec" and result.status is ToolStatus.UNKNOWN:
            pid = result.metadata.get("pid")
            identity = result.metadata.get("identity_token")
            process_handle = result.metadata.get("process_handle")
            if isinstance(pid, int):
                self.storage.register_process(
                    process_handle if isinstance(process_handle, str) else call.action_id,
                    context.session_id,
                    pid,
                    host=call.host,
                    identity_token=identity if isinstance(identity, str) else None,
                    argv_hash=sha256_hex(canonical_json(call.arguments)),
                )
        if call.tool in {"process.poll", "process.stop"} and result.status is ToolStatus.COMPLETED:
            tracked_handle = call.arguments.get("action_id")
            if isinstance(tracked_handle, str):
                try:
                    self.storage.mark_process_stopped(tracked_handle)
                except KeyError:
                    pass

    def _path_evidence(self, paths: list[Any]) -> list[dict[str, Any]]:
        """Capture bounded read-only evidence for crash reconciliation."""

        evidence: list[dict[str, Any]] = []
        for raw in paths[:64]:
            if not isinstance(raw, str):
                continue
            item: dict[str, Any] = {"path": raw}
            try:
                checked = canonicalize_authorized_path(
                    raw,
                    self.policy.config.security.authorized_roots,
                    cwd=self.policy.config.project_root,
                    must_exist=False,
                    reject_unc=self.policy.config.security.reject_unc_paths,
                )
                checked = checked.revalidate(
                    self.policy.config.security.authorized_roots,
                    must_exist=False,
                    reject_unc=self.policy.config.security.reject_unc_paths,
                )
                path = checked.resolved
                item["path"] = str(path)
                if not path.exists():
                    item.update(exists=False, kind="missing")
                elif path.is_file():
                    stat = path.stat()
                    item.update(exists=True, kind="file", size=stat.st_size, mtime_ns=stat.st_mtime_ns)
                    if stat.st_size <= 67_108_864:
                        digest = hashlib.sha256()
                        with path.open("rb") as stream:
                            for chunk in iter(lambda: stream.read(1_048_576), b""):
                                digest.update(chunk)
                        item["sha256"] = digest.hexdigest()
                    else:
                        item["sha256"] = None
                        item["hash_status"] = "too_large"
                elif path.is_dir():
                    stat = path.stat()
                    item.update(exists=True, kind="directory", mtime_ns=stat.st_mtime_ns)
                else:
                    item.update(exists=True, kind="other")
            except PathAuthorizationError:
                item.update(
                    exists=None,
                    kind="blocked",
                    error="outside_authorized_roots",
                )
            except OSError as exc:
                item.update(exists=None, error=type(exc).__name__)
            evidence.append(item)
        return evidence

    @staticmethod
    def _failure(call: ToolCall, code: str, message: str) -> ToolResult:
        now = utc_now()
        return ToolResult(
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
            started_at=now,
            ended_at=utc_now(),
            status=ToolStatus.FAILED,
            error=ToolError(code=code, message=message, retryable=False),
        )

    @staticmethod
    def _unknown(call: ToolCall, code: str, message: str) -> ToolResult:
        now = utc_now()
        return ToolResult(
            call_id=call.call_id,
            action_id=call.action_id,
            tool=call.tool,
            host=call.host,
            cwd=call.cwd,
            started_at=now,
            ended_at=utc_now(),
            status=ToolStatus.UNKNOWN,
            side_effects=["possible_unconfirmed_side_effect"],
            error=ToolError(code=code, message=message, retryable=False),
        )

    def _bind_call_cwd(self, call: ToolCall) -> ToolCall:
        """Make the top-level, host-resolved cwd the sole execution authority."""
        roots = self.policy.config.security.authorized_roots
        raw_cwd = call.cwd or str(self.policy.config.project_root)
        checked_cwd = canonicalize_authorized_path(raw_cwd, roots, must_exist=True, reject_unc=self.policy.config.security.reject_unc_paths)
        effective_cwd = str(checked_cwd.resolved)
        arguments = dict(call.arguments)
        if call.tool == "fs.apply_patch" and isinstance(arguments.get("patch"), str):
            arguments["patch"] = self._normalize_update_patch_separators(
                str(arguments["patch"]), effective_cwd
            )
        if call.tool.startswith("fs."):
            path_rules = {
                "fs.list": {"path": False},
                # A missing read target is a normal observation (for example,
                # stat-before-create). Authorize its nearest existing parent
                # here, then let the concrete read handler report not-found.
                # Existing symlink/reparse escapes are still rejected during
                # canonicalization and again by the handler.
                "fs.stat": {"path": False},
                "fs.read": {"path": False},
                "fs.search": {"path": False},
                "fs.mkdir": {"path": False},
                "fs.move": {"source": True, "destination": False},
                "fs.delete": {"path": True},
            }.get(call.tool, {})
            for key, must_exist in path_rules.items():
                value = arguments.get(key)
                if isinstance(value, str):
                    if call.tool in {
                        "fs.list",
                        "fs.stat",
                        "fs.read",
                        "fs.search",
                    }:
                        # A live model may express the abstract workspace root
                        # as an empty string or a container-style marker. The
                        # model has no host path authority, so map only these
                        # exact markers for read-only tools. Never do this for
                        # writes, moves or deletes: a blank destructive target
                        # must continue to fail closed.
                        marker = value.strip().replace("\\", "/").rstrip("/")
                        if marker in {"", "/", "/workspace", "workspace"}:
                            value = effective_cwd
                    checked = canonicalize_authorized_path(
                        value, roots, cwd=effective_cwd, must_exist=must_exist, reject_unc=self.policy.config.security.reject_unc_paths
                    )
                    arguments[key] = str(checked.resolved)
        elif call.tool.startswith("git.") or call.tool in {"process.exec", "process.start", "shell.exec"}:
            arguments["cwd"] = effective_cwd
        return call.model_copy(update={"cwd": effective_cwd, "arguments": arguments})

    def _normalize_update_patch_separators(self, patch: str, cwd: str) -> str:
        """Repair one unambiguous model formatting variant for update patches.

        Some models emit ``- old``/``+ new`` although AsterCode's exact patch
        grammar uses ``-old``/``+new``.  The host may remove that one separator
        only when the original old context fails and the repaired old context
        matches every authorized target exactly.  Adds and ambiguous updates
        are left untouched and fail closed in normal policy validation.
        """

        try:
            changes = parse_patch(patch)
            updates = [(path, old) for path, old, _new in changes if old is not None]
            if not updates:
                return patch

            roots = self.policy.config.security.authorized_roots

            def contexts_match(items: list[tuple[str, str | None, str]]) -> bool:
                found_update = False
                for path_text, old, _new in items:
                    if old is None:
                        continue
                    found_update = True
                    checked = canonicalize_authorized_path(
                        path_text,
                        roots,
                        cwd=cwd,
                        must_exist=True,
                        reject_unc=self.policy.config.security.reject_unc_paths,
                    )
                    raw = checked.resolved.read_bytes()
                    encoding = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
                    current = raw.decode(encoding).replace("\r\n", "\n")
                    if old.replace("\r\n", "\n") not in current:
                        return False
                return found_update

            if contexts_match(changes):
                return patch

            repaired_lines: list[str] = []
            in_update = False
            for line in patch.splitlines():
                if line.startswith("*** Update File:"):
                    in_update = True
                elif line.startswith(("*** Add File:", "*** Delete File:")):
                    in_update = False
                elif line == "*** End Patch":
                    in_update = False
                if (
                    in_update
                    and len(line) >= 3
                    and line[0] in {"-", "+"}
                    and line[1] == " "
                    and line[2] != " "
                ):
                    line = line[0] + line[2:]
                repaired_lines.append(line)
            repaired = "\n".join(repaired_lines)
            if patch.endswith("\n"):
                repaired += "\n"
            return repaired if contexts_match(parse_patch(repaired)) else patch
        except (OSError, UnicodeError, ValueError, PathAuthorizationError):
            return patch


__all__ = ["LocalToolGateway"]
