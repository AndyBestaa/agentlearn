"""Run an explicitly approved live create/modify/delete chat cycle.

This script is intentionally excluded from offline CI. It requires an already
configured live provider in the process environment and a dedicated workspace
whose ``.astercode`` state directory already exists. It never prints secrets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from astercode.security import redact_secrets
from astercode.tools.filesystem import parse_patch


@dataclass(frozen=True)
class Step:
    name: str
    prompt: str
    expected_tool: str | None
    expected_content: bytes | None
    expected_risk: str | None


class Transcript:
    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process
        self.text = ""
        self.closed = False
        self.condition = threading.Condition()
        thread = threading.Thread(target=self._pump, daemon=True)
        thread.start()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        while True:
            character = self.process.stdout.read(1)
            if character == "":
                break
            with self.condition:
                self.text += character
                self.condition.notify_all()
        with self.condition:
            self.closed = True
            self.condition.notify_all()

    def snapshot(self) -> str:
        with self.condition:
            return self.text

    def wait_any(
        self,
        tokens: tuple[str, ...],
        start: int,
        *,
        timeout: float,
    ) -> tuple[str, int, int]:
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                matches = []
                for token in tokens:
                    index = self.text.find(token, start)
                    if index >= 0:
                        matches.append((index, token))
                if matches:
                    index, token = min(matches)
                    return token, index, index + len(token)
                if self.closed or self.process.poll() is not None:
                    raise RuntimeError(
                        f"aster exited early with code {self.process.poll()}; "
                        f"tail={redact_secrets(self.text[-2_000:])!r}"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"timeout waiting for {tokens}; "
                        f"tail={redact_secrets(self.text[-2_000:])!r}"
                    )
                self.condition.wait(min(remaining, 1.0))


def _connect_readonly(database: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{database.as_posix()}?mode=ro",
        uri=True,
        timeout=5,
    )
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _session_ids(database: Path) -> set[str]:
    with _connect_readonly(database) as connection:
        return {
            str(row[0])
            for row in connection.execute("SELECT session_id FROM sessions")
        }


def _current_approval(database: Path, session_id: str) -> dict[str, Any]:
    with _connect_readonly(database) as connection:
        row = connection.execute(
            "SELECT status, state_json FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError(f"session disappeared: {session_id}")
        if str(row[0]) != "waiting_approval":
            raise RuntimeError(f"session is not waiting_approval: {row[0]!r}")
        state = json.loads(str(row[1]))
        request = state.get("approval_request")
        if not isinstance(request, dict):
            raise RuntimeError("waiting session has no approval_request")
        persisted = connection.execute(
            "SELECT action_id, status FROM approvals WHERE approval_id=?",
            (request.get("approval_id"),),
        ).fetchone()
        if persisted is None:
            raise RuntimeError("approval request was not persisted")
        if str(persisted[0]) != request.get("action_id") or str(persisted[1]) != "pending":
            raise RuntimeError("persisted approval binding/status mismatch")
        return request


def _same_path(left: str | Path, right: Path) -> bool:
    return os.path.normcase(str(Path(left).resolve(strict=False))) == os.path.normcase(
        str(right.resolve(strict=False))
    )


def _validate_approval(
    request: dict[str, Any],
    *,
    step: Step,
    root: Path,
    target: Path,
) -> str:
    if request.get("tool") != step.expected_tool:
        raise RuntimeError(f"unexpected approval tool: {request.get('tool')!r}")
    if request.get("risk") != step.expected_risk:
        raise RuntimeError(f"unexpected approval risk: {request.get('risk')!r}")
    if request.get("host") != "local":
        raise RuntimeError(f"unexpected approval host: {request.get('host')!r}")
    if not _same_path(str(request.get("cwd", "")), root):
        raise RuntimeError(f"unexpected approval cwd: {request.get('cwd')!r}")
    real_paths = request.get("real_paths")
    if not isinstance(real_paths, list) or len(real_paths) != 1:
        raise RuntimeError(f"approval must bind exactly one real path: {real_paths!r}")
    if not _same_path(str(real_paths[0]), target):
        raise RuntimeError(f"approval target mismatch: {real_paths!r}")
    for field in ("approval_id", "action_id", "action_hash", "nonce"):
        value = request.get(field)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"approval is missing {field}")

    normalized = request.get("normalized_action")
    if not isinstance(normalized, dict):
        raise RuntimeError("approval has no normalized_action")
    arguments = normalized.get("arguments")
    if not isinstance(arguments, dict):
        raise RuntimeError("approval has no normalized arguments")
    if step.expected_tool == "fs.apply_patch":
        patch = arguments.get("patch")
        if not isinstance(patch, str):
            raise RuntimeError("patch approval has no patch text")
        if not isinstance(request.get("diff_hash"), str):
            raise RuntimeError("patch approval has no diff_hash")
        changes = parse_patch(patch)
        if len(changes) != 1:
            raise RuntimeError(f"patch does not bind only {target.name}")
        patch_path = Path(changes[0][0])
        resolved_patch_path = patch_path if patch_path.is_absolute() else root / patch_path
        if not _same_path(resolved_patch_path, target):
            raise RuntimeError(f"patch does not bind only {target.name}")
        if step.expected_content is None:
            raise RuntimeError("patch step has no expected content")
        if request.get("diff_hash") != hashlib.sha256(patch.encode()).hexdigest():
            raise RuntimeError("patch diff_hash does not match the exact patch text")
        _path, old, new = changes[0]
        if old is None:
            if os.path.lexists(target):
                raise RuntimeError("add patch target already exists")
            candidate = new
        else:
            if not target.is_file() or target.is_symlink():
                raise RuntimeError("update patch target is not one regular file")
            current = target.read_text(encoding="utf-8").replace("\r\n", "\n")
            old_normalized = old.replace("\r\n", "\n")
            if old_normalized not in current:
                raise RuntimeError("update patch old context does not match")
            candidate = current.replace(
                old_normalized,
                new.replace("\r\n", "\n"),
                1,
            )
        if candidate.encode() != step.expected_content:
            raise RuntimeError("approved patch would not produce the exact expected bytes")
    elif step.expected_tool == "fs.delete":
        if request.get("diff_hash") is not None:
            raise RuntimeError("delete approval unexpectedly contains diff_hash")
        if bool(arguments.get("recursive")):
            raise RuntimeError("recursive delete must never be auto-approved")
        if not _same_path(str(arguments.get("path", "")), target):
            raise RuntimeError(f"delete target mismatch: {arguments.get('path')!r}")
        is_junction = bool(getattr(target, "is_junction", lambda: False)())
        if not target.is_file() or target.is_symlink() or is_junction:
            raise RuntimeError("delete target is not the expected regular test file")
    else:
        raise RuntimeError(f"unsupported approval tool: {step.expected_tool!r}")
    return str(request["approval_id"])


def _send(process: subprocess.Popen[str], line: str) -> None:
    assert process.stdin is not None
    process.stdin.write(line + "\n")
    process.stdin.flush()


def _steps(target_name: str) -> list[Step]:
    def content(value: str) -> bytes:
        return f'VALUE = "{value}"\nprint(VALUE)\n'.encode()

    return [
        Step(
            "chat",
            "Hello. Reply briefly without calling tools.",
            None,
            None,
            None,
        ),
        Step(
            "cycle1-create",
            f'First call git.status exactly once to inspect this non-Git workspace. Treat its expected failure as an observation and continue in the same turn. Then create only {target_name} with exactly two lines: VALUE = "cycle1" and print(VALUE). Use fs.apply_patch exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify the bytes. Do not run code.',
            "fs.apply_patch",
            content("cycle1"),
            "P1",
        ),
        Step(
            "cycle1-modify",
            f'Modify only {target_name} so its exact content becomes two lines: VALUE = "cycle1-modified" and print(VALUE). Use fs.apply_patch exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify the bytes. Do not run code.',
            "fs.apply_patch",
            content("cycle1-modified"),
            "P1",
        ),
        Step(
            "cycle1-delete",
            f'Delete only {target_name} with fs.delete and recursive=false exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify it is absent.',
            "fs.delete",
            None,
            "P2",
        ),
        Step(
            "cycle2-create",
            f'Create only {target_name} with exactly two lines: VALUE = "cycle2" and print(VALUE). Use fs.apply_patch exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify the bytes. Do not run code.',
            "fs.apply_patch",
            content("cycle2"),
            "P1",
        ),
        Step(
            "cycle2-modify",
            f'Modify only {target_name} so its exact content becomes two lines: VALUE = "cycle2-modified" and print(VALUE). Use fs.apply_patch exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify the bytes. Do not run code.',
            "fs.apply_patch",
            content("cycle2-modified"),
            "P1",
        ),
        Step(
            "cycle2-delete",
            f'Delete only {target_name} with fs.delete and recursive=false exactly once. After it succeeds, make no more tool calls and report completion; the host test will verify it is absent.',
            "fs.delete",
            None,
            "P2",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--target", default="chat_cycle.py")
    parser.add_argument("--step-timeout", type=float, default=180.0)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    if Path(args.target).name != args.target or (os.name == "nt" and ":" in args.target):
        raise RuntimeError("--target must be one plain filename")
    target = root / args.target
    database = root / ".astercode" / "astercode.db"
    if (root / ".git").exists() or (root / ".git").is_symlink():
        raise RuntimeError("live non-Git recovery smoke requires a workspace without .git")
    is_junction = bool(getattr(target, "is_junction", lambda: False)())
    if os.path.lexists(target) or is_junction:
        raise RuntimeError(f"refusing to overwrite pre-existing test target: {target}")
    if not database.is_file():
        raise RuntimeError(f"AsterCode state database is missing: {database}")
    before_ids = _session_ids(database)

    env = dict(os.environ)
    provider = env.get("ASTERCODE_MODEL_PROVIDER", "").strip()
    model = env.get("ASTERCODE_MODEL_ID", "").strip()
    key_name = "DEEPSEEK_API_KEY" if provider == "deepseek" else "OPENAI_API_KEY"
    if not provider or not model or not env.get(key_name, "").strip():
        raise RuntimeError("live provider/model/key are not present in the process environment")
    env.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "NO_COLOR": "1",
            "COLUMNS": "220",
        }
    )
    command_prefix = [sys.executable, "-m", "astercode"]
    chat_command = [*command_prefix, "chat", "--root", str(root)]
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        chat_command,
        cwd=root,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=0,
        creationflags=creationflags,
    )
    transcript = Transcript(process)
    prompt_token = "\u4f60: "
    approval_token = "[q]:"
    cursor = 0
    approvals: list[str] = []
    session_id: str | None = None

    try:
        _token, _index, cursor = transcript.wait_any(
            (prompt_token,), cursor, timeout=30
        )
        startup = transcript.snapshot()[:cursor]
        if f"{provider}/{model}" not in startup or "Key\uff1aPRESENT" not in startup:
            raise RuntimeError(f"live provider startup check failed: {startup!r}")

        for step in _steps(target.name):
            print(f"START {step.name}", flush=True)
            step_start = cursor
            _send(process, step.prompt)
            step_approvals = 0
            while True:
                token, index, end = transcript.wait_any(
                    (approval_token, prompt_token),
                    cursor,
                    timeout=args.step_timeout,
                )
                cursor = end
                if token == approval_token:
                    if session_id is None:
                        new_ids = _session_ids(database) - before_ids
                        if len(new_ids) != 1:
                            _send(process, "d")
                            raise RuntimeError(
                                f"could not identify one live session: {sorted(new_ids)}"
                            )
                        session_id = next(iter(new_ids))
                    if step.expected_tool is None or step_approvals:
                        _send(process, "d")
                        raise RuntimeError(f"unexpected approval during {step.name}")
                    request = _current_approval(database, session_id)
                    try:
                        approval_id = _validate_approval(
                            request,
                            step=step,
                            root=root,
                            target=target,
                        )
                    except Exception:
                        _send(process, "d")
                        try:
                            _token, _index, cursor = transcript.wait_any(
                                (prompt_token,),
                                cursor,
                                timeout=10,
                            )
                        except (RuntimeError, TimeoutError):
                            pass
                        raise
                    approvals.append(approval_id)
                    step_approvals += 1
                    _send(process, "a")
                    print(f"APPROVED {step.name} {step.expected_tool}", flush=True)
                    continue
                break

            segment = transcript.snapshot()[step_start:index]
            if session_id is None:
                new_ids = _session_ids(database) - before_ids
                if len(new_ids) != 1:
                    raise RuntimeError(
                        f"could not identify one live session: {sorted(new_ids)}"
                    )
                session_id = next(iter(new_ids))
            if "Offline fake provider" in segment:
                raise RuntimeError("live test unexpectedly used Fake Provider")
            if step.expected_tool is None:
                if "Aster>" not in segment:
                    raise RuntimeError("chat step produced no assistant response")
            else:
                marker = f"\u5de5\u5177 {step.expected_tool}: completed"
                if step_approvals != 1 or marker not in segment:
                    raise RuntimeError(
                        f"expected completed {step.expected_tool} during {step.name}; "
                        f"tail={segment[-1_800:]!r}"
                    )
                for bad_status in ("partial", "failed", "blocked"):
                    if f"\u72b6\u6001\uff1a{bad_status}" in segment:
                        raise RuntimeError(
                            f"non-completed state during {step.name}: {bad_status}"
                        )

            if step.expected_content is None:
                if step.expected_tool == "fs.delete" and os.path.lexists(target):
                    raise RuntimeError(f"delete step left target behind: {target}")
            elif target.read_bytes() != step.expected_content:
                raise RuntimeError(
                    f"content mismatch during {step.name}: {target.read_bytes()!r}"
                )
            print(f"PASS {step.name}", flush=True)

        _send(process, "/exit")
        assert process.stdin is not None
        process.stdin.close()
        return_code = process.wait(timeout=30)
        if return_code != 0:
            raise RuntimeError(f"aster exited with {return_code}")
    finally:
        if process.poll() is None:
            try:
                _send(process, "/exit")
            except (BrokenPipeError, OSError):
                pass
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    if session_id is None:
        raise RuntimeError("live session id was not captured")
    final_new_ids = _session_ids(database) - before_ids
    if final_new_ids != {session_id}:
        raise RuntimeError(
            f"live test did not remain in exactly one new session: {sorted(final_new_ids)}"
        )
    if os.path.lexists(target):
        raise RuntimeError(f"final test target still exists: {target}")
    if len(approvals) != 6 or len(set(approvals)) != 6:
        raise RuntimeError(f"expected 6 approvals, observed {len(approvals)}")

    with _connect_readonly(database) as connection:
        row = connection.execute(
            "SELECT status, workspace, state_json FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        calls = list(
            connection.execute(
                "SELECT turn_id, call_id, action_id, tool, arguments_json, status "
                "FROM tool_calls WHERE session_id=? ORDER BY rowid",
                (session_id,),
            )
        )
        consumed = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT approval_id, status FROM approvals WHERE approval_id IN "
                f"({','.join('?' for _ in approvals)})",
                approvals,
            )
        }
        turn_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM turns WHERE session_id=? AND role='user'",
                (session_id,),
            ).fetchone()[0]
        )
        side_effect_action_ids = [
            str(action_id)
            for _turn_id, _call_id, action_id, tool, _arguments_json, status in calls
            if str(tool) in {"fs.apply_patch", "fs.delete"}
            and str(status) == "completed"
        ]
        requested_counts = {
            str(action_id): int(count)
            for action_id, count in connection.execute(
                "SELECT action_id, COUNT(*) FROM audit_log "
                "WHERE event_type='approval.requested' AND action_id IN "
                f"({','.join('?' for _ in side_effect_action_ids)}) "
                "GROUP BY action_id",
                side_effect_action_ids,
            )
        }
        approval_action_rows = list(
            connection.execute(
                "SELECT action_id, status, COUNT(*) FROM approvals "
                "WHERE action_id IN "
                f"({','.join('?' for _ in side_effect_action_ids)}) "
                "GROUP BY action_id, status",
                side_effect_action_ids,
            )
        )
        grant_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM approval_grants WHERE session_id=?",
                (session_id,),
            ).fetchone()[0]
        )
        tool_retry_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE session_id=? AND event_type='tool.retry'",
                (session_id,),
            ).fetchone()[0]
        )
    if row is None or str(row[0]) != "completed" or not _same_path(str(row[1]), root):
        raise RuntimeError(f"final session status is not completed: {row!r}")
    final_state = json.loads(str(row[2]))
    rejected = [tuple(item) for item in calls if str(item[5]) == "policy_check"]
    rejected_results = {
        str(item.get("call_id")): item
        for item in final_state.get("tool_results", [])
        if str(item.get("status")) == "cancelled"
        and not item.get("side_effects")
        and str((item.get("error") or {}).get("message"))
        == "policy validation failed (ValueError)"
    }
    if len(rejected) > 6 or {
        str(item[1]) for item in rejected
    } != set(rejected_results):
        raise RuntimeError(
            "non-executed proposals were not bounded, stale, side-effect-free "
            f"policy rejections: {rejected}"
        )
    executed_calls = [tuple(item) for item in calls if str(item[5]) != "policy_check"]
    failed = [item for item in executed_calls if str(item[5]) != "completed"]
    if (
        len(failed) != 1
        or str(failed[0][3]) != "git.status"
        or str(failed[0][5]) != "failed"
    ):
        raise RuntimeError(
            f"expected exactly one recoverable git.status failure: {failed}"
        )
    significant_calls = [
        item
        for item in executed_calls
        if str(item[3]) == "git.status"
        or (
            str(item[3]) in {"fs.apply_patch", "fs.delete"}
            and str(item[5]) == "completed"
        )
    ]
    call_tools = [
        str(tool)
        for _turn_id, _call_id, _action_id, tool, _arguments_json, _status in significant_calls
    ]
    expected_calls = [
        "git.status",
        "fs.apply_patch",
        "fs.apply_patch",
        "fs.delete",
        "fs.apply_patch",
        "fs.apply_patch",
        "fs.delete",
    ]
    if call_tools != expected_calls:
        raise RuntimeError(f"unexpected exact tool-call sequence: {call_tools}")
    call_turns = [str(turn_id) for turn_id, *_rest in significant_calls]
    call_ids = [str(call_id) for _turn_id, call_id, *_rest in calls]
    if len(set(call_ids)) != len(call_ids):
        raise RuntimeError(f"tool call IDs were not unique: {call_ids}")
    if (
        len(call_turns) != 7
        or len(set(call_turns)) != 6
        or call_turns[0] != call_turns[1]
        or len(set(call_turns[1:])) != 6
    ):
        raise RuntimeError(
            "git.status and the first patch must share one turn, while the six "
            f"side effects remain isolated: {call_turns}"
        )
    for _turn_id, _call_id, _action_id, tool, arguments_json, _status in calls:
        arguments = json.loads(str(arguments_json))
        if str(tool) == "fs.read":
            read_path = Path(str(arguments.get("path", "")))
            resolved_read_path = read_path if read_path.is_absolute() else root / read_path
            if not _same_path(resolved_read_path, target):
                raise RuntimeError(f"read escaped the exact test target: {arguments}")
        elif str(tool) == "fs.list":
            list_path = Path(str(arguments.get("path", "")))
            resolved_list_path = list_path if list_path.is_absolute() else root / list_path
            if not _same_path(resolved_list_path, root) or bool(
                arguments.get("recursive")
            ):
                raise RuntimeError(f"list escaped the non-recursive workspace root: {arguments}")
    side_effects = [
        str(tool)
        for _turn_id, _call_id, _action_id, tool, _arguments_json, status in calls
        if str(tool) in {"fs.apply_patch", "fs.delete"}
        and str(status) == "completed"
    ]
    expected_side_effects = [
        "fs.apply_patch",
        "fs.apply_patch",
        "fs.delete",
    ] * 2
    if side_effects != expected_side_effects:
        raise RuntimeError(f"unexpected side-effect sequence: {side_effects}")
    disallowed = [
        str(tool)
        for _turn_id, _call_id, _action_id, tool, _arguments_json, _status in calls
        if str(tool)
        not in {
            "fs.list",
            "fs.stat",
            "fs.read",
            "fs.search",
            "git.status",
            "git.diff",
            "git.log",
            "git.show",
            "git.branch",
            "fs.apply_patch",
            "fs.delete",
        }
    ]
    if disallowed:
        raise RuntimeError(f"unexpected tools were executed: {disallowed}")
    if set(consumed) != set(approvals) or set(consumed.values()) != {"consumed"}:
        raise RuntimeError(f"approvals were not all consumed: {consumed}")
    if len(side_effect_action_ids) != 6 or len(set(side_effect_action_ids)) != 6:
        raise RuntimeError(
            f"side-effect action IDs were not six unique values: {side_effect_action_ids}"
        )
    approval_actions = {
        str(action_id): str(status)
        for action_id, status, count in approval_action_rows
        if int(count) == 1
    }
    if len(approval_action_rows) != 6 or set(approval_actions) != set(
        side_effect_action_ids
    ) or set(approval_actions.values()) != {"consumed"}:
        raise RuntimeError(
            f"side-effect actions do not map one-to-one to consumed approvals: {approval_actions}"
        )
    if grant_count:
        raise RuntimeError(f"live smoke unexpectedly left {grant_count} session grants")
    if set(requested_counts) != set(side_effect_action_ids) or set(
        requested_counts.values()
    ) != {1}:
        raise RuntimeError(
            f"approval.requested audit events are not one per action: {requested_counts}"
        )
    if turn_count != len(_steps(target.name)):
        raise RuntimeError(f"expected 7 user turns in one session, observed {turn_count}")
    if tool_retry_count or any(
        key != "provider" for key in dict(final_state.get("retry_attempts", {}))
    ):
        raise RuntimeError(
            f"unexpected tool retry evidence: events={tool_retry_count}, "
            f"state={final_state.get('retry_attempts')}"
        )

    audit = subprocess.run(
        [*command_prefix, "audit", "verify", "--root", str(root)],
        cwd=root,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=60,
    )
    if audit.returncode != 0 or '"valid": true' not in audit.stdout.lower():
        raise RuntimeError(
            f"audit verification failed: rc={audit.returncode}, "
            f"output={redact_secrets(audit.stdout[-1000:])!r}"
        )

    print("LIVE_CHAT_CYCLE_SMOKE_PASSED")
    print(
        f"session_id={session_id} turns={turn_count} approvals={len(approvals)} "
        f"tool_calls={len(calls)} side_effects={len(side_effects)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
