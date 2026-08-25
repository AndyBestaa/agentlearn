"""Process and shell execution with fail-closed network/sandbox semantics."""

from __future__ import annotations

import math
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterable, Mapping, cast

from ..windows_job import CREATE_SUSPENDED, WindowsJobLimits, WindowsJobObject
from .base import ToolResult, ToolSpec, new_action_id, timed_result


class UnsandboxedExecutionBlocked(RuntimeError):
    """Raised when the host cannot enforce the configured network boundary."""


_STORE_POWERSHELL_PACKAGE = re.compile(
    r"^Microsoft\.PowerShell_(\d+(?:\.\d+){1,3})_(?:x64|arm64)__8wekyb3d8bbwe$",
    re.IGNORECASE,
)


def _path_has_reparse_point(path: Path) -> bool:
    """Return whether *path* itself is a link/reparse point.

    ``Path.is_symlink`` does not identify Windows junctions and other reparse
    points on every supported Python version.  ``st_file_attributes`` is
    available on Windows and is harmlessly absent on POSIX.
    """

    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        return True
    try:
        attributes = int(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0))
    except (FileNotFoundError, OSError, ValueError):
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _validate_trusted_powershell7_candidate(candidate: Path, windows_apps_root: Path) -> Path | None:
    """Validate a PowerShell Store executable without trusting PATH.

    The package identity and publisher suffix are checked in addition to the
    fixed ``WindowsApps`` location.  This prevents a repository executable or
    an arbitrary PATH shim from becoming a shell interpreter.
    """

    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError):
        return None
    # Standard users can execute registered Store applications but Windows
    # denies enumerating/resolving the protected WindowsApps directory itself.
    # Keep that fixed root lexical; resolving the concrete candidate still
    # exposes any redirect before the containment check below.
    root = Path(os.path.abspath(windows_apps_root))
    if not root.is_dir():
        return None
    if not resolved.is_file() or resolved.name.casefold() != "pwsh.exe":
        return None
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None
    if len(relative.parts) != 2 or relative.parts[1].casefold() != "pwsh.exe":
        return None
    if _STORE_POWERSHELL_PACKAGE.fullmatch(relative.parts[0]) is None:
        return None
    # Do not follow a link/reparse point while accepting the executable.
    if _path_has_reparse_point(root):
        return None
    for part_count in (1, 2):
        current = root.joinpath(*relative.parts[:part_count])
        if _path_has_reparse_point(current):
            return None
    return resolved


def _windows_system_locations() -> tuple[Path, Path] | None:
    """Return Program Files and Windows directories from OS APIs, not env."""

    if os.name != "nt":
        return None
    try:
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return None
        windows_buffer = ctypes.create_unicode_buffer(32_768)
        length = windll.kernel32.GetWindowsDirectoryW(windows_buffer, len(windows_buffer))
        if not isinstance(length, int) or length <= 0 or length >= len(windows_buffer):
            return None
        program_files_buffer = ctypes.create_unicode_buffer(32_768)
        # CSIDL_PROGRAM_FILES is resolved by the shell for the native process
        # architecture and cannot be redirected through inherited env vars.
        hresult = windll.shell32.SHGetFolderPathW(None, 0x0026, None, 0, program_files_buffer)
        if hresult != 0:
            return None
        program_files = Path(program_files_buffer.value)
        windows = Path(windows_buffer.value)
        if not program_files.is_absolute() or not windows.is_absolute():
            return None
        return program_files, windows
    except (AttributeError, OSError, ValueError):
        return None


def discover_trusted_powershell7() -> Path | None:
    """Discover a trusted PowerShell 7 executable on Windows.

    Classic MSI/winget installs use a fixed path.  Microsoft Store installs do
    not put ``pwsh.exe`` in the sanitized PATH, so query the package manager
    through the fixed, inbox Windows PowerShell executable and validate the
    returned package identity before using it.  No user PATH or app-execution
    alias is consulted.
    """

    locations = _windows_system_locations()
    if locations is None:
        return None
    program_files, system_root = locations
    classic = program_files / "PowerShell" / "7" / "pwsh.exe"
    try:
        resolved_classic = classic.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError):
        resolved_classic = None
    if resolved_classic is not None and resolved_classic.is_file():
        lexical_classic = Path(os.path.abspath(classic))
        classic_components = (
            program_files / "PowerShell",
            program_files / "PowerShell" / "7",
            classic,
        )
        if resolved_classic == lexical_classic and not any(_path_has_reparse_point(item) for item in classic_components):
            return resolved_classic

    inbox_powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    try:
        resolved_inbox = inbox_powershell.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError):
        return None
    if not resolved_inbox.is_file() or resolved_inbox != Path(os.path.abspath(inbox_powershell)) or _path_has_reparse_point(resolved_inbox):
        return None
    query = "Get-AppxPackage -Name Microsoft.PowerShell | Select-Object -ExpandProperty InstallLocation"
    query_env = {
        key: value
        for key, value in os.environ.items()
        if key in {"WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC", "USERPROFILE", "LOCALAPPDATA", "APPDATA"}
    }
    query_env.update(
        {
            "SystemRoot": str(system_root),
            "WINDIR": str(system_root),
            "PATH": str(system_root / "System32"),
            "PSModulePath": str(system_root / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
        }
    )
    try:
        completed = subprocess.run(
            [str(resolved_inbox), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
            env=query_env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    windows_apps = program_files / "WindowsApps"
    candidates: list[Path] = []
    for line in completed.stdout.splitlines():
        location = line.strip()
        if not location or "\x00" in location:
            continue
        validated = _validate_trusted_powershell7_candidate(Path(location) / "pwsh.exe", windows_apps)
        if validated is not None:
            candidates.append(validated)

    # Package-manager output is not a security decision; choose the highest
    # numeric package version deterministically after identity validation.
    def version_key(path: Path) -> tuple[int, ...]:
        match = _STORE_POWERSHELL_PACKAGE.fullmatch(path.parent.name)
        return tuple(int(part) for part in match.group(1).split(".")) if match else ()

    return max(candidates, key=version_key, default=None)


@dataclass(frozen=True, slots=True)
class _CaptureSnapshot:
    text: str
    total_chars: int
    retained_bytes: int
    total_bytes: int
    truncated: bool
    complete: bool
    error: str | None


class _BoundedPipeCapture:
    """Continuously drain one text pipe while retaining only a fixed prefix."""

    _READ_CHARS = 8_192

    def __init__(self, stream: IO[str], max_chars: int, *, name: str) -> None:
        self._stream = stream
        self._max_chars = max(0, max_chars)
        self._encoding = getattr(stream, "encoding", None) or "utf-8"
        self._errors = getattr(stream, "errors", None) or "replace"
        self._chunks: list[str] = []
        self._retained_chars = 0
        self._total_chars = 0
        self._retained_bytes = 0
        self._total_bytes = 0
        self._truncated = False
        self._error: str | None = None
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._drain,
            name=name,
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _drain(self) -> None:
        binary_stream = getattr(self._stream, "buffer", None)
        read_candidate = getattr(binary_stream, "read1", None)
        read_available = cast(Callable[[int], bytes], read_candidate) if callable(read_candidate) else None
        decoder = None
        if callable(read_available):
            import codecs

            decoder = codecs.getincrementaldecoder(self._encoding)(errors=self._errors)
        try:
            while True:
                eof = False
                if decoder is None:
                    chunk = self._stream.read(self._READ_CHARS)
                    observed_bytes = len(chunk.encode(self._encoding, errors=self._errors))
                else:
                    assert read_available is not None
                    raw = read_available(self._READ_CHARS)
                    observed_bytes = len(raw)
                    eof = not raw
                    chunk = decoder.decode(raw, final=eof)
                if not chunk:
                    break
                with self._lock:
                    self._total_chars += len(chunk)
                    self._total_bytes += observed_bytes
                    remaining = self._max_chars - self._retained_chars
                    if remaining > 0:
                        kept = chunk[:remaining]
                        self._chunks.append(kept)
                        self._retained_chars += len(kept)
                        self._retained_bytes += len(kept.encode(self._encoding, errors=self._errors))
                    if len(chunk) > max(0, remaining):
                        self._truncated = True
                if eof:
                    break
        except (OSError, ValueError) as exc:
            with self._lock:
                self._truncated = True
                self._error = type(exc).__name__
        finally:
            # The reader thread owns this stream. Closing it here avoids a
            # cross-thread TextIOWrapper close that can otherwise block while
            # another thread is inside read() on Windows.
            with suppress(OSError, ValueError):
                self._stream.close()
            self._done.set()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(max(0.0, timeout))

    def snapshot(self) -> _CaptureSnapshot:
        with self._lock:
            return _CaptureSnapshot(
                text="".join(self._chunks),
                total_chars=self._total_chars,
                retained_bytes=min(self._retained_bytes, self._total_bytes),
                total_bytes=self._total_bytes,
                truncated=self._truncated,
                complete=self._done.is_set() and self._error is None,
                error=self._error,
            )


class _ProcessCapture:
    """Bounded stdout/stderr drainers for one owned process tree."""

    def __init__(self, proc: subprocess.Popen[str], max_chars: int, handle: str) -> None:
        if proc.stdout is None or proc.stderr is None:
            raise RuntimeError("managed process pipes were not created")
        self.stdout = _BoundedPipeCapture(
            proc.stdout,
            max_chars,
            name=f"astercode-{handle}-stdout",
        )
        self.stderr = _BoundedPipeCapture(
            proc.stderr,
            max_chars,
            name=f"astercode-{handle}-stderr",
        )

    def start(self) -> None:
        self.stdout.start()
        self.stderr.start()

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        stdout_complete = self.stdout.wait(max(0.0, deadline - time.monotonic()))
        stderr_complete = self.stderr.wait(max(0.0, deadline - time.monotonic()))
        return stdout_complete and stderr_complete

    def snapshots(self) -> tuple[_CaptureSnapshot, _CaptureSnapshot]:
        return self.stdout.snapshot(), self.stderr.snapshot()


class ProcessTools:
    specs: tuple[ToolSpec, ...] = (
        ToolSpec(
            "process.exec",
            "Execute a structured argv in an authorized cwd. Run reviewed workspace files such as ['python', 'add.py']; never use inline interpreter flags such as python -c, node -e, or ruby -e.",
            "process.exec",
            ("process_start",),
            "P2",
            timeout_seconds=120,
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "timeout": {"type": "number", "minimum": 0.1},
                },
                "required": ["argv", "cwd", "timeout"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "shell.exec",
            "Execute a shell script only after explicit unsandboxed approval.",
            "process.shell",
            ("process_start",),
            "P2",
            timeout_seconds=120,
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "script": {"type": "string"},
                    "dialect": {"type": "string", "enum": ["powershell", "pwsh", "bash"]},
                    "cwd": {"type": "string"},
                    "timeout": {"type": "number", "minimum": 0.1},
                },
                "required": ["script", "dialect", "cwd", "timeout"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "process.start",
            "Start an approved long-running argv and return a process handle.",
            "process.start",
            ("process_start",),
            "P2",
            timeout_seconds=30,
            idempotent=False,
            schema={
                "type": "object",
                "properties": {"argv": {"type": "array", "items": {"type": "string"}}, "cwd": {"type": "string"}},
                "required": ["argv", "cwd"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "process.poll",
            "Poll a process handle created by this agent.",
            "process.read",
            max_output=8_000,
            schema={
                "type": "object",
                "properties": {"action_id": {"type": "string"}},
                "required": ["action_id"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "process.send_input",
            "Send bounded stdin to a process created by this agent.",
            "process.write",
            ("process_input",),
            "P2",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {"action_id": {"type": "string"}, "input": {"type": "string", "maxLength": 16_384}},
                "required": ["action_id", "input"],
                "additionalProperties": False,
            },
        ),
        ToolSpec(
            "process.stop",
            "Stop a process tree created by this agent.",
            "process.stop",
            ("process_stop",),
            "P2",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {"action_id": {"type": "string"}},
                "required": ["action_id"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(
        self,
        roots: Iterable[str | Path],
        *,
        network_mode: str = "deny_by_default",
        max_output: int = 32_000,
        clean_path: Iterable[str | Path] = (),
        sandbox_enforced: bool = False,
        network_policy_enforced: bool = False,
        max_processes: int = 32,
        max_memory_bytes: int | None = None,
        max_cpu_time_seconds: float | None = None,
        max_timeout: float = 3_600.0,
    ) -> None:
        self.roots = tuple(Path(root).resolve() for root in roots)
        self.network_mode = network_mode
        self.max_output = max_output
        self.clean_path = tuple(str(Path(item).resolve()) for item in clean_path)
        self.sandbox_enforced = sandbox_enforced
        self.network_policy_enforced = network_policy_enforced
        self.max_processes = max_processes
        self.max_memory_bytes = max_memory_bytes
        self.max_cpu_time_seconds = max_cpu_time_seconds
        self.max_timeout = max_timeout
        self._state_lock = threading.RLock()
        self._children: dict[str, subprocess.Popen[str]] = {}
        self._windows_jobs: dict[str, WindowsJobObject] = {}
        self._captures: dict[str, _ProcessCapture] = {}
        self._starting_handles: set[str] = set()

    @staticmethod
    def _new_process_handle() -> str:
        """Return an opaque, non-reusable handle for one concrete process."""

        return f"proc_{uuid.uuid4().hex}"

    def _boundary_check(self, allow_unsandboxed: bool) -> None:
        if not allow_unsandboxed:
            raise UnsandboxedExecutionBlocked("no verified process sandbox is available; explicit P2 approval is required")
        if not self.sandbox_enforced:
            raise UnsandboxedExecutionBlocked("no verified process sandbox is available; approval cannot replace an OS-enforced boundary")
        if not self.network_policy_enforced:
            raise UnsandboxedExecutionBlocked(
                f"configured network mode {self.network_mode!r} has no verified process enforcement; "
                "approval cannot grant unrestricted host networking"
            )

    def _cwd(self, raw: str | Path) -> Path:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = self.roots[0] / candidate
        candidate = candidate.resolve()
        if not any(candidate == root or root in candidate.parents for root in self.roots):
            raise PermissionError("cwd outside authorized roots")
        return candidate

    def _check_process_budget(self) -> None:
        # Exited roots remain addressable until poll/stop/cancel consumes the
        # handle. Auto-reaping here would silently discard their bounded
        # output and could miss descendants that still own inherited pipes.
        with self._state_lock:
            if len(self._children) + len(self._starting_handles) >= self.max_processes:
                raise RuntimeError("process-count limit reached")

    def _managed_child(self, process_handle: str) -> subprocess.Popen[str] | None:
        with self._state_lock:
            return self._children.get(process_handle)

    def _managed_capture(self, process_handle: str) -> _ProcessCapture | None:
        with self._state_lock:
            return self._captures.get(process_handle)

    def _timeout(self, value: float) -> float:
        parsed = float(value)
        if not math.isfinite(parsed) or parsed < 0.1 or parsed > self.max_timeout:
            raise ValueError(f"timeout must be finite and between 0.1 and {self.max_timeout} seconds")
        return parsed

    def _spawn(
        self,
        process_handle: str,
        argv: list[str],
        workdir: Path,
        env: Mapping[str, str],
        *,
        stdin: int,
    ) -> subprocess.Popen[str]:
        """Spawn a child, establishing a Windows Job before target code runs."""

        # Reserve a slot atomically, then perform OS calls outside the lock so
        # a slow Job cleanup cannot block poll/stop on unrelated handles.
        with self._state_lock:
            self._check_process_budget()
            self._starting_handles.add(process_handle)
        registered = False
        job: WindowsJobObject | None = None
        creationflags = 0
        try:
            if os.name == "nt":
                job = WindowsJobObject(
                    WindowsJobLimits(
                        active_process_limit=self.max_processes,
                        job_memory_limit=self.max_memory_bytes,
                        job_cpu_time_limit_seconds=self.max_cpu_time_seconds,
                    )
                )
                new_process_group = vars(subprocess).get("CREATE_NEW_PROCESS_GROUP")
                if not isinstance(new_process_group, int):
                    raise UnsandboxedExecutionBlocked("Windows process-group support is unavailable")
                creationflags = new_process_group | CREATE_SUSPENDED
            try:
                proc = subprocess.Popen(
                    argv,
                    cwd=str(workdir),
                    env=dict(env),
                    stdin=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    start_new_session=(os.name != "nt"),
                    creationflags=creationflags,
                )
            except Exception:
                if job is not None:
                    job.close()
                raise
            if job is not None:
                try:
                    job.assign_and_resume(proc.pid)
                except Exception:
                    # Popen returned a CREATE_SUSPENDED process.  It has not
                    # run target code unless assign_and_resume completed.
                    with suppress(OSError):
                        proc.kill()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        # Register before raising so the caller can recover
                        # the concrete Popen even though assignment to its
                        # local variable did not complete.
                        with self._state_lock:
                            self._children[process_handle] = proc
                            self._windows_jobs[process_handle] = job
                            self._starting_handles.discard(process_handle)
                        registered = True
                        raise RuntimeError("Windows Job assignment failed and suspended-process cleanup is unconfirmed") from None
                    self._close_pipes(proc)
                    job.close()
                    raise
            with self._state_lock:
                if job is not None:
                    self._windows_jobs[process_handle] = job
                self._children[process_handle] = proc
                self._starting_handles.discard(process_handle)
            registered = True
            return proc
        finally:
            if not registered:
                with self._state_lock:
                    self._starting_handles.discard(process_handle)

    def _begin_capture(self, process_handle: str, proc: subprocess.Popen[str]) -> _ProcessCapture:
        capture = _ProcessCapture(proc, self.max_output, process_handle)
        with self._state_lock:
            if self._children.get(process_handle) is not proc:
                raise RuntimeError("process handle was released before capture started")
            self._captures[process_handle] = capture
        try:
            capture.start()
        except Exception:
            with self._state_lock:
                self._captures.pop(process_handle, None)
            raise
        return capture

    def _containment_metadata(self, process_handle: str) -> dict[str, object]:
        with self._state_lock:
            if process_handle not in self._windows_jobs:
                return {}
        return {
            "process_tree_containment": "windows_job_object",
            "kill_on_job_close": True,
            "active_process_limit": self.max_processes,
            "job_memory_limit": self.max_memory_bytes,
            "job_cpu_time_limit_seconds": self.max_cpu_time_seconds,
            "filesystem_sandbox": False,
            "network_sandbox": False,
        }

    def _release_action(
        self,
        process_handle: str,
        proc: subprocess.Popen[str],
        *,
        capture_wait: float = 1.0,
    ) -> _ProcessCapture | None:
        # stdin is not consumed by the capture threads. It is safe to close
        # after the child has exited or its tree has been terminated.
        if proc.stdin is not None:
            with suppress(OSError, ValueError):
                proc.stdin.close()
        with self._state_lock:
            job = self._windows_jobs.pop(process_handle, None)
            capture = self._captures.pop(process_handle, None)
            self._children.pop(process_handle, None)
        if job is not None:
            # Normal root exit can still leave descendants holding inherited
            # pipe handles. KILL_ON_JOB_CLOSE supplies EOF to the drainers.
            job.close()
        if capture is not None:
            capture.wait(capture_wait)
        else:
            self._close_pipes(proc)
        return capture

    def _apply_capture(
        self,
        result: ToolResult,
        capture: _ProcessCapture,
        *,
        final: bool,
    ) -> None:
        stdout, stderr = capture.snapshots()
        result.stdout = stdout.text
        result.stderr = stderr.text
        result.truncated = result.truncated or stdout.truncated or stderr.truncated
        capture_complete = stdout.complete and stderr.complete
        if final and not capture_complete:
            # We never wait indefinitely for a pipe whose write end may be
            # held by an unconfirmed descendant. The retained prefix remains
            # useful, but it must not be represented as complete output.
            result.truncated = True
        result.metadata["capture"] = {
            "retention_limit_chars_per_stream": self.max_output,
            "stdout": {
                "retained_chars": len(stdout.text),
                "observed_chars": stdout.total_chars,
                "discarded_chars": max(0, stdout.total_chars - len(stdout.text)),
                "retained_bytes": stdout.retained_bytes,
                "observed_bytes": stdout.total_bytes,
                "discarded_bytes": max(0, stdout.total_bytes - stdout.retained_bytes),
                "truncated": stdout.truncated,
                "complete": stdout.complete,
                "content_complete": stdout.complete and not stdout.truncated,
                "error": stdout.error,
            },
            "stderr": {
                "retained_chars": len(stderr.text),
                "observed_chars": stderr.total_chars,
                "discarded_chars": max(0, stderr.total_chars - len(stderr.text)),
                "retained_bytes": stderr.retained_bytes,
                "observed_bytes": stderr.total_bytes,
                "discarded_bytes": max(0, stderr.total_bytes - stderr.retained_bytes),
                "truncated": stderr.truncated,
                "complete": stderr.complete,
                "content_complete": stderr.complete and not stderr.truncated,
                "error": stderr.error,
            },
            "complete": capture_complete,
        }

    def exec(
        self, argv: list[str], cwd: str, timeout: float = 120, *, allow_unsandboxed: bool = False, env_refs: Mapping[str, str] | None = None
    ) -> ToolResult:
        args = {"argv": argv, "cwd": cwd, "timeout": timeout}
        action_id = new_action_id("process.exec", args)
        result = timed_result("process.exec", action_id, cwd)
        process_handle = self._new_process_handle()
        proc: subprocess.Popen[str] | None = None
        capture: _ProcessCapture | None = None
        try:
            if not argv or any(not isinstance(item, str) or not item for item in argv):
                raise ValueError("argv must be a non-empty list of non-empty strings")
            self._boundary_check(allow_unsandboxed)
            timeout = self._timeout(timeout)
            workdir = self._cwd(cwd)
            env = self._clean_env(env_refs or {})
            proc = self._spawn(
                process_handle,
                argv,
                workdir,
                env,
                stdin=subprocess.DEVNULL,
            )
            capture = self._begin_capture(process_handle, proc)
            result.side_effects = ["process_start"]
            result.metadata.update(
                {
                    "pid": proc.pid,
                    "identity_token": self.process_identity(proc.pid),
                    "process_handle": process_handle,
                    **self._containment_metadata(process_handle),
                }
            )
            try:
                result.exit_code = proc.wait(timeout=timeout)
                result.status = "completed" if proc.returncode == 0 else "failed"
            except subprocess.TimeoutExpired:
                terminated = self._terminate(process_handle, proc)
                capture.wait(1.0)
                result.status = "unknown"
                result.error = f"timeout after {timeout}s; side effect state requires reconcile"
                result.metadata["process_tree_stop_confirmed"] = terminated
            else:
                # The root may exit while a descendant keeps an inherited
                # pipe open. Never wait indefinitely: close the owned process
                # tree and explicitly report whether that cleanup succeeded.
                if not capture.wait(0.25):
                    terminated = self._terminate(process_handle, proc)
                    capture.wait(1.0)
                    result.metadata["descendant_cleanup_triggered"] = True
                    result.metadata["process_tree_stop_confirmed"] = terminated
                    if not terminated:
                        result.status = "unknown"
                        result.error = "root process exited but descendant cleanup could not be confirmed"
        except UnsandboxedExecutionBlocked as exc:
            result.status, result.error = "failed", str(exc)
            result.metadata["blocked"] = True
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
            proc = proc or self._managed_child(process_handle)
            if proc is not None:
                result.metadata.setdefault("pid", proc.pid)
                result.metadata.setdefault("identity_token", self.process_identity(proc.pid))
                result.metadata.setdefault("process_handle", process_handle)
                result.metadata.update(self._containment_metadata(process_handle))
                try:
                    confirmed = self._terminate(process_handle, proc)
                except Exception:
                    confirmed = False
                result.metadata["process_tree_stop_confirmed"] = confirmed
                if not confirmed:
                    result.status = "unknown"
                    result.error = f"{result.error}; failed-process cleanup could not be confirmed"
        finally:
            proc = proc or self._managed_child(process_handle)
            if proc is not None and self._managed_child(process_handle) is proc:
                released_capture = self._release_action(process_handle, proc)
                capture = capture or released_capture
            if capture is not None:
                self._apply_capture(result, capture, final=True)
        return result.bounded(self.max_output).finish()

    def shell(self, script: str, dialect: str, cwd: str, timeout: float = 120, *, allow_unsandboxed: bool = False) -> ToolResult:
        if dialect not in {"powershell", "pwsh", "bash"}:
            result = timed_result("shell.exec", new_action_id("shell.exec", {"script": script, "dialect": dialect, "cwd": cwd}), cwd)
            result.status, result.error = "failed", "dialect must be powershell or bash"
            return result.finish()
        if dialect in {"powershell", "pwsh"}:
            # Do not weaken the host execution policy.  ``-NoProfile`` and
            # ``-NonInteractive`` keep the invocation deterministic; the
            # machine/user policy remains authoritative.
            powershell_executable = discover_trusted_powershell7()
            if powershell_executable is None and dialect == "powershell":
                safe_path = self._clean_env({})["PATH"]
                powershell_executable = Path(shutil.which("powershell.exe", path=safe_path) or "")
                if not powershell_executable.is_file():
                    powershell_executable = None
            if powershell_executable is None:
                result = timed_result("shell.exec", new_action_id("shell.exec", {"script": script, "dialect": dialect, "cwd": cwd}), cwd)
                result.status, result.error = "failed", "PowerShell executable is not available in the sanitized PATH"
                return result.finish()
            argv = [str(powershell_executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]
        else:
            bash_executable = shutil.which("bash", path=self._clean_env({})["PATH"])
            if bash_executable is None:
                result = timed_result("shell.exec", new_action_id("shell.exec", {"script": script, "dialect": dialect, "cwd": cwd}), cwd)
                result.status, result.error = "failed", "bash executable is not available in the sanitized PATH"
                return result.finish()
            argv = [bash_executable, "--noprofile", "--norc", "-c", script]
        result = self.exec(argv, cwd, timeout, allow_unsandboxed=allow_unsandboxed)
        result.tool = "shell.exec"
        return result

    def start(self, argv: list[str], cwd: str, *, allow_unsandboxed: bool = False) -> ToolResult:
        args = {"argv": argv, "cwd": cwd}
        result = timed_result("process.start", new_action_id("process.start", args), cwd)
        process_handle = self._new_process_handle()
        proc: subprocess.Popen[str] | None = None
        try:
            if not argv or any(not isinstance(item, str) or not item for item in argv):
                raise ValueError("argv must be a non-empty list of non-empty strings")
            self._boundary_check(allow_unsandboxed)
            workdir = self._cwd(cwd)
            proc = self._spawn(
                process_handle,
                argv,
                workdir,
                self._clean_env({}),
                stdin=subprocess.PIPE,
            )
            self._begin_capture(process_handle, proc)
            result.stdout = process_handle
            result.metadata.update(
                {
                    "pid": proc.pid,
                    "identity_token": self.process_identity(proc.pid),
                    "process_handle": process_handle,
                    **self._containment_metadata(process_handle),
                }
            )
            result.side_effects = ["process_start"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
            proc = proc or self._managed_child(process_handle)
            if proc is not None:
                result.metadata.setdefault("pid", proc.pid)
                result.metadata.setdefault("identity_token", self.process_identity(proc.pid))
                result.metadata.setdefault("process_handle", process_handle)
                result.metadata.update(self._containment_metadata(process_handle))
                try:
                    confirmed = self._terminate(process_handle, proc)
                except Exception:
                    confirmed = False
                result.metadata["process_tree_stop_confirmed"] = confirmed
                if not confirmed:
                    result.status = "unknown"
                    result.error = f"{result.error}; failed-process cleanup could not be confirmed"
                self._release_action(process_handle, proc)
        return result.finish()

    def poll(self, action_id: str) -> ToolResult:
        result = timed_result("process.poll", new_action_id("process.poll", {"action_id": action_id}))
        proc = self._managed_child(action_id)
        if proc is None:
            result.status, result.error = "failed", "unknown process action_id"
        else:
            capture = self._managed_capture(action_id)
            returncode = proc.poll()
            result.metadata["pid"] = proc.pid
            result.metadata["process_handle"] = action_id
            result.metadata["returncode"] = returncode
            result.metadata["state"] = "running" if returncode is None else "exited"
            if returncode is not None:
                result.exit_code = returncode
                if capture is not None and not capture.wait(0.25):
                    terminated = self._terminate(action_id, proc)
                    capture.wait(1.0)
                    result.metadata["descendant_cleanup_triggered"] = True
                    result.metadata["process_tree_stop_confirmed"] = terminated
                    if not terminated:
                        result.status = "unknown"
                        result.error = "root process exited but descendant cleanup could not be confirmed"
                released_capture = self._release_action(action_id, proc)
                capture = capture or released_capture
            if capture is not None:
                self._apply_capture(result, capture, final=returncode is not None)
        return result.bounded(self.max_output).finish()

    def send_input(self, action_id: str, input: str) -> ToolResult:
        result = timed_result("process.send_input", new_action_id("process.send_input", {"action_id": action_id, "input": input}))
        proc = self._managed_child(action_id)
        if proc is None or proc.stdin is None or proc.poll() is not None:
            result.status, result.error = "failed", "process is not running or was not created by this agent"
        elif "\x00" in input or len(input) > 16_384:
            result.status, result.error = "failed", "input is invalid or too large"
        else:
            proc.stdin.write(input)
            proc.stdin.flush()
            result.stdout = action_id
        return result.finish()

    def stop(self, action_id: str) -> ToolResult:
        result = timed_result("process.stop", new_action_id("process.stop", {"action_id": action_id}))
        proc = self._managed_child(action_id)
        if proc is None:
            result.status, result.error = "failed", "unknown process action_id"
        else:
            terminated = False
            try:
                terminated = self._terminate(action_id, proc)
            except Exception as exc:
                result.error = f"process tree termination raised {type(exc).__name__}"
            finally:
                capture = self._release_action(action_id, proc)
            result.metadata["process_handle"] = action_id
            result.side_effects = ["process_stop"]
            if capture is not None:
                self._apply_capture(result, capture, final=True)
            if not terminated:
                result.status = "unknown"
                result.error = result.error or "process tree termination could not be confirmed"
        return result.bounded(self.max_output).finish()

    def stop_all(self) -> list[str]:
        """Terminate every process tree started by this executor instance."""
        stopped: list[str] = []
        with self._state_lock:
            children = list(self._children.items())
        for action_id, proc in children:
            try:
                if self._terminate(action_id, proc):
                    stopped.append(action_id)
            except Exception:
                # The persisted process registry retains the evidence needed
                # to report/reconcile an unconfirmed stop.
                pass
            finally:
                self._release_action(action_id, proc)
        return stopped

    @staticmethod
    def _close_pipes(proc: subprocess.Popen[str]) -> None:
        """Release every pipe owned by a managed long-running process."""

        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()

    @staticmethod
    def process_identity(pid: int) -> str | None:
        """Return a PID-reuse-resistant OS creation token, or ``missing``."""

        if pid <= 0:
            return None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                get_last_error = getattr(ctypes, "get_last_error", None)
                if not callable(get_last_error):
                    return None
                return "missing" if int(get_last_error()) == 87 else None
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            try:
                ok = kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(creation),
                    ctypes.byref(exit_time),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                )
                if not ok:
                    return None
                exit_value = (int(exit_time.dwHighDateTime) << 32) | int(exit_time.dwLowDateTime)
                if exit_value != 0:
                    # A terminated child can remain queryable until its parent
                    # closes/reaps the process handle.  It is no longer a live
                    # PID target and must not make recovery report an orphan.
                    return "missing"
                value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
                return f"windows-filetime:{value}"
            finally:
                kernel32.CloseHandle(handle)
        stat_path = Path(f"/proc/{pid}/stat")
        try:
            raw = stat_path.read_text(encoding="ascii")
        except FileNotFoundError:
            return "missing"
        except OSError:
            return None
        closing = raw.rfind(")")
        fields = raw[closing + 2 :].split() if closing >= 0 else []
        if len(fields) <= 19:
            return None
        if fields[0] == "Z":
            # An exited child remains in /proc until its parent reaps it, but
            # it cannot execute or receive signals and must not be reported as
            # a live orphan during cross-process recovery.
            return "missing"
        return f"linux-proc-start:{fields[19]}"

    @staticmethod
    def _run_windows_taskkill(pid: int) -> subprocess.CompletedProcess[str] | None:
        """Use the pinned System32 binary with a bounded, sanitized launch."""

        system_root = Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")
        executable = (system_root / "System32" / "taskkill.exe").resolve()
        if not executable.is_file():
            return None
        env = {
            "SystemRoot": str(system_root),
            "WINDIR": str(system_root),
            "PATH": str(executable.parent),
        }
        try:
            return subprocess.run(
                [str(executable), "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=10,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

    @classmethod
    def terminate_registered(cls, pid: int, identity_token: str | None) -> bool:
        """Terminate only a persisted process whose OS creation token still matches."""

        if not identity_token:
            return False
        current = cls.process_identity(pid)
        if current == "missing":
            return True
        if current is None or current != identity_token:
            return False
        if os.name == "nt":
            completed = cls._run_windows_taskkill(pid)
            if completed is None:
                return False
            if completed.returncode != 0 and cls.process_identity(pid) == identity_token:
                return False
        else:
            killpg = getattr(os, "killpg", None)
            if killpg is None:
                return False
            try:
                killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                return True
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and cls.process_identity(pid) == identity_token:
                time.sleep(0.05)
            if cls.process_identity(pid) == identity_token:
                try:
                    killpg(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except ProcessLookupError:
                    return True
        return cls.process_identity(pid) != identity_token

    def _clean_env(self, env_refs: Mapping[str, str]) -> dict[str, str]:
        allowed = {"SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME", "LANG", "LC_ALL", "PATHEXT", "COMSPEC"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        if os.name == "nt":
            system_root = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
            program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            safe_path = [
                str(Path(system_root) / "System32"),
                str(Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0"),
                system_root,
            ]
            powershell_7 = program_files / "PowerShell" / "7"
            if powershell_7.is_dir():
                safe_path.append(str(powershell_7))
            git_cmd = program_files / "Git" / "cmd"
            if git_cmd.is_dir():
                safe_path.append(str(git_cmd))
        else:
            safe_path = ["/usr/bin", "/bin"]
        env["PATH"] = os.pathsep.join(dict.fromkeys([*self.clean_path, *safe_path]))
        # ``env_refs`` maps a target name to an existing host environment
        # reference.  Raw values are never accepted from a model/tool call.
        for key, reference in env_refs.items():
            if not key or "=" in key or "\x00" in key or "\x00" in reference:
                raise ValueError("invalid environment reference")
            if (
                key.endswith("_API_KEY")
                or "TOKEN" in key.upper()
                or "PASSWORD" in key.upper()
                or "SECRET" in key.upper()
                or "TOKEN" in reference.upper()
                or "PASSWORD" in reference.upper()
                or "SECRET" in reference.upper()
            ):
                raise PermissionError("secret-valued environment variables must use a secret broker")
            if reference not in os.environ:
                raise PermissionError("environment values must be resolved by a secret broker reference")
            env[key] = os.environ[reference]
        return env

    def _terminate(self, action_id: str, proc: subprocess.Popen[str]) -> bool:
        if os.name == "nt":
            with self._state_lock:
                job = self._windows_jobs.get(action_id)
            if job is not None:
                tree_confirmed = job.terminate(timeout=3)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # Closing the handle in _release_action is still a
                    # kill-on-close attempt, but it is not verified here.
                    return False
                return tree_confirmed and proc.poll() is not None
            if proc.poll() is not None:
                return True
            # Legacy/persisted processes do not have an owned Job handle in
            # this executor.  Keep the explicit best-effort fallback rather
            # than claiming Job-backed confirmation for them.
            completed = self._run_windows_taskkill(proc.pid)
            if completed is None:
                return False
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if completed.returncode != 0:
                    self._run_windows_taskkill(proc.pid)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    return False
            return proc.poll() is not None
        else:
            killpg = getattr(os, "killpg", None)
            if killpg is None:
                return False

            def group_exists() -> bool:
                try:
                    killpg(proc.pid, 0)
                except ProcessLookupError:
                    return False
                except PermissionError:
                    return True
                return True

            # A process-group leader may already have exited while descendants
            # keep stdout/stderr open, so never short-circuit on proc.poll().
            try:
                killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                if proc.poll() is None:
                    with suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=0.25)
                return proc.poll() is not None
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and group_exists():
                if proc.poll() is None:
                    with suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=0.05)
                else:
                    time.sleep(0.05)
            if group_exists():
                try:
                    killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and group_exists():
                    if proc.poll() is None:
                        with suppress(subprocess.TimeoutExpired):
                            proc.wait(timeout=0.05)
                    else:
                        time.sleep(0.05)
            if proc.poll() is None:
                with suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=0.25)
            return proc.poll() is not None and not group_exists()
