"""Cross-process advisory file locks used to serialize workspace writes.

The lock is enforced by the host process, not by the model.  Lock files are
kept in place after release so another process can never race by locking a
different inode created at the same pathname.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator


class LockTimeoutError(TimeoutError):
    """Raised when an inter-process lock cannot be acquired in time."""


_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}


def _local_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


class InterProcessFileLock:
    """A small Windows/POSIX exclusive lock with bounded waiting.

    OS byte-range/flock locks are automatically released when a process dies,
    which avoids relying on stale PID files for correctness.  A process-local
    mutex also makes separate instances contend correctly within one process.
    """

    def __init__(self, path: Path, *, poll_interval_seconds: float = 0.05) -> None:
        self.path = path.expanduser().resolve(strict=False)
        self.poll_interval_seconds = max(0.005, poll_interval_seconds)
        self._stream: BinaryIO | None = None
        self._local = _local_lock(self.path)

    def acquire(self, timeout_seconds: float = 30.0) -> None:
        if self._stream is not None:
            raise RuntimeError("file lock instances are not re-entrant")
        timeout_seconds = max(0.0, timeout_seconds)
        deadline = time.monotonic() + timeout_seconds
        if not self._local.acquire(timeout=timeout_seconds):
            raise LockTimeoutError(f"timed out waiting for lock: {self.path}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            stream = self.path.open("a+b")
            if stream.seek(0, os.SEEK_END) == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            while True:
                try:
                    self._try_os_lock(stream)
                    self._stream = stream
                    return
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        stream.close()
                        raise LockTimeoutError(f"timed out waiting for lock: {self.path}") from None
                    time.sleep(min(self.poll_interval_seconds, max(0.0, deadline - time.monotonic())))
        except BaseException:
            self._local.release()
            raise

    def release(self) -> None:
        stream = self._stream
        if stream is None:
            raise RuntimeError("file lock is not held")
        self._stream = None
        try:
            self._unlock_os(stream)
        finally:
            stream.close()
            self._local.release()

    @contextmanager
    def held(self, timeout_seconds: float = 30.0) -> Iterator[None]:
        self.acquire(timeout_seconds)
        try:
            yield
        finally:
            self.release()

    @staticmethod
    def _try_os_lock(stream: BinaryIO) -> None:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            locking = getattr(msvcrt, "locking", None)
            mode = getattr(msvcrt, "LK_NBLCK", None)
            if not callable(locking) or not isinstance(mode, int):
                raise RuntimeError("Windows file-lock API is unavailable")
            locking(stream.fileno(), mode, 1)
        else:
            import fcntl

            fcntl.flock(  # type: ignore[attr-defined]
                stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB  # type: ignore[attr-defined]
            )

    @staticmethod
    def _unlock_os(stream: BinaryIO) -> None:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            locking = getattr(msvcrt, "locking", None)
            mode = getattr(msvcrt, "LK_UNLCK", None)
            if not callable(locking) or not isinstance(mode, int):
                raise RuntimeError("Windows file-lock API is unavailable")
            locking(stream.fileno(), mode, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]


class WorkspaceWriteLock(InterProcessFileLock):
    """Exclusive lock shared by all write-capable sessions in one workspace."""

    def __init__(self, workspace: Path) -> None:
        root = workspace.expanduser().resolve(strict=True)
        super().__init__(root / ".astercode" / "workspace-write.lock")


__all__ = ["InterProcessFileLock", "LockTimeoutError", "WorkspaceWriteLock"]
