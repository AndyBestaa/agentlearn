from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from astercode.lock import WorkspaceWriteLock

_CHILD = """
import sys
from pathlib import Path
from astercode.lock import LockTimeoutError, WorkspaceWriteLock

lock = WorkspaceWriteLock(Path(sys.argv[1]))
try:
    lock.acquire(float(sys.argv[2]))
except LockTimeoutError:
    raise SystemExit(3)
else:
    lock.release()
"""


def _child_try_lock(workspace: Path, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _CHILD, str(workspace), str(timeout)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_workspace_write_lock_contends_across_processes(tmp_path: Path) -> None:
    lock = WorkspaceWriteLock(tmp_path)
    with lock.held():
        blocked = _child_try_lock(tmp_path, 0.2)
    acquired = _child_try_lock(tmp_path, 2.0)

    assert blocked.returncode == 3, blocked.stderr
    assert acquired.returncode == 0, acquired.stderr
