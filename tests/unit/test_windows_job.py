from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from astercode.tools import process as process_module
from astercode.tools.process import ProcessTools
from astercode.windows_job import (
    CREATE_SUSPENDED,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    WindowsJobError,
    WindowsJobLimits,
    WindowsJobObject,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job Object tests")
CREATE_NEW_PROCESS_GROUP = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def _wait_for_pid_file(path: Path, timeout: float = 10.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = path.read_text(encoding="ascii").strip()
            if value:
                return int(value)
        except (FileNotFoundError, OSError, ValueError):
            # ``Path.write_text`` creates the file before its payload becomes
            # visible. Wait for a complete numeric PID instead of only the
            # directory entry, otherwise this assertion is race-prone.
            pass
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for a complete PID in {path.name}")


def _wait_for_identity_change(pid: int, identity: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ProcessTools.process_identity(pid) != identity:
            return
        time.sleep(0.02)
    raise AssertionError(f"process {pid} remained alive after Job termination")


def test_job_limit_flags_and_handle_lifecycle() -> None:
    job = WindowsJobObject(
        WindowsJobLimits(active_process_limit=3, job_memory_limit=64 * 1024 * 1024)
    )
    try:
        assert job.limit_flags == (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        assert job.active_process_count() == 0
        assert not job.closed
    finally:
        job.close()
        job.close()
    assert job.closed


def test_job_cpu_time_limit_terminates_busy_process(tmp_path: Path) -> None:
    job = WindowsJobObject(
        WindowsJobLimits(active_process_limit=1, job_cpu_time_limit_seconds=0.2)
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", "while True: pass"],
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
    )
    try:
        assert job.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME
        job.assign_and_resume(proc.pid)
        proc.wait(timeout=10)
        assert proc.returncode != 0
        assert job.active_process_count() == 0
    finally:
        job.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_job_active_process_limit_blocks_child_creation(tmp_path: Path) -> None:
    child_marker = tmp_path / "child-created"
    code = (
        "import pathlib, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(30)"
    )
    job = WindowsJobObject(WindowsJobLimits(active_process_limit=1))
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(child_marker)],
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
    )
    try:
        job.assign_and_resume(proc.pid)
        proc.wait(timeout=10)
        assert proc.returncode != 0
        assert not child_marker.exists()
        assert job.active_process_count() == 0
    finally:
        job.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_job_memory_limit_blocks_large_allocation(tmp_path: Path) -> None:
    allocation_marker = tmp_path / "allocation-succeeded"
    code = (
        "import pathlib, sys, time; "
        "payload=bytearray(512*1024*1024); "
        "pathlib.Path(sys.argv[1]).write_text(str(len(payload)), encoding='ascii'); "
        "time.sleep(30)"
    )
    job = WindowsJobObject(
        WindowsJobLimits(active_process_limit=1, job_memory_limit=64 * 1024 * 1024)
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(allocation_marker)],
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
    )
    try:
        job.assign_and_resume(proc.pid)
        proc.wait(timeout=10)
        assert proc.returncode != 0
        assert not allocation_marker.exists()
        assert job.active_process_count() == 0
    finally:
        job.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_kill_on_close_terminates_process_tree(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "child.pid"
    parent_code = (
        "import pathlib, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(120)"
    )
    job = WindowsJobObject(WindowsJobLimits(active_process_limit=4))
    proc = subprocess.Popen(
        [sys.executable, "-c", parent_code, str(child_pid_file)],
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
    )
    try:
        job.assign_and_resume(proc.pid)
        parent_identity = ProcessTools.process_identity(proc.pid)
        assert isinstance(parent_identity, str) and parent_identity != "missing"
        child_pid = _wait_for_pid_file(child_pid_file)
        child_identity = ProcessTools.process_identity(child_pid)
        assert isinstance(child_identity, str) and child_identity != "missing"

        job.close()
        proc.wait(timeout=10)
        assert proc.poll() is not None
        _wait_for_identity_change(child_pid, child_identity)
    finally:
        job.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_job_kill_on_host_process_crash_prevents_cross_process_orphan(
    tmp_path: Path,
) -> None:
    child_pid_file = tmp_path / "crash-child.pid"
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text("import time\ntime.sleep(120)\n", encoding="utf-8")
    helper = tmp_path / "crashing_host.py"
    helper.write_text(
        "import os, pathlib, sys, time\n"
        "from astercode.tools.process import ProcessTools\n"
        "root = pathlib.Path(sys.argv[1])\n"
        "tools = ProcessTools([root], max_processes=4, "
        "sandbox_enforced=True, network_policy_enforced=True)\n"
        "result = tools.start([sys.executable, sys.argv[2]], str(root), "
        "allow_unsandboxed=True)\n"
        "if result.status != 'completed': raise RuntimeError(result.error)\n"
        "pathlib.Path(sys.argv[3]).write_text(str(result.metadata['pid']), "
        "encoding='ascii')\n"
        "time.sleep(0.25)\n"
        "os._exit(23)\n",
        encoding="utf-8",
    )
    host = subprocess.Popen(
        [sys.executable, str(helper), str(tmp_path), str(sleeper), str(child_pid_file)],
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=CREATE_NEW_PROCESS_GROUP,
    )
    child_pid: int | None = None
    try:
        child_pid = _wait_for_pid_file(child_pid_file)
        identity = ProcessTools.process_identity(child_pid)
        assert isinstance(identity, str)
        host.wait(timeout=10)
        assert host.returncode == 23
        _wait_for_identity_change(child_pid, identity)
    finally:
        if host.poll() is None:
            host.kill()
            host.wait(timeout=5)
        if child_pid is not None and ProcessTools.process_identity(child_pid) != "missing":
            ProcessTools._run_windows_taskkill(child_pid)


def test_process_tools_assigns_job_before_resuming(tmp_path: Path) -> None:
    result = ProcessTools(
        [tmp_path],
        max_processes=4,
        max_memory_bytes=128 * 1024 * 1024,
        max_cpu_time_seconds=60,
        sandbox_enforced=True,
        network_policy_enforced=True,
    ).exec(
        [sys.executable, "-c", "print('contained')"],
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "completed"
    assert result.stdout.strip() == "contained"
    assert result.metadata["process_tree_containment"] == "windows_job_object"
    assert result.metadata["kill_on_job_close"] is True
    assert result.metadata["active_process_limit"] == 4
    assert result.metadata["job_memory_limit"] == 128 * 1024 * 1024
    assert result.metadata["job_cpu_time_limit_seconds"] == 60
    assert result.metadata["filesystem_sandbox"] is False
    assert result.metadata["network_sandbox"] is False


def test_assignment_failure_never_runs_target_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "must-not-exist"

    def fail_assignment(self: WindowsJobObject, pid: int) -> None:
        del self, pid
        raise WindowsJobError("simulated incompatible parent Job")

    monkeypatch.setattr(WindowsJobObject, "assign_and_resume", fail_assignment)
    result = ProcessTools(
        [tmp_path], sandbox_enforced=True, network_policy_enforced=True
    ).exec(
        [
            sys.executable,
            "-c",
            "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(marker),
        ],
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "failed"
    assert "incompatible parent Job" in str(result.error)
    assert not marker.exists()


def test_assignment_failure_recovers_registered_popen_after_first_wait_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "must-stay-suspended"
    real_popen = process_module.subprocess.Popen
    wait_calls = 0

    def fail_assignment(self: WindowsJobObject, pid: int) -> None:
        del self, pid
        raise WindowsJobError("simulated assignment failure")

    def popen_with_one_false_timeout(*args, **kwargs):
        nonlocal wait_calls
        proc = real_popen(*args, **kwargs)
        real_wait = proc.wait

        def wait(*, timeout=None):
            nonlocal wait_calls
            wait_calls += 1
            if wait_calls == 1:
                raise subprocess.TimeoutExpired(proc.args, timeout)
            return real_wait(timeout=timeout)

        proc.wait = wait  # type: ignore[method-assign]
        return proc

    monkeypatch.setattr(WindowsJobObject, "assign_and_resume", fail_assignment)
    monkeypatch.setattr(process_module.subprocess, "Popen", popen_with_one_false_timeout)
    tools = ProcessTools(
        [tmp_path], sandbox_enforced=True, network_policy_enforced=True
    )

    result = tools.exec(
        [
            sys.executable,
            "-c",
            "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(marker),
        ],
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "failed"
    assert result.metadata["process_tree_stop_confirmed"] is True
    assert result.metadata["process_handle"].startswith("proc_")
    assert wait_calls >= 2
    assert not tools._children
    assert not tools._windows_jobs
    assert not marker.exists()


def test_process_tools_stop_terminates_full_job_tree(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "managed-child.pid"
    parent_code = (
        "import pathlib, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(120)"
    )
    tools = ProcessTools(
        [tmp_path],
        max_processes=4,
        sandbox_enforced=True,
        network_policy_enforced=True,
    )
    started = tools.start(
        [sys.executable, "-c", parent_code, str(child_pid_file)],
        str(tmp_path),
        allow_unsandboxed=True,
    )
    assert started.status == "completed", started.error
    action_id = started.stdout
    try:
        child_pid = _wait_for_pid_file(child_pid_file)
        child_identity = ProcessTools.process_identity(child_pid)
        assert isinstance(child_identity, str) and child_identity != "missing"

        stopped = tools.stop(action_id)

        assert stopped.status == "completed", stopped.error
        assert action_id not in tools._children
        _wait_for_identity_change(child_pid, child_identity)
    finally:
        tools.stop_all()
