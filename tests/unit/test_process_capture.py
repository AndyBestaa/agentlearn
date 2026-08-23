from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from astercode.tools.process import ProcessTools


def _tools(tmp_path: Path, *, max_output: int = 4_096) -> ProcessTools:
    return ProcessTools(
        [tmp_path],
        max_output=max_output,
        max_processes=8,
        sandbox_enforced=True,
        network_policy_enforced=True,
    )


def _wait_for_file(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path.name}")


def test_identical_starts_have_independent_process_handles(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    argv = [sys.executable, "-c", "import time; time.sleep(120)"]

    first = tools.start(argv, str(tmp_path), allow_unsandboxed=True)
    second = tools.start(argv, str(tmp_path), allow_unsandboxed=True)
    try:
        assert first.status == "completed", first.error
        assert second.status == "completed", second.error
        # The deterministic action remains the approval/idempotency binding.
        assert first.action_id == second.action_id
        # Each concrete process has a unique opaque lifecycle handle.
        assert first.stdout != second.stdout
        assert first.metadata["process_handle"] == first.stdout
        assert second.metadata["process_handle"] == second.stdout

        stopped_first = tools.stop(first.stdout)
        assert stopped_first.status == "completed", stopped_first.error
        assert first.stdout not in tools._children

        still_running = tools.poll(second.stdout)
        assert still_running.status == "completed", still_running.error
        assert still_running.metadata["state"] == "running"
        assert second.stdout in tools._children

        stopped_second = tools.stop(second.stdout)
        assert stopped_second.status == "completed", stopped_second.error
    finally:
        tools.stop_all()


def test_identical_concurrent_execs_use_unique_containment_keys(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    argv = [
        sys.executable,
        "-c",
        "import time; time.sleep(0.2); print('done')",
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                tools.exec,
                argv,
                str(tmp_path),
                10,
                allow_unsandboxed=True,
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=20) for future in futures]

    assert all(result.status == "completed" for result in results)
    assert results[0].action_id == results[1].action_id
    assert results[0].metadata["process_handle"] != results[1].metadata["process_handle"]
    assert not tools._children


def test_concurrent_starts_cannot_overrun_process_budget(tmp_path: Path) -> None:
    tools = ProcessTools(
        [tmp_path],
        max_processes=1,
        sandbox_enforced=True,
        network_policy_enforced=True,
    )
    argv = [sys.executable, "-c", "import time; time.sleep(120)"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                tools.start,
                argv,
                str(tmp_path),
                allow_unsandboxed=True,
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=20) for future in futures]

    started = [result for result in results if result.status == "completed"]
    rejected = [result for result in results if result.status == "failed"]
    try:
        assert len(started) == 1
        assert len(rejected) == 1
        assert "process-count limit reached" in str(rejected[0].error)
        assert len(tools._children) == 1
    finally:
        tools.stop_all()


def test_exec_drains_large_output_with_bounded_memory(tmp_path: Path) -> None:
    limit = 4_096
    tools = _tools(tmp_path, max_output=limit)
    result = tools.exec(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('O'*300000); "
            "sys.stderr.write('E'*250000)",
        ],
        str(tmp_path),
        timeout=20,
        allow_unsandboxed=True,
    )

    assert result.status == "completed", result.error
    assert len(result.stdout) <= limit
    assert len(result.stderr) <= limit
    assert result.stdout == "O" * limit
    assert result.stderr == "E" * limit
    assert result.truncated is True
    capture = result.metadata["capture"]
    assert capture["complete"] is True
    assert capture["stdout"]["observed_chars"] == 300_000
    assert capture["stderr"]["observed_chars"] == 250_000
    assert capture["stdout"]["observed_bytes"] == 300_000
    assert capture["stdout"]["retained_bytes"] == limit
    assert capture["stdout"]["discarded_bytes"] == 300_000 - limit
    assert capture["stdout"]["content_complete"] is False
    assert capture["stderr"]["observed_bytes"] == 250_000
    assert capture["stderr"]["retained_bytes"] == limit
    assert capture["stderr"]["discarded_bytes"] == 250_000 - limit
    assert capture["stderr"]["content_complete"] is False


def test_start_continuously_drains_large_output_before_poll(tmp_path: Path) -> None:
    marker = tmp_path / "output-drained"
    limit = 2_048
    tools = _tools(tmp_path, max_output=limit)
    code = (
        "import pathlib, sys, time; "
        "sys.stdout.write('O'*300000); sys.stdout.flush(); "
        "sys.stderr.write('E'*300000); sys.stderr.flush(); "
        "pathlib.Path(sys.argv[1]).write_text('ready', encoding='ascii'); "
        "time.sleep(120)"
    )
    started = tools.start(
        [sys.executable, "-c", code, str(marker)],
        str(tmp_path),
        allow_unsandboxed=True,
    )
    assert started.status == "completed", started.error
    try:
        # Without simultaneous pipe draining, the child blocks long before it
        # reaches this marker because each stream exceeds normal pipe capacity.
        _wait_for_file(marker)
        deadline = time.monotonic() + 5
        while True:
            polled = tools.poll(started.stdout)
            capture = polled.metadata["capture"]
            if (
                capture["stdout"]["observed_chars"] == 300_000
                and capture["stderr"]["observed_chars"] == 300_000
            ):
                break
            if time.monotonic() >= deadline:
                raise AssertionError("background capture did not drain both pipes")
            time.sleep(0.02)
        assert polled.metadata["state"] == "running"
        assert len(polled.stdout) <= limit
        assert len(polled.stderr) <= limit
        assert polled.truncated is True
        assert capture["stdout"]["observed_chars"] == 300_000
        assert capture["stderr"]["observed_chars"] == 300_000
        assert capture["stdout"]["discarded_bytes"] == 300_000 - limit
        assert capture["stderr"]["discarded_bytes"] == 300_000 - limit
    finally:
        tools.stop(started.stdout)


def test_exec_timeout_kills_descendant_that_inherits_pipes(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "pipe-child.pid"
    child_code = "import time; print('child-ready', flush=True); time.sleep(120)"
    parent_code = (
        "import pathlib, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', sys.argv[2]]); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii'); "
        "print('parent-ready', flush=True); time.sleep(120)"
    )
    tools = _tools(tmp_path)

    started_at = time.monotonic()
    result = tools.exec(
        [
            sys.executable,
            "-c",
            parent_code,
            str(child_pid_file),
            child_code,
        ],
        str(tmp_path),
        timeout=1,
        allow_unsandboxed=True,
    )
    elapsed = time.monotonic() - started_at

    assert result.status == "unknown"
    assert "timeout after 1.0s" in str(result.error)
    assert elapsed < 12
    assert result.metadata["process_tree_stop_confirmed"] is True
    assert result.metadata["capture"]["complete"] is True
    assert "parent-ready" in result.stdout
    assert "child-ready" in result.stdout
    _wait_for_file(child_pid_file)
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ProcessTools.process_identity(child_pid) == "missing":
            break
        time.sleep(0.02)
    assert ProcessTools.process_identity(child_pid) == "missing"
    if os.name == "nt":
        assert result.metadata["process_tree_containment"] == "windows_job_object"
