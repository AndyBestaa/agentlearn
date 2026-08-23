from __future__ import annotations

import time
from pathlib import Path

import pytest

from astercode.tools.docker_process import (
    DockerProcessTools,
    DockerSandboxUnavailable,
    attest_docker_sandbox,
)


def _live_tools(tmp_path: Path) -> DockerProcessTools:
    try:
        attestation = attest_docker_sandbox(
            configured_image=(
                "mirror.gcr.io/library/python@"
                "sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a"
            ),
            user="65534:65534",
            max_processes=16,
            max_memory_bytes=268_435_456,
            cpus=1.0,
            tmpfs_bytes=16_777_216,
            workspace_bytes=67_108_864,
        )
    except DockerSandboxUnavailable as exc:
        pytest.skip(f"live Docker sandbox unavailable: {exc}")
    return DockerProcessTools(
        [tmp_path],
        attestation=attestation,
        container_user="65534:65534",
        container_cpus=1.0,
        container_tmpfs_bytes=16_777_216,
        container_workspace_bytes=67_108_864,
        max_processes=16,
        max_memory_bytes=268_435_456,
    )


def test_live_docker_exec_writes_only_ephemeral_copy(tmp_path: Path) -> None:
    (tmp_path / "hello.py").write_text('print("hello from sandbox")\n', encoding="utf-8")
    tools = _live_tools(tmp_path)
    read = tools.exec(
        ["python", "hello.py"],
        str(tmp_path),
        timeout=20,
        allow_unsandboxed=True,
    )
    assert read.status == "completed"
    assert read.stdout.strip() == "hello from sandbox"
    assert read.metadata["filesystem_sandbox"] is True
    assert read.metadata["network_sandbox"] is True
    assert read.metadata["host_workspace_read_only"] is True
    assert read.metadata["ephemeral_workspace_writable"] is True

    write = tools.exec(
        [
            "python",
            "-c",
            "from pathlib import Path; Path('forbidden.txt').write_text('x')",
        ],
        str(tmp_path),
        timeout=20,
        allow_unsandboxed=True,
    )
    assert write.status == "completed"
    assert not (tmp_path / "forbidden.txt").exists()

    compiled = tools.exec(
        ["python", "-m", "compileall", "-q", "."],
        str(tmp_path),
        timeout=20,
        allow_unsandboxed=True,
    )
    assert compiled.status == "completed"
    assert not (tmp_path / "__pycache__").exists()


def test_live_docker_network_and_agent_state_are_unavailable(tmp_path: Path) -> None:
    state = tmp_path / ".astercode"
    state.mkdir()
    (state / "secret-state.txt").write_text("must not enter sandbox", encoding="utf-8")
    environment = tmp_path / ".venv"
    environment.mkdir()
    (environment / "host-only.txt").write_text("must not be copied", encoding="utf-8")
    tools = _live_tools(tmp_path)
    result = tools.exec(
        [
            "python",
            "-c",
            (
                "import pathlib,socket; "
                "print('state_visible=' + str(pathlib.Path('/workspace/.astercode/secret-state.txt').exists())); "
                "print('venv_visible=' + str(pathlib.Path('/workspace/.venv/host-only.txt').exists())); "
                "s=socket.socket(); s.settimeout(.5); "
                "\ntry: s.connect(('1.1.1.1',443)); print('network=OPEN')"
                "\nexcept OSError: print('network=BLOCKED')"
                "\nfinally: s.close()"
            ),
        ],
        str(tmp_path),
        timeout=20,
        allow_unsandboxed=True,
    )
    assert result.status == "completed"
    assert "state_visible=False" in result.stdout
    assert "venv_visible=False" in result.stdout
    assert "network=BLOCKED" in result.stdout


def test_live_docker_timeout_and_stop_leave_no_container(tmp_path: Path) -> None:
    tools = _live_tools(tmp_path)
    timed_out = tools.exec(
        ["python", "-c", "import time; time.sleep(30)"],
        str(tmp_path),
        timeout=0.5,
        allow_unsandboxed=True,
    )
    assert timed_out.status == "unknown"
    assert timed_out.metadata["process_tree_stop_confirmed"] is True
    assert tools._container_names == {}

    started = tools.start(
        ["python", "-c", "import time; print('ready', flush=True); time.sleep(30)"],
        str(tmp_path),
        allow_unsandboxed=True,
    )
    assert started.status == "completed"
    handle = started.stdout
    deadline = time.monotonic() + 10
    observed = ""
    while time.monotonic() < deadline:
        polled = tools.poll(handle)
        observed += polled.stdout
        if "ready" in observed:
            break
        time.sleep(0.1)
    assert "ready" in observed
    stopped = tools.stop(handle)
    assert stopped.status == "completed"
    assert tools._container_names == {}
