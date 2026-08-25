from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import ApprovalDecision
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage
from astercode.tools.docker_process import (
    DockerProcessTools,
    DockerSandboxAttestation,
    DockerSandboxUnavailable,
    attest_docker_sandbox,
)


def _live_attestation() -> DockerSandboxAttestation:
    try:
        return attest_docker_sandbox(
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
        if os.environ.get("ASTERCODE_REQUIRE_LIVE_DOCKER") == "1":
            raise AssertionError(f"required live Docker sandbox unavailable: {exc}") from exc
        pytest.skip(f"live Docker sandbox unavailable: {exc}")


def _live_tools(tmp_path: Path) -> DockerProcessTools:
    attestation = _live_attestation()
    return DockerProcessTools(
        [tmp_path],
        attestation=attestation,
        container_user="65534:65534",
        container_cpus=1.0,
        container_tmpfs_bytes=16_777_216,
        container_workspace_bytes=67_108_864,
        artifacts_dir=tmp_path / ".astercode" / "artifacts",
        artifact_max_bytes=1_048_576,
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


def test_live_docker_persisted_identity_can_stop_after_executor_restart(
    tmp_path: Path,
) -> None:
    tools = _live_tools(tmp_path)
    started = tools.start(
        ["python", "-c", "import time; time.sleep(120)"],
        str(tmp_path),
        allow_unsandboxed=True,
    )
    assert started.status == "completed"
    handle = started.stdout
    record = {
        "pid": started.metadata["pid"],
        "identity_token": started.metadata["identity_token"],
        "backend_kind": started.metadata["process_tree_containment"],
        "backend_ref": started.metadata["container_name"],
        "backend_identity": started.metadata["container_image_id"],
    }
    try:
        assert DockerProcessTools.terminate_registered_record(record) is True
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            polled = tools.poll(handle)
            if polled.metadata.get("state") == "exited":
                break
            time.sleep(0.1)
        assert polled.metadata["state"] == "exited"
    finally:
        tools.stop_all()


def test_live_docker_exports_only_requested_regular_files(tmp_path: Path) -> None:
    script = tmp_path / "build.py"
    script.write_text(
        "from pathlib import Path\n"
        "try:\n"
        "    Path('/exports/injected.txt').write_text('must fail', encoding='utf-8')\n"
        "except PermissionError:\n"
        "    pass\n"
        "Path('dist').mkdir()\n"
        "Path('dist/result.txt').write_text('verified artifact', encoding='utf-8')\n"
        "Path('dist/not-requested.txt').write_text('private build output', encoding='utf-8')\n",
        encoding="utf-8",
    )
    tools = _live_tools(tmp_path)

    result = tools.exec_export(
        ["python", "build.py"],
        str(tmp_path),
        20,
        ["dist/result.txt"],
        allow_unsandboxed=True,
    )

    assert result.status == "completed", result.error
    assert result.metadata["container_cleanup_confirmed"] is True
    assert result.metadata["exported_bytes"] == len("verified artifact")
    assert len(result.artifacts) == 1
    exported = Path(result.artifacts[0])
    assert exported.read_text(encoding="utf-8") == "verified artifact"
    assert not (exported.parent / "not-requested.txt").exists()
    assert not any(path.name == "injected.txt" for path in exported.parents[1].rglob("*"))
    assert not (tmp_path / "dist").exists()


@pytest.mark.asyncio
async def test_fake_model_to_approval_to_docker_artifact_export(
    app_config: AppConfig, storage: Storage, tmp_path: Path
) -> None:
    script = tmp_path / "package.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('dist').mkdir()\n"
        "Path('dist/package.txt').write_text('package evidence', encoding='utf-8')\n",
        encoding="utf-8",
    )
    provider = DeterministicFakeProvider(
        [
            {
                "plan": ["build and export the requested package"],
                "message": "requesting exact build export approval",
                "tool_calls": [
                    {
                        "tool": "process.exec_export",
                        "arguments": {
                            "argv": ["python", "package.py"],
                            "cwd": str(tmp_path),
                            "timeout": 20,
                            "artifact_paths": ["dist/package.txt"],
                        },
                        "host": "local",
                        "cwd": str(tmp_path),
                        "purpose": "retain the requested build artifact",
                    }
                ],
                "outcome": "continue",
            },
            {
                "plan": [],
                "message": "artifact exported with runtime evidence",
                "tool_calls": [],
                "outcome": "completed",
            },
        ]
    )
    config_data = app_config.model_dump(mode="python")
    config_data["security"]["process"]["sandbox_backend"] = "container"
    config = AppConfig.model_validate(config_data)
    orchestrator = Orchestrator(
        config,
        provider=provider,
        registry=build_registry(
            config, docker_attestation=_live_attestation()
        ),
        storage=storage,
    )
    paused = await asyncio.wait_for(
        orchestrator.run("build and retain package.txt"), timeout=30
    )
    try:
        assert paused["status"] == "waiting_approval"
        request = paused["approval_request"]
        # Running an interpreter remains P3 even though the export tool itself
        # declares a P2 minimum. Concrete command risk always wins.
        assert request["risk"] == "P3"
        decision = ApprovalDecision(
            approval_id=request["approval_id"],
            action_id=request["action_id"],
            action_hash=request["action_hash"],
            nonce=request["nonce"],
            approved=True,
            actor="integration-test",
        )
        result = await asyncio.wait_for(
            orchestrator.resume(
                paused["session_id"], decision.model_dump(mode="json")
            ),
            timeout=30,
        )
        assert result["status"] == "completed"
        exported = Path(result["tool_results"][0]["artifacts"][0])
        assert exported.read_text(encoding="utf-8") == "package evidence"
        assert result["tool_results"][0]["metadata"]["container_cleanup_confirmed"] is True
        assert len(result["tool_results"][0]["metadata"]["exported_artifact_ids"]) == 1
    finally:
        await orchestrator.close()
