from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig, SandboxBackend
from astercode.policy import PolicyEngine
from astercode.runtime import _policy_capabilities, build_registry
from astercode.tools.docker_process import (
    DockerProcessTools,
    DockerSandboxAttestation,
    DockerSandboxUnavailable,
    _copy_and_exec_command,
    _docker_host_env,
    _fixed_container_options,
    _resolve_local_image,
    discover_trusted_image_tool,
)
from astercode.tools.process import ProcessTools


def _attestation() -> DockerSandboxAttestation:
    return DockerSandboxAttestation(
        executable=Path(r"C:\trusted\docker.exe"),
        configured_image="mcr.microsoft.com/devcontainers/python:3.12-bookworm",
        image_digest="python@sha256:" + "a" * 64,
        image_id="sha256:" + "b" * 64,
    )


def test_container_options_enforce_fixed_ephemeral_offline_boundary(tmp_path: Path) -> None:
    (tmp_path / ".astercode").mkdir()
    (tmp_path / ".git").mkdir()
    arguments = _fixed_container_options(
        name="astercode-test",
        image="python@sha256:" + "a" * 64,
        root=tmp_path,
        user="65534:65534",
        max_processes=16,
        max_memory_bytes=268_435_456,
        cpus=1.0,
        tmpfs_bytes=8_388_608,
        workspace_bytes=67_108_864,
    )

    assert arguments[:2] == ["run", "--rm"]
    assert arguments[arguments.index("--network") + 1] == "none"
    assert "--read-only" in arguments
    assert arguments[arguments.index("--cap-drop") + 1] == "ALL"
    assert arguments[arguments.index("--security-opt") + 1] == "no-new-privileges:true"
    assert arguments[arguments.index("--user") + 1] == "65534:65534"
    assert arguments[arguments.index("--memory") + 1] == "268435456"
    assert any("target=/workspace-source,readonly" in item for item in arguments)
    assert any(item.startswith("/workspace:rw,") and "size=67108864" in item for item in arguments)
    assert any("/workspace-source/.astercode:" in item for item in arguments)
    assert any("/workspace-source/.git:" in item for item in arguments)
    assert not any("docker.sock" in item.lower() for item in arguments)
    assert arguments[-1] == "python@sha256:" + "a" * 64


def test_container_options_reject_unrepresentable_mount(tmp_path: Path) -> None:
    root = tmp_path / "comma,name"
    root.mkdir()
    with pytest.raises(DockerSandboxUnavailable, match="bind mount"):
        _fixed_container_options(
            name="astercode-test",
            image="python@sha256:" + "a" * 64,
            root=root,
            user="65534:65534",
            max_processes=8,
            max_memory_bytes=None,
            cpus=1.0,
            tmpfs_bytes=1_048_576,
            workspace_bytes=16_777_216,
        )


def test_container_options_reject_git_file_that_cannot_be_hidden(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text("gitdir: outside", encoding="utf-8")
    with pytest.raises(DockerSandboxUnavailable, match="must be a directory"):
        _fixed_container_options(
            name="astercode-test",
            image="python@sha256:" + "a" * 64,
            root=tmp_path,
            user="65534:65534",
            max_processes=8,
            max_memory_bytes=None,
            cpus=1.0,
            tmpfs_bytes=1_048_576,
            workspace_bytes=16_777_216,
        )


def test_image_security_tool_discovery_does_not_trust_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PATH", r"C:\untrusted")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty-localappdata"))
    assert discover_trusted_image_tool("cosign") is None
    with pytest.raises(ValueError, match="invalid"):
        discover_trusted_image_tool("cosign.exe")


def test_export_container_is_retained_until_artifacts_are_copied(
    tmp_path: Path,
) -> None:
    arguments = _fixed_container_options(
        name="astercode-test",
        image="python@sha256:" + "a" * 64,
        root=tmp_path,
        user="65534:65534",
        max_processes=8,
        max_memory_bytes=None,
        cpus=1.0,
        tmpfs_bytes=1_048_576,
        workspace_bytes=16_777_216,
        auto_remove=False,
    )

    assert arguments[0] == "run"
    assert "--rm" not in arguments


@pytest.mark.parametrize(
    "value",
    ["../secret", "/absolute", "a\\b", "a//b", "./file", ""],
)
def test_artifact_export_rejects_ambiguous_or_escaping_paths(value: str) -> None:
    with pytest.raises(ValueError, match="artifact paths"):
        DockerProcessTools._validated_artifact_paths([value])


def test_copy_wrapper_does_not_evaluate_model_arguments() -> None:
    malicious = "value;$(touch /tmp/owned)"
    command = _copy_and_exec_command("/workspace", ["python", malicious])
    assert command[-2:] == ["python", malicious]
    assert malicious not in command[2]


def _local_copy_wrapper_command(
    source: Path, destination: Path, argv: list[str]
) -> list[str]:
    command = _copy_and_exec_command(str(destination), argv)
    script = command[2].replace("'/workspace-source'", json.dumps(str(source)))
    script = script.replace("'/workspace'", json.dumps(str(destination)))
    return [sys.executable, "-c", script, *command[3:]]


def test_copy_wrapper_verifies_a_stable_snapshot_before_exec(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "input.txt").write_text("stable", encoding="utf-8")

    completed = subprocess.run(
        _local_copy_wrapper_command(
            source,
            destination,
            [sys.executable, "-c", "print(open('input.txt').read())"],
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=10,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "stable"


def test_copy_wrapper_refuses_a_source_change_before_exec(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    changed = source / "input.txt"
    changed.write_text("before", encoding="utf-8")
    command = _local_copy_wrapper_command(
        source,
        destination,
        [sys.executable, "-c", "raise SystemExit('must not execute')"],
    )
    mutation = f"open({str(changed)!r}, 'w', encoding='utf-8').write('after')\n"
    command[2] = command[2].replace(
        f"source_before = manifest({json.dumps(str(source))})\n",
        f"source_before = manifest({json.dumps(str(source))})\n{mutation}",
    )

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=10,
    )

    assert completed.returncode == 86
    assert "workspace changed" in completed.stderr
    assert "must not execute" not in completed.stderr


def test_docker_control_environment_drops_remote_and_proxy_overrides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    monkeypatch.setenv("DOCKER_CONFIG", r"C:\untrusted")
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid")
    executable = tmp_path / "docker"
    env = _docker_host_env(executable)
    assert "DOCKER_HOST" not in env
    assert "DOCKER_CONTEXT" not in env
    assert "DOCKER_CONFIG" not in env
    assert "HTTP_PROXY" not in env
    assert env["PATH"] == str(tmp_path)


def test_local_tag_is_resolved_to_immutable_repo_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "python@sha256:" + "a" * 64
    payload = {"Id": "sha256:" + "b" * 64, "RepoDigests": [digest]}
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(payload), stderr=""
    )
    monkeypatch.setattr(
        "astercode.tools.docker_process._run_control", lambda *args, **kwargs: completed
    )
    assert _resolve_local_image(Path("docker"), "python:3.12-slim") == (
        digest,
        "sha256:" + "b" * 64,
    )


def test_configured_digest_must_match_local_repo_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "Id": "sha256:" + "b" * 64,
        "RepoDigests": ["python@sha256:" + "a" * 64],
    }
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(payload), stderr=""
    )
    monkeypatch.setattr(
        "astercode.tools.docker_process._run_control", lambda *args, **kwargs: completed
    )
    with pytest.raises(DockerSandboxUnavailable, match="does not match"):
        _resolve_local_image(
            Path("docker"), "python:3.12-slim@sha256:" + "c" * 64
        )


def test_configured_digest_preserves_exact_registry_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "mirror.gcr.io/library/python@sha256:" + "a" * 64
    payload = {
        "Id": "sha256:" + "b" * 64,
        "RepoDigests": ["python@sha256:" + "a" * 64],
    }
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(payload), stderr=""
    )
    monkeypatch.setattr(
        "astercode.tools.docker_process._run_control", lambda *args, **kwargs: completed
    )
    assert _resolve_local_image(Path("docker"), requested)[0] == requested


def test_runtime_uses_attested_docker_executor_and_derives_policy_capabilities(
    app_config: AppConfig,
) -> None:
    data = app_config.model_dump(mode="python")
    data["security"]["process"]["sandbox_backend"] = SandboxBackend.CONTAINER
    config = AppConfig.model_validate(data)
    registry = build_registry(config, docker_attestation=_attestation())
    process = next(
        provider for provider in registry.providers() if isinstance(provider, ProcessTools)
    )
    assert isinstance(process, DockerProcessTools)
    capabilities = _policy_capabilities(registry)
    assert capabilities.process_sandbox_enforced is True
    assert capabilities.process_network_policy_enforced is True
    spec, _handler = registry.get("process.exec_export")
    assert spec.side_effects == ("process_start", "artifact_write")
    decision = PolicyEngine(config, runtime_capabilities=capabilities).evaluate(
        "process.exec_export",
        {
            "argv": ["python", "build.py"],
            "cwd": str(app_config.project_root),
            "timeout": 30,
            "artifact_paths": ["dist/result.txt"],
        },
        cwd=str(app_config.project_root),
        declared=spec,
        purpose="build and retain the requested artifact",
    )
    assert decision.decision == "approval_required"
    assert decision.approval is not None
    assert str(config.storage.artifacts_dir) in decision.approval.real_paths


def test_docker_argument_mapping_keeps_model_values_as_single_argv(tmp_path: Path) -> None:
    tools = DockerProcessTools(
        [tmp_path],
        attestation=_attestation(),
        container_user="65534:65534",
        container_cpus=1.0,
        container_tmpfs_bytes=8_388_608,
        container_workspace_bytes=67_108_864,
    )
    malicious = "name;$(touch owned);Write-Output hacked"
    assert tools._map_argument(malicious, tmp_path) == malicious
    script = tmp_path / "hello.py"
    assert tools._map_argument(str(script), tmp_path) == "/workspace/hello.py"


def test_process_security_defaults_request_container_without_claiming_proof(
    tmp_path: Path,
) -> None:
    config = AppConfig.model_validate(
        {
            "project_root": tmp_path,
            "security": {"authorized_roots": [tmp_path]},
            "storage": {},
        }
    )
    assert config.security.process.sandbox_backend is SandboxBackend.CONTAINER
    assert config.security.process.container_image.endswith(
        "@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a"
    )
    assert config.security.process.container_workspace_bytes == 536_870_912
    assert config.security.process.has_enforced_sandbox is False


def test_persisted_container_is_removed_only_after_identity_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    name = "astercode-" + "a" * 32
    image_id = "sha256:" + "b" * 64
    calls: list[list[str]] = []
    exists = True

    def fake_control(
        _executable: Path, arguments: list[str], *, timeout: float = 15.0
    ) -> subprocess.CompletedProcess[str]:
        nonlocal exists
        del timeout
        calls.append(arguments)
        if arguments[1] == "inspect":
            if not exists:
                return subprocess.CompletedProcess(
                    arguments, 1, "", f"Error: No such object: {name}"
                )
            payload = {
                "Name": "/" + name,
                "Image": image_id,
                "Config": {"Labels": {"astercode.process_handle": name}},
            }
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")
        exists = False
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(
        "astercode.tools.docker_process.discover_trusted_docker",
        lambda: tmp_path / "docker",
    )
    monkeypatch.setattr("astercode.tools.docker_process._run_control", fake_control)
    monkeypatch.setattr(
        DockerProcessTools, "process_identity", staticmethod(lambda _pid: "missing")
    )

    stopped = DockerProcessTools.terminate_registered_record(
        {
            "pid": 4242,
            "identity_token": "old-process",
            "backend_kind": "docker_linux_container",
            "backend_ref": name,
            "backend_identity": image_id,
        }
    )

    assert stopped is True
    assert calls[0][:2] == ["container", "inspect"]
    assert calls[1] == ["container", "rm", "--force", name]


def test_persisted_container_identity_mismatch_is_never_removed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    name = "astercode-" + "a" * 32
    expected_image = "sha256:" + "b" * 64
    payload = {
        "Name": "/" + name,
        "Image": "sha256:" + "c" * 64,
        "Config": {"Labels": {"astercode.process_handle": name}},
    }
    calls: list[list[str]] = []

    def fake_control(
        _executable: Path, arguments: list[str], *, timeout: float = 15.0
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

    monkeypatch.setattr(
        "astercode.tools.docker_process.discover_trusted_docker",
        lambda: tmp_path / "docker",
    )
    monkeypatch.setattr("astercode.tools.docker_process._run_control", fake_control)

    stopped = DockerProcessTools.terminate_registered_record(
        {
            "pid": 4242,
            "identity_token": "process-token",
            "backend_kind": "docker_linux_container",
            "backend_ref": name,
            "backend_identity": expected_image,
        }
    )

    assert stopped is False
    assert len(calls) == 1
