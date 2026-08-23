"""Docker-backed process execution with active, fail-closed attestation.

The Docker client is a trusted host adapter.  Model-provided argv is appended
as individual arguments after a fixed ``docker run`` boundary.  The host
workspace is mounted read-only and copied into a size-limited tmpfs where
builds may write without changing the user's files.  Agent state is hidden,
networking is disabled, and no Docker socket or host credentials enter the
container.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .base import ToolResult, new_action_id, timed_result
from .process import ProcessTools, _ProcessCapture


class DockerSandboxUnavailable(RuntimeError):
    """Raised when Docker cannot prove every required isolation property."""


_COPY_EXCLUDES = (
    ".astercode",
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
)
_COPY_AND_EXEC = """import os, shutil, sys
excluded = set(sys.argv[1].split(','))
def ignore(_directory, names):
    return [name for name in names if name in excluded or name.endswith('.pyc')]
shutil.copytree('/workspace-source', '/workspace', dirs_exist_ok=True, symlinks=True, ignore=ignore)
os.chdir(sys.argv[2])
os.execvp(sys.argv[3], sys.argv[3:])
"""


@dataclass(frozen=True, slots=True)
class DockerSandboxAttestation:
    executable: Path
    configured_image: str
    image_digest: str
    image_id: str
    engine_os: str = "linux"


def _trusted_docker_candidates() -> tuple[Path, ...]:
    if os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        return (
            local / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe",
            program_files / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
        )
    return (Path("/usr/bin/docker"), Path("/usr/local/bin/docker"))


def discover_trusted_docker() -> Path | None:
    """Return only a Docker CLI from a fixed installation location."""

    for candidate in _trusted_docker_candidates():
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _docker_host_env(executable: Path) -> dict[str, str]:
    allowed = {
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["PATH"] = str(executable.parent)
    # Never inherit a project/user-selected remote daemon, context, proxy or
    # credential-helper configuration.  Docker Desktop/Linux use their local
    # default endpoint when these variables are absent.
    return env


def _run_control(
    executable: Path,
    arguments: list[str],
    *,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(executable), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            env=_docker_host_env(executable),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DockerSandboxUnavailable(
            f"Docker control command failed ({type(exc).__name__})"
        ) from exc


def _resolve_local_image(
    executable: Path, configured_image: str
) -> tuple[str, str]:
    completed = _run_control(
        executable,
        ["image", "inspect", configured_image, "--format", "{{json .}}"],
    )
    if completed.returncode != 0:
        raise DockerSandboxUnavailable(
            f"configured sandbox image is not present locally: {configured_image}"
        )
    try:
        payload = json.loads(completed.stdout)
        image_id = str(payload["Id"])
        repo_digests = [str(item) for item in payload.get("RepoDigests") or []]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DockerSandboxUnavailable("Docker returned invalid image metadata") from exc
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise DockerSandboxUnavailable("Docker image ID is not a SHA-256 digest")
    if "@sha256:" in configured_image:
        requested = configured_image.rsplit("@", 1)[-1]
        if not any(item.rsplit("@", 1)[-1] == requested for item in repo_digests):
            raise DockerSandboxUnavailable("configured image digest does not match the local image")
        # Preserve the exact configured registry/repository.  A local alias
        # with the same content digest must not silently rewrite provenance.
        digest = configured_image
    else:
        digest = next(
            (
                item
                for item in repo_digests
                if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", item)
            ),
            "",
        )
    if not digest:
        raise DockerSandboxUnavailable(
            "sandbox image has no immutable RepoDigest; load or pull a signed registry image"
        )
    return digest, image_id


def _fixed_container_options(
    *,
    name: str,
    image: str,
    root: Path,
    user: str,
    max_processes: int,
    max_memory_bytes: int | None,
    cpus: float,
    tmpfs_bytes: int,
    workspace_bytes: int,
) -> list[str]:
    source = str(root)
    if "," in source or any(ord(char) < 32 for char in source):
        raise DockerSandboxUnavailable("authorized root cannot be represented as a Docker bind mount")
    uid, gid = user.split(":", 1)
    for hidden in (".astercode", ".git"):
        candidate = root / hidden
        is_junction = bool(getattr(candidate, "is_junction", lambda: False)())
        if candidate.is_symlink() or is_junction:
            raise DockerSandboxUnavailable(f"{hidden} cannot be a link or junction")
        if candidate.exists() and not candidate.is_dir():
            raise DockerSandboxUnavailable(
                f"{hidden} must be a directory so the container can hide it"
            )
    options = [
        "run",
        "--rm",
        "--interactive",
        "--init",
        "--name",
        name,
        "--label",
        f"astercode.process_handle={name}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(max_processes),
        "--cpus",
        str(cpus),
        "--user",
        user,
        "--stop-timeout",
        "3",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size={tmpfs_bytes},mode=0700,uid={uid},gid={gid}",
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,size={workspace_bytes},mode=0700,uid={uid},gid={gid}",
        "--mount",
        f"type=bind,source={source},target=/workspace-source,readonly",
        "--workdir",
        "/",
        "--env",
        "HOME=/tmp",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONUNBUFFERED=1",
    ]
    if max_memory_bytes is not None:
        options.extend(["--memory", str(max_memory_bytes), "--memory-swap", str(max_memory_bytes)])
    for hidden in (".astercode", ".git"):
        if (root / hidden).is_dir():
            options.extend(
                [
                    "--tmpfs",
                    f"/workspace-source/{hidden}:rw,nosuid,nodev,noexec,size=1048576",
                ]
            )
    options.append(image)
    return options


def _copy_and_exec_command(workdir: str, argv: list[str]) -> list[str]:
    """Copy sources and exec argv without evaluating model-provided text."""

    return [
        "python",
        "-c",
        _COPY_AND_EXEC,
        ",".join(_COPY_EXCLUDES),
        workdir,
        *argv,
    ]


def attest_docker_sandbox(
    *,
    configured_image: str,
    user: str,
    max_processes: int,
    max_memory_bytes: int | None,
    cpus: float,
    tmpfs_bytes: int,
    workspace_bytes: int,
) -> DockerSandboxAttestation:
    """Prove read-only host files, isolated writes and disabled network."""

    executable = discover_trusted_docker()
    if executable is None:
        raise DockerSandboxUnavailable("trusted Docker CLI was not found")
    version = _run_control(executable, ["version", "--format", "{{.Server.Os}}"])
    if version.returncode != 0 or version.stdout.strip().lower() != "linux":
        raise DockerSandboxUnavailable("a reachable Docker Linux engine is required")
    image_digest, image_id = _resolve_local_image(executable, configured_image)
    with tempfile.TemporaryDirectory(prefix="astercode-docker-probe-") as raw_root:
        root = Path(raw_root).resolve()
        root.chmod(0o755)
        (root / ".astercode").mkdir()
        (root / ".astercode" / "must-be-hidden").write_text("hidden", encoding="utf-8")
        (root / "visible.txt").write_text("visible", encoding="utf-8")
        name = f"astercode-probe-{os.getpid()}-{threading.get_ident()}".lower()
        probe = (
            "import json,pathlib,socket;"
            "src=pathlib.Path('/workspace-source');r=pathlib.Path('/workspace');"
            "root_blocked=False;source_blocked=False;network_blocked=False;"
            "\ntry:pathlib.Path('/root-write').write_text('x')"
            "\nexcept OSError:root_blocked=True"
            "\ntry:(src/'source-write').write_text('x')"
            "\nexcept OSError:source_blocked=True"
            "\n(r/'ephemeral-write').write_text('isolated')"
            "\ns=socket.socket();s.settimeout(0.5)"
            "\ntry:s.connect(('1.1.1.1',443))"
            "\nexcept OSError:network_blocked=True"
            "\nfinally:s.close()"
            "\nhidden=not (src/'.astercode'/'must-be-hidden').exists() and not (r/'.astercode').exists()"
            "\nephemeral=(r/'ephemeral-write').read_text()=='isolated'"
            "\nok=root_blocked and source_blocked and ephemeral and network_blocked and hidden and (r/'visible.txt').exists()"
            "\nprint(json.dumps({'ok':ok,'root_read_only':root_blocked,'host_source_read_only':source_blocked,'ephemeral_workspace_writable':ephemeral,'network_none':network_blocked,'state_hidden':hidden},sort_keys=True))"
            "\nraise SystemExit(0 if ok else 23)"
        )
        arguments = _fixed_container_options(
            name=name,
            image=image_digest,
            root=root,
            user=user,
            max_processes=max_processes,
            max_memory_bytes=max_memory_bytes,
            cpus=cpus,
            tmpfs_bytes=tmpfs_bytes,
            workspace_bytes=workspace_bytes,
        )
        completed = _run_control(
            executable,
            [
                *arguments,
                *_copy_and_exec_command(
                    "/workspace", ["python", "-c", probe]
                ),
            ],
            timeout=30,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[-500:]
            raise DockerSandboxUnavailable(
                f"Docker isolation probe failed: {detail or 'no diagnostic'}"
            )
        try:
            evidence = json.loads(completed.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise DockerSandboxUnavailable("Docker isolation probe returned invalid evidence") from exc
        if evidence.get("ok") is not True:
            raise DockerSandboxUnavailable("Docker isolation probe did not prove every boundary")
        if (root / "source-write").exists() or (root / "ephemeral-write").exists():
            raise DockerSandboxUnavailable("Docker probe writes escaped into the host workspace")
    return DockerSandboxAttestation(
        executable=executable,
        configured_image=configured_image,
        image_digest=image_digest,
        image_id=image_id,
    )


class DockerProcessTools(ProcessTools):
    """Run the existing process contract through one attested Linux image."""

    def __init__(
        self,
        roots: Iterable[str | Path],
        *,
        attestation: DockerSandboxAttestation,
        container_user: str,
        container_cpus: float,
        container_tmpfs_bytes: int,
        container_workspace_bytes: int,
        network_mode: str = "deny_by_default",
        max_output: int = 32_000,
        max_processes: int = 32,
        max_memory_bytes: int | None = None,
        max_cpu_time_seconds: float | None = None,
        max_timeout: float = 3_600.0,
    ) -> None:
        super().__init__(
            roots,
            network_mode=network_mode,
            max_output=max_output,
            sandbox_enforced=True,
            network_policy_enforced=True,
            max_processes=max_processes,
            max_memory_bytes=max_memory_bytes,
            max_cpu_time_seconds=max_cpu_time_seconds,
            max_timeout=max_timeout,
        )
        self.attestation = attestation
        self.container_user = container_user
        self.container_cpus = container_cpus
        self.container_tmpfs_bytes = container_tmpfs_bytes
        self.container_workspace_bytes = container_workspace_bytes
        self._container_names: dict[str, str] = {}

    def _root_and_container_cwd(self, workdir: Path) -> tuple[Path, str]:
        for root in self.roots:
            try:
                relative = workdir.relative_to(root)
            except ValueError:
                continue
            posix = relative.as_posix()
            return root, "/workspace" if posix == "." else f"/workspace/{posix}"
        raise PermissionError("cwd outside authorized roots")

    def _map_argument(self, value: str, root: Path) -> str:
        if "\x00" in value:
            raise ValueError("argv cannot contain NUL")
        candidate = Path(value)
        if candidate.is_absolute():
            with suppress(ValueError):
                relative = candidate.resolve(strict=False).relative_to(root)
                return f"/workspace/{relative.as_posix()}"
            basename = candidate.name.lower()
            if basename in {"python", "python.exe", "python3", "python3.exe"}:
                return "python"
            if value.startswith("/"):
                return value
            raise PermissionError("host executable/path cannot be passed into the Linux sandbox")
        if "\\" in value and (":" in value or value.startswith("\\")):
            raise PermissionError("Windows path outside the authorized root is not available in the sandbox")
        return value

    def _spawn(
        self,
        process_handle: str,
        argv: list[str],
        workdir: Path,
        env: Mapping[str, str],
        *,
        stdin: int,
    ) -> subprocess.Popen[str]:
        del env
        root, container_cwd = self._root_and_container_cwd(workdir)
        name = f"astercode-{process_handle.removeprefix('proc_')}".lower()
        command = [self._map_argument(item, root) for item in argv]
        docker_argv = [
            str(self.attestation.executable),
            *_fixed_container_options(
                name=name,
                image=self.attestation.image_digest,
                root=root,
                user=self.container_user,
                max_processes=self.max_processes,
                max_memory_bytes=self.max_memory_bytes,
                cpus=self.container_cpus,
                tmpfs_bytes=self.container_tmpfs_bytes,
                workspace_bytes=self.container_workspace_bytes,
            ),
            *_copy_and_exec_command(container_cwd, command),
        ]
        with self._state_lock:
            self._container_names[process_handle] = name
        try:
            return super()._spawn(
                process_handle,
                docker_argv,
                workdir,
                _docker_host_env(self.attestation.executable),
                stdin=stdin,
            )
        except Exception:
            with self._state_lock:
                self._container_names.pop(process_handle, None)
            raise

    def _containment_metadata(self, process_handle: str) -> dict[str, object]:
        with self._state_lock:
            name = self._container_names.get(process_handle)
        return {
            "process_tree_containment": "docker_linux_container",
            "container_name": name,
            "container_image": self.attestation.image_digest,
            "container_image_id": self.attestation.image_id,
            "filesystem_sandbox": True,
            "host_workspace_read_only": True,
            "ephemeral_workspace_writable": True,
            "ephemeral_workspace_limit": self.container_workspace_bytes,
            "copy_excludes": list(_COPY_EXCLUDES),
            "agent_state_hidden": True,
            "network_sandbox": True,
            "network_mode": "none",
            "capabilities_dropped": "ALL",
            "no_new_privileges": True,
            "container_user": self.container_user,
            "pids_limit": self.max_processes,
            "memory_limit": self.max_memory_bytes,
            "cpus": self.container_cpus,
        }

    def _container_absent(self, name: str) -> bool:
        completed = _run_control(
            self.attestation.executable,
            ["container", "inspect", name],
            timeout=5,
        )
        return completed.returncode != 0 and "No such" in completed.stderr

    def _terminate(self, action_id: str, proc: subprocess.Popen[str]) -> bool:
        with self._state_lock:
            name = self._container_names.get(action_id)
        container_stopped = name is None
        if name is not None:
            try:
                completed = _run_control(
                    self.attestation.executable,
                    ["container", "rm", "--force", name],
                    timeout=10,
                )
                container_stopped = completed.returncode == 0 or self._container_absent(name)
            except DockerSandboxUnavailable:
                container_stopped = False
        client_stopped = super()._terminate(action_id, proc)
        return container_stopped and client_stopped

    def _release_action(
        self,
        process_handle: str,
        proc: subprocess.Popen[str],
        *,
        capture_wait: float = 1.0,
    ) -> _ProcessCapture | None:
        try:
            return super()._release_action(
                process_handle, proc, capture_wait=capture_wait
            )
        finally:
            with self._state_lock:
                self._container_names.pop(process_handle, None)

    def shell(
        self,
        script: str,
        dialect: str,
        cwd: str,
        timeout: float = 120,
        *,
        allow_unsandboxed: bool = False,
    ) -> ToolResult:
        if dialect != "bash":
            result = timed_result(
                "shell.exec",
                new_action_id(
                    "shell.exec", {"script": script, "dialect": dialect, "cwd": cwd}
                ),
                cwd,
            )
            result.status = "failed"
            result.error = "the current Docker Linux sandbox supports only the bash dialect"
            return result.finish()
        result = self.exec(
            ["bash", "--noprofile", "--norc", "-c", script],
            cwd,
            timeout,
            allow_unsandboxed=allow_unsandboxed,
        )
        result.tool = "shell.exec"
        return result


__all__ = [
    "DockerProcessTools",
    "DockerSandboxAttestation",
    "DockerSandboxUnavailable",
    "attest_docker_sandbox",
    "discover_trusted_docker",
]
