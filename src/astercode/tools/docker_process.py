"""Docker-backed process execution with active, fail-closed attestation.

The Docker client is a trusted host adapter.  Model-provided argv is appended
as individual arguments after a fixed ``docker run`` boundary.  The host
workspace is mounted read-only and copied into a size-limited tmpfs where
builds may write without changing the user's files.  Agent state is hidden,
networking is disabled, and no Docker socket or host credentials enter the
container.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .base import ToolResult, ToolSpec, new_action_id, timed_result
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
_COPY_AND_EXEC = """import hashlib, os, shutil, stat, sys
excluded = set(sys.argv[1].split(','))
def ignore(_directory, names):
    return [name for name in names if name in excluded or name.endswith('.pyc')]
def manifest(root):
    records = {}
    def walk(directory, relative):
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            if entry.name in excluded or entry.name.endswith('.pyc'):
                continue
            child = entry.name if not relative else relative + '/' + entry.name
            # Use the same path-based stat API before and after hashing.  On
            # Windows, ``DirEntry.stat`` can report synthetic zero dev/inode
            # values while ``os.lstat`` reports the actual file identity.
            before = os.lstat(entry.path)
            mode = before.st_mode
            if stat.S_ISLNK(mode):
                records[child] = ('link', os.readlink(entry.path))
            elif stat.S_ISDIR(mode):
                records[child] = ('directory',)
                walk(entry.path, child)
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with open(entry.path, 'rb') as stream:
                    for block in iter(lambda: stream.read(1048576), b''):
                        digest.update(block)
                after = os.lstat(entry.path)
                identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
                identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
                if identity_before != identity_after:
                    raise RuntimeError('source changed while it was being hashed: ' + child)
                records[child] = ('file', digest.hexdigest())
            else:
                raise RuntimeError('unsupported workspace entry: ' + child)
    walk(root, '')
    return records
source_before = manifest('/workspace-source')
shutil.copytree('/workspace-source', '/workspace', dirs_exist_ok=True, symlinks=True, ignore=ignore)
source_after = manifest('/workspace-source')
copied = manifest('/workspace')
if source_before != source_after or source_after != copied:
    print('AsterCode refused to execute because the workspace changed while the sandbox snapshot was copied.', file=sys.stderr)
    raise SystemExit(86)
os.chdir(sys.argv[2])
os.execvp(sys.argv[3], sys.argv[3:])
"""
_COPY_EXEC_AND_EXPORT = """import hashlib, json, os, shutil, stat, subprocess, sys
excluded = set(sys.argv[1].split(','))
workdir = sys.argv[2]
exports = json.loads(sys.argv[3])
max_bytes = int(sys.argv[4])
uid, gid = (int(item) for item in sys.argv[5].split(':'))
command = sys.argv[6:]
def ignore(_directory, names):
    return [name for name in names if name in excluded or name.endswith('.pyc')]
def manifest(root):
    records = {}
    def walk(directory, relative):
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            if entry.name in excluded or entry.name.endswith('.pyc'):
                continue
            child = entry.name if not relative else relative + '/' + entry.name
            before = os.lstat(entry.path)
            mode = before.st_mode
            if stat.S_ISLNK(mode): records[child] = ('link', os.readlink(entry.path))
            elif stat.S_ISDIR(mode): records[child] = ('directory',); walk(entry.path, child)
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with open(entry.path, 'rb') as stream:
                    for block in iter(lambda: stream.read(1048576), b''): digest.update(block)
                after = os.lstat(entry.path)
                before_id = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
                after_id = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
                if before_id != after_id: raise RuntimeError('source changed while it was being hashed: ' + child)
                records[child] = ('file', digest.hexdigest())
            else: raise RuntimeError('unsupported workspace entry: ' + child)
    walk(root, '')
    return records
before = manifest('/workspace-source')
def copy_workspace(source, target):
    os.makedirs(target, exist_ok=True)
    for entry in os.scandir(source):
        if entry.name in excluded or entry.name.endswith('.pyc'): continue
        destination = os.path.join(target, entry.name)
        mode = os.lstat(entry.path).st_mode
        if stat.S_ISLNK(mode): os.symlink(os.readlink(entry.path), destination)
        elif stat.S_ISDIR(mode): copy_workspace(entry.path, destination)
        elif stat.S_ISREG(mode): shutil.copyfile(entry.path, destination)
        else: raise RuntimeError('unsupported workspace entry: ' + entry.name)
copy_workspace('/workspace-source', '/workspace')
after = manifest('/workspace-source')
if before != after or after != manifest('/workspace'):
    print('AsterCode refused to execute because the workspace changed while the sandbox snapshot was copied.', file=sys.stderr)
    raise SystemExit(86)
os.chmod('/exports', 0o700)
def demote():
    os.setgroups([]); os.setgid(gid); os.setuid(uid)
completed = subprocess.run(command, cwd=workdir, stdin=subprocess.DEVNULL, preexec_fn=demote, check=False)
if completed.returncode != 0: raise SystemExit(completed.returncode)
total = 0
for relative in exports:
    source = os.path.join(workdir, *relative.split('/'))
    current = workdir
    for part in relative.split('/'):
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode): raise RuntimeError('artifact path contains a symbolic link: ' + relative)
    info = os.lstat(source)
    if not stat.S_ISREG(info.st_mode): raise RuntimeError('artifact is not a regular file: ' + relative)
    total += info.st_size
    if total > max_bytes: raise RuntimeError('artifact export exceeds the configured byte limit')
    target = os.path.join('/exports', *relative.split('/'))
    os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
    with open(source, 'rb') as reader, open(target, 'xb') as writer:
        shutil.copyfileobj(reader, writer, length=1048576)
        writer.flush(); os.fsync(writer.fileno())
    os.chmod(target, 0o600)
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


def discover_trusted_image_tool(name: str) -> Path | None:
    """Find an optional SBOM/signature scanner without trusting PATH."""

    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", name):
        raise ValueError("invalid image security tool name")
    candidates: list[Path] = []
    if os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        candidates.extend(
            [
                local / "Programs" / name / f"{name}.exe",
                program_files / name / f"{name}.exe",
            ]
        )
        # WinGet uses a fixed user-owned package root. Inspect only known
        # package prefixes and expected executable names; never trust PATH.
        winget_root = local / "Microsoft" / "WinGet" / "Packages"
        winget_specs = {
            "cosign": ("Sigstore.Cosign_Microsoft.Winget.Source_*", "cosign-windows-amd64.exe"),
            "syft": ("Anchore.Syft_Microsoft.Winget.Source_*", "syft.exe"),
            "trivy": ("AquaSecurity.Trivy_Microsoft.Winget.Source_*", "trivy.exe"),
        }
        if name in winget_specs:
            package_glob, executable_name = winget_specs[name]
            candidates.extend(winget_root.glob(f"{package_glob}/{executable_name}"))
    else:
        candidates.extend([Path("/usr/bin") / name, Path("/usr/local/bin") / name])
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
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
    auto_remove: bool = True,
    export_dir: Path | None = None,
    root_wrapper: bool = False,
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
        *(["--rm"] if auto_remove else []),
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
        "--stop-timeout",
        "3",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size={tmpfs_bytes},mode=0700,uid={uid},gid={gid}",
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,size={workspace_bytes},mode={'0777' if root_wrapper else '0700'},uid={uid},gid={gid}",
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
    if not root_wrapper:
        options.extend(["--user", user])
    else:
        # The trusted wrapper needs only these two capabilities to launch the
        # model-selected command as the configured unprivileged uid/gid.  The
        # child loses them when setuid/setgid completes.
        options.extend(["--cap-add", "SETUID", "--cap-add", "SETGID"])
    if export_dir is not None:
        export_source = str(export_dir)
        if "," in export_source or any(ord(char) < 32 for char in export_source):
            raise DockerSandboxUnavailable("artifact staging path cannot be represented as a Docker bind mount")
        options.extend(
            ["--mount", f"type=bind,source={export_source},target=/exports"]
        )
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

    specs = (
        *ProcessTools.specs,
        ToolSpec(
            "process.exec_export",
            "Run reviewed workspace files in the Docker sandbox and export only the listed regular files into AsterCode's artifact store.",
            "process.build_export",
            ("process_start", "artifact_write"),
            "P2",
            timeout_seconds=120,
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "timeout": {"type": "number", "minimum": 0.1},
                    "artifact_paths": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                        "maxItems": 16,
                        "uniqueItems": True,
                    },
                },
                "required": ["argv", "cwd", "timeout", "artifact_paths"],
                "additionalProperties": False,
            },
        ),
    )

    def __init__(
        self,
        roots: Iterable[str | Path],
        *,
        attestation: DockerSandboxAttestation,
        container_user: str,
        container_cpus: float,
        container_tmpfs_bytes: int,
        container_workspace_bytes: int,
        artifacts_dir: str | Path | None = None,
        artifact_max_bytes: int = 67_108_864,
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
        self.artifacts_dir = (
            Path(artifacts_dir).expanduser().resolve(strict=False)
            if artifacts_dir is not None
            else None
        )
        self.artifact_max_bytes = artifact_max_bytes
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
            "copy_consistency_check": "sha256_source_before_after_and_copy",
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

    @staticmethod
    def _validated_artifact_paths(values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError("artifact paths must be non-empty relative strings")
            if "\\" in value:
                raise ValueError("artifact paths must use forward slashes")
            parts = value.split("/")
            if value.startswith("/") or any(part in {"", ".", ".."} for part in parts):
                raise ValueError("artifact paths must stay below the sandbox cwd")
            normalized.append("/".join(parts))
        if len(normalized) != len(set(normalized)):
            raise ValueError("artifact paths must be unique")
        return normalized

    def _spawn_export(
        self,
        process_handle: str,
        argv: list[str],
        workdir: Path,
        artifact_paths: list[str],
        staging: Path,
    ) -> subprocess.Popen[str]:
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
                export_dir=staging,
                root_wrapper=True,
            ),
            "python",
            "-c",
            _COPY_EXEC_AND_EXPORT,
            ",".join(_COPY_EXCLUDES),
            container_cwd,
            json.dumps(artifact_paths, separators=(",", ":")),
            str(self.artifact_max_bytes),
            self.container_user,
            *command,
        ]
        with self._state_lock:
            self._container_names[process_handle] = name
        try:
            return ProcessTools._spawn(
                self,
                process_handle,
                docker_argv,
                workdir,
                _docker_host_env(self.attestation.executable),
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            with self._state_lock:
                self._container_names.pop(process_handle, None)
            raise

    def exec_export(
        self,
        argv: list[str],
        cwd: str,
        timeout: float,
        artifact_paths: list[str],
        *,
        allow_unsandboxed: bool = False,
    ) -> ToolResult:
        args = {
            "argv": argv,
            "cwd": cwd,
            "timeout": timeout,
            "artifact_paths": artifact_paths,
        }
        result = timed_result(
            "process.exec_export", new_action_id("process.exec_export", args), cwd
        )
        process_handle = self._new_process_handle()
        proc: subprocess.Popen[str] | None = None
        capture: _ProcessCapture | None = None
        staging: Path | None = None
        final: Path | None = None
        try:
            if not argv or any(not isinstance(item, str) or not item for item in argv):
                raise ValueError("argv must be a non-empty list of non-empty strings")
            paths = self._validated_artifact_paths(artifact_paths)
            self._boundary_check(allow_unsandboxed)
            timeout = self._timeout(timeout)
            workdir = self._cwd(cwd)
            if self.artifacts_dir is None:
                raise PermissionError("the Docker artifact store is not configured")
            artifact_root = self.artifacts_dir
            artifact_root.mkdir(parents=True, exist_ok=True)
            if artifact_root.is_symlink() or bool(
                getattr(artifact_root, "is_junction", lambda: False)()
            ):
                raise PermissionError("artifact store cannot be a link or junction")
            staging = Path(
                tempfile.mkdtemp(prefix=".build-export-", dir=str(artifact_root))
            )
            final = artifact_root / f"build_{uuid.uuid4().hex}"
            proc = self._spawn_export(
                process_handle, argv, workdir, paths, staging
            )
            capture = self._begin_capture(process_handle, proc)
            result.side_effects = ["process_start", "artifact_write"]
            result.metadata.update(
                {
                    "pid": proc.pid,
                    "identity_token": self.process_identity(proc.pid),
                    "process_handle": process_handle,
                    **self._containment_metadata(process_handle),
                }
            )
            result.metadata["trusted_export_wrapper"] = True
            result.metadata["capabilities_dropped"] = (
                "ALL except SETUID/SETGID held only by trusted export wrapper"
            )
            result.metadata["wrapper_capabilities"] = ["SETUID", "SETGID"]
            result.metadata["build_command_user"] = self.container_user
            try:
                result.exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                confirmed = self._terminate(process_handle, proc)
                result.status = "unknown"
                result.error = f"timeout after {timeout}s; artifact state requires reconcile"
                result.metadata["process_tree_stop_confirmed"] = confirmed
            else:
                result.status = "completed" if proc.returncode == 0 else "failed"
                if not capture.wait(1.0):
                    result.status = "unknown"
                    result.error = "build output pipes did not close before artifact export"
                if result.status == "completed":
                    exported: list[dict[str, object]] = []
                    total = 0
                    observed: set[str] = set()
                    for directory, directories, files in os.walk(staging):
                        directory_path = Path(directory)
                        for name in directories:
                            candidate = directory_path / name
                            if candidate.is_symlink() or bool(
                                getattr(candidate, "is_junction", lambda: False)()
                            ):
                                raise PermissionError("artifact export contains a linked directory")
                        for name in files:
                            candidate = directory_path / name
                            if candidate.is_symlink() or not candidate.is_file():
                                raise PermissionError("artifact export contains a non-regular file")
                            observed.add(candidate.relative_to(staging).as_posix())
                    if observed != set(paths):
                        raise PermissionError("artifact export did not match the exact requested file set")
                    for relative in paths:
                        target = staging / Path(relative)
                        size = target.stat().st_size
                        total += size
                        if total > self.artifact_max_bytes:
                            raise PermissionError("artifact export exceeds the configured byte limit")
                        sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
                        exported.append(
                            {"path": relative, "size": size, "sha256": sha256}
                        )
                    os.replace(staging, final)
                    staging = None
                    result.artifacts = [str(final / Path(item)) for item in paths]
                    result.metadata["exported_artifacts"] = exported
                    result.metadata["exported_bytes"] = total
            with self._state_lock:
                container_name = self._container_names.get(process_handle)
            if container_name is not None:
                removed = _run_control(
                    self.attestation.executable,
                    ["container", "rm", "--force", container_name],
                    timeout=10,
                )
                cleanup_confirmed = removed.returncode == 0 or self._container_absent(
                    container_name
                )
                result.metadata["container_cleanup_confirmed"] = cleanup_confirmed
                if not cleanup_confirmed:
                    result.status = "unknown"
                    result.error = result.error or "artifact exported but container cleanup is unknown"
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            if proc is not None:
                try:
                    confirmed = self._terminate(process_handle, proc)
                except Exception:
                    confirmed = False
                result.metadata["process_tree_stop_confirmed"] = confirmed
                if not confirmed:
                    result.status = "unknown"
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            proc = proc or self._managed_child(process_handle)
            if proc is not None and self._managed_child(process_handle) is proc:
                released = self._release_action(process_handle, proc)
                capture = capture or released
            if capture is not None:
                self._apply_capture(result, capture, final=True)
        return result.bounded(self.max_output).finish()

    def _container_absent(self, name: str) -> bool:
        completed = _run_control(
            self.attestation.executable,
            ["container", "inspect", name],
            timeout=5,
        )
        return completed.returncode != 0 and "No such" in completed.stderr

    @classmethod
    def terminate_registered_record(cls, record: Mapping[str, object]) -> bool:
        """Stop a persisted Docker process only after revalidating its identity."""

        pid = record.get("pid")
        expected_process = record.get("identity_token")
        if not isinstance(pid, int) or pid <= 0:
            return False
        if record.get("backend_kind") != "docker_linux_container":
            expected = expected_process if isinstance(expected_process, str) else None
            current = cls.process_identity(pid)
            if current == "missing" or (
                isinstance(expected, str)
                and isinstance(current, str)
                and current != expected
            ):
                return True
            return cls.terminate_registered(pid, expected)

        name = record.get("backend_ref")
        expected_image = record.get("backend_identity")
        if not isinstance(name, str) or not re.fullmatch(r"astercode-[0-9a-f]{32}", name):
            return False
        if not isinstance(expected_image, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", expected_image
        ):
            return False
        executable = discover_trusted_docker()
        if executable is None:
            return False
        try:
            inspected = _run_control(
                executable,
                ["container", "inspect", name, "--format", "{{json .}}"],
                timeout=5,
            )
        except DockerSandboxUnavailable:
            return False
        if inspected.returncode != 0:
            container_stopped = "No such" in inspected.stderr
        else:
            try:
                payload = json.loads(inspected.stdout)
                labels = payload["Config"]["Labels"] or {}
                identity_matches = (
                    str(payload["Name"]).removeprefix("/") == name
                    and labels.get("astercode.process_handle") == name
                    and payload["Image"] == expected_image
                )
            except (KeyError, TypeError, json.JSONDecodeError):
                return False
            if not identity_matches:
                return False
            try:
                removed = _run_control(
                    executable,
                    ["container", "rm", "--force", name],
                    timeout=10,
                )
            except DockerSandboxUnavailable:
                return False
            container_stopped = removed.returncode == 0

        expected = expected_process if isinstance(expected_process, str) else None
        current = cls.process_identity(pid)
        host_stopped = current == "missing" or (
            isinstance(expected, str)
            and isinstance(current, str)
            and current != expected
        )
        if not host_stopped:
            host_stopped = cls.terminate_registered(pid, expected)
        if not container_stopped or not host_stopped:
            return False

        # Re-check after stopping the host client.  A very fast cancellation
        # can race Docker container creation: the first inspect may say "No
        # such" while the daemon is still processing ``docker run``.
        try:
            verified = _run_control(
                executable,
                ["container", "inspect", name, "--format", "{{json .}}"],
                timeout=5,
            )
        except DockerSandboxUnavailable:
            return False
        if verified.returncode != 0:
            return "No such" in verified.stderr
        try:
            payload = json.loads(verified.stdout)
            labels = payload["Config"]["Labels"] or {}
            still_owned = (
                str(payload["Name"]).removeprefix("/") == name
                and labels.get("astercode.process_handle") == name
                and payload["Image"] == expected_image
            )
        except (KeyError, TypeError, json.JSONDecodeError):
            return False
        if not still_owned:
            return False
        try:
            removed = _run_control(
                executable,
                ["container", "rm", "--force", name],
                timeout=10,
            )
            confirmed = _run_control(
                executable,
                ["container", "inspect", name, "--format", "{{json .}}"],
                timeout=5,
            )
        except DockerSandboxUnavailable:
            return False
        return removed.returncode == 0 and confirmed.returncode != 0 and "No such" in confirmed.stderr

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
    "discover_trusted_image_tool",
]
