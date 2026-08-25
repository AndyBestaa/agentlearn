"""Run AsterCode's deterministic, credential-free resume demonstration.

The default path exercises the production filesystem, Git, policy, approval,
LangGraph, storage, audit, and Docker process adapters.  ``--backend fake`` is
an explicitly labelled CI fallback: it validates the exact fixture bytes but
does not claim to have launched a process or an OS sandbox.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal, Mapping

from astercode.config import AppConfig
from astercode.models import ApprovalDecision
from astercode.provider import DeterministicFakeProvider
from astercode.runtime import Orchestrator, build_registry
from astercode.storage import Storage
from astercode.tools.base import ToolResult, new_action_id, timed_result
from astercode.tools.docker_process import DockerSandboxUnavailable, attest_docker_sandbox
from astercode.tools.filesystem import FilesystemTools
from astercode.tools.git import GitTools
from astercode.tools.process import ProcessTools
from astercode.tools.registry import ToolRegistry

Backend = Literal["docker", "fake"]
TEST_ARGV = ["python", "test_calculator.py"]
EXPECTED_TEST_STDOUT = "calculator regression: 3 checks passed\n"
PATCH = """*** Begin Patch
*** Update File: calculator.py
-    return left - right
+    return left + right
*** End Patch"""
RESUME_RESPONSE_INDEX = 4


class DemoFailure(RuntimeError):
    """Raised when any claimed piece of demo evidence is missing."""


class FixtureFakeProcessTools(ProcessTools):
    """Test-only exact-fixture executor used only by ``--backend fake``.

    It never launches a command.  A completed result means only that the exact
    trusted regression fixture contains the expected fixed bytes.  Its metadata
    makes that limitation machine-readable and the console report repeats it.
    """

    def __init__(
        self,
        root: Path,
        *,
        buggy_source: bytes,
        fixed_source: bytes,
        test_source: bytes,
    ) -> None:
        super().__init__(
            [root],
            network_mode="deny_by_default",
            sandbox_enforced=True,
            network_policy_enforced=True,
        )
        self.root = root.resolve(strict=True)
        self.buggy_source = buggy_source
        self.fixed_source = fixed_source
        self.test_source = test_source

    def exec(
        self,
        argv: list[str],
        cwd: str,
        timeout: float = 120,
        *,
        allow_unsandboxed: bool = False,
        env_refs: Mapping[str, str] | None = None,
    ) -> ToolResult:
        del timeout, env_refs
        arguments = {"argv": argv, "cwd": cwd}
        result = timed_result("process.exec", new_action_id("process.exec", arguments), cwd)
        try:
            self._boundary_check(allow_unsandboxed)
            workdir = self._cwd(cwd)
            if workdir != self.root or argv != TEST_ARGV:
                raise DemoFailure("fake demo executor accepts only the exact fixture test command")
            if (workdir / "test_calculator.py").read_bytes() != self.test_source:
                raise DemoFailure("regression fixture changed unexpectedly")
            source = (workdir / "calculator.py").read_bytes()
            result.exit_code = 0 if source == self.fixed_source else 1
            if source == self.fixed_source:
                result.status = "completed"
                result.stdout = EXPECTED_TEST_STDOUT
            elif source == self.buggy_source:
                result.status = "failed"
                result.stderr = "fixture assertion: add(2, 3) returned -1; expected 5\n"
                result.error = "process exited with code 1"
            else:
                raise DemoFailure("calculator fixture changed unexpectedly")
            result.side_effects = ["process_start"]
            result.metadata.update(
                {
                    "execution_backend": "fixture-fake",
                    "execution_simulated": True,
                    "filesystem_sandbox": False,
                    "network_sandbox": False,
                }
            )
        except Exception as exc:
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        return result.finish()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _template_root(repository_root: Path) -> Path:
    template = repository_root / "examples" / "resume_demo"
    required = {".gitignore", "calculator.py", "test_calculator.py", "README.md"}
    observed = {item.name for item in template.iterdir()} if template.is_dir() else set()
    unexpected = observed - required - {"__pycache__"}
    missing = required - observed
    if missing or unexpected or any(not (template / name).is_file() for name in required):
        raise DemoFailure(
            "resume fixture is invalid: "
            f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )
    return template.resolve(strict=True)


def _trusted_git(root: Path) -> str:
    git = GitTools([root]).git
    if git is None:
        raise DemoFailure("a trusted system Git installation is required")
    return git


def _run_git(git: str, workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    # Do not inherit provider credentials (or repository-controlled PATH
    # entries) into the trusted fixture bootstrap process.
    inherited = ("SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")
    environment = {key: os.environ[key] for key in inherited if key in os.environ}
    if os.name == "nt":
        system_root = Path(environment.get("SystemRoot", environment.get("WINDIR", r"C:\Windows")))
        environment["PATH"] = os.pathsep.join((str(Path(git).parent), str(system_root / "System32")))
    else:
        environment["PATH"] = "/usr/bin:/bin"
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
    )
    completed = subprocess.run(
        [git, "-C", str(workspace), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise DemoFailure(f"Git command failed ({' '.join(arguments)}): {detail}")
    return completed


def prepare_workspace(repository_root: Path, destination: Path) -> dict[str, Any]:
    """Copy the intentionally buggy fixture and create a deterministic baseline."""

    destination = destination.expanduser().resolve(strict=False)
    if destination.exists() or destination.is_symlink():
        raise DemoFailure(f"refusing to overwrite an existing demo path: {destination}")
    template = _template_root(repository_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    for name in (".gitignore", "README.md", "calculator.py", "test_calculator.py"):
        shutil.copy2(template / name, destination / name)
    git = _trusted_git(destination)
    _run_git(git, destination, "init", "--initial-branch=main")
    _run_git(git, destination, "config", "user.email", "resume-demo@example.invalid")
    _run_git(git, destination, "config", "user.name", "AsterCode Resume Demo")
    _run_git(git, destination, "config", "core.autocrlf", "false")
    (destination / ".git" / "astercode-no-hooks").mkdir()
    _run_git(git, destination, "add", "--", ".gitignore", "README.md", "calculator.py", "test_calculator.py")
    _run_git(
        git,
        destination,
        "-c",
        "core.hooksPath=.git/astercode-no-hooks",
        "commit",
        "--no-gpg-sign",
        "-m",
        "fixture: intentional calculator regression",
    )
    buggy_source = (destination / "calculator.py").read_bytes()
    fixed_source = buggy_source.replace(b"return left - right", b"return left + right")
    if fixed_source == buggy_source or fixed_source.count(b"return left + right") != 1:
        raise DemoFailure("fixture must contain exactly one intentional arithmetic bug")
    return {
        "workspace": destination,
        "git": git,
        "buggy_source": buggy_source,
        "fixed_source": fixed_source,
        "test_source": (destination / "test_calculator.py").read_bytes(),
    }


def _config(workspace: Path, backend: Backend) -> AppConfig:
    return AppConfig.model_validate(
        {
            "project_root": workspace,
            "model": {"provider": "fake", "model_id": None, "max_retries": 0},
            "budget": {"max_rounds": 12, "max_tool_calls": 12, "max_elapsed_seconds": 180},
            "security": {
                "authorized_roots": [workspace],
                "authorized_ssh_hosts": [],
                "network_mode": "deny_by_default",
                "process": {
                    "sandbox_backend": "container" if backend == "docker" else "none",
                    "allow_unsandboxed_process": False,
                    "container_cpus": 1.0,
                    "container_tmpfs_bytes": 16_777_216,
                    "container_workspace_bytes": 67_108_864,
                    "max_processes": 16,
                    "max_memory_bytes": 268_435_456,
                    "max_cpu_time_seconds": 60,
                    "max_timeout_seconds": 60,
                },
            },
        }
    )


def _registry(config: AppConfig, fixture: Mapping[str, Any], backend: Backend) -> ToolRegistry:
    workspace = Path(fixture["workspace"])
    if backend == "fake":
        registry = ToolRegistry()
        registry.register_provider(FilesystemTools([workspace]))
        registry.register_provider(GitTools([workspace]))
        registry.register_provider(
            FixtureFakeProcessTools(
                workspace,
                buggy_source=bytes(fixture["buggy_source"]),
                fixed_source=bytes(fixture["fixed_source"]),
                test_source=bytes(fixture["test_source"]),
            )
        )
        return registry
    process = config.security.process
    try:
        attestation = attest_docker_sandbox(
            configured_image=process.container_image,
            user=process.container_user,
            max_processes=process.max_processes,
            max_memory_bytes=process.max_memory_bytes,
            cpus=process.container_cpus,
            tmpfs_bytes=process.container_tmpfs_bytes,
            workspace_bytes=process.container_workspace_bytes,
        )
    except DockerSandboxUnavailable as exc:
        raise DemoFailure(
            "attested Docker sandbox is unavailable; install/start Docker and the pinned "
            "image, or use the clearly simulated --backend fake mode"
        ) from exc
    return build_registry(config, docker_attestation=attestation)


def _responses(workspace: Path) -> list[dict[str, Any]]:
    cwd = str(workspace)

    def call(tool: str, arguments: dict[str, Any], purpose: str) -> dict[str, Any]:
        return {
            "tool": tool,
            "arguments": arguments,
            "host": "local",
            "cwd": cwd,
            "purpose": purpose,
        }

    return [
        {
            "plan": ["inspect", "diagnose", "patch", "test", "review diff"],
            "message": "Inspecting the implementation before making changes.",
            "tool_calls": [
                call(
                    "fs.read",
                    {"path": "calculator.py", "start_line": 1, "end_line": None},
                    "inspect the calculator implementation",
                )
            ],
            "outcome": "continue",
        },
        {
            "plan": ["inspect tests", "diagnose", "patch", "test", "review diff"],
            "message": "Reading the focused regression checks.",
            "tool_calls": [
                call(
                    "fs.read",
                    {"path": "test_calculator.py", "start_line": 1, "end_line": None},
                    "confirm the required addition behavior",
                )
            ],
            "outcome": "continue",
        },
        {
            "plan": ["patch", "test", "review diff"],
            "message": "Diagnosis: add() subtracts right from left. Applying one minimal operator fix.",
            "tool_calls": [
                call(
                    "fs.apply_patch",
                    {"patch": PATCH},
                    "replace the incorrect subtraction with addition",
                )
            ],
            "outcome": "continue",
        },
        {
            "plan": ["test", "review diff"],
            "message": "Running the dependency-free regression checks in the approved sandbox.",
            "tool_calls": [
                call(
                    "process.exec",
                    {"argv": TEST_ARGV, "cwd": cwd, "timeout": 30},
                    "verify all calculator regression cases",
                )
            ],
            "outcome": "continue",
        },
        {
            "plan": ["review diff"],
            "message": "Capturing the exact source diff as evidence.",
            "tool_calls": [
                call(
                    "git.diff",
                    {"cwd": cwd, "cached": False},
                    "verify the change is limited to the arithmetic operator",
                )
            ],
            "outcome": "continue",
        },
        {
            "plan": ["review status"],
            "message": "Checking the final working-tree status.",
            "tool_calls": [
                call("git.status", {"cwd": cwd}, "confirm only calculator.py changed")
            ],
            "outcome": "continue",
        },
        {
            "plan": [],
            "message": "The bug is fixed, the regression checks passed, and the minimal diff was captured.",
            "tool_calls": [],
            "outcome": "completed",
        },
    ]


def _invoke_baseline(registry: ToolRegistry, workspace: Path) -> ToolResult:
    _spec, handler = registry.get("process.exec")
    result = handler(
        argv=list(TEST_ARGV),
        cwd=str(workspace),
        timeout=30,
        allow_unsandboxed=True,
    )
    if not isinstance(result, ToolResult):
        raise DemoFailure("baseline executor returned an invalid result")
    return result


def _exact_process_approval(state: Mapping[str, Any], workspace: Path) -> ApprovalDecision:
    request = state.get("approval_request")
    if not isinstance(request, Mapping):
        raise DemoFailure("waiting state did not contain a persisted approval request")
    normalized = request.get("normalized_action")
    arguments = normalized.get("arguments") if isinstance(normalized, Mapping) else None
    if (
        request.get("tool") != "process.exec"
        or request.get("risk") != "P3"
        or request.get("host") != "local"
        or not isinstance(arguments, Mapping)
        or list(arguments.get("argv", [])) != TEST_ARGV
        or Path(str(arguments.get("cwd", ""))).resolve(strict=False) != workspace
    ):
        raise DemoFailure("refusing an unexpected or widened demo approval request")
    return ApprovalDecision(
        approval_id=str(request["approval_id"]),
        action_id=str(request["action_id"]),
        action_hash=str(request["action_hash"]),
        nonce=str(request["nonce"]),
        approved=True,
        actor="resume-demo-harness",
    )


async def run_demo(fixture: Mapping[str, Any], backend: Backend) -> dict[str, Any]:
    workspace = Path(fixture["workspace"]).resolve(strict=True)
    config = _config(workspace, backend)
    registry = _registry(config, fixture, backend)
    baseline = _invoke_baseline(registry, workspace)
    if baseline.status != "failed" or baseline.exit_code == 0:
        raise DemoFailure("baseline regression unexpectedly passed")

    responses = _responses(workspace)
    storage = Storage(config.storage)
    first_orchestrator = Orchestrator(
        config,
        provider=DeterministicFakeProvider(responses[:RESUME_RESPONSE_INDEX]),
        registry=registry,
        storage=storage,
        auto_approve=True,
    )
    try:
        paused = await first_orchestrator.run(
            "Inspect the calculator regression, diagnose it, apply the smallest fix, "
            "run the focused test, and report the exact Git diff."
        )
    finally:
        # This deliberately closes the LangGraph SQLite saver.  The next
        # resume cannot rely on Python object state from the first runtime.
        await first_orchestrator.close()

    if paused.get("status") != "waiting_approval":
        raise DemoFailure(
            f"first runtime did not persist the expected approval pause: {paused.get('status')!r}"
        )
    session_id = str(paused["session_id"])
    decision = _exact_process_approval(paused, workspace)

    recovered_storage = Storage(config.storage)
    recovered_storage.initialize()
    persisted = recovered_storage.get_session(session_id)
    checkpoint = recovered_storage.latest_checkpoint(session_id)
    persisted_state = persisted.get("state")
    if (
        persisted.get("status") != "waiting_approval"
        or not isinstance(persisted_state, Mapping)
        or persisted_state.get("approval_request") != paused.get("approval_request")
        or not isinstance(checkpoint, Mapping)
        or str(checkpoint.get("phase", "")).upper() != "POLICY_CHECK"
    ):
        raise DemoFailure("persisted approval/checkpoint evidence did not survive runtime teardown")

    recovered_orchestrator = Orchestrator(
        config,
        provider=DeterministicFakeProvider(responses[RESUME_RESPONSE_INDEX:]),
        registry=_registry(config, fixture, backend),
        storage=recovered_storage,
        auto_approve=True,
    )
    try:
        state = await recovered_orchestrator.resume(
            session_id, decision.model_dump(mode="json")
        )
    finally:
        await recovered_orchestrator.close()

    if state.get("status") != "completed":
        raise DemoFailure(
            f"agent did not complete: status={state.get('status')!r}, "
            f"blockers={state.get('blockers')!r}"
        )
    if (workspace / "calculator.py").read_bytes() != fixture["fixed_source"]:
        raise DemoFailure("agent did not produce the exact expected source bytes")

    tool_results = list(state.get("tool_results", []))
    expected_tools = [
        "fs.read",
        "fs.read",
        "fs.apply_patch",
        "process.exec",
        "git.diff",
        "git.status",
    ]
    observed_tools = [item.get("tool") for item in tool_results]
    if observed_tools != expected_tools:
        raise DemoFailure(f"unexpected tool chain: {observed_tools!r}")
    process_result = tool_results[3]
    diff_result = tool_results[4]
    status_result = tool_results[5]
    if process_result.get("status") != "completed" or EXPECTED_TEST_STDOUT.strip() not in str(
        process_result.get("stdout", "")
    ):
        raise DemoFailure("focused regression evidence is missing")
    diff = str(diff_result.get("stdout", ""))
    if "-    return left - right" not in diff or "+    return left + right" not in diff:
        raise DemoFailure("minimal Git diff evidence is missing")
    git_status = str(status_result.get("stdout", ""))
    if "calculator.py" not in git_status or "test_calculator.py" in git_status:
        raise DemoFailure(f"unexpected final Git status: {git_status!r}")
    audit = recovered_storage.verify_audit_chain()
    if audit.get("valid") is not True:
        raise DemoFailure(f"audit chain verification failed: {audit!r}")

    metadata = dict(process_result.get("metadata", {}))
    if backend == "docker":
        required = {
            "filesystem_sandbox": True,
            "network_sandbox": True,
            "host_workspace_read_only": True,
            "ephemeral_workspace_writable": True,
        }
        if any(metadata.get(key) is not value for key, value in required.items()):
            raise DemoFailure(f"Docker sandbox evidence is incomplete: {metadata!r}")
    elif metadata.get("execution_simulated") is not True:
        raise DemoFailure("fake backend did not disclose simulation metadata")

    evidence = {
        "schema_version": 1,
        "status": "completed",
        "workspace": str(workspace),
        "provider": "deterministic-fake",
        "api_key_used": False,
        "execution_backend": backend,
        "execution_simulated": backend == "fake",
        "baseline": {"status": baseline.status, "exit_code": baseline.exit_code},
        "tool_chain": observed_tools,
        "approval": {"count": 1, "tool": "process.exec", "risk": "P3"},
        "recovery": {
            "orchestrator_rebuilt": True,
            "persisted_status": persisted.get("status"),
            "checkpoint_phase": checkpoint.get("phase"),
            "checkpoint_id": checkpoint.get("checkpoint_id"),
        },
        "validation": {
            "status": process_result.get("status"),
            "exit_code": process_result.get("exit_code"),
            "stdout": process_result.get("stdout"),
            "sandbox": metadata,
        },
        "git_diff": diff,
        "git_status": git_status,
        "fixed_source_sha256": _sha256(bytes(fixture["fixed_source"])),
        "audit": audit,
        "session_id": state.get("session_id"),
    }
    evidence_path = workspace / ".astercode" / "resume-demo-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    evidence["evidence_path"] = str(evidence_path)
    return evidence


def _new_default_workspace() -> tuple[Path, Path]:
    temp_root = Path(tempfile.mkdtemp(prefix="astercode-resume-demo-"))
    return temp_root, temp_root / "project"


def _remove_readonly_and_retry(function: Any, path: str, _error: BaseException) -> None:
    """Allow cleanup of Git's read-only object files on Windows."""

    os.chmod(path, stat.S_IWRITE)
    function(path)


def _print_report(evidence: Mapping[str, Any]) -> None:
    print("\nAsterCode resume demo: PASS")
    print(f"workspace: {evidence['workspace']}")
    print(f"provider: {evidence['provider']} (API key used: no)")
    backend = str(evidence["execution_backend"])
    suffix = " (SIMULATED; no process or sandbox claim)" if evidence["execution_simulated"] else ""
    print(f"execution backend: {backend}{suffix}")
    print(f"baseline: {evidence['baseline']['status']} (intentional regression observed)")
    print(f"tool chain: {' -> '.join(evidence['tool_chain'])}")
    print("approval: one exact P3 process.exec approval paused and resumed")
    print("recovery: first orchestrator closed; new runtime resumed the persisted SQLite checkpoint")
    print(f"test: {str(evidence['validation']['stdout']).strip()}")
    print("diff evidence:")
    print(str(evidence["git_diff"]).rstrip())
    print(f"audit chain: valid={evidence['audit']['valid']}, entries={evidence['audit']['entries']}")
    print(f"evidence JSON: {evidence['evidence_path']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="AsterCode repository root",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        help="new destination path; existing paths are never overwritten",
    )
    parser.add_argument(
        "--backend",
        choices=("docker", "fake"),
        default="docker",
        help="docker is the real offline acceptance path; fake is a labelled CI fallback",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="prepare a fresh buggy Git project for an optional live-model demo",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="remove only an automatically generated temporary workspace after success",
    )
    args = parser.parse_args()

    repository_root = args.root.expanduser().resolve(strict=True)
    temporary_root: Path | None = None
    if args.workspace is None:
        temporary_root, workspace = _new_default_workspace()
    else:
        if args.cleanup:
            parser.error("--cleanup is allowed only for an automatically generated workspace")
        workspace = args.workspace

    fixture = prepare_workspace(repository_root, workspace)
    print(f"prepared fresh fixture: {fixture['workspace']}")
    if args.prepare_only:
        print("optional live demo (uses your existing provider environment without displaying its key):")
        print(f'  cd "{fixture["workspace"]}"')
        print("  aster")
        return 0

    try:
        evidence = asyncio.run(run_demo(fixture, args.backend))
        _print_report(evidence)
    finally:
        if args.cleanup and temporary_root is not None:
            resolved_temp = Path(tempfile.gettempdir()).resolve(strict=True)
            checked = temporary_root.resolve(strict=True)
            if checked.parent != resolved_temp or not checked.name.startswith("astercode-resume-demo-"):
                raise DemoFailure("refusing to clean an unexpected path")
            shutil.rmtree(checked, onexc=_remove_readonly_and_retry)
            print("temporary workspace cleaned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
