from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from astercode.tools import process as process_module
from astercode.tools.process import (
    ProcessTools,
    _validate_trusted_powershell7_candidate,
    _windows_system_locations,
    discover_trusted_powershell7,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX /proc zombie regression")
def test_process_identity_treats_an_unreaped_zombie_as_stopped() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            raw = Path(f"/proc/{proc.pid}/stat").read_text(encoding="ascii")
            closing = raw.rfind(")")
            fields = raw[closing + 2 :].split()
            if fields and fields[0] == "Z":
                break
            time.sleep(0.02)
        else:
            raise AssertionError("child did not become an observable zombie")

        assert ProcessTools.process_identity(proc.pid) == "missing"
    finally:
        proc.wait(timeout=5)


def test_process_fails_closed_without_verified_sandbox(tmp_path: Path, monkeypatch) -> None:
    def unexpected_spawn(*args, **kwargs):
        del args, kwargs
        raise AssertionError("subprocess must not start before explicit boundary approval")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_spawn)
    result = ProcessTools([tmp_path], network_mode="deny_by_default").exec(
        [sys.executable, "-c", "print('must not run')"],
        str(tmp_path),
    )

    assert result.status == "failed"
    assert result.metadata["blocked"] is True
    assert "no verified process sandbox" in str(result.error)


def test_process_rejects_outside_cwd_before_spawn(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    def unexpected_spawn(*args, **kwargs):
        del args, kwargs
        raise AssertionError("outside cwd must be rejected before spawn")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_spawn)
    result = ProcessTools(
        [root],
        network_mode="deny_by_default",
        sandbox_enforced=True,
        network_policy_enforced=True,
    ).exec(
        [sys.executable, "-c", "print('must not run')"],
        str(outside),
        allow_unsandboxed=True,
    )

    assert result.status == "failed"
    assert "outside authorized roots" in str(result.error)


def test_process_rejects_secret_valued_environment_before_spawn(tmp_path: Path, monkeypatch) -> None:
    def unexpected_spawn(*args, **kwargs):
        del args, kwargs
        raise AssertionError("secret-bearing process must not start")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_spawn)
    result = ProcessTools(
        [tmp_path],
        network_mode="deny_by_default",
        sandbox_enforced=True,
        network_policy_enforced=True,
    ).exec(
        [sys.executable, "-c", "print('must not run')"],
        str(tmp_path),
        allow_unsandboxed=True,
        env_refs={"SERVICE_TOKEN": "not-a-real-token"},
    )

    assert result.status == "failed"
    assert "secret broker" in str(result.error)


def test_structured_argv_treats_shell_metacharacters_as_one_argument(tmp_path: Path) -> None:
    tools = ProcessTools([tmp_path], sandbox_enforced=True, network_policy_enforced=True)
    hostile_name = "name;$(touch pwned)`whoami` & echo bad.txt"

    result = tools.exec(
        [sys.executable, "-c", "import sys; print(repr(sys.argv[1]))", hostile_name],
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "completed"
    assert hostile_name in result.stdout
    assert not (tmp_path / "pwned").exists()


def test_clean_path_ignores_workspace_path_override(tmp_path: Path, monkeypatch) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    monkeypatch.setenv("PATH", str(fake_bin))

    env = ProcessTools([tmp_path])._clean_env({})

    assert str(fake_bin) not in env["PATH"].split(os.pathsep)


def test_process_rejects_non_finite_or_over_budget_timeout(tmp_path: Path, monkeypatch) -> None:
    def unexpected_spawn(*args, **kwargs):
        raise AssertionError("invalid timeout must be rejected before spawn")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_spawn)
    tools = ProcessTools(
        [tmp_path],
        max_timeout=5,
        sandbox_enforced=True,
        network_policy_enforced=True,
    )

    assert tools.exec([sys.executable, "-c", "pass"], str(tmp_path), timeout=float("inf"), allow_unsandboxed=True).status == "failed"
    assert tools.exec([sys.executable, "-c", "pass"], str(tmp_path), timeout=6, allow_unsandboxed=True).status == "failed"


def test_approval_cannot_bypass_unverified_network_boundary(tmp_path: Path, monkeypatch) -> None:
    def unexpected_spawn(*args, **kwargs):
        del args, kwargs
        raise AssertionError("process must not start without verified network isolation")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_spawn)
    result = ProcessTools(
        [tmp_path],
        network_mode="deny_by_default",
        sandbox_enforced=True,
        network_policy_enforced=False,
    ).exec(
        [sys.executable, "-c", "print('must not run')"],
        str(tmp_path),
        allow_unsandboxed=True,
    )

    assert result.status == "failed"
    assert result.metadata["blocked"] is True
    assert "no verified process enforcement" in str(result.error)
    assert "approval cannot grant unrestricted host networking" in str(result.error)


def test_store_powershell_candidate_requires_expected_package_identity(
    tmp_path: Path,
) -> None:
    windows_apps = tmp_path / "WindowsApps"
    package = windows_apps / "Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe"
    package.mkdir(parents=True)
    executable = package / "pwsh.exe"
    executable.write_bytes(b"test")

    assert _validate_trusted_powershell7_candidate(executable, windows_apps) == executable.resolve()

    wrong_publisher = windows_apps / "Microsoft.PowerShell_7.6.5.0_x64__untrustedpublisher"
    wrong_publisher.mkdir()
    wrong_executable = wrong_publisher / "pwsh.exe"
    wrong_executable.write_bytes(b"test")
    assert _validate_trusted_powershell7_candidate(wrong_executable, windows_apps) is None


def test_store_powershell_candidate_rejects_an_outside_path(
    tmp_path: Path,
) -> None:
    windows_apps = tmp_path / "WindowsApps"
    windows_apps.mkdir()
    outside = tmp_path / "Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe"
    outside.mkdir()
    executable = outside / "pwsh.exe"
    executable.write_bytes(b"test")

    assert _validate_trusted_powershell7_candidate(executable, windows_apps) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows Store discovery is Windows-specific")
def test_discovers_a_validated_store_powershell_install(tmp_path: Path, monkeypatch) -> None:
    program_files = tmp_path / "Program Files"
    package = program_files / "WindowsApps" / "Microsoft.PowerShell_7.6.5.0_x64__8wekyb3d8bbwe"
    package.mkdir(parents=True)
    executable = package / "pwsh.exe"
    executable.write_bytes(b"test")
    system_root = tmp_path / "Windows"
    inbox = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    inbox.parent.mkdir(parents=True)
    inbox.write_bytes(b"test")
    program_data = tmp_path / "ProgramData"
    program_data.mkdir()
    monkeypatch.setattr(
        process_module,
        "_windows_system_locations",
        lambda: (program_files, system_root, program_data),
    )

    captured_env: dict[str, str] = {}
    captured_cwd: list[str] = []

    def fake_run(*args, **kwargs):
        del args
        captured_env.update(kwargs["env"])
        captured_cwd.append(kwargs["cwd"])
        return subprocess.CompletedProcess([], 0, f"{package}\n", "")

    monkeypatch.setattr(process_module.subprocess, "run", fake_run)

    assert discover_trusted_powershell7() == executable.resolve()
    assert captured_env["SystemDrive"].casefold() == system_root.drive.casefold()
    assert Path(captured_env["ProgramData"]) == program_data
    assert "%SystemDrive%" not in captured_env["ProgramData"]
    assert Path(captured_env["ProgramFiles"]) == program_files
    assert captured_cwd == [str(inbox.parent.resolve())]


@pytest.mark.skipif(os.name != "nt", reason="Windows clean environment is Windows-specific")
def test_clean_env_uses_os_resolved_windows_paths(tmp_path: Path, monkeypatch) -> None:
    program_files = tmp_path / "Program Files"
    program_files.mkdir()
    system_root = tmp_path / "Windows"
    system_root.mkdir()
    program_data = tmp_path / "ProgramData"
    program_data.mkdir()
    monkeypatch.setattr(
        process_module,
        "_windows_system_locations",
        lambda: (program_files, system_root, program_data),
    )
    monkeypatch.setenv("SystemDrive", "%SystemDrive%")
    monkeypatch.setenv("ProgramData", r"%SystemDrive%\ProgramData")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "untrusted-program-files"))

    env = ProcessTools([tmp_path])._clean_env({})

    assert env["SystemDrive"].casefold() == system_root.drive.casefold()
    assert Path(env["ProgramData"]) == program_data
    assert Path(env["ProgramFiles"]) == program_files
    assert "%SystemDrive%" not in env["ProgramData"]


@pytest.mark.skipif(os.name != "nt", reason="Windows known folders are Windows-specific")
def test_windows_system_locations_ignore_inherited_path_overrides(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "untrusted-program-files"))
    monkeypatch.setenv("ProgramW6432", str(tmp_path / "untrusted-program-w6432"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "untrusted-windows"))
    monkeypatch.setenv("WINDIR", str(tmp_path / "untrusted-windir"))

    locations = _windows_system_locations()

    assert locations is not None
    program_files, windows, program_data = locations
    assert tmp_path not in program_files.parents
    assert tmp_path not in windows.parents
    assert tmp_path not in program_data.parents
    assert program_files.is_dir()
    assert windows.is_dir()
    assert program_data.is_dir()
