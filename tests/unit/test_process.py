from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from astercode.tools import process as process_module
from astercode.tools.process import ProcessTools


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


def test_process_fails_closed_without_verified_sandbox(
    tmp_path: Path, monkeypatch
) -> None:
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


def test_process_rejects_outside_cwd_before_spawn(
    tmp_path: Path, monkeypatch
) -> None:
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


def test_process_rejects_secret_valued_environment_before_spawn(
    tmp_path: Path, monkeypatch
) -> None:
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
    tools = ProcessTools(
        [tmp_path], sandbox_enforced=True, network_policy_enforced=True
    )
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


def test_approval_cannot_bypass_unverified_network_boundary(
    tmp_path: Path, monkeypatch
) -> None:
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
