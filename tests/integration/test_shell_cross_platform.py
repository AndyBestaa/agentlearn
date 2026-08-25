from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from astercode.tools.process import ProcessTools, discover_trusted_powershell7


@pytest.mark.skipif(os.name == "nt", reason="POSIX bash smoke requires a POSIX host")
def test_posix_bash_no_profile_utf8_and_lf_smoke(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this POSIX host")
    tools = ProcessTools(
        [tmp_path],
        clean_path=[Path(bash).parent],
        sandbox_enforced=True,
        network_policy_enforced=True,
    )

    result = tools.shell(
        "printf '%s\\n' 'café; literal-$HOME' > output.txt",
        "bash",
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "completed", f"error={result.error!r} stderr={result.stderr!r}"
    assert (tmp_path / "output.txt").read_bytes() == "café; literal-$HOME\n".encode()


@pytest.mark.skipif(os.name != "nt", reason="Git Bash compatibility smoke is Windows-specific")
def test_git_bash_no_profile_utf8_and_lf_smoke(tmp_path: Path) -> None:
    git_bin = Path(r"C:\Program Files\Git\bin")
    if not (git_bin / "bash.exe").is_file():
        pytest.skip("Git Bash is unavailable")
    tools = ProcessTools(
        [tmp_path],
        clean_path=[git_bin],
        sandbox_enforced=True,
        network_policy_enforced=True,
    )

    result = tools.shell(
        "printf '%s\\n' '你好; literal-$HOME' > output.txt",
        "bash",
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "completed", f"error={result.error!r} stderr={result.stderr!r}"
    assert (tmp_path / "output.txt").read_bytes() == "你好; literal-$HOME\n".encode()


@pytest.mark.skipif(os.name != "nt", reason="PowerShell compatibility smoke is Windows-specific")
def test_powershell7_no_profile_and_utf8_smoke(tmp_path: Path) -> None:
    if discover_trusted_powershell7() is None:
        pytest.skip("PowerShell 7 is unavailable on this host")
    tools = ProcessTools([tmp_path], sandbox_enforced=True, network_policy_enforced=True)

    result = tools.shell(
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); Write-Output '你好; literal-$HOME'",
        "pwsh",
        str(tmp_path),
        timeout=10,
        allow_unsandboxed=True,
    )

    assert result.status == "completed", f"error={result.error!r} stderr={result.stderr!r}"
    assert "你好; literal-$HOME" in result.stdout
