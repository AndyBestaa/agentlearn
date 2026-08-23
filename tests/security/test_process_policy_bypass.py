from __future__ import annotations

import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import RiskLevel
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("process.exec", {"argv": ["git", "reset", "--hard"]}),
        ("process.exec", {"argv": [r"C:\Program Files\Git\cmd\git.exe", "status"]}),
        ("process.start", {"argv": [r"C:\Windows\System32\OpenSSH\ssh.exe", "host"]}),
        ("process.exec", {"argv": ["curl", "https://example.test/upload"]}),
        ("process.exec", {"argv": ["rm", "-rf", "workspace"]}),
        ("process.exec", {"argv": ["systemctl", "restart", "example.service"]}),
        ("process.exec", {"argv": ["taskkill.exe", "/PID", "1234", "/F"]}),
        ("process.exec", {"argv": ["cmd.exe", "/d", "/c", "curl https://example.test"]}),
        ("process.exec", {"argv": ["python", "-c", "import os; os.system('git reset --hard')"]}),
        ("process.exec", {"argv": ["env", "SAFE=1", "git", "status"]}),
        ("process.exec", {"argv": ["uv", "run", "curl", "https://example.test"]}),
        ("shell.exec", {"script": '"C:\\Program Files\\Git\\cmd\\git.exe" status', "dialect": "powershell"}),
        ("shell.exec", {"script": "Remove-Item -Recurse -Force .", "dialect": "powershell"}),
        ("shell.exec", {"script": "ssh host -- dangerous", "dialect": "bash"}),
        ("shell.exec", {"script": "sudo systemctl restart example.service", "dialect": "bash"}),
    ],
)
def test_general_process_tools_cannot_bypass_dedicated_boundaries(
    app_config: AppConfig,
    tmp_path: Path,
    tool: str,
    arguments: dict[str, object],
) -> None:
    decision = PolicyEngine(
        app_config,
        runtime_capabilities=RuntimePolicyCapabilities(
            process_sandbox_enforced=True,
            process_network_policy_enforced=True,
        ),
    ).evaluate(tool, arguments, cwd=str(tmp_path))

    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P4
    assert decision.approval is None
    assert any(word in decision.reason for word in ("dedicated", "cannot use", "constrained"))


def test_attested_process_still_requires_bound_approval_for_non_bypass_command(
    app_config: AppConfig, tmp_path: Path
) -> None:
    engine = PolicyEngine(
        app_config,
        runtime_capabilities=RuntimePolicyCapabilities(
            process_sandbox_enforced=True,
            process_network_policy_enforced=True,
        ),
    )

    structured = engine.evaluate(
        "process.exec",
        {"argv": ["ruff", "check", "."], "cwd": str(tmp_path), "timeout": 30},
        cwd=str(tmp_path),
    )
    interpreter = engine.evaluate(
        "process.exec",
        {"argv": [sys.executable, "-m", "pytest", "-q"], "cwd": str(tmp_path), "timeout": 30},
        cwd=str(tmp_path),
    )

    assert structured.decision == "approval_required"
    assert structured.risk is RiskLevel.P2
    assert structured.approval is not None
    assert interpreter.decision == "approval_required"
    assert interpreter.risk is RiskLevel.P3
    assert interpreter.approval is not None
