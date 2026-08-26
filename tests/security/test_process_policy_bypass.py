from __future__ import annotations

import sys
from pathlib import Path

import pytest

from astercode.config import AppConfig
from astercode.models import RiskLevel
from astercode.policy import PolicyEngine, RuntimePolicyCapabilities
from astercode.tools.process import ProcessTools


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
        ("process.exec", {"argv": ["cmd", "/cgit", "status"]}),
        ("process.exec", {"argv": ["cmd.exe", "/cecho", "hi"]}),
        ("process.exec", {"argv": ["bash", "-cgit", "status"]}),
        ("process.exec", {"argv": ["python", "-cprint(1)"]}),
        ("process.exec", {"argv": ["pwsh", "-Command:git status"]}),
        ("process.exec", {"argv": ["powershell", "-EncodedCommand:Z2l0"]}),
        ("process.exec", {"argv": ["node", "--eval=fetch('https://example.test')"]}),
        ("process.exec", {"argv": ["python", "-m", "http.server"]}),
        ("process.exec", {"argv": ["python", "-mhttp.server"]}),
        ("process.exec", {"argv": ["py", "-m", "http.server"]}),
        ("process.exec", {"argv": ["pythonw.exe", "-c", "print(1)"]}),
        ("process.exec", {"argv": ["nodejs", "-r", "evil.js"]}),
        ("process.exec", {"argv": ["deno", "run", "evil.ts"]}),
        ("process.exec", {"argv": ["bun", "run", "evil.ts"]}),
        ("process.exec", {"argv": ["node", "--require=evil.js"]}),
        ("process.exec", {"argv": ["ruby", "-r", "evil.rb"]}),
        ("process.exec", {"argv": ["perl", "-M", "evil"]}),
        ("process.exec", {"argv": ["pwsh", "-File", "reviewed.ps1"]}),
        ("process.exec", {"argv": ["pwsh", "reviewed.ps1"]}),
        ("process.exec", {"argv": ["bash", "--rcfile", "evil.bash"]}),
        ("process.exec", {"argv": ["gh", "pr", "create"]}),
        ("process.exec", {"argv": ["svn", "commit"]}),
        ("process.exec", {"argv": ["hg", "push"]}),
        ("process.exec", {"argv": ["env", "SAFE=1", "git", "status"]}),
        ("process.exec", {"argv": ["uv", "run", "curl", "https://example.test"]}),
        ("process.exec", {"argv": ["env", "python", "-m", "http.server"]}),
        ("process.exec", {"argv": ["uv", "run", "python", "-m", "http.server"]}),
        ("process.exec", {"argv": ["sudo", "python", "reviewed.py"]}),
        ("process.start", {"argv": ["xargs", "python", "-m", "http.server"]}),
        ("shell.exec", {"script": '"C:\\Program Files\\Git\\cmd\\git.exe" status', "dialect": "powershell"}),
        ("shell.exec", {"script": "Remove-Item -Recurse -Force .", "dialect": "powershell"}),
        ("shell.exec", {"script": "ssh host -- dangerous", "dialect": "bash"}),
        ("shell.exec", {"script": "sudo systemctl restart example.service", "dialect": "bash"}),
        ("shell.exec", {"script": "`git status", "dialect": "powershell"}),
        (
            "shell.exec",
            {"script": "`Invoke-WebRequest https://example.test", "dialect": "powershell"},
        ),
        (
            "shell.exec",
            {
                "script": '&([string]::Join("", ("g", "it"))) status',
                "dialect": "powershell",
            },
        ),
        ("shell.exec", {"script": r"g\it status", "dialect": "bash"}),
        ("shell.exec", {"script": 'g"it" status', "dialect": "bash"}),
        ("shell.exec", {"script": "eval git status", "dialect": "bash"}),
        ("shell.exec", {"script": ".\\reviewed.ps1", "dialect": "powershell"}),
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
    assert any(word in decision.reason for word in ("dedicated", "cannot use", "constrained", "inline", "module", "wrapper", "profile"))


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
        {"argv": [sys.executable, "reviewed_test.py", "-q"], "cwd": str(tmp_path), "timeout": 30},
        cwd=str(tmp_path),
    )

    assert structured.decision == "approval_required"
    assert structured.risk is RiskLevel.P2
    assert structured.approval is not None
    assert interpreter.decision == "approval_required"
    assert interpreter.risk is RiskLevel.P3
    assert interpreter.approval is not None


def test_interpreter_module_loading_is_denied_even_with_attested_boundaries(
    app_config: AppConfig, tmp_path: Path
) -> None:
    decision = PolicyEngine(
        app_config,
        runtime_capabilities=RuntimePolicyCapabilities(
            process_sandbox_enforced=True,
            process_network_policy_enforced=True,
        ),
    ).evaluate(
        "process.exec",
        {"argv": [sys.executable, "-m", "pytest"], "cwd": str(tmp_path), "timeout": 30},
        cwd=str(tmp_path),
    )

    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P4
    assert decision.approval is None
    assert "module" in decision.reason


def test_powershell_reviewed_file_requires_profile_and_interactive_guards(
    app_config: AppConfig, tmp_path: Path
) -> None:
    engine = PolicyEngine(
        app_config,
        runtime_capabilities=RuntimePolicyCapabilities(
            process_sandbox_enforced=True,
            process_network_policy_enforced=True,
        ),
    )

    unsafe = engine.evaluate(
        "process.exec",
        {"argv": ["pwsh", "reviewed.ps1"], "cwd": str(tmp_path), "timeout": 30},
        cwd=str(tmp_path),
    )
    safe = engine.evaluate(
        "process.exec",
        {
            "argv": ["pwsh", "-NoProfile", "-NonInteractive", "reviewed.ps1"],
            "cwd": str(tmp_path),
            "timeout": 30,
        },
        cwd=str(tmp_path),
    )

    assert unsafe.decision == "deny"
    assert unsafe.risk is RiskLevel.P4
    assert "profile" in unsafe.reason
    assert safe.decision == "approval_required"
    assert safe.risk is RiskLevel.P3
    assert safe.approval is not None


@pytest.mark.parametrize(
    ("script", "dialect"),
    [
        ("Write-Output hello", "powershell"),
        ("printf hello", "bash"),
    ],
)
def test_attested_shell_is_blocked_until_a_constrained_adapter_exists(
    app_config: AppConfig,
    tmp_path: Path,
    script: str,
    dialect: str,
) -> None:
    decision = PolicyEngine(
        app_config,
        runtime_capabilities=RuntimePolicyCapabilities(
            process_sandbox_enforced=True,
            process_network_policy_enforced=True,
        ),
    ).evaluate(
        "shell.exec",
        {"script": script, "dialect": dialect, "cwd": str(tmp_path), "timeout": 10},
        cwd=str(tmp_path),
    )

    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P4
    assert decision.approval is None
    assert "constrained" in decision.reason


def test_shell_tool_declaration_is_blocked_until_adapter_exists() -> None:
    shell_spec = next(spec for spec in ProcessTools.specs if spec.name == "shell.exec")

    assert shell_spec.risk == RiskLevel.P4.value
    assert "blocked" in shell_spec.description
