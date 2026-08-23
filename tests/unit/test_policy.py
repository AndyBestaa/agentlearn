from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from astercode.config import AppConfig, ExecutionMode
from astercode.models import ApprovalDecision, ApprovalStatus, RiskLevel, utc_now
from astercode.policy import PolicyEngine
from astercode.storage import Storage


def _decision_for(request, *, approved: bool = True) -> ApprovalDecision:
    return ApprovalDecision(
        approval_id=request.approval_id,
        action_id=request.action_id,
        action_hash=request.action_hash,
        nonce=request.nonce,
        approved=approved,
    )


def test_policy_classifies_concrete_operations(app_config: AppConfig, tmp_path: Path) -> None:
    engine = PolicyEngine(app_config)

    assert engine.classify("fs.read", {"path": str(tmp_path)}) is RiskLevel.P0
    assert engine.classify("fs.apply_patch", {"patch": "x"}) is RiskLevel.P1
    assert engine.classify("process.exec", {"argv": ["python"]}) is RiskLevel.P3
    assert engine.classify("fs.delete", {"path": "x", "recursive": True}) is RiskLevel.P4
    assert engine.classify("git.push", {"remote": "origin"}) is RiskLevel.P3


def test_process_launch_is_denied_before_approval_without_attested_boundaries(
    app_config: AppConfig, tmp_path: Path
) -> None:
    data = app_config.model_dump()
    data["security"]["process"]["allow_unsandboxed_process"] = True
    config = AppConfig.model_validate(data)

    decision = PolicyEngine(config).evaluate(
        "process.exec",
        {"argv": ["python", "-V"], "cwd": str(tmp_path), "timeout": 10},
        cwd=str(tmp_path),
    )

    assert decision.decision == "deny"
    assert decision.approval is None
    assert "approval cannot replace" in decision.reason


def test_policy_allows_read_but_binds_write_approval_hash(
    app_config: AppConfig, tmp_path: Path
) -> None:
    file = tmp_path / "file.txt"
    file.write_text("one\n", encoding="utf-8")
    engine = PolicyEngine(app_config)

    read = engine.evaluate("fs.read", {"path": str(file)}, cwd=str(tmp_path))
    first = engine.evaluate(
        "fs.apply_patch",
        {"patch": "*** Begin Patch\n*** Add File: first.txt\n+first\n*** End Patch"},
        cwd=str(tmp_path),
    )
    second = engine.evaluate(
        "fs.apply_patch",
        {"patch": "*** Begin Patch\n*** Add File: second.txt\n+second\n*** End Patch"},
        cwd=str(tmp_path),
    )

    assert read.decision == "allow"
    assert read.risk is RiskLevel.P0
    assert first.decision == "approval_required"
    assert first.approval is not None
    assert first.normalized_action["real_paths"] == [str(tmp_path / "first.txt")]
    assert first.action_hash != second.action_hash


def test_policy_rejects_unbound_patch_format_before_approval(
    app_config: AppConfig, tmp_path: Path
) -> None:
    engine = PolicyEngine(app_config)

    with pytest.raises(ValueError, match=r"\*\*\* Begin Patch"):
        engine.evaluate(
            "fs.apply_patch",
            {
                "patch": (
                    "--- /dev/null\n"
                    "+++ b/hello.py\n"
                    "@@ -0,0 +1 @@\n"
                    '+print("hello world")'
                )
            },
            cwd=str(tmp_path),
        )

    assert not (tmp_path / "hello.py").exists()


def test_policy_denies_ssh_when_allowlist_is_empty(app_config: AppConfig) -> None:
    decision = PolicyEngine(app_config).evaluate(
        "ssh.exec",
        {"command": ["uname", "-a"]},
        host="unconfigured-host",
    )

    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P4


def test_policy_denies_external_network_when_default_is_deny(app_config: AppConfig) -> None:
    decision = PolicyEngine(app_config).evaluate(
        "git.push",
        {"cwd": str(app_config.project_root), "remote": "origin", "branch": "main"},
        cwd=str(app_config.project_root),
    )

    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P3


def test_recursive_delete_is_p4_default_deny(app_config: AppConfig) -> None:
    decision = PolicyEngine(app_config).evaluate(
        "fs.delete",
        {"path": "old", "recursive": True},
        cwd=str(app_config.project_root),
    )
    assert decision.decision == "deny"
    assert decision.risk is RiskLevel.P4


def test_read_only_mode_denies_workspace_write(app_config: AppConfig) -> None:
    readonly = app_config.model_copy(update={"execution_mode": ExecutionMode.READ_ONLY})
    decision = PolicyEngine(readonly).evaluate(
        "fs.mkdir", {"path": "new"}, cwd=str(readonly.project_root)
    )
    assert decision.decision == "deny"


def test_approval_expires_and_is_single_use(
    app_config: AppConfig, storage: Storage
) -> None:
    engine = PolicyEngine(app_config, storage)
    evaluated = engine.evaluate("fs.mkdir", {"path": "created"}, cwd=str(app_config.project_root))
    assert evaluated.approval is not None
    request = evaluated.approval
    engine.persist_request(request)

    decision = engine.approve(request, actor="unit-test")
    assert engine.verify_decision(request, decision) is True

    engine.consume(request)
    assert storage.get_approval(request.approval_id)["status"] == ApprovalStatus.CONSUMED.value
    assert engine.verify_decision(request, decision) is False

    expired = request.model_copy(update={"expires_at": utc_now() - timedelta(seconds=1)})
    assert engine.verify_decision(expired, _decision_for(expired)) is False


def test_approval_rejects_changed_hash_or_nonce(
    app_config: AppConfig, storage: Storage
) -> None:
    engine = PolicyEngine(app_config, storage)
    evaluated = engine.evaluate("fs.mkdir", {"path": "created"}, cwd=str(app_config.project_root))
    assert evaluated.approval is not None
    request = evaluated.approval
    engine.persist_request(request)

    wrong_hash = _decision_for(request).model_copy(update={"action_hash": "0" * 64})
    wrong_nonce = _decision_for(request).model_copy(update={"nonce": "x" * 32})

    assert engine.verify_decision(request, wrong_hash) is False
    assert engine.verify_decision(request, wrong_nonce) is False
