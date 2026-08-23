from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest


def _load_live_smoke() -> Any:
    path = Path(__file__).parents[2] / "scripts" / "live_chat_cycle_smoke.py"
    spec = importlib.util.spec_from_file_location("_astercode_live_chat_cycle_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load live smoke helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


_LIVE_SMOKE = _load_live_smoke()
Step = _LIVE_SMOKE.Step
_validate_approval = _LIVE_SMOKE._validate_approval
_steps = _LIVE_SMOKE._steps


def _patch_request(root: Path, target: Path, patch: str) -> dict[str, object]:
    return {
        "tool": "fs.apply_patch",
        "risk": "P1",
        "host": "local",
        "cwd": str(root),
        "real_paths": [str(target)],
        "approval_id": "approval_test",
        "action_id": "action_test",
        "action_hash": "a" * 64,
        "nonce": "nonce-for-live-smoke-test",
        "diff_hash": hashlib.sha256(patch.encode()).hexdigest(),
        "normalized_action": {"arguments": {"patch": patch}},
    }


def test_live_smoke_accepts_an_absolute_patch_bound_to_the_exact_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "chat_cycle.py"
    content = b'VALUE = "cycle2"\nprint(VALUE)\n'
    patch = (
        "*** Begin Patch\n"
        f"*** Add File: {target}\n"
        '+VALUE = "cycle2"\n'
        "+print(VALUE)\n"
        "*** End Patch"
    )
    step = Step("create", "create", "fs.apply_patch", content, "P1")

    approval_id = _validate_approval(
        _patch_request(tmp_path, target, patch),
        step=step,
        root=tmp_path,
        target=target,
    )

    assert approval_id == "approval_test"


def test_live_smoke_rejects_a_patch_for_a_different_path(tmp_path: Path) -> None:
    target = tmp_path / "chat_cycle.py"
    other = tmp_path / "other.py"
    content = b'VALUE = "cycle2"\nprint(VALUE)\n'
    patch = (
        "*** Begin Patch\n"
        f"*** Add File: {other}\n"
        '+VALUE = "cycle2"\n'
        "+print(VALUE)\n"
        "*** End Patch"
    )
    step = Step("create", "create", "fs.apply_patch", content, "P1")

    with pytest.raises(RuntimeError, match="patch does not bind only"):
        _validate_approval(
            _patch_request(tmp_path, target, patch),
            step=step,
            root=tmp_path,
            target=target,
        )


def test_live_smoke_first_create_exercises_non_git_recovery() -> None:
    steps = _steps("chat_cycle.py")
    first_create = next(step for step in steps if step.name == "cycle1-create")
    assert "git.status exactly once" in first_create.prompt
    assert "expected failure as an observation" in first_create.prompt
