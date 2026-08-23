from __future__ import annotations

from pathlib import Path

import pytest

from astercode.security import (
    REDACTED,
    PathAuthorizationError,
    SecretDetectedError,
    canonicalize_authorized_path,
    contains_probable_secret,
    redact_secrets,
    require_secret_reference,
)


def test_canonicalize_relative_path_under_authorized_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "src" / "module.py"
    target.parent.mkdir()
    target.write_text("value = 1\n", encoding="utf-8")

    checked = canonicalize_authorized_path(
        "src/module.py",
        [workspace],
        cwd=workspace,
        must_exist=True,
    )

    assert checked.resolved == target.resolve()
    assert checked.root == workspace.resolve()
    assert checked.exists is True


def test_canonicalize_rejects_dotdot_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    with pytest.raises(PathAuthorizationError, match="outside"):
        canonicalize_authorized_path(
            "../outside.txt",
            [workspace],
            cwd=workspace,
            must_exist=True,
        )


def test_redactor_handles_text_and_nested_sensitive_keys() -> None:
    fake_token = "sk-" + "A" * 24
    payload = {
        "message": f"Authorization: Bearer {'B' * 24}; token={fake_token}",
        "password": "not-a-real-password",
        "nested": [{"api_key": fake_token}],
        "api_key_env": "OPENAI_API_KEY",
    }

    safe = redact_secrets(payload)

    assert fake_token not in str(safe)
    assert safe["password"] == REDACTED
    assert safe["nested"][0]["api_key"] == REDACTED
    assert safe["api_key_env"] == "OPENAI_API_KEY"
    assert contains_probable_secret(payload) is True


def test_secret_reference_accepts_name_but_rejects_inline_value() -> None:
    assert require_secret_reference("api_key_env", "OPENAI_API_KEY") == "OPENAI_API_KEY"
    with pytest.raises(SecretDetectedError, match="inline secret"):
        require_secret_reference("api_key_env", "sk-" + "Z" * 24)
