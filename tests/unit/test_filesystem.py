from __future__ import annotations

import os
from pathlib import Path

from astercode.tools import filesystem as filesystem_module
from astercode.tools.filesystem import FilesystemTools


def test_apply_patch_uses_sibling_atomic_replace(
    tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("alpha\nbeta\n", encoding="utf-8")
    tools = FilesystemTools([tmp_path])
    real_replace = os.replace
    replacements: list[tuple[Path, Path]] = []

    def recording_replace(source: str, destination: str) -> None:
        replacements.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(filesystem_module.os, "replace", recording_replace)
    result = tools.apply_patch(
        """*** Begin Patch
*** Update File: sample.txt
-alpha
+gamma
*** End Patch"""
    )

    assert result.status == "completed"
    assert target.read_text(encoding="utf-8") == "gamma\nbeta\n"
    assert len(replacements) == 1
    temporary, destination = replacements[0]
    assert temporary.parent == target.parent
    assert destination == target
    assert not temporary.exists()


def test_failed_atomic_replace_preserves_original_and_cleans_temp(
    tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "sample.txt"
    original = "alpha\nbeta\n"
    target.write_text(original, encoding="utf-8")
    tools = FilesystemTools([tmp_path])

    def fail_replace(source: str, destination: str) -> None:
        del source, destination
        raise OSError("simulated replace failure")

    monkeypatch.setattr(filesystem_module.os, "replace", fail_replace)
    result = tools.apply_patch(
        """*** Begin Patch
*** Update File: sample.txt
-alpha
+gamma
*** End Patch"""
    )

    assert result.status == "failed"
    assert target.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".sample.txt.*.tmp")) == []


def test_patch_context_mismatch_does_not_overwrite_file(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    original = "user-owned change\n"
    target.write_text(original, encoding="utf-8")

    result = FilesystemTools([tmp_path]).apply_patch(
        """*** Begin Patch
*** Update File: sample.txt
-stale context
+replacement
*** End Patch"""
    )

    assert result.status == "failed"
    assert "context does not match" in str(result.error)
    assert target.read_text(encoding="utf-8") == original


def test_multi_file_patch_preflights_all_context_before_writing(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("one\n", encoding="utf-8")
    second.write_text("user change\n", encoding="utf-8")

    result = FilesystemTools([tmp_path]).apply_patch(
        """*** Begin Patch
*** Update File: first.txt
-one
+updated
*** Update File: second.txt
-stale
+must not apply
*** End Patch"""
    )

    assert result.status == "failed"
    assert first.read_text(encoding="utf-8") == "one\n"
    assert second.read_text(encoding="utf-8") == "user change\n"


def test_patch_relative_paths_bind_to_calling_cwd(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    target = nested / "sample.txt"
    target.write_text("before\n", encoding="utf-8")

    result = FilesystemTools([tmp_path]).apply_patch(
        """*** Begin Patch
*** Update File: sample.txt
-before
+after
*** End Patch""",
        cwd=str(nested),
    )

    assert result.status == "completed"
    assert target.read_text(encoding="utf-8") == "after\n"


def test_search_treats_option_like_pattern_as_data(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("needle\n", encoding="utf-8")
    captured: list[list[str]] = []

    class Completed:
        stdout = ""
        stderr = ""
        returncode = 1

    def fake_run(argv, **kwargs):
        del kwargs
        captured.append(list(argv))
        return Completed()

    monkeypatch.setattr(filesystem_module, "_trusted_rg", lambda: "rg")
    monkeypatch.setattr(filesystem_module.subprocess, "run", fake_run, raising=False)
    result = FilesystemTools([tmp_path]).search("--pre=not-an-executable", ".")

    assert result.status == "completed"
    assert "--" in captured[0]
    assert captured[0][captured[0].index("--") + 1] == "--pre=not-an-executable"


def test_filesystem_protects_runtime_and_dotenv_paths(tmp_path: Path) -> None:
    state = tmp_path / ".astercode"
    state.mkdir()
    (state / "audit.jsonl").write_text("private\n", encoding="utf-8")
    dotenv = tmp_path / ".env"
    dotenv.write_text("TOKEN=private\n", encoding="utf-8")
    tools = FilesystemTools([tmp_path])

    assert tools.read(str(state / "audit.jsonl")).status == "failed"
    assert tools.read(str(dotenv)).status == "failed"
