from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest


def _load_preflight() -> Any:
    path = Path(__file__).parents[2] / "scripts" / "portability_preflight.py"
    spec = importlib.util.spec_from_file_location("_astercode_portability_preflight", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load portability preflight: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Any, module)


PREFLIGHT = _load_preflight()


def _git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required for portability preflight tests")
    return git


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        [_git_executable(), "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"test Git command failed: {' '.join(arguments)}")
    return completed


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=AsterCode Portability Tests",
        "-c",
        "user.email=portability@example.invalid",
        "-c",
        "core.hooksPath=.git/no-hooks",
        "commit",
        "--no-gpg-sign",
        "-m",
        message,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "portable-repository"
    root.mkdir()
    _git_executable()
    subprocess.run(
        [_git_executable(), "init", "--initial-branch=main", str(root)],
        check=True,
        capture_output=True,
        timeout=20,
    )
    (root / ".git" / "no-hooks").mkdir()
    (root / ".gitignore").write_text(
        "\n".join(
            (
                ".venv/",
                ".env",
                ".env.*",
                "!.env.example",
                "__pycache__/",
                "*.py[cod]",
                ".pytest_cache/",
                ".mypy_cache/",
                ".ruff_cache/",
                ".langgraph_api/",
                ".astercode/",
                "%SystemDrive%/",
                "config.toml",
                "dist/",
                "build/",
                "*.pem",
                "*.key",
                "*.p12",
                "*.pfx",
                "*.db",
                "*.sqlite",
                "*.sqlite3",
                "*.db-shm",
                "*.db-wal",
                "",
            )
        ),
        encoding="utf-8",
        newline="\n",
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "portable-fixture"\nversion = "0.0.0"\nrequires-python = ">=3.12"\n',
        encoding="utf-8",
        newline="\n",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 1\n", encoding="utf-8", newline="\n")
    digest = "a" * 64
    (root / "config.example.toml").write_text(
        "project_root = \".\"\n"
        "[security.process]\n"
        f'container_image = "example.invalid/python@sha256:{digest}"\n',
        encoding="utf-8",
        newline="\n",
    )
    (root / "safe.txt").write_text("portable fixture\n", encoding="utf-8", newline="\n")
    (root / "AGENTS.md").write_text("# Fixture agent rules\n", encoding="utf-8", newline="\n")
    (root / "HANDOFF.md").write_text("# Fixture handoff\n", encoding="utf-8", newline="\n")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8", newline="\n")
    docs = root / "docs"
    docs.mkdir()
    (docs / "implementation-plan.md").write_text("# Plan\n", encoding="utf-8", newline="\n")
    (docs / "threat-model.md").write_text("# Threat model\n", encoding="utf-8", newline="\n")
    (docs / "release-checklist.md").write_text("# Release checklist\n", encoding="utf-8", newline="\n")
    _commit(root, "portable baseline")
    return root


def _check(report: Any, check_id: str) -> Any:
    return next(item for item in report.checks if item.check_id == check_id)


def test_dirty_repository_fails_unless_development_override_is_explicit(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "safe.txt").write_text(
        "intentional development change\n",
        encoding="utf-8",
        newline="\n",
    )

    blocked = PREFLIGHT.run_preflight(root, profile="source")
    allowed = PREFLIGHT.run_preflight(root, profile="source", allow_dirty=True)

    assert blocked.exit_code == 1
    assert _check(blocked, "repository.clean").status == "FAIL"
    assert allowed.passed is True
    assert _check(allowed, "repository.clean").status == "PASS"


def test_literal_systemdrive_directory_is_rejected_without_reading_children(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    artifact = root / "%SystemDrive%"
    artifact.mkdir()
    child_name = "must-not-be-inspected.txt"
    (artifact / child_name).write_bytes(b"opaque machine-local content")

    report = PREFLIGHT.run_preflight(root, profile="source")
    rendered = PREFLIGHT.render_report(report, "text")

    assert report.exit_code == 1
    assert _check(report, "runtime.literal_systemdrive").status == "FAIL"
    assert child_name not in rendered


def test_tracked_runtime_state_fails_even_when_git_was_forced_to_add_it(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    runtime = root / ".astercode" / "state.db"
    runtime.parent.mkdir()
    runtime.write_bytes(b"not a real database")
    _git(root, "add", "--force", ".astercode/state.db")
    _git(
        root,
        "-c",
        "user.name=AsterCode Portability Tests",
        "-c",
        "user.email=portability@example.invalid",
        "-c",
        "core.hooksPath=.git/no-hooks",
        "commit",
        "--no-gpg-sign",
        "-m",
        "bad runtime fixture",
    )

    report = PREFLIGHT.run_preflight(root, profile="source")

    assert report.exit_code == 1
    assert _check(report, "tracked.hygiene").status == "FAIL"


def test_local_git_exclude_cannot_replace_a_tracked_ignore_rule(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    ignore = root / ".gitignore"
    ignore.write_text(
        ignore.read_text(encoding="utf-8").replace("%SystemDrive%/\n", ""),
        encoding="utf-8",
        newline="\n",
    )
    _commit(root, "remove required tracked ignore")
    info_exclude = root / ".git" / "info" / "exclude"
    with info_exclude.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("%SystemDrive%/\n")

    report = PREFLIGHT.run_preflight(root, profile="source")

    assert report.exit_code == 1
    assert _check(report, "runtime.ignore").status == "FAIL"


def test_machine_specific_user_home_path_is_rejected(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    machine_path = "C:" + "\\Users" + "\\Alice\\private-project"
    (root / "notes.txt").write_text(f"checkout={machine_path}\n", encoding="utf-8")
    _commit(root, "bad local path fixture")

    report = PREFLIGHT.run_preflight(root, profile="source")

    assert report.exit_code == 1
    assert _check(report, "content.machine_paths").status == "FAIL"
    assert machine_path not in PREFLIGHT.render_report(report, "json")


def test_secret_detection_fails_without_echoing_the_value(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    secret = "sk-" + "A" * 24
    (root / "accidental.txt").write_text(f"token={secret}\n", encoding="utf-8")
    _commit(root, "bad secret fixture")

    report = PREFLIGHT.run_preflight(root, profile="source")
    rendered_json = PREFLIGHT.render_report(report, "json")
    rendered_text = PREFLIGHT.render_report(report, "text")

    assert report.exit_code == 1
    assert _check(report, "content.secrets").status == "FAIL"
    assert secret not in rendered_json
    assert secret not in rendered_text


def test_inherited_provider_secret_is_matched_exactly_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    marker = "company-provider-value-" + "Z" * 20
    monkeypatch.setenv("DEEPSEEK_API_KEY", marker)
    (root / "accidental.txt").write_text(f"copied value: {marker}\n", encoding="utf-8")
    _commit(root, "bad inherited secret fixture")

    report = PREFLIGHT.run_preflight(root, profile="source")
    rendered = PREFLIGHT.render_report(report, "json")

    assert report.exit_code == 1
    assert _check(report, "content.secrets").status == "FAIL"
    assert "inherited_value:DEEPSEEK_API_KEY" in rendered
    assert marker not in rendered


def test_demo_profile_checks_local_engine_and_exact_image_without_pull(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    original_trusted_command = PREFLIGHT._trusted_command
    external = Path(sys.executable).resolve()
    observed: list[tuple[str, ...]] = []

    def trusted_command(name: str, candidate_root: Path) -> Path | None:
        if name in {"uv", "docker"}:
            return external
        return original_trusted_command(name, candidate_root)

    def runner(
        argv: Any,
        cwd: Path,
        env: dict[str, str],
        input_bytes: bytes | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[bytes]:
        arguments = tuple(str(item) for item in argv)
        if "--host" in arguments:
            observed.append(arguments)
            if "version" in arguments:
                return subprocess.CompletedProcess(arguments, 0, b"linux\n", b"")
            return subprocess.CompletedProcess(
                arguments,
                0,
                ("sha256:" + "b" * 64 + "\n").encode(),
                b"",
            )
        return PREFLIGHT._run_command(argv, cwd, env, input_bytes, timeout)

    monkeypatch.setattr(PREFLIGHT, "_trusted_command", trusted_command)

    report = PREFLIGHT.run_preflight(root, profile="demo", runner=runner)

    assert report.passed is True
    assert _check(report, "docker.engine").status == "PASS"
    assert _check(report, "docker.image_present").status == "PASS"
    assert observed
    assert all("pull" not in arguments for arguments in observed)


def test_current_repository_source_profile_passes_with_allow_dirty() -> None:
    root = Path(__file__).parents[2]

    report = PREFLIGHT.run_preflight(root, profile="source", allow_dirty=True)

    assert report.passed is True, PREFLIGHT.render_report(report, "text")
    assert PREFLIGHT._git_environment()["GIT_NO_LAZY_FETCH"] == "1"
    assert _check(report, "tracked.hygiene").status == "PASS"
    assert _check(report, "runtime.ignore").status == "PASS"
    assert _check(report, "handoff.manifest").status == "PASS"
    assert _check(report, "content.secrets").status == "PASS"
    assert _check(report, "content.machine_paths").status == "PASS"
