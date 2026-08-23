from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from astercode.tools import git as git_module
from astercode.tools.git import GitTools


def _run_trusted_git(
    tools: GitTools, cwd: Path, *args: str
) -> subprocess.CompletedProcess[str]:
    assert tools.git is not None
    return subprocess.run(
        [tools.git, "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _marker_command(script: Path, marker: Path) -> str:
    argv = [sys.executable, str(script), str(marker)]
    return subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)


def test_git_show_rejects_revision_injection_before_spawn(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / ".git").mkdir()
    tools = GitTools([tmp_path])

    def unexpected_run(*args, **kwargs):
        del args, kwargs
        raise AssertionError("invalid revision must not reach subprocess")

    monkeypatch.setattr(git_module.subprocess, "run", unexpected_run)
    result = tools.show(str(tmp_path), "HEAD;$((1+1))")

    assert result.status == "failed"
    assert "invalid revision" in str(result.error)


def test_git_commit_message_is_one_argv_element_not_shell_text(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / ".git").mkdir()
    tools = GitTools([tmp_path])
    tools.git = str(tmp_path / "fake-git")
    captured: dict[str, Any] = {}

    def recording_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(git_module.subprocess, "run", recording_run)
    message = "safe message; $(touch should-not-exist) `ignored`"
    result = tools.commit(str(tmp_path), message)

    assert result.status == "completed"
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[-3:] == ["commit", "-m", message]
    hooks_arg = next(value for value in argv if value.startswith("core.hooksPath="))
    hooks_path = Path(hooks_arg.split("=", 1)[1])
    assert hooks_path.is_absolute()
    assert hooks_path.parent == Path(tempfile.gettempdir()).resolve()
    assert captured["kwargs"]["env"]["GIT_ATTR_NOSYSTEM"] == "1"
    assert captured["kwargs"]["env"]["GIT_NO_LAZY_FETCH"] == "1"
    assert "shell" not in captured["kwargs"]
    assert not (tmp_path / "should-not-exist").exists()


def test_git_push_rejects_option_and_shell_metacharacters(
    tmp_path: Path, monkeypatch
) -> None:
    tools = GitTools([tmp_path])

    def unexpected_run(*args, **kwargs):
        del args, kwargs
        raise AssertionError("invalid push target must not reach subprocess")

    monkeypatch.setattr(git_module.subprocess, "run", unexpected_run)

    assert tools.push(str(tmp_path), "--upload-pack=evil", "main").status == "failed"
    assert tools.push(str(tmp_path), "origin", "main;whoami").status == "failed"


def test_git_rejects_external_core_worktree(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n\tworktree = ../../outside\n", encoding="utf-8")
    result = GitTools([tmp_path]).status(str(tmp_path))
    assert result.status == "failed"
    assert "worktree" in str(result.error)


def test_git_rejects_repository_config_include(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[includeIf "gitdir:/**"]\n\tpath = C:/outside/host-config\n',
        encoding="utf-8",
    )

    result = GitTools([tmp_path]).status(str(tmp_path))

    assert result.status == "failed"
    assert "include directives" in str(result.error)


def test_git_commit_disables_repository_requested_signing(tmp_path: Path) -> None:
    tools = GitTools([tmp_path])
    if tools.git is None:
        return

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [tools.git or "", "-C", str(tmp_path), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    assert run("init").returncode == 0
    assert run("config", "user.name", "AsterCode Test").returncode == 0
    assert run("config", "user.email", "astercode@example.invalid").returncode == 0
    assert run("config", "commit.gpgSign", "true").returncode == 0
    assert run("config", "gpg.program", "definitely-does-not-exist-astercode").returncode == 0
    (tmp_path / "tracked.txt").write_text("safe\n", encoding="utf-8")
    assert run("add", "--", "tracked.txt").returncode == 0

    result = tools.commit(str(tmp_path), "safe unsigned commit")

    assert result.status == "completed", result.error
    assert run("rev-list", "--count", "HEAD").stdout.strip() == "1"


def test_git_discovery_ignores_workspace_controlled_path(tmp_path: Path, monkeypatch) -> None:
    fake_git = tmp_path / ("git.exe" if os.name == "nt" else "git")
    fake_git.write_text("not an executable", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))

    discovered = GitTools([tmp_path]).git

    assert discovered is None or Path(discovered).resolve() != fake_git.resolve()


@pytest.mark.parametrize(
    ("config_key", "operation"),
    [
        ("filter.evil.process", "status"),
        ("filter.evil.clean", "diff"),
        ("diff.evil.command", "diff"),
        ("diff.evil.textconv", "show"),
    ],
)
def test_readonly_git_never_starts_repository_external_driver(
    tmp_path: Path,
    config_key: str,
    operation: str,
) -> None:
    tools = GitTools([tmp_path])
    if tools.git is None:
        pytest.skip("trusted Git executable is unavailable")

    assert _run_trusted_git(tools, tmp_path, "init").returncode == 0
    assert (
        _run_trusted_git(tools, tmp_path, "config", "user.name", "AsterCode Test").returncode
        == 0
    )
    assert (
        _run_trusted_git(
            tools,
            tmp_path,
            "config",
            "user.email",
            "astercode@example.invalid",
        ).returncode
        == 0
    )
    (tmp_path / ".gitattributes").write_text(
        "*.txt filter=evil diff=evil\n",
        encoding="utf-8",
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    assert (
        _run_trusted_git(tools, tmp_path, "add", "--", ".gitattributes", "tracked.txt").returncode
        == 0
    )
    assert _run_trusted_git(tools, tmp_path, "commit", "-m", "baseline").returncode == 0
    tracked.write_text("after\n", encoding="utf-8")

    marker = tmp_path / "external-driver-ran.marker"
    script = tmp_path / "external_driver.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    assert (
        _run_trusted_git(
            tools,
            tmp_path,
            "config",
            config_key,
            _marker_command(script, marker),
        ).returncode
        == 0
    )

    if operation == "status":
        result = tools.status(str(tmp_path))
    elif operation == "diff":
        result = tools.diff(str(tmp_path))
    else:
        result = tools.show(str(tmp_path), "HEAD")

    assert result.status == "failed"
    assert "external behavior" in str(result.error)
    assert not marker.exists()


@pytest.mark.parametrize("operation", ["status", "diff", "log", "show", "branch"])
def test_every_automatic_readonly_git_tool_fails_closed_on_filter_config(
    tmp_path: Path,
    operation: str,
) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[filter "unsafe"]\n\tprocess = definitely-must-not-run\n',
        encoding="utf-8",
    )
    tools = GitTools([tmp_path])

    if operation == "status":
        result = tools.status(str(tmp_path))
    elif operation == "diff":
        result = tools.diff(str(tmp_path))
    elif operation == "log":
        result = tools.log(str(tmp_path))
    elif operation == "show":
        result = tools.show(str(tmp_path), "HEAD")
    else:
        result = tools.branch(str(tmp_path))

    assert result.status == "failed"
    assert "external behavior" in str(result.error)


@pytest.mark.parametrize("name", ["attributesFile", "excludesFile", "fsmonitor", "hooksPath"])
def test_git_rejects_repository_external_files_and_hook_configuration(
    tmp_path: Path,
    name: str,
) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        f"[core]\n\t{name} = ../../outside-controlled-file\n",
        encoding="utf-8",
    )

    result = GitTools([tmp_path]).status(str(tmp_path))

    assert result.status == "failed"
    assert "external behavior" in str(result.error)


def test_git_rejects_external_driver_in_worktree_config(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        "[extensions]\n\tworktreeConfig = true\n",
        encoding="utf-8",
    )
    (git_dir / "config.worktree").write_text(
        '[diff "unsafe"]\n\tcommand = definitely-must-not-run\n',
        encoding="utf-8",
    )

    result = GitTools([tmp_path]).status(str(tmp_path))

    assert result.status == "failed"
    assert "external behavior" in str(result.error)


def test_git_rejects_external_driver_in_linked_worktree_common_config(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    linked_git_dir = tmp_path / "common" / "worktrees" / "worktree"
    worktree.mkdir()
    linked_git_dir.mkdir(parents=True)
    (worktree / ".git").write_text(
        "gitdir: ../common/worktrees/worktree\n",
        encoding="utf-8",
    )
    (linked_git_dir / "commondir").write_text("../..\n", encoding="utf-8")
    (tmp_path / "common" / "config").write_text(
        '[filter "unsafe"]\n\tclean = definitely-must-not-run\n',
        encoding="utf-8",
    )

    result = GitTools([tmp_path]).status(str(worktree))

    assert result.status == "failed"
    assert "external behavior" in str(result.error)


def test_git_commit_does_not_run_hook_from_worktree_root(tmp_path: Path) -> None:
    tools = GitTools([tmp_path])
    if tools.git is None:
        pytest.skip("trusted Git executable is unavailable")

    assert _run_trusted_git(tools, tmp_path, "init").returncode == 0
    assert (
        _run_trusted_git(tools, tmp_path, "config", "user.name", "AsterCode Test").returncode
        == 0
    )
    assert (
        _run_trusted_git(
            tools,
            tmp_path,
            "config",
            "user.email",
            "astercode@example.invalid",
        ).returncode
        == 0
    )
    marker = tmp_path / "hook-ran.marker"
    hook = tmp_path / "pre-commit"
    hook.write_text(
        "#!/bin/sh\nprintf executed > hook-ran.marker\nexit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    (tmp_path / "tracked.txt").write_text("safe\n", encoding="utf-8")
    assert _run_trusted_git(tools, tmp_path, "add", "--", "tracked.txt").returncode == 0

    result = tools.commit(str(tmp_path), "commit with hooks disabled")

    assert result.status == "completed", result.error
    assert not marker.exists()
