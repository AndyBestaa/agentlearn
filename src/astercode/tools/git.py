"""Small, non-shell Git adapter with read-only defaults."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..security import PathAuthorizationError, canonicalize_authorized_path
from .base import ToolResult, ToolSpec, new_action_id, timed_result


@dataclass(frozen=True)
class _GitConfigEntry:
    section: str
    subsection: str | None
    name: str
    value: str


_CONFIG_SECTION_RE = re.compile(
    r'^\s*\[\s*([A-Za-z0-9][A-Za-z0-9.-]*)'
    r'(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(?:[#;].*)?$'
)
_CONFIG_ENTRY_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$"
)


def _logical_config_lines(text: str) -> Iterator[str]:
    """Yield Git-config logical lines without interpreting includes.

    Git permits a value to continue onto the next physical line with an odd
    number of trailing backslashes.  Joining those lines before parsing keeps
    a malicious section/key from being hidden by continuation syntax.
    """

    pending = ""
    for physical in text.splitlines():
        line = f"{pending}{physical}" if pending else physical
        stripped = line.rstrip()
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2:
            pending = stripped[:-1]
            continue
        yield line
        pending = ""
    if pending:
        raise PermissionError("unterminated continuation in git config")


def _parse_git_config(path: Path) -> list[_GitConfigEntry]:
    """Parse the small security-relevant subset of Git config, fail closed."""

    section: str | None = None
    subsection: str | None = None
    entries: list[_GitConfigEntry] = []
    text = path.read_text(encoding="utf-8", errors="strict")
    for line_number, line in enumerate(_logical_config_lines(text), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("["):
            match = _CONFIG_SECTION_RE.fullmatch(line)
            if match is None:
                raise PermissionError(
                    f"unsupported git config section syntax at {path.name}:{line_number}"
                )
            raw_section = match.group(1)
            quoted_subsection = match.group(2)
            # Git also accepts the legacy [section.subsection] spelling.
            if quoted_subsection is None and "." in raw_section:
                raw_section, quoted_subsection = raw_section.split(".", 1)
            section = raw_section.lower()
            subsection = quoted_subsection.lower() if quoted_subsection is not None else None
            continue
        if section is None:
            raise PermissionError(
                f"git config entry appears before a section at {path.name}:{line_number}"
            )
        match = _CONFIG_ENTRY_RE.fullmatch(line)
        if match is None:
            raise PermissionError(
                f"unsupported git config entry syntax at {path.name}:{line_number}"
            )
        entries.append(
            _GitConfigEntry(
                section=section,
                subsection=subsection,
                name=match.group(1).lower(),
                value=(match.group(2) or "true").strip(),
            )
        )
    return entries


def _is_external_driver_config(entry: _GitConfigEntry) -> bool:
    """Return whether a repository config entry can select external behavior."""

    if entry.section in {"include", "includeif", "filter"}:
        return True
    # A named diff or merge section is a driver declaration.  Reject the
    # complete section instead of trying to predict current and future Git
    # executable-driver keys.
    if entry.section in {"diff", "merge"} and entry.subsection is not None:
        return True
    if entry.section == "diff" and entry.name == "external":
        return True
    if entry.section == "interactive" and entry.name == "difffilter":
        return True
    if entry.section == "core" and entry.name in {
        "attributesfile",
        "excludesfile",
        "fsmonitor",
        "hookspath",
    }:
        return True
    return False


class GitTools:
    specs = (
        ToolSpec("git.status", "Show working tree status.", "git.read", max_output=32_000, schema={"type": "object", "properties": {"cwd": {"type": "string"}}, "required": ["cwd"], "additionalProperties": False}),
        ToolSpec("git.diff", "Show a bounded diff.", "git.read", max_output=64_000, schema={"type": "object", "properties": {"cwd": {"type": "string"}, "cached": {"type": "boolean"}}, "required": ["cwd", "cached"], "additionalProperties": False}),
        ToolSpec("git.log", "Show recent commits.", "git.read", max_output=32_000, schema={"type": "object", "properties": {"cwd": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": ["cwd", "limit"], "additionalProperties": False}),
        ToolSpec("git.show", "Show one commit or object.", "git.read", max_output=64_000, schema={"type": "object", "properties": {"cwd": {"type": "string"}, "revision": {"type": "string"}}, "required": ["cwd", "revision"], "additionalProperties": False}),
        ToolSpec("git.branch", "List branches.", "git.read", max_output=16_000, schema={"type": "object", "properties": {"cwd": {"type": "string"}}, "required": ["cwd"], "additionalProperties": False}),
        ToolSpec("git.commit", "Create a commit; gateway approval required.", "git.write", ("git_commit",), "P3", idempotent=False, schema={"type": "object", "properties": {"cwd": {"type": "string"}, "message": {"type": "string"}}, "required": ["cwd", "message"], "additionalProperties": False}),
        ToolSpec("git.push", "Push commits; gateway approval required.", "git.external", ("git_push", "network"), "P3", idempotent=False, schema={"type": "object", "properties": {"cwd": {"type": "string"}, "remote": {"type": "string"}, "branch": {"type": "string"}}, "required": ["cwd", "remote", "branch"], "additionalProperties": False}),
    )

    def __init__(self, roots: Iterable[str | Path], *, max_output: int = 64_000) -> None:
        self.roots = tuple(Path(root).resolve() for root in roots)
        self.git = self._find_git()
        self.max_output = max_output

    @staticmethod
    def _find_git() -> str | None:
        candidates: list[Path] = []
        if os.name == "nt":
            for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
                if base:
                    candidates.append(Path(base) / "Git" / "cmd" / "git.exe")
        else:
            candidates.extend([Path("/usr/bin/git"), Path("/bin/git")])
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate.resolve())
        # A PATH fallback could resolve to a repository-controlled executable;
        # fail closed on non-standard installations instead of executing it.
        return None

    def _validated_metadata_file(self, path: Path) -> Path | None:
        """Resolve an optional repository metadata file inside an allowed root."""

        if not path.exists():
            if path.is_symlink():
                raise PermissionError(f"dangling git metadata link is not allowed: {path.name}")
            return None
        try:
            checked = canonicalize_authorized_path(
                path,
                self.roots,
                must_exist=True,
                reject_unc=True,
            )
            resolved = checked.revalidate(
                self.roots,
                must_exist=True,
                reject_unc=True,
            ).resolved
        except PathAuthorizationError as exc:
            raise PermissionError(str(exc)) from exc
        if not resolved.is_file():
            raise PermissionError(f"git metadata path is not a regular file: {path.name}")
        return resolved

    def _validate_git_metadata(self, path: Path) -> tuple[Path, Path]:
        """Reject a worktree whose .git directory redirects outside the root."""
        marker: Path | None = None
        current = path
        while True:
            candidate = current / ".git"
            if candidate.exists() or candidate.is_symlink():
                marker = candidate
                break
            if any(current == root for root in self.roots) or current.parent == current:
                break
            current = current.parent
        if marker is None:
            raise PermissionError("no git metadata found inside authorized root")
        if marker.is_symlink():
            # A symlinked marker can redirect a repository outside the
            # workspace even when ``is_dir`` appears harmless.
            resolved_marker = marker.resolve(strict=True)
            if not any(resolved_marker == root or root in resolved_marker.parents for root in self.roots):
                raise PermissionError("symlinked .git directory escapes authorized roots")
        if marker.is_dir():
            resolved = marker.resolve(strict=True)
            if not any(resolved == root or root in resolved.parents for root in self.roots):
                raise PermissionError("git directory escapes authorized roots")
            git_dir = resolved
        else:
            if not marker.is_file():
                raise PermissionError("git metadata marker is not a regular file")
            first = marker.read_text(encoding="utf-8", errors="strict").splitlines()[0] if marker.stat().st_size else ""
            if not first.lower().startswith("gitdir:"):
                raise PermissionError("invalid .git metadata marker")
            git_dir = Path(first.split(":", 1)[1].strip())
            if not git_dir.is_absolute():
                git_dir = marker.parent / git_dir
            git_dir = git_dir.resolve(strict=True)
            if not any(git_dir == root or root in git_dir.parents for root in self.roots):
                raise PermissionError("git directory escapes authorized roots")
        common_dir = git_dir
        commondir_path = self._validated_metadata_file(git_dir / "commondir")
        if commondir_path is not None:
            common = Path(commondir_path.read_text(encoding="utf-8", errors="strict").strip())
            if not common.is_absolute():
                common = git_dir / common
            common = common.resolve(strict=True)
            if not any(common == root or root in common.parents for root in self.roots):
                raise PermissionError("git common directory escapes authorized roots")
            if not common.is_dir():
                raise PermissionError("git common directory is not a directory")
            common_dir = common

        config_paths = [common_dir / "config", git_dir / "config.worktree"]
        if git_dir != common_dir:
            config_paths.append(git_dir / "config")
        seen_configs: set[Path] = set()
        for config_path in config_paths:
            resolved_config = self._validated_metadata_file(config_path)
            if resolved_config is None or resolved_config in seen_configs:
                continue
            seen_configs.add(resolved_config)
            entries = _parse_git_config(resolved_config)
            for entry in entries:
                if _is_external_driver_config(entry):
                    if entry.section in {"include", "includeif"}:
                        raise PermissionError("git config include directives are not allowed")
                    detail = entry.section
                    if entry.subsection is not None:
                        detail = f"{detail}.{entry.subsection}"
                    detail = f"{detail}.{entry.name}"
                    raise PermissionError(
                        f"repository git config requests external behavior: {detail}"
                    )
                if (
                    entry.section == "core"
                    and entry.subsection is None
                    and entry.name == "worktree"
                ):
                    worktree = Path(entry.value.strip().strip('"'))
                    if not worktree.is_absolute():
                        worktree = resolved_config.parent / worktree
                    worktree = worktree.resolve(strict=False)
                    if not any(worktree == root or root in worktree.parents for root in self.roots):
                        raise PermissionError("git core.worktree escapes authorized roots")

        alternates_path = self._validated_metadata_file(
            common_dir / "objects" / "info" / "alternates"
        )
        if alternates_path is not None:
            for line in alternates_path.read_text(encoding="utf-8", errors="strict").splitlines():
                if not line.strip():
                    continue
                alternate = Path(line.strip())
                if not alternate.is_absolute():
                    alternate = alternates_path.parent / alternate
                alternate = alternate.resolve(strict=True)
                if not any(alternate == root or root in alternate.parents for root in self.roots):
                    raise PermissionError("git object alternates escape authorized roots")
        work_tree = marker.parent.resolve(strict=True)
        return git_dir, work_tree

    def _run(self, name: str, cwd: str, args: list[str], *, timeout: float = 60) -> ToolResult:
        result = timed_result(name, new_action_id(name, {"cwd": cwd, "args": args}), cwd)
        try:
            if not self.git:
                raise RuntimeError("git executable not found")
            try:
                checked = canonicalize_authorized_path(cwd, self.roots, must_exist=True, reject_unc=True)
                path = checked.revalidate(self.roots, must_exist=True, reject_unc=True).resolved
                git_dir, work_tree = self._validate_git_metadata(path)
            except PathAuthorizationError as exc:
                raise PermissionError(str(exc)) from exc
            # Keep Git non-interactive and prevent repository/system hooks or
            # credential prompts from turning a model proposal into an
            # unbounded side effect.  The gateway still requires approval for
            # commit/push; this is an additional executor-side boundary.
            env = {
                "PATH": str(Path(self.git).parent),
                "LC_ALL": "C",
                "LANG": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_ATTR_NOSYSTEM": "1",
                # Partial/promisor clones may otherwise fetch missing objects
                # during an apparently read-only log/show/diff operation.
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
            }
            # An empty core.hooksPath means the current directory to Git, so
            # it must not be used as a hook-disabling value.  A fresh empty
            # directory outside the worktree keeps hook lookup away from
            # repository-controlled paths.
            with tempfile.TemporaryDirectory(prefix="astercode-git-hooks-") as hooks_dir:
                final_git_dir, final_work_tree = self._validate_git_metadata(path)
                if final_git_dir != git_dir or final_work_tree != work_tree:
                    raise PermissionError("git metadata changed before command launch")
                git_args = [
                    "--no-pager",
                    "-c",
                    f"core.hooksPath={hooks_dir}",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "diff.external=",
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "tag.gpgSign=false",
                    "-c",
                    "credential.helper=",
                    "-c",
                    "core.askPass=",
                    f"--git-dir={git_dir}",
                    f"--work-tree={work_tree}",
                    "-C",
                    str(path),
                    *args,
                ]
                completed = subprocess.run(
                    [self.git, *git_args],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    env=env,
                )
            result.stdout, result.stderr, result.exit_code = completed.stdout, completed.stderr, completed.returncode
            result.status = "completed" if completed.returncode == 0 else "failed"
            if completed.returncode != 0:
                result.error = completed.stderr.strip() or f"git exited with code {completed.returncode}"
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.bounded(self.max_output).finish()

    def status(self, cwd: str) -> ToolResult:
        return self._run("git.status", cwd, ["status", "--short", "--branch"])

    def diff(self, cwd: str, cached: bool = False) -> ToolResult:
        return self._run("git.diff", cwd, ["diff", "--no-ext-diff", "--no-textconv", "--cached" if cached else "--"])

    def log(self, cwd: str, limit: int = 20) -> ToolResult:
        return self._run("git.log", cwd, ["log", f"-{max(1, min(limit, 100))}", "--oneline", "--decorate"])

    def show(self, cwd: str, revision: str) -> ToolResult:
        if revision.startswith("-") or any(ch in revision for ch in ";&|$`\r\n"):
            result = timed_result("git.show", new_action_id("git.show", {"cwd": cwd, "revision": revision}), cwd)
            result.status, result.error = "failed", "invalid revision"
            return result.finish()
        return self._run("git.show", cwd, ["show", "--no-ext-diff", "--no-textconv", "--stat", "--oneline", revision])

    def branch(self, cwd: str) -> ToolResult:
        return self._run("git.branch", cwd, ["branch", "--all", "--no-color"])

    def commit(self, cwd: str, message: str) -> ToolResult:
        return self._run("git.commit", cwd, ["commit", "-m", message])

    def push(self, cwd: str, remote: str, branch: str) -> ToolResult:
        for value in (remote, branch):
            if not value or value.startswith("-") or any(ch in value for ch in ";&|$`\r\n"):
                result = timed_result("git.push", new_action_id("git.push", {"cwd": cwd, "remote": remote, "branch": branch}), cwd)
                result.status, result.error = "failed", "invalid remote or branch"
                return result.finish()
        return self._run("git.push", cwd, ["push", remote, branch], timeout=120)
