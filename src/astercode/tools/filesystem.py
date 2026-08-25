"""Workspace-scoped filesystem tools.

Every operation resolves the path immediately before use and checks it against
the configured roots.  Writes use a temporary sibling and atomic replacement.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from ..security import AuthorizedPath, PathAuthorizationError, canonicalize_authorized_path, protected_path_reason
from .base import ToolResult, ToolSpec, new_action_id, timed_result


class FilesystemTools:
    specs = (
        ToolSpec("fs.list", "List entries under an authorized directory. Use path '.' for the current workspace root; never guess an absolute host path.", "filesystem.read", max_output=16_000, schema={"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}, "required": ["path", "recursive"], "additionalProperties": False}),
        ToolSpec("fs.stat", "Read metadata for an authorized path.", "filesystem.read", max_output=8_000, schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        ToolSpec("fs.read", "Read bounded UTF-8 text from an authorized file.", "filesystem.read", max_output=32_000, schema={"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1}, "end_line": {"type": ["integer", "null"], "minimum": 1}}, "required": ["path", "start_line", "end_line"], "additionalProperties": False}),
        ToolSpec("fs.search", "Search authorized files with ripgrep when available.", "filesystem.read", max_output=32_000, schema={"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}, "max_results": {"type": "integer", "minimum": 1, "maximum": 1000}}, "required": ["pattern", "path", "max_results"], "additionalProperties": False}),
        ToolSpec(
            "fs.apply_patch",
            "Apply an exact AsterCode patch inside the workspace; standard ---/+++ unified diffs are invalid.",
            "filesystem.write",
            ("file_write",),
            "P1",
            idempotent=False,
            schema={
                "type": "object",
                "properties": {
                    "patch": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 262_144,
                        "description": (
                            "Use exactly: *** Begin Patch, then *** Add File: path or "
                            "*** Update File: path with +/- lines, then *** End Patch. "
                            "Never use ---/+++ headers; use fs.delete for deletion."
                        ),
                        "examples": [
                            "*** Begin Patch\n*** Add File: hello.py\n+print(\"hello\")\n*** End Patch"
                        ],
                    }
                },
                "required": ["patch"],
                "additionalProperties": False,
            },
        ),
        ToolSpec("fs.mkdir", "Create an authorized directory.", "filesystem.write", ("directory_create",), "P1", idempotent=True, schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}),
        ToolSpec("fs.move", "Move an authorized path within the workspace.", "filesystem.write", ("path_move",), "P1", idempotent=False, schema={"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}, "required": ["source", "destination"], "additionalProperties": False}),
        ToolSpec("fs.delete", "Delete an authorized path; approval is required by the gateway.", "filesystem.delete", ("path_delete",), "P3", idempotent=False, schema={"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}, "required": ["path", "recursive"], "additionalProperties": False}),
    )

    def __init__(self, roots: Iterable[str | Path], *, max_read_bytes: int = 1_000_000) -> None:
        self.roots = tuple(self._canonical_root(Path(root)) for root in roots)
        if not self.roots:
            raise ValueError("at least one authorized root is required")
        self.max_read_bytes = max_read_bytes

    @staticmethod
    def _canonical_root(path: Path) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        return path.resolve(strict=True)

    def resolve(self, raw: str | Path, *, must_exist: bool = False, for_write: bool = False, cwd: str | Path | None = None) -> Path:
        return self.resolve_authorized(raw, must_exist=must_exist, for_write=for_write, cwd=cwd).resolved

    def resolve_authorized(self, raw: str | Path, *, must_exist: bool = False, for_write: bool = False, cwd: str | Path | None = None) -> AuthorizedPath:
        """Return a path plus the identity anchor used for TOCTOU checks."""
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute() and cwd is None:
            candidate = self.roots[0] / candidate
        try:
            checked = canonicalize_authorized_path(candidate, self.roots, cwd=cwd, must_exist=must_exist, reject_unc=True)
        except PathAuthorizationError as exc:
            raise PermissionError(str(exc)) from exc
        # Reparse/symlink escapes are caught above. For writes, reject a
        # symlinked final target even when its target remains inside the root.
        effective_candidate = candidate
        if not effective_candidate.is_absolute():
            base = Path(cwd).expanduser() if cwd is not None else self.roots[0]
            if not base.is_absolute():
                base = self.roots[0] / base
            effective_candidate = base / effective_candidate
        if for_write:
            _reject_link_or_reparse_traversal(effective_candidate, checked.root)
        protected = protected_path_reason(checked.resolved, self.roots)
        if protected:
            raise PermissionError(protected)
        return checked

    def _revalidate(self, checked: AuthorizedPath, *, must_exist: bool | None = None) -> Path:
        """Re-resolve immediately before an operation that can observe or write."""
        return checked.revalidate(self.roots, must_exist=must_exist, reject_unc=True).resolved

    def _result(self, name: str, args: dict[str, Any], cwd: str | None = None) -> ToolResult:
        return timed_result(name, new_action_id(name, args), cwd)

    def list(self, path: str = ".", recursive: bool = False) -> ToolResult:
        args = {"path": path, "recursive": recursive}
        result = self._result("fs.list", args)
        try:
            checked = self.resolve_authorized(path, must_exist=True)
            target = self._revalidate(checked, must_exist=True)
            if not target.is_dir():
                raise NotADirectoryError(str(target))
            iterator = target.rglob("*") if recursive else target.iterdir()
            rows: list[dict[str, Any]] = []
            for child in iterator:
                try:
                    if protected_path_reason(child, self.roots):
                        continue
                    # Re-validate every discovered entry so a symlink/junction
                    # cannot make a read/list operation cross the root.
                    child_checked = self.resolve_authorized(child, must_exist=True)
                    self._revalidate(child_checked, must_exist=True)
                    st = child.stat()
                    rows.append({"path": str(child), "name": child.name, "is_dir": child.is_dir(), "size": st.st_size, "mtime": st.st_mtime, "symlink": child.is_symlink()})
                except OSError as exc:
                    rows.append({"path": str(child), "error": str(exc)})
                if len(rows) >= 2_000:
                    result.truncated = True
                    break
            rows.sort(key=lambda item: str(item.get("path", "")).lower())
            result.stdout = _json(rows)
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def stat(self, path: str) -> ToolResult:
        result = self._result("fs.stat", {"path": path})
        try:
            checked = self.resolve_authorized(path, must_exist=True)
            target = self._revalidate(checked, must_exist=True)
            st = target.stat()
            result.stdout = _json({"path": str(target), "is_dir": target.is_dir(), "is_file": target.is_file(), "size": st.st_size, "mtime": st.st_mtime, "mode": st.st_mode, "sha256": _sha256(target) if target.is_file() and st.st_size <= self.max_read_bytes else None})
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def read(self, path: str, start_line: int = 1, end_line: int | None = None) -> ToolResult:
        args = {"path": path, "start_line": start_line, "end_line": end_line}
        result = self._result("fs.read", args)
        try:
            if start_line < 1 or (end_line is not None and end_line < start_line):
                raise ValueError("invalid line range")
            checked = self.resolve_authorized(path, must_exist=True)
            target = self._revalidate(checked, must_exist=True)
            if not target.is_file():
                raise IsADirectoryError(str(target))
            if target.stat().st_size > self.max_read_bytes:
                raise ValueError(f"file exceeds read limit ({self.max_read_bytes} bytes)")
            raw = target.read_bytes()
            encoding = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
            text = raw.decode(encoding)
            lines = text.splitlines(keepends=True)
            selected = lines[start_line - 1 : end_line]
            result.stdout = "".join(f"{i + start_line}: {line}" for i, line in enumerate(selected))
            result.metadata["encoding"] = encoding
            result.metadata["newline"] = "CRLF" if "\r\n" in text else "LF"
        except UnicodeDecodeError:
            result.status, result.error = "failed", "file is not UTF-8 text"
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def search(self, pattern: str, path: str = ".", max_results: int = 100) -> ToolResult:
        args = {"pattern": pattern, "path": path, "max_results": max_results}
        result = self._result("fs.search", args)
        try:
            max_results = max(1, min(int(max_results), 1_000))
            if not pattern or len(pattern) > 500 or "\x00" in pattern:
                raise ValueError("pattern must be 1..500 characters")
            checked = self.resolve_authorized(path, must_exist=True)
            target = self._revalidate(checked, must_exist=True)
            if not target.is_dir():
                target = target.parent
            rg = _trusted_rg()
            if rg:
                completed = subprocess.run([rg, "--no-config", "--no-heading", "--line-number", "--color", "never", "--no-follow", "--glob", "!.astercode/**", "--glob", "!.git/**", "--glob", "!.env", "--glob", "!.env.*", "--max-count", str(max_results), "--", pattern, str(target)], cwd=str(target), capture_output=True, text=True, timeout=30, check=False)
                lines = completed.stdout.splitlines()
                if len(lines) > max_results:
                    result.truncated = True
                    lines = lines[:max_results]
                result.stdout, result.stderr, result.exit_code = "\n".join(lines), completed.stderr, completed.returncode
            else:
                hits: list[str] = []
                for file in target.rglob("*"):
                    if file.is_symlink() or protected_path_reason(file, self.roots) or not file.is_file() or ".venv" in file.parts:
                        continue
                    try:
                        checked_file = self.resolve_authorized(file, must_exist=True)
                        self._revalidate(checked_file, must_exist=True)
                        for idx, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
                            # The no-rg fallback deliberately uses literal
                            # matching: Python regex backtracking cannot be
                            # safely time-limited in this worker.
                            if pattern in line:
                                hits.append(f"{file}:{idx}:{line}")
                                if len(hits) >= max_results:
                                    break
                    except (OSError, UnicodeDecodeError):
                        continue
                    if len(hits) >= max_results:
                        break
                result.stdout = "\n".join(hits)
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def apply_patch(self, patch: str, cwd: str = ".") -> ToolResult:
        result = self._result("fs.apply_patch", {"patch": patch, "cwd": cwd})
        prepared: list[tuple[Path, AuthorizedPath, str, str, str, bool]] = []
        written_targets: list[tuple[Path, str, str, bool]] = []
        try:
            if not patch.strip():
                raise ValueError("empty patch")
            changes = parse_patch(patch)
            if not changes:
                raise ValueError(
                    "unsupported patch format; use *** Begin Patch with "
                    "*** Add File or *** Update File sections, not ---/+++ headers"
                )
            # Preflight every section first.  A later context mismatch must
            # not leave earlier sections partially applied.
            for path_text, old, new in changes:
                checked = self.resolve_authorized(path_text, for_write=True, cwd=cwd)
                target = self._revalidate(checked, must_exist=checked.exists)
                raw_existing = target.read_bytes() if target.exists() else b""
                self._revalidate(checked, must_exist=checked.exists)
                encoding = "utf-8-sig" if raw_existing.startswith(b"\xef\xbb\xbf") else "utf-8"
                existing = raw_existing.decode(encoding) if raw_existing else ""
                match_existing = existing.replace("\r\n", "\n")
                if old is not None:
                    old_normalized = old.replace("\r\n", "\n")
                    new_normalized = new.replace("\r\n", "\n")
                    if old_normalized not in match_existing:
                        raise ValueError(f"patch context does not match: {path_text}")
                    updated = match_existing.replace(old_normalized, new_normalized, 1)
                else:
                    if target.exists():
                        raise FileExistsError(f"add patch target already exists: {path_text}")
                    updated = new
                prepared.append((target, checked, updated, existing, encoding, target.exists()))

            written: list[str] = []
            for target, checked, updated, existing, encoding, existed in prepared:
                self._revalidate(checked, must_exist=existed)
                _atomic_text_write(
                    target,
                    updated,
                    existing,
                    encoding=encoding,
                    replace_existing=existed,
                )
                written_targets.append((target, existing, encoding, existed))
                written.append(str(target))
            result.stdout = _json({"written": written})
            result.side_effects = ["file_write"]
        except Exception as exc:
            # Best-effort rollback of sections already written in this patch;
            # any rollback failure is surfaced instead of being hidden.
            rollback_errors: list[str] = []
            for target, previous, encoding, existed in reversed(written_targets):
                try:
                    if existed:
                        _atomic_text_write(target, previous, previous, encoding=encoding)
                    else:
                        target.unlink(missing_ok=True)
                except OSError as rollback_exc:
                    rollback_errors.append(type(rollback_exc).__name__)
            result.status, result.error = "failed", str(exc)
            if rollback_errors:
                result.error = f"{result.error}; rollback failed ({', '.join(rollback_errors)})"
        return result.finish()

    def mkdir(self, path: str) -> ToolResult:
        result = self._result("fs.mkdir", {"path": path})
        try:
            checked = self.resolve_authorized(path, for_write=True)
            target = self._revalidate(checked, must_exist=checked.exists)
            target.mkdir(parents=True, exist_ok=False)
            result.stdout = str(target)
            result.side_effects = ["directory_create"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def move(self, source: str, destination: str) -> ToolResult:
        result = self._result("fs.move", {"source": source, "destination": destination})
        try:
            src_checked = self.resolve_authorized(source, must_exist=True, for_write=True)
            dst_checked = self.resolve_authorized(destination, for_write=True)
            src = self._revalidate(src_checked, must_exist=True)
            dst = self._revalidate(dst_checked, must_exist=False)
            if any(src == root for root in self.roots):
                raise PermissionError("refusing to move an authorized root")
            if dst.exists():
                raise FileExistsError(str(dst))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            result.stdout = _json({"source": str(src), "destination": str(dst)})
            result.side_effects = ["path_move"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()

    def delete(self, path: str, recursive: bool = False) -> ToolResult:
        result = self._result("fs.delete", {"path": path, "recursive": recursive})
        try:
            checked = self.resolve_authorized(path, must_exist=True, for_write=True)
            target = self._revalidate(checked, must_exist=True)
            if any(target == root for root in self.roots):
                raise PermissionError("refusing to delete authorized root")
            if target.is_symlink():
                raise PermissionError("refusing to delete through a symlink")
            if target.is_dir():
                if not recursive:
                    target.rmdir()
                else:
                    for child in target.rglob("*"):
                        is_junction = getattr(child, "is_junction", lambda: False)()
                        if child.is_symlink() or is_junction:
                            raise PermissionError("recursive delete refuses symlink/junction descendants")
                    shutil.rmtree(target)
            else:
                target.unlink()
            result.stdout, result.side_effects = str(target), ["path_delete"]
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
        return result.finish()


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _reject_link_or_reparse_traversal(candidate: Path, root: Path) -> None:
    """Reject write targets whose lexical path crosses a redirecting entry.

    Resolving a junction that points back inside an authorized root is safe for
    reads, but it is ambiguous for writes: deleting ``link`` could otherwise
    delete the linked directory rather than the junction entry.  Walk the
    original lexical path and fail closed on symlinks, junctions, or any other
    Windows reparse point.  Missing suffixes are safe to stop at because they
    cannot yet redirect traversal.
    """

    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(root)
    except ValueError as exc:
        raise PermissionError("write path is not lexically inside the authorized root") from exc

    current = root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for part in relative.parts:
        current = current / part
        is_link = current.is_symlink()
        is_junction = bool(getattr(current, "is_junction", lambda: False)())
        is_reparse = False
        try:
            metadata = current.stat(follow_symlinks=False)
            attributes = int(getattr(metadata, "st_file_attributes", 0))
            is_reparse = bool(attributes & reparse_flag)
        except FileNotFoundError:
            if not is_link:
                break
        if is_link or is_junction or is_reparse:
            raise PermissionError(
                f"write path cannot traverse a link, junction, or reparse point: {current}"
            )


def _trusted_rg() -> str | None:
    """Locate only conventional system ripgrep installations.

    A repository/PATH-provided ``rg`` is not trusted because this operation is
    P0 read-only and must not become an executable-code primitive.
    """
    candidates: list[Path] = []
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                candidates.append(Path(base) / "ripgrep" / "rg.exe")
    else:
        candidates.extend([Path("/usr/bin/rg"), Path("/bin/rg"), Path("/usr/local/bin/rg")])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text_write(
    path: Path,
    text: str,
    previous: str,
    *,
    encoding: str = "utf-8",
    replace_existing: bool = True,
) -> None:
    newline = "\r\n" if "\r\n" in previous else "\n"
    if newline == "\r\n":
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    previous_stat = None
    try:
        if path.exists():
            previous_stat = path.stat()
    except OSError:
        previous_stat = None
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if previous_stat is not None:
            # Preserve executable/read-only bits and timestamps where the
            # platform permits it; content replacement remains atomic.
            try:
                os.chmod(temp_name, stat.S_IMODE(previous_stat.st_mode))
                shutil.copystat(path, temp_name, follow_symlinks=False)
            except OSError:
                os.chmod(temp_name, stat.S_IMODE(previous_stat.st_mode))
        if replace_existing:
            os.replace(temp_name, path)
        else:
            # Publish an Add patch without overwriting a file that appeared
            # after approval/preflight. The temp file is on the same volume,
            # so a hard-link publish is atomic and fails if ``path`` exists.
            os.link(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def parse_patch(patch: str) -> list[tuple[str, str | None, str]]:
    """Parse a deliberately small exact-replacement patch format.

    Supported sections are the familiar OpenAI-style `*** Update File:` with
    `-old`/`+new` lines and `*** Add File:`.  Context must match exactly.
    """
    lines = patch.splitlines()
    changes: list[tuple[str, str | None, str]] = []
    current: str | None = None
    old_lines: list[str] = []
    new_lines: list[str] = []
    mode: str | None = None

    def flush() -> None:
        nonlocal current, old_lines, new_lines, mode
        if current is None:
            return
        if mode == "add":
            changes.append((current, None, "\n".join(new_lines) + ("\n" if new_lines else "")))
        else:
            old = "\n".join(old_lines) + ("\n" if old_lines else "")
            new = "\n".join(new_lines) + ("\n" if new_lines else "")
            changes.append((current, old, new))
        current, old_lines, new_lines, mode = None, [], [], None

    for line in lines:
        if line.startswith("*** Update File:"):
            flush(); current = line.split(":", 1)[1].strip(); mode = "update"
        elif line.startswith("*** Add File:"):
            flush(); current = line.split(":", 1)[1].strip(); mode = "add"
        elif line.startswith("*** Delete File:"):
            raise ValueError("delete sections must use fs.delete with its own approval")
        elif line == "*** End Patch":
            flush()
        elif current is not None:
            if mode == "delete":
                continue
            if line.startswith("-"):
                old_lines.append(line[1:])
            elif line.startswith("+"):
                new_lines.append(line[1:])
            elif line.startswith(" "):
                value = line[1:]; old_lines.append(value); new_lines.append(value)
    flush()
    return changes
