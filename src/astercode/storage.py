"""SQLite WAL persistence, migrations, checkpoints, memory and audit chain."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .config import StorageConfig
from .lock import InterProcessFileLock, WorkspaceWriteLock
from .models import ApprovalRequest, ApprovalStatus, CheckpointRecord, RiskLevel, SessionStatus, new_id, utc_now
from .security import GENESIS_AUDIT_HASH, audit_entry_hash, redact_secrets

SCHEMA_VERSION = 8


class MemoryConflictError(ValueError):
    """Raised when a memory proposal would silently overwrite newer state."""


class AuditIntegrityError(RuntimeError):
    """Raised when audit evidence cannot be safely appended or repaired."""


_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, workspace TEXT NOT NULL, goal TEXT NOT NULL,
    status TEXT NOT NULL, state_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS turns (
    turn_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    role TEXT NOT NULL, content_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id TEXT, role TEXT NOT NULL, content_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id TEXT, event_type TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id TEXT, phase TEXT NOT NULL, state_json TEXT NOT NULL,
    action_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_calls (
    call_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    turn_id TEXT, action_id TEXT NOT NULL, tool TEXT NOT NULL,
    arguments_json TEXT NOT NULL, result_json TEXT, status TEXT,
    created_at TEXT NOT NULL, ended_at TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY, action_id TEXT NOT NULL,
    request_json TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals(action_id, status);
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY, session_id TEXT, path TEXT NOT NULL,
    sha256 TEXT, size INTEGER NOT NULL, media_type TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_entries (
    memory_id TEXT PRIMARY KEY, namespace TEXT NOT NULL, content TEXT NOT NULL,
    source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    confidence REAL NOT NULL, ttl_at TEXT, tags_json TEXT NOT NULL,
    supersedes TEXT, sensitivity TEXT NOT NULL DEFAULT 'normal', deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_memory_namespace ON memory_entries(namespace, deleted, ttl_at);
CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(memory_id UNINDEXED, namespace, content, tags);
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id TEXT PRIMARY KEY, session_id TEXT, action_id TEXT,
    event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_flags (
    name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);
"""


def _execute_script(connection: sqlite3.Connection, script: str) -> None:
    """Execute our static migration SQL without sqlite3.executescript commits."""

    for statement in script.split(";"):
        if statement.strip():
            connection.execute(statement)


def _migration_1(connection: sqlite3.Connection) -> None:
    _execute_script(connection, _BASE_SCHEMA)


def _migration_2(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_hosts (
            host_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT NOT NULL, fingerprint TEXT NOT NULL, known_hosts TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )
        """
    )


def _migration_3(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_proposals (
            proposal_id TEXT PRIMARY KEY,
            operation TEXT NOT NULL CHECK(operation IN ('create', 'edit')),
            namespace TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
            created_at TEXT NOT NULL, confidence REAL NOT NULL, ttl_at TEXT,
            tags_json TEXT NOT NULL, supersedes TEXT, expected_updated_at TEXT,
            sensitivity TEXT NOT NULL, status TEXT NOT NULL,
            conflict_reason TEXT, committed_memory_id TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_proposals_status ON memory_proposals(status, created_at)"
    )
    audit_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'"
    ).fetchone()
    if audit_exists:
        for row in connection.execute(
            "SELECT payload_json, created_at FROM audit_log WHERE event_type='memory.propose' ORDER BY rowid"
        ).fetchall():
            try:
                payload = json.loads(row["payload_json"])
                proposal_id = str(payload["proposal_id"])
                connection.execute(
                    """
                    INSERT OR IGNORE INTO memory_proposals(
                        proposal_id, operation, namespace, content, source, created_at,
                        confidence, ttl_at, tags_json, supersedes, expected_updated_at,
                        sensitivity, status, conflict_reason, committed_memory_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL)
                    """,
                    (
                        proposal_id,
                        "edit" if payload.get("supersedes") else "create",
                        str(payload["namespace"]),
                        str(payload["content"]),
                        str(payload["source"]),
                        str(payload.get("created_at") or row["created_at"]),
                        float(payload.get("confidence", 0.8)),
                        payload.get("ttl_at"),
                        json.dumps(payload.get("tags", []), ensure_ascii=False, sort_keys=True),
                        payload.get("supersedes"),
                        payload.get("expected_updated_at"),
                        str(payload.get("sensitivity", "normal")),
                    ),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                # Corrupt audit data must not abort the schema upgrade.  It is
                # retained in the immutable audit table for manual inspection.
                continue
        for row in connection.execute(
            "SELECT payload_json FROM audit_log WHERE event_type='memory.commit' ORDER BY rowid"
        ).fetchall():
            try:
                payload = json.loads(row["payload_json"])
                connection.execute(
                    """
                    UPDATE memory_proposals SET status='committed', committed_memory_id=?
                    WHERE proposal_id=?
                    """,
                    (payload.get("memory_id"), payload["proposal_id"]),
                )
            except (KeyError, TypeError, json.JSONDecodeError):
                continue


def _migration_4(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(memory_entries)").fetchall()
    }
    if "superseded_by" not in columns:
        connection.execute("ALTER TABLE memory_entries ADD COLUMN superseded_by TEXT")
    if "conflict_status" not in columns:
        connection.execute(
            "ALTER TABLE memory_entries ADD COLUMN conflict_status TEXT NOT NULL DEFAULT 'none'"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_active ON memory_entries(namespace, deleted, superseded_by, ttl_at)"
    )


def _migration_5(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_processes (
            action_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            pid INTEGER NOT NULL,
            host TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'stopped', 'unknown')),
            created_at TEXT NOT NULL,
            stopped_at TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_runtime_processes_active ON runtime_processes(status, session_id)"
    )


def _migration_6(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(runtime_processes)").fetchall()
    }
    if "identity_token" not in columns:
        connection.execute("ALTER TABLE runtime_processes ADD COLUMN identity_token TEXT")
    if "argv_hash" not in columns:
        connection.execute("ALTER TABLE runtime_processes ADD COLUMN argv_hash TEXT")


def _migration_7(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_grants (
            grant_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            action_hash TEXT NOT NULL,
            tool TEXT NOT NULL,
            risk TEXT NOT NULL,
            request_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'expired')),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_approval_grants_match ON approval_grants(session_id, action_hash, status, expires_at)"
    )


def _migration_8(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(runtime_processes)").fetchall()
    }
    for name in ("backend_kind", "backend_ref", "backend_identity"):
        if name not in columns:
            connection.execute(f"ALTER TABLE runtime_processes ADD COLUMN {name} TEXT")
    # v7 did not persist enough backend evidence to distinguish a Docker
    # client from a generic local process.  Never claim those in-flight rows
    # can be safely recovered after upgrade.
    connection.execute(
        "UPDATE runtime_processes SET status='unknown', stopped_at=? WHERE status='active'",
        (utc_now().isoformat(),),
    )


_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migration_1,
    2: _migration_2,
    3: _migration_3,
    4: _migration_4,
    5: _migration_5,
    6: _migration_6,
    7: _migration_7,
    8: _migration_8,
}


# These are deliberately structural invariants, rather than a checksum of
# SQLite's generated SQL.  SQLite may render equivalent DDL differently across
# supported versions, while a missing table or column means the recorded
# migration version cannot be trusted.  Requirements are cumulative through
# the recorded schema version.
_CRITICAL_SCHEMA_BY_VERSION: dict[int, dict[str, frozenset[str]]] = {
    1: {
        "schema_migrations": frozenset({"version", "applied_at"}),
        "sessions": frozenset(
            {
                "session_id",
                "workspace",
                "goal",
                "status",
                "state_json",
                "created_at",
                "updated_at",
            }
        ),
        "turns": frozenset(
            {"turn_id", "session_id", "role", "content_json", "created_at"}
        ),
        "messages": frozenset(
            {
                "message_id",
                "session_id",
                "turn_id",
                "role",
                "content_json",
                "created_at",
            }
        ),
        "events": frozenset(
            {
                "event_id",
                "session_id",
                "turn_id",
                "event_type",
                "payload_json",
                "created_at",
            }
        ),
        "checkpoints": frozenset(
            {
                "checkpoint_id",
                "session_id",
                "turn_id",
                "phase",
                "state_json",
                "action_id",
                "created_at",
            }
        ),
        "tool_calls": frozenset(
            {
                "call_id",
                "session_id",
                "turn_id",
                "action_id",
                "tool",
                "arguments_json",
                "result_json",
                "status",
                "created_at",
                "ended_at",
            }
        ),
        "approvals": frozenset(
            {
                "approval_id",
                "action_id",
                "request_json",
                "status",
                "created_at",
                "expires_at",
                "consumed_at",
            }
        ),
        "artifacts": frozenset(
            {"artifact_id", "session_id", "path", "sha256", "size", "media_type", "created_at"}
        ),
        "memory_entries": frozenset(
            {
                "memory_id",
                "namespace",
                "content",
                "source",
                "created_at",
                "updated_at",
                "confidence",
                "ttl_at",
                "tags_json",
                "supersedes",
                "sensitivity",
                "deleted",
            }
        ),
        "memory_fts": frozenset({"memory_id", "namespace", "content", "tags"}),
        "audit_log": frozenset(
            {
                "audit_id",
                "session_id",
                "action_id",
                "event_type",
                "payload_json",
                "previous_hash",
                "entry_hash",
                "created_at",
            }
        ),
        "runtime_flags": frozenset({"name", "value", "updated_at"}),
    },
    2: {
        "ssh_hosts": frozenset(
            {
                "host_id",
                "hostname",
                "port",
                "username",
                "fingerprint",
                "known_hosts",
                "created_at",
                "updated_at",
            }
        )
    },
    3: {
        "memory_proposals": frozenset(
            {
                "proposal_id",
                "operation",
                "namespace",
                "content",
                "source",
                "created_at",
                "confidence",
                "ttl_at",
                "tags_json",
                "supersedes",
                "expected_updated_at",
                "sensitivity",
                "status",
                "conflict_reason",
                "committed_memory_id",
            }
        )
    },
    4: {"memory_entries": frozenset({"superseded_by", "conflict_status"})},
    5: {
        "runtime_processes": frozenset(
            {
                "action_id",
                "session_id",
                "pid",
                "host",
                "status",
                "created_at",
                "stopped_at",
            }
        )
    },
    6: {"runtime_processes": frozenset({"identity_token", "argv_hash"})},
    7: {
        "approval_grants": frozenset(
            {
                "grant_id",
                "session_id",
                "action_hash",
                "tool",
                "risk",
                "request_json",
                "status",
                "created_at",
                "expires_at",
                "revoked_at",
            }
        )
    },
    8: {
        "runtime_processes": frozenset(
            {"backend_kind", "backend_ref", "backend_identity"}
        )
    },
}


class Storage:
    """A small thread-safe SQLite repository with explicit migrations.

    Raw model messages are never written directly: all JSON payloads pass
    through secret redaction before persistence and audit logging.
    """

    def __init__(self, config: StorageConfig) -> None:
        self.config = config
        self._lock = threading.RLock()
        self._initialized = False
        self.last_migration_backup: Path | None = None

    @staticmethod
    def _guard_local_state_path(
        path: Path,
        *,
        expected: str,
    ) -> None:
        """Reject linked/reparsed state paths before any read or write.

        Hard-linked files are rejected because writing the in-workspace name
        would also mutate a second name outside the workspace.  This is a
        pre-open guard; callers invoke it again at each persistent I/O boundary.
        """

        candidate = Path(os.path.abspath(path))
        for parent in reversed(candidate.parents):
            is_junction = bool(getattr(parent, "is_junction", lambda: False)())
            if parent.is_symlink() or is_junction:
                raise RuntimeError(f"state parent cannot be a link or junction: {parent}")
            if parent.exists() and not parent.is_dir():
                raise RuntimeError(f"state parent is not a directory: {parent}")
        is_junction = bool(getattr(candidate, "is_junction", lambda: False)())
        if candidate.is_symlink() or is_junction:
            raise RuntimeError(f"state path cannot be a link or junction: {candidate}")
        try:
            info = candidate.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        if expected == "file" and not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"state path is not a regular file: {candidate}")
        if expected == "directory" and not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"state path is not a directory: {candidate}")
        if expected == "file" and info.st_nlink > 1:
            raise RuntimeError(f"state file cannot be hard-linked: {candidate}")

    def guard_sqlite_path(self, path: Path) -> None:
        """Guard a SQLite database and every sidecar SQLite may mutate."""

        self._guard_local_state_path(path, expected="file")
        for suffix in ("-journal", "-shm", "-wal"):
            self._guard_local_state_path(Path(f"{path}{suffix}"), expected="file")

    def guard_artifacts_dir(self) -> None:
        self._guard_local_state_path(
            self.config.artifacts_dir,
            expected="directory",
        )

    def _guard_storage_paths(self) -> None:
        self.guard_sqlite_path(self.config.database_path)
        self._guard_local_state_path(
            self.config.database_path.with_name(
                self.config.database_path.name + ".migrate.lock"
            ),
            expected="file",
        )
        self._guard_local_state_path(self.config.audit_jsonl_path, expected="file")
        self._guard_local_state_path(self._audit_lock_path, expected="file")
        self.guard_artifacts_dir()

    def _connect(self) -> sqlite3.Connection:
        self.guard_sqlite_path(self.config.database_path)
        self.config.database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.config.database_path), timeout=self.config.busy_timeout_ms / 1000, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.config.busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA wal_autocheckpoint={int(self.config.wal_autocheckpoint_pages)}")
        return conn

    @contextmanager
    def _connection(self):
        """Open, commit/rollback, and close one connection deterministically."""
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _inspect_schema(self, connection: sqlite3.Connection) -> tuple[int, bool]:
        """Validate migration evidence without changing persistent DB state.

        A recorded maximum version is not sufficient: a truncated or forged
        ``schema_migrations`` table could otherwise make initialization skip
        required DDL and fail much later during a user action.
        """

        rows = connection.execute(
            "SELECT name, type, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        objects = {str(row[0]): (str(row[1]), row[2]) for row in rows}
        if "schema_migrations" not in objects:
            if objects:
                raise RuntimeError(
                    "database contains unversioned objects; refusing to infer a schema version"
                )
            return 0, False

        migration_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(schema_migrations)").fetchall()
        }
        if not {"version", "applied_at"} <= migration_columns:
            raise RuntimeError("schema_migrations is missing critical columns")

        raw_versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        if not raw_versions:
            other_objects = set(objects) - {"schema_migrations"}
            if other_objects:
                raise RuntimeError(
                    "database has objects but no recorded schema migrations"
                )
            return 0, False

        versions = [int(row[0]) for row in raw_versions]
        version = versions[-1]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema v{version} is newer than supported v{SCHEMA_VERSION}"
            )
        expected_versions = list(range(1, version + 1))
        if versions != expected_versions:
            raise RuntimeError(
                "schema migration history is not continuous: "
                f"expected {expected_versions}, found {versions}"
            )

        required: dict[str, set[str]] = {}
        for target in range(1, version + 1):
            for table, introduced_columns in _CRITICAL_SCHEMA_BY_VERSION[target].items():
                required.setdefault(table, set()).update(introduced_columns)
        for table, expected_columns in required.items():
            if table not in objects:
                raise RuntimeError(
                    f"database schema v{version} is missing critical table {table}"
                )
            actual_columns = {
                str(row[1])
                for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
            }
            missing = expected_columns - actual_columns
            if missing:
                raise RuntimeError(
                    f"database schema v{version} table {table} is missing critical columns: "
                    + ", ".join(sorted(missing))
                )

        memory_fts_sql = objects.get("memory_fts", ("", ""))[1]
        if version >= 1 and (
            not isinstance(memory_fts_sql, str)
            or "VIRTUAL TABLE" not in memory_fts_sql.upper()
            or "USING FTS5" not in memory_fts_sql.upper()
        ):
            raise RuntimeError("database memory_fts is not the required FTS5 virtual table")

        return version, bool(set(objects) - {"schema_migrations"})

    def _inspect_existing_database(self) -> tuple[int, bool]:
        """Open an existing database read-only and run schema preflight."""

        path = self.config.database_path
        self.guard_sqlite_path(path)
        if not path.exists():
            return 0, False
        if not path.is_file():
            raise RuntimeError(f"database path is not a regular file: {path}")
        uri = path.resolve().as_uri() + "?mode=ro"
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self.config.busy_timeout_ms / 1000,
                check_same_thread=False,
            )
            try:
                return self._inspect_schema(connection)
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(f"database schema preflight failed: {exc}") from exc

    def initialize(self) -> None:
        if self._initialized:
            return
        self._guard_storage_paths()
        # The first check happens before the migration lock file or database
        # is touched.  This ensures an older binary cannot change a future or
        # structurally invalid database merely by attempting to start.
        self._inspect_existing_database()
        migration_lock = InterProcessFileLock(
            self.config.database_path.with_name(self.config.database_path.name + ".migrate.lock")
        )
        with self._lock, migration_lock.held(
            timeout_seconds=max(1.0, self.config.busy_timeout_ms / 1000)
        ):
            # Another process may have created or migrated the database while
            # this process waited for the lock.  Revalidate under the lock.
            self._inspect_existing_database()
            with self._connection() as conn:
                version, has_existing_data = self._inspect_schema(conn)
                # WAL is persistent database state; setting it once during
                # initialization avoids an expensive lock negotiation on
                # every short-lived repository connection.
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                )
                conn.commit()
                if version < SCHEMA_VERSION and has_existing_data:
                    self.last_migration_backup = self._backup_database(conn, version)
                for target in range(version + 1, SCHEMA_VERSION + 1):
                    migration = _MIGRATIONS[target]
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        migration(conn)
                        conn.execute(
                            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                            (target, utc_now().isoformat()),
                        )
                        conn.execute(f"PRAGMA user_version={target}")
                        conn.commit()
                    except BaseException:
                        conn.rollback()
                        raise
            self._initialized = True

    def _backup_database(self, connection: sqlite3.Connection, from_version: int) -> Path:
        """Create a transactionally consistent SQLite backup before upgrade."""

        backup_dir = self.config.database_path.parent / "backups"
        self._guard_local_state_path(backup_dir, expected="directory")
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
        backup = backup_dir / (
            f"{self.config.database_path.stem}.v{from_version}-to-v{SCHEMA_VERSION}.{stamp}.db"
        )
        destination = sqlite3.connect(str(backup))
        try:
            connection.backup(destination)
            integrity = destination.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                raise RuntimeError("migration backup failed SQLite integrity_check")
            destination.commit()
        except BaseException:
            destination.close()
            backup.unlink(missing_ok=True)
            raise
        finally:
            try:
                destination.close()
            except sqlite3.Error:
                pass
        return backup

    @contextmanager
    def workspace_write_lock(
        self, workspace: str | Path, *, timeout_seconds: float = 30.0
    ) -> Iterator[None]:
        """Serialize write-capable sessions that share one workspace."""

        lock = WorkspaceWriteLock(Path(workspace))
        with lock.held(timeout_seconds):
            yield

    def _ensure(self) -> None:
        if not self._initialized:
            self.initialize()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(redact_secrets(value), ensure_ascii=False, sort_keys=True, default=str)

    def create_session(self, workspace: str, goal: str, session_id: str | None = None) -> dict[str, Any]:
        self._ensure(); sid = session_id or new_id("session"); now = utc_now().isoformat(); goal = str(redact_secrets(goal))
        with self._lock, self._connection() as conn:
            conn.execute("INSERT INTO sessions(session_id, workspace, goal, status, state_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (sid, workspace, goal, SessionStatus.CREATED.value, "{}", now, now))
        return self.get_session(sid)

    def update_session(self, session_id: str, *, status: str | SessionStatus | None = None, state: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._ensure(); current = self.get_session(session_id)
        new_status = status.value if isinstance(status, SessionStatus) else (status or current["status"])
        state_json = self._json(state if state is not None else current.get("state", {})); now = utc_now().isoformat()
        with self._lock, self._connection() as conn:
            conn.execute("UPDATE sessions SET status=?, state_json=?, updated_at=? WHERE session_id=?", (new_status, state_json, now, session_id))
        return self.get_session(session_id)

    def get_session(self, session_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown session: {session_id}")
        result = dict(row); result["state"] = json.loads(result.pop("state_json") or "{}")
        return result

    def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        self._ensure()
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT session_id, workspace, goal, status, created_at, updated_at FROM sessions ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [dict(row) for row in rows]

    def delete_session(self, session_id: str) -> None:
        self._ensure()
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        self.append_audit(event_type="session.delete", payload={"session_id": session_id})

    def save_turn(self, session_id: str, role: str, content: Any, turn_id: str | None = None) -> str:
        self._ensure(); tid = turn_id or new_id("turn")
        with self._lock, self._connection() as conn:
            conn.execute("INSERT INTO turns(turn_id, session_id, role, content_json, created_at) VALUES (?, ?, ?, ?, ?)", (tid, session_id, role, self._json(content), utc_now().isoformat()))
            conn.execute("INSERT INTO messages(message_id, session_id, turn_id, role, content_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", (new_id("message"), session_id, tid, role, self._json(content), utc_now().isoformat()))
        return tid

    def save_tool_call(self, session_id: str, call_id: str, action_id: str, tool: str, arguments: Any, *, turn_id: str | None = None, result: Any | None = None, status: str | None = None, ended_at: str | None = None) -> None:
        self._ensure()
        with self._lock, self._connection() as conn:
            conn.execute("INSERT OR REPLACE INTO tool_calls(call_id, session_id, turn_id, action_id, tool, arguments_json, result_json, status, created_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (call_id, session_id, turn_id, action_id, tool, self._json(arguments), self._json(result) if result is not None else None, status, utc_now().isoformat(), ended_at))

    def save_artifact(self, session_id: str | None, path: str, size: int, sha256: str, media_type: str = "text/plain") -> str:
        self._ensure()
        artifact_id = new_id("artifact")
        with self._lock, self._connection() as conn:
            conn.execute("INSERT INTO artifacts(artifact_id, session_id, path, sha256, size, media_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (artifact_id, session_id, path, sha256, size, media_type, utc_now().isoformat()))
        return artifact_id

    def register_process(
        self,
        action_id: str,
        session_id: str,
        pid: int,
        host: str = "local",
        created_at: str | None = None,
        identity_token: str | None = None,
        argv_hash: str | None = None,
        backend_kind: str | None = None,
        backend_ref: str | None = None,
        backend_identity: str | None = None,
    ) -> dict[str, Any]:
        """Persist the identity of an agent-created long-running process."""

        self._ensure()
        if pid <= 0:
            raise ValueError("process PID must be positive")
        timestamp = created_at or utc_now().isoformat()
        with self._lock, self._connection() as conn:
            existing = conn.execute(
                "SELECT * FROM runtime_processes WHERE action_id=?", (action_id,)
            ).fetchone()
            if existing is not None and (
                int(existing["pid"]) != pid
                or str(existing["session_id"]) != session_id
                or str(existing["host"]) != host
                or existing["identity_token"] != identity_token
                or existing["argv_hash"] != argv_hash
                or existing["backend_kind"] != backend_kind
                or existing["backend_ref"] != backend_ref
                or existing["backend_identity"] != backend_identity
            ):
                raise ValueError("action_id is already bound to a different process")
            if existing is not None:
                return dict(existing)
            conn.execute(
                """
                INSERT INTO runtime_processes(
                    action_id, session_id, pid, host, status, created_at, stopped_at,
                    identity_token, argv_hash, backend_kind, backend_ref,
                    backend_identity
                ) VALUES (?, ?, ?, ?, 'active', ?, NULL, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    session_id,
                    pid,
                    host,
                    timestamp,
                    identity_token,
                    argv_hash,
                    backend_kind,
                    backend_ref,
                    backend_identity,
                ),
            )
            row = conn.execute(
                "SELECT * FROM runtime_processes WHERE action_id=?", (action_id,)
            ).fetchone()
        assert row is not None
        return dict(row)

    def mark_process_stopped(
        self, action_id: str, *, status: str = "stopped"
    ) -> dict[str, Any]:
        """Mark a registered process stopped, or unknown after failed reconcile."""

        self._ensure()
        if status not in {"stopped", "unknown"}:
            raise ValueError("process terminal status must be stopped or unknown")
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "UPDATE runtime_processes SET status=?, stopped_at=? WHERE action_id=?",
                (status, utc_now().isoformat(), action_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"unknown process action: {action_id}")
            row = conn.execute(
                "SELECT * FROM runtime_processes WHERE action_id=?", (action_id,)
            ).fetchone()
        assert row is not None
        return dict(row)

    def list_active_processes(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """List persisted process identities requiring stop/reconcile."""

        self._ensure()
        query = "SELECT * FROM runtime_processes WHERE status='active'"
        params: tuple[str, ...] = ()
        if session_id is not None:
            query += " AND session_id=?"
            params = (session_id,)
        query += " ORDER BY created_at ASC"
        with self._lock, self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def save_event(self, session_id: str, event_type: str, payload: Any, turn_id: str | None = None) -> str:
        self._ensure(); eid = new_id("event")
        with self._lock, self._connection() as conn:
            conn.execute("INSERT INTO events(event_id, session_id, turn_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", (eid, session_id, turn_id, event_type, self._json(payload), utc_now().isoformat()))
        self.append_audit(session_id=session_id, event_type=event_type, payload=payload)
        return eid

    def save_checkpoint(self, record: CheckpointRecord | Mapping[str, Any], *, session_id: str | None = None, phase: str | None = None, state: Mapping[str, Any] | None = None, action_id: str | None = None, turn_id: str | None = None) -> str:
        self._ensure()
        if isinstance(record, CheckpointRecord):
            item = record
        else:
            item = CheckpointRecord(session_id=session_id or str(record.get("session_id")), turn_id=turn_id or record.get("turn_id"), phase=phase or str(record.get("phase", "CHECKPOINT")), state=dict(state or record.get("state", {})), action_id=action_id or record.get("action_id"))
        with self._lock, self._connection() as conn:
            conn.execute("INSERT INTO checkpoints(checkpoint_id, session_id, turn_id, phase, state_json, action_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (item.checkpoint_id, item.session_id, item.turn_id, item.phase, self._json(item.state), item.action_id, item.created_at.isoformat()))
        return item.checkpoint_id

    def latest_checkpoint(self, session_id: str) -> dict[str, Any] | None:
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM checkpoints WHERE session_id=? ORDER BY created_at DESC LIMIT 1", (session_id,)).fetchone()
        if row is None: return None
        result = dict(row); result["state"] = json.loads(result.pop("state_json")); return result

    def list_subagent_reservations(self, parent_session_id: str) -> list[dict[str, Any]]:
        """Recover unique delegated grants without relying on SQLite JSON1.

        A recovered reservation is conservatively charged at its full budget.
        This is intentionally safe even when a crash happened after child
        completion but before the parent captured the child's actual usage.
        """

        self._ensure()
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT checkpoint_id, session_id, state_json, created_at "
                "FROM checkpoints WHERE phase='SUBAGENT_RESERVED' "
                "ORDER BY created_at ASC"
            ).fetchall()
        unique: dict[str, dict[str, Any]] = {}
        for row in rows:
            state = json.loads(str(row["state_json"]) or "{}")
            if not isinstance(state, Mapping):
                continue
            if state.get("parent_session_id") != parent_session_id:
                continue
            grant_id = state.get("grant_id")
            budget = state.get("budget")
            if not isinstance(grant_id, str) or not isinstance(budget, Mapping):
                continue
            unique.setdefault(
                grant_id,
                {
                    "grant_id": grant_id,
                    "child_session_id": str(row["session_id"]),
                    "checkpoint_id": str(row["checkpoint_id"]),
                    "budget": dict(budget),
                    "created_at": str(row["created_at"]),
                },
            )
        return list(unique.values())

    def list_events(self, session_id: str, limit: int = 200) -> list[dict[str, Any]]:
        self._ensure()
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM events WHERE session_id=? ORDER BY created_at ASC LIMIT ?", (session_id, max(1, min(limit, 10_000)))).fetchall()
        output = []
        for row in rows:
            item = dict(row); item["payload"] = json.loads(item.pop("payload_json")); output.append(item)
        return output

    def save_approval(self, request: ApprovalRequest | Mapping[str, Any]) -> dict[str, Any]:
        self._ensure(); item = request if isinstance(request, ApprovalRequest) else ApprovalRequest.model_validate(request)
        with self._lock, self._connection() as conn:
            existing = conn.execute("SELECT status FROM approvals WHERE approval_id=?", (item.approval_id,)).fetchone()
            # A consumed nonce is permanently spent.  Never let a retry or a
            # crash-recovery path replace it with a fresh pending row.
            if existing is not None and existing[0] == ApprovalStatus.CONSUMED.value:
                return self.get_approval(item.approval_id)
            conn.execute("INSERT OR REPLACE INTO approvals(approval_id, action_id, request_json, status, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, NULL)", (item.approval_id, item.action_id, self._json(item.model_dump(mode="json")), item.status.value, item.created_at.isoformat(), item.expires_at.isoformat()))
        self.append_audit(
            action_id=item.action_id,
            event_type="approval.requested",
            payload={
                "approval_id": item.approval_id,
                "tool": item.tool,
                "risk": item.risk.value,
                "action_hash": item.action_hash,
                "expires_at": item.expires_at.isoformat(),
            },
        )
        return item.model_dump(mode="json")

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if row is None: raise KeyError(f"unknown approval: {approval_id}")
        request = json.loads(row["request_json"]); request["status"] = row["status"]; request["consumed_at"] = row["consumed_at"]; return request

    def update_approval_status(self, approval_id: str, status: ApprovalStatus) -> dict[str, Any]:
        self._ensure(); consumed = utc_now().isoformat() if status is ApprovalStatus.CONSUMED else None
        with self._lock, self._connection() as conn:
            current = conn.execute("SELECT status, action_id FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            if current is None:
                raise KeyError(f"unknown approval: {approval_id}")
            current_status = str(current["status"])
            action_id = str(current["action_id"])
            if current_status == ApprovalStatus.CONSUMED.value and status is not ApprovalStatus.CONSUMED:
                raise ValueError("a consumed approval cannot be reopened")
            if current_status == ApprovalStatus.DENIED.value and status not in {ApprovalStatus.DENIED, ApprovalStatus.CONSUMED}:
                raise ValueError("a denied approval cannot be reopened")
            conn.execute("UPDATE approvals SET status=?, consumed_at=? WHERE approval_id=?", (status.value, consumed, approval_id))
        self.append_audit(
            action_id=action_id,
            event_type="approval.status",
            payload={"approval_id": approval_id, "status": status.value},
        )
        return self.get_approval(approval_id)

    def get_approval_by_action(self, action_id: str) -> dict[str, Any] | None:
        """Return the latest persisted request for an exact action binding."""
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT approval_id FROM approvals WHERE action_id=? ORDER BY created_at DESC LIMIT 1", (action_id,)).fetchone()
        if row is None:
            return None
        return self.get_approval(str(row[0]))

    def revoke_approval(self, approval_id: str) -> dict[str, Any]:
        """Revoke a pending/approved request without reopening spent nonces."""
        self._ensure()
        current = self.get_approval(approval_id)
        if current["status"] == ApprovalStatus.CONSUMED.value:
            raise ValueError("a consumed approval cannot be revoked")
        if current["status"] in {ApprovalStatus.DENIED.value, ApprovalStatus.REVOKED.value}:
            return current
        return self.update_approval_status(approval_id, ApprovalStatus.REVOKED)

    def save_session_grant(self, session_id: str, request: ApprovalRequest) -> dict[str, Any]:
        """Persist a session-scoped grant for this exact normalized action hash."""

        self._ensure()
        if request.risk not in {RiskLevel.P1, RiskLevel.P2}:
            raise ValueError("session grants are limited to P1/P2 actions")
        self.get_session(session_id)
        grant_id = new_id("grant")
        now = utc_now().isoformat()
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO approval_grants(
                    grant_id, session_id, action_hash, tool, risk, request_json,
                    status, created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL)
                """,
                (
                    grant_id,
                    session_id,
                    request.action_hash,
                    request.tool,
                    request.risk.value,
                    self._json(request.model_dump(mode="json")),
                    now,
                    request.expires_at.isoformat(),
                ),
            )
        self.append_audit(
            session_id=session_id,
            action_id=request.action_id,
            event_type="approval.session_grant",
            payload={"grant_id": grant_id, "tool": request.tool, "risk": request.risk.value, "action_hash": request.action_hash, "expires_at": request.expires_at.isoformat()},
        )
        return self.get_session_grant(grant_id)

    def get_session_grant(self, grant_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM approval_grants WHERE grant_id=?", (grant_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown approval grant: {grant_id}")
        item = dict(row)
        item["request"] = json.loads(item.pop("request_json"))
        return item

    def find_session_grant(self, session_id: str, action_hash_value: str) -> dict[str, Any] | None:
        self._ensure()
        now = utc_now().isoformat()
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE approval_grants SET status='expired' WHERE status='active' AND expires_at<=?",
                (now,),
            )
            row = conn.execute(
                """
                SELECT grant_id FROM approval_grants
                WHERE session_id=? AND action_hash=? AND status='active' AND expires_at>?
                ORDER BY created_at DESC LIMIT 1
                """,
                (session_id, action_hash_value, now),
            ).fetchone()
        return None if row is None else self.get_session_grant(str(row[0]))

    def list_session_grants(self, session_id: str | None = None) -> list[dict[str, Any]]:
        self._ensure()
        query = "SELECT grant_id FROM approval_grants"
        params: tuple[str, ...] = ()
        if session_id is not None:
            query += " WHERE session_id=?"
            params = (session_id,)
        query += " ORDER BY created_at DESC"
        with self._lock, self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self.get_session_grant(str(row[0])) for row in rows]

    def revoke_session_grant(self, grant_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "UPDATE approval_grants SET status='revoked', revoked_at=? WHERE grant_id=? AND status='active'",
                (utc_now().isoformat(), grant_id),
            )
            if cursor.rowcount == 0:
                current = conn.execute("SELECT 1 FROM approval_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if current is None:
                    raise KeyError(f"unknown approval grant: {grant_id}")
        result = self.get_session_grant(grant_id)
        self.append_audit(
            session_id=str(result["session_id"]),
            event_type="approval.session_grant_revoked",
            payload={"grant_id": grant_id},
        )
        return result

    @property
    def _audit_lock_path(self) -> Path:
        return self.config.database_path.with_name(self.config.database_path.name + ".audit.lock")

    @staticmethod
    def _audit_record_from_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = json.loads(str(row["payload_json"]))
        return {
            "audit_id": str(row["audit_id"]),
            "session_id": row["session_id"],
            "action_id": row["action_id"],
            "event_type": str(row["event_type"]),
            "payload": payload,
            "previous_hash": str(row["previous_hash"]),
            "entry_hash": str(row["entry_hash"]),
            "created_at": str(row["created_at"]),
        }

    def _database_audit_records_locked(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY rowid ASC").fetchall()
        try:
            return [self._audit_record_from_row(row) for row in rows]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(
                f"invalid database audit row ({type(exc).__name__})"
            ) from exc

    def _jsonl_audit_records_locked(self) -> list[dict[str, Any]]:
        path = self.config.audit_jsonl_path
        self._guard_local_state_path(path, expected="file")
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise TypeError("audit JSONL entries must be objects")
                records.append(item)
        except (OSError, UnicodeError, TypeError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(
                f"invalid audit JSONL ({type(exc).__name__})"
            ) from exc
        return records

    @staticmethod
    def _validate_audit_record(record: Mapping[str, Any]) -> None:
        expected_keys = {
            "audit_id",
            "session_id",
            "action_id",
            "event_type",
            "payload",
            "previous_hash",
            "entry_hash",
            "created_at",
        }
        if set(record) != expected_keys:
            raise AuditIntegrityError("audit record fields do not match the schema")
        payload = record["payload"]
        try:
            expected = audit_entry_hash(
                previous_hash=str(record["previous_hash"]),
                audit_id=str(record["audit_id"]),
                event_type=str(record["event_type"]),
                payload=payload if isinstance(payload, Mapping) else {"value": payload},
                created_at=datetime.fromisoformat(str(record["created_at"])),
                session_id=record["session_id"],
                action_id=record["action_id"],
            )
        except (TypeError, ValueError) as exc:
            raise AuditIntegrityError(
                f"invalid audit record ({type(exc).__name__})"
            ) from exc
        if str(record["entry_hash"]) != expected:
            raise AuditIntegrityError("audit entry hash mismatch")

    @classmethod
    def _logical_audit_chain(
        cls, records: list[dict[str, Any]], *, label: str
    ) -> list[dict[str, Any]]:
        """Rebuild the one permitted chain from hashes, independent of file order."""

        by_id: dict[str, dict[str, Any]] = {}
        by_hash: dict[str, dict[str, Any]] = {}
        by_previous: dict[str, dict[str, Any]] = {}
        for record in records:
            cls._validate_audit_record(record)
            audit_id = str(record["audit_id"])
            entry_hash = str(record["entry_hash"])
            previous_hash = str(record["previous_hash"])
            if audit_id in by_id:
                raise AuditIntegrityError(f"duplicate {label} audit_id")
            if entry_hash in by_hash:
                raise AuditIntegrityError(f"duplicate {label} entry_hash")
            if previous_hash in by_previous:
                raise AuditIntegrityError(f"branched {label} audit chain")
            by_id[audit_id] = record
            by_hash[entry_hash] = record
            by_previous[previous_hash] = record

        logical: list[dict[str, Any]] = []
        next_hash = GENESIS_AUDIT_HASH
        while next_hash in by_previous:
            record = by_previous[next_hash]
            logical.append(record)
            next_hash = str(record["entry_hash"])
        if len(logical) != len(records):
            raise AuditIntegrityError(f"disconnected or cyclic {label} audit chain")
        return logical

    def _append_audit_jsonl_locked(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        path = self.config.audit_jsonl_path
        self._guard_local_state_path(path, expected="file")
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = b"".join(
            (self._json(record) + "\n").encode("utf-8") for record in records
        )
        with path.open("ab") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())

    def _insert_audit_record_locked(
        self,
        *,
        event_type: str,
        payload: Any,
        session_id: str | None,
        action_id: str | None,
    ) -> dict[str, Any]:
        audit_id = new_id("audit")
        created = utc_now()
        safe_payload = redact_secrets(payload)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            previous = str(last[0]) if last else GENESIS_AUDIT_HASH
            digest = audit_entry_hash(
                previous_hash=previous,
                audit_id=audit_id,
                event_type=event_type,
                payload=(
                    safe_payload
                    if isinstance(safe_payload, Mapping)
                    else {"value": safe_payload}
                ),
                created_at=created,
                session_id=session_id,
                action_id=action_id,
            )
            conn.execute(
                "INSERT INTO audit_log(audit_id, session_id, action_id, event_type, payload_json, previous_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    audit_id,
                    session_id,
                    action_id,
                    event_type,
                    self._json(safe_payload),
                    previous,
                    digest,
                    created.isoformat(),
                ),
            )
        return {
            "audit_id": audit_id,
            "session_id": session_id,
            "action_id": action_id,
            "event_type": event_type,
            "payload": safe_payload,
            "previous_hash": previous,
            "entry_hash": digest,
            "created_at": created.isoformat(),
        }

    def append_audit(
        self,
        *,
        event_type: str,
        payload: Any,
        session_id: str | None = None,
        action_id: str | None = None,
    ) -> str:
        """Append one record while serializing the DB and durable mirror writes."""

        self._ensure()
        self._guard_local_state_path(self._audit_lock_path, expected="file")
        audit_lock = InterProcessFileLock(self._audit_lock_path)
        with self._lock, audit_lock.held(
            timeout_seconds=max(1.0, self.config.busy_timeout_ms / 1000)
        ):
            record = self._insert_audit_record_locked(
                event_type=event_type,
                payload=payload,
                session_id=session_id,
                action_id=action_id,
            )
            # SQLite is the authoritative ledger.  Commit it first so a crash
            # can only leave an append-only-repairable missing mirror record,
            # never an unauthoritative JSONL record that would need deletion.
            self._append_audit_jsonl_locked([record])
        return str(record["audit_id"])

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify SQLite and JSONL as one uniquely linked logical hash chain."""

        self._ensure()
        self._guard_local_state_path(self._audit_lock_path, expected="file")
        audit_lock = InterProcessFileLock(self._audit_lock_path)
        try:
            with self._lock, audit_lock.held(
                timeout_seconds=max(1.0, self.config.busy_timeout_ms / 1000)
            ):
                database_records = self._database_audit_records_locked()
                database_chain = self._logical_audit_chain(
                    database_records, label="database"
                )
                if [record["audit_id"] for record in database_chain] != [
                    record["audit_id"] for record in database_records
                ]:
                    raise AuditIntegrityError("database row order does not match its hash chain")

                jsonl_records = self._jsonl_audit_records_locked()
                jsonl_chain = self._logical_audit_chain(jsonl_records, label="JSONL")
                if jsonl_chain != database_chain:
                    raise AuditIntegrityError(
                        "audit JSONL does not exactly match the database chain"
                    )
        except AuditIntegrityError as exc:
            return {
                "valid": False,
                "entries": len(locals().get("database_records", [])),
                "failure_at": None,
                "reason": str(exc),
            }
        head = (
            str(database_chain[-1]["entry_hash"])
            if database_chain
            else GENESIS_AUDIT_HASH
        )
        return {"valid": True, "entries": len(database_chain), "head": head}

    def repair_audit_mirror(self) -> dict[str, Any]:
        """Explicitly append exact DB records missing from an untampered JSONL mirror.

        Existing JSONL bytes are never deleted, overwritten, or reordered.  A
        repair is allowed only when every existing mirror record uniquely and
        exactly matches an entry in the already-valid authoritative DB chain.
        """

        self._ensure()
        self._guard_local_state_path(self._audit_lock_path, expected="file")
        audit_lock = InterProcessFileLock(self._audit_lock_path)
        with self._lock, audit_lock.held(
            timeout_seconds=max(1.0, self.config.busy_timeout_ms / 1000)
        ):
            database_records = self._database_audit_records_locked()
            database_chain = self._logical_audit_chain(
                database_records, label="database"
            )
            if [record["audit_id"] for record in database_chain] != [
                record["audit_id"] for record in database_records
            ]:
                raise AuditIntegrityError(
                    "database row order does not match its hash chain"
                )

            jsonl_records = self._jsonl_audit_records_locked()
            database_by_id = {
                str(record["audit_id"]): record for record in database_chain
            }
            mirrored_ids: set[str] = set()
            mirrored_hashes: set[str] = set()
            for record in jsonl_records:
                self._validate_audit_record(record)
                audit_id = str(record["audit_id"])
                entry_hash = str(record["entry_hash"])
                if audit_id in mirrored_ids:
                    raise AuditIntegrityError("duplicate JSONL audit_id")
                if entry_hash in mirrored_hashes:
                    raise AuditIntegrityError("duplicate JSONL entry_hash")
                expected = database_by_id.get(audit_id)
                if expected is None or record != expected:
                    raise AuditIntegrityError(
                        "JSONL record does not exactly match the database"
                    )
                mirrored_ids.add(audit_id)
                mirrored_hashes.add(entry_hash)

            missing = [
                record
                for record in database_chain
                if str(record["audit_id"]) not in mirrored_ids
            ]
            if not missing:
                # No mutation is needed; this remains a read-only no-op.
                self._logical_audit_chain(jsonl_records, label="JSONL")
                return {
                    "repaired": False,
                    "missing_entries": 0,
                    "repair_audit_id": None,
                }

            # Only append authoritative records.  Delayed records may be out
            # of physical file order; their previous_hash/entry_hash values
            # reconstruct the one canonical logical order during verification.
            self._append_audit_jsonl_locked(missing)
            repair_record = self._insert_audit_record_locked(
                event_type="audit.mirror_repaired",
                payload={
                    "missing_entries": len(missing),
                    "recovered_audit_ids": [
                        str(record["audit_id"]) for record in missing
                    ],
                    "recovered_entry_hashes": [
                        str(record["entry_hash"]) for record in missing
                    ],
                },
                session_id=None,
                action_id=None,
            )
            self._append_audit_jsonl_locked([repair_record])
            return {
                "repaired": True,
                "missing_entries": len(missing),
                "repair_audit_id": str(repair_record["audit_id"]),
            }

    def export_session(self, session_id: str) -> dict[str, Any]:
        return {"session": self.get_session(session_id), "events": self.list_events(session_id), "checkpoint": self.latest_checkpoint(session_id)}

    def propose_memory(
        self,
        *,
        content: str,
        namespace: str,
        source: str,
        ttl_days: int | None = None,
        confidence: float = 0.8,
        tags: list[str] | None = None,
        sensitivity: str = "normal",
        supersedes: str | None = None,
        expected_updated_at: str | None = None,
        ttl_at: str | None = None,
    ) -> dict[str, Any]:
        """Persist a reviewable proposal; it has no effect until committed."""

        self._ensure()
        normalized_tags = [str(tag).strip() for tag in (tags or []) if str(tag).strip()]
        self._validate_memory_payload(
            content=content,
            namespace=namespace,
            source=source,
            confidence=confidence,
            tags=normalized_tags,
            sensitivity=sensitivity,
        )
        if ttl_days is not None and ttl_days < 0:
            raise ValueError("memory TTL cannot be negative")
        if ttl_days is not None and ttl_at is not None:
            raise ValueError("specify ttl_days or ttl_at, not both")
        now = utc_now()
        expires = (now + timedelta(days=ttl_days)).isoformat() if ttl_days is not None else None
        if ttl_at is not None:
            try:
                parsed_expiry = datetime.fromisoformat(ttl_at)
            except ValueError as exc:
                raise ValueError("memory ttl_at must be an ISO-8601 timestamp") from exc
            if parsed_expiry.tzinfo is None:
                raise ValueError("memory ttl_at must include a timezone")
            expires = parsed_expiry.astimezone(UTC).isoformat()
        if supersedes is not None:
            target = self.get_memory(supersedes)
            expected_updated_at = expected_updated_at or str(target["updated_at"])
        proposal_id = new_id("memory_proposal")
        payload = {
            "proposal_id": proposal_id,
            "operation": "edit" if supersedes else "create",
            "content": content,
            "namespace": namespace,
            "source": source,
            "created_at": now.isoformat(),
            "confidence": confidence,
            "ttl_at": expires,
            "tags": normalized_tags,
            "supersedes": supersedes,
            "expected_updated_at": expected_updated_at,
            "sensitivity": sensitivity,
            "status": "pending",
            "conflict_reason": None,
            "committed_memory_id": None,
            "authority": "advisory_only",
        }
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO memory_proposals(
                    proposal_id, operation, namespace, content, source, created_at,
                    confidence, ttl_at, tags_json, supersedes, expected_updated_at,
                    sensitivity, status, conflict_reason, committed_memory_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL)
                """,
                (
                    proposal_id,
                    payload["operation"],
                    namespace,
                    content,
                    source,
                    payload["created_at"],
                    confidence,
                    expires,
                    self._json(normalized_tags),
                    supersedes,
                    expected_updated_at,
                    sensitivity,
                ),
            )
        self.append_audit(event_type="memory.propose", payload=payload)
        return payload

    def propose_memory_edit(
        self,
        memory_id: str,
        *,
        content: str,
        namespace: str | None = None,
        source: str | None = None,
        confidence: float | None = None,
        tags: list[str] | None = None,
        sensitivity: str | None = None,
    ) -> dict[str, Any]:
        """Propose a replacement while preserving unspecified metadata exactly."""

        current = self.get_memory(memory_id)
        if current["deleted"] or not current["active"]:
            raise MemoryConflictError("only an active memory can be edited")
        return self.propose_memory(
            content=content,
            namespace=namespace or str(current["namespace"]),
            source=source or str(current["source"]),
            confidence=float(current["confidence"] if confidence is None else confidence),
            tags=list(current["tags"] if tags is None else tags),
            sensitivity=sensitivity or str(current["sensitivity"]),
            ttl_at=current["ttl_at"],
            supersedes=memory_id,
            expected_updated_at=str(current["updated_at"]),
        )

    def get_memory_proposal(self, proposal_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM memory_proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown memory proposal: {proposal_id}")
        item = dict(row)
        item["tags"] = json.loads(item.pop("tags_json"))
        item["authority"] = "advisory_only"
        return item

    def commit_memory(self, proposal_id: str) -> dict[str, Any]:
        """Commit one proposal atomically or mark a detected conflict."""

        self._ensure()
        memory_id = new_id("memory")
        now = utc_now().isoformat()
        conflict: str | None = None
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM memory_proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown memory proposal: {proposal_id}")
            proposal = dict(row)
            if proposal["status"] == "committed":
                raise ValueError("memory proposal has already been committed")
            if proposal["status"] == "conflict":
                raise MemoryConflictError(str(proposal["conflict_reason"]))
            if proposal["status"] != "pending":
                raise ValueError(f"memory proposal is {proposal['status']}")

            target: sqlite3.Row | None = None
            supersedes = proposal.get("supersedes")
            if supersedes:
                target = conn.execute(
                    "SELECT * FROM memory_entries WHERE memory_id=?", (supersedes,)
                ).fetchone()
                if target is None:
                    conflict = "the memory being edited no longer exists"
                elif bool(target["deleted"]):
                    conflict = "the memory being edited was deleted"
                elif target["superseded_by"] is not None:
                    conflict = "the memory was already superseded by another edit"
                elif target["ttl_at"] is not None and str(target["ttl_at"]) <= now:
                    conflict = "the memory being edited has expired"
                elif target["updated_at"] != proposal.get("expected_updated_at"):
                    conflict = "the memory changed after this proposal was created"
            else:
                duplicate = conn.execute(
                    """
                    SELECT memory_id FROM memory_entries
                    WHERE namespace=? AND content=? AND deleted=0 AND superseded_by IS NULL
                      AND (ttl_at IS NULL OR ttl_at>?) LIMIT 1
                    """,
                    (proposal["namespace"], proposal["content"], now),
                ).fetchone()
                if duplicate is not None:
                    conflict = f"an equivalent active memory already exists: {duplicate[0]}"

            if conflict is not None:
                conn.execute(
                    "UPDATE memory_proposals SET status='conflict', conflict_reason=? WHERE proposal_id=?",
                    (conflict, proposal_id),
                )
                conn.commit()
            else:
                conn.execute(
                    """
                    INSERT INTO memory_entries(
                        memory_id, namespace, content, source, created_at, updated_at,
                        confidence, ttl_at, tags_json, supersedes, sensitivity, deleted,
                        superseded_by, conflict_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, 'none')
                    """,
                    (
                        memory_id,
                        proposal["namespace"],
                        proposal["content"],
                        proposal["source"],
                        now,
                        now,
                        float(proposal["confidence"]),
                        proposal.get("ttl_at"),
                        proposal["tags_json"],
                        supersedes,
                        proposal["sensitivity"],
                    ),
                )
                conn.execute(
                    "INSERT INTO memory_fts(memory_id, namespace, content, tags) VALUES (?, ?, ?, ?)",
                    (
                        memory_id,
                        proposal["namespace"],
                        proposal["content"],
                        " ".join(json.loads(proposal["tags_json"])),
                    ),
                )
                if supersedes:
                    conn.execute(
                        "UPDATE memory_entries SET superseded_by=?, conflict_status='superseded' WHERE memory_id=?",
                        (memory_id, supersedes),
                    )
                    conn.execute("DELETE FROM memory_fts WHERE memory_id=?", (supersedes,))
                conn.execute(
                    """
                    UPDATE memory_proposals
                    SET status='committed', committed_memory_id=?
                    WHERE proposal_id=?
                    """,
                    (memory_id, proposal_id),
                )
                conn.commit()
        if conflict is not None:
            self.append_audit(
                event_type="memory.conflict",
                payload={"proposal_id": proposal_id, "reason": conflict},
            )
            raise MemoryConflictError(conflict)
        self.append_audit(
            event_type="memory.commit",
            payload={
                "memory_id": memory_id,
                "proposal_id": proposal_id,
                "supersedes": proposal.get("supersedes"),
            },
        )
        return self.get_memory(memory_id)

    def list_memory(self, namespace: str | None = None) -> list[dict[str, Any]]:
        self._ensure(); now = utc_now().isoformat()
        query = "SELECT * FROM memory_entries WHERE deleted=0 AND superseded_by IS NULL AND (ttl_at IS NULL OR ttl_at>?)"; params: list[Any] = [now]
        if namespace: query += " AND namespace=?"; params.append(namespace)
        query += " ORDER BY updated_at DESC"
        with self._lock, self._connection() as conn: rows = conn.execute(query, params).fetchall()
        return [self._memory_row(row) for row in rows]

    def search_memory(self, query: str, namespace: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        self._ensure()
        terms = re.findall(r"[\w\u4e00-\u9fff-]{2,}", query)
        if not terms:
            return []
        fts_query = " AND ".join(terms[:16])
        sql = "SELECT memory_entries.* FROM memory_fts JOIN memory_entries ON memory_entries.memory_id=memory_fts.memory_id WHERE memory_fts MATCH ? AND memory_entries.deleted=0 AND memory_entries.superseded_by IS NULL AND (memory_entries.ttl_at IS NULL OR memory_entries.ttl_at>?)"
        params: list[Any] = [fts_query, utc_now().isoformat()]
        if namespace:
            sql += " AND memory_entries.namespace=?"
            params.append(namespace)
        sql += " ORDER BY memory_entries.updated_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self._lock, self._connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._memory_row(row) for row in rows]

    def export_memory(self) -> list[dict[str, Any]]:
        return self.list_memory()

    def reindex_memory(self) -> None:
        self._ensure()
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM memory_fts")
            rows = conn.execute("SELECT memory_id, namespace, content, tags_json FROM memory_entries WHERE deleted=0 AND superseded_by IS NULL").fetchall()
            conn.executemany("INSERT INTO memory_fts(memory_id, namespace, content, tags) VALUES (?, ?, ?, ?)", [(row[0], row[1], row[2], " ".join(json.loads(row[3]))) for row in rows])

    def get_memory(self, memory_id: str) -> dict[str, Any]:
        self._ensure()
        with self._lock, self._connection() as conn: row = conn.execute("SELECT * FROM memory_entries WHERE memory_id=?", (memory_id,)).fetchone()
        if row is None: raise KeyError(memory_id)
        return self._memory_row(row)

    @staticmethod
    def _memory_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["tags"] = json.loads(item.pop("tags_json"))
        item["deleted"] = bool(item["deleted"])
        ttl_active = item.get("ttl_at") is None or str(item["ttl_at"]) > utc_now().isoformat()
        item["active"] = (
            not item["deleted"] and item.get("superseded_by") is None and ttl_active
        )
        item["authority"] = "advisory_only"
        return item

    def forget_memory(self, memory_id: str) -> None:
        self._ensure()
        with self._lock, self._connection() as conn:
            cursor = conn.execute("UPDATE memory_entries SET deleted=1, updated_at=? WHERE memory_id=?", (utc_now().isoformat(), memory_id))
            if cursor.rowcount == 0:
                raise KeyError(memory_id)
            conn.execute("DELETE FROM memory_fts WHERE memory_id=?", (memory_id,))
        self.append_audit(event_type="memory.forget", payload={"memory_id": memory_id})

    def list_memory_conflicts(self) -> list[dict[str, Any]]:
        self._ensure()
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT proposal_id FROM memory_proposals WHERE status='conflict' ORDER BY created_at DESC"
            ).fetchall()
        return [self.get_memory_proposal(str(row[0])) for row in rows]

    @staticmethod
    def _validate_memory_payload(
        *,
        content: str,
        namespace: str,
        source: str,
        confidence: float,
        tags: list[str],
        sensitivity: str,
    ) -> None:
        if not content.strip() or len(content) > 20_000:
            raise ValueError("memory content must be 1..20000 characters")
        if namespace not in {"user", "project", "workspace"}:
            raise ValueError("memory namespace must be user, project, or workspace")
        if not source.strip() or len(source) > 2_000:
            raise ValueError("memory source must be 1..2000 characters")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("memory confidence must be between 0 and 1")
        if sensitivity not in {"normal", "sensitive"}:
            raise ValueError("unsupported memory sensitivity")
        if len(tags) > 64 or any(len(tag) > 128 for tag in tags):
            raise ValueError("memory tags exceed the bounded size")
        secret_surface = {"content": content, "source": source, "tags": tags}
        if redact_secrets(secret_surface) != secret_surface:
            raise ValueError("memory content appears to contain a secret")

    def set_kill_switch(self, reason: str) -> None:
        self._ensure()
        with self._lock, self._connection() as conn: conn.execute("INSERT OR REPLACE INTO runtime_flags(name,value,updated_at) VALUES ('kill_switch', ?, ?)", (self._json({"engaged": True, "reason": redact_secrets(reason)}), utc_now().isoformat()))
        self.append_audit(event_type="kill_switch.engaged", payload={"reason": reason})

    def clear_kill_switch(self) -> None:
        self._ensure()
        with self._lock, self._connection() as conn: conn.execute("DELETE FROM runtime_flags WHERE name='kill_switch'")
        self.append_audit(event_type="kill_switch.cleared", payload={})

    def kill_switch_engaged(self) -> bool:
        self._ensure()
        with self._lock, self._connection() as conn: row = conn.execute("SELECT value FROM runtime_flags WHERE name='kill_switch'").fetchone()
        return bool(row and json.loads(row[0]).get("engaged"))


__all__ = ["AuditIntegrityError", "MemoryConflictError", "SCHEMA_VERSION", "Storage"]
