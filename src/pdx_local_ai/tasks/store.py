"""tasks.sqlite: separate task database with migration, CAS/lease/fencing and event log.

Design notes
- One database file (``tasks.sqlite``) beside ``catalog.sqlite``; it never shares a
  transaction with the catalog. Cross-database effects go through ``task_outbox`` and
  idempotency keys and are reconciled, not claimed exactly-once.
- Every connection is opened per thread. All mutating work runs in ``BEGIN IMMEDIATE``.
- ``task.state_version`` is the CAS counter; ``task_lease.fencing_token`` fences writers.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from .contracts import LIMITS, TERMINAL_STATES, TaskError, canonical_json, utf8_len

TASK_SCHEMA_VERSION = 2
TASKS_DB_NAME = "tasks.sqlite"

_DDL_V1 = """
CREATE TABLE task (
    task_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    creator_actor_kind TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_version TEXT NOT NULL,
    template_sha256 TEXT NOT NULL,
    context_mode TEXT NOT NULL,
    params_json TEXT NOT NULL,
    params_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    state_version INTEGER NOT NULL,
    terminal_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_seen_epoch REAL NOT NULL,
    deadline_epoch REAL NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0,
    input_bytes INTEGER NOT NULL,
    retain_until TEXT,
    idempotency_key TEXT,
    request_sha256 TEXT
);
CREATE INDEX task_state_idx ON task(workspace_id, state);
CREATE UNIQUE INDEX task_idem_idx ON task(workspace_id, principal_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE TABLE task_approval (
    task_id TEXT PRIMARY KEY REFERENCES task(task_id) ON DELETE CASCADE,
    params_sha256 TEXT NOT NULL,
    approver_actor_kind TEXT NOT NULL,
    approver_principal_id TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE task_step (
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    depends_on_json TEXT NOT NULL,
    state TEXT NOT NULL,
    current_attempt_id TEXT,
    PRIMARY KEY (task_id, step_id)
);
CREATE TABLE task_attempt (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    state TEXT NOT NULL,
    parent_digests_json TEXT NOT NULL,
    artifact_json TEXT,
    artifact_sha256 TEXT,
    incomplete INTEGER NOT NULL DEFAULT 0,
    stop_reason TEXT,
    rework_note TEXT,
    created_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE (task_id, step_id, attempt_no)
);
CREATE TABLE task_lease (
    task_id TEXT PRIMARY KEY REFERENCES task(task_id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    expires_at_epoch REAL NOT NULL
);
CREATE TABLE task_operation (
    operation_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT,
    step_id TEXT,
    action TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    response_json TEXT,
    fencing_token INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (task_id, idempotency_key)
);
CREATE TABLE task_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT,
    step_id TEXT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    origin TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX task_event_idx ON task_event(task_id, seq);
CREATE TABLE task_artifact (
    artifact_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    rel_path TEXT NOT NULL,
    origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (task_id, attempt_id, name)
);
CREATE TABLE task_hop (
    hop_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    parent_hop_id TEXT,
    hop_no INTEGER NOT NULL,
    query_norm TEXT NOT NULL,
    entity TEXT,
    visited_key TEXT NOT NULL,
    status TEXT NOT NULL,
    stop_reason TEXT,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    consumed_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX task_hop_idx ON task_hop(task_id, attempt_id);
CREATE TABLE task_evidence (
    evidence_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    hop_id TEXT,
    file_record_id TEXT NOT NULL,
    source_root_id TEXT NOT NULL,
    block_instance_id TEXT NOT NULL,
    source_version_id TEXT NOT NULL,
    citation_id TEXT NOT NULL,
    text TEXT NOT NULL,
    text_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX task_evidence_idx ON task_evidence(task_id, attempt_id);
CREATE TABLE task_visited (
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    visited_key TEXT NOT NULL,
    PRIMARY KEY (task_id, attempt_id, visited_key)
);
CREATE TABLE task_ledger (
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    ledger_json TEXT NOT NULL,
    PRIMARY KEY (task_id, attempt_id)
);
CREATE TABLE task_outbox (
    outbox_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_DDL_V2 = """
CREATE TABLE task_context_measurement (
    measurement_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task(task_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    context_mode TEXT NOT NULL,
    prefix_sha256 TEXT NOT NULL,
    prefix_bytes INTEGER NOT NULL,
    context_sha256 TEXT NOT NULL,
    context_bytes INTEGER NOT NULL,
    evidence_window_count INTEGER NOT NULL,
    evidence_window_bytes INTEGER NOT NULL,
    omitted_count INTEGER NOT NULL,
    eligible_file_bytes INTEGER,
    ledger_queries INTEGER NOT NULL,
    hop_count INTEGER NOT NULL,
    ledger_remaining_json TEXT,
    retrieval_terminal_reason TEXT,
    task_state TEXT NOT NULL CHECK (task_state IN ('queued', 'running')),
    measurement_error TEXT,
    provider_name TEXT,
    provider_input_tokens INTEGER,
    provider_output_tokens INTEGER,
    UNIQUE (attempt_id, step_id, context_sha256)
);
"""

_MIGRATIONS: dict[int, str] = {1: _DDL_V1, 2: _DDL_V2}


def utc_iso(epoch: float | None = None) -> str:
    dt = datetime.fromtimestamp(time.time() if epoch is None else epoch, UTC)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def apply_task_migrations(conn: sqlite3.Connection) -> int:
    """Forward-only migration. Refuses a database written by a newer schema."""
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > TASK_SCHEMA_VERSION:
        raise TaskError("TASK_DB_UNSUPPORTED_VERSION",
                        f"tasks.sqlite schema {current} is newer than supported {TASK_SCHEMA_VERSION}")
    if current == TASK_SCHEMA_VERSION:
        return current
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-read inside the write lock so two migrators cannot both apply DDL.
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        for version in range(current + 1, TASK_SCHEMA_VERSION + 1):
            for statement in _split_sql(_MIGRATIONS[version]):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={int(version)}")
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise TaskError("TASK_DB_MIGRATION_FAILED", f"tasks.sqlite migration failed: {exc}") from exc
    return TASK_SCHEMA_VERSION


def _split_sql(script: str) -> list[str]:
    return [s.strip() for s in script.split(";\n") if s.strip()]


def migrate_tasks_database(path: Path) -> int:
    """Entry point used by the installer: create/upgrade ``tasks.sqlite`` if present or required."""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=5.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return apply_task_migrations(conn)
    finally:
        conn.close()


class TaskStore:
    """Thin persistence layer. Business rules live in ``TaskService``."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.clock = clock
        self._local = threading.local()
        self._conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self.conn
        apply_task_migrations(conn)

    # ------------------------------------------------------------------ connections
    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
            with self._conns_lock:
                self._conns.append(conn)
        return conn

    def close(self) -> None:
        with self._conns_lock:
            for conn in self._conns:
                with contextlib.suppress(Exception):
                    conn.close()
            self._conns.clear()
        self._local = threading.local()

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    # ------------------------------------------------------------------ reads
    def get_task(self, task_id: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
        return (conn or self.conn).execute("SELECT * FROM task WHERE task_id=?", (task_id,)).fetchone()

    def require_task(self, task_id: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row:
        row = self.get_task(task_id, conn)
        if row is None:
            raise TaskError("TASK_NOT_FOUND", "task not found")
        return row

    # ------------------------------------------------------------------ CAS state
    def cas_state(self, conn: sqlite3.Connection, task_id: str, expected_version: int, new_state: str,
                  *, reason: str | None = None, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        cur = conn.execute(
            "UPDATE task SET state=?, state_version=state_version+1, updated_at=?, last_seen_epoch=?, "
            "terminal_reason=COALESCE(?, terminal_reason), "
            "retain_until=CASE WHEN ? IN ('succeeded','failed','cancelled','timed_out') THEN ? ELSE retain_until END "
            "WHERE task_id=? AND state_version=?",
            (new_state, utc_iso(now), max(now, 0.0), reason, new_state,
             utc_iso(now + LIMITS["retention_days"] * 86400), task_id, expected_version),
        )
        if cur.rowcount != 1:
            raise TaskError("TASK_STATE_CONFLICT", "task state_version changed concurrently",
                            {"expected_state_version": expected_version})
        return expected_version + 1

    def touch(self, conn: sqlite3.Connection, task_id: str, now: float) -> None:
        conn.execute("UPDATE task SET last_seen_epoch=?, updated_at=? WHERE task_id=?",
                     (now, utc_iso(now), task_id))

    # ------------------------------------------------------------------ events
    def append_event(self, conn: sqlite3.Connection, task_id: str, kind: str, payload: dict[str, Any],
                     *, origin: str = "task_host", attempt_id: str | None = None,
                     step_id: str | None = None, terminal: bool = False) -> int:
        count = conn.execute("SELECT COUNT(*) FROM task_event WHERE task_id=?", (task_id,)).fetchone()[0]
        cap = LIMITS["max_events_per_task"]
        if count >= cap + (16 if terminal else 0):
            raise TaskError("EVENT_QUOTA_EXCEEDED", "task event quota exhausted")
        text = canonical_json(payload)
        truncated = 0
        if utf8_len(text) > LIMITS["event_payload_bytes"]:
            text = canonical_json({"truncated": True, "kind": kind,
                                   "preview": text[: LIMITS["event_payload_bytes"] // 4]})
            truncated = 1
        cur = conn.execute(
            "INSERT INTO task_event(task_id, attempt_id, step_id, ts, kind, origin, payload_json, truncated) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (task_id, attempt_id, step_id, utc_iso(self.clock()), kind, origin, text, truncated),
        )
        return int(cur.lastrowid)

    # ------------------------------------------------------------------ lease / fencing
    def acquire_lease(self, conn: sqlite3.Connection, task_id: str, owner: str,
                      *, allow_takeover: bool = False) -> int:
        now = self.clock()
        expires = now + LIMITS["lease_seconds"]
        row = conn.execute("SELECT * FROM task_lease WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            conn.execute("INSERT INTO task_lease VALUES (?,?,?,?)", (task_id, owner, 1, expires))
            return 1
        if row["owner_id"] == owner:
            conn.execute("UPDATE task_lease SET expires_at_epoch=? WHERE task_id=?", (expires, task_id))
            return int(row["fencing_token"])
        if row["expires_at_epoch"] <= now:
            if not allow_takeover:
                raise TaskError("LEASE_LOST", "lease expired and was not renewed; call resume_task to take over")
            token = int(row["fencing_token"]) + 1
            conn.execute("UPDATE task_lease SET owner_id=?, fencing_token=?, expires_at_epoch=? WHERE task_id=?",
                         (owner, token, expires, task_id))
            return token
        raise TaskError("LEASE_HELD", "another executor holds the task lease",
                        {"expires_in_seconds": round(row["expires_at_epoch"] - now, 3)})

    def require_fence(self, conn: sqlite3.Connection, task_id: str, owner: str, token: int) -> None:
        row = conn.execute("SELECT owner_id, fencing_token FROM task_lease WHERE task_id=?", (task_id,)).fetchone()
        if row is None or row["owner_id"] != owner or int(row["fencing_token"]) != int(token):
            raise TaskError("LEASE_LOST", "fencing token no longer valid; a newer executor owns the task")

    def release_lease(self, conn: sqlite3.Connection, task_id: str, owner: str) -> None:
        conn.execute("UPDATE task_lease SET expires_at_epoch=0 WHERE task_id=? AND owner_id=?", (task_id, owner))

    # ------------------------------------------------------------------ counters
    def count_by_state(self, conn: sqlite3.Connection, workspace_id: str, states: tuple[str, ...]) -> int:
        marks = ",".join("?" for _ in states)
        return int(conn.execute(
            f"SELECT COUNT(*) FROM task WHERE workspace_id=? AND state IN ({marks})",
            (workspace_id, *states),
        ).fetchone()[0])

    # ------------------------------------------------------------------ lifecycle
    def backup_to(self, dest: Path) -> list[str]:
        """Online backup with integrity check (used by installer upgrade)."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        out = sqlite3.connect(str(dest))
        try:
            self.conn.backup(out)
            out.commit()
            return [str(r[0]) for r in out.execute("PRAGMA integrity_check")]
        finally:
            out.close()

    def purge_expired(self, *, now: float | None = None) -> dict[str, Any]:
        """Delete terminal tasks past ``retain_until``; returns counts and workspace dirs to remove."""
        now_iso = utc_iso(self.clock() if now is None else now)
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT task_id FROM task WHERE state IN ('succeeded','failed','cancelled','timed_out') "
                "AND retain_until IS NOT NULL AND retain_until<=?", (now_iso,)).fetchall()
            ids = [r[0] for r in rows]
            for task_id in ids:
                conn.execute("DELETE FROM task WHERE task_id=?", (task_id,))  # cascades
        return {"purged_tasks": len(ids), "task_ids": ids}

    def purge_all_terminal(self) -> dict[str, Any]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT task_id FROM task WHERE state IN ('succeeded','failed','cancelled','timed_out')").fetchall()
            ids = [r[0] for r in rows]
            for task_id in ids:
                conn.execute("DELETE FROM task WHERE task_id=?", (task_id,))
        return {"purged_tasks": len(ids), "task_ids": ids}

    def checkpoint(self) -> None:
        with contextlib.suppress(Exception):
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


__all__ = [
    "TASKS_DB_NAME", "TASK_SCHEMA_VERSION", "TaskStore", "apply_task_migrations",
    "migrate_tasks_database", "utc_iso", "TERMINAL_STATES", "json",
]
