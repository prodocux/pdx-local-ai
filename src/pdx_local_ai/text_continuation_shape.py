"""Product shape check and capability preflight for migration 012.

The comparison matches reference execution: normalized sqlite_master SQL
from a clean execution of 001, 011, and 012. This module does not rewrite objects
and maintains strict product isolation (zero external proposal dependencies).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .validation import ContractError
from .paths import get_root

ROOT = get_root()
SQL_001 = ROOT / "sql" / "001_gate0.sql"
SQL_011 = ROOT / "sql" / "011_text_intake.sql"
SQL_012 = ROOT / "sql" / "012_text_range_continuation.sql"

TABLES = (
    "text_range_artifact",
    "text_range_cursor",
    "text_range_generation",
    "text_range_generation_member",
    "text_range_generation_seal",
    "text_freshness_witness",
    "text_range_publication_event",
    "text_current_published_generation",
)

VIEWS = (
    "text_freshness_witness_intent",
    "text_range_publication_intent",
)

CORE_TRIGGER_NAMES = (
    "text_range_artifact_immutable",
    "text_range_artifact_verify_identity",
    "text_range_cursor_verify_identity",
    "text_range_cursor_transition_guard",
    "text_range_generation_immutable",
    "text_range_generation_verify_identity",
    "text_range_generation_member_immutable",
    "text_range_generation_member_guard",
    "text_range_generation_seal_verify",
    "text_range_generation_seal_immutable",
    "text_freshness_witness_intent_insert",
    "text_freshness_witness_guard",
    "text_range_publication_intent_publish",
    "text_range_publication_event_guard",
    "text_range_publication_event_publish_pointer",
    "text_current_published_generation_guard",
)

ALL_TRIGGER_NAMES = CORE_TRIGGER_NAMES + (
    "text_range_artifact_delete_forbidden",
    "text_range_generation_delete_forbidden",
    "text_range_generation_member_delete_forbidden",
    "text_range_generation_seal_delete_forbidden",
    "text_freshness_witness_update_forbidden",
    "text_freshness_witness_delete_forbidden",
    "text_range_publication_event_update_forbidden",
    "text_range_publication_event_delete_forbidden",
    "text_current_published_generation_delete_forbidden",
)

SENTINELS_012 = TABLES + VIEWS + ALL_TRIGGER_NAMES


class TextContinuationShapeError(RuntimeError):
    """012 is missing or its installed definitions differ from the reference."""


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())


def _master_sql(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
        for row in conn.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL")
    }


def preflight_check(conn: sqlite3.Connection) -> tuple[str, float | int, str, str]:
    """Execute SQLite capability preflight checks before any migration transaction or DDL.

    Validates:
    - SQLite version >= 3.42.0
    - unixepoch('subsec') returns real or integer (non-NULL)
    - CAST((unixepoch('subsec') * 1000) AS INTEGER) evaluates to 'integer'

    Fails closed with ContractError without modifying schema or leaving open transactions.
    """
    try:
        row = conn.execute(
            "SELECT sqlite_version(), "
            "unixepoch('subsec'), "
            "typeof(unixepoch('subsec')), "
            "typeof(CAST((unixepoch('subsec') * 1000) AS INTEGER))"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        raise ContractError(f"preflight failed: SQLite >= 3.42.0 with unixepoch(subsec) required: {exc}") from exc

    if not row:
        raise ContractError("preflight failed: SQLite >= 3.42.0 with unixepoch(subsec) required")

    version_str, raw_subsec, subsec_type, ms_cast_type = row

    if not version_str or not isinstance(version_str, str):
        raise ContractError("preflight failed: invalid sqlite_version string")

    try:
        parts = [int(p) for p in version_str.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
    except Exception as exc:
        raise ContractError(f"preflight failed: unable to parse sqlite version {version_str}: {exc}") from exc

    if tuple(parts) < (3, 42, 0):
        raise ContractError(f"preflight failed: SQLite >= 3.42.0 with unixepoch(subsec) required (got {version_str})")

    if raw_subsec is None or subsec_type not in ("real", "integer"):
        raise ContractError(
            f"preflight failed: unixepoch('subsec') must return real or integer (got {subsec_type})"
        )

    if ms_cast_type != "integer":
        raise ContractError(
            f"preflight failed: typeof(CAST((unixepoch('subsec') * 1000) AS INTEGER)) must be integer (got {ms_cast_type})"
        )

    return (version_str, raw_subsec, subsec_type, ms_cast_type)


_APPROVED_TEXT_CONTINUATION_SQL: dict[tuple[str, str], str] | None = None


def approved_text_continuation_sql() -> dict[tuple[str, str], str]:
    """Return normalized sqlite_master SQL produced by clean 001+011 then 012 execution."""
    global _APPROVED_TEXT_CONTINUATION_SQL
    if _APPROVED_TEXT_CONTINUATION_SQL is not None:
        return _APPROVED_TEXT_CONTINUATION_SQL
    reference = sqlite3.connect(":memory:")
    try:
        reference.execute("PRAGMA foreign_keys=ON")
        reference.executescript(SQL_001.read_text(encoding="utf-8"))
        reference.executescript(SQL_011.read_text(encoding="utf-8"))
        before = _master_sql(reference)
        reference.executescript(SQL_012.read_text(encoding="utf-8"))
        after = _master_sql(reference)
    finally:
        reference.close()

    approved = {key: sql for key, sql in after.items() if before.get(key) != sql}
    names = {name for _type, name in approved}

    if not set(TABLES).issubset(names):
        missing = set(TABLES) - names
        raise TextContinuationShapeError(f"text continuation migration missing tables: {missing}")

    if not set(VIEWS).issubset(names):
        missing = set(VIEWS) - names
        raise TextContinuationShapeError(f"text continuation migration missing views: {missing}")

    if not set(CORE_TRIGGER_NAMES).issubset(names):
        missing = set(CORE_TRIGGER_NAMES) - names
        raise TextContinuationShapeError(f"text continuation migration missing core triggers: {missing}")

    _APPROVED_TEXT_CONTINUATION_SQL = approved
    return approved


def require_text_continuation_shape(conn: sqlite3.Connection) -> None:
    """Fail closed unless installed 012 objects match reference execution exactly.

    This function does not write or auto-repair.
    """
    approved = approved_text_continuation_sql()
    installed = _master_sql(conn)
    for key, sql in approved.items():
        if installed.get(key) != sql:
            raise TextContinuationShapeError(
                f"text continuation migration shape mismatch for {key}: expected {sql!r}, got {installed.get(key)!r}"
            )
