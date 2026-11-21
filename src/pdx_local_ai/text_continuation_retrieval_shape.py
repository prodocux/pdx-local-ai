"""Product shape check and capability preflight for migration 013.

The comparison matches reference execution: normalized sqlite_master SQL
from a clean execution of 001, 011, 012, and 013. This module does not rewrite objects
and maintains strict product tree isolation (zero external proposal dependencies).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .text_continuation_shape import require_text_continuation_shape
from .text_intake_shape import require_text_intake_shape
from .validation import ContractError
from .paths import get_root

ROOT = get_root()
SQL_001 = ROOT / "sql" / "001_gate0.sql"
SQL_011 = ROOT / "sql" / "011_text_intake.sql"
SQL_012 = ROOT / "sql" / "012_text_range_continuation.sql"
SQL_013 = ROOT / "sql" / "013_text_continuation_retrieval.sql"

PRIMARY_TABLES_013 = (
    "text_continuation_projection",
    "text_continuation_block_instance",
    "text_continuation_source_range",
    "text_continuation_fts_binding",
    "text_continuation_block_fts",
    "text_continuation_slice_receipt",
    "text_continuation_generation_accumulator",
    "text_continuation_materialization_marker",
)

SHADOW_TABLES_013 = (
    "text_continuation_block_fts_config",
    "text_continuation_block_fts_content",
    "text_continuation_block_fts_data",
    "text_continuation_block_fts_docsize",
    "text_continuation_block_fts_idx",
)

TABLES_013 = PRIMARY_TABLES_013 + SHADOW_TABLES_013

VIEWS_013 = (
    "text_continuation_fts_drift",
)

TRIGGERS_013 = (
    # Projection (3)
    "trg_continuation_projection_protect_update",
    "trg_continuation_projection_protect_delete",
    "trg_continuation_projection_verify_generation_identity",
    # Blocks (6)
    "trg_continuation_block_after_insert_sync_fts",
    "trg_continuation_block_before_delete_sync_fts",
    "trg_continuation_block_protect_sealed_slice",
    "trg_continuation_block_protect_update_sealed",
    "trg_continuation_block_protect_delete_sealed",
    "trg_continuation_block_verify_causality",
    # Source Ranges (4)
    "trg_continuation_source_range_protect_insert_sealed",
    "trg_continuation_source_range_protect_update",
    "trg_continuation_source_range_protect_delete_sealed",
    "trg_continuation_source_range_verify_causality",
    # FTS Bindings (3)
    "trg_continuation_fts_binding_protect_update",
    "trg_continuation_fts_binding_protect_delete_sealed",
    "trg_continuation_fts_binding_verify_causality",
    # Slice Receipts (3)
    "trg_receipt_validate_member",
    "trg_receipt_immutable_update",
    "trg_receipt_immutable_delete",
    # Accumulator (5)
    "trg_receipt_advance_accumulator_insert",
    "trg_receipt_advance_accumulator_update",
    "trg_accumulator_protect_manual_update",
    "trg_accumulator_protect_manual_insert",
    "trg_accumulator_protect_delete",
    # Marker (3)
    "trg_marker_verify_readiness",
    "trg_marker_protect_update",
    "trg_marker_protect_delete",
)

SENTINELS_013 = set(TABLES_013) | set(VIEWS_013) | set(TRIGGERS_013)


class TextContinuationRetrievalShapeError(RuntimeError):
    """013 is missing, partial, or its installed definitions differ from the reference."""


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())


def _master_sql(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
        for row in conn.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL")
    }


def preflight_check(conn: sqlite3.Connection) -> tuple[str, float | int, str, str]:
    """Execute SQLite capability and upstream prerequisite shape checks before 013 migration.

    Validates:
    - SQLite version >= 3.42.0
    - unixepoch('subsec') returns real or integer (non-NULL)
    - CAST((unixepoch('subsec') * 1000) AS INTEGER) evaluates to 'integer'
    - Upstream 011 text intake migration shape matches approved reference exactly
    - Upstream 012 text range continuation migration shape matches approved reference exactly

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

    # Upstream dependency shape audits
    try:
        require_text_intake_shape(conn)
    except Exception as exc:
        raise ContractError(
            f"preflight failed: upstream text intake (011) shape audit failed: {exc}"
        ) from exc

    try:
        require_text_continuation_shape(conn)
    except Exception as exc:
        raise ContractError(
            f"preflight failed: upstream text continuation (012) shape audit failed: {exc}"
        ) from exc

    return (version_str, raw_subsec, subsec_type, ms_cast_type)


_APPROVED_SQL_CACHE: dict[tuple[str, str], str] | None = None


def approved_text_continuation_retrieval_sql() -> dict[tuple[str, str], str]:
    """Return normalized sqlite_master SQL produced by clean 001+011+012 then 013 execution."""
    global _APPROVED_SQL_CACHE
    if _APPROVED_SQL_CACHE is not None:
        return _APPROVED_SQL_CACHE

    reference = sqlite3.connect(":memory:")
    try:
        reference.execute("PRAGMA foreign_keys=ON")
        reference.executescript(SQL_001.read_text(encoding="utf-8"))
        reference.executescript(SQL_011.read_text(encoding="utf-8"))
        reference.executescript(SQL_012.read_text(encoding="utf-8"))
        before = _master_sql(reference)
        reference.executescript(SQL_013.read_text(encoding="utf-8"))
        after = _master_sql(reference)
    finally:
        reference.close()

    approved = {
        key: sql for key, sql in after.items()
        if before.get(key) != sql and key[1] not in SHADOW_TABLES_013 and not key[1].startswith("sqlite_autoindex")
    }
    names = {name for _type, name in approved}

    if not set(PRIMARY_TABLES_013).issubset(names):
        missing = set(PRIMARY_TABLES_013) - names
        raise TextContinuationRetrievalShapeError(f"continuation retrieval migration missing primary tables: {missing}")

    if not set(VIEWS_013).issubset(names):
        missing = set(VIEWS_013) - names
        raise TextContinuationRetrievalShapeError(f"continuation retrieval migration missing views: {missing}")

    if not set(TRIGGERS_013).issubset(names):
        missing = set(TRIGGERS_013) - names
        raise TextContinuationRetrievalShapeError(f"continuation retrieval migration missing triggers: {missing}")

    _APPROVED_SQL_CACHE = approved
    return approved


def require_text_continuation_retrieval_shape(conn: sqlite3.Connection) -> None:
    """Fail closed unless installed 013 objects match reference execution exactly.

    Verifies all 41 sentinels exist and non-shadow definitions match approved SQL.
    Does not write or perform silent auto-repair.
    """
    installed_names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE name IS NOT NULL")}
    missing_sentinels = SENTINELS_013 - installed_names
    if missing_sentinels:
        raise TextContinuationRetrievalShapeError(
            f"continuation retrieval migration sentinel missing: {sorted(missing_sentinels)}"
        )

    approved = approved_text_continuation_retrieval_sql()
    installed = _master_sql(conn)
    for key, sql in approved.items():
        if installed.get(key) != sql:
            raise TextContinuationRetrievalShapeError(
                f"continuation retrieval migration shape mismatch for {key}: expected {sql!r}, got {installed.get(key)!r}"
            )


def _split_sql_statements(script: str) -> list[str]:
    """Split SQL script into executable statements respecting trigger blocks and SQLite grammar."""
    statements: list[str] = []
    current: list[str] = []
    for line in script.splitlines(keepends=True):
        current.append(line)
        stmt = "".join(current)
        if sqlite3.complete_statement(stmt):
            stmt_strip = stmt.strip()
            if stmt_strip:
                statements.append(stmt_strip)
            current = []
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements
