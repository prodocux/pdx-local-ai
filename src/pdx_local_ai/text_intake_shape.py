"""Product shape check for migration 011.

The comparison matches the proposal-local reference: normalized
``sqlite_master.sql`` from a clean execution of 001 then 011. This module
does not rewrite objects.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from .paths import get_root

ROOT = get_root()
SQL_001 = ROOT / "sql" / "001_gate0.sql"
SQL_011 = ROOT / "sql" / "011_text_intake.sql"
TABLES = (
    "source_projection_owner",
    "text_projection",
    "text_block_instance",
    "text_block_fts",
    "text_fts_binding",
    "text_source_range",
    "text_coverage_disclosure",
    "text_coverage_limit",
    "text_projection_publication",
    "secret_denylist_audit",
)
TRIGGER_NAMES = (
    "text_projection_claim_owner",
    "projection_claim_owner",
    "text_block_instance_index",
    "text_projection_publication_guard",
    "source_projection_owner_update_forbidden",
    "source_projection_owner_delete_forbidden",
    "text_projection_publication_update_forbidden",
    "text_projection_publication_delete_forbidden",
    "text_source_range_delete_forbidden",
    "text_coverage_limit_delete_forbidden",
    "secret_denylist_audit_delete_forbidden",
)


class TextIntakeShapeError(RuntimeError):
    """011 is missing or its installed definitions differ from the reference."""


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())


def _master_sql(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
        for row in conn.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL")
    }


def approved_text_intake_sql() -> dict[tuple[str, str], str]:
    """Return the normalized SQL a clean 001+011 database must contain."""
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(SQL_001.read_text(encoding="utf-8"))
        before = _master_sql(reference)
        reference.executescript(SQL_011.read_text(encoding="utf-8"))
        after = _master_sql(reference)
    finally:
        reference.close()
    approved = {key: sql for key, sql in after.items() if before.get(key) != sql}
    names = {name for _type, name in approved}
    if not set(TABLES).issubset(names) or not set(TRIGGER_NAMES).issubset(names):
        raise TextIntakeShapeError("text intake migration is incomplete or incompatible")
    if ("view", "text_fts_drift") not in approved or ("table", "text_block_fts") not in approved:
        raise TextIntakeShapeError("text intake migration is incomplete or incompatible")
    return approved


def require_text_intake_shape(conn: sqlite3.Connection) -> None:
    """Fail when installed 011 definitions differ. Do not repair them."""
    approved = approved_text_intake_sql()
    installed = _master_sql(conn)
    for key, sql in approved.items():
        if installed.get(key) != sql:
            raise TextIntakeShapeError("text intake migration is incomplete or incompatible")
