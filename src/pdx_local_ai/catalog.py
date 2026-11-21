from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import time
import unicodedata
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .kernel_adapter import KernelAdapter
from .provenance import create_index_provenance
from .text_continuation_retrieval_shape import (
    SENTINELS_013 as _TEXT_CONTINUATION_RETRIEVAL_SENTINELS,
    _split_sql_statements as _split_sql_statements_013,
    preflight_check as preflight_check_013,
    require_text_continuation_retrieval_shape,
)
from .text_continuation_shape import (
    SENTINELS_012 as _TEXT_CONTINUATION_SENTINELS,
    preflight_check,
    require_text_continuation_shape,
)
from .text_intake_publish import intake_text_file
from .text_intake_shape import require_text_intake_shape
from .validation import (
    ContractError,
    validate_citation_against_block,
    validate_retrieval_receipt,
    validate_relative_path,
    validate_source_root_path,
    validate_text_citation_against_block,
)

from .paths import get_root

ROOT = get_root()
SQL_FILES = [
    ROOT / "sql" / "001_gate0.sql",
    ROOT / "sql" / "002_gate2.sql",
    ROOT / "sql" / "003_memory.sql",
    ROOT / "sql" / "004_layered_memory.sql",
    ROOT / "sql" / "005_governed_memory.sql",
    ROOT / "sql" / "006_canonical_knowledge.sql",
    ROOT / "sql" / "007_governed_recall.sql",
    ROOT / "sql" / "008_vector_generation.sql",
    ROOT / "sql" / "011_text_intake.sql",
    ROOT / "sql" / "012_text_range_continuation.sql",
    ROOT / "sql" / "013_text_continuation_retrieval.sql",
    ROOT / "sql" / "014_source_root_coverage.sql",
]
_TEXT_INTAKE_SENTINELS = (
    "source_projection_owner",
    "text_projection",
    "text_block_fts",
    "text_fts_drift",
    "text_projection_publication_guard",
    "secret_denylist_audit",
)
SUPPORTED = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_json(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _uuid() -> str:
    return str(uuid.uuid4())


_LEXICAL_TIMEOUT = object()


_AUTHORIZED_FILES = """
WITH authorized_files AS (
  SELECT f.file_record_id, f.current_source_version_id
  FROM file_acl a JOIN file_record f ON f.file_record_id=a.file_record_id
  WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
    AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
  ORDER BY f.file_record_id LIMIT ?
)
"""
_KERNEL_LEXICAL_SQL = _AUTHORIZED_FILES + """
SELECT b.*, f.file_record_id, f.source_root_id, sv.source_sha256,
       p.parser_contract_name, p.parser_contract_version, bm25(block_fts) AS rank
FROM block_fts
JOIN block_instance b ON b.block_instance_id=block_fts.block_instance_id
JOIN authorized_files af ON af.current_source_version_id=b.source_version_id
JOIN file_record f ON f.file_record_id=af.file_record_id
JOIN source_version sv ON sv.source_version_id=b.source_version_id
JOIN projection p ON p.projection_id=b.projection_id
WHERE block_fts MATCH ?
ORDER BY rank, b.block_instance_id
LIMIT 1 OFFSET ?
"""
_TEXT_LEXICAL_SQL = _AUTHORIZED_FILES + """
SELECT b.block_instance_id, b.workspace_id, b.projection_id, b.source_version_id, b.text,
       f.file_record_id, f.source_root_id, f.current_source_version_id, sv.source_sha256,
       tp.parser_contract_name, tp.parser_contract_version,
       r.line_start, r.line_end_exclusive, r.source_codepoint_start, r.source_codepoint_end_exclusive,
       bm25(text_block_fts) AS rank
FROM text_block_fts
JOIN text_block_instance b ON b.block_instance_id=text_block_fts.block_instance_id
JOIN text_fts_binding bind ON bind.block_instance_id=b.block_instance_id
JOIN text_source_range r ON r.block_instance_id=b.block_instance_id
JOIN text_projection tp ON tp.projection_id=b.projection_id
JOIN text_projection_publication pub ON pub.projection_id=tp.projection_id
JOIN authorized_files af ON af.current_source_version_id=b.source_version_id
JOIN file_record f ON f.file_record_id=af.file_record_id
JOIN source_version sv ON sv.source_version_id=b.source_version_id
WHERE text_block_fts MATCH ?
  AND length(b.text) > 0
  AND NOT EXISTS (
    SELECT 1 FROM text_fts_drift d WHERE d.block_instance_id=b.block_instance_id
  )
ORDER BY rank, b.block_instance_id
LIMIT 1 OFFSET ?
"""


_VECTOR_GENERATION_COLUMNS = (
    ("generation_id", "TEXT", 1, None, 1),
    ("workspace_id", "TEXT", 1, None, 0),
    ("profile", "TEXT", 1, None, 0),
    ("backend_kind", "TEXT", 1, None, 0),
    ("dimensions", "INTEGER", 1, None, 0),
    ("encoding", "TEXT", 1, None, 0),
    ("normalization", "TEXT", 1, None, 0),
    ("metric", "TEXT", 1, None, 0),
    ("entry_count", "INTEGER", 1, None, 0),
    ("state", "TEXT", 1, None, 0),
    ("is_current", "INTEGER", 1, None, 0),
    ("build_manifest_digest", "TEXT", 1, None, 0),
    ("capability_digest", "TEXT", 1, None, 0),
    ("image_sha256", "TEXT", 1, None, 0),
    ("image_locator", "TEXT", 1, None, 0),
    ("image_byte_size", "INTEGER", 1, None, 0),
    ("purged_at", "TEXT", 1, None, 0),
    ("created_at", "TEXT", 1, None, 0),
    ("updated_at", "TEXT", 1, None, 0),
    ("audit_reconciliation_sha256", "TEXT", 1, None, 0),
)


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())


_APPROVED_VECTOR_GENERATION_SQL: dict[tuple[str, str], str] | None = None


def _approved_vector_generation_sql() -> dict[tuple[str, str], str]:
    """Normalized sqlite_master text produced by executing migration 008."""
    global _APPROVED_VECTOR_GENERATION_SQL
    if _APPROVED_VECTOR_GENERATION_SQL is not None:
        return _APPROVED_VECTOR_GENERATION_SQL
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript((ROOT / "sql" / "008_vector_generation.sql").read_text(encoding="utf-8"))
        approved = {
            (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
            for row in reference.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE tbl_name = 'vector_generation' AND sql IS NOT NULL
                """
            )
        }
    finally:
        reference.close()
    if set(approved) != {
        ("table", "vector_generation"),
        ("index", "vector_generation_one_current"),
        ("trigger", "vector_generation_identity_immutable"),
        ("trigger", "vector_generation_state_machine"),
    }:
        raise ContractError("vector_generation migration is incomplete or incompatible")
    _APPROVED_VECTOR_GENERATION_SQL = approved
    return approved


def _installed_vector_generation_sql(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
        for row in conn.execute(
            """
            SELECT type, name, sql FROM sqlite_master
            WHERE tbl_name = 'vector_generation' AND sql IS NOT NULL
            """
        )
    }


def require_vector_generation_shape(conn: sqlite3.Connection) -> None:
    """Fail closed unless the installed generation table matches migration 008."""
    columns = [
        (row[1], row[2], row[3], row[4], row[5])
        for row in conn.execute("PRAGMA table_info(vector_generation)")
    ]
    if columns != list(_VECTOR_GENERATION_COLUMNS):
        raise ContractError("vector_generation migration is incomplete or incompatible")
    indexes = {
        row[1]: row
        for row in conn.execute("PRAGMA index_list(vector_generation)")
    }
    current = indexes.get("vector_generation_one_current")
    if current is None or current[2] != 1 or current[4] != 1:
        raise ContractError("vector_generation migration is incomplete or incompatible")
    index_columns = [
        row[2] for row in conn.execute("PRAGMA index_info(vector_generation_one_current)")
    ]
    if index_columns != ["workspace_id", "profile"]:
        raise ContractError("vector_generation migration is incomplete or incompatible")
    if "sqlite_autoindex_vector_generation_1" not in indexes:
        raise ContractError("vector_generation migration is incomplete or incompatible")
    if _installed_vector_generation_sql(conn) != _approved_vector_generation_sql():
        raise ContractError("vector_generation migration is incomplete or incompatible")


def apply_migrations(
    conn: sqlite3.Connection,
    _migration_013_statement_hook: "Callable[[int, str], None] | None" = None,
) -> None:
    """Apply all pending schema migrations to *conn*.

    Parameters
    ----------
    conn:
        Open SQLite connection with ``isolation_level=None`` (autocommit disabled
        externally by the caller, or managed inside this function).
    _migration_013_statement_hook:
        **Test-only parameter** — never pass this in production code.
        If provided, called as ``hook(statement_index, sql_text)`` before each
        DDL statement inside the 013 BEGIN IMMEDIATE block, allowing tests to
        raise an exception at a specific index to verify mid-transaction rollback.
        The parameter is intentionally positional-keyword with a leading underscore
        to signal its non-public status.
    """
    for sql_file in SQL_FILES:
        if sql_file.name == "013_text_continuation_retrieval.sql":
            preflight_check_013(conn)
            placeholders = ",".join("?" for _ in _TEXT_CONTINUATION_RETRIEVAL_SENTINELS)
            present = conn.execute(
                f"SELECT 1 FROM sqlite_master WHERE name IN ({placeholders})",
                list(_TEXT_CONTINUATION_RETRIEVAL_SENTINELS),
            ).fetchone()
            if present is None:
                statements = _split_sql_statements_013(sql_file.read_text(encoding="utf-8"))
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for idx, stmt in enumerate(statements):
                        if _migration_013_statement_hook is not None:
                            _migration_013_statement_hook(idx, stmt)
                        conn.execute(stmt)
                    require_text_continuation_retrieval_shape(conn)
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise
            else:
                require_text_continuation_retrieval_shape(conn)
            continue
        if sql_file.name == "012_text_range_continuation.sql":
            preflight_check(conn)
            placeholders = ",".join("?" for _ in _TEXT_CONTINUATION_SENTINELS)
            present = conn.execute(
                f"SELECT 1 FROM sqlite_master WHERE name IN ({placeholders})",
                _TEXT_CONTINUATION_SENTINELS,
            ).fetchone()
            if present is None:
                atomic_script = f"BEGIN IMMEDIATE;\n{sql_file.read_text(encoding='utf-8')}\nCOMMIT;\n"
                try:
                    conn.executescript(atomic_script)
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            require_text_continuation_shape(conn)
            continue
        if sql_file.name == "011_text_intake.sql":
            placeholders = ",".join("?" for _ in _TEXT_INTAKE_SENTINELS)
            present = conn.execute(
                f"SELECT 1 FROM sqlite_master WHERE name IN ({placeholders})",
                _TEXT_INTAKE_SENTINELS,
            ).fetchone()
            if present is None:
                conn.executescript(sql_file.read_text(encoding="utf-8"))
            require_text_intake_shape(conn)
            continue
        if sql_file.name == "014_source_root_coverage.sql":
            present = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'source_root_coverage'"
            ).fetchone()
            if present is None:
                conn.executescript(sql_file.read_text(encoding="utf-8"))
            continue
        if sql_file.name != "008_vector_generation.sql":
            conn.executescript(sql_file.read_text(encoding="utf-8"))
            continue
        present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vector_generation'"
        ).fetchone()
        if present is None:
            conn.executescript(sql_file.read_text(encoding="utf-8"))
        require_vector_generation_shape(conn)
    conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")


@dataclass(frozen=True)
class RetrievalLimits:
    metadata_candidates: int = 100
    lexical_candidates: int = 30
    opened_files: int = 5
    opened_blocks: int = 8
    returned_bytes: int = 40_000
    elapsed_ms: int = 3_000
    deadline_perf: float | None = None

    def validate(self) -> None:
        for key, value in asdict(self).items():
            if key == "deadline_perf":
                if value is not None:
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(value)
                        or value <= 0.0
                    ):
                        raise ContractError("deadline_perf must be a finite positive number and not bool")
                continue
            if value < (1 if key in {"metadata_candidates", "lexical_candidates", "elapsed_ms"} else 0):
                raise ContractError(f"invalid retrieval limit: {key}")


_SUPPORTED_LIMITS_CEILINGS: dict[str, int] = {
    "metadata_candidates": 1000,
    "lexical_candidates": 200,
    "opened_files": 50,
    "opened_blocks": 100,
    "returned_bytes": 524288,
    "elapsed_ms": 60000,
}
SUPPORTED_LIMITS_CEILINGS = dict(_SUPPORTED_LIMITS_CEILINGS)


def validate_supported_limits(limits: RetrievalLimits) -> None:
    limits.validate()
    for key, max_val in _SUPPORTED_LIMITS_CEILINGS.items():
        actual = getattr(limits, key)
        if actual > max_val:
            raise ContractError(f"retrieval limit exceeds supported ceiling: {key}={actual} > {max_val}")


CURRENT_SCHEMA_VERSION = 14


class SourceChanged(RuntimeError):
    pass


class Catalog:
    def __init__(self, database: str | Path, *, extractor: Callable[[str, bytes], dict[str, Any]] | None = None, format_adapter: Any = None) -> None:
        if format_adapter is not None and extractor is not None:
            raise ContractError("choose extractor or format_adapter")
        self._format_adapter = format_adapter
        if format_adapter is not None:
            extractor = format_adapter
        self.database = str(database)
        self.conn = sqlite3.connect(self.database)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        db_version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if db_version > CURRENT_SCHEMA_VERSION:
            self.conn.close()
            raise ContractError(
                f"Database schema version {db_version} is newer than supported version {CURRENT_SCHEMA_VERSION}; refusing to open."
            )
        try:
            apply_migrations(self.conn)
        except Exception:
            self.conn.close()
            raise
        self._kernel_adapter: KernelAdapter | None = None
        if extractor is None:
            self._kernel_adapter = KernelAdapter(
                engine_database=self.database,
                engine_artifact_root=Path(self.database).with_suffix(".engine-artifacts"),
            )
            self.extractor = self._kernel_adapter.extract
        else:
            self.extractor = extractor

        from .text_continuation_retrieval import ContinuationRetrievalEngine
        self._retrieval_engine = ContinuationRetrievalEngine(self.conn)

    def close(self) -> None:
        if self._kernel_adapter is not None:
            self._kernel_adapter.close()
        self.conn.close()

    def add_root(
        self,
        *,
        workspace_id: str,
        canonical_path: str,
        inherit_read_principal: str | None = None,
    ) -> str:
        validate_source_root_path(canonical_path)
        root = Path(canonical_path)
        if not root.is_dir():
            raise ContractError("source root does not exist or is not a directory")
        self._reject_reparse_chain(root)
        root_id = _uuid()
        config = {
            "schema_version": "pdx_local_source_root_v1",
            "workspace_id": workspace_id,
            "source_root_id": root_id,
            "canonical_path": canonical_path,
            "enabled": True,
            "reparse_policy": "reject",
            "allow_unc": False,
            "allow_device_paths": False,
            "allow_alternate_data_streams": False,
            "inherit_read_principal": inherit_read_principal,
        }
        with self.conn:
            self.conn.execute(
                "INSERT INTO source_root VALUES (?,?,?,?,?,?)",
                (root_id, workspace_id, canonical_path, 1, _json(config), _now()),
            )
        return root_id

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        info = os.lstat(path)
        return bool(getattr(info, "st_file_attributes", 0) & REPARSE) or stat.S_ISLNK(info.st_mode)

    def _reject_reparse_chain(self, path: Path) -> None:
        resolved = path.absolute()
        chain = list(resolved.parents)
        for item in reversed(chain[:-1]):
            if item.exists() and self._is_reparse(item):
                raise ContractError(f"reparse-point ancestor rejected: {item}")
        if self._is_reparse(resolved):
            raise ContractError("source root is a reparse point")

    @property
    def supported(self):
        adapter = getattr(self, "_format_adapter", None)
        return SUPPORTED if adapter is None else {**SUPPORTED, **adapter.media}

    def _enumerate(self, root: Path, *, extensions=None) -> Iterable[Path]:
        supported = self.supported if extensions is None else extensions
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(
                name for name in dirs
                if not self._is_reparse(current_path / name)
            )
            for name in sorted(files):
                path = current_path / name
                if path.suffix.lower() not in supported or self._is_reparse(path):
                    continue
                yield path

    def _enumerate_routed(self, root: Path) -> Iterable[Path]:
        """Files outside kernel ``SUPPORTED``. Format routing handles them."""
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(
                name for name in dirs
                if not self._is_reparse(current_path / name)
            )
            for name in sorted(files):
                path = current_path / name
                if path.suffix.lower() in self.supported or self._is_reparse(path):
                    continue
                yield path

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[str, str]:
        return str(info.st_dev), str(info.st_ino)

    @staticmethod
    def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    def _read_stable(self, root: Path, path: Path) -> tuple[bytes, os.stat_result, str]:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        if resolved_root != resolved and resolved_root not in resolved.parents:
            raise ContractError("resolved file escaped source root")
        if self._is_reparse(path):
            raise ContractError("reparse-point file rejected")
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            self._verify_open_handle_path(handle.fileno(), path, resolved_root)
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                chunks.append(chunk)
                digest.update(chunk)
            after = os.fstat(handle.fileno())
        current = os.stat(path, follow_symlinks=False)
        if self._stat_identity(before) != self._stat_identity(after) or self._stat_identity(after) != self._stat_identity(current):
            raise SourceChanged("source changed while creating controlled byte snapshot")
        return b"".join(chunks), after, digest.hexdigest()

    @staticmethod
    def _verify_open_handle_path(file_descriptor: int, expected_path: Path, resolved_root: Path) -> None:
        """Bind validation to the opened Windows handle, not a prior pathname check."""
        if os.name != "nt":
            return
        import ctypes
        import msvcrt
        from ctypes import wintypes

        get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_final_path.restype = wintypes.DWORD
        os_handle = msvcrt.get_osfhandle(file_descriptor)
        needed = get_final_path(os_handle, None, 0, 0)
        if not needed:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(needed + 1)
        written = get_final_path(os_handle, buffer, len(buffer), 0)
        if not written or written >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        final_name = buffer.value
        Catalog._validate_final_handle_path(final_name, expected_path, resolved_root)

    @staticmethod
    def _validate_final_handle_path(final_name: str, expected_path: Path, resolved_root: Path) -> None:
        """Validate the namespace and containment of a resolved Windows handle path."""
        if final_name.startswith("\\\\?\\UNC\\"):
            raise ContractError("opened handle resolved to UNC storage")
        if final_name.startswith("\\\\?\\"):
            final_name = final_name[4:]
        final_path = Path(final_name)

        def canonical_windows_name(path: Path) -> Path:
            # realpath expands Windows 8.3 short-name components (e.g. a user
            # directory alias) while preserving the path-based containment
            # check. The file is already open and its identity is checked
            # independently.
            return Path(os.path.normcase(os.path.realpath(os.path.abspath(path))))

        expected = canonical_windows_name(expected_path)
        actual = canonical_windows_name(final_path)
        root = canonical_windows_name(resolved_root)
        if actual != expected:
            raise SourceChanged("opened handle final path differs from validated path")
        if root != actual and root not in actual.parents:
            raise ContractError("opened handle escaped source root")

    def _upsert_file_record(
        self, *, workspace_id: str, root_id: str, relative: str,
        media_type: str, volume: str, file_identity: str,
        discovered_relatives: set[str],
    ) -> str:
        row = self.conn.execute(
            "SELECT file_record_id FROM file_record WHERE source_root_id=? AND relative_path=?",
            (root_id, relative),
        ).fetchone()
        if row:
            return str(row[0])
        rename_rows = self.conn.execute(
            "SELECT file_record_id, relative_path FROM file_record WHERE source_root_id=? AND volume_identity=? AND file_identity=? AND catalog_status!='deleted'",
            (root_id, volume, file_identity),
        ).fetchall()
        rename = next((item for item in rename_rows if str(item["relative_path"]) not in discovered_relatives), None)
        if rename is not None:
            file_id = str(rename["file_record_id"])
            with self.conn:
                self.conn.execute(
                    "UPDATE file_record SET relative_path=?, media_type=?, catalog_status='active', last_reconciled_at=? WHERE file_record_id=?",
                    (relative, media_type, _now(), file_id),
                )
            return file_id
        file_id = _uuid()
        with self.conn:
            self.conn.execute(
                "INSERT INTO file_record VALUES (?,?,?,?,?,?,?,?,?,?)",
                (file_id, workspace_id, root_id, relative, media_type, "active", volume, file_identity, None, _now()),
            )
            root_cfg_row = self.conn.execute(
                "SELECT config_json FROM source_root WHERE source_root_id=?",
                (root_id,),
            ).fetchone()
            if root_cfg_row:
                try:
                    root_cfg = json.loads(root_cfg_row[0])
                    inherit_principal = root_cfg.get("inherit_read_principal")
                    if inherit_principal:
                        existing_acl = self.conn.execute(
                            "SELECT 1 FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
                            (workspace_id, inherit_principal, file_id),
                        ).fetchone()
                        if existing_acl is None:
                            self.conn.execute(
                                "INSERT INTO file_acl VALUES (?,?,?,1)",
                                (workspace_id, inherit_principal, file_id),
                            )
                except Exception:
                    pass
        return file_id

    def _attempt(self, *, workspace_id: str, root_id: str, file_id: str | None, relative: str) -> str:
        attempt_id = _uuid()
        attempt_number = self.conn.execute(
            "SELECT count(*)+1 FROM index_attempt WHERE source_root_id=? AND relative_path=?",
            (root_id, relative),
        ).fetchone()[0]
        now = _now()
        with self.conn:
            self.conn.execute(
                "INSERT INTO index_attempt VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (attempt_id, workspace_id, root_id, file_id, relative, "running", attempt_number, None, None, now, now),
            )
        return attempt_id

    def _finish_attempt(self, attempt_id: str, status: str, *, version_id: str | None = None, code: str | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE index_attempt SET status=?, observed_source_version_id=?, failure_code=?, updated_at=? WHERE index_attempt_id=?",
                (status, version_id, code, _now(), attempt_id),
            )

    def scan(
        self,
        *,
        source_root_id: str,
        raise_on_error: bool = False,
        on_file_event: Callable[[str, str | None, str, str, str | None], None] | None = None,
    ) -> dict[str, int]:
        root_row = self.conn.execute(
            "SELECT * FROM source_root WHERE source_root_id=? AND enabled=1", (source_root_id,)
        ).fetchone()
        if not root_row:
            raise ContractError("enabled source root not found")
        root = Path(root_row["canonical_path"])
        self._reject_reparse_chain(root)
        discovered = list(self._enumerate(root))
        seen: set[str] = set()
        counts = {"indexed": 0, "unchanged": 0, "stale": 0, "failed": 0, "missing": 0}
        csv_paths: list[Path] = []
        for path in self._enumerate_routed(root):
            relative = str(path.relative_to(root)).replace("/", "\\")
            if on_file_event:
                on_file_event(relative, None, "processing", "scan", None)
            try:
                validate_relative_path(relative)
                receipt = intake_text_file(
                    self.conn, source_root_id=source_root_id, relative_path=relative,
                )
            except ContractError as err:
                counts["stale"] += 1
                if on_file_event:
                    on_file_event(relative, None, "failed", "intake", str(err))
                if raise_on_error:
                    raise
                continue
            except Exception as err:
                counts["failed"] += 1
                if on_file_event:
                    on_file_event(relative, None, "failed", "intake", str(err))
                if raise_on_error:
                    raise
                continue
            if path.suffix.lower() == ".csv":
                if receipt.outcome == "kernel":
                    csv_paths.append(path)
                continue
            if receipt.outcome == "published":
                counts["indexed"] += 1
            elif receipt.outcome == "unchanged":
                counts["unchanged"] += 1
            elif receipt.outcome == "unsupported":
                row = self.conn.execute(
                    "SELECT file_record_id FROM file_record WHERE source_root_id=? AND relative_path=?",
                    (source_root_id, relative),
                ).fetchone()
                if row is not None:
                    f_rec_id = str(row["file_record_id"])
                    seen.add(f_rec_id)
                    if on_file_event:
                        on_file_event(relative, f_rec_id, "failed", "intake", "UNSUPPORTED_TEXT_PAYLOAD")
                else:
                    if on_file_event:
                        on_file_event(relative, None, "succeeded", "skipped", None)
                continue
            row = self.conn.execute(
                "SELECT file_record_id FROM file_record WHERE source_root_id=? AND relative_path=?",
                (source_root_id, relative),
            ).fetchone()
            if row is not None:
                f_rec_id = str(row["file_record_id"])
                seen.add(f_rec_id)
                if on_file_event:
                    on_file_event(relative, f_rec_id, "succeeded", "intake", None)
        discovered_relatives = {
            str(path.relative_to(root)).replace("/", "\\") for path in (*discovered, *csv_paths)
        }
        for path in discovered:
            self._index_kernel_file(
                root=root, root_row=root_row, source_root_id=source_root_id, path=path,
                media_type=self.supported[path.suffix.lower()], discovered_relatives=discovered_relatives,
                seen=seen, counts=counts, raise_on_error=raise_on_error,
                on_file_event=on_file_event,
            )
        for path in csv_paths:
            self._index_kernel_file(
                root=root, root_row=root_row, source_root_id=source_root_id, path=path,
                media_type="text/csv", discovered_relatives=discovered_relatives,
                seen=seen, counts=counts, raise_on_error=raise_on_error,
                on_file_event=on_file_event,
            )
        from .archive_host import consume_opted_in_archives
        consume_opted_in_archives(self, root_row, seen)
        now = _now()
        rows = self.conn.execute(
            "SELECT file_record_id FROM file_record WHERE source_root_id=? AND catalog_status='active'",
            (source_root_id,),
        ).fetchall()
        missing = [str(row[0]) for row in rows if str(row[0]) not in seen]
        with self.conn:
            for file_id in missing:
                self.conn.execute(
                    "UPDATE file_record SET catalog_status='missing', last_reconciled_at=? WHERE file_record_id=?",
                    (now, file_id),
                )
        counts["missing"] = len(missing)
        return counts

    def _index_kernel_file(
        self, *, root: Path, root_row: sqlite3.Row, source_root_id: str, path: Path,
        media_type: str, discovered_relatives: set[str], seen: set[str],
        counts: dict[str, int], raise_on_error: bool,
        on_file_event: Callable[[str, str | None, str, str, str | None], None] | None = None,
    ) -> None:
        """Existing Kernel extraction path. Callers run the denylist before CSV reaches here."""
        relative = str(path.relative_to(root)).replace("/", "\\")
        validate_relative_path(relative)
        info = os.stat(path, follow_symlinks=False)
        volume, identity = self._identity(info)
        file_id = self._upsert_file_record(
            workspace_id=root_row["workspace_id"], root_id=source_root_id,
            relative=relative, media_type=media_type, volume=volume, file_identity=identity,
            discovered_relatives=discovered_relatives,
        )
        seen.add(file_id)
        if on_file_event:
            on_file_event(relative, file_id, "processing", "scan", None)
        attempt_id = self._attempt(
            workspace_id=root_row["workspace_id"], root_id=source_root_id,
            file_id=file_id, relative=relative,
        )
        try:
            payload, stable, source_sha = self._read_stable(root, path)
            current = self.conn.execute(
                "SELECT sv.source_sha256 FROM file_record f LEFT JOIN source_version sv ON sv.source_version_id=f.current_source_version_id WHERE f.file_record_id=?",
                (file_id,),
            ).fetchone()
            if current and current[0] == source_sha:
                with self.conn:
                    self.conn.execute(
                        "UPDATE file_record SET catalog_status='active', relative_path=?, volume_identity=?, file_identity=?, last_reconciled_at=? WHERE file_record_id=?",
                        (relative, str(stable.st_dev), str(stable.st_ino), _now(), file_id),
                    )
                self._finish_attempt(attempt_id, "succeeded")
                counts["unchanged"] += 1
                if on_file_event:
                    on_file_event(relative, file_id, "succeeded", "scan", None)
                return
            kernel_result = self.extractor(path.name, payload)
            if kernel_result.get("source_sha256") != source_sha:
                raise RuntimeError("Kernel source digest mismatch")
            after_extract = os.stat(path, follow_symlinks=False)
            if self._stat_identity(after_extract) != self._stat_identity(stable):
                raise SourceChanged("source changed after snapshot and before publication")
            self._publish(
                root_row=root_row, file_id=file_id, relative=relative,
                attempt_id=attempt_id,
                source_sha=source_sha, stable=stable, kernel_result=kernel_result,
            )
            counts["indexed"] += 1
            if on_file_event:
                on_file_event(relative, file_id, "succeeded", "scan", None)
        except SourceChanged:
            self._finish_attempt(attempt_id, "stale", code="SOURCE_CHANGED")
            counts["stale"] += 1
            if on_file_event:
                on_file_event(relative, file_id, "failed", "scan", "SOURCE_CHANGED")
        except Exception as e:
            self._finish_attempt(attempt_id, "retryable_failed", code="INDEX_FAILED")
            counts["failed"] += 1
            if on_file_event:
                on_file_event(relative, file_id, "failed", "scan", str(e))
            if raise_on_error:
                raise

    def grant_read_access(self, *, workspace_id: str, principal_id: str, file_record_id: str) -> None:
        """Trusted control-plane operation; scanning never grants its caller access."""
        row = self.conn.execute(
            "SELECT 1 FROM file_record WHERE workspace_id=? AND file_record_id=?",
            (workspace_id, file_record_id),
        ).fetchone()
        if row is None:
            raise ContractError("file record does not belong to workspace")
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO file_acl VALUES (?,?,?,1)",
                (workspace_id, principal_id, file_record_id),
            )

    def revoke_read_access(self, *, workspace_id: str, principal_id: str, file_record_id: str) -> None:
        """Trusted control-plane operation; explicitly revokes read access (can_read=0)."""
        row = self.conn.execute(
            "SELECT 1 FROM file_record WHERE workspace_id=? AND file_record_id=?",
            (workspace_id, file_record_id),
        ).fetchone()
        if row is None:
            raise ContractError("file record does not belong to workspace")
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO file_acl VALUES (?,?,?,0)",
                (workspace_id, principal_id, file_record_id),
            )

    def _publish(
        self, *, root_row: sqlite3.Row, file_id: str, relative: str,
        attempt_id: str, source_sha: str,
        stable: os.stat_result, kernel_result: dict[str, Any]
    ) -> None:
        version_id, projection_id = _uuid(), _uuid()
        now = _now()
        canonical_kernel = _json(kernel_result)
        kernel_digest = hashlib.sha256(canonical_kernel.encode("utf-8")).hexdigest()
        parser = kernel_result.get("parser_contract")
        parser_label = ""
        if isinstance(parser, dict) and parser.get("name"):
            parser_label = f"{parser['name']}@{parser.get('version', '')}"
        provenance = create_index_provenance(
            attempt_id=attempt_id, source_version_id=version_id,
            projection_id=projection_id, source_sha256=source_sha,
            projection_sha256=kernel_digest, generated_at=now,
            parser_contract=parser_label,
            archive_profile=str(kernel_result.get("archive_profile") or "not_applicable"),
            catalog_revision=str(kernel_result.get("catalog_revision") or ""),
        )
        text_items = kernel_result.get("text_items") or []
        if kernel_result.get("schema_version") == "pdx_local_kernel_projection_aggregate_v1":
            coverage = str(kernel_result["coverage"]["disposition"])
            is_incomplete = coverage != "complete"
            unknown_remainder = coverage == "partial_unknown"
            parser_contract = kernel_result["parser_contract"]
            disclosure = {
                "truncation_reason_codes": list(kernel_result["coverage"]["warnings"]),
                "observed_limits": {"ranges": len(kernel_result["ranges"])},
                "processed_counts": kernel_result["counts"]["processed_through_range_end"],
                "known_total_counts": kernel_result["counts"]["known_total"],
                "is_incomplete": is_incomplete,
                "unknown_remainder": unknown_remainder,
                "omitted_content_classes": kernel_result["coverage"]["omitted_content_classes"],
                "ocr_disposition": kernel_result["ocr_disposition"],
            }
        else:
            truncated = bool(kernel_result.get("truncated"))
            is_incomplete = truncated
            unknown_remainder = truncated
            # Published rc8 has no continuation metadata; preserve fail-closed behavior.
            coverage = "partial_unknown" if truncated else "complete"
            parser_contract = {"name": "prodocux_content_blocks_v1", "version": "v1"}
            disclosure = {
                "truncation_reason_codes": ["KERNEL_BOUNDED_OUTPUT"] if truncated else [],
                "observed_limits": {},
                "processed_counts": {"blocks": len(text_items)},
                "known_total_counts": {"blocks": None if truncated else len(text_items)},
                "is_incomplete": is_incomplete,
                "unknown_remainder": unknown_remainder,
            }
        blocks: list[tuple[Any, ...]] = []
        for ordinal, item in enumerate(text_items):
            text = str(item.get("text") or "")
            block_id = _uuid()
            blocks.append((
                block_id, root_row["workspace_id"], version_id, projection_id,
                ordinal, str(item.get("type") or "text"), text,
                hashlib.sha256(text.encode("utf-8")).hexdigest(), "structural",
                str(item.get("source_locator") or item.get("id") or ordinal),
            ))
        with self.conn:
            self.conn.execute(
                "INSERT INTO source_version VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (version_id, root_row["workspace_id"], root_row["source_root_id"], file_id,
                 source_sha, stable.st_size, stable.st_mtime_ns, str(stable.st_dev), str(stable.st_ino),
                 "indexed", coverage, int(unknown_remainder), _json(disclosure), now),
            )
            self.conn.execute(
                "INSERT INTO projection VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (projection_id, version_id, source_sha, parser_contract["name"], parser_contract["version"],
                 str(kernel_result["kernel_version"]), len(blocks), kernel_digest,
                 _json(provenance), provenance["bundle_digest"], now),
            )
            self.conn.executemany("INSERT INTO block_instance VALUES (?,?,?,?,?,?,?,?,?,?)", blocks)
            self.conn.executemany(
                "INSERT INTO block_fts(block_instance_id,text) VALUES (?,?)",
                [(row[0], row[6]) for row in blocks],
            )
            self.conn.execute(
                "UPDATE file_record SET relative_path=?, catalog_status='active', volume_identity=?, file_identity=?, current_source_version_id=?, last_reconciled_at=? WHERE file_record_id=?",
                (relative, str(stable.st_dev), str(stable.st_ino), version_id, now, file_id),
            )
            self.conn.execute(
                "UPDATE index_attempt SET status='succeeded', observed_source_version_id=?, updated_at=? WHERE index_attempt_id=?",
                (version_id, now, attempt_id),
            )

    @staticmethod
    def _fts_query(query: str) -> str:
        tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
        if not tokens:
            raise ContractError("query has no searchable tokens")
        return " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens[:32])

    def _next_lexical_row(
        self, side: str, *, workspace_id: str, principal_id: str, source_root_id: str,
        fts_query: str, metadata_candidates: int, offset: int,
    ) -> sqlite3.Row | None | object:
        return self._retrieval_engine._next_lexical_row(
            side,
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            fts_query=fts_query,
            metadata_candidates=metadata_candidates,
            offset=offset,
        )

    def retrieve(
        self, *, workspace_id: str, principal_id: str, source_root_id: str,
        query: str, limits: RetrievalLimits | None = None
    ) -> dict[str, Any]:
        """Run authorization, fail-closed validation, 3-stream FTS, citations, and receipt in one SQLite snapshot."""
        limits = limits or RetrievalLimits()
        validate_supported_limits(limits)
        return self._retrieval_engine.retrieve(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query=query,
            limits=limits,
        )

    def _retrieve_snapshot(
        self, *, workspace_id: str, principal_id: str, source_root_id: str,
        query: str, limits: RetrievalLimits | None = None
    ) -> dict[str, Any]:
        limits = limits or RetrievalLimits()
        validate_supported_limits(limits)
        return self._retrieval_engine._retrieve_snapshot(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query=query,
            limits=limits,
        )
