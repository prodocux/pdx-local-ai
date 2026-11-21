"""Atomic text publication and rescan for Gate 5A-0 slice 4.

A successful publish is one transaction. The publication marker is the
last projection insert, and only that transaction moves
``file_record.current_source_version_id``. An unchanged hash is not
decoded or published again. A stale source writes no owner, source
version, staging row, marker, or pointer change.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .text_intake_decode import DecodeResult, decode_snapshot
from .text_intake_route import (
    ControlledSnapshot,
    _FILE_ATTRIBUTE_REPARSE_POINT,
    _handle_info,
    _kernel32,
    _mtime_ns,
    _size_of,
    _try_open_info,
    prepare_text_route,
)
from .validation import ContractError

_DISCLOSURE_SCHEMA = "pdx_local_text_coverage_ref_v1"
_FILETIME_TO_UNIX_NS = 11_644_473_600_000_000_000


@dataclass(frozen=True)
class TextPublishReceipt:
    outcome: str
    full_hash_count: int
    decode_count: int
    unchanged_count: int
    source_version_id: str | None
    projection_id: str | None
    current_source_version_id: str | None


def intake_text_file(
    conn: sqlite3.Connection,
    *,
    source_root_id: str,
    relative_path: str,
    before_precheck: Callable[[], None] | None = None,
    before_in_transaction_check: Callable[[], None] | None = None,
) -> TextPublishReceipt:
    """Route, hash, and either publish or record an unchanged rescan.

    Decode runs only when the full snapshot hash differs from the current
    source version. The source path is checked before the transaction and
    again inside it, before any publication row or pointer change. This
    does not change ``SUPPORTED`` or union retrieval.
    """
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    with prepare_text_route(conn, source_root_id=source_root_id, relative_path=relative_path) as routed:
        if routed.snapshot is None:
            return TextPublishReceipt(
                routed.disposition, 0, 0, 0, None, None,
                _current_pointer(conn, source_root_id, routed.relative_path),
            )
        snapshot = routed.snapshot
        current_id = _current_pointer(conn, source_root_id, snapshot.relative_path)
        if current_id is not None and _sha_of(conn, current_id) == snapshot.source_sha256:
            return TextPublishReceipt(
                "unchanged", 1, 0, 1, current_id, _projection_of(conn, current_id), current_id,
            )
        if before_precheck is not None:
            before_precheck()
        _require_current_source(snapshot)
        for _chunk in snapshot.iter_chunks(offset=0, limit=0):
            pass
        decoded = decode_snapshot(snapshot)
        return _publish(
            conn,
            source_root_id=source_root_id,
            snapshot=snapshot,
            decoded=decoded,
            before_in_transaction_check=before_in_transaction_check,
        )


def _publish(
    conn: sqlite3.Connection,
    *,
    source_root_id: str,
    snapshot: ControlledSnapshot,
    decoded: DecodeResult,
    before_in_transaction_check: Callable[[], None] | None,
) -> TextPublishReceipt:
    root = _root(conn, source_root_id)
    if conn.in_transaction:
        raise ContractError("text publication requires its own transaction")
    conn.execute("BEGIN")
    try:
        if before_in_transaction_check is not None:
            before_in_transaction_check()
        _require_current_source(snapshot)
        receipt = _write(conn, root, snapshot, decoded)
        conn.commit()
        return receipt
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def _write(
    conn: sqlite3.Connection,
    root: sqlite3.Row,
    snapshot: ControlledSnapshot,
    decoded: DecodeResult,
) -> TextPublishReceipt:
    now = _now()
    workspace_id = str(root["workspace_id"])
    source_root_id = str(root["source_root_id"])
    file_id = _ensure_file(conn, workspace_id, source_root_id, snapshot, now)
    source_id = str(uuid.uuid4())
    if decoded.outcome == "unsupported":
        _insert_source(
            conn, source_id, workspace_id, source_root_id, file_id, snapshot,
            "unsupported", "not_evaluated", 0,
            {"schema_version": _DISCLOSURE_SCHEMA, "reason": decoded.reason}, now,
        )
        _attempt(conn, workspace_id, source_root_id, file_id, snapshot.relative_path, source_id, "terminal_failed", decoded.reason, now)
        return TextPublishReceipt(
            "unsupported", 1, 1, 0, source_id, None, _current_pointer(conn, source_root_id, snapshot.relative_path),
        )
    if decoded.outcome != "decoded" or decoded.decoder_profile is None or decoded.coverage_disposition is None:
        raise ContractError("text publication has no decoded snapshot")
    projection_id = str(uuid.uuid4())
    disclosure_id = str(uuid.uuid4())
    _insert_source(
        conn, source_id, workspace_id, source_root_id, file_id, snapshot,
        "indexed", decoded.coverage_disposition, int(decoded.unknown_remainder),
        {"schema_version": _DISCLOSURE_SCHEMA, "text_disclosure_id": disclosure_id}, now,
    )
    conn.execute(
        "INSERT INTO text_projection VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            projection_id, workspace_id, source_root_id, file_id, source_id, snapshot.source_sha256,
            "pdx_local_text_decoder", "1", "pdx-local-ai", "pdx_local_text_projection_v1",
            decoded.decoder_profile, decoded.normalization_profile, len(decoded.blocks),
            "text_line_codepoint_v1", now,
        ),
    )
    for block in decoded.blocks:
        block_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO text_block_instance VALUES (?,?,?,?,?,?,?)",
            (block_id, workspace_id, projection_id, source_id, block.ordinal, block.text, block.text_sha256),
        )
        conn.execute(
            "INSERT INTO text_source_range VALUES (?,?,?,?,?,?,?,?)",
            (
                block_id, "text_line_codepoint_v1", workspace_id, projection_id,
                block.line_start, block.line_end_exclusive,
                block.source_codepoint_start, block.source_codepoint_end_exclusive,
            ),
        )
    conn.execute(
        "INSERT INTO text_coverage_disclosure VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            disclosure_id, workspace_id, source_root_id, file_id, source_id, projection_id,
            decoded.coverage_disposition, int(decoded.unknown_remainder), decoded.decoder_profile,
            1 if decoded.bom_removed else 0, decoded.normalization_profile,
        ),
    )
    for limit in decoded.limits:
        reached = None if limit.line_end_reached is None else int(limit.line_end_reached)
        conn.execute(
            "INSERT INTO text_coverage_limit VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                disclosure_id, limit.limit_name, limit.observed_count, limit.known_total,
                limit.omitted_start, limit.omitted_end_exclusive, limit.truncation_reason,
                limit.coordinate_space, limit.boundary, reached,
            ),
        )
    _attempt(conn, workspace_id, source_root_id, file_id, snapshot.relative_path, source_id, "succeeded", None, now)
    conn.execute(
        "INSERT INTO text_projection_publication VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), projection_id, disclosure_id, source_id, now),
    )
    conn.execute(
        "UPDATE file_record SET current_source_version_id=?, last_reconciled_at=? WHERE file_record_id=?",
        (source_id, now, file_id),
    )
    return TextPublishReceipt("published", 1, 1, 0, source_id, projection_id, source_id)


def _require_current_source(snapshot: ControlledSnapshot) -> None:
    kernel32 = _kernel32()
    handle = _try_open_info(kernel32, snapshot.final_path)
    if handle is None:
        raise ContractError("source is stale")
    try:
        info = _handle_info(kernel32, handle)
        identity = f"{info.nFileIndexHigh}:{info.nFileIndexLow}"
        if (
            info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or str(info.dwVolumeSerialNumber) != snapshot.volume_serial
            or identity != snapshot.file_index
            or _size_of(info) != snapshot.size
            or _mtime_ns(info) != snapshot.mtime_ns
        ):
            raise ContractError("source is stale")
    finally:
        kernel32.CloseHandle(handle)


def _root(conn: sqlite3.Connection, source_root_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT source_root_id, workspace_id, enabled FROM source_root WHERE source_root_id=?",
        (source_root_id,),
    ).fetchone()
    if row is None or int(row["enabled"]) != 1:
        raise ContractError("enabled source root not found")
    return row


def _ensure_file(
    conn: sqlite3.Connection,
    workspace_id: str,
    source_root_id: str,
    snapshot: ControlledSnapshot,
    now: str,
) -> str:
    row = conn.execute(
        "SELECT file_record_id FROM file_record WHERE source_root_id=? AND relative_path=?",
        (source_root_id, snapshot.relative_path),
    ).fetchone()
    if row is not None:
        return str(row["file_record_id"])
    file_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO file_record VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            file_id, workspace_id, source_root_id, snapshot.relative_path, "text/plain", "active",
            snapshot.volume_serial, snapshot.file_index, None, now,
        ),
    )
    root_cfg_row = conn.execute(
        "SELECT config_json FROM source_root WHERE source_root_id=?",
        (source_root_id,),
    ).fetchone()
    if root_cfg_row:
        try:
            root_cfg = json.loads(root_cfg_row[0])
            inherit_principal = root_cfg.get("inherit_read_principal")
            if inherit_principal:
                existing_acl = conn.execute(
                    "SELECT 1 FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=?",
                    (workspace_id, inherit_principal, file_id),
                ).fetchone()
                if existing_acl is None:
                    conn.execute(
                        "INSERT INTO file_acl VALUES (?,?,?,1)",
                        (workspace_id, inherit_principal, file_id),
                    )
        except Exception:
            pass
    return file_id


def _insert_source(
    conn: sqlite3.Connection,
    source_id: str,
    workspace_id: str,
    source_root_id: str,
    file_id: str,
    snapshot: ControlledSnapshot,
    status: str,
    disposition: str,
    remainder: int,
    disclosure: dict[str, str],
    now: str,
) -> None:
    conn.execute(
        "INSERT INTO source_version VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            source_id, workspace_id, source_root_id, file_id, snapshot.source_sha256, snapshot.size,
            snapshot.mtime_ns - _FILETIME_TO_UNIX_NS, snapshot.volume_serial, snapshot.file_index,
            status, disposition, remainder,
            json.dumps(disclosure, ensure_ascii=False, sort_keys=True, separators=(",", ":")), now,
        ),
    )


def _attempt(
    conn: sqlite3.Connection,
    workspace_id: str,
    source_root_id: str,
    file_id: str,
    relative_path: str,
    source_id: str,
    status: str,
    failure_code: str | None,
    now: str,
) -> None:
    number = conn.execute(
        "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM index_attempt WHERE file_record_id=?",
        (file_id,),
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO index_attempt VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(uuid.uuid4()), workspace_id, source_root_id, file_id, relative_path, status,
            int(number), source_id, failure_code, now, now,
        ),
    )


def _current_pointer(conn: sqlite3.Connection, source_root_id: str, relative_path: str | None) -> str | None:
    if relative_path is None:
        return None
    row = conn.execute(
        "SELECT current_source_version_id FROM file_record WHERE source_root_id=? AND relative_path=?",
        (source_root_id, relative_path),
    ).fetchone()
    if row is None or row["current_source_version_id"] is None:
        return None
    return str(row["current_source_version_id"])


def _sha_of(conn: sqlite3.Connection, source_version_id: str) -> str:
    row = conn.execute(
        "SELECT source_sha256 FROM source_version WHERE source_version_id=?",
        (source_version_id,),
    ).fetchone()
    return "" if row is None else str(row["source_sha256"])


def _projection_of(conn: sqlite3.Connection, source_version_id: str) -> str | None:
    row = conn.execute(
        "SELECT projection_id FROM text_projection WHERE source_version_id=?",
        (source_version_id,),
    ).fetchone()
    if row is None:
        return None
    return str(row["projection_id"])


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
