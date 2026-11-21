"""Non-committing Catalog retrieval for a caller-owned snapshot."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import unicodedata
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .validation import ContractError, validate_citation_against_block, validate_retrieval_receipt
from .paths import get_root

ROOT = get_root()
MIGRATION = ROOT / "sql" / "010_catalog_coverage_disclosure.sql"
BUDGET_PROFILE_SHA256 = "c50d0974b4cc27008070347a5a1c05d65353f8ce763342250e7e885d1eed7235"
METADATA_LIMIT = 100
LEXICAL_LIMIT = 30
_SHAPE_OBJECTS = {
    ("table", "catalog_coverage_disclosure"),
    ("index", "catalog_coverage_disclosure_one_receipt"),
    ("trigger", "catalog_coverage_disclosure_update_forbidden"),
    ("trigger", "catalog_coverage_disclosure_delete_forbidden"),
    ("trigger", "catalog_coverage_disclosure_insert_binding"),
}
_DISPOSITIONS = {"complete", "partial_known", "partial_unknown", "not_evaluated"}
_fail_checkpoint: str | None = None
_approved_sql: dict[tuple[str, str], str] | None = None


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _compact_sql(sql: str) -> str:
    return " ".join(sql.split())


def _deadline_reached(deadline: float, checkpoint: str, clock: Callable[[], float]) -> bool:
    return _fail_checkpoint == checkpoint or clock() >= deadline


def _ensure_deadline(deadline: float, checkpoint: str, clock: Callable[[], float]) -> None:
    if _deadline_reached(deadline, checkpoint, clock):
        raise ContractError("catalog snapshot deadline passed")


def _approved_disclosure_sql() -> dict[tuple[str, str], str]:
    global _approved_sql
    if _approved_sql is not None:
        return _approved_sql
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(MIGRATION.read_text(encoding="utf-8"))
        approved = {
            (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
            for row in reference.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE tbl_name = 'catalog_coverage_disclosure' AND sql IS NOT NULL
                """
            )
        }
    finally:
        reference.close()
    if set(approved) != _SHAPE_OBJECTS:
        raise ContractError("catalog coverage disclosure migration is incomplete or incompatible")
    _approved_sql = approved
    return approved


def _installed_disclosure_sql(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    return {
        (str(row[0]), str(row[1])): _compact_sql(str(row[2]))
        for row in conn.execute(
            """
            SELECT type, name, sql FROM sqlite_master
            WHERE tbl_name = 'catalog_coverage_disclosure' AND sql IS NOT NULL
            """
        )
    }


def require_catalog_coverage_disclosure_shape(conn: sqlite3.Connection) -> None:
    """Fail closed unless the installed disclosure objects match migration 010."""
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise ContractError("catalog snapshot requires foreign keys")
    if _installed_disclosure_sql(conn) != _approved_disclosure_sql():
        raise ContractError("catalog coverage disclosure migration is incomplete or incompatible")
    indexes = {row[1]: row for row in conn.execute("PRAGMA index_list(catalog_coverage_disclosure)")}
    receipt_index = indexes.get("catalog_coverage_disclosure_one_receipt")
    if receipt_index is None or receipt_index[2] != 1:
        raise ContractError("catalog coverage disclosure migration is incomplete or incompatible")


def _fts_query(query: str) -> str:
    tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    if not tokens:
        raise ContractError("query has no searchable tokens")
    return " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens[:32])


def _limits(value: dict[str, Any]) -> dict[str, int]:
    required = (
        "metadata_candidates",
        "lexical_candidates",
        "opened_files",
        "opened_blocks",
        "returned_bytes",
        "elapsed_ms",
    )
    if set(value) != set(required):
        raise ContractError("invalid catalog snapshot limit")
    parsed: dict[str, int] = {}
    for key in required:
        item = value[key]
        if type(item) is not int:
            raise ContractError("invalid catalog snapshot limit")
        parsed[key] = item
    if parsed["metadata_candidates"] != METADATA_LIMIT or parsed["lexical_candidates"] != LEXICAL_LIMIT:
        raise ContractError("invalid catalog snapshot limit")
    if parsed["elapsed_ms"] < 1 or parsed["opened_files"] < 0 or parsed["opened_blocks"] < 0 or parsed["returned_bytes"] < 0:
        raise ContractError("invalid catalog snapshot limit")
    return parsed


def _metadata_probe(conn: sqlite3.Connection, workspace_id: str, principal_id: str, source_root_id: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        """
        SELECT f.file_record_id, f.current_source_version_id
        FROM file_acl a
        JOIN file_record f ON f.file_record_id = a.file_record_id
        WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
          AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
        ORDER BY f.file_record_id
        LIMIT ?
        """,
        (workspace_id, principal_id, workspace_id, source_root_id, METADATA_LIMIT + 1),
    ))


def _split_metadata(rows: list[sqlite3.Row]) -> tuple[list[tuple[str, str]], tuple[str, str] | None]:
    witness = None
    if len(rows) > METADATA_LIMIT:
        witness = (str(rows[METADATA_LIMIT]["file_record_id"]), str(rows[METADATA_LIMIT]["current_source_version_id"] or ""))
        rows = rows[:METADATA_LIMIT]
    members: list[tuple[str, str]] = []
    for row in rows:
        version_id = row["current_source_version_id"]
        if version_id is None:
            raise ContractError("catalog snapshot metadata candidate has no current source version")
        members.append((str(row["file_record_id"]), str(version_id)))
    if witness is not None and witness[1] == "":
        raise ContractError("catalog snapshot metadata candidate has no current source version")
    return members, witness


def _coverage(conn: sqlite3.Connection, members: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    covered: list[tuple[str, str, str]] = []
    for file_id, version_id in members:
        row = conn.execute(
            "SELECT coverage_disposition FROM source_version WHERE source_version_id=?",
            (version_id,),
        ).fetchone()
        if row is None:
            raise ContractError("catalog snapshot source version is missing")
        disposition = str(row["coverage_disposition"])
        if disposition not in _DISPOSITIONS:
            raise ContractError("catalog snapshot source version is missing")
        covered.append((file_id, version_id, disposition))
    return covered


def _fts_rows(conn: sqlite3.Connection, fts_query: str, members: list[tuple[str, str]]) -> list[sqlite3.Row]:
    if not members:
        return []
    return list(conn.execute(
        """
        SELECT b.block_instance_id, b.text, b.locator_kind, b.locator_value, b.projection_id,
               b.source_version_id, f.file_record_id, f.source_root_id, sv.source_sha256,
               p.parser_contract_name, p.parser_contract_version, bm25(block_fts) AS rank
        FROM block_fts
        JOIN block_instance b ON b.block_instance_id = block_fts.block_instance_id
        JOIN source_version sv ON sv.source_version_id = b.source_version_id
        JOIN file_record f ON f.file_record_id = sv.file_record_id
          AND f.current_source_version_id = b.source_version_id
        JOIN projection p ON p.projection_id = b.projection_id
        WHERE block_fts MATCH ?
          AND b.source_version_id IN (SELECT value FROM json_each(?))
        ORDER BY rank, b.block_instance_id
        LIMIT ?
        """,
        (fts_query, json.dumps([version_id for _, version_id in members]), LEXICAL_LIMIT + 1),
    ))


def _lexical_identity(rows: list[sqlite3.Row]) -> tuple[list[str], str | None]:
    witness = str(rows[LEXICAL_LIMIT]["block_instance_id"]) if len(rows) > LEXICAL_LIMIT else None
    retained = [str(row["block_instance_id"]) for row in rows[:LEXICAL_LIMIT]]
    return retained, witness


def _query_with_deadline(
    conn: sqlite3.Connection,
    deadline: float,
    query_fn,
    clock: Callable[[], float],
    checkpoint: str = "query_progress",
):
    def handler() -> int:
        return int(_deadline_reached(deadline, checkpoint, clock))

    conn.set_progress_handler(handler, 1)
    try:
        return query_fn()
    except sqlite3.OperationalError as exc:
        if "interrupted" not in str(exc).lower():
            raise
        raise ContractError("catalog snapshot deadline passed") from exc
    finally:
        conn.set_progress_handler(None, 0)


def _same_probe(
    members: list[tuple[str, str]],
    witness: tuple[str, str] | None,
    covered: list[tuple[str, str, str]],
    retained: list[str],
    lexical_witness: str | None,
    again_members: list[tuple[str, str]],
    again_witness: tuple[str, str] | None,
    again_covered: list[tuple[str, str, str]],
    again_retained: list[str],
    again_lexical_witness: str | None,
) -> None:
    if (
        members != again_members
        or witness != again_witness
        or covered != again_covered
        or retained != again_retained
        or lexical_witness != again_lexical_witness
    ):
        raise ContractError("catalog snapshot drifted")


def _recheck(
    conn: sqlite3.Connection,
    *,
    deadline: float,
    phase: str,
    workspace_id: str,
    principal_id: str,
    source_root_id: str,
    fts_query: str,
    members: list[tuple[str, str]],
    witness: tuple[str, str] | None,
    covered: list[tuple[str, str, str]],
    retained: list[str],
    lexical_witness: str | None,
    clock: Callable[[], float],
) -> None:
    again_members, again_witness = _split_metadata(_query_with_deadline(
        conn, deadline, lambda: _metadata_probe(conn, workspace_id, principal_id, source_root_id),
        clock, f"{phase}_recheck_metadata",
    ))
    again_covered = _coverage(conn, again_members)
    again_rows = _query_with_deadline(
        conn, deadline, lambda: _fts_rows(conn, fts_query, again_members),
        clock, f"{phase}_recheck_fts",
    )
    again_retained, again_lexical_witness = _lexical_identity(again_rows)
    _same_probe(
        members, witness, covered, retained, lexical_witness,
        again_members, again_witness, again_covered, again_retained, again_lexical_witness,
    )


def retrieve_in_snapshot(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    principal_id: str,
    source_root_id: str,
    query: str,
    limits: dict[str, Any],
    deadline: float,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Read Catalog hits inside the caller's transaction and insert its receipt."""
    tick = time.monotonic if clock is None else clock
    if not conn.in_transaction:
        raise ContractError("catalog snapshot requires an open transaction")
    parsed = _limits(limits)
    require_catalog_coverage_disclosure_shape(conn)
    started = tick()
    _ensure_deadline(deadline, "before_metadata_capture", tick)
    fts_query = _fts_query(query)
    root = conn.execute(
        "SELECT 1 FROM source_root WHERE source_root_id=? AND workspace_id=? AND enabled=1",
        (source_root_id, workspace_id),
    ).fetchone()
    if root is None:
        raise ContractError("enabled source root does not belong to workspace")
    previous_factory = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        metadata_rows = _query_with_deadline(
            conn, deadline, lambda: _metadata_probe(conn, workspace_id, principal_id, source_root_id), tick,
        )
        _ensure_deadline(deadline, "after_metadata_capture", tick)
        members, witness = _split_metadata(metadata_rows)
        member_pairs = set(members)
        fts_hits = _query_with_deadline(conn, deadline, lambda: _fts_rows(conn, fts_query, members), tick)
        retained_rows = fts_hits[:LEXICAL_LIMIT]
        retained, lexical_witness = _lexical_identity(fts_hits)
        selected: list[sqlite3.Row] = []
        opened_files: list[str] = []
        byte_count = 0
        stop_reason: str | None = None
        for row in retained_rows:
            _ensure_deadline(deadline, "selection_row", tick)
            identity = (str(row["file_record_id"]), str(row["source_version_id"]))
            if identity not in member_pairs:
                raise ContractError("catalog snapshot hit is outside the metadata candidate set")
            encoded = str(row["text"]).encode("utf-8")
            if identity[0] not in opened_files and len(opened_files) >= parsed["opened_files"]:
                stop_reason = "file_limit"
                break
            if len(selected) >= parsed["opened_blocks"]:
                stop_reason = "block_limit"
                break
            if byte_count + len(encoded) > parsed["returned_bytes"]:
                stop_reason = "byte_limit"
                break
            if identity[0] not in opened_files:
                opened_files.append(identity[0])
            selected.append(row)
            byte_count += len(encoded)
        if stop_reason is None and witness is not None:
            stop_reason = "metadata_candidate_limit"
        elif stop_reason is None and lexical_witness is not None:
            stop_reason = "lexical_candidate_limit"
        elif stop_reason is None:
            stop_reason = "score_threshold" if selected else "no_candidates"
        _ensure_deadline(deadline, "before_coverage_read", tick)
        covered = _coverage(conn, members)
        _ensure_deadline(deadline, "after_coverage_read", tick)
        coverage_by_version = {version_id: disposition for _, version_id, disposition in covered}
        citations: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        cited_versions: set[str] = set()
        complete_sources = partial_known = partial_unknown = 0
        for row in selected:
            normalized = unicodedata.normalize("NFC", str(row["text"]))
            if any(0xD800 <= ord(char) <= 0xDFFF for char in normalized):
                raise ContractError("block contains an unpaired Unicode surrogate")
            citation = {
                "schema_version": "pdx_local_citation_v1",
                "citation_id": str(uuid.uuid4()),
                "workspace_id": workspace_id,
                "source_root_id": row["source_root_id"],
                "file_record_id": row["file_record_id"],
                "source_version_id": row["source_version_id"],
                "source_sha256": row["source_sha256"],
                "projection_id": row["projection_id"],
                "parser_contract": {"name": row["parser_contract_name"], "version": row["parser_contract_version"]},
                "block_instance_id": row["block_instance_id"],
                "locator": {"kind": row["locator_kind"], "value": row["locator_value"]},
                "quote_start": 0,
                "quote_end": len(normalized),
                "quote_normalization": "unicode_nfc_codepoint_v1",
                "quoted_text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            }
            selected_text = validate_citation_against_block(citation, dict(row))
            version_id = str(row["source_version_id"])
            if version_id not in cited_versions:
                disposition = coverage_by_version[version_id]
                complete_sources += disposition == "complete"
                partial_known += disposition == "partial_known"
                partial_unknown += disposition == "partial_unknown"
                cited_versions.add(version_id)
            citations.append(citation)
            results.append({"text": selected_text, "citation": citation, "rank": row["rank"]})
        observed = max(0, math.ceil((tick() - started) * 1000))
        query_id, receipt_id = str(uuid.uuid4()), str(uuid.uuid4())
        created_at = _now()
        receipt = {
            "schema_version": "pdx_local_retrieval_receipt_v1",
            "receipt_id": receipt_id,
            "query_id": query_id,
            "workspace_id": workspace_id,
            "acl_policy_sha256": _sha({
                "policy": "workspace_acl_and_process_ntfs_v1",
                "workspace_id": workspace_id,
                "principal_id": principal_id,
                "source_root_id": source_root_id,
                "authorized_file_record_ids": [file_id for file_id, _ in members],
                "metadata_candidate_overflow": witness is not None,
            }),
            "execution": {
                "status": "completed",
                "budget_exhausted": stop_reason.endswith("_limit"),
                "stop_reason": stop_reason,
                "observed_elapsed_ms": observed,
            },
            "scope_coverage": {"disposition": "bounded", "eligible_roots": 1, "searched_roots": 1},
            "source_coverage": {
                "complete_sources": complete_sources,
                "partial_known_sources": partial_known,
                "partial_unknown_sources": partial_unknown,
            },
            "limits": parsed,
            "consumed": {
                "metadata_candidates": len(members),
                "lexical_candidates": len(retained),
                "opened_files": len(opened_files),
                "opened_blocks": len(selected),
                "returned_bytes": byte_count,
                "elapsed_ms": min(observed, parsed["elapsed_ms"]),
            },
            "result_count": len(results),
            "citation_ids": [item["citation_id"] for item in citations],
            "created_at": created_at,
        }
        validate_retrieval_receipt(receipt)
        receipt_json = _json(receipt)
        receipt_sha = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
        for index, item in enumerate(citations):
            _ensure_deadline(deadline, "before_citation_insert" if index == 0 else "before_subsequent_citation_insert", tick)
            conn.execute(
                "INSERT INTO citation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    item["citation_id"], query_id, workspace_id, item["source_root_id"], item["file_record_id"],
                    item["source_version_id"], item["source_sha256"], item["projection_id"],
                    item["parser_contract"]["name"], item["parser_contract"]["version"], item["block_instance_id"],
                    item["locator"]["kind"], item["locator"]["value"], item["quote_start"], item["quote_end"],
                    item["quote_normalization"], item["quoted_text_sha256"], created_at,
                ),
            )
        _ensure_deadline(deadline, "before_receipt_insert", tick)
        conn.execute(
            "INSERT INTO retrieval_receipt VALUES (?,?,?,?,?)",
            (receipt_id, query_id, workspace_id, receipt_json, created_at),
        )
        _recheck(
            conn,
            deadline=deadline,
            phase="first",
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            fts_query=fts_query,
            members=members,
            witness=witness,
            covered=covered,
            retained=retained,
            lexical_witness=lexical_witness,
            clock=tick,
        )
        _ensure_deadline(deadline, "before_disclosure_insert", tick)
        require_catalog_coverage_disclosure_shape(conn)
        disclosure_id = str(uuid.uuid4())
        candidate_set = {
            "profile_id": "pdx_local_document_catalog_metadata_candidates_v1",
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "source_root_id": source_root_id,
            "metadata_candidates": METADATA_LIMIT,
            "members": [{"file_record_id": file_id, "source_version_id": version_id} for file_id, version_id in members],
        }
        candidate_set_sha256 = _sha(candidate_set)
        disclosure = {
            "schema_version": "pdx_local_catalog_coverage_disclosure_v1",
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "source_root_id": source_root_id,
            "catalog_query_id": query_id,
            "catalog_receipt_id": receipt_id,
            "catalog_receipt_sha256": receipt_sha,
            "budget_profile_sha256": BUDGET_PROFILE_SHA256,
            "candidate_set_sha256": candidate_set_sha256,
            "sources": [
                {
                    "file_record_id": file_id,
                    "source_version_id": version_id,
                    "coverage_disposition": disposition,
                }
                for file_id, version_id, disposition in covered
            ],
        }
        disclosure_json = _json(disclosure)
        disclosure_sha256 = hashlib.sha256(disclosure_json.encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO catalog_coverage_disclosure (
              disclosure_id, catalog_receipt_id, catalog_query_id, workspace_id, principal_id,
              source_root_id, catalog_receipt_sha256, disclosure_json, disclosure_sha256, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                disclosure_id, receipt_id, query_id, workspace_id, principal_id, source_root_id,
                receipt_sha, disclosure_json, disclosure_sha256, created_at,
            ),
        )
        _recheck(
            conn,
            deadline=deadline,
            phase="second",
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            fts_query=fts_query,
            members=members,
            witness=witness,
            covered=covered,
            retained=retained,
            lexical_witness=lexical_witness,
            clock=tick,
        )
        _ensure_deadline(deadline, "before_return", tick)
    finally:
        conn.row_factory = previous_factory
        conn.set_progress_handler(None, 0)
    return {
        "query_id": query_id,
        "results": results,
        "receipt": receipt,
        "disclosure_id": disclosure_id,
        "disclosure": disclosure,
        "disclosure_sha256": disclosure_sha256,
        "candidate_set_sha256": candidate_set_sha256,
    }
