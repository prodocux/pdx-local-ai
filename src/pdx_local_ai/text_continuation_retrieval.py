"""Gate 5A-2 Continuation Retrieval Switch Runtime Implementation Candidate.

Provides 3-stream mixed-source retrieval synthesis (Kernel, Text Baseline, Text Continuation)
without cross-table BM25 score conflation, strict single global L+1 lexical candidate budget
with sole overflow witness exclusion, deterministic pointer routing via text_current_published_generation,
and fail-closed corrupted binding protection under Gate 5A-2 specification.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import unicodedata
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .catalog import Catalog, RetrievalLimits, validate_supported_limits
from .validation import (
    ContractError,
    validate_citation_against_block,
    validate_retrieval_receipt,
    validate_text_citation_against_block,
)

# Pinned UUIDv5 Namespaces
UUID_NAMESPACE_CONTINUATION_PROJECTION: uuid.UUID = uuid.UUID("3b7f1e52-19e0-4a8a-b851-92b67f10bda4")
UUID_NAMESPACE_CONTINUATION_BLOCK: uuid.UUID = uuid.UUID("7a2c4e68-3d1f-4952-9b24-81d3f9e20a67")

_LEXICAL_TIMEOUT = object()
_SQLITE_INTERRUPT_CODE = getattr(sqlite3, "SQLITE_INTERRUPT", 9)


@dataclass(frozen=True)
class CandidateBlock:
    context: Any
    side: str
    stream_position: int
    stream_turn_ordinal: int
    source_root_id: str
    file_record_id: str
    block_instance_id: str
    source_version_id: str
    raw_bm25_rank: float
    row_payload: sqlite3.Row


def _is_interrupted_error(exc: sqlite3.OperationalError) -> bool:
    """Classify SQLite interruption errors fail-closed.

    Rules per Gate 5A-2 governance:
    1. When sqlite_errorcode is present: classify strictly by errorcode.
       Non-SQLITE_INTERRUPT codes MUST return False (and thus be re-raised).
    2. Only when sqlite_errorcode is absent: fall back to legacy 'interrupted' in str(exc).lower().
       Unconditional OR is prohibited.
       Catch-all whitelisting of 'vtable constructor failed' is prohibited.
    """
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return code == _SQLITE_INTERRUPT_CODE
    return "interrupted" in str(exc).lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_json(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _uuid() -> str:
    return str(uuid.uuid4())


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
SELECT b.*, f.file_record_id, f.source_root_id, af.current_source_version_id, sv.source_sha256,
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

_TEXT_BASELINE_LEXICAL_SQL = _AUTHORIZED_FILES + """
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
  AND NOT EXISTS (
    SELECT 1 FROM text_current_published_generation pubgen
    WHERE pubgen.source_version_id=b.source_version_id
  )
ORDER BY rank, b.block_instance_id
LIMIT 1 OFFSET ?
"""

_TEXT_CONTINUATION_LEXICAL_SQL = _AUTHORIZED_FILES + """
SELECT b.block_instance_id, cp.workspace_id, b.projection_id, cp.source_version_id, b.text,
       f.file_record_id, f.source_root_id, af.current_source_version_id, sv.source_sha256,
       'pdx_local_text_decoder' AS parser_contract_name, '1' AS parser_contract_version,
       r.line_start, r.line_end_exclusive, r.source_codepoint_start, r.source_codepoint_end_exclusive,
       bm25(text_continuation_block_fts) AS rank
FROM text_continuation_block_fts
JOIN text_continuation_block_instance b ON b.block_instance_id=text_continuation_block_fts.block_instance_id
JOIN text_continuation_fts_binding bind ON bind.block_instance_id=b.block_instance_id
JOIN text_continuation_source_range r ON r.block_instance_id=b.block_instance_id
JOIN text_continuation_projection cp ON cp.projection_id=b.projection_id
JOIN text_continuation_materialization_marker m ON m.generation_id=b.generation_id
JOIN text_current_published_generation pub ON pub.generation_id=b.generation_id AND pub.source_version_id=cp.source_version_id
JOIN text_range_generation_member mem ON mem.generation_id=b.generation_id AND mem.range_artifact_id=b.range_artifact_id AND mem.range_ordinal=b.range_ordinal
JOIN text_range_artifact art ON art.range_artifact_id=b.range_artifact_id
JOIN authorized_files af ON af.current_source_version_id=cp.source_version_id
JOIN file_record f ON f.file_record_id=af.file_record_id
JOIN source_version sv ON sv.source_version_id=cp.source_version_id
WHERE text_continuation_block_fts MATCH ?
  AND length(b.text) > 0
  AND NOT EXISTS (
    SELECT 1 FROM text_continuation_fts_drift d WHERE d.block_instance_id=b.block_instance_id
  )
  AND r.line_start = CAST(json_extract(art.recomputed_records, '$[' || b.block_ordinal || '].locator.line_start') AS INTEGER)
  AND r.line_end_exclusive = CAST(json_extract(art.recomputed_records, '$[' || b.block_ordinal || '].locator.line_end_exclusive') AS INTEGER)
  AND r.source_codepoint_start = CAST(json_extract(art.recomputed_records, '$[' || b.block_ordinal || '].locator.code_point_start') AS INTEGER)
  AND r.source_codepoint_end_exclusive = CAST(json_extract(art.recomputed_records, '$[' || b.block_ordinal || '].locator.code_point_end_exclusive') AS INTEGER)
  AND b.text = json_extract(art.recomputed_records, '$[' || b.block_ordinal || '].block_text')
ORDER BY rank, b.block_instance_id
LIMIT 1 OFFSET ?
"""

_CORRUPT_POINTER_CHECK_SQL = _AUTHORIZED_FILES + """
SELECT cpg.generation_id
FROM text_current_published_generation cpg
JOIN authorized_files af ON af.current_source_version_id = cpg.source_version_id
JOIN source_version sv ON sv.source_version_id = cpg.source_version_id
LEFT JOIN text_range_generation g ON g.generation_id = cpg.generation_id
LEFT JOIN text_range_generation_seal s ON s.generation_id = cpg.generation_id
LEFT JOIN text_continuation_materialization_marker m ON m.generation_id = cpg.generation_id
LEFT JOIN text_continuation_projection cp ON cp.generation_id = cpg.generation_id
WHERE g.generation_id IS NULL
   OR g.terminal_reason IS NOT NULL
   OR s.generation_id IS NULL
   OR m.generation_id IS NULL
   OR cp.projection_id IS NULL
   OR cp.projection_id != m.projection_id
   OR g.workspace_id != cpg.workspace_id
   OR g.file_record_id != cpg.file_record_id
   OR g.source_version_id != cpg.source_version_id
   OR g.source_sha256 != sv.source_sha256
   OR g.source_size_bytes != sv.size_bytes
   OR s.total_ranges != g.total_ranges
   OR s.total_bytes != g.total_bytes
   OR s.source_size_bytes != g.source_size_bytes
   OR s.final_manifest_digest != g.final_manifest_digest
   OR m.total_ranges != g.total_ranges
   OR m.total_source_bytes != g.source_size_bytes
   OR m.final_manifest_digest != g.final_manifest_digest
   OR cp.workspace_id != cpg.workspace_id
   OR cp.source_version_id != cpg.source_version_id
   OR cp.source_sha256 != g.source_sha256
   OR cp.block_count != m.total_blocks
   OR cp.final_manifest_digest != g.final_manifest_digest
   OR (
       SELECT count(*) FROM text_range_generation_member mem
       WHERE mem.generation_id = cpg.generation_id
   ) != m.total_ranges
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member mem
       WHERE mem.generation_id = cpg.generation_id
         AND NOT EXISTS (
             SELECT 1 FROM text_range_artifact art
             WHERE art.range_artifact_id = mem.range_artifact_id
         )
   )
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member mem
       JOIN text_range_artifact art ON art.range_artifact_id = mem.range_artifact_id
       WHERE mem.generation_id = cpg.generation_id
         AND (
             art.workspace_id != cpg.workspace_id
             OR art.file_record_id != cpg.file_record_id
             OR art.source_version_id != cpg.source_version_id
             OR art.source_sha256 != g.source_sha256
             OR art.range_ordinal != mem.range_ordinal
             OR art.range_start != mem.range_start
             OR art.range_end_exclusive != mem.range_end_exclusive
             OR art.manifest_digest != mem.manifest_digest
         )
   )
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member mem
       JOIN text_range_artifact art ON art.range_artifact_id = mem.range_artifact_id
       WHERE mem.generation_id = cpg.generation_id
         AND mem.range_ordinal = 0
         AND (
             art.previous_cursor != 0
             OR art.previous_manifest_digest != 'f3207ab9220fdd13edba85174ea823e315e421bcde37c4dda94f452ab6f733ae'
         )
   )
   OR EXISTS (
       SELECT 1
       FROM text_range_generation_member curr_m
       JOIN text_range_artifact curr_a ON curr_a.range_artifact_id = curr_m.range_artifact_id
       JOIN text_range_generation_member prev_m
         ON prev_m.generation_id = curr_m.generation_id AND prev_m.range_ordinal = curr_m.range_ordinal - 1
       JOIN text_range_artifact prev_a ON prev_a.range_artifact_id = prev_m.range_artifact_id
       WHERE curr_m.generation_id = cpg.generation_id
         AND (
             curr_a.previous_cursor != prev_a.next_cursor
             OR curr_a.input_decoder_state != prev_a.next_decoder_state
             OR curr_a.previous_manifest_digest != prev_a.manifest_digest
         )
   )
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member last_m
       WHERE last_m.generation_id = cpg.generation_id
         AND last_m.range_ordinal = g.total_ranges - 1
         AND last_m.manifest_digest != g.final_manifest_digest
   )
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member mem
       JOIN text_range_artifact art ON art.range_artifact_id = mem.range_artifact_id
       LEFT JOIN text_continuation_slice_receipt rec
         ON rec.generation_id = mem.generation_id AND rec.range_ordinal = mem.range_ordinal
       WHERE mem.generation_id = cpg.generation_id
         AND (
             rec.generation_id IS NULL
             OR rec.range_artifact_id != mem.range_artifact_id
             OR rec.slice_manifest_digest != art.manifest_digest
             OR rec.slice_manifest_digest != mem.manifest_digest
             OR rec.slice_block_count != json_array_length(art.recomputed_records)
         )
   )
   OR (
       SELECT count(*) FROM text_continuation_block_instance bi
       WHERE bi.generation_id = cpg.generation_id
   ) != m.total_blocks
   OR (
       SELECT count(*) FROM text_continuation_source_range sr
       WHERE sr.projection_id = m.projection_id
   ) != m.total_blocks
   OR (
       SELECT count(*) FROM text_continuation_fts_binding bd
       WHERE bd.generation_id = cpg.generation_id AND bd.projection_id = m.projection_id
   ) != m.total_blocks
   OR EXISTS (
       SELECT 1 FROM text_continuation_block_instance bi
       JOIN text_range_artifact art ON art.range_artifact_id = bi.range_artifact_id
       LEFT JOIN text_continuation_source_range sr ON sr.block_instance_id = bi.block_instance_id
       LEFT JOIN text_continuation_fts_binding bd ON bd.block_instance_id = bi.block_instance_id
       LEFT JOIN text_continuation_block_fts fts ON fts.block_instance_id = bi.block_instance_id
       WHERE bi.generation_id = cpg.generation_id
         AND (
             bi.projection_id != m.projection_id
             OR sr.block_instance_id IS NULL
             OR sr.projection_id != m.projection_id
             OR bd.block_instance_id IS NULL
             OR bd.projection_id != m.projection_id
             OR bd.generation_id != cpg.generation_id
             OR fts.block_instance_id IS NULL
             OR fts.text != bi.text
             OR bi.text != json_extract(art.recomputed_records, '$[' || bi.block_ordinal || '].block_text')
             OR sr.line_start != CAST(json_extract(art.recomputed_records, '$[' || bi.block_ordinal || '].locator.line_start') AS INTEGER)
             OR sr.line_end_exclusive != CAST(json_extract(art.recomputed_records, '$[' || bi.block_ordinal || '].locator.line_end_exclusive') AS INTEGER)
             OR sr.source_codepoint_start != CAST(json_extract(art.recomputed_records, '$[' || bi.block_ordinal || '].locator.code_point_start') AS INTEGER)
             OR sr.source_codepoint_end_exclusive != CAST(json_extract(art.recomputed_records, '$[' || bi.block_ordinal || '].locator.code_point_end_exclusive') AS INTEGER)
             OR bi.byte_count != length(CAST(bi.text AS BLOB))
             OR bi.codepoint_count != length(bi.text)
         )
   )
   OR EXISTS (
       SELECT 1 FROM text_range_generation_member mem
       JOIN text_range_artifact art ON art.range_artifact_id = mem.range_artifact_id
       JOIN json_each(art.recomputed_records) j
       WHERE mem.generation_id = cpg.generation_id
         AND NOT EXISTS (
             SELECT 1 FROM text_continuation_block_instance bi
             JOIN text_continuation_source_range sr ON sr.block_instance_id = bi.block_instance_id
             WHERE bi.generation_id = cpg.generation_id
               AND bi.range_artifact_id = mem.range_artifact_id
               AND bi.range_ordinal = mem.range_ordinal
               AND bi.block_ordinal = CAST(j.key AS INTEGER)
               AND bi.text = json_extract(j.value, '$.block_text')
               AND sr.line_start = CAST(json_extract(j.value, '$.locator.line_start') AS INTEGER)
               AND sr.line_end_exclusive = CAST(json_extract(j.value, '$.locator.line_end_exclusive') AS INTEGER)
               AND sr.source_codepoint_start = CAST(json_extract(j.value, '$.locator.code_point_start') AS INTEGER)
               AND sr.source_codepoint_end_exclusive = CAST(json_extract(j.value, '$.locator.code_point_end_exclusive') AS INTEGER)
         )
   )
   OR EXISTS (
       SELECT 1 FROM text_continuation_fts_drift d
       JOIN text_continuation_block_instance bi ON bi.block_instance_id = d.block_instance_id
       WHERE bi.generation_id = cpg.generation_id
   )
LIMIT 1
"""


class ContinuationRetrievalEngine:
    """Runtime engine performing 3-stream mixed-source retrieval under Gate 5A-2."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        progress_step: int = 10,
        progress_handler: Callable[[], int] | None = None,
    ) -> None:
        self.conn = conn
        self.progress_step = progress_step
        self.progress_handler = progress_handler
        self._active_stage: str = "idle"
        self.cumulative_rows_fetched: int = 0

    @staticmethod
    def _fts_query(query: str) -> str:
        tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
        if not tokens:
            raise ContractError("query has no searchable tokens")
        return " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens[:32])

    def _next_lexical_row(
        self,
        side: str,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        fts_query: str,
        metadata_candidates: int,
        offset: int,
    ) -> sqlite3.Row | None | object:
        if side == "kernel":
            sql = _KERNEL_LEXICAL_SQL
        elif side == "text_continuation":
            sql = _TEXT_CONTINUATION_LEXICAL_SQL
        else:
            sql = _TEXT_BASELINE_LEXICAL_SQL

        try:
            row = self.conn.execute(
                sql,
                (
                    workspace_id,
                    principal_id,
                    workspace_id,
                    source_root_id,
                    metadata_candidates,
                    fts_query,
                    offset,
                ),
            ).fetchone()
            if row is not None:
                self.cumulative_rows_fetched += 1
            return row
        except sqlite3.OperationalError as exc:
            if not _is_interrupted_error(exc):
                raise
            return _LEXICAL_TIMEOUT

    def retrieve(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        limits: RetrievalLimits | None = None,
    ) -> dict[str, Any]:
        """Run authorization, fail-closed validation, 3-stream FTS, citations, and receipt in one SQLite transaction."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            result = self._retrieve_snapshot(
                workspace_id=workspace_id,
                principal_id=principal_id,
                source_root_id=source_root_id,
                query=query,
                limits=limits,
            )
            self.conn.commit()
            t_committed = time.perf_counter()
            t_query_stopped = result.get("t_query_stopped", t_committed)
            result["finalization_latency_ms"] = max(0.0, (t_committed - t_query_stopped) * 1000.0)
            return result
        except Exception:
            self.conn.rollback()
            raise

    def fetch_candidates(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        limits: RetrievalLimits,
        context: Any,
    ) -> dict[str, Any]:
        """In-transaction candidate fetch without starting or committing SQLite transaction."""
        validate_supported_limits(limits)
        started_perf = time.perf_counter()
        deadline_perf = getattr(limits, "deadline_perf", None)
        if deadline_perf is not None:
            deadline = min(started_perf + limits.elapsed_ms / 1000, deadline_perf)
        else:
            deadline = started_perf + limits.elapsed_ms / 1000

        fts_query = self._fts_query(query)
        timed_out = False
        raw_fetched: list[tuple[str, int, sqlite3.Row]] = []
        metadata_candidate_overflow = False

        handler = self.progress_handler or (lambda: int(time.perf_counter() >= deadline))
        self.conn.set_progress_handler(handler, self.progress_step)
        try:
            if time.perf_counter() >= deadline:
                timed_out = True

            self._active_stage = "root"
            try:
                root = self.conn.execute(
                    "SELECT 1 FROM source_root WHERE source_root_id=? AND workspace_id=? AND enabled=1",
                    (source_root_id, workspace_id),
                ).fetchone()
            except sqlite3.OperationalError as exc:
                if not _is_interrupted_error(exc):
                    raise
                timed_out = True
                root = None

            if not timed_out and root is None:
                raise ContractError("enabled source root does not belong to workspace")

            if not timed_out:
                self._active_stage = "metadata"
                bounded_auth_sql = """
                SELECT f.file_record_id
                FROM file_acl a
                JOIN file_record f ON f.file_record_id = a.file_record_id
                WHERE a.workspace_id = ? AND a.principal_id = ? AND a.can_read = 1
                  AND f.workspace_id = ? AND f.source_root_id = ? AND f.catalog_status = 'active'
                ORDER BY f.file_record_id
                LIMIT ?
                """
                try:
                    authorized_rows = self.conn.execute(
                        bounded_auth_sql,
                        (workspace_id, principal_id, workspace_id, source_root_id, limits.metadata_candidates + 1),
                    ).fetchall()
                except sqlite3.OperationalError as exc:
                    if not _is_interrupted_error(exc):
                        raise
                    timed_out = True
                    authorized_rows = []
            else:
                authorized_rows = []

            total_authorized = len(authorized_rows)
            authorized_ids = [str(item[0]) for item in authorized_rows[:limits.metadata_candidates]]
            metadata_candidate_overflow = total_authorized > limits.metadata_candidates

            if not timed_out:
                self._active_stage = "pointer_integrity"
                if time.perf_counter() >= deadline:
                    timed_out = True
                else:
                    try:
                        corrupt = self.conn.execute(
                            _CORRUPT_POINTER_CHECK_SQL,
                            (workspace_id, principal_id, workspace_id, source_root_id, limits.metadata_candidates),
                        ).fetchone()
                    except sqlite3.OperationalError as exc:
                        if not _is_interrupted_error(exc):
                            raise
                        timed_out = True
                        corrupt = None

                    if corrupt is not None:
                        raise ContractError("CORRUPT_PUBLISHED_GENERATION_BINDING")

            self._active_stage = "lexical"
            kernel_offset = 0
            text_baseline_offset = 0
            text_continuation_offset = 0
            top_turn_is_kernel = True
            text_turn_is_baseline = True
            kernel_done = False
            text_baseline_done = False
            text_continuation_done = False

            kernel_pos = 0
            text_baseline_pos = 0
            text_continuation_pos = 0

            page = {
                "workspace_id": workspace_id,
                "principal_id": principal_id,
                "source_root_id": source_root_id,
                "fts_query": fts_query,
                "metadata_candidates": limits.metadata_candidates,
            }

            while not timed_out and len(raw_fetched) < limits.lexical_candidates + 1:
                if top_turn_is_kernel:
                    if not kernel_done:
                        row = self._next_lexical_row("kernel", offset=kernel_offset, **page)
                        if row is _LEXICAL_TIMEOUT:
                            timed_out = True
                            raw_fetched.clear()
                            break
                        if row is not None:
                            kernel_pos += 1
                            raw_fetched.append(("kernel", kernel_pos, row))
                            kernel_offset += 1
                            top_turn_is_kernel = False
                            continue
                        kernel_done = True
                    top_turn_is_kernel = False

                got_text = False
                for _ in range(2):
                    if text_turn_is_baseline:
                        if not text_baseline_done:
                            row = self._next_lexical_row("text_baseline", offset=text_baseline_offset, **page)
                            if row is _LEXICAL_TIMEOUT:
                                timed_out = True
                                raw_fetched.clear()
                                break
                            if row is not None:
                                text_baseline_pos += 1
                                raw_fetched.append(("text_baseline", text_baseline_pos, row))
                                text_baseline_offset += 1
                                text_turn_is_baseline = False
                                got_text = True
                                break
                            text_baseline_done = True
                        text_turn_is_baseline = False
                    else:
                        if not text_continuation_done:
                            row = self._next_lexical_row("text_continuation", offset=text_continuation_offset, **page)
                            if row is _LEXICAL_TIMEOUT:
                                timed_out = True
                                raw_fetched.clear()
                                break
                            if row is not None:
                                text_continuation_pos += 1
                                raw_fetched.append(("text_continuation", text_continuation_pos, row))
                                text_continuation_offset += 1
                                text_turn_is_baseline = True
                                got_text = True
                                break
                            text_continuation_done = True
                        text_turn_is_baseline = True

                if timed_out:
                    break

                if got_text:
                    top_turn_is_kernel = True
                    continue

                if not kernel_done:
                    row = self._next_lexical_row("kernel", offset=kernel_offset, **page)
                    if row is _LEXICAL_TIMEOUT:
                        timed_out = True
                        raw_fetched.clear()
                        break
                    if row is not None:
                        kernel_pos += 1
                        raw_fetched.append(("kernel", kernel_pos, row))
                        kernel_offset += 1
                        top_turn_is_kernel = False
                        continue
                    kernel_done = True

                break
        finally:
            t_query_stopped = time.perf_counter()
            self._active_stage = "idle"
            self.conn.set_progress_handler(None, 0)

        lexical_overflow = len(raw_fetched) > limits.lexical_candidates
        admitted_raw = raw_fetched[:-1] if lexical_overflow else raw_fetched

        candidates = [
            CandidateBlock(
                context=context,
                side=side,
                stream_position=stream_pos,
                stream_turn_ordinal=idx + 1,
                source_root_id=source_root_id,
                file_record_id=str(row["file_record_id"]),
                block_instance_id=str(row["block_instance_id"]),
                source_version_id=str(row["source_version_id"]),
                raw_bm25_rank=float(row["rank"]),
                row_payload=row,
            )
            for idx, (side, stream_pos, row) in enumerate(admitted_raw)
        ]

        return {
            "source_root_id": source_root_id,
            "candidates": candidates,
            "authorized_ids": authorized_ids,
            "total_authorized": total_authorized,
            "metadata_candidate_overflow": metadata_candidate_overflow,
            "overflow_witness_present": lexical_overflow,
            "timed_out": timed_out,
            "t_query_stopped": t_query_stopped,
            "started_perf": started_perf,
        }

    def finalize_retrieval(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query_id: str,
        receipt_id: str,
        admitted_candidates: list[CandidateBlock],
        stop_reason: str,
        budget_exhausted: bool,
        context: Any,
        authorized_ids: list[str],
        limits: RetrievalLimits,
        total_authorized: int,
        started_perf: float,
        t_query_stopped: float,
        deadline: float | None = None,
        scope_eligible_roots: int = 1,
        scope_searched_roots: int = 1,
        lexical_candidates_count: int | None = None,
    ) -> dict[str, Any]:
        """In-transaction citation and receipt generation without committing."""
        deadline_perf = getattr(limits, "deadline_perf", None)
        deadline = deadline or (
            min(started_perf + limits.elapsed_ms / 1000, deadline_perf)
            if deadline_perf is not None
            else started_perf + limits.elapsed_ms / 1000
        )
        citations: list[tuple[dict[str, Any], str]] = []
        results: list[dict[str, Any]] = []
        now = _now()

        # Validate that all admitted candidates belong to the given context and source_root_id
        for candidate in admitted_candidates:
            if candidate.context is not context:
                raise ContractError("CandidateBlock context mismatch")
            if candidate.source_root_id != source_root_id:
                raise ContractError("CandidateBlock source_root_id mismatch")

        citation_candidates = admitted_candidates
        if time.perf_counter() >= deadline or stop_reason == "time_limit":
            stop_reason = "time_limit"
            budget_exhausted = True
            citation_candidates = []

        files: set[str] = set()
        byte_count = 0
        for candidate in citation_candidates:
            if time.perf_counter() >= deadline:
                stop_reason = "time_limit"
                budget_exhausted = True
                citations.clear()
                results.clear()
                break

            row = candidate.row_payload
            side = candidate.side
            encoded = row["text"].encode("utf-8")
            files.add(str(row["file_record_id"]))
            byte_count += len(encoded)

            normalized = unicodedata.normalize("NFC", str(row["text"]))
            if any(0xD800 <= ord(char) <= 0xDFFF for char in normalized):
                raise ContractError("block contains an unpaired Unicode surrogate")

            if side in ("text", "text_baseline", "text_continuation"):
                loc_line_start = int(row["line_start"])
                loc_line_end = int(row["line_end_exclusive"])
                loc_cp_start = int(row["source_codepoint_start"])
                loc_cp_end = int(row["source_codepoint_end_exclusive"])

                locator_value = _json({
                    "line_end_exclusive": loc_line_end,
                    "line_start": loc_line_start,
                    "source_codepoint_end_exclusive": loc_cp_end,
                    "source_codepoint_start": loc_cp_start,
                })
                citation = {
                    "schema_version": "pdx_local_text_citation_v1",
                    "citation_id": _uuid(),
                    "workspace_id": workspace_id,
                    "source_root_id": row["source_root_id"],
                    "file_record_id": row["file_record_id"],
                    "source_version_id": row["source_version_id"],
                    "source_sha256": row["source_sha256"],
                    "projection_id": row["projection_id"],
                    "parser_contract": {
                        "name": row["parser_contract_name"],
                        "version": row["parser_contract_version"],
                    },
                    "block_instance_id": row["block_instance_id"],
                    "locator": {
                        "kind": "text_line_codepoint_v1",
                        "line_start": loc_line_start,
                        "line_end_exclusive": loc_line_end,
                        "source_codepoint_start": loc_cp_start,
                        "source_codepoint_end_exclusive": loc_cp_end,
                    },
                    "quote_start": 0,
                    "quote_end": len(normalized),
                    "quote_normalization": "unicode_nfc_codepoint_v1",
                    "quoted_text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                }
                context_dict = {
                    "authorized": True,
                    "published": True,
                    "drift": False,
                    "workspace_id": workspace_id,
                    "source_root_id": row["source_root_id"],
                    "file_record_id": row["file_record_id"],
                    "source_version_id": row["source_version_id"],
                    "current_source_version_id": row["current_source_version_id"],
                    "projection_id": row["projection_id"],
                    "block_instance_id": row["block_instance_id"],
                    "parser_contract_name": row["parser_contract_name"],
                    "parser_contract_version": row["parser_contract_version"],
                    "block_text": row["text"],
                    "line_start": loc_line_start,
                    "line_end_exclusive": loc_line_end,
                    "source_codepoint_start": loc_cp_start,
                    "source_codepoint_end_exclusive": loc_cp_end,
                }
                selected_text = validate_text_citation_against_block(citation, context_dict)
            else:
                locator_value = row["locator_value"]
                citation = {
                    "schema_version": "pdx_local_citation_v1",
                    "citation_id": _uuid(),
                    "workspace_id": workspace_id,
                    "source_root_id": row["source_root_id"],
                    "file_record_id": row["file_record_id"],
                    "source_version_id": row["source_version_id"],
                    "source_sha256": row["source_sha256"],
                    "projection_id": row["projection_id"],
                    "parser_contract": {
                        "name": row["parser_contract_name"],
                        "version": row["parser_contract_version"],
                    },
                    "block_instance_id": row["block_instance_id"],
                    "locator": {"kind": row["locator_kind"], "value": row["locator_value"]},
                    "quote_start": 0,
                    "quote_end": len(normalized),
                    "quote_normalization": "unicode_nfc_codepoint_v1",
                    "quoted_text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                }
                context_dict = {
                    "authorized": True,
                    "workspace_id": workspace_id,
                    "source_root_id": row["source_root_id"],
                    "file_record_id": row["file_record_id"],
                    "source_version_id": row["source_version_id"],
                    "current_source_version_id": row["current_source_version_id"],
                    "projection_id": row["projection_id"],
                    "block_instance_id": row["block_instance_id"],
                    "parser_contract_name": row["parser_contract_name"],
                    "parser_contract_version": row["parser_contract_version"],
                    "block_text": row["text"],
                    "locator_kind": row["locator_kind"],
                    "locator_value": row["locator_value"],
                }
                selected_text = validate_citation_against_block(citation, dict(row))

            citations.append((citation, locator_value))
            results.append({"text": selected_text, "citation": citation, "rank": row["rank"]})

        elapsed_ms = max(0, math.ceil((time.perf_counter() - started_perf) * 1000))
        if stop_reason == "time_limit" and elapsed_ms < limits.elapsed_ms:
            elapsed_ms = limits.elapsed_ms

        consumed = {
            "metadata_candidates": min(total_authorized, limits.metadata_candidates),
            "lexical_candidates": (
                lexical_candidates_count
                if lexical_candidates_count is not None
                else len(admitted_candidates)
            ),
            "opened_files": len(files),
            "opened_blocks": len(citations),
            "returned_bytes": byte_count,
            "elapsed_ms": min(elapsed_ms, limits.elapsed_ms),
        }

        coverage_by_source: dict[str, str] = {}
        for candidate in citation_candidates if results else []:
            row = candidate.row_payload
            source_id = str(row["source_version_id"])
            if source_id not in coverage_by_source:
                coverage_by_source[source_id] = str(
                    self.conn.execute(
                        "SELECT coverage_disposition FROM source_version WHERE source_version_id=?",
                        (source_id,),
                    ).fetchone()[0]
                )

        complete_sources = sum(value == "complete" for value in coverage_by_source.values())
        partial_known = sum(value == "partial_known" for value in coverage_by_source.values())
        partial_unknown = sum(value == "partial_unknown" for value in coverage_by_source.values())

        limits_dict = {
            "metadata_candidates": limits.metadata_candidates,
            "lexical_candidates": limits.lexical_candidates,
            "opened_files": limits.opened_files,
            "opened_blocks": limits.opened_blocks,
            "returned_bytes": limits.returned_bytes,
            "elapsed_ms": limits.elapsed_ms,
        }

        t_committed_now = time.perf_counter()
        finalization_latency_ms = (t_committed_now - t_query_stopped) * 1000.0

        receipt = {
            "schema_version": "pdx_local_retrieval_receipt_v1",
            "receipt_id": receipt_id,
            "query_id": query_id,
            "workspace_id": workspace_id,
            "acl_policy_sha256": _sha_json({
                "policy": "workspace_acl_and_process_ntfs_v1",
                "workspace_id": workspace_id,
                "principal_id": principal_id,
                "source_root_id": source_root_id,
                "authorized_file_record_ids": authorized_ids,
            }),
            "execution": {
                "status": "completed",
                "budget_exhausted": budget_exhausted,
                "stop_reason": stop_reason,
                "observed_elapsed_ms": elapsed_ms,
            },
            "scope_coverage": {"disposition": "bounded", "eligible_roots": scope_eligible_roots, "searched_roots": scope_searched_roots},
            "source_coverage": {
                "complete_sources": complete_sources,
                "partial_known_sources": partial_known,
                "partial_unknown_sources": partial_unknown,
            },
            "limits": limits_dict,
            "consumed": consumed,
            "result_count": len(results),
            "citation_ids": [item["citation_id"] for item, _locator_value in citations],
            "created_at": now,
        }
        validate_retrieval_receipt(receipt)

        for item, locator_value in citations:
            self.conn.execute(
                "INSERT INTO citation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    item["citation_id"],
                    query_id,
                    workspace_id,
                    item["source_root_id"],
                    item["file_record_id"],
                    item["source_version_id"],
                    item["source_sha256"],
                    item["projection_id"],
                    item["parser_contract"]["name"],
                    item["parser_contract"]["version"],
                    item["block_instance_id"],
                    item["locator"]["kind"],
                    locator_value,
                    item["quote_start"],
                    item["quote_end"],
                    item["quote_normalization"],
                    item["quoted_text_sha256"],
                    now,
                ),
            )
        self.conn.execute(
            "INSERT INTO retrieval_receipt VALUES (?,?,?,?,?)",
            (receipt_id, query_id, workspace_id, _json(receipt), now),
        )
        return {
            "query_id": query_id,
            "receipt_id": receipt_id,
            "results": results,
            "receipt": receipt,
            "citations": citations,
            "cumulative_rows_fetched": self.cumulative_rows_fetched,
            "finalization_latency_ms": finalization_latency_ms,
        }

    def _retrieve_snapshot(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        limits: RetrievalLimits | None = None,
    ) -> dict[str, Any]:
        limits = limits or RetrievalLimits()
        validate_supported_limits(limits)
        query_id, receipt_id = _uuid(), _uuid()
        local_context = object()

        fetch_res = self.fetch_candidates(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query=query,
            limits=limits,
            context=local_context,
        )

        timed_out = fetch_res["timed_out"]
        candidates = fetch_res["candidates"]
        metadata_candidate_overflow = fetch_res["metadata_candidate_overflow"]
        lexical_overflow = fetch_res["overflow_witness_present"]
        started_perf = fetch_res["started_perf"]
        t_query_stopped = fetch_res["t_query_stopped"]
        authorized_ids = fetch_res["authorized_ids"]
        total_authorized = fetch_res["total_authorized"]

        deadline_perf = getattr(limits, "deadline_perf", None)
        deadline = (
            min(started_perf + limits.elapsed_ms / 1000, deadline_perf)
            if deadline_perf is not None
            else started_perf + limits.elapsed_ms / 1000
        )

        selected: list[CandidateBlock] = []
        files: set[str] = set()
        byte_count = 0
        stop_reason: str | None = None

        for candidate in candidates:
            if time.perf_counter() >= deadline:
                stop_reason = "time_limit"
                break
            row = candidate.row_payload
            encoded = row["text"].encode("utf-8")
            if row["file_record_id"] not in files and len(files) >= limits.opened_files:
                stop_reason = "file_limit"
                break
            if len(selected) >= limits.opened_blocks:
                stop_reason = "block_limit"
                break
            if byte_count + len(encoded) > limits.returned_bytes:
                stop_reason = "byte_limit"
                break
            files.add(str(row["file_record_id"]))
            selected.append(candidate)
            byte_count += len(encoded)

        if timed_out:
            stop_reason = "time_limit"
        elif stop_reason is None:
            if metadata_candidate_overflow:
                stop_reason = "metadata_candidate_limit"
            elif lexical_overflow:
                stop_reason = "lexical_candidate_limit"
            else:
                stop_reason = "score_threshold" if selected else "no_candidates"

        budget_exhausted = stop_reason.endswith("_limit")
        if time.perf_counter() >= deadline:
            stop_reason = "time_limit"
            budget_exhausted = True
            selected = []

        fin = self.finalize_retrieval(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query_id=query_id,
            receipt_id=receipt_id,
            admitted_candidates=selected,
            stop_reason=stop_reason,
            budget_exhausted=budget_exhausted,
            context=local_context,
            authorized_ids=authorized_ids,
            limits=limits,
            total_authorized=total_authorized,
            started_perf=started_perf,
            t_query_stopped=t_query_stopped,
            deadline=deadline,
            lexical_candidates_count=len(candidates),
        )
        fin["t_query_stopped"] = t_query_stopped
        return fin


class ContinuationRetrievalCatalog(Catalog):
    """Catalog subclass wired with Gate 5A-2 Continuation Retrieval Switch."""

    def __init__(
        self,
        database: str | Path,
        *,
        extractor: Callable[[str, bytes], dict[str, Any]] | None = None,
        progress_step: int = 10,
        progress_handler: Callable[[], int] | None = None,
    ) -> None:
        super().__init__(database, extractor=extractor)
        self.progress_step = progress_step
        self.progress_handler = progress_handler
        self._retrieval_engine = ContinuationRetrievalEngine(
            self.conn,
            progress_step=progress_step,
            progress_handler=progress_handler,
        )

    def retrieve(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        limits: RetrievalLimits | None = None,
    ) -> dict[str, Any]:
        return self._retrieval_engine.retrieve(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query=query,
            limits=limits,
        )

    def _retrieve_snapshot(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        limits: RetrievalLimits | None = None,
    ) -> dict[str, Any]:
        return self._retrieval_engine._retrieve_snapshot(
            workspace_id=workspace_id,
            principal_id=principal_id,
            source_root_id=source_root_id,
            query=query,
            limits=limits,
        )


def wire_catalog_retrieval_switch(
    catalog: Catalog,
    *,
    progress_step: int = 10,
    progress_handler: Callable[[], int] | None = None,
) -> Catalog:
    """Wires an existing Catalog instance to use the Gate 5A-2 Continuation Retrieval Switch."""
    engine = ContinuationRetrievalEngine(
        catalog.conn,
        progress_step=progress_step,
        progress_handler=progress_handler,
    )
    setattr(catalog, "_retrieval_engine", engine)
    catalog.retrieve = engine.retrieve  # type: ignore[assignment]
    catalog._retrieve_snapshot = engine._retrieve_snapshot  # type: ignore[assignment]
    return catalog


def switched_retrieve(
    catalog: Catalog,
    *,
    workspace_id: str,
    principal_id: str,
    source_root_id: str,
    query: str,
    limits: RetrievalLimits | None = None,
    progress_step: int = 10,
    progress_handler: Callable[[], int] | None = None,
) -> dict[str, Any]:
    """Execute switched retrieval on any Catalog instance."""
    engine = getattr(catalog, "_retrieval_engine", None)
    if engine is None or progress_handler is not None or progress_step != 10:
        engine = ContinuationRetrievalEngine(
            catalog.conn,
            progress_step=progress_step,
            progress_handler=progress_handler,
        )
    return engine.retrieve(
        workspace_id=workspace_id,
        principal_id=principal_id,
        source_root_id=source_root_id,
        query=query,
        limits=limits,
    )
