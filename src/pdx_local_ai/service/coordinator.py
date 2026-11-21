"""MultiRootRetrievalCoordinator with single SQLite transaction ownership, dynamic busy timeout, and deterministic RRF."""

from __future__ import annotations

import math
import sqlite3
import time
import uuid
from collections import defaultdict
from typing import Any

from ..catalog import RetrievalLimits
from ..text_continuation_retrieval import CandidateBlock, ContinuationRetrievalEngine
from .contracts import (
    AgentSearchRequest,
    AgentSearchResponse,
    IndexBusyError,
    InternalCandidateContext,
    PermissionDeniedError,
    SearchResultItem,
    ServiceError,
    TimeoutExhaustedError,
)

_BUSY_EXTENDED_CODES = {
    5,    # SQLITE_BUSY
    6,    # SQLITE_LOCKED
    261,  # SQLITE_BUSY_RECOVERY
    517,  # SQLITE_BUSY_SNAPSHOT
    773,  # SQLITE_BUSY_TIMEOUT
    262,  # SQLITE_LOCKED_SHAREDCACHE
}


def _is_busy_or_locked(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return code in _BUSY_EXTENDED_CODES
    msg = str(exc).lower()
    return "database is locked" in msg or "database table is locked" in msg or "database is busy" in msg


class MultiRootRetrievalCoordinator:
    """Coordinates search across multiple source roots within a single SQLite transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def _acquire_immediate_transaction(self, deadline_perf: float) -> None:
        """Acquire BEGIN IMMEDIATE with dynamic busy_timeout and backoff until deadline_perf."""
        backoff = 0.005
        while True:
            now = time.perf_counter()
            if now >= deadline_perf:
                raise TimeoutExhaustedError("Deadline exceeded while waiting for database lock")
            remaining_ms = max(1, math.ceil((deadline_perf - now) * 1000.0))
            try:
                self.conn.execute(f"PRAGMA busy_timeout = {remaining_ms}")
                self.conn.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if not _is_busy_or_locked(exc):
                    raise
                if time.perf_counter() >= deadline_perf:
                    raise IndexBusyError("Lock busy timeout exhausted") from exc
                time.sleep(backoff)
                backoff = min(backoff * 1.5, 0.05)

    def _check_root_authorized(self, workspace_id: str, principal_id: str, source_root_id: str) -> None:
        """Verify root is enabled and principal is authorized to read."""
        row = self.conn.execute(
            "SELECT enabled FROM source_root WHERE workspace_id=? AND source_root_id=?",
            (workspace_id, source_root_id),
        ).fetchone()
        if not row or int(row[0]) != 1:
            raise PermissionDeniedError(f"Source root '{source_root_id}' is not enabled or does not belong to workspace")

        auth_row = self.conn.execute(
            """
            SELECT 1 FROM file_acl a
            JOIN file_record f ON f.file_record_id = a.file_record_id
            WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
              AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
            LIMIT 1
            """,
            (workspace_id, principal_id, workspace_id, source_root_id),
        ).fetchone()
        if not auth_row:
            raise PermissionDeniedError(f"Principal '{principal_id}' has no read access to source root '{source_root_id}'")

    def execute_search(
        self,
        request: AgentSearchRequest,
        deadline_perf: float | None = None,
        started_perf: float | None = None,
    ) -> AgentSearchResponse:
        """Execute multi-root search under a single atomic SQLite transaction with global budgets."""
        request.validate()
        if started_perf is None:
            started_perf = time.perf_counter()
        if deadline_perf is None:
            deadline_perf = started_perf + (request.timeout_ms / 1000.0)

        try:
            self._acquire_immediate_transaction(deadline_perf)
        except (TimeoutExhaustedError, IndexBusyError):
            latency_ms = (time.perf_counter() - started_perf) * 1000.0
            return AgentSearchResponse(
                query_id=str(uuid.uuid4()),
                status="timed_out",
                stop_reason="time_limit",
                results=[],
                receipts=[],
                latency_ms=latency_ms,
                finalization_latency_ms=0.0,
                cumulative_rows_fetched=0,
                receipt_id=None,
                warning="DEADLINE_EXCEEDED_BEFORE_LOCK",
                degraded=True,
            )

        try:
            query_id = str(uuid.uuid4())
            tx_token = str(uuid.uuid4())
            db_conn_id = id(self.conn)
            context = InternalCandidateContext(
                query_id=query_id,
                principal_id=request.principal_id,
                workspace_id=request.workspace_id,
                db_conn_id=db_conn_id,
                tx_token=tx_token,
                created_perf=started_perf,
            )

            # Pre-flight authorization check for all roots
            for root_id in request.source_root_ids:
                self._check_root_authorized(request.workspace_id, request.principal_id, root_id)

            engine = ContinuationRetrievalEngine(self.conn)
            contacted_roots: list[str] = []
            root_fetch_meta: dict[str, dict[str, Any]] = {}
            all_candidates: list[CandidateBlock] = []
            timed_out = False

            # Global decremented candidate budgets
            remaining_meta = request.effective_metadata_candidates
            remaining_lex = request.effective_lexical_candidates
            candidate_budget_exhausted_reason: str | None = None

            # Bounded fetch across roots with global budget decrementation
            for root_id in request.source_root_ids:
                if time.perf_counter() >= deadline_perf:
                    timed_out = True
                    break
                if remaining_meta <= 0 or remaining_lex <= 0:
                    # Global candidate budget exhausted across roots
                    if remaining_lex <= 0:
                        candidate_budget_exhausted_reason = "lexical_candidate_limit"
                    else:
                        candidate_budget_exhausted_reason = "metadata_candidate_limit"
                    break

                contacted_roots.append(root_id)
                remaining_ms = max(1, math.ceil((deadline_perf - time.perf_counter()) * 1000.0))
                limits = RetrievalLimits(
                    metadata_candidates=remaining_meta,
                    lexical_candidates=remaining_lex,
                    opened_files=request.opened_files,
                    opened_blocks=request.opened_blocks,
                    returned_bytes=request.returned_bytes,
                    elapsed_ms=remaining_ms,
                    deadline_perf=deadline_perf,
                )

                fetch_res = engine.fetch_candidates(
                    workspace_id=request.workspace_id,
                    principal_id=request.principal_id,
                    source_root_id=root_id,
                    query=request.query,
                    limits=limits,
                    context=context,
                )
                root_fetch_meta[root_id] = fetch_res
                if fetch_res["timed_out"]:
                    timed_out = True
                    break

                # Decrement remaining global budgets
                consumed_meta = len(fetch_res["authorized_ids"])
                consumed_lex = len(fetch_res["candidates"])
                remaining_meta = max(0, remaining_meta - consumed_meta)
                remaining_lex = max(0, remaining_lex - consumed_lex)
                all_candidates.extend(fetch_res["candidates"])

            if time.perf_counter() >= deadline_perf:
                timed_out = True

            # Reciprocal Rank Fusion (RRF)
            # Group candidate blocks by unique block identity: (source_root_id, file_record_id, block_instance_id)
            block_positions: dict[tuple[str, str, str], list[int]] = defaultdict(list)
            block_rep: dict[tuple[str, str, str], CandidateBlock] = {}

            for c in all_candidates:
                key = (c.source_root_id, c.file_record_id, c.block_instance_id)
                block_positions[key].append(c.stream_position)
                if key not in block_rep:
                    block_rep[key] = c

            scored_blocks: list[tuple[float, CandidateBlock]] = []
            for key, positions in block_positions.items():
                score = sum(1.0 / (60.0 + pos) for pos in positions)
                scored_blocks.append((score, block_rep[key]))

            # Deterministic sorting: score DESC, tie-breaker: (source_root_id ASC, file_record_id ASC, block_instance_id ASC)
            scored_blocks.sort(
                key=lambda item: (
                    -item[0],
                    item[1].source_root_id,
                    item[1].file_record_id,
                    item[1].block_instance_id,
                )
            )

            # Global Budget Admittance Selection
            selected_candidates: list[CandidateBlock] = []
            files_opened: set[str] = set()
            bytes_opened = 0
            stop_reason: str | None = None

            if not timed_out:
                for score, cand in scored_blocks:
                    if time.perf_counter() >= deadline_perf:
                        timed_out = True
                        break

                    row = cand.row_payload
                    encoded = str(row["text"]).encode("utf-8")

                    if cand.file_record_id not in files_opened and len(files_opened) >= request.opened_files:
                        stop_reason = "file_limit"
                        break
                    if len(selected_candidates) >= request.opened_blocks:
                        stop_reason = "block_limit"
                        break
                    if len(selected_candidates) >= request.limit:
                        stop_reason = "score_threshold"
                        break
                    if bytes_opened + len(encoded) > request.returned_bytes:
                        stop_reason = "byte_limit"
                        break

                    files_opened.add(cand.file_record_id)
                    bytes_opened += len(encoded)
                    selected_candidates.append(cand)

                if stop_reason is None:
                    if candidate_budget_exhausted_reason and (len(contacted_roots) < len(request.source_root_ids) or remaining_lex <= 0 or remaining_meta <= 0):
                        stop_reason = candidate_budget_exhausted_reason
                    else:
                        stop_reason = "score_threshold" if selected_candidates else "no_candidates"

            if timed_out or time.perf_counter() >= deadline_perf:
                timed_out = True
                stop_reason = "time_limit"
                selected_candidates = []

            budget_exhausted = stop_reason.endswith("_limit")

            # Finalize across contacted roots:
            # Under contract: If ANY timeout occurs before or during finalization,
            # ALL candidates must be cleared across all roots, leaving zero half-success states.
            score_lookup = {
                (c.source_root_id, c.file_record_id, c.block_instance_id): score
                for score, c in scored_blocks
            }

            def _build_receipts_and_results(
                candidates_to_finalize: list[CandidateBlock],
                current_stop_reason: str,
                current_budget_exhausted: bool,
            ) -> tuple[list[dict[str, Any]], list[SearchResultItem]]:
                receipts_out: list[dict[str, Any]] = []
                results_out: list[SearchResultItem] = []
                for root_id in contacted_roots:
                    meta = root_fetch_meta[root_id]
                    admitted_for_root = [c for c in candidates_to_finalize if c.source_root_id == root_id]
                    root_limits = RetrievalLimits(
                        metadata_candidates=request.effective_metadata_candidates,
                        lexical_candidates=request.effective_lexical_candidates,
                        opened_files=request.opened_files,
                        opened_blocks=request.opened_blocks,
                        returned_bytes=request.returned_bytes,
                        elapsed_ms=max(1, math.ceil((deadline_perf - started_perf) * 1000.0)),
                        deadline_perf=deadline_perf,
                    )
                    root_receipt_id = str(uuid.uuid4())
                    fin_res = engine.finalize_retrieval(
                        workspace_id=request.workspace_id,
                        principal_id=request.principal_id,
                        source_root_id=root_id,
                        query_id=query_id,
                        receipt_id=root_receipt_id,
                        admitted_candidates=admitted_for_root,
                        stop_reason=current_stop_reason,
                        budget_exhausted=current_budget_exhausted,
                        context=context,
                        authorized_ids=meta["authorized_ids"],
                        limits=root_limits,
                        total_authorized=meta["total_authorized"],
                        started_perf=meta["started_perf"],
                        t_query_stopped=meta["t_query_stopped"],
                        deadline=deadline_perf,
                        scope_eligible_roots=len(request.source_root_ids),
                        scope_searched_roots=len(contacted_roots),
                    )
                    receipts_out.append(fin_res["receipt"])
                    for res in fin_res["results"]:
                        cit = res["citation"]
                        key = (cit["source_root_id"], cit["file_record_id"], cit["block_instance_id"])
                        results_out.append(
                            SearchResultItem(
                                file_record_id=cit["file_record_id"],
                                source_root_id=cit["source_root_id"],
                                block_instance_id=cit["block_instance_id"],
                                score=score_lookup.get(key, 0.0),
                                text=res["text"],
                                citation=cit,
                            )
                        )
                return receipts_out, results_out

            receipts: list[dict[str, Any]] = []
            final_results: list[SearchResultItem] = []

            if not timed_out:
                # Use SAVEPOINT to protect partial writes without ever releasing the single BEGIN IMMEDIATE lock!
                self.conn.execute("SAVEPOINT multi_root_finalization")
                receipts, final_results = _build_receipts_and_results(selected_candidates, stop_reason, budget_exhausted)
                # Check if finalization exceeded deadline:
                if time.perf_counter() >= deadline_perf:
                    # Rollback partial candidate writes to eliminate cross-root half-success within the SAME transaction!
                    self.conn.execute("ROLLBACK TO SAVEPOINT multi_root_finalization")
                    self.conn.execute("RELEASE SAVEPOINT multi_root_finalization")
                    timed_out = True
                    stop_reason = "time_limit"
                    budget_exhausted = True
                    selected_candidates = []
                    receipts, final_results = _build_receipts_and_results([], "time_limit", True)
                else:
                    self.conn.execute("RELEASE SAVEPOINT multi_root_finalization")
            else:
                receipts, final_results = _build_receipts_and_results([], "time_limit", True)

            # Deterministic tie-breaker sorting: score DESC, source_root_id ASC, file_record_id ASC, block_instance_id ASC
            final_results.sort(
                key=lambda r: (
                    -r.score,
                    r.source_root_id,
                    r.file_record_id,
                    r.block_instance_id,
                )
            )

            # Atomic commit of all roots' receipts and citations
            self.conn.commit()

            ended_perf = time.perf_counter()
            latency_ms = (ended_perf - started_perf) * 1000.0

            # Measure finalization latency accurately AFTER conn.commit()
            min_t_query_stopped = (
                min(meta["t_query_stopped"] for meta in root_fetch_meta.values())
                if root_fetch_meta
                else started_perf
            )
            finalization_latency_ms = max(0.0, (ended_perf - min_t_query_stopped) * 1000.0)

            primary_receipt_id = receipts[0]["receipt_id"] if receipts and "receipt_id" in receipts[0] else None

            return AgentSearchResponse(
                query_id=query_id,
                status="timed_out" if timed_out else "completed",
                stop_reason=stop_reason or "score_threshold",
                results=final_results,
                receipts=receipts,
                latency_ms=latency_ms,
                finalization_latency_ms=finalization_latency_ms,
                cumulative_rows_fetched=engine.cumulative_rows_fetched,
                receipt_id=primary_receipt_id,
            )

        except Exception:
            self.conn.rollback()
            raise
