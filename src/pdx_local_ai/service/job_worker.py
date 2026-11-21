"""RefreshJobQueueWorker with fine-grained transactions, worker-owned connections, and coalesced next-cycle queues."""

from __future__ import annotations

import codecs
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..catalog import Catalog
from ..text_continuation_materialization import MaterializationRepository
from ..text_continuation_runtime import ContinuationRepository
from ..text_intake_route import _spool_text
from ..validation import ContractError
from .contracts import (
    PermissionDeniedError,
    QueueFullError,
    RefreshJobStatus,
    RefreshPermissionDeniedError,
    RefreshSourceScope,
    ServiceError,
    ServiceShuttingDownError,
    ShutdownSummary,
    ShutdownTimeoutError,
)


class _WorkerCancelled(Exception):
    """Internal cancellation exception raised at cooperative checkpoints."""
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class FileJobEvent:
    file_record_id: str | None
    relative_path: str
    status: str  # "pending", "processing", "succeeded", "failed"
    stage: str   # "discovered", "intake", "continuation", "completed", "failed"
    error: str | None = None


@dataclass
class RootScanCoverage:
    workspace_id: str
    source_root_id: str
    last_scan_completed_at: str | None = None
    last_scan_succeeded_at: str | None = None
    last_full_coverage_at: str | None = None
    unsupported_count: int = 0


def _compute_ranges(snap: Any, chunk_size: int = 65536) -> list[tuple[int, int]]:
    """Bounded streaming range chunking strictly adhering to approved block and line budgets.

    Handles cross-batch CRLF without line splitting and defers 8192-codepoint hard cuts to verify
    whether lines truly exceed 8192 codepoints vs ending cleanly on a newline.
    """
    if snap.size == 0:
        return []
    prefix = snap.read_at(0, min(4, snap.size))
    if prefix.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8"
        bom_len = 3
    elif prefix.startswith(b"\xff\xfe"):
        encoding = "utf-16-le"
        bom_len = 2
    elif prefix.startswith(b"\xfe\xff"):
        encoding = "utf-16-be"
        bom_len = 2
    else:
        encoding = "utf-8"
        bom_len = 0

    decoder = codecs.getincrementaldecoder(encoding)()

    cut_offsets: list[int] = []
    pending_count = 0
    pending_stored_len = 0
    current_line_cps = 0

    line_start_byte = bom_len
    current_byte = bom_len
    stream_offset = bom_len

    pending_cr = False
    candidate_hard_cut: int | None = None

    def finish_line() -> None:
        nonlocal pending_count, pending_stored_len, current_line_cps, line_start_byte, candidate_hard_cut
        line_cps = current_line_cps
        current_line_cps = 0
        candidate_hard_cut = None

        if line_cps > 8192:
            if pending_count > 0:
                cut_offsets.append(line_start_byte)
                pending_count = 0
                pending_stored_len = 0
            cut_offsets.append(current_byte)
        else:
            cand_count = pending_count + 1
            cand_len = (pending_stored_len + 1 + line_cps) if pending_count > 0 else line_cps
            if pending_count > 0 and (cand_count > 40 or cand_len > 8192):
                cut_offsets.append(line_start_byte)
                pending_count = 1
                pending_stored_len = line_cps
            else:
                pending_count = cand_count
                pending_stored_len = cand_len
        line_start_byte = current_byte

    while stream_offset < snap.size:
        read_len = min(chunk_size, snap.size - stream_offset)
        raw_chunk = snap.read_at(stream_offset, read_len)
        stream_offset += read_len
        is_final = (stream_offset == snap.size)
        text_chunk = decoder.decode(raw_chunk, final=is_final)

        i = 0
        while i < len(text_chunk):
            ch = text_chunk[i]

            if pending_cr:
                if ch == "\n":
                    # Consumed CRLF across buffer boundaries
                    current_byte += len("\n".encode(encoding))
                    pending_cr = False
                    finish_line()
                    i += 1
                    continue
                else:
                    # Isolated CR from previous buffer
                    pending_cr = False
                    finish_line()

            if ch == "\r":
                current_byte += len("\r".encode(encoding))
                if i + 1 < len(text_chunk):
                    if text_chunk[i + 1] == "\n":
                        current_byte += len("\n".encode(encoding))
                        i += 1
                    finish_line()
                elif is_final:
                    finish_line()
                else:
                    pending_cr = True
            elif ch == "\n":
                current_byte += len("\n".encode(encoding))
                finish_line()
            else:
                if candidate_hard_cut is not None:
                    # Line continued past multiple of 8192 codepoints; commit approved hard cut
                    if pending_count > 0:
                        cut_offsets.append(line_start_byte)
                        pending_count = 0
                        pending_stored_len = 0
                    cut_offsets.append(candidate_hard_cut)
                    candidate_hard_cut = None

                current_line_cps += 1
                current_byte += len(ch.encode(encoding))
                if current_line_cps > 0 and current_line_cps % 8192 == 0:
                    candidate_hard_cut = current_byte
            i += 1

    if pending_cr:
        finish_line()
    elif current_line_cps > 0:
        if candidate_hard_cut is not None:
            if pending_count > 0:
                cut_offsets.append(line_start_byte)
                pending_count = 0
                pending_stored_len = 0
            cut_offsets.append(candidate_hard_cut)
        finish_line()

    ranges: list[tuple[int, int]] = []
    prev = 0
    for cut in cut_offsets:
        if cut > prev:
            ranges.append((prev, cut))
            prev = cut
    if prev < snap.size:
        ranges.append((prev, snap.size))
    return ranges


class RefreshJobQueueWorker:
    """Manages background incremental indexing, dedicated worker connection lifecycles, and coalesced queues."""

    _db_root_coverage: dict[tuple[str, str, str], RootScanCoverage] = {}
    _all_job_events: dict[str, dict[str, FileJobEvent]] = {}

    def __init__(
        self,
        catalog: Catalog,
        database_path: str | Path | None = None,
        max_queue_size: int = 64,
        max_active_workers: int = 1,
    ) -> None:
        self.catalog = catalog
        self.database_path = Path(database_path or catalog.database)
        self.extractor = catalog.extractor
        self.max_queue_size = max_queue_size
        self.max_active_workers = max_active_workers
        self._lock = threading.RLock()
        self._jobs: dict[str, RefreshJobStatus] = {}
        # Key: (workspace_id, source_root_id) -> active job_id
        self._active_jobs: dict[tuple[str, str], str] = {}
        # Key: (workspace_id, source_root_id) -> pending next cycle job_id
        self._pending_jobs: dict[tuple[str, str], str] = {}
        # Operator permissions: explicit grant required, default-deny
        self._refresh_permissions: dict[tuple[str, str, str], bool] = {}
        # Active worker threads
        self._active_worker_threads: set[threading.Thread] = set()
        # Shutdown & cooperative cancellation flags
        self._shutdown_event = threading.Event()
        self._shutting_down = False
        self._drain_in_progress = False
        self._drained_jobs_count = 0
        self._scanner: Any | None = None
        self._job_events_listeners: dict[str, threading.Event] = {}

    def record_job_event(
        self,
        *,
        job_id: str,
        workspace_id: str,
        source_root_id: str,
        relative_path: str,
        file_record_id: str | None,
        status: str,
        stage: str,
        error: str | None = None,
    ) -> None:
        """Record fine-grained per-file stage event for a specific job."""
        with self._lock:
            ev_dict = RefreshJobQueueWorker._all_job_events.setdefault(job_id, {})
            existing = ev_dict.get(relative_path)
            f_id = file_record_id or (existing.file_record_id if existing else None)
            ev_dict[relative_path] = FileJobEvent(
                file_record_id=f_id,
                relative_path=relative_path,
                status=status,
                stage=stage,
                error=error,
            )

    def get_job_events(self, job_id: str) -> list[FileJobEvent]:
        """Fetch all per-file stage events for a specific job."""
        with self._lock:
            events_dict = RefreshJobQueueWorker._all_job_events.get(job_id, {})
            return list(events_dict.values())

    def get_root_coverage(self, workspace_id: str, source_root_id: str) -> RootScanCoverage | None:
        """Fetch recorded cycle scan and coverage timestamps for a source root from persistent database."""
        try:
            with sqlite3.connect(str(self.database_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    """
                    SELECT last_scan_completed_at, last_scan_succeeded_at, last_full_coverage_at, unsupported_count
                    FROM source_root_coverage
                    WHERE workspace_id = ? AND source_root_id = ?
                    """,
                    (workspace_id, source_root_id),
                ).fetchone()
                if row:
                    return RootScanCoverage(
                        workspace_id=workspace_id,
                        source_root_id=source_root_id,
                        last_scan_completed_at=row["last_scan_completed_at"],
                        last_scan_succeeded_at=row["last_scan_succeeded_at"],
                        last_full_coverage_at=row["last_full_coverage_at"],
                        unsupported_count=int(row["unsupported_count"] or 0),
                    )
        except Exception:
            pass
        with self._lock:
            key = (str(self.database_path), workspace_id, source_root_id)
            return RefreshJobQueueWorker._db_root_coverage.get(key)

    def set_root_coverage(
        self,
        workspace_id: str,
        source_root_id: str,
        last_scan_completed_at: str | None = None,
        last_scan_succeeded_at: str | None = None,
        last_full_coverage_at: str | None = None,
        unsupported_count: int = 0,
    ) -> None:
        """Explicitly record scan and full coverage timestamps for a root in persistent database and memory."""
        now_iso = _now()
        cov = RootScanCoverage(
            workspace_id=workspace_id,
            source_root_id=source_root_id,
            last_scan_completed_at=last_scan_completed_at,
            last_scan_succeeded_at=last_scan_succeeded_at,
            last_full_coverage_at=last_full_coverage_at,
            unsupported_count=unsupported_count,
        )
        with self._lock:
            key = (str(self.database_path), workspace_id, source_root_id)
            RefreshJobQueueWorker._db_root_coverage[key] = cov
        try:
            with sqlite3.connect(str(self.database_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO source_root_coverage (
                        workspace_id, source_root_id, last_scan_completed_at,
                        last_scan_succeeded_at, last_full_coverage_at, unsupported_count,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(workspace_id, source_root_id) DO UPDATE SET
                        last_scan_completed_at = excluded.last_scan_completed_at,
                        last_scan_succeeded_at = COALESCE(excluded.last_scan_succeeded_at, source_root_coverage.last_scan_succeeded_at),
                        last_full_coverage_at = COALESCE(excluded.last_full_coverage_at, source_root_coverage.last_full_coverage_at),
                        unsupported_count = excluded.unsupported_count,
                        updated_at = excluded.updated_at
                    """,
                    (
                        workspace_id, source_root_id, last_scan_completed_at,
                        last_scan_succeeded_at, last_full_coverage_at, unsupported_count,
                        now_iso, now_iso,
                    ),
                )
        except Exception:
            pass

    def grant_refresh_permission(self, workspace_id: str, principal_id: str, source_root_id: str) -> None:
        """Explicitly authorize principal to trigger refresh on source root."""
        self._refresh_permissions[(workspace_id, principal_id, source_root_id)] = True

    def revoke_refresh_permission(self, workspace_id: str, principal_id: str, source_root_id: str) -> None:
        """Revoke principal's permission to trigger refresh on source root."""
        self._refresh_permissions[(workspace_id, principal_id, source_root_id)] = False

    def can_trigger_refresh(self, workspace_id: str, principal_id: str, source_root_id: str) -> bool:
        """Check if principal has can_trigger_refresh permission (default-deny)."""
        key = (workspace_id, principal_id, source_root_id)
        return self._refresh_permissions.get(key, False)

    def trigger_refresh(self, scope: RefreshSourceScope) -> RefreshJobStatus:
        """Enqueue or coalesce a refresh job for a source root."""
        if not self.can_trigger_refresh(scope.workspace_id, scope.operator_principal_id, scope.source_root_id):
            raise RefreshPermissionDeniedError(
                f"Principal '{scope.operator_principal_id}' does not have refresh permission on root '{scope.source_root_id}'"
            )

        key = (scope.workspace_id, scope.source_root_id)
        with self._lock:
            if self._shutting_down:
                raise ServiceShuttingDownError("Worker is shutting down and cannot accept new jobs")

            # 1. If root is already queued in pending jobs, coalesce immediately into existing pending job.
            # Does not consume additional queue slot, does not generate a new ID, and succeeds even if queue is at capacity.
            pending_id = self._pending_jobs.get(key)
            if pending_id:
                existing = self._jobs[pending_id]
                coalesced = RefreshJobStatus(
                    job_id=existing.job_id,
                    workspace_id=existing.workspace_id,
                    source_root_id=existing.source_root_id,
                    stage="scheduled_next_cycle",
                    is_coalesced_pending=True,
                    files_total=existing.files_total,
                    files_processed=existing.files_processed,
                )
                self._jobs[pending_id] = coalesced
                return coalesced

            # 2. If active job is currently running for this root, enqueue next-cycle job if capacity allows
            active_id = self._active_jobs.get(key)
            if active_id:
                if len(self._pending_jobs) >= self.max_queue_size:
                    raise QueueFullError(f"Worker queue reached capacity of {self.max_queue_size}")
                new_job_id = str(uuid.uuid4())
                pending_job = RefreshJobStatus(
                    job_id=new_job_id,
                    workspace_id=scope.workspace_id,
                    source_root_id=scope.source_root_id,
                    stage="scheduled_next_cycle",
                    is_coalesced_pending=False,
                )
                self._pending_jobs[key] = new_job_id
                self._jobs[new_job_id] = pending_job
                return pending_job

            # 3. No active job running for this root, but worker concurrency limit is reached
            if len(self._active_worker_threads) >= self.max_active_workers:
                if len(self._pending_jobs) >= self.max_queue_size:
                    raise QueueFullError(f"Worker queue reached capacity of {self.max_queue_size}")
                new_job_id = str(uuid.uuid4())
                pending_job = RefreshJobStatus(
                    job_id=new_job_id,
                    workspace_id=scope.workspace_id,
                    source_root_id=scope.source_root_id,
                    stage="scheduled_next_cycle",
                    is_coalesced_pending=False,
                )
                self._pending_jobs[key] = new_job_id
                self._jobs[new_job_id] = pending_job
                return pending_job

            # 4. Active worker slot is available: activate and spawn immediately
            job_id = str(uuid.uuid4())
            new_job = RefreshJobStatus(
                job_id=job_id,
                workspace_id=scope.workspace_id,
                source_root_id=scope.source_root_id,
                stage="scanning",
                is_coalesced_pending=False,
            )
            self._active_jobs[key] = job_id
            self._jobs[job_id] = new_job

            worker_thread = threading.Thread(
                target=self._run_job_lifecycle,
                args=(scope.workspace_id, scope.source_root_id, job_id),
                daemon=True,
            )
            self._active_worker_threads.add(worker_thread)
            worker_thread.start()
            return new_job

    def _run_job_lifecycle(self, workspace_id: str, source_root_id: str, job_id: str) -> None:
        """Run single job cycle and chain coalesced next cycle if scheduled."""
        key = (workspace_id, source_root_id)
        cur_thread = threading.current_thread()
        try:
            self._execute_scan_cycle(workspace_id, source_root_id, job_id)
        finally:
            with self._lock:
                self._active_worker_threads.discard(cur_thread)
                self._active_jobs.pop(key, None)

                # Check if we should dispatch next pending job
                can_dispatch = (not self._shutting_down or self._drain_in_progress) and not self._shutdown_event.is_set()
                if can_dispatch and len(self._active_worker_threads) < self.max_active_workers:
                    next_key = None
                    if key in self._pending_jobs:
                        next_key = key
                    elif self._pending_jobs:
                        next_key = next(iter(self._pending_jobs))

                    if next_key is not None:
                        next_job_id = self._pending_jobs.pop(next_key)
                        self._active_jobs[next_key] = next_job_id
                        pending_job = self._jobs[next_job_id]
                        self._jobs[next_job_id] = RefreshJobStatus(
                            job_id=pending_job.job_id,
                            workspace_id=pending_job.workspace_id,
                            source_root_id=pending_job.source_root_id,
                            stage="scanning",
                            is_coalesced_pending=pending_job.is_coalesced_pending,
                        )
                        next_ws, next_root = next_key
                        next_thread = threading.Thread(
                            target=self._run_job_lifecycle,
                            args=(next_ws, next_root, next_job_id),
                            daemon=True,
                        )
                        self._active_worker_threads.add(next_thread)
                        next_thread.start()

    def _execute_scan_cycle(self, workspace_id: str, source_root_id: str, job_id: str) -> None:
        """Execute scan, intake, and continuation materialization on a worker-owned connection."""
        worker_catalog: Catalog | None = None
        try:
            # Checkpoint A: before opening catalog connection
            if self._shutdown_event.is_set():
                raise _WorkerCancelled("Worker cancelled before opening catalog")

            # Dedicated connection created, held, and closed by the worker
            worker_catalog = Catalog(self.database_path, extractor=self.extractor)
            worker_catalog.conn.execute("PRAGMA busy_timeout = 5000")

            with self._lock:
                self._jobs[job_id] = RefreshJobStatus(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    stage="scanning",
                    is_coalesced_pending=self._jobs[job_id].is_coalesced_pending,
                )

            # Diagnostic/testing hook for simulating an uncooperative or blocked scan lifecycle
            sim_block = float(os.environ.get("PDX_WORKER_SIMULATE_BLOCK_SEC", "0.0"))
            if sim_block > 0.0:
                time.sleep(sim_block)

            # Pre-register existing active files as pending
            active_existing = worker_catalog.conn.execute(
                "SELECT file_record_id, relative_path FROM file_record WHERE workspace_id=? AND source_root_id=? AND catalog_status='active'",
                (workspace_id, source_root_id),
            ).fetchall()
            for fid, rpath in active_existing:
                self.record_job_event(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    relative_path=str(rpath),
                    file_record_id=str(fid),
                    status="pending",
                    stage="discovered",
                    error=None,
                )

            # Callback for scan phase file events
            def handle_file_event(rel_path: str, f_rec_id: str | None, status: str, stage: str, err: str | None) -> None:
                # Checkpoint B: during catalog scan file processing
                if self._shutdown_event.is_set():
                    raise _WorkerCancelled("Worker cancelled during directory scan")
                self.record_job_event(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    relative_path=rel_path,
                    file_record_id=f_rec_id,
                    status=status,
                    stage=stage,
                    error=err,
                )

            # 1. Full directory scan and catalog intake (handles empty directory & deletion cleanly)
            scan_counts = worker_catalog.scan(
                source_root_id=source_root_id,
                raise_on_error=True,
                on_file_event=handle_file_event,
            )

            total_discovered = (
                scan_counts.get("indexed", 0)
                + scan_counts.get("unchanged", 0)
                + scan_counts.get("stale", 0)
            )

            with self._lock:
                self._jobs[job_id] = RefreshJobStatus(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    stage="indexing",
                    is_coalesced_pending=self._jobs[job_id].is_coalesced_pending,
                    files_total=total_discovered,
                    files_processed=scan_counts.get("indexed", 0) + scan_counts.get("unchanged", 0),
                )

            # 2. Ingest unindexed / updated text files into full continuation generation pipeline
            unindexed_files = worker_catalog.conn.execute(
                """
                SELECT f.file_record_id, f.current_source_version_id, f.relative_path, r.canonical_path, sv.source_sha256, sv.size_bytes
                FROM file_record f
                JOIN source_root r ON r.source_root_id = f.source_root_id
                JOIN source_version sv ON sv.source_version_id = f.current_source_version_id
                JOIN text_projection tp ON tp.source_version_id = f.current_source_version_id
                WHERE f.source_root_id = ?
                  AND f.catalog_status = 'active'
                  AND sv.size_bytes > 0
                  AND NOT EXISTS (
                      SELECT 1 FROM text_current_published_generation pub
                      WHERE pub.file_record_id = f.file_record_id AND pub.source_version_id = f.current_source_version_id
                  )
                ORDER BY f.file_record_id ASC
                """,
                (source_root_id,),
            ).fetchall()

            unindexed_ids = {str(r[0]) for r in unindexed_files}
            all_active = worker_catalog.conn.execute(
                """
                SELECT f.file_record_id, f.relative_path
                FROM file_record f
                WHERE f.source_root_id = ? AND f.catalog_status = 'active'
                """,
                (source_root_id,),
            ).fetchall()

            for af_id, af_rel in all_active:
                af_id_str = str(af_id)
                if af_id_str not in unindexed_ids:
                    # File does not need continuation (already published or 0 bytes or kernel-indexed)
                    with self._lock:
                        events_dict = RefreshJobQueueWorker._all_job_events.get(job_id, {})
                        cur_ev = events_dict.get(af_id_str) or next((e for e in events_dict.values() if e.relative_path == str(af_rel)), None)
                    if cur_ev and cur_ev.status == "succeeded" and cur_ev.stage != "completed":
                        self.record_job_event(
                            job_id=job_id,
                            workspace_id=workspace_id,
                            source_root_id=source_root_id,
                            relative_path=str(af_rel),
                            file_record_id=af_id_str,
                            status="succeeded",
                            stage="completed",
                            error=None,
                        )

            # Close worker_catalog to prevent SQLite concurrency contention during continuation transactions
            worker_catalog.close()
            worker_catalog = None

            for row in unindexed_files:
                # Checkpoint C: before continuation processing for file
                if self._shutdown_event.is_set():
                    raise _WorkerCancelled("Worker cancelled before continuation processing")
                f_id = str(row[0])
                sv_id = str(row[1])
                rel_path = str(row[2])
                c_root = Path(str(row[3])).resolve()
                rel_path_obj = Path(rel_path)
                f_path = (c_root / rel_path_obj).resolve()
                sv_sha = str(row[4])
                sv_size = int(row[5])

                self.record_job_event(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    relative_path=rel_path,
                    file_record_id=f_id,
                    status="processing",
                    stage="continuation",
                    error=None,
                )

                snap = None
                try:
                    if self._shutdown_event.is_set():
                        raise _WorkerCancelled("Worker cancelled before text spooling")
                    snap = _spool_text(f_path, rel_path, c_root)
                    if self._shutdown_event.is_set():
                        raise _WorkerCancelled("Worker cancelled after text spooling")
                    ranges = _compute_ranges(snap)
                    if not ranges:
                        self.record_job_event(
                            job_id=job_id,
                            workspace_id=workspace_id,
                            source_root_id=source_root_id,
                            relative_path=rel_path,
                            file_record_id=f_id,
                            status="succeeded",
                            stage="completed",
                            error=None,
                        )
                        continue
                    gen_id = f"gen-{uuid.uuid4().hex[:16]}"
                    now_ms = int(time.time() * 1000)

                    members: list[dict[str, Any]] = []
                    with ContinuationRepository(db_path=self.database_path) as cont_repo:
                        for ordinal, (r_start, r_end) in enumerate(ranges):
                            if self._shutdown_event.is_set():
                                raise _WorkerCancelled("Worker cancelled during range artifact creation")
                            art_id = f"art-{uuid.uuid4().hex[:16]}"
                            art_ts = now_ms + ordinal * 1000
                            cont_repo.commit_range_artifact(
                                {
                                    "range_artifact_id": art_id,
                                    "workspace_id": workspace_id,
                                    "file_record_id": f_id,
                                    "source_version_id": sv_id,
                                    "source_sha256": sv_sha,
                                    "snapshot_mode": "rebuild_controlled_snapshot_and_verify_source_sha256",
                                    "range_ordinal": ordinal,
                                    "range_start": r_start,
                                    "range_end_exclusive": r_end,
                                    "created_at_unix_ms": art_ts,
                                },
                                snapshot=snap,
                            )
                            d_row = cont_repo._conn.execute(
                                "SELECT manifest_digest FROM text_range_artifact WHERE range_artifact_id = ?",
                                (art_id,),
                            ).fetchone()
                            m_digest = str(d_row[0])
                            members.append({
                                "range_ordinal": ordinal,
                                "range_artifact_id": art_id,
                                "range_start": r_start,
                                "range_end_exclusive": r_end,
                                "manifest_digest": m_digest,
                            })

                        gen_ts = now_ms + len(ranges) * 1000
                        seal_ts = gen_ts + 500

                        # create_generation
                        cont_repo.create_generation({
                            "generation_id": gen_id,
                            "workspace_id": workspace_id,
                            "file_record_id": f_id,
                            "source_version_id": sv_id,
                            "source_sha256": sv_sha,
                            "source_size_bytes": snap.size,
                            "snapshot_mode": "rebuild_controlled_snapshot_and_verify_source_sha256",
                            "total_ranges": len(ranges),
                            "total_bytes": snap.size,
                            "final_manifest_digest": members[-1]["manifest_digest"],
                            "created_at_unix_ms": gen_ts,
                        })

                        # add_generation_member
                        for m in members:
                            cont_repo.add_generation_member(gen_id, m)

                        # seal_generation
                        cont_repo.seal_generation(gen_id, sealed_at_unix_ms=seal_ts)

                    # materialize_generation
                    with MaterializationRepository(self.database_path) as mat_repo:
                        mat_repo.materialize_generation(gen_id)

                    # Checkpoint D: before publication transaction
                    if self._shutdown_event.is_set():
                        raise _WorkerCancelled("Worker cancelled before publishing generation")

                    # publish_generation
                    with ContinuationRepository(db_path=self.database_path) as cont_repo:
                        wit_id = f"wit-{uuid.uuid4().hex[:16]}"
                        pub_id = f"pub-{uuid.uuid4().hex[:16]}"
                        cont_repo.publish_generation(
                            source_file=f_path,
                            expected_sha=sv_sha,
                            generation_id=gen_id,
                            witness_id=wit_id,
                            publication_id=pub_id,
                            workspace_id=workspace_id,
                            file_record_id=f_id,
                            source_version_id=sv_id,
                        )

                    self.record_job_event(
                        job_id=job_id,
                        workspace_id=workspace_id,
                        source_root_id=source_root_id,
                        relative_path=rel_path,
                        file_record_id=f_id,
                        status="succeeded",
                        stage="completed",
                        error=None,
                    )
                except _WorkerCancelled:
                    raise
                except Exception as exc:
                    self.record_job_event(
                        job_id=job_id,
                        workspace_id=workspace_id,
                        source_root_id=source_root_id,
                        relative_path=rel_path,
                        file_record_id=f_id,
                        status="failed",
                        stage="continuation",
                        error=str(exc),
                    )
                    raise
                finally:
                    if snap is not None:
                        snap.cleanup()

            # 3. Continuation materialization pipeline: query unmaterialized sealed generations
            with sqlite3.connect(str(self.database_path)) as conn:
                unmaterialized = conn.execute(
                    """
                    SELECT s.generation_id
                    FROM text_range_generation_seal s
                    JOIN text_range_generation g ON g.generation_id = s.generation_id
                    JOIN file_record f ON f.file_record_id = g.file_record_id
                    WHERE f.source_root_id = ?
                      AND s.generation_id NOT IN (
                          SELECT generation_id FROM text_continuation_materialization_marker
                      )
                    ORDER BY s.sealed_at_unix_ms ASC
                    """,
                    (source_root_id,),
                ).fetchall()

            for (gen_id,) in unmaterialized:
                if self._shutdown_event.is_set():
                    raise _WorkerCancelled("Worker cancelled before materialization")
                with MaterializationRepository(self.database_path) as repo:
                    repo.materialize_generation(gen_id)

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            events = self.get_job_events(job_id)
            has_failures = any(ev.status == "failed" for ev in events)
            final_stage = "failed" if has_failures else "completed"
            err_summary = next((ev.error for ev in events if ev.status == "failed" and ev.error), None) if has_failures else None

            cov_succeeded = now_iso if not has_failures else None
            is_full_coverage = False
            if not has_failures and total_discovered > 0:
                with sqlite3.connect(str(self.database_path)) as ro:
                    unindexed = ro.execute(
                        "SELECT COUNT(*) FROM file_record WHERE workspace_id=? AND source_root_id=? AND catalog_status='active' AND current_source_version_id IS NULL",
                        (workspace_id, source_root_id),
                    ).fetchone()[0]
                    unpub = ro.execute(
                        """
                        SELECT COUNT(*) FROM file_record f
                        WHERE f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
                          AND f.current_source_version_id IS NOT NULL
                          AND NOT EXISTS (
                              SELECT 1 FROM text_projection_publication pub WHERE pub.source_version_id = f.current_source_version_id
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM projection p WHERE p.source_version_id = f.current_source_version_id
                          )
                        """,
                        (workspace_id, source_root_id),
                    ).fetchone()[0]
                    if unindexed == 0 and unpub == 0:
                        is_full_coverage = True
            cov_full = now_iso if is_full_coverage else None
            unsupported_cnt = scan_counts.get("unsupported", 0)

            self.set_root_coverage(
                workspace_id=workspace_id,
                source_root_id=source_root_id,
                last_scan_completed_at=now_iso,
                last_scan_succeeded_at=now_iso if not has_failures else None,
                last_full_coverage_at=cov_full,
                unsupported_count=unsupported_cnt,
            )

            with self._lock:
                self._jobs[job_id] = RefreshJobStatus(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    stage=final_stage,
                    is_coalesced_pending=self._jobs[job_id].is_coalesced_pending,
                    files_total=total_discovered,
                    files_processed=total_discovered if not has_failures else (scan_counts.get("indexed", 0) + scan_counts.get("unchanged", 0)),
                    error_summary=err_summary,
                )

        except _WorkerCancelled as exc:
            if worker_catalog is not None:
                try:
                    worker_catalog.conn.rollback()
                except Exception:
                    pass
                try:
                    worker_catalog.close()
                except Exception:
                    pass
                worker_catalog = None
            with self._lock:
                cur = self._jobs.get(job_id)
                self._jobs[job_id] = RefreshJobStatus(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    stage="failed",
                    is_coalesced_pending=cur.is_coalesced_pending if cur else False,
                    error_summary="WORKER_CANCELLED",
                )
            self._signal_job_completed(job_id)
        except Exception as exc:
            if worker_catalog is not None:
                try:
                    worker_catalog.conn.rollback()
                except Exception:
                    pass
                try:
                    worker_catalog.close()
                except Exception:
                    pass
                worker_catalog = None
            with self._lock:
                cur = self._jobs.get(job_id)
                self._jobs[job_id] = RefreshJobStatus(
                    job_id=job_id,
                    workspace_id=workspace_id,
                    source_root_id=source_root_id,
                    stage="failed",
                    is_coalesced_pending=cur.is_coalesced_pending if cur else False,
                    error_summary=str(exc),
                )
            self._signal_job_completed(job_id)
        else:
            with self._lock:
                self._drained_jobs_count += 1
            self._signal_job_completed(job_id)
        finally:
            if worker_catalog is not None:
                try:
                    worker_catalog.close()
                except Exception:
                    pass

    def _signal_job_completed(self, job_id: str) -> None:
        with self._lock:
            ev = self._job_events_listeners.get(job_id)
            if ev is not None:
                ev.set()

    def get_job_completion_event(self, job_id: str) -> threading.Event:
        """Fetch or create thread-safe event signaled when job finishes."""
        with self._lock:
            if job_id not in self._job_events_listeners:
                ev = threading.Event()
                cur = self._jobs.get(job_id)
                if cur and cur.stage in ("completed", "failed", "rejected"):
                    ev.set()
                self._job_events_listeners[job_id] = ev
            return self._job_events_listeners[job_id]

    def attach_scanner(self, scanner: Any) -> None:
        """Attach associated scanner to stop during worker shutdown."""
        self._scanner = scanner

    def is_shutting_down(self) -> bool:
        """Check if worker is currently in shutdown phase."""
        with self._lock:
            return self._shutting_down

    def shutdown(self, drain: bool = True, timeout_sec: float = 10.0) -> ShutdownSummary:
        """Gracefully shuts down worker, stopping ingestion, optionally draining or cancelling within timeout_sec."""
        start_mono = time.monotonic()
        deadline = start_mono + timeout_sec

        if self._scanner is not None and hasattr(self._scanner, "stop"):
            scanner_timeout = max(0.01, deadline - time.monotonic())
            try:
                self._scanner.stop(timeout=scanner_timeout)
            except TypeError:
                self._scanner.stop()

        with self._lock:
            self._shutting_down = True
            self._drain_in_progress = drain

        if not drain:
            self._shutdown_event.set()
            with self._lock:
                for p_key, p_id in list(self._pending_jobs.items()):
                    pj = self._jobs.get(p_id)
                    if pj:
                        self._jobs[p_id] = RefreshJobStatus(
                            job_id=pj.job_id,
                            workspace_id=pj.workspace_id,
                            source_root_id=pj.source_root_id,
                            stage="failed",
                            is_coalesced_pending=pj.is_coalesced_pending,
                            error_summary="SHUTDOWN_DRAIN_ABORTED",
                        )
                        self._signal_job_completed(p_id)
                self._pending_jobs.clear()

        # Wait for threads and pending jobs to drain or cancel
        while time.monotonic() < deadline:
            with self._lock:
                active_workers = len(self._active_worker_threads)
                pending_count = len(self._pending_jobs)
                scanner_alive = (
                    self._scanner is not None
                    and hasattr(self._scanner, "is_running")
                    and self._scanner.is_running()
                )
            if active_workers == 0 and pending_count == 0 and not scanner_alive:
                break
            time.sleep(0.02)

        if time.monotonic() >= deadline:
            # Deadline expired! Trigger cancellation to remaining threads
            self._shutdown_event.set()
            with self._lock:
                for p_key, p_id in list(self._pending_jobs.items()):
                    pj = self._jobs.get(p_id)
                    if pj:
                        self._jobs[p_id] = RefreshJobStatus(
                            job_id=pj.job_id,
                            workspace_id=pj.workspace_id,
                            source_root_id=pj.source_root_id,
                            stage="failed",
                            is_coalesced_pending=pj.is_coalesced_pending,
                            error_summary="SHUTDOWN_DRAIN_ABORTED",
                        )
                        self._signal_job_completed(p_id)
                self._pending_jobs.clear()

        # Join surviving threads with remaining time budget
        rem_budget = max(0.01, deadline - time.monotonic())
        with self._lock:
            threads_to_join = list(self._active_worker_threads)
        for t in threads_to_join:
            t.join(timeout=rem_budget)

        with self._lock:
            alive_threads = [t for t in self._active_worker_threads if t.is_alive()]
            remaining_active = list(self._active_jobs.values())
            remaining_pending = list(self._pending_jobs.values())
            scanner_alive = (
                self._scanner is not None
                and hasattr(self._scanner, "is_running")
                and self._scanner.is_running()
            )

        total_alive = len(alive_threads) + (1 if scanner_alive else 0)
        remaining_jobs = remaining_active + remaining_pending

        if total_alive > 0 or remaining_jobs:
            return ShutdownSummary(
                status="shutdown_incomplete",
                alive_threads_count=total_alive,
                remaining_jobs=remaining_jobs,
                drained_jobs_count=self._drained_jobs_count,
            )
        else:
            return ShutdownSummary(
                status="completed_clean",
                alive_threads_count=0,
                remaining_jobs=[],
                drained_jobs_count=self._drained_jobs_count,
            )

    def get_job_status(self, job_id: str) -> RefreshJobStatus | None:
        """Retrieve job status by job_id."""
        with self._lock:
            return self._jobs.get(job_id)


class PeriodicScanner:
    """Periodically triggers background refresh for registered source roots."""

    def __init__(self, worker: RefreshJobQueueWorker, interval_seconds: float = 60.0) -> None:
        self.worker = worker
        self.interval_seconds = interval_seconds
        self._lock = threading.Lock()
        self._scopes: set[RefreshSourceScope] = set()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def is_running(self) -> bool:
        """Check if periodic scanner thread is currently running."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def register(self, scope: RefreshSourceScope) -> None:
        """Register a source scope for periodic scanning."""
        with self._lock:
            self._scopes.add(scope)

    def unregister(self, scope: RefreshSourceScope) -> None:
        """Unregister a source scope."""
        with self._lock:
            self._scopes.discard(scope)

    def start(self) -> None:
        """Start the periodic scan background thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the periodic scan background thread without masking alive threads on timeout."""
        self._stop_event.set()
        with self._lock:
            t = self._thread
        if t is not None:
            t.join(timeout=timeout)
            with self._lock:
                if not t.is_alive():
                    self._thread = None
                # If still alive, self._thread remains observable!

    def _run_loop(self) -> None:
        """Periodic loop scanning all registered scopes."""
        while not self._stop_event.wait(self.interval_seconds):
            with self._lock:
                scopes_to_run = list(self._scopes)
            for scope in scopes_to_run:
                if self._stop_event.is_set():
                    break
                try:
                    self.worker.trigger_refresh(scope)
                except Exception:
                    pass
