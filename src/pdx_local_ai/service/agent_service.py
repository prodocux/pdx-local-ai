"""PdxLocalAgentService implementing dual-perspective ACL and unified service endpoints."""

from __future__ import annotations

import datetime
import json
import math
import time
import uuid
from typing import Any

from ..catalog import Catalog
from .contracts import (
    AgentSearchRequest,
    AgentSearchResponse,
    PermissionDeniedError,
    QueueFullError,
    RefreshJobStatus,
    RefreshPermissionDeniedError,
    RefreshSourceScope,
    SecurityContext,
    SourceIndexStatus,
)
from .coordinator import MultiRootRetrievalCoordinator
from .job_worker import PeriodicScanner, RefreshJobQueueWorker


SUPPORTED_REFRESH_POLICIES = ("manual_only", "interval_scan")


def _parse_iso_to_unix(iso_str: str) -> float:
    try:
        from datetime import datetime, timezone
        cleaned = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


class PdxLocalAgentService:
    """Unified service entrypoint for AI agent retrieval and background index operations."""

    def __init__(
        self,
        catalog: Catalog,
        worker: RefreshJobQueueWorker | None = None,
        refresh_policy: str = "manual_only",
        poll_interval_sec: float = 60.0,
        stale_ttl_sec: float = 300.0,
    ) -> None:
        self.catalog = catalog
        self.worker = worker or RefreshJobQueueWorker(catalog)
        self.coordinator = MultiRootRetrievalCoordinator(catalog.conn)

        if refresh_policy not in SUPPORTED_REFRESH_POLICIES:
            if refresh_policy == "change_driven":
                raise NotImplementedError("change_driven refresh_policy is not implemented yet")
            raise ValueError(f"Unsupported refresh_policy: '{refresh_policy}'. Supported: {SUPPORTED_REFRESH_POLICIES}")

        self.refresh_policy = refresh_policy
        self.poll_interval_sec = poll_interval_sec
        self.stale_ttl_sec = stale_ttl_sec
        self.scanner: PeriodicScanner | None = None
        if refresh_policy == "interval_scan":
            self.scanner = PeriodicScanner(self.worker, interval_seconds=poll_interval_sec)
            self.worker.attach_scanner(self.scanner)
            self.scanner.start()

    def _is_root_stale(
        self,
        workspace_id: str,
        source_root_id: str,
        target_timestamp: str | None = None,
        stale_ttl_sec: float | None = None,
    ) -> bool:
        cov = self.worker.get_root_coverage(workspace_id, source_root_id)
        if cov is None or cov.last_scan_succeeded_at is None:
            return True
        if target_timestamp is not None and cov.last_scan_succeeded_at < target_timestamp:
            return True
        ttl = stale_ttl_sec if stale_ttl_sec is not None else self.stale_ttl_sec
        if ttl is not None and ttl > 0:
            last_ts = _parse_iso_to_unix(cov.last_scan_succeeded_at)
            if time.time() - last_ts > ttl:
                return True
        return False

    def search_documents(
        self,
        request: AgentSearchRequest,
        context: SecurityContext,
        search_mode: str = "background_refresh",
        target_timestamp: str | None = None,
    ) -> AgentSearchResponse:
        """Execute bounded multi-root agent retrieval under trusted SecurityContext with refresh strategy."""
        if request.workspace_id != context.workspace_id or request.principal_id != context.principal_id:
            raise PermissionDeniedError("Security context mismatch with request identity")

        started_perf = time.perf_counter()
        deadline_perf = started_perf + (request.timeout_ms / 1000.0)

        if search_mode == "background_refresh":
            service_warning: str | None = None
            is_degraded: bool = False
            for r_id in request.source_root_ids:
                if self._is_root_stale(context.workspace_id, r_id, target_timestamp):
                    # Background mode strictly enforces can_trigger_refresh
                    if not (context.can_trigger_refresh and self.worker.can_trigger_refresh(context.workspace_id, context.principal_id, r_id)):
                        service_warning = "UNAUTHORIZED_REFRESH_SKIPPED"
                    else:
                        try:
                            scope = RefreshSourceScope(
                                workspace_id=context.workspace_id,
                                source_root_id=r_id,
                                operator_principal_id=context.principal_id,
                            )
                            self.worker.trigger_refresh(scope)
                        except QueueFullError:
                            service_warning = "WORKER_QUEUE_FULL"
                            is_degraded = True
                        except Exception as exc:
                            service_warning = f"BACKGROUND_REFRESH_FAILED: {exc}"
                            is_degraded = True

            resp = self.coordinator.execute_search(
                request,
                deadline_perf=deadline_perf,
                started_perf=started_perf,
            )
            if service_warning or is_degraded:
                resp = AgentSearchResponse(
                    query_id=resp.query_id,
                    status=resp.status,
                    stop_reason=resp.stop_reason,
                    results=resp.results,
                    receipts=resp.receipts,
                    latency_ms=resp.latency_ms,
                    finalization_latency_ms=resp.finalization_latency_ms,
                    cumulative_rows_fetched=resp.cumulative_rows_fetched,
                    receipt_id=resp.receipt_id,
                    warning=service_warning,
                    degraded=is_degraded,
                )
            return resp

        elif search_mode == "wait_for_refresh":
            service_warning: str | None = None
            is_degraded: bool = False

            # Wait and trigger refresh for each stale requested root WITHOUT holding SQLite transaction
            for r_id in request.source_root_ids:
                if self._is_root_stale(context.workspace_id, r_id, target_timestamp):
                    active_job_id = self.worker._active_jobs.get((context.workspace_id, r_id))
                    if active_job_id is None:
                        # Stale & no active job: must check permission
                        if not (context.can_trigger_refresh and self.worker.can_trigger_refresh(context.workspace_id, context.principal_id, r_id)):
                            raise RefreshPermissionDeniedError(
                                f"Principal '{context.principal_id}' lacks refresh permission to trigger refresh on stale root '{r_id}'"
                            )
                        scope = RefreshSourceScope(
                            workspace_id=context.workspace_id,
                            source_root_id=r_id,
                            operator_principal_id=context.principal_id,
                        )
                        job_status = self.worker.trigger_refresh(scope)
                        target_job_id = job_status.job_id
                    else:
                        # Active job in progress: check whether to wait for current or coalesce next cycle
                        need_next_cycle = target_timestamp is not None
                        if need_next_cycle:
                            if not (context.can_trigger_refresh and self.worker.can_trigger_refresh(context.workspace_id, context.principal_id, r_id)):
                                raise RefreshPermissionDeniedError(
                                    f"Principal '{context.principal_id}' lacks refresh permission to trigger next-cycle refresh on root '{r_id}'"
                                )
                            scope = RefreshSourceScope(
                                workspace_id=context.workspace_id,
                                source_root_id=r_id,
                                operator_principal_id=context.principal_id,
                            )
                            job_status = self.worker.trigger_refresh(scope)
                            target_job_id = job_status.job_id
                        else:
                            target_job_id = active_job_id

                    # Wait for target job to complete without holding SQLite locks
                    event = self.worker.get_job_completion_event(target_job_id)
                    remaining_wait_sec = max(0.0, deadline_perf - time.perf_counter())
                    finished = event.wait(timeout=remaining_wait_sec)

                    if not finished or time.perf_counter() >= deadline_perf:
                        # Timeout exhausted before entering core retrieval transaction
                        latency_ms = (time.perf_counter() - started_perf) * 1000.0
                        return AgentSearchResponse(
                            query_id=str(uuid.uuid4()),
                            status="timed_out",
                            stop_reason="refresh_wait_timeout",
                            results=[],
                            receipts=[],
                            latency_ms=latency_ms,
                            finalization_latency_ms=0.0,
                            cumulative_rows_fetched=0,
                            receipt_id=None,
                            warning="WAIT_FOR_REFRESH_TIMED_OUT",
                            degraded=True,
                        )

                    # Assess completion status of worker job
                    final_job_status = self.get_refresh_job(target_job_id, context=context, view="principal_scoped")
                    if final_job_status and final_job_status.stage == "failed":
                        service_warning = "REFRESH_JOB_FAILED_DEGRADED"
                        is_degraded = True

            # Enter core retrieval transaction under single connection ownership with exact same deadline_perf
            resp = self.coordinator.execute_search(
                request,
                deadline_perf=deadline_perf,
                started_perf=started_perf,
            )
            if service_warning or is_degraded:
                resp = AgentSearchResponse(
                    query_id=resp.query_id,
                    status=resp.status,
                    stop_reason=resp.stop_reason,
                    results=resp.results,
                    receipts=resp.receipts,
                    latency_ms=resp.latency_ms,
                    finalization_latency_ms=resp.finalization_latency_ms,
                    cumulative_rows_fetched=resp.cumulative_rows_fetched,
                    receipt_id=resp.receipt_id,
                    warning=service_warning,
                    degraded=is_degraded,
                )
            return resp
            if service_warning or is_degraded:
                resp = AgentSearchResponse(
                    query_id=resp.query_id,
                    status=resp.status,
                    stop_reason=resp.stop_reason,
                    results=resp.results,
                    receipts=resp.receipts,
                    latency_ms=resp.latency_ms,
                    finalization_latency_ms=resp.finalization_latency_ms,
                    cumulative_rows_fetched=resp.cumulative_rows_fetched,
                    receipt_id=resp.receipt_id,
                    warning=service_warning,
                    degraded=is_degraded,
                )
            return resp
        else:
            raise ValueError(f"Unsupported search_mode: {search_mode}")

    def refresh_source(
        self,
        source_root_id: str,
        context: SecurityContext,
    ) -> RefreshJobStatus:
        """Request incremental refresh of a source root under trusted SecurityContext."""
        if not context.can_trigger_refresh or not self.worker.can_trigger_refresh(context.workspace_id, context.principal_id, source_root_id):
            raise RefreshPermissionDeniedError(
                f"Principal '{context.principal_id}' lacks refresh permission on root '{source_root_id}'"
            )

        scope = RefreshSourceScope(
            workspace_id=context.workspace_id,
            source_root_id=source_root_id,
            operator_principal_id=context.principal_id,
        )
        return self.worker.trigger_refresh(scope)

    def get_refresh_job(
        self,
        job_id: str,
        context: SecurityContext,
        view: str = "principal_scoped",
    ) -> RefreshJobStatus | None:
        """Fetch job status with strict SecurityContext role enforcement and authorization projection."""
        if view == "admin_full" and not context.is_admin:
            raise PermissionDeniedError("Admin privileges required for admin_full view")

        status = self.worker.get_job_status(job_id)
        if status is None:
            return None

        # 1. Enforce strict workspace tenant isolation FIRST:
        # Cross-workspace inspection is prohibited even for admins or matching principals
        if status.workspace_id != context.workspace_id:
            raise PermissionDeniedError(f"Access denied: job '{job_id}' does not belong to workspace '{context.workspace_id}'")

        # 2. Authorized Admin view with admin_full: return full unprojected status
        if context.is_admin and view == "admin_full":
            return status

        # 3. For principal_scoped: verify caller has read access on root
        row = self.catalog.conn.execute(
            """
            SELECT 1 FROM file_acl a
            JOIN file_record f ON f.file_record_id = a.file_record_id
            WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
              AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
            LIMIT 1
            """,
            (context.workspace_id, context.principal_id, context.workspace_id, status.source_root_id),
        ).fetchone()
        if not row:
            raise PermissionDeniedError(f"Access denied to job status for root '{status.source_root_id}'")

        # 4. Genuine authorized file progress & failure projection based on THIS job's events:
        auth_rows = self.catalog.conn.execute(
            """
            SELECT f.file_record_id, f.relative_path
            FROM file_acl a
            JOIN file_record f ON f.file_record_id = a.file_record_id
            WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
              AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
            """,
            (context.workspace_id, context.principal_id, context.workspace_id, status.source_root_id),
        ).fetchall()

        auth_files = {str(r[0]): str(r[1]) for r in auth_rows}
        auth_total = len(auth_files)

        # Get per-file events recorded for THIS specific job
        job_events = self.worker.get_job_events(job_id)
        events_by_fid = {ev.file_record_id: ev for ev in job_events if ev.file_record_id}
        events_by_path = {ev.relative_path: ev for ev in job_events}

        auth_succeeded = 0
        auth_failed = 0
        auth_processing = 0
        auth_pending = 0
        auth_errors: list[str] = []

        for f_id, rel_path in auth_files.items():
            ev = events_by_fid.get(f_id) or events_by_path.get(rel_path)
            if ev is None:
                auth_pending += 1
            elif ev.status == "failed":
                auth_failed += 1
                if ev.error:
                    auth_errors.append(ev.error)
            elif ev.status == "succeeded" and ev.stage == "completed":
                # Only terminal stage success counts as auth_succeeded!
                auth_succeeded += 1
            elif ev.status == "processing":
                auth_processing += 1
            else:
                # Intermediate stage (e.g. status == "succeeded" but stage == "intake")
                # "未知不能推定成功": unfinished stage cannot be presumed successful
                auth_pending += 1

        # Project status and stage based on authorized file events:
        # Unknown cannot be presumed successful ("未知不能推定成功")
        if auth_failed > 0:
            projected_stage = "failed"
            projected_total = auth_total
            projected_processed = auth_succeeded
            err_summary = auth_errors[0] if auth_errors else "Authorized file processing failed"
        elif status.stage == "completed":
            if auth_total == 0 or auth_succeeded == auth_total:
                projected_stage = "completed"
                projected_total = auth_total
                projected_processed = auth_total
                err_summary = None
            else:
                # Some authorized files not completed ("未知不能推定成功")
                projected_stage = "failed"
                projected_total = auth_total
                projected_processed = auth_succeeded
                err_summary = "Job ended without completing all authorized files"
        elif status.stage == "failed":
            if auth_pending > 0 or auth_processing > 0:
                projected_stage = "failed"
                projected_total = auth_total
                projected_processed = auth_succeeded
                err_summary = "Job aborted before all authorized files could be completed"
            else:
                # All authorized files succeeded completely in this job!
                # Conceal unauthorized file failure completely
                projected_stage = "completed"
                projected_total = auth_total
                projected_processed = auth_total
                err_summary = None
        else:
            projected_stage = status.stage
            projected_total = auth_total
            projected_processed = auth_succeeded
            err_summary = None

        return RefreshJobStatus(
            job_id=status.job_id,
            workspace_id=status.workspace_id,
            source_root_id=status.source_root_id,
            stage=projected_stage,
            is_coalesced_pending=status.is_coalesced_pending,
            files_total=projected_total,
            files_processed=projected_processed,
            error_summary=err_summary,
        )

    def _format_coverage(self, workspace_id: str, source_root_id: str, principal_id: str, admin: bool) -> dict[str, Any]:
        from pathlib import Path

        if admin:
            rows = self.catalog.conn.execute(
                """
                SELECT relative_path FROM file_record
                WHERE workspace_id=? AND source_root_id=? AND catalog_status='active'
                """,
                (workspace_id, source_root_id),
            ).fetchall()
        else:
            rows = self.catalog.conn.execute(
                """
                SELECT DISTINCT f.relative_path
                FROM file_acl a
                JOIN file_record f ON f.file_record_id = a.file_record_id
                WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
                  AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
                """,
                (workspace_id, principal_id, workspace_id, source_root_id),
            ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            suffix = Path(str(row[0])).suffix.lower() or "(none)"
            counts[suffix] = counts.get(suffix, 0) + 1
        from ..archive_host import qualification

        row = self.catalog.conn.execute(
            "SELECT config_json FROM source_root WHERE source_root_id=?",
            (source_root_id,),
        ).fetchone()
        config = json.loads(row[0]) if row and row[0] else {}
        opted_in = config.get("archive_enabled") is True
        database = None
        if opted_in:
            database = Path(self.catalog.database).with_name(source_root_id + ".archive.sqlite")
        archive = qualification(enabled=opted_in, database=database)
        return {
            "indexed_suffix_counts": counts,
            "archive": archive,
            "archive_opt_in": opted_in,
            "archive_last_disposition": config.get("archive_last_disposition"),
            "unsupported_not_indexed": True,
        }

    def get_index_status(
        self,
        source_root_id: str,
        context: SecurityContext,
        view: str = "principal_scoped",
    ) -> SourceIndexStatus:
        """Probe index status with dual-perspective information leakage defense and authentic snapshot timestamps."""
        workspace_id = context.workspace_id
        principal_id = context.principal_id
        is_admin = context.is_admin

        if view == "admin_full" and not is_admin:
            raise PermissionDeniedError("Admin privileges required for admin_full view")

        # 1. Verify root exists and is enabled
        root_row = self.catalog.conn.execute(
            "SELECT enabled FROM source_root WHERE workspace_id=? AND source_root_id=?",
            (workspace_id, source_root_id),
        ).fetchone()
        if not root_row or int(root_row[0]) != 1:
            raise PermissionDeniedError(f"Source root '{source_root_id}' not found or disabled")

        # 2. Check principal read access (if not admin)
        if not is_admin:
            auth_row = self.catalog.conn.execute(
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
                raise PermissionDeniedError(f"Principal '{principal_id}' has no read access to root '{source_root_id}'")

        # 3. Check active indexing status
        active_job = self.worker._active_jobs.get((workspace_id, source_root_id))
        is_indexing = active_job is not None

        # 4. Count files
        if is_admin:
            auth_count = self.catalog.conn.execute(
                """
                SELECT COUNT(*) FROM file_record
                WHERE workspace_id=? AND source_root_id=? AND catalog_status='active'
                """,
                (workspace_id, source_root_id),
            ).fetchone()[0]
        else:
            auth_count = self.catalog.conn.execute(
                """
                SELECT COUNT(DISTINCT f.file_record_id)
                FROM file_acl a
                JOIN file_record f ON f.file_record_id = a.file_record_id
                WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
                  AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
                """,
                (workspace_id, principal_id, workspace_id, source_root_id),
            ).fetchone()[0]

        # 5. Determine authentic index publication timestamp from database (excluding raw index attempts)
        if view == "admin_full":
            ts_row = self.catalog.conn.execute(
                """
                SELECT MAX(ts) FROM (
                    SELECT MAX(p.published_at) AS ts
                    FROM projection p
                    JOIN source_version s ON s.source_version_id = p.source_version_id
                    JOIN file_record f ON f.file_record_id = s.file_record_id AND f.current_source_version_id = s.source_version_id
                    WHERE f.workspace_id = ? AND f.source_root_id = ? AND f.catalog_status = 'active'
                    UNION ALL
                    SELECT MAX(pub.published_at) AS ts
                    FROM text_projection_publication pub
                    JOIN source_version s ON s.source_version_id = pub.source_version_id
                    JOIN file_record f ON f.file_record_id = s.file_record_id AND f.current_source_version_id = s.source_version_id
                    WHERE f.workspace_id = ? AND f.source_root_id = ? AND f.catalog_status = 'active'
                )
                """,
                (workspace_id, source_root_id, workspace_id, source_root_id),
            ).fetchone()
        else:
            ts_row = self.catalog.conn.execute(
                """
                SELECT MAX(ts) FROM (
                    SELECT MAX(p.published_at) AS ts
                    FROM projection p
                    JOIN source_version s ON s.source_version_id = p.source_version_id
                    JOIN file_record f ON f.file_record_id = s.file_record_id AND f.current_source_version_id = s.source_version_id
                    JOIN file_acl a ON a.file_record_id = f.file_record_id
                    WHERE a.workspace_id = ? AND a.principal_id = ? AND a.can_read = 1
                      AND f.workspace_id = ? AND f.source_root_id = ? AND f.catalog_status = 'active'
                    UNION ALL
                    SELECT MAX(pub.published_at) AS ts
                    FROM text_projection_publication pub
                    JOIN source_version s ON s.source_version_id = pub.source_version_id
                    JOIN file_record f ON f.file_record_id = s.file_record_id AND f.current_source_version_id = s.source_version_id
                    JOIN file_acl a ON a.file_record_id = f.file_record_id
                    WHERE a.workspace_id = ? AND a.principal_id = ? AND a.can_read = 1
                      AND f.workspace_id = ? AND f.source_root_id = ? AND f.catalog_status = 'active'
                )
                """,
                (
                    workspace_id, principal_id, workspace_id, source_root_id,
                    workspace_id, principal_id, workspace_id, source_root_id,
                ),
            ).fetchone()

        snapshot_time = ts_row[0] if (ts_row and ts_row[0]) else None
        format_coverage = self._format_coverage(workspace_id, source_root_id, principal_id, view == "admin_full")

        # 6. Retrieve authentic whole-round scan completion and full coverage records
        root_cov = self.worker.get_root_coverage(workspace_id, source_root_id)
        last_scan_completed_at = root_cov.last_scan_completed_at if root_cov else None
        last_scan_succeeded_at = root_cov.last_scan_succeeded_at if root_cov else None

        if view == "admin_full":
            total_count = self.catalog.conn.execute(
                "SELECT COUNT(*) FROM file_record WHERE workspace_id=? AND source_root_id=?",
                (workspace_id, source_root_id),
            ).fetchone()[0]
            # Failure count: strictly latest attempt per file to exclude historical recovered failures
            fail_rows = self.catalog.conn.execute(
                """
                SELECT i1.file_record_id, i1.relative_path, i1.failure_code
                FROM index_attempt i1
                WHERE i1.workspace_id = ? AND i1.source_root_id = ?
                  AND i1.status IN ('retryable_failed', 'terminal_failed')
                  AND i1.attempt_number = (
                      SELECT MAX(i2.attempt_number)
                      FROM index_attempt i2
                      WHERE i2.workspace_id = i1.workspace_id
                        AND i2.source_root_id = i1.source_root_id
                        AND (i2.file_record_id = i1.file_record_id OR i2.relative_path = i1.relative_path)
                  )
                """,
                (workspace_id, source_root_id),
            ).fetchall()
            unindexed_count = self.catalog.conn.execute(
                "SELECT COUNT(*) FROM file_record WHERE workspace_id=? AND source_root_id=? AND catalog_status='active' AND current_source_version_id IS NULL",
                (workspace_id, source_root_id),
            ).fetchone()[0]
            if last_scan_succeeded_at and len(fail_rows) == 0 and int(total_count) > 0 and unindexed_count == 0:
                last_full_coverage_at = root_cov.last_full_coverage_at or last_scan_succeeded_at
            else:
                last_full_coverage_at = None

            return SourceIndexStatus(
                workspace_id=workspace_id,
                source_root_id=source_root_id,
                view="admin_full",
                snapshot_time=snapshot_time,
                is_indexing=is_indexing,
                authorized_files_count=int(auth_count),
                total_files_count=int(total_count),
                failure_count=len(fail_rows),
                failures_detail=[{"file_record_id": r[0], "relative_path": r[1], "failure_code": r[2]} for r in fail_rows],
                last_scan_completed_at=last_scan_completed_at,
                last_scan_succeeded_at=last_scan_succeeded_at,
                last_full_coverage_at=last_full_coverage_at,
                format_coverage=format_coverage,
            )
        else:
            # Principal scoped: strictly authorized files only. Zero leakage of unreadable file counts or paths!
            auth_fail_rows = self.catalog.conn.execute(
                """
                SELECT i1.file_record_id, i1.relative_path
                FROM file_acl a
                JOIN index_attempt i1 ON i1.file_record_id = a.file_record_id
                WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
                  AND i1.workspace_id=? AND i1.source_root_id=?
                  AND i1.status IN ('retryable_failed', 'terminal_failed')
                  AND i1.attempt_number = (
                      SELECT MAX(i2.attempt_number)
                      FROM index_attempt i2
                      WHERE i2.workspace_id = i1.workspace_id
                        AND i2.source_root_id = i1.source_root_id
                        AND (i2.file_record_id = i1.file_record_id OR i2.relative_path = i1.relative_path)
                  )
                """,
                (workspace_id, principal_id, workspace_id, source_root_id),
            ).fetchall()
            auth_unindexed = self.catalog.conn.execute(
                """
                SELECT COUNT(DISTINCT f.file_record_id)
                FROM file_acl a
                JOIN file_record f ON f.file_record_id = a.file_record_id
                WHERE a.workspace_id=? AND a.principal_id=? AND a.can_read=1
                  AND f.workspace_id=? AND f.source_root_id=? AND f.catalog_status='active'
                  AND f.current_source_version_id IS NULL
                """,
                (workspace_id, principal_id, workspace_id, source_root_id),
            ).fetchone()[0]
            if last_scan_succeeded_at and len(auth_fail_rows) == 0 and int(auth_count) > 0 and auth_unindexed == 0:
                last_full_coverage_at = root_cov.last_full_coverage_at or last_scan_succeeded_at
            else:
                last_full_coverage_at = None

            return SourceIndexStatus(
                workspace_id=workspace_id,
                source_root_id=source_root_id,
                view="principal_scoped",
                snapshot_time=snapshot_time,
                is_indexing=is_indexing,
                authorized_files_count=int(auth_count),
                total_files_count=None,
                failure_count=len(auth_fail_rows),
                failures_detail=[],  # No detailed leak to general principals
                last_scan_completed_at=last_scan_completed_at,
                last_scan_succeeded_at=last_scan_succeeded_at,
                last_full_coverage_at=last_full_coverage_at,
                format_coverage=format_coverage,
            )


AgentService = PdxLocalAgentService

