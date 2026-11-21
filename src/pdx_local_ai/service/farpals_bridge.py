"""Farpals ecosystem bridge adapter for PdxLocal Agent Service."""

from __future__ import annotations

from typing import Any

from .contracts import (
    AgentSearchRequest,
    RefreshJobStatus,
    RefreshSourceScope,
    ServiceError,
    SourceIndexStatus,
)


class FarpalsBridgeAdapter:
    """Translates between Farpals JSON contracts and PdxLocal internal DTOs with job_id-keyed correlation."""

    def __init__(self) -> None:
        self._job_correlation_map: dict[str, str] = {}

    def bind_job_correlation(self, job_id: str, correlation_id: str) -> None:
        """Explicitly bind correlation_id to job_id."""
        self._job_correlation_map[job_id] = correlation_id

    def parse_source_refresh_request(self, payload: dict[str, Any]) -> RefreshSourceScope:
        """Parse farpals-source-refresh.bridge.v1 payload."""
        if payload.get("contract_version") != "farpals-source-refresh.bridge.v1":
            raise ServiceError("CONTRACT_MISMATCH", f"Expected farpals-source-refresh.bridge.v1, got {payload.get('contract_version')}")

        return RefreshSourceScope(
            workspace_id=payload["workspace_id"],
            source_root_id=payload["source_root_id"],
            operator_principal_id=payload["operator_principal_id"],
        )

    def format_job_status_response(self, status: RefreshJobStatus, correlation_id: str | None = None) -> dict[str, Any]:
        """Format to farpals-job-status.bridge.v1 contract strictly keyed by job_id without root fallback."""
        corr = correlation_id or self._job_correlation_map.get(status.job_id)
        res: dict[str, Any] = {
            "contract_version": "farpals-job-status.bridge.v1",
            "job_id": status.job_id,
            "stage": status.stage,
            "is_coalesced_pending": status.is_coalesced_pending,
            "files_total": status.files_total,
            "files_processed": status.files_processed,
            "error_summary": status.error_summary,
        }
        if corr is not None:
            res["correlation_id"] = corr
        return res

    def parse_agent_search_request(self, payload: dict[str, Any]) -> AgentSearchRequest:
        """Parse farpals-agent-search.bridge.v1 payload."""
        if payload.get("contract_version") != "farpals-agent-search.bridge.v1":
            raise ServiceError("CONTRACT_MISMATCH", f"Expected farpals-agent-search.bridge.v1, got {payload.get('contract_version')}")

        return AgentSearchRequest(
            workspace_id=payload["workspace_id"],
            principal_id=payload["principal_id"],
            source_root_ids=payload["source_root_ids"],
            query=payload["query"],
            timeout_ms=payload.get("timeout_ms", 3000),
            limit=payload.get("limit", 10),
        )

    def format_index_status_response(self, status: SourceIndexStatus) -> dict[str, Any]:
        """Format to farpals-index-status.bridge.v1 contract."""
        return {
            "contract_version": "farpals-index-status.bridge.v1",
            "workspace_id": status.workspace_id,
            "source_root_id": status.source_root_id,
            "view": status.view,
            "snapshot_time": status.snapshot_time,
            "is_indexing": status.is_indexing,
            "authorized_files_count": status.authorized_files_count,
            "total_files_count": status.total_files_count,
            "failure_count": status.failure_count,
            "last_scan_succeeded_at": status.last_scan_succeeded_at,
            "last_full_coverage_at": status.last_full_coverage_at,
        }

    def project_wordpress_attachment_subjob(self, *, file_record_id: str, attachment_id: int, status: str) -> dict[str, Any]:
        """Project file task onto existing farpals-job-projection.v1 schema."""
        return {
            "contract_version": "farpals-job-projection.v1",
            "subject": {
                "type": "wordpress_attachment",
                "id": attachment_id,
            },
            "task_id": file_record_id,
            "status": status,
        }

    def reject_engine_job_submit_for_refresh(self, payload: dict[str, Any]) -> None:
        """Strictly prohibit using engine-job-submit.consumer.v1 for directory rescan."""
        if payload.get("contract_version") == "engine-job-submit.consumer.v1":
            raise ServiceError("CONTRACT_VIOLATION", "engine-job-submit.consumer.v1 is strictly reserved for Engine private file tasks, not source refresh")
