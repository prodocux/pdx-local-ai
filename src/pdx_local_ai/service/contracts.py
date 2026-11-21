"""Contract and DTO definitions for PdxLocal Agent Access & Index Refresh Service."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..catalog import SUPPORTED_LIMITS_CEILINGS
from ..validation import ContractError


class ServiceError(ContractError):
    """Base error for service exceptions with structured code."""

    def __init__(self, code: str, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.details = dict(details or {})


class PermissionDeniedError(ServiceError):
    def __init__(self, message: str = "Permission denied", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("PERMISSION_DENIED", message, details)


class RefreshPermissionDeniedError(ServiceError):
    def __init__(self, message: str = "Refresh permission denied", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("REFRESH_PERMISSION_DENIED", message, details)


class IndexBusyError(ServiceError):
    def __init__(self, message: str = "Index is busy or locked", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("INDEX_BUSY", message, details)


class TimeoutExhaustedError(ServiceError):
    def __init__(self, message: str = "Timeout exhausted before acquiring lock", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("TIMEOUT_EXHAUSTED", message, details)


class QueueFullError(ServiceError):
    def __init__(self, message: str = "Worker queue is full", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("QUEUE_FULL", message, details)


class ServiceShuttingDownError(ServiceError):
    def __init__(self, message: str = "Service is shutting down", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("SERVICE_SHUTTING_DOWN", message, details)


class ShutdownTimeoutError(ServiceError):
    def __init__(self, message: str = "Shutdown timed out", details: Mapping[str, Any] | None = None) -> None:
        super().__init__("SHUTDOWN_TIMEOUT", message, details)


@dataclass(frozen=True)
class ShutdownSummary:
    """Summary of graceful shutdown execution."""

    status: str  # "completed_clean" | "shutdown_incomplete"
    alive_threads_count: int = 0
    remaining_jobs: list[str] = field(default_factory=list)
    drained_jobs_count: int = 0


@dataclass(frozen=True)
class SecurityContext:
    """Trusted connection context injected by host/transport, strictly verifying identity and roles."""

    workspace_id: str
    principal_id: str
    is_admin: bool = False
    can_trigger_refresh: bool = False
    # Task harness capabilities. Default-deny; granted only by the trusted host.
    can_approve_tasks: bool = False
    can_review_tasks: bool = False
    actor_kind: str = "agent"  # "agent" (MCP client) | "human_cli" (local operator CLI)


@dataclass(frozen=True)
class InternalCandidateContext:
    """Security and transaction binding token for candidates within a single retrieval execution."""

    query_id: str
    principal_id: str
    workspace_id: str
    db_conn_id: int
    tx_token: str
    created_perf: float


@dataclass(frozen=True)
class AgentSearchRequest:
    """Bounded, authenticated agent search request across multiple source roots with global budgets."""

    workspace_id: str
    principal_id: str
    source_root_ids: list[str]
    query: str
    timeout_ms: int = 3000
    limit: int = 10
    opened_files: int = 5
    opened_blocks: int = 8
    returned_bytes: int = 40_000
    metadata_candidates: int = 100
    lexical_candidates: int = 30
    metadata_candidates_per_root: int | None = None
    lexical_candidates_per_root: int | None = None

    def validate(self) -> None:
        if not self.workspace_id or not isinstance(self.workspace_id, str):
            raise ServiceError("VALIDATION_ERROR", "workspace_id is required")
        if not self.principal_id or not isinstance(self.principal_id, str):
            raise ServiceError("VALIDATION_ERROR", "principal_id is required")
        if not self.source_root_ids or not isinstance(self.source_root_ids, list):
            raise ServiceError("VALIDATION_ERROR", "source_root_ids must be a non-empty list")
        if not self.query or not isinstance(self.query, str):
            raise ServiceError("VALIDATION_ERROR", "query must be a non-empty string")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, (int, float)) or not math.isfinite(self.timeout_ms) or self.timeout_ms <= 0:
            raise ServiceError("VALIDATION_ERROR", "timeout_ms must be a positive finite number and not bool")

        effective_meta = self.metadata_candidates_per_root if self.metadata_candidates_per_root is not None else self.metadata_candidates
        effective_lex = self.lexical_candidates_per_root if self.lexical_candidates_per_root is not None else self.lexical_candidates

        for val in (self.limit, self.opened_files, self.opened_blocks, self.returned_bytes, effective_meta, effective_lex):
            if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                raise ServiceError("VALIDATION_ERROR", "budgets must be positive integers and not bool")

        # Enforce supported upper bounds aligning with core validate_supported_limits
        if self.timeout_ms > SUPPORTED_LIMITS_CEILINGS["elapsed_ms"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"timeout_ms exceeds supported ceiling: timeout_ms={self.timeout_ms} > {SUPPORTED_LIMITS_CEILINGS['elapsed_ms']}",
            )
        if self.limit > SUPPORTED_LIMITS_CEILINGS["opened_blocks"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"limit exceeds supported ceiling: limit={self.limit} > {SUPPORTED_LIMITS_CEILINGS['opened_blocks']}",
            )
        if self.opened_files > SUPPORTED_LIMITS_CEILINGS["opened_files"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"opened_files exceeds supported ceiling: opened_files={self.opened_files} > {SUPPORTED_LIMITS_CEILINGS['opened_files']}",
            )
        if self.opened_blocks > SUPPORTED_LIMITS_CEILINGS["opened_blocks"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"opened_blocks exceeds supported ceiling: opened_blocks={self.opened_blocks} > {SUPPORTED_LIMITS_CEILINGS['opened_blocks']}",
            )
        if self.returned_bytes > SUPPORTED_LIMITS_CEILINGS["returned_bytes"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"returned_bytes exceeds supported ceiling: returned_bytes={self.returned_bytes} > {SUPPORTED_LIMITS_CEILINGS['returned_bytes']}",
            )
        if self.metadata_candidates > SUPPORTED_LIMITS_CEILINGS["metadata_candidates"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"metadata_candidates exceeds supported ceiling: metadata_candidates={self.metadata_candidates} > {SUPPORTED_LIMITS_CEILINGS['metadata_candidates']}",
            )
        if self.lexical_candidates > SUPPORTED_LIMITS_CEILINGS["lexical_candidates"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"lexical_candidates exceeds supported ceiling: lexical_candidates={self.lexical_candidates} > {SUPPORTED_LIMITS_CEILINGS['lexical_candidates']}",
            )
        if self.metadata_candidates_per_root is not None and self.metadata_candidates_per_root > SUPPORTED_LIMITS_CEILINGS["metadata_candidates"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"metadata_candidates_per_root exceeds supported ceiling: metadata_candidates_per_root={self.metadata_candidates_per_root} > {SUPPORTED_LIMITS_CEILINGS['metadata_candidates']}",
            )
        if self.lexical_candidates_per_root is not None and self.lexical_candidates_per_root > SUPPORTED_LIMITS_CEILINGS["lexical_candidates"]:
            raise ServiceError(
                "VALIDATION_ERROR",
                f"lexical_candidates_per_root exceeds supported ceiling: lexical_candidates_per_root={self.lexical_candidates_per_root} > {SUPPORTED_LIMITS_CEILINGS['lexical_candidates']}",
            )

    @property
    def effective_metadata_candidates(self) -> int:
        return self.metadata_candidates_per_root if self.metadata_candidates_per_root is not None else self.metadata_candidates

    @property
    def effective_lexical_candidates(self) -> int:
        return self.lexical_candidates_per_root if self.lexical_candidates_per_root is not None else self.lexical_candidates


@dataclass(frozen=True)
class SearchResultItem:
    """Clean, external-facing search result block with citation and fusion rank."""

    file_record_id: str
    source_root_id: str
    block_instance_id: str
    score: float
    text: str
    citation: dict[str, Any]


@dataclass(frozen=True)
class AgentSearchResponse:
    """Response bundle for multi-root agent search."""

    query_id: str
    status: str  # "completed" | "timed_out" | "error"
    stop_reason: str
    results: list[SearchResultItem]
    receipts: list[dict[str, Any]]
    latency_ms: float
    finalization_latency_ms: float
    cumulative_rows_fetched: int
    receipt_id: str | None = None
    warning: str | None = None
    degraded: bool = False


@dataclass(frozen=True)
class RefreshSourceScope:
    """Scope parameter for refreshing an indexed root."""

    workspace_id: str
    source_root_id: str
    operator_principal_id: str


@dataclass(frozen=True)
class RefreshJobStatus:
    """Status record of a background refresh job."""

    job_id: str
    workspace_id: str
    source_root_id: str
    stage: str  # "scheduled_next_cycle" | "scanning" | "processing" | "indexing" | "completed" | "failed"
    is_coalesced_pending: bool
    files_total: int = 0
    files_processed: int = 0
    error_summary: str | None = None


@dataclass(frozen=True)
class SourceIndexStatus:
    """Perspective-scoped health and index probe response."""

    workspace_id: str
    source_root_id: str
    view: str  # "admin_full" | "principal_scoped"
    snapshot_time: str | None = None
    is_indexing: bool = False
    authorized_files_count: int = 0
    total_files_count: int | None = None
    failure_count: int = 0
    failures_detail: list[dict[str, Any]] = field(default_factory=list)
    last_scan_completed_at: str | None = None
    last_scan_succeeded_at: str | None = None
    last_full_coverage_at: str | None = None
    format_coverage: dict[str, Any] | None = None
