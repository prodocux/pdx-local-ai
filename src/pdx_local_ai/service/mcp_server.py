"""MCP server adapter exposing PdxLocal Agent Service tools with trusted security context."""

from __future__ import annotations

from typing import Any

from .agent_service import PdxLocalAgentService
from .contracts import (
    AgentSearchRequest,
    PermissionDeniedError,
    RefreshPermissionDeniedError,
    SecurityContext,
)

MCP_TOOLS = [
    {
        "name": "search_documents",
        "description": "Perform bounded semantic and lexical document search across authorized source roots.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_root_ids": {"type": "array", "items": {"type": "string"}},
                "query": {"type": "string"},
                "timeout_ms": {"type": "integer", "default": 3000},
                "limit": {"type": "integer", "default": 10},
                "search_mode": {"type": "string", "enum": ["background_refresh", "wait_for_refresh"], "default": "background_refresh"},
                "target_timestamp": {"type": "string"},
            },
            "required": ["source_root_ids", "query"],
        },
    },
    {
        "name": "refresh_source",
        "description": "Trigger background incremental scan and index refresh on a source root.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_root_id": {"type": "string"},
            },
            "required": ["source_root_id"],
        },
    },
    {
        "name": "get_refresh_job",
        "description": "Get status of a background refresh job.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "view": {"type": "string", "enum": ["admin_full", "principal_scoped"], "default": "principal_scoped"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_index_status",
        "description": "Get index health, snapshot timestamp, and coverage metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_root_id": {"type": "string"},
                "view": {"type": "string", "enum": ["admin_full", "principal_scoped"], "default": "principal_scoped"},
            },
            "required": ["source_root_id"],
        },
    },
]


class McpServerHandler:
    """Dispatches MCP tool invocations to PdxLocalAgentService under a trusted SecurityContext."""

    def __init__(
        self,
        service: PdxLocalAgentService,
        security_context: SecurityContext,
        task_service_factory: Any = None,
    ) -> None:
        self.service = service
        self.security_context = security_context
        # Lazy: tasks.sqlite is only created when a task tool is first used.
        self._task_service_factory = task_service_factory
        self._task_service: Any = None

    def set_security_context(self, security_context: SecurityContext) -> None:
        """Update trusted connection security context."""
        self.security_context = security_context

    @property
    def task_service(self) -> Any:
        if self._task_service is None and self._task_service_factory is not None:
            self._task_service = self._task_service_factory()
        return self._task_service

    def close_tasks(self, timeout_sec: float = 5.0) -> dict[str, Any] | None:
        """Graceful task shutdown (only if the task layer was ever used)."""
        if self._task_service is None:
            return None
        return self._task_service.shutdown(timeout_sec=timeout_sec)

    def list_tools(self) -> list[dict[str, Any]]:
        tools = list(MCP_TOOLS)
        if self._task_service_factory is not None:
            from ..tasks.mcp_tools import task_tool_definitions
            tools.extend(task_tool_definitions(self.security_context))
        return tools

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._task_service_factory is not None:
            from ..tasks.mcp_tools import TASK_TOOL_NAMES, call_task_tool
            if tool_name in TASK_TOOL_NAMES:
                return call_task_tool(self.task_service, self.security_context, tool_name, arguments)
        view = arguments.get("view", "principal_scoped")
        if view == "admin_full" and not self.security_context.is_admin:
            raise PermissionDeniedError("Admin privileges required for admin_full view")

        if tool_name == "search_documents":
            root_ids = arguments.get("source_root_ids")
            if root_ids is None:
                rows = self.service.catalog.conn.execute(
                    "SELECT source_root_id FROM source_root WHERE workspace_id = ? AND enabled = 1",
                    (self.security_context.workspace_id,),
                ).fetchall()
                root_ids = [str(r[0]) for r in rows]
            req = AgentSearchRequest(
                workspace_id=self.security_context.workspace_id,
                principal_id=self.security_context.principal_id,
                source_root_ids=root_ids,
                query=arguments["query"],
                timeout_ms=arguments.get("timeout_ms", 3000),
                limit=arguments.get("limit", 10),
            )
            resp = self.service.search_documents(
                req,
                context=self.security_context,
                search_mode=arguments.get("search_mode", "background_refresh"),
                target_timestamp=arguments.get("target_timestamp"),
            )
            return {
                "query_id": resp.query_id,
                "status": resp.status,
                "stop_reason": resp.stop_reason,
                "latency_ms": resp.latency_ms,
                "finalization_latency_ms": resp.finalization_latency_ms,
                "receipt_id": resp.receipt_id,
                "warning": resp.warning,
                "degraded": resp.degraded,
                "results": [
                    {
                        "file_record_id": r.file_record_id,
                        "source_root_id": r.source_root_id,
                        "score": r.score,
                        "text": r.text,
                        "citation": r.citation,
                    }
                    for r in resp.results
                ],
                "receipts_count": len(resp.receipts),
            }

        elif tool_name == "refresh_source":
            status = self.service.refresh_source(
                source_root_id=arguments["source_root_id"],
                context=self.security_context,
            )
            return {
                "job_id": status.job_id,
                "stage": status.stage,
                "is_coalesced_pending": status.is_coalesced_pending,
            }

        elif tool_name == "get_refresh_job":
            status = self.service.get_refresh_job(
                job_id=arguments["job_id"],
                context=self.security_context,
                view=view,
            )
            if status is None:
                return {"found": False}
            return {
                "found": True,
                "job_id": status.job_id,
                "stage": status.stage,
                "is_coalesced_pending": status.is_coalesced_pending,
                "files_total": status.files_total,
                "files_processed": status.files_processed,
                "error_summary": status.error_summary,
            }

        elif tool_name == "get_index_status":
            idx = self.service.get_index_status(
                source_root_id=arguments["source_root_id"],
                context=self.security_context,
                view=view,
            )
            return {
                "source_root_id": idx.source_root_id,
                "view": idx.view,
                "snapshot_time": idx.snapshot_time,
                "is_indexing": idx.is_indexing,
                "authorized_files_count": idx.authorized_files_count,
                "total_files_count": idx.total_files_count,
                "failure_count": idx.failure_count,
                "last_scan_completed_at": idx.last_scan_completed_at,
                "last_scan_succeeded_at": idx.last_scan_succeeded_at,
                "last_full_coverage_at": idx.last_full_coverage_at,
                "format_coverage": idx.format_coverage,
            }

        else:
            raise ValueError(f"Unknown tool: {tool_name}")
