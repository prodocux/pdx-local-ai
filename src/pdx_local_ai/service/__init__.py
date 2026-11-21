"""PdxLocal Agent Access & Index Refresh Service Layer."""

from .contracts import (
    AgentSearchRequest,
    AgentSearchResponse,
    InternalCandidateContext,
    PermissionDeniedError,
    QueueFullError,
    RefreshJobStatus,
    RefreshPermissionDeniedError,
    RefreshSourceScope,
    SearchResultItem,
    SecurityContext,
    ServiceError,
    ServiceShuttingDownError,
    ShutdownSummary,
    ShutdownTimeoutError,
    SourceIndexStatus,
)

from .agent_service import PdxLocalAgentService
from .coordinator import MultiRootRetrievalCoordinator
from .job_worker import PeriodicScanner, RefreshJobQueueWorker
from .mcp_server import MCP_TOOLS, McpServerHandler
from .stdio_transport import McpStdioTransport, resolve_trusted_security_context

__all__ = [
    "AgentSearchRequest",
    "AgentSearchResponse",
    "InternalCandidateContext",
    "MCP_TOOLS",
    "McpServerHandler",
    "McpStdioTransport",
    "MultiRootRetrievalCoordinator",
    "PdxLocalAgentService",
    "PeriodicScanner",
    "PermissionDeniedError",
    "QueueFullError",
    "RefreshJobQueueWorker",
    "RefreshJobStatus",
    "RefreshPermissionDeniedError",
    "RefreshSourceScope",
    "SearchResultItem",
    "SecurityContext",
    "ServiceError",
    "ServiceShuttingDownError",
    "ShutdownSummary",
    "ShutdownTimeoutError",
    "SourceIndexStatus",
    "resolve_trusted_security_context",
]
