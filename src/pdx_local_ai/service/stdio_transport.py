"""MCP stdio transport implementing JSON-RPC 2.0 framing, stream isolation, and trusted security context."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, TextIO

from .contracts import PermissionDeniedError, SecurityContext
from .mcp_server import McpServerHandler

SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05",)


class McpStdioTransport:
    """Standard I/O transport for Model Context Protocol over JSON-RPC 2.0."""

    def __init__(
        self,
        handler: McpServerHandler,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        self.handler = handler
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self._initialized = False

    def log(self, message: str) -> None:
        """Write diagnostics exclusively to stderr."""
        try:
            self.stderr.write(f"[pdx-mcp-stdio] {message}\n")
            self.stderr.flush()
        except Exception:
            pass

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process incoming JSON-RPC 2.0 message."""
        jsonrpc = message.get("jsonrpc", "2.0")
        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})

        # Handle notifications (no id)
        if msg_id is None:
            if method == "notifications/initialized":
                self._initialized = True
                self.log("Received notifications/initialized handshake")
            elif method == "$/cancelRequest":
                self.log(f"Received cancelRequest: {params}")
            return None

        # Handle requests
        if method == "initialize":
            requested_proto = params.get("protocolVersion")
            if requested_proto in SUPPORTED_PROTOCOL_VERSIONS:
                negotiated = requested_proto
            else:
                negotiated = SUPPORTED_PROTOCOL_VERSIONS[0]

            self.log(f"Handling initialize request, requested={requested_proto}, negotiated={negotiated}")
            return {
                "jsonrpc": jsonrpc,
                "id": msg_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": "pdx-local-ai",
                        "version": "1.0.0",
                    },
                },
            }

        elif method == "ping":
            return {
                "jsonrpc": jsonrpc,
                "id": msg_id,
                "result": {},
            }

        elif method == "tools/list":
            if not self._initialized:
                self.log("Rejected tools/list: server not initialized")
                return {
                    "jsonrpc": jsonrpc,
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": "Server not initialized. Client must send 'initialize' followed by 'notifications/initialized'.",
                    },
                }

            tools = self.handler.list_tools()
            return {
                "jsonrpc": jsonrpc,
                "id": msg_id,
                "result": {
                    "tools": tools,
                },
            }

        elif method == "tools/call":
            if not self._initialized:
                self.log("Rejected tools/call: server not initialized")
                return {
                    "jsonrpc": jsonrpc,
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": "Server not initialized. Client must send 'initialize' followed by 'notifications/initialized'.",
                    },
                }

            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not tool_name:
                return {
                    "jsonrpc": jsonrpc,
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": "Missing 'name' in tools/call parameters",
                    },
                }

            try:
                result = self.handler.call_tool(tool_name, arguments)
                return {
                    "jsonrpc": jsonrpc,
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result, ensure_ascii=False),
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as exc:
                self.log(f"Tool call error for '{tool_name}': {exc}")
                return {
                    "jsonrpc": jsonrpc,
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": str(exc),
                            }
                        ],
                        "isError": True,
                    },
                }

        else:
            self.log(f"Unknown JSON-RPC method: {method}")
            return {
                "jsonrpc": jsonrpc,
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }

    def process_line(self, line: str) -> None:
        """Parse single line and write response exclusively to stdout."""
        line = line.strip()
        if not line:
            return

        try:
            req = json.loads(line)
        except Exception as exc:
            self.log(f"JSON parse error: {exc}")
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {exc}",
                },
            }
            self.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            self.stdout.flush()
            return

        if not isinstance(req, dict):
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: message must be a JSON object",
                },
            }
            self.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            self.stdout.flush()
            return

        resp = self.handle_message(req)
        if resp is not None:
            self.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            self.stdout.flush()

    def run(self) -> None:
        """Run transport loop reading from stdin until EOF."""
        self.log("Starting MCP stdio transport loop")
        for line in self.stdin:
            self.process_line(line)
        self.log("MCP stdio transport loop finished (EOF)")


def resolve_trusted_security_context(
    cli_args: list[str] | None = None,
) -> SecurityContext:
    """Resolve trusted security context from host CLI arguments or environment variables with default-deny."""
    parser = argparse.ArgumentParser(description="PdxLocal AI MCP stdio host")
    parser.add_argument("--workspace-id", dest="workspace_id", default=None)
    parser.add_argument("--principal-id", dest="principal_id", default=None)
    parser.add_argument("--is-admin", dest="is_admin", action="store_true", default=None)
    parser.add_argument("--can-trigger-refresh", dest="can_trigger_refresh", action="store_true", default=None)
    parser.add_argument("--can-approve-tasks", dest="can_approve_tasks", action="store_true", default=None)
    parser.add_argument("--can-review-tasks", dest="can_review_tasks", action="store_true", default=None)

    parsed, _ = parser.parse_known_args(cli_args)

    workspace_id = parsed.workspace_id or os.environ.get("PDX_LOCAL_WORKSPACE_ID")
    principal_id = parsed.principal_id or os.environ.get("PDX_LOCAL_PRINCIPAL_ID")

    if not workspace_id or not principal_id:
        raise PermissionDeniedError(
            "Trusted security context missing: workspace-id and principal-id must be injected by trusted host"
        )

    # Boolean flags
    if parsed.is_admin is not None:
        is_admin = bool(parsed.is_admin)
    else:
        is_admin = os.environ.get("PDX_LOCAL_IS_ADMIN", "").lower() in ("1", "true", "yes")

    if parsed.can_trigger_refresh is not None:
        can_trigger_refresh = bool(parsed.can_trigger_refresh)
    else:
        can_trigger_refresh = os.environ.get("PDX_LOCAL_CAN_TRIGGER_REFRESH", "").lower() in ("1", "true", "yes")

    # Task capabilities are default-deny and can only come from the trusted host
    # (CLI flags / environment), never from tool arguments.
    if parsed.can_approve_tasks is not None:
        can_approve_tasks = bool(parsed.can_approve_tasks)
    else:
        can_approve_tasks = os.environ.get("PDX_LOCAL_CAN_APPROVE_TASKS", "").lower() in ("1", "true", "yes")
    if parsed.can_review_tasks is not None:
        can_review_tasks = bool(parsed.can_review_tasks)
    else:
        can_review_tasks = os.environ.get("PDX_LOCAL_CAN_REVIEW_TASKS", "").lower() in ("1", "true", "yes")

    return SecurityContext(
        workspace_id=str(workspace_id),
        principal_id=str(principal_id),
        is_admin=is_admin,
        can_trigger_refresh=can_trigger_refresh,
        can_approve_tasks=can_approve_tasks,
        can_review_tasks=can_review_tasks,
    )


def run_stdio_server(
    catalog_path: str | Path,
    security_context: SecurityContext,
    refresh_policy: str = "manual_only",
    poll_interval_sec: float = 60.0,
    stale_ttl_sec: float = 300.0,
    authorized_refresh_roots: list[str] | None = None,
    scheduled_refresh_roots: list[str] | None = None,
    shutdown_timeout_sec: float = 2.0,
) -> int:
    """Instantiate live catalog, worker, agent service and run stdio transport until EOF."""
    from ..catalog import Catalog
    from .agent_service import PdxLocalAgentService
    from .contracts import RefreshSourceScope
    from .job_worker import RefreshJobQueueWorker

    cat_path = Path(catalog_path).resolve()
    profile_dir = cat_path.parent
    lock_file = profile_dir / "maintenance.lock"
    migration_marker = profile_dir / "MIGRATION_FAILED"
    from ..maintenance_lock import CrossProcessMaintenanceLock
    from ..process_identity import get_process_info

    # ── Startup Guard (pre-lock probe) ───────────────────────────────────────
    # Quick non-blocking check before attempting to acquire the registration lock.
    # This is an optimistic fast-path only; the authoritative check is AFTER the lock.
    if CrossProcessMaintenanceLock.is_locked(lock_file):
        sys.stderr.write(
            f"[CRITICAL ERROR] Service startup refused: Profile directory {profile_dir} is locked for maintenance "
            f"(installation or upgrade in progress). Exiting.\n"
        )
        return 4

    # ── Atomic Session Registration ───────────────────────────────────────────
    # Acquire registration lock to close the TOCTOU window between "no installer running"
    # and the session file appearing on disk.
    reg_lock = CrossProcessMaintenanceLock(lock_file)
    if not reg_lock.acquire(timeout_sec=3.0):
        sys.stderr.write(
            "[CRITICAL ERROR] Service startup refused: Could not acquire registration lock "
            "(installer may have started maintenance between the probe and acquisition). Exiting.\n"
        )
        return 4

    # ── Second authoritative check INSIDE the lock ───────────────────────────
    # Now that we hold the lock, re-check both guards.  This closes the TOCTOU window
    # between the optimistic probe above and lock acquisition.
    if migration_marker.exists():
        reg_lock.release()
        sys.stderr.write(
            f"[CRITICAL ERROR] Service startup refused: Migration failure marker present at {migration_marker}. "
            "Run 'pdx-local installer install' to resolve before starting service. Exiting.\n"
        )
        return 5

    # (maintenance lock itself is now held by us — another installer cannot acquire it
    #  while we are registering, so no second is_locked() check needed here.)

    # ── Write session record (fatal if it fails) ─────────────────────────────
    session_id = str(uuid.uuid4())
    sessions_dir = profile_dir / "run" / "sessions"
    try:
        sessions_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        reg_lock.release()
        sys.stderr.write(
            f"[CRITICAL ERROR] Service startup refused: Cannot create sessions directory {sessions_dir}: {exc}\n"
        )
        return 6

    session_file = sessions_dir / f"session_{session_id}.json"

    # Retrieve current process creation time for subsequent identity verification
    _my_exe, _my_create_time = get_process_info(os.getpid())

    session_data = {
        "session_id": session_id,
        "pid": os.getpid(),
        "executable": sys.executable,
        "create_time": _my_create_time,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "running",
    }
    try:
        session_file.write_text(json.dumps(session_data, indent=2), encoding="utf-8")
    except Exception as exc:
        reg_lock.release()
        sys.stderr.write(
            f"[CRITICAL ERROR] Service startup refused: Cannot write session record to {session_file}: {exc}. "
            "The installer will not be able to identify this process for safe termination. Exiting.\n"
        )
        return 6

    # All pre-conditions satisfied — release the registration lock.
    # The session file is now on disk; the installer will see it and respect it.
    reg_lock.release()

    catalog = Catalog(cat_path)
    worker = RefreshJobQueueWorker(catalog)

    # 1. Authorize refresh roots for principal
    if security_context.can_trigger_refresh or security_context.is_admin:
        if authorized_refresh_roots:
            for rid in authorized_refresh_roots:
                worker.grant_refresh_permission(security_context.workspace_id, security_context.principal_id, rid)
        else:
            rows = catalog.conn.execute(
                "SELECT source_root_id FROM source_root WHERE workspace_id = ? AND enabled = 1",
                (security_context.workspace_id,),
            ).fetchall()
            for (rid,) in rows:
                worker.grant_refresh_permission(security_context.workspace_id, security_context.principal_id, str(rid))

        # Also authorize scheduled refresh roots if specified
        if scheduled_refresh_roots:
            for rid in scheduled_refresh_roots:
                worker.grant_refresh_permission(security_context.workspace_id, security_context.principal_id, rid)

    service = PdxLocalAgentService(
        catalog=catalog,
        worker=worker,
        refresh_policy=refresh_policy,
        poll_interval_sec=poll_interval_sec,
        stale_ttl_sec=stale_ttl_sec,
    )
    def _task_service_factory() -> Any:
        from ..tasks.service import TaskService
        return TaskService.open(profile_dir, agent_service=service, catalog=catalog)

    handler = McpServerHandler(service=service, security_context=security_context,
                               task_service_factory=_task_service_factory)
    transport = McpStdioTransport(handler=handler)

    # 2. Register scheduled refresh roots into periodic scanner from trusted configuration
    if service.scanner is not None and scheduled_refresh_roots:
        for rid in scheduled_refresh_roots:
            if worker.can_trigger_refresh(security_context.workspace_id, security_context.principal_id, rid):
                scope = RefreshSourceScope(
                    workspace_id=security_context.workspace_id,
                    source_root_id=rid,
                    operator_principal_id=security_context.principal_id,
                )
                service.scanner.register(scope)
                transport.log(f"Registered scheduled root '{rid}' for interval scanning ({poll_interval_sec}s)")
            else:
                transport.log(f"Warning: scheduled root '{rid}' skipped: principal lacks refresh permission")

    transport_exit_code = 0
    try:
        transport.run()
    except Exception as exc:
        transport.log(f"Transport loop terminated with error: {exc}")
        transport_exit_code = 1

    # 3a. Task layer first: stop accepting actions, drain, mark owned running tasks interrupted.
    try:
        task_summary = handler.close_tasks(timeout_sec=shutdown_timeout_sec)
        if task_summary is not None:
            transport.log(f"Task layer shutdown: {task_summary}")
    except Exception as exc:
        transport.log(f"Task layer shutdown error: {exc}")

    # 3. Graceful worker shutdown and clean exit verification
    shutdown_summary = None
    try:
        shutdown_summary = worker.shutdown(drain=False, timeout_sec=shutdown_timeout_sec)
    except Exception as exc:
        transport.log(f"Worker shutdown error: {exc}")
        return 2
    finally:
        try:
            catalog.close()
        except Exception:
            pass
        try:
            session_file.unlink(missing_ok=True)
        except Exception:
            pass

    if shutdown_summary is not None and shutdown_summary.status != "completed_clean":
        transport.log(
            f"Worker shutdown incomplete: status={shutdown_summary.status}, "
            f"alive_threads={shutdown_summary.alive_threads_count}, "
            f"remaining_jobs={shutdown_summary.remaining_jobs}"
        )
        return 3

    return transport_exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI Entrypoint for running the MCP stdio server process."""
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "service":
        argv = argv[1:]

    parser = argparse.ArgumentParser(description="PdxLocal AI MCP stdio process host")
    parser.add_argument("--catalog-path", required=True, help="Path to catalog SQLite database")
    parser.add_argument("--workspace-id", default=None)
    parser.add_argument("--principal-id", default=None)
    parser.add_argument("--is-admin", action="store_true", default=None)
    parser.add_argument("--can-trigger-refresh", action="store_true", default=None)
    parser.add_argument("--authorized-refresh-root", action="append", dest="authorized_refresh_roots", default=None)
    parser.add_argument("--scheduled-refresh-root", action="append", dest="scheduled_refresh_roots", default=None)
    parser.add_argument("--refresh-policy", default="manual_only")
    parser.add_argument("--poll-interval-sec", type=float, default=60.0)
    parser.add_argument("--stale-ttl-sec", type=float, default=300.0)
    parser.add_argument("--shutdown-timeout-sec", type=float, default=2.0)

    args, _ = parser.parse_known_args(argv)
    security_context = resolve_trusted_security_context(argv)

    return run_stdio_server(
        catalog_path=args.catalog_path,
        security_context=security_context,
        refresh_policy=args.refresh_policy,
        poll_interval_sec=args.poll_interval_sec,
        stale_ttl_sec=args.stale_ttl_sec,
        authorized_refresh_roots=args.authorized_refresh_roots,
        scheduled_refresh_roots=args.scheduled_refresh_roots,
        shutdown_timeout_sec=args.shutdown_timeout_sec,
    )


if __name__ == "__main__":
    sys.exit(main())
