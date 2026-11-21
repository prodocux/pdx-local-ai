"""Task harness contracts: states, transition table, error codes, permission matrix, limits.

Everything here is declarative and import-light so it can be unit-tested and
rendered into the operations guide without touching storage.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from ..service.contracts import SecurityContext, ServiceError

TASK_CONTRACT_VERSION = "pdx_local_task_v1"

# --------------------------------------------------------------------------- limits
LIMITS: dict[str, int] = {
    "max_active_tasks": 1,
    "max_pending_tasks": 32,
    "max_steps": 32,
    "max_tool_actions": 64,
    "tool_return_bytes": 64 * 1024,
    "context_packet_bytes": 64 * 1024,
    "task_input_bytes": 10 * 1024 * 1024,
    "candidate_output_bytes": 10 * 1024 * 1024,
    "params_bytes": 64 * 1024,
    "task_wall_clock_seconds": 30 * 60,
    "action_seconds": 30,
    "verification_seconds": 10,
    "max_events_per_task": 2000,
    "event_payload_bytes": 16 * 1024,
    "lease_seconds": 120,
    "max_attempts_per_step": 3,
    "retention_days": 30,
    # bounded_multihop initial policy
    "max_hops": 3,
    "max_branches_per_hop": 2,
}

# Shared retrieval ledger (all hops and all branches of one step draw from it).
LEDGER_DEFAULTS: dict[str, int] = {
    "elapsed_ms": 12_000,
    "candidates": 600,
    "opened_files": 24,
    "opened_blocks": 48,
    "returned_bytes": 160_000,
}

CONTEXT_MODES = ("bounded_retrieval", "bounded_full", "bounded_multihop")

# --------------------------------------------------------------------------- states
DRAFT = "draft"
AWAITING_APPROVAL = "awaiting_approval"
QUEUED = "queued"
RUNNING = "running"
WAITING_INPUT = "waiting_input"
AWAITING_VERIFICATION = "awaiting_verification"
NEEDS_REVIEW = "needs_review"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"
TIMED_OUT = "timed_out"
INTERRUPTED = "interrupted"

TASK_STATES = (
    DRAFT, AWAITING_APPROVAL, QUEUED, RUNNING, WAITING_INPUT, AWAITING_VERIFICATION,
    NEEDS_REVIEW, SUCCEEDED, FAILED, CANCELLED, TIMED_OUT, INTERRUPTED,
)
TERMINAL_STATES = frozenset({SUCCEEDED, FAILED, CANCELLED, TIMED_OUT})

TRANSITIONS: dict[str, frozenset[str]] = {
    DRAFT: frozenset({AWAITING_APPROVAL, CANCELLED}),
    AWAITING_APPROVAL: frozenset({QUEUED, CANCELLED}),
    QUEUED: frozenset({RUNNING, CANCELLED, TIMED_OUT}),
    RUNNING: frozenset({
        AWAITING_VERIFICATION, WAITING_INPUT, NEEDS_REVIEW, FAILED, CANCELLED,
        TIMED_OUT, INTERRUPTED,
    }),
    WAITING_INPUT: frozenset({RUNNING, CANCELLED, TIMED_OUT}),
    AWAITING_VERIFICATION: frozenset({SUCCEEDED, NEEDS_REVIEW, FAILED, INTERRUPTED, CANCELLED}),
    NEEDS_REVIEW: frozenset({SUCCEEDED, FAILED, RUNNING, CANCELLED}),
    INTERRUPTED: frozenset({RUNNING, NEEDS_REVIEW, FAILED, CANCELLED}),
    SUCCEEDED: frozenset(),
    FAILED: frozenset(),
    CANCELLED: frozenset(),
    TIMED_OUT: frozenset(),
}

STEP_STATES = ("pending", "ready", "in_progress", "accepted", "stale")
ATTEMPT_STATES = ("active", "accepted", "rejected", "superseded", "abandoned")
OPERATION_STATES = ("intent", "completed", "failed", "unknown")

# --------------------------------------------------------------------------- errors
ERROR_CODES = frozenset({
    "TASK_NOT_FOUND", "TASK_INVALID_TRANSITION", "TASK_STATE_CONFLICT",
    "TASK_PERMISSION_DENIED", "SELF_APPROVAL_DENIED", "TASK_VALIDATION_ERROR",
    "TEMPLATE_UNKNOWN", "TASK_QUOTA_EXCEEDED", "TASK_QUEUE_FULL", "ACTIVE_TASK_LIMIT",
    "LEASE_HELD", "LEASE_LOST", "ACTION_NOT_ALLOWED", "ACTION_BUDGET_EXCEEDED",
    "CONTEXT_BUDGET_EXCEEDED", "HOP_LIMIT", "HOP_DUPLICATE", "HOP_UNGROUNDED",
    "BRANCH_LIMIT", "SOURCE_VERSION_DRIFT", "SOURCE_NOT_AUTHORIZED",
    "TASK_DEADLINE_EXCEEDED", "IDEMPOTENCY_CONFLICT", "ARTIFACT_REJECTED",
    "RESULT_REJECTED", "CLOCK_UNTRUSTED", "TASK_SHUTTING_DOWN", "TASK_AUTH_REVOKED",
    "TASK_DB_MIGRATION_FAILED", "TASK_DB_UNSUPPORTED_VERSION", "ENGINE_UNAVAILABLE",
    "TASK_RESULT_TOO_LARGE", "EVENT_QUOTA_EXCEEDED", "STEP_NOT_READY",
    "ATTEMPT_LIMIT", "RETRIEVAL_BUDGET_EXHAUSTED",
})


class TaskError(ServiceError):
    """Structured task-layer error. ``origin`` tags where a rejection came from."""

    def __init__(self, code: str, message: str, details: Mapping[str, Any] | None = None,
                 *, origin: str = "local_policy") -> None:
        if code not in ERROR_CODES:  # programming error: never emit undeclared codes
            raise AssertionError(f"undeclared task error code: {code}")
        merged = dict(details or {})
        merged.setdefault("origin", origin)
        super().__init__(code, message, merged)
        self.origin = origin


# --------------------------------------------------------------------------- permissions
# operation -> (who may call). "owner" = same workspace + principal that created the task.
PERMISSION_MATRIX: dict[str, str] = {
    "list_task_templates": "principal",
    "create_task": "principal",
    "get_task": "owner_or_admin",
    "list_tasks": "principal",
    "get_task_context": "owner",
    "dispatch_task_action": "owner",
    "recall_published_memory": "owner",
    "submit_task_result": "owner",
    "cancel_task": "owner_or_admin",
    "resume_task": "owner",
    "get_task_events": "owner_or_admin",
    "approve_task": "approver",
    "review_task_result": "reviewer",
    "purge_expired_tasks": "admin",
}


def authorize(context: SecurityContext, operation: str,
              task_workspace: str | None = None, task_principal: str | None = None) -> None:
    rule = PERMISSION_MATRIX.get(operation)
    if rule is None:
        raise TaskError("TASK_PERMISSION_DENIED", f"unknown operation: {operation}")
    if task_workspace is not None and task_workspace != context.workspace_id:
        # Never reveal that a task exists in another workspace.
        raise TaskError("TASK_NOT_FOUND", "task not found")
    is_owner = task_principal is not None and task_principal == context.principal_id
    ok = {
        "principal": True,
        "owner": is_owner,
        "owner_or_admin": is_owner or context.is_admin,
        "approver": bool(getattr(context, "can_approve_tasks", False)),
        "reviewer": bool(getattr(context, "can_review_tasks", False)),
        "admin": context.is_admin,
    }[rule]
    if not ok:
        if task_principal is not None and not is_owner and rule in {"owner", "owner_or_admin"}:
            raise TaskError("TASK_NOT_FOUND", "task not found")
        raise TaskError("TASK_PERMISSION_DENIED", f"{operation} not permitted for this connection")


# --------------------------------------------------------------------------- helpers
def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}\.(json|txt)$")


def validate_candidate_name(name: Any) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise TaskError("ARTIFACT_REJECTED", "candidate name must match [a-z0-9_-]{1,64}.(json|txt)")
    return name


def check_transition(current: str, target: str) -> None:
    if target not in TRANSITIONS.get(current, frozenset()):
        raise TaskError("TASK_INVALID_TRANSITION", f"{current} -> {target} is not allowed",
                        {"from": current, "to": target})


def normalize_query(query: str) -> str:
    return " ".join(query.lower().split())
