"""MCP tool surface for the task harness. Thin wiring only: all rules live in TaskService."""

from __future__ import annotations

from typing import Any

from ..service.contracts import SecurityContext
from .contracts import TaskError

_IDEM = {"type": "string", "minLength": 16, "maxLength": 128}
_TASK = {"type": "string"}

_TOOLS: list[dict[str, Any]] = [
    {"name": "list_task_templates", "description": "List host-managed task templates, limits and action schemas.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "create_task",
     "description": "Create a task from a template. It waits for human approval before it can run.",
     "inputSchema": {"type": "object", "properties": {
         "template_id": {"type": "string"}, "params": {"type": "object"},
         "context_mode": {"type": "string", "enum": ["bounded_retrieval", "bounded_full", "bounded_multihop"]},
         "idempotency_key": _IDEM}, "required": ["template_id", "params"]}},
    {"name": "get_task", "description": "Task summary, steps, artifacts, verification and the action envelope.",
     "inputSchema": {"type": "object", "properties": {"task_id": _TASK}, "required": ["task_id"]}},
    {"name": "list_tasks", "description": "List your tasks (administrators see the workspace).",
     "inputSchema": {"type": "object", "properties": {
         "states": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer"}}}},
    {"name": "get_task_context",
     "description": "Rebuild the bounded context packet (stable prefix + volatile part) for the active step.",
     "inputSchema": {"type": "object", "properties": {"task_id": _TASK, "step_id": {"type": "string"}},
                     "required": ["task_id"]}},
    {"name": "dispatch_task_action",
     "description": "Run one bounded action (search, recall_memory, recall_published_memory, write_candidate, submit_step) for the active step.",
     "inputSchema": {"type": "object", "properties": {
         "task_id": _TASK, "action": {"type": "string", "enum": ["search", "recall_memory", "recall_published_memory", "write_candidate", "submit_step"]},
         "arguments": {"type": "object"}, "idempotency_key": _IDEM, "expected_state_version": {"type": "integer"}},
         "required": ["task_id", "action", "idempotency_key"]}},
    {"name": "submit_task_result",
     "description": "Submit the artifact for a step. Claimed success is verified by the host, never trusted.",
     "inputSchema": {"type": "object", "properties": {
         "task_id": _TASK, "step_id": {"type": "string"}, "artifact": {"type": "object"},
         "declare_incomplete": {"type": "boolean"},
         "reason": {"type": "string", "enum": ["missing_link", "budget_exhausted", "needs_input",
                                                "ambiguity_unresolved", "no_new_evidence", "hop_limit"]},
         "idempotency_key": _IDEM, "expected_state_version": {"type": "integer"}},
         "required": ["task_id", "step_id", "artifact", "idempotency_key"]}},
    {"name": "cancel_task", "description": "Cancel a task.",
     "inputSchema": {"type": "object", "properties": {"task_id": _TASK, "reason": {"type": "string"}},
                     "required": ["task_id"]}},
    {"name": "resume_task",
     "description": "Resume an interrupted or waiting task after re-validating authorization.",
     "inputSchema": {"type": "object", "properties": {"task_id": _TASK}, "required": ["task_id"]}},
    {"name": "get_task_events", "description": "Bounded, redacted task event log.",
     "inputSchema": {"type": "object", "properties": {
         "task_id": _TASK, "after_seq": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["task_id"]}},
]
_APPROVER_TOOL = {
    "name": "approve_task",
    "description": "Approve a task (only exposed to hosts that explicitly grant approval capability).",
    "inputSchema": {"type": "object", "properties": {"task_id": _TASK, "expected_state_version": {"type": "integer"}},
                    "required": ["task_id"]}}
_REVIEWER_TOOL = {
    "name": "review_task_result",
    "description": "Independent review of a needs_review task (only exposed when review capability is granted).",
    "inputSchema": {"type": "object", "properties": {
        "task_id": _TASK, "decision": {"type": "string", "enum": ["accept", "reject", "rework"]},
        "step_id": {"type": "string"}, "note": {"type": "string"}, "expected_state_version": {"type": "integer"}},
        "required": ["task_id", "decision"]}}

TASK_TOOL_NAMES = frozenset([t["name"] for t in _TOOLS] + ["approve_task", "review_task_result"])


def task_tool_definitions(context: SecurityContext) -> list[dict[str, Any]]:
    tools = list(_TOOLS)
    if context.can_approve_tasks:
        tools.append(_APPROVER_TOOL)
    if context.can_review_tasks:
        tools.append(_REVIEWER_TOOL)
    return tools


def call_task_tool(service: Any, context: SecurityContext, name: str, a: dict[str, Any]) -> dict[str, Any]:
    if name == "list_task_templates":
        return service.list_task_templates(context)
    if name == "create_task":
        return service.create_task(context, a["template_id"], a["params"], context_mode=a.get("context_mode"),
                                   idempotency_key=a.get("idempotency_key"))
    if name == "get_task":
        return service.get_task(context, a["task_id"])
    if name == "list_tasks":
        return service.list_tasks(context, states=a.get("states"), limit=a.get("limit", 20))
    if name == "get_task_context":
        return service.get_task_context(context, a["task_id"], a.get("step_id"))
    if name == "dispatch_task_action":
        return service.dispatch_task_action(context, a["task_id"], a["action"], a.get("arguments"),
                                            a["idempotency_key"],
                                            expected_state_version=a.get("expected_state_version"))
    if name == "submit_task_result":
        return service.submit_task_result(context, a["task_id"], a["step_id"], a["artifact"], a["idempotency_key"],
                                          declare_incomplete=bool(a.get("declare_incomplete")), reason=a.get("reason"),
                                          expected_state_version=a.get("expected_state_version"))
    if name == "cancel_task":
        return service.cancel_task(context, a["task_id"], a.get("reason"))
    if name == "resume_task":
        return service.resume_task(context, a["task_id"])
    if name == "get_task_events":
        return service.get_task_events(context, a["task_id"], after_seq=a.get("after_seq", 0),
                                       limit=a.get("limit", 100))
    if name == "approve_task":
        if not context.can_approve_tasks:
            raise TaskError("TASK_PERMISSION_DENIED", "approval capability not granted to this connection")
        return service.approve_task(context, a["task_id"], expected_state_version=a.get("expected_state_version"))
    if name == "review_task_result":
        if not context.can_review_tasks:
            raise TaskError("TASK_PERMISSION_DENIED", "review capability not granted to this connection")
        return service.review_task_result(context, a["task_id"], a["decision"], step_id=a.get("step_id"),
                                          note=a.get("note"), expected_state_version=a.get("expected_state_version"))
    raise ValueError(f"Unknown tool: {name}")
