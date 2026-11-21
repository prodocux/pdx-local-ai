"""Startup/shutdown reconciliation: leases, interrupted operations, outbox, workspace, retention.

Nothing here claims exactly-once across SQLite, the file system and external tools. The
guarantees are: DB writes are atomic per transaction; file writes are idempotent by digest;
cross-database effects are retried through ``task_outbox`` with idempotency keys.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .contracts import INTERRUPTED, NEEDS_REVIEW, TaskError
from .store import utc_iso

if TYPE_CHECKING:  # pragma: no cover
    from .service import TaskService

MAX_OUTBOX_ATTEMPTS = 5


def recover(service: "TaskService") -> dict[str, Any]:
    store, now = service.store, service.clock()
    report: dict[str, Any] = {"interrupted": [], "verification_interrupted": [], "outbox": {}, "workspace": {}}
    with store.tx() as conn:
        rows = conn.execute(
            "SELECT t.* FROM task t LEFT JOIN task_lease l ON l.task_id=t.task_id "
            "WHERE t.state='running' AND (l.task_id IS NULL OR l.expires_at_epoch<=?)", (now,)).fetchall()
        for task in rows:
            v = store.cas_state(conn, task["task_id"], task["state_version"], INTERRUPTED,
                                reason="executor_lost", now=now)
            store.append_event(conn, task["task_id"], "state_changed",
                               {"from": "running", "to": INTERRUPTED, "reason": "executor_lost", "state_version": v},
                               origin="recovery", terminal=True)
            report["interrupted"].append(task["task_id"])
        stuck = conn.execute("SELECT * FROM task WHERE state='awaiting_verification'").fetchall()
        for task in stuck:
            v = store.cas_state(conn, task["task_id"], task["state_version"], NEEDS_REVIEW,
                                reason="verification_interrupted", now=now)
            store.append_event(conn, task["task_id"], "state_changed",
                               {"from": "awaiting_verification", "to": NEEDS_REVIEW, "state_version": v},
                               origin="recovery", terminal=True)
            report["verification_interrupted"].append(task["task_id"])
    report["outbox"] = process_outbox(service)
    expired = purge_expired(service)  # retention: terminal tasks past retain_until
    report["retention"] = {"purged_tasks": expired["purged_tasks"]}
    report["workspace"] = expired["workspace"]
    return report


def process_outbox(service: "TaskService", task_id: str | None = None) -> dict[str, Any]:
    store = service.store
    done = failed = skipped = 0
    q = "SELECT * FROM task_outbox WHERE state IN ('pending','retry')"
    args: tuple[Any, ...] = ()
    if task_id is not None:
        q += " AND task_id=?"
        args = (task_id,)
    rows = store.conn.execute(q + " ORDER BY created_at", args).fetchall()
    for row in rows:
        if service.memory is None or row["kind"] != "memory_proposal":
            skipped += 1
            continue
        payload = json.loads(row["payload_json"])
        state = json.loads(row["result_json"]) if row["result_json"] else {}

        def on_progress(progress: dict[str, Any], outbox_id: str = row["outbox_id"]) -> None:
            with store.tx() as conn:
                conn.execute("UPDATE task_outbox SET result_json=?, updated_at=? WHERE outbox_id=?",
                             (json.dumps(progress, sort_keys=True), utc_iso(service.clock()), outbox_id))

        try:
            service._fault("outbox_before_effect")
            result = service.memory.propose(
                workspace_id=payload["workspace_id"], principal_id=payload["principal_id"], task_id=row["task_id"],
                scope_id=payload["scope_id"], content=payload["content"], citation_id=payload["citation_id"],
                state=state, on_progress=on_progress)
            with store.tx() as conn:
                conn.execute("UPDATE task_outbox SET state='done', attempts=attempts+1, result_json=?, updated_at=? "
                             "WHERE outbox_id=?", (json.dumps(result, sort_keys=True), utc_iso(service.clock()),
                                                   row["outbox_id"]))
                store.append_event(conn, row["task_id"], "memory_proposal_created",
                                   {"proposal_id": result.get("proposal_id"), "state": result.get("proposal_state"),
                                    "auto_published": False}, origin="memory", terminal=True)
            done += 1
        except Exception as exc:  # reconcile later; never fail the already-verified task
            attempts = int(row["attempts"]) + 1
            new_state = "failed" if attempts >= MAX_OUTBOX_ATTEMPTS else "retry"
            with store.tx() as conn:
                conn.execute("UPDATE task_outbox SET state=?, attempts=?, updated_at=? WHERE outbox_id=?",
                             (new_state, attempts, utc_iso(service.clock()), row["outbox_id"]))
                try:
                    store.append_event(conn, row["task_id"], "outbox_failed",
                                       {"error": type(exc).__name__, "attempts": attempts, "state": new_state},
                                       origin="memory", terminal=True)
                except TaskError:
                    pass
            failed += 1
    return {"done": done, "failed": failed, "skipped": skipped}


def reconcile_workspace(service: "TaskService") -> dict[str, Any]:
    known = {r[0] for r in service.store.conn.execute("SELECT task_id FROM task")}
    orphans = service.workspace.list_orphans(known)
    removed = []
    for task_id in orphans:
        try:
            service.workspace.remove_task(task_id)
            removed.append(task_id)
        except TaskError:
            continue
    return {"orphan_dirs_removed": len(removed)}


def purge_expired(service: "TaskService") -> dict[str, Any]:
    result = service.store.purge_expired()
    for task_id in result["task_ids"]:
        service.workspace.remove_task(task_id)
    result["workspace"] = reconcile_workspace(service)
    return result
