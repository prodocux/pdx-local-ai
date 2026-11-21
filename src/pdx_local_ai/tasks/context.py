"""ContextAssembler, shared retrieval ledger and the minimal action envelope.

The packet is rebuilt from task storage on every step (never from chat history).
Stable-prefix rule: the ``prefix`` segment is immutable per (template, step, params),
serialized deterministically (sorted keys, fixed separators) and contains no timestamps,
random identifiers or attempt numbers. Volatile material is appended last.
"""

from __future__ import annotations

import json
import math
import sqlite3
from typing import Any

from .contracts import (
    LEDGER_DEFAULTS,
    LIMITS,
    TaskError,
    canonical_json,
    sha256_json,
    utf8_len,
)
from .templates import ACTION_SCHEMAS, get_template

CONTEXT_CONTRACT = "pdx_local_task_context_v1"
ENVELOPE_CONTRACT = "pdx_local_task_envelope_v1"

_RULES = (
    "Use only listed actions; every action is re-validated by the host.",
    "Cite evidence only by evidence_id returned by the host.",
    "claimed success is never success; the host verifies results.",
    "Do not request paths, credentials, or hidden acceptance data.",
)


# --------------------------------------------------------------------------- ledger
class RetrievalLedger:
    """One shared ledger per (task, attempt). All hops and branches draw from it."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    @classmethod
    def new(cls, now: float, limits: dict[str, int] | None = None, *, max_queries: int) -> "RetrievalLedger":
        lim = dict(LEDGER_DEFAULTS)
        lim.update(limits or {})
        return cls({
            "limits": lim,
            "consumed": {k: 0 for k in lim},
            "queries": 0,
            "max_queries": max_queries,
            "pins": {},          # file_record_id -> source_version_id (version pinning)
            "branches": {},      # parent_hop_id -> follow-up count
        })

    @classmethod
    def load(cls, conn: sqlite3.Connection, task_id: str, attempt_id: str) -> "RetrievalLedger":
        row = conn.execute("SELECT ledger_json FROM task_ledger WHERE task_id=? AND attempt_id=?",
                           (task_id, attempt_id)).fetchone()
        if row is None:
            raise TaskError("RETRIEVAL_BUDGET_EXHAUSTED", "retrieval ledger missing")
        return cls(json.loads(row[0]))

    def save(self, conn: sqlite3.Connection, task_id: str, attempt_id: str) -> None:
        conn.execute("INSERT INTO task_ledger(task_id, attempt_id, ledger_json) VALUES (?,?,?) "
                     "ON CONFLICT(task_id, attempt_id) DO UPDATE SET ledger_json=excluded.ledger_json",
                     (task_id, attempt_id, canonical_json(self.data)))

    def remaining(self, now: float) -> dict[str, int]:
        lim, used = self.data["limits"], self.data["consumed"]
        rem = {k: max(0, int(lim[k]) - int(used[k])) for k in lim}
        # elapsed_ms is retrieval time actually consumed (charged from receipts), not wall time
        # since first use: agent think time / pauses must not drain the retrieval budget.
        rem["queries"] = max(0, int(self.data["max_queries"]) - int(self.data["queries"]))
        return rem

    def allocate(self, now: float, queries_left: int) -> dict[str, int]:
        """Per-query allocation = ceil(remaining / queries_left); the ledger is never reset."""
        rem = self.remaining(now)
        if rem["queries"] <= 0:
            raise TaskError("RETRIEVAL_BUDGET_EXHAUSTED", "query quota exhausted", {"stop_reason": "query_quota"})
        for key in ("elapsed_ms", "candidates", "opened_files", "opened_blocks", "returned_bytes"):
            if rem[key] <= 0:
                raise TaskError("RETRIEVAL_BUDGET_EXHAUSTED", f"shared retrieval budget exhausted: {key}",
                                {"stop_reason": "budget_exhausted", "exhausted": key})
        share = max(1, min(queries_left, rem["queries"]))
        out = {k: max(1, math.ceil(rem[k] / share)) for k in
               ("elapsed_ms", "candidates", "opened_files", "opened_blocks", "returned_bytes")}
        out["elapsed_ms"] = max(50, min(out["elapsed_ms"], rem["elapsed_ms"]))
        out["returned_bytes"] = min(out["returned_bytes"], LIMITS["tool_return_bytes"] - 4096)
        return out

    def charge(self, consumed: dict[str, int]) -> None:
        for key, value in consumed.items():
            if key in self.data["consumed"]:
                self.data["consumed"][key] = int(self.data["consumed"][key]) + max(0, int(value))
        self.data["queries"] = int(self.data["queries"]) + 1

    def public(self, now: float) -> dict[str, Any]:
        rem = self.remaining(now)
        return {k: rem[k] for k in sorted(rem)}


# --------------------------------------------------------------------------- assembler
def _evidence_rows(conn: sqlite3.Connection, task_id: str, attempt_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM task_evidence WHERE task_id=? AND attempt_id=? ORDER BY created_at, evidence_id",
        (task_id, attempt_id)).fetchall()


def current_attempt(conn: sqlite3.Connection, task_id: str, step_id: str) -> sqlite3.Row | None:
    step = conn.execute("SELECT current_attempt_id FROM task_step WHERE task_id=? AND step_id=?",
                        (task_id, step_id)).fetchone()
    if step is None or step["current_attempt_id"] is None:
        return None
    return conn.execute("SELECT * FROM task_attempt WHERE attempt_id=?", (step["current_attempt_id"],)).fetchone()


def accepted_parent_artifacts(conn: sqlite3.Connection, task_id: str, depends_on: list[str]) -> list[dict[str, Any]]:
    parents = []
    for dep in sorted(depends_on):
        step = conn.execute("SELECT * FROM task_step WHERE task_id=? AND step_id=?", (task_id, dep)).fetchone()
        if step is None or step["state"] != "accepted" or step["current_attempt_id"] is None:
            raise TaskError("STEP_NOT_READY", f"dependency {dep} is not accepted")
        att = conn.execute("SELECT * FROM task_attempt WHERE attempt_id=?", (step["current_attempt_id"],)).fetchone()
        if att is None or att["artifact_json"] is None:
            raise TaskError("STEP_NOT_READY", f"dependency {dep} has no artifact")
        parents.append({"step_id": dep, "artifact_sha256": att["artifact_sha256"],
                        "attempt_id": att["attempt_id"], "artifact": json.loads(att["artifact_json"])})
    return parents


class ContextAssembler:
    """Rebuilds a bounded ContextPacket for one step from stored state."""

    def __init__(self, store: Any) -> None:
        self.store = store

    def stable_prefix(self, task: sqlite3.Row, step_id: str) -> dict[str, Any]:
        template = get_template(task["template_id"])
        step = next(s for s in template["steps"] if s["id"] == step_id)
        return {
            "contract": CONTEXT_CONTRACT,
            "template": {"id": task["template_id"], "version": task["template_version"],
                         "sha256": task["template_sha256"]},
            "context_mode": task["context_mode"],
            "step": {"id": step["id"], "kind": step["kind"], "actions": list(step["actions"])},
            "params": json.loads(task["params_json"]),
            "action_schemas": {a: ACTION_SCHEMAS[a] for a in sorted(step["actions"])},
            "rules": list(_RULES),
        }

    def assemble(self, conn: sqlite3.Connection, task: sqlite3.Row, step_id: str, now: float,
                 *, ledger: RetrievalLedger | None = None) -> dict[str, Any]:
        template = get_template(task["template_id"])
        step_def = next(s for s in template["steps"] if s["id"] == step_id)
        attempt = current_attempt(conn, task["task_id"], step_id)
        if attempt is None:
            raise TaskError("STEP_NOT_READY", "step has no active attempt")
        parents = accepted_parent_artifacts(conn, task["task_id"], step_def["depends_on"])
        prefix = self.stable_prefix(task, step_id)
        mode = task["context_mode"]
        window_cap, text_cap = {"bounded_retrieval": (8, 2000), "bounded_multihop": (6, 1500),
                                "bounded_full": (64, 20000)}[mode]
        evidence_rows: list[sqlite3.Row] = []
        parent_attempt_ids = [p["attempt_id"] for p in parents]
        for pid in parent_attempt_ids + [attempt["attempt_id"]]:
            evidence_rows.extend(_evidence_rows(conn, task["task_id"], pid))
        hops = conn.execute(
            "SELECT hop_id, parent_hop_id, hop_no, entity, status, stop_reason, evidence_count "
            "FROM task_hop WHERE task_id=? AND attempt_id=? ORDER BY hop_no, created_at, hop_id",
            (task["task_id"], attempt["attempt_id"])).fetchall()
        volatile: dict[str, Any] = {
            "task_id": task["task_id"],
            "state": task["state"],
            "state_version": task["state_version"],
            "attempt": {"id": attempt["attempt_id"], "no": attempt["attempt_no"]},
            "rework_note": attempt["rework_note"],
            "parents": parents,
            "hops": [dict(h) for h in hops],
            "ledger_remaining": ledger.public(now) if ledger is not None else None,
        }
        if mode == "bounded_multihop" or ledger is not None:
            volatile["pins"] = len((ledger.data["pins"]) if ledger is not None else {})
        selected_ids: set[str] = set()
        for p in parents:
            art = p["artifact"]
            for ids in _collect_evidence_ids(art):
                selected_ids.add(ids)
        ordered = sorted(evidence_rows, key=lambda r: (0 if r["evidence_id"] in selected_ids else 1, r["created_at"]))
        windows: list[dict[str, Any]] = []
        for row in ordered[:window_cap]:
            text = row["text"]
            windows.append({
                "evidence_id": row["evidence_id"], "hop_id": row["hop_id"],
                "citation_id": row["citation_id"], "source_version_id": row["source_version_id"],
                "truncated": len(text) > text_cap, "text": text[:text_cap],
            })
        omitted = [r["evidence_id"] for r in ordered[window_cap:]]

        def build(wins: list[dict[str, Any]], omitted_ids: list[str]) -> dict[str, Any]:
            packet = {"prefix": prefix, "prefix_sha256": sha256_json(prefix),
                      "volatile": {**volatile, "evidence_windows": wins,
                                   "omitted_evidence_ids": omitted_ids[:64],
                                   "omitted_count": len(omitted_ids)}}
            return packet

        packet = build(windows, omitted)
        # Critical material (prefix + parent artifacts) is never silently truncated.
        critical = build([], [])
        if utf8_len(canonical_json(critical)) > LIMITS["context_packet_bytes"]:
            raise TaskError("CONTEXT_BUDGET_EXCEEDED", "critical context exceeds packet limit",
                            {"limit_bytes": LIMITS["context_packet_bytes"]})
        while utf8_len(canonical_json(packet)) > LIMITS["context_packet_bytes"] and windows:
            dropped = windows.pop()
            omitted.insert(0, dropped["evidence_id"])
            packet = build(windows, omitted)
        encoded = canonical_json(packet)
        packet["context_sha256"] = sha256_json(json.loads(encoded))
        packet["context_bytes"] = utf8_len(encoded)
        return packet


def _collect_evidence_ids(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "evidence_ids" and isinstance(value, list):
                out.extend(str(v) for v in value)
            else:
                out.extend(_collect_evidence_ids(value))
    elif isinstance(node, list):
        for v in node:
            out.extend(_collect_evidence_ids(v))
    return out


# --------------------------------------------------------------------------- envelope
def build_envelope(task: sqlite3.Row, step_id: str | None, attempt: sqlite3.Row | None,
                   remaining: dict[str, Any], *, evidence_ids: list[str], hop_ids: list[str],
                   actions_left: int, next_step: str) -> dict[str, Any]:
    """Minimal, bounded action envelope. Never carries lease secrets or acceptance answers."""
    template = get_template(task["template_id"])
    actions: list[str] = []
    if step_id is not None and task["state"] in ("running", "queued"):
        step = next(s for s in template["steps"] if s["id"] == step_id)
        actions = list(step["actions"])
    return {
        "contract": ENVELOPE_CONTRACT,
        "task_id": task["task_id"],
        "state": task["state"],
        "state_version": task["state_version"],
        "step_id": step_id,
        "attempt_no": attempt["attempt_no"] if attempt is not None else None,
        "next": next_step,
        "available_actions": actions,
        "action_schemas": {a: ACTION_SCHEMAS[a] for a in sorted(actions)},
        "enums": {"evidence_ids": evidence_ids[:64], "parent_hop_id": hop_ids[:16]},
        "remaining": {"tool_actions": actions_left, **{k: remaining[k] for k in sorted(remaining)}},
        "refs": {"context": "get_task_context", "events": "get_task_events"},
    }
