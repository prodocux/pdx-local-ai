"""Host-registered bounded validators. Open-ended content is routed to ``needs_review``.

``claimed_success`` from a model is never treated as success; this module is the only
path from ``awaiting_verification`` to ``succeeded``.
"""

from __future__ import annotations

import json
import sqlite3
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable

from jsonschema import Draft202012Validator

from .contracts import LIMITS, TaskError, normalize_query
from .templates import get_template

SELECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "selected_evidence_ids": {"type": "array", "minItems": 1, "maxItems": 32,
                                  "items": {"type": "string"}},
        "notes": {"type": "string", "maxLength": 1000},
    },
    "required": ["selected_evidence_ids"],
    "additionalProperties": False,
}

AclCheck = Callable[[str], bool]


def _norm(text: str) -> str:
    return " ".join(unicodedata.normalize("NFC", text).split())


@dataclass
class Verdict:
    outcome: str  # succeeded | needs_review | failed
    reason: str
    checks: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "reason": self.reason, "checks": self.checks}


def schema_errors(schema: dict[str, Any], value: Any) -> str | None:
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: list(e.path))
    if not errors:
        return None
    path = "/".join(str(p) for p in errors[0].path)
    return f"{errors[0].message} (at /{path})"


def _evidence_map(conn: sqlite3.Connection, task_id: str, attempt_ids: list[str]) -> dict[str, sqlite3.Row]:
    out: dict[str, sqlite3.Row] = {}
    for att in attempt_ids:
        for row in conn.execute("SELECT * FROM task_evidence WHERE task_id=? AND attempt_id=?", (task_id, att)):
            out[row["evidence_id"]] = row
    return out


def validate_selection(conn: sqlite3.Connection, task_id: str, attempt_id: str, artifact: dict[str, Any]) -> None:
    err = schema_errors(SELECTION_SCHEMA, artifact)
    if err:
        raise TaskError("RESULT_REJECTED", f"selection invalid: {err}")
    known = _evidence_map(conn, task_id, [attempt_id])
    missing = [e for e in artifact["selected_evidence_ids"] if e not in known]
    if missing:
        raise TaskError("RESULT_REJECTED", "selection cites unknown evidence", {"unknown": missing[:8]})


def validate_trace(conn: sqlite3.Connection, task: sqlite3.Row, attempt_id: str, artifact: dict[str, Any],
                   *, allow_partial: bool = False) -> dict[str, Any]:
    """Deterministic chain check. Returns ``{complete, stop_reason, ambiguous}``."""
    template = get_template(task["template_id"])
    err = schema_errors(template["trace_artifact_schema"], artifact)
    if err:
        raise TaskError("RESULT_REJECTED", f"trace invalid: {err}")
    params = json.loads(task["params_json"])
    hops = {r["hop_id"]: r for r in conn.execute(
        "SELECT * FROM task_hop WHERE task_id=? AND attempt_id=?", (task["task_id"], attempt_id))}
    evidence = _evidence_map(conn, task["task_id"], [attempt_id])
    chain = artifact["chain"]
    prev_hop: str | None = None
    prev_texts = ""
    for index, link in enumerate(chain):
        hop = hops.get(link["hop_id"])
        if hop is None:
            raise TaskError("RESULT_REJECTED", "chain references unknown hop", {"hop_id": link["hop_id"]})
        if (hop["parent_hop_id"] or None) != prev_hop:
            raise TaskError("RESULT_REJECTED", "chain order does not follow hop parentage",
                            {"stop_reason": "missing_link", "at": index})
        if index == 0 and normalize_query(link["entity"]) != normalize_query(params["start_entity"]):
            raise TaskError("RESULT_REJECTED", "first hop must use the declared start_entity",
                            {"stop_reason": "missing_link"})
        rows = []
        for eid in link["evidence_ids"]:
            row = evidence.get(eid)
            if row is None or row["hop_id"] != link["hop_id"]:
                raise TaskError("RESULT_REJECTED", "chain cites evidence from a different hop",
                                {"stop_reason": "missing_link", "evidence_id": eid})
            rows.append(row)
        texts = _norm(" ".join(r["text"] for r in rows)).lower()
        if _norm(link["entity"]).lower() not in texts:
            raise TaskError("RESULT_REJECTED", "hop evidence does not contain the link entity",
                            {"stop_reason": "missing_link", "at": index})
        if index > 0 and _norm(link["entity"]).lower() not in prev_texts:
            raise TaskError("RESULT_REJECTED", "link entity is not grounded in the previous hop evidence",
                            {"stop_reason": "missing_link", "at": index})
        prev_hop, prev_texts = link["hop_id"], texts
    if _norm(artifact["answer"]).lower() not in prev_texts:
        raise TaskError("RESULT_REJECTED", "answer is not quoted by the last hop evidence",
                        {"stop_reason": "missing_link"})
    alternatives = [a for a in artifact.get("alternatives", [])
                    if _norm(a["answer"]).lower() != _norm(artifact["answer"]).lower()]
    return {"complete": True, "ambiguous": bool(alternatives),
            "stop_reason": "ambiguity_unresolved" if alternatives else "chain_complete"}


def verify_task(conn: sqlite3.Connection, task: sqlite3.Row, final_attempt: sqlite3.Row,
                *, parents: list[dict[str, Any]], recalled_memory_ids: set[str],
                acl_check: AclCheck) -> Verdict:
    started = time.monotonic()
    template = get_template(task["template_id"])
    params = json.loads(task["params_json"])
    artifact = json.loads(final_attempt["artifact_json"])
    checks: list[dict[str, Any]] = []

    def record(check_id: str, status: str, detail: str = "") -> None:
        checks.append({"id": check_id, "status": status, "detail": detail})

    def over_time() -> bool:
        return time.monotonic() - started > LIMITS["verification_seconds"]

    err = schema_errors(template["final_artifact_schema"], artifact)
    record("json_schema", "fail" if err else "pass", err or "")
    if err:
        return Verdict("failed", "final artifact violates schema", checks)

    parent_attempt_ids = [p["attempt_id"] for p in parents]
    evidence = _evidence_map(conn, task["task_id"], parent_attempt_ids)
    selected: set[str] = set()
    for p in parents:
        selected.update(p["artifact"].get("selected_evidence_ids", []))

    def acl_failures(ids: list[str]) -> list[str]:
        files = {evidence[e]["file_record_id"] for e in ids if e in evidence}
        return sorted(f for f in files if not acl_check(f))

    def cited_ok(ids: list[str], check_id: str, *, require_selected: bool) -> Verdict | None:
        unknown = [e for e in ids if e not in evidence]
        if unknown:
            record(check_id, "fail", f"unknown evidence: {unknown[:4]}")
            return Verdict("failed", "citation does not resolve to task evidence", checks)
        if require_selected and any(e not in selected for e in ids):
            record(check_id, "fail", "citation outside gathered selection")
            return Verdict("failed", "citation outside gathered selection", checks)
        revoked = acl_failures(ids)
        if revoked:
            record(check_id, "fail", "source access revoked")
            return Verdict("failed", "permission_denied: source access revoked after retrieval", checks)
        return None

    validators = template["validators"]
    review_reasons: list[str] = []

    if "required_fields" in validators:
        want = {q["field"] for q in params["questions"]}
        got = [i["field"] for i in artifact["items"]]
        if set(got) != want or len(got) != len(set(got)):
            record("required_fields", "fail", f"fields {sorted(got)} != {sorted(want)}")
            return Verdict("failed", "required fields mismatch", checks)
        record("required_fields", "pass")

    if "evidence_values" in validators:
        for item in artifact["items"]:
            bad = cited_ok(item["evidence_ids"], "evidence_values", require_selected=True)
            if bad:
                return bad
            haystack = _norm(" ".join(evidence[e]["text"] for e in item["evidence_ids"])).lower()
            if _norm(item["value"]).lower() not in haystack:
                review_reasons.append(f"value for '{item['field']}' not quoted verbatim")
        record("evidence_values", "review" if review_reasons else "pass", "; ".join(review_reasons))

    if "trace_matches" in validators:
        trace = next((p for p in parents if p["step_id"] == "trace"), None)
        if trace is None or trace["artifact_sha256"] != artifact["trace_sha256"] \
                or _norm(trace["artifact"]["answer"]) != _norm(artifact["answer"]):
            record("trace_matches", "fail", "final result does not match accepted trace")
            return Verdict("failed", "final result does not match accepted trace", checks)
        chain_ids = [e for link in trace["artifact"]["chain"] for e in link["evidence_ids"]]
        bad = cited_ok(chain_ids, "trace_matches", require_selected=False)
        if bad:
            return bad
        record("trace_matches", "pass")

    if "output_schema" in validators:
        err = schema_errors(params["output_schema"], artifact["output"])
        record("output_schema", "fail" if err else "pass", err or "")
        if err:
            return Verdict("failed", "output violates declared output_schema", checks)

    if "evidence_refs" in validators:
        bad = cited_ok(artifact["evidence_ids"], "evidence_refs", require_selected=True)
        if bad:
            return bad
        record("evidence_refs", "pass")

    if "memory_refs" in validators:
        unknown = [m for m in artifact.get("memory_ids", []) if m not in recalled_memory_ids]
        if unknown:
            record("memory_refs", "fail", f"unrecalled memory: {unknown[:4]}")
            return Verdict("failed", "memory reference not recalled in this task", checks)
        record("memory_refs", "pass")

    if over_time():
        record("verification_time", "review", "verification time budget exceeded")
        return Verdict("needs_review", "verification_timeout", checks)
    if review_reasons:
        return Verdict("needs_review", "; ".join(review_reasons), checks)
    if not template["auto_accept"]:
        record("open_ended_content", "review", "structure verified; content requires review")
        return Verdict("needs_review", "open_ended_content_requires_review", checks)
    return Verdict("succeeded", "all registered validators passed", checks)
