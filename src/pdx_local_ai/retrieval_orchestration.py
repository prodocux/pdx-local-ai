"""Gate 4C-3 lexical-first orchestration inside one caller transaction."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .validation import ContractError
from .paths import get_root

ROOT = get_root()
SQL_009 = ROOT / "sql" / "009_retrieval_orchestration.sql"
POLICY_PATH = ROOT / "docs" / "proposals" / "gate4c3" / "lexical-first-policy-v1.json"
REQUEST_SCHEMA = ROOT / "schemas" / "pdx_local_retrieval_escalation_request_v1.schema.json"
STAGE_SCHEMA = ROOT / "schemas" / "pdx_local_retrieval_stage_receipt_v1.schema.json"
TERMINAL_SCHEMA = ROOT / "schemas" / "pdx_local_retrieval_orchestration_receipt_v1.schema.json"
POLICY_SHA256 = hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()
ESCALATE = {
    "no_lexical_candidates",
    "insufficient_result_count",
    "low_term_coverage",
    "ambiguous_lexical_rank",
    "lexical_budget_exhausted",
}


@dataclass
class _Identity:
    profile: str
    contract: str
    target_id: str
    target_version_id: str | None
    content_sha256: str
    content: str
    source_binding_id: str | None
    provenance: str
    from_lexical: bool
    from_vector: bool = False
    lexical_score: float | None = None
    vector_score: float | None = None

    def ref(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "target_id": self.target_id,
            "target_version_id": self.target_version_id,
            "content_sha256": self.content_sha256,
        }

    def key(self) -> tuple[str, str, str]:
        version = "" if self.target_version_id is None else self.target_version_id
        return (self.profile, self.target_id, version)


def apply_retrieval_orchestration_migration(conn: sqlite3.Connection) -> None:
    """Install additive 009. Catalog stays on migrations 001 through 008."""
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SQL_009.read_text(encoding="utf-8"))


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def order_key(identity: _Identity) -> tuple[Any, ...]:
    """Ascending total order. A missing score is not zero."""
    vector_missing = 0 if identity.vector_score is not None else 1
    lexical_missing = 0 if identity.lexical_score is not None else 1
    vector_order = 0.0 if identity.vector_score is None else -_finite(identity.vector_score)
    lexical_order = 0.0 if identity.lexical_score is None else -_finite(identity.lexical_score)
    version = "" if identity.target_version_id is None else identity.target_version_id
    return (
        vector_missing,
        vector_order,
        lexical_missing,
        lexical_order,
        identity.target_id,
        version,
    )


def require_exact_citation_ids(actual: Sequence[str], required: Sequence[str]) -> None:
    if list(actual) != list(required):
        raise ContractError("citation set does not match result refs")


def orchestrate_retrieval(
    conn: sqlite3.Connection,
    *,
    request: Mapping[str, Any],
    query_text: str,
    query_vector: Sequence[float] | None = None,
    store: Any = None,
    monotonic: Callable[[], float] | None = None,
    now: Callable[[], str] | None = None,
    new_id: Callable[[], str] | None = None,
    before_citation_recheck: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Run R1 and optional R2, then publish receipts in one transaction."""
    clock = monotonic or time.monotonic
    stamp = now or _now
    mint = new_id or (lambda: str(uuid.uuid4()))
    if conn.in_transaction:
        raise ContractError("orchestration requires an idle connection")
    _validate_request(dict(request))
    tokens = _tokens(query_text)
    apply_retrieval_orchestration_migration(conn)
    if conn.row_factory is not sqlite3.Row:
        conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        receipt = _run(
            conn,
            request=dict(request),
            tokens=tokens,
            query_vector=query_vector,
            store=store,
            clock=clock,
            stamp=stamp,
            mint=mint,
            before_citation_recheck=before_citation_recheck,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return receipt


def _run(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    tokens: list[str],
    query_vector: Sequence[float] | None,
    store: Any,
    clock: Callable[[], float],
    stamp: Callable[[], str],
    mint: Callable[[], str],
    before_citation_recheck: Callable[[], None] | None,
) -> dict[str, Any]:
    limits = request["aggregate_limits"]
    deadline = clock() + limits["elapsed_ms"] / 1000.0
    r1_mark = clock()
    admitted, r1_input, flags = _lexical(conn, request=request, tokens=tokens, deadline=deadline, clock=clock)
    r1_elapsed = _elapsed(r1_mark, clock(), limits["elapsed_ms"])
    decision = _r1_decision(admitted, tokens, flags)
    wanted = decision in ESCALATE
    snapshot = None
    vector_admitted = 0
    r2_elapsed = 0
    r2_input = 0
    if _needs_vector(decision, wanted, request, admitted, limits, flags):
        r2_mark = clock()
        snapshot, vector_admitted = _vector(
            conn,
            request=request,
            admitted=admitted,
            limits=limits,
            query_vector=query_vector,
            store=store,
            deadline=deadline,
            clock=clock,
            flags=flags,
        )
        r2_elapsed = _elapsed(r2_mark, clock(), max(0, limits["elapsed_ms"] - r1_elapsed))
        r2_input = int(snapshot.authorized_scored)
    reason = _terminal_reason(
        decision=decision,
        wanted=wanted,
        allow_vector=bool(request["allow_vector_escalation"]),
        admitted=admitted,
        limits=limits,
        flags=flags,
        snapshot=snapshot,
    )
    ordered = sorted(admitted, key=order_key)
    for identity in ordered:
        identity.lexical_score = None
        identity.vector_score = None
    citation_ids = _citation_union(conn, request, ordered)
    if before_citation_recheck is not None:
        before_citation_recheck()
    _recheck_citations(conn, request, ordered, citation_ids)
    return _publish(
        conn,
        request=request,
        ordered=ordered,
        reason=reason,
        decision=decision,
        r1_input=r1_input,
        r1_elapsed=min(r1_elapsed, limits["elapsed_ms"]),
        r2_input=r2_input,
        r2_elapsed=min(r2_elapsed, max(0, limits["elapsed_ms"] - r1_elapsed)),
        vector_admitted=vector_admitted,
        snapshot=snapshot,
        citation_ids=citation_ids,
        created=stamp(),
        mint=mint,
    )


def _needs_vector(
    decision: str,
    wanted: bool,
    request: dict[str, Any],
    admitted: list[_Identity],
    limits: dict[str, int],
    flags: dict[str, bool],
) -> bool:
    if not wanted or not request["allow_vector_escalation"]:
        return False
    if any(flags.values()):
        return False
    pool_remaining = limits["lexical_candidates"] - len(admitted)
    result_remaining = limits["results"] - len(admitted)
    fused_remaining = limits["fused_candidates"] - len(admitted)
    byte_remaining = limits["returned_bytes"] - sum(_identity_bytes(item) for item in admitted)
    vector_remaining = limits["vector_candidates"]
    return min(pool_remaining, vector_remaining, result_remaining, fused_remaining, byte_remaining) >= 1


def _lexical(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    tokens: list[str],
    deadline: float,
    clock: Callable[[], float],
) -> tuple[list[_Identity], int, dict[str, bool]]:
    limits = request["aggregate_limits"]
    rows = _lexical_rows(
        conn,
        layer=request["selected_memory_layer"],
        workspace_id=request["workspace_id"],
        principal_id=request["principal_id"],
        fts_query=_fts_query(tokens),
        limit=limits["lexical_candidates"] + 1,
    )
    admitted: list[_Identity] = []
    scored = 0
    used_bytes = 0
    flags = {"time": False, "pool": False, "result": False, "byte": False, "fused": False}
    for row in rows:
        if clock() >= deadline:
            flags["time"] = True
            break
        scored += 1
        identity = _identity_from_row(request["selected_memory_layer"], row)
        size = _identity_bytes(identity)
        if len(admitted) >= limits["lexical_candidates"]:
            flags["pool"] = True
            break
        if len(admitted) >= limits["results"]:
            flags["result"] = True
            break
        if size > limits["returned_bytes"] - used_bytes:
            flags["byte"] = True
            break
        if len(admitted) >= limits["fused_candidates"]:
            flags["fused"] = True
            break
        admitted.append(identity)
        used_bytes += size
    return admitted, scored, flags


def _vector(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    admitted: list[_Identity],
    limits: dict[str, int],
    query_vector: Sequence[float] | None,
    store: Any,
    deadline: float,
    clock: Callable[[], float],
    flags: dict[str, bool],
) -> tuple[Any, int]:
    if store is None:
        raise ContractError("snapshot query store is required")
    bound = getattr(store, "_conn", None)
    if bound is not None and bound is not conn:
        raise ContractError("snapshot query connection mismatch")
    pool_remaining = limits["lexical_candidates"] - len(admitted)
    vector_remaining = limits["vector_candidates"]
    result_remaining = limits["results"] - len(admitted)
    fused_remaining = limits["fused_candidates"] - len(admitted)
    byte_remaining = limits["returned_bytes"] - sum(_identity_bytes(item) for item in admitted)
    k = min(pool_remaining, vector_remaining, result_remaining, fused_remaining)
    snapshot = store.query_in_snapshot(
        workspace_id=request["workspace_id"],
        principal_id=request["principal_id"],
        layer=request["selected_memory_layer"],
        query_context={"vector": None if query_vector is None else list(query_vector)},
        k=k,
        deadline=deadline,
        _monotonic=clock,
    )
    if snapshot.disposition == "time_limit":
        flags["time"] = True
        return snapshot, 0
    if snapshot.disposition != "results":
        return snapshot, 0
    by_key = {item.key(): item for item in admitted}
    vector_admitted = 0
    for hit in snapshot.results:
        if clock() >= deadline:
            flags["time"] = True
            break
        if pool_remaining < 1 or vector_remaining < 1:
            flags["pool"] = True
            break
        identity = _identity_from_hit(conn, request, hit)
        existing = by_key.get(identity.key())
        if existing is not None:
            existing.vector_score = _finite(float(hit["score"]))
            existing.from_vector = True
            vector_admitted += 1
            pool_remaining -= 1
            vector_remaining -= 1
            continue
        if result_remaining < 1:
            flags["result"] = True
            break
        size = _identity_bytes(identity)
        if size > byte_remaining:
            flags["byte"] = True
            break
        if fused_remaining < 1:
            flags["fused"] = True
            break
        identity.vector_score = _finite(float(hit["score"]))
        identity.from_vector = True
        admitted.append(identity)
        by_key[identity.key()] = identity
        vector_admitted += 1
        pool_remaining -= 1
        vector_remaining -= 1
        result_remaining -= 1
        fused_remaining -= 1
        byte_remaining -= size
    return snapshot, vector_admitted


def _r1_decision(admitted: list[_Identity], tokens: list[str], flags: dict[str, bool]) -> str:
    if any(flags.values()):
        return "lexical_budget_exhausted"
    count = len(admitted)
    if count == 0:
        return "no_lexical_candidates"
    if count == 1:
        return "insufficient_result_count"
    if _coverage(admitted[0].content, tokens) < 1.0:
        return "low_term_coverage"
    first = admitted[0].lexical_score
    second = admitted[1].lexical_score
    if first is None or second is None or not first > second:
        return "ambiguous_lexical_rank"
    return "lexical_sufficient"


def _terminal_reason(
    *,
    decision: str,
    wanted: bool,
    allow_vector: bool,
    admitted: list[_Identity],
    limits: dict[str, int],
    flags: dict[str, bool],
    snapshot: Any,
) -> str:
    lexical_consumed = sum(1 for item in admitted if item.from_lexical)
    vector_consumed = sum(1 for item in admitted if item.from_vector)
    pool_remaining = limits["lexical_candidates"] - lexical_consumed - vector_consumed
    vector_remaining = limits["vector_candidates"] - vector_consumed
    result_remaining = limits["results"] - len(admitted)
    byte_remaining = limits["returned_bytes"] - sum(_identity_bytes(item) for item in admitted)
    fused_remaining = limits["fused_candidates"] - len(admitted)
    if flags["time"] or (snapshot is not None and snapshot.disposition == "time_limit"):
        return "time_limit"
    if flags["pool"] or (wanted and allow_vector and (pool_remaining == 0 or vector_remaining == 0)):
        return "candidate_limit"
    if flags["result"] or (wanted and allow_vector and result_remaining == 0):
        return "result_limit"
    if flags["byte"] or (wanted and allow_vector and byte_remaining < 1 and result_remaining > 0):
        return "byte_limit"
    if flags["fused"] or (
        wanted and allow_vector and fused_remaining == 0 and pool_remaining > 0 and vector_remaining > 0
    ):
        return "candidate_limit"
    if decision == "lexical_sufficient":
        return "lexical_sufficient"
    if wanted and not allow_vector:
        return "vector_not_authorized"
    if snapshot is not None and snapshot.disposition == "vector_generation_unavailable":
        return "vector_generation_unavailable"
    if snapshot is not None and snapshot.disposition == "no_authorized_candidates":
        return "no_authorized_candidates"
    if len(admitted) == 0:
        return "no_authorized_candidates"
    if snapshot is not None and snapshot.disposition == "results":
        return "vector_sufficient"
    raise ContractError("orchestration terminal reason is unresolved")


def _publish(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    ordered: list[_Identity],
    reason: str,
    decision: str,
    r1_input: int,
    r1_elapsed: int,
    r2_input: int,
    r2_elapsed: int,
    vector_admitted: int,
    snapshot: Any,
    citation_ids: list[str],
    created: str,
    mint: Callable[[], str],
) -> dict[str, Any]:
    limits = request["aggregate_limits"]
    lexical_rows = [item for item in ordered if item.from_lexical]
    lexical_bytes = sum(_identity_bytes(item) for item in lexical_rows)
    vector_bytes = sum(_identity_bytes(item) for item in ordered if not item.from_lexical)
    r2_completed = (
        snapshot is not None
        and snapshot.generation_id is not None
        and snapshot.disposition in {"results", "no_authorized_candidates"}
    )
    r2_reason = decision if r2_completed else _skipped_reason(reason, decision)
    r2_disposition = "completed" if r2_completed else "skipped"
    r1_limits = _stage_counters(
        limits["lexical_candidates"], limits["results"], limits["returned_bytes"], limits["elapsed_ms"]
    )
    r2_limits = _stage_counters(
        limits["vector_candidates"], limits["results"], limits["returned_bytes"], limits["elapsed_ms"]
    )
    r1_consumed = _stage_counters(len(lexical_rows), len(lexical_rows), lexical_bytes, r1_elapsed)
    aggregate_consumed = {
        "lexical_candidates": r1_consumed["candidates"],
        "vector_candidates": vector_admitted,
        "fused_candidates": len(ordered),
        "results": len(ordered),
        "document_files": 0,
        "document_blocks": 0,
        "returned_bytes": lexical_bytes + vector_bytes,
        "elapsed_ms": min(limits["elapsed_ms"], r1_elapsed + r2_elapsed),
    }
    _require_within(aggregate_consumed, limits)
    r1 = _stage_envelope(
        request=request,
        stage="r1_lexical",
        disposition="completed",
        entry_reason="explicit_memory_layer",
        limits=r1_limits,
        consumed=r1_consumed,
        input_count=r1_input,
        output_count=len(lexical_rows),
        identities=lexical_rows,
        generation_id=None,
        generation_sha=None,
        created=created,
        mint=mint,
    )
    vector_ids = [item for item in ordered if item.from_vector]
    vector_only = [item for item in ordered if not item.from_lexical]
    r2 = _stage_envelope(
        request=request,
        stage="r2_vector",
        disposition=r2_disposition,
        entry_reason=r2_reason,
        limits=r2_limits,
        consumed=_stage_counters(vector_admitted, len(vector_only), vector_bytes, r2_elapsed),
        input_count=r2_input,
        output_count=vector_admitted,
        identities=vector_ids,
        generation_id=None if snapshot is None or not r2_completed else snapshot.generation_id,
        generation_sha=None if snapshot is None or not r2_completed else snapshot.image_sha256,
        created=created,
        mint=mint,
    )
    _validate(STAGE_SCHEMA, r1)
    _validate(STAGE_SCHEMA, r2)
    terminal = {
        "schema_version": "pdx_local_retrieval_orchestration_receipt_v1",
        "receipt_id": mint(),
        "request_id": request["request_id"],
        "request_sha256": canonical_sha256(request),
        "query_id": request["query_id"],
        "workspace_id": request["workspace_id"],
        "principal_id": request["principal_id"],
        "selected_memory_layer": request["selected_memory_layer"],
        "policy_id": "lexical-first",
        "policy_version": "1",
        "policy_sha256": POLICY_SHA256,
        "allow_vector_escalation": request["allow_vector_escalation"],
        "allow_document_expansion": False,
        "stage_receipt_ids": [r1["stage_receipt_id"], r2["stage_receipt_id"]],
        "stage_receipt_sha256s": [canonical_sha256(r1), canonical_sha256(r2)],
        "aggregate_limits": limits,
        "aggregate_consumed": {
            "lexical_candidates": len(lexical_rows),
            "vector_candidates": vector_admitted,
            "fused_candidates": len(ordered),
            "results": len(ordered),
            "document_files": 0,
            "document_blocks": 0,
            "returned_bytes": lexical_bytes + vector_bytes,
            "elapsed_ms": min(limits["elapsed_ms"], r1_elapsed + r2_elapsed),
        },
        "terminal_reason": reason,
        "result_refs": [item.ref() for item in ordered],
        "citation_ids": citation_ids,
        "document_expansion": "not_authorized",
        "catalog_receipt_id": None,
        "catalog_receipt_sha256": None,
        "created_at": created,
    }
    _require_within(terminal["aggregate_consumed"], limits)
    _validate(TERMINAL_SCHEMA, terminal)
    try:
        _insert_stage(conn, r1)
        _insert_stage(conn, r2)
        _insert_terminal(conn, terminal)
        for ordinal, stage in enumerate((r1, r2)):
            conn.execute(
                """
                INSERT INTO retrieval_orchestration_stage_link
                VALUES (?,?,?,?)
                """,
                (terminal["receipt_id"], stage["stage_receipt_id"], ordinal, canonical_sha256(stage)),
            )
        conn.execute(
            "INSERT INTO retrieval_orchestration_query_id VALUES (?,?,?,?)",
            (request["workspace_id"], request["principal_id"], request["query_id"], terminal["receipt_id"]),
        )
    except sqlite3.IntegrityError as error:
        raise ContractError("query id already consumed") from error
    return terminal


def _stage_envelope(
    *,
    request: dict[str, Any],
    stage: str,
    disposition: str,
    entry_reason: str,
    limits: dict[str, int],
    consumed: dict[str, int],
    input_count: int,
    output_count: int,
    identities: list[_Identity],
    generation_id: str | None,
    generation_sha: str | None,
    created: str,
    mint: Callable[[], str],
) -> dict[str, Any]:
    envelope = {
        "schema_version": "pdx_local_retrieval_stage_receipt_v1",
        "stage_receipt_id": mint(),
        "request_id": request["request_id"],
        "query_id": request["query_id"],
        "workspace_id": request["workspace_id"],
        "principal_id": request["principal_id"],
        "stage": stage,
        "disposition": disposition,
        "entry_reason": entry_reason,
        "profile": request["selected_memory_layer"],
        "generation_id": generation_id,
        "generation_sha256": generation_sha,
        "limits": limits,
        "consumed": consumed,
        "input_candidate_count": input_count,
        "output_candidate_count": output_count,
        "authorized_ids_sha256": _ids_sha(identities),
        "subreceipt_id": None,
        "subreceipt_sha256": None,
        "created_at": created,
    }
    return envelope


def _skipped_reason(reason: str, decision: str) -> str:
    """Keep the lexical insufficiency when the terminal already states the policy outcome.

    vector_not_authorized and vector_generation_unavailable stay on the terminal
    receipt. The stage receipt keeps the lexical decision that asked for escalation.
    """
    if reason in {"vector_not_authorized", "vector_generation_unavailable"} and decision in ESCALATE:
        return decision
    if reason == "vector_not_authorized":
        return "vector_not_authorized"
    if reason == "vector_generation_unavailable":
        return "vector_generation_unavailable"
    if reason == "lexical_sufficient":
        return "lexical_sufficient"
    if reason in {"candidate_limit", "result_limit", "byte_limit", "time_limit"}:
        return "lexical_budget_exhausted"
    if decision in ESCALATE:
        return decision
    return "lexical_budget_exhausted"


def _citation_union(conn: sqlite3.Connection, request: dict[str, Any], ordered: list[_Identity]) -> list[str]:
    found: list[str] = []
    for identity in ordered:
        found.extend(_citations(conn, request, identity))
    return sorted(set(found))


def _recheck_citations(
    conn: sqlite3.Connection,
    request: dict[str, Any],
    ordered: list[_Identity],
    citation_ids: list[str],
) -> None:
    again = _citation_union(conn, request, ordered)
    require_exact_citation_ids(citation_ids, again)


def _citations(conn: sqlite3.Connection, request: dict[str, Any], identity: _Identity) -> list[str]:
    workspace_id = request["workspace_id"]
    principal_id = request["principal_id"]
    if identity.provenance in {"user_stated", "model_proposed"}:
        extra = conn.execute(
            "SELECT citation_id FROM memory_source_binding_citation WHERE source_binding_id=?",
            (identity.source_binding_id,),
        ).fetchall()
        if extra:
            raise ContractError("non-grounded provenance contributed a citation")
        return []
    if identity.contract == "pdx_local_memory_record_v1":
        row = conn.execute(
            """
            SELECT m.source_citation_id
            FROM memory_record m
            JOIN citation c ON c.citation_id=m.source_citation_id AND c.workspace_id=m.workspace_id
            JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                 AND a.principal_id=m.principal_id AND a.can_read=1
            WHERE m.memory_id=? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
            """,
            (identity.target_id, workspace_id, principal_id),
        ).fetchone()
        if row is None:
            raise ContractError("citation acl drifted")
        return [row["source_citation_id"]]
    if identity.contract == "pdx_local_memory_record_v2":
        rows = conn.execute(
            """
            SELECT x.citation_id
            FROM memory_source_binding b
            JOIN memory_source_binding_citation x ON x.source_binding_id=b.source_binding_id
            JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=b.workspace_id
            JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                 AND a.principal_id=b.principal_id AND a.can_read=1
            WHERE b.source_binding_id=? AND b.workspace_id=? AND b.principal_id=?
                  AND b.provenance_category='document_grounded'
            ORDER BY x.citation_id
            """,
            (identity.source_binding_id, workspace_id, principal_id),
        ).fetchall()
        expected = conn.execute(
            "SELECT citation_id FROM memory_source_binding_citation WHERE source_binding_id=? ORDER BY citation_id",
            (identity.source_binding_id,),
        ).fetchall()
        if not rows or len(rows) != len(expected):
            raise ContractError("citation acl drifted")
        return [row["citation_id"] for row in rows]
    rows = conn.execute(
        """
        SELECT x.citation_id
        FROM canonical_knowledge_version_citation x
        JOIN canonical_knowledge_version v ON v.version_id=x.version_id
        JOIN canonical_knowledge k ON k.canonical_knowledge_id=v.canonical_knowledge_id
             AND k.current_version_id=v.version_id
        JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=k.workspace_id
        JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
             AND a.principal_id=? AND a.can_read=1
        WHERE x.version_id=? AND k.workspace_id=? AND k.status='active'
        ORDER BY x.citation_id
        """,
        (principal_id, identity.target_version_id, workspace_id),
    ).fetchall()
    expected = conn.execute(
        "SELECT citation_id FROM canonical_knowledge_version_citation WHERE version_id=? ORDER BY citation_id",
        (identity.target_version_id,),
    ).fetchall()
    if not rows or len(rows) != len(expected):
        raise ContractError("citation acl drifted")
    return [row["citation_id"] for row in rows]


def _identity_from_row(layer: str, row: sqlite3.Row) -> _Identity:
    return _Identity(
        profile=layer,
        contract=row["contract"],
        target_id=row["target_id"],
        target_version_id=row["target_version_id"],
        content_sha256=row["content_sha256"],
        content=row["content"],
        source_binding_id=row["source_binding_id"],
        provenance=row["provenance"],
        from_lexical=True,
        lexical_score=_finite(-float(row["lexical_rank"])),
    )


def _identity_from_hit(conn: sqlite3.Connection, request: dict[str, Any], hit: Mapping[str, Any]) -> _Identity:
    contract = str(hit["source_contract_version"])
    target_id = str(hit["target_id"])
    version_id = hit["target_version_id"]
    workspace_id = request["workspace_id"]
    principal_id = request["principal_id"]
    layer = request["selected_memory_layer"]
    if layer == "l2" and contract == "pdx_local_memory_record_v1":
        row = conn.execute(
            """
            SELECT content, content_sha256 FROM memory_record
            WHERE memory_id=? AND workspace_id=? AND principal_id=? AND status='active'
            """,
            (target_id, workspace_id, principal_id),
        ).fetchone()
        provenance, binding = "document_grounded", None
    elif layer == "l2" and contract == "pdx_local_memory_record_v2":
        row = conn.execute(
            """
            SELECT m.content, m.content_sha256, b.source_binding_id, b.provenance_category
            FROM memory_record_v2 m
            JOIN memory_source_binding b ON b.source_binding_id=m.source_binding_id
            WHERE m.memory_id=? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
            """,
            (target_id, workspace_id, principal_id),
        ).fetchone()
        provenance = None if row is None else row["provenance_category"]
        binding = None if row is None else row["source_binding_id"]
    elif layer == "l3" and contract == "pdx_local_canonical_knowledge_version_v1":
        row = conn.execute(
            """
            SELECT v.content, v.content_sha256
            FROM canonical_knowledge k
            JOIN canonical_knowledge_version v ON v.version_id=k.current_version_id
            WHERE k.canonical_knowledge_id=? AND v.version_id=? AND k.workspace_id=? AND k.status='active'
            """,
            (target_id, version_id, workspace_id),
        ).fetchone()
        provenance, binding = "document_grounded", None
    else:
        raise ContractError("snapshot identity is outside the selected layer")
    if row is None or provenance is None:
        raise ContractError("snapshot identity drifted")
    return _Identity(
        profile=layer,
        contract=contract,
        target_id=target_id,
        target_version_id=None if version_id is None else str(version_id),
        content_sha256=row["content_sha256"],
        content=row["content"],
        source_binding_id=binding,
        provenance=provenance,
        from_lexical=False,
    )


def _lexical_rows(
    conn: sqlite3.Connection,
    *,
    layer: str,
    workspace_id: str,
    principal_id: str,
    fts_query: str,
    limit: int,
) -> list[sqlite3.Row]:
    if layer == "l2":
        return conn.execute(
            """
            SELECT * FROM (
              SELECT 'pdx_local_memory_record_v1' AS contract, m.memory_id AS target_id,
                     NULL AS target_version_id, m.content_sha256, m.content,
                     NULL AS source_binding_id, 'document_grounded' AS provenance,
                     bm25(governed_l2_fts) AS lexical_rank
              FROM governed_l2_fts f
              JOIN memory_record m ON f.content_contract_version='pdx_local_memory_record_v1'
                   AND m.memory_id=f.target_id
              JOIN citation c ON c.citation_id=m.source_citation_id AND c.workspace_id=m.workspace_id
              JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                   AND a.principal_id=m.principal_id AND a.can_read=1
              WHERE governed_l2_fts MATCH ? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
              UNION ALL
              SELECT 'pdx_local_memory_record_v2', m.memory_id, NULL, m.content_sha256, m.content,
                     b.source_binding_id, b.provenance_category, bm25(governed_l2_fts)
              FROM governed_l2_fts f
              JOIN memory_record_v2 m ON f.content_contract_version='pdx_local_memory_record_v2'
                   AND m.memory_id=f.target_id
              JOIN memory_source_binding b ON b.source_binding_id=m.source_binding_id
                   AND b.memory_id=m.memory_id AND b.workspace_id=m.workspace_id
                   AND b.principal_id=m.principal_id
              WHERE governed_l2_fts MATCH ? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
                    AND ((b.provenance_category='document_grounded'
                          AND EXISTS (SELECT 1 FROM memory_source_binding_citation x
                                      WHERE x.source_binding_id=b.source_binding_id)
                          AND NOT EXISTS (
                            SELECT 1 FROM memory_source_binding_citation x
                            LEFT JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=b.workspace_id
                            LEFT JOIN file_acl a ON a.file_record_id=c.file_record_id
                                 AND a.workspace_id=c.workspace_id AND a.principal_id=b.principal_id
                                 AND a.can_read=1
                            WHERE x.source_binding_id=b.source_binding_id
                                  AND (c.citation_id IS NULL OR a.file_record_id IS NULL)))
                         OR (b.provenance_category IN ('user_stated','model_proposed')
                             AND NOT EXISTS (SELECT 1 FROM memory_source_binding_citation x
                                             WHERE x.source_binding_id=b.source_binding_id)))
            ) ORDER BY lexical_rank, contract, target_id LIMIT ?
            """,
            (fts_query, workspace_id, principal_id, fts_query, workspace_id, principal_id, limit),
        ).fetchall()
    return conn.execute(
        """
        SELECT 'pdx_local_canonical_knowledge_version_v1' AS contract,
               k.canonical_knowledge_id AS target_id, v.version_id AS target_version_id,
               v.content_sha256, v.content, NULL AS source_binding_id,
               'document_grounded' AS provenance, bm25(governed_l3_fts) AS lexical_rank
        FROM governed_l3_fts f
        JOIN canonical_knowledge_version v ON v.version_id=f.version_id
             AND v.canonical_knowledge_id=f.canonical_knowledge_id
        JOIN canonical_knowledge k ON k.canonical_knowledge_id=v.canonical_knowledge_id
             AND k.current_version_id=v.version_id
        WHERE governed_l3_fts MATCH ? AND k.workspace_id=? AND k.status='active'
              AND EXISTS (SELECT 1 FROM canonical_knowledge_version_citation x WHERE x.version_id=v.version_id)
              AND NOT EXISTS (
                SELECT 1 FROM canonical_knowledge_version_citation x
                LEFT JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=k.workspace_id
                LEFT JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                     AND a.principal_id=? AND a.can_read=1
                WHERE x.version_id=v.version_id AND (c.citation_id IS NULL OR a.file_record_id IS NULL))
        ORDER BY lexical_rank, k.canonical_knowledge_id, v.version_id LIMIT ?
        """,
        (fts_query, workspace_id, principal_id, limit),
    ).fetchall()


def _validate_request(request: dict[str, Any]) -> None:
    _validate(REQUEST_SCHEMA, request)
    if request.get("allow_rerank", False):
        raise ContractError("rerank is not authorized")
    if request["selected_memory_layer"] not in {"l2", "l3"}:
        raise ContractError("selected layer must be l2 or l3")
    if request["allow_document_expansion"] or request["source_root_ids"]:
        raise ContractError("document expansion is not authorized")
    limits = request["aggregate_limits"]
    if limits["document_files"] or limits["document_blocks"]:
        raise ContractError("document budget is not authorized")
    if (request["policy_id"], request["policy_version"], request["policy_sha256"]) != (
        "lexical-first",
        "1",
        POLICY_SHA256,
    ):
        raise ContractError("lexical-first policy digest mismatch")


def _tokens(query: str) -> list[str]:
    terms = re.findall(r"[\w]+", query, flags=re.UNICODE)[:32]
    if not terms:
        raise ContractError("orchestration query has no searchable terms")
    return terms


def _fts_query(tokens: list[str]) -> str:
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in tokens)


def _coverage(content: str, tokens: list[str]) -> float:
    present = {word.casefold() for word in re.findall(r"[\w]+", content, flags=re.UNICODE)}
    return sum(token.casefold() in present for token in tokens) / len(tokens)


def _finite(value: float) -> float:
    if value == 0:
        value = 0.0
    if not math.isfinite(value):
        raise ContractError("score is not finite")
    return value


def _identity_bytes(identity: _Identity) -> int:
    return len(canonical_json(identity.ref()).encode("utf-8"))


def _ids_sha(identities: list[_Identity]) -> str:
    payload = [
        {"target_id": item.target_id, "target_version_id": item.target_version_id}
        for item in sorted(identities, key=lambda item: item.key())
    ]
    return canonical_sha256(payload)


def _stage_counters(candidates: int, results: int, returned_bytes: int, elapsed_ms: int) -> dict[str, int]:
    return {
        "candidates": candidates,
        "results": results,
        "document_files": 0,
        "document_blocks": 0,
        "returned_bytes": returned_bytes,
        "elapsed_ms": elapsed_ms,
    }


def _require_within(consumed: Mapping[str, int], limits: Mapping[str, int]) -> None:
    for key, value in consumed.items():
        if value > limits[key]:
            raise ContractError("aggregate budget exceeded")


def _validate(path: Path, instance: dict[str, Any]) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ContractError(errors[0].message)


def _insert_stage(conn: sqlite3.Connection, envelope: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO retrieval_stage_receipt VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            envelope["stage_receipt_id"],
            envelope["workspace_id"],
            envelope["principal_id"],
            envelope["request_id"],
            envelope["query_id"],
            envelope["stage"],
            envelope["disposition"],
            canonical_json(envelope),
            canonical_sha256(envelope),
            envelope["created_at"],
        ),
    )


def _insert_terminal(conn: sqlite3.Connection, envelope: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO retrieval_orchestration_receipt VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            envelope["receipt_id"],
            envelope["workspace_id"],
            envelope["principal_id"],
            envelope["request_id"],
            envelope["query_id"],
            canonical_json(envelope),
            canonical_sha256(envelope),
            envelope["created_at"],
        ),
    )


def _elapsed(started: float, finished: float, limit: int) -> int:
    return min(limit, max(0, int((finished - started) * 1000)))


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
