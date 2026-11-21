"""Gate 4C-4 document expansion plus Gate 4C-5 rerank. One caller transaction."""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .catalog_snapshot import retrieve_in_snapshot
from .retrieval_orchestration import (
    ESCALATE,
    POLICY_SHA256,
    REQUEST_SCHEMA,
    SQL_009,
    STAGE_SCHEMA,
    TERMINAL_SCHEMA,
    _Identity,
    _citation_union,
    _elapsed,
    _identity_bytes,
    _ids_sha,
    _insert_stage,
    _insert_terminal,
    _lexical,
    _needs_vector,
    _now,
    _r1_decision,
    _recheck_citations,
    _require_within,
    _finite,
    _stage_counters,
    _skipped_reason,
    _stage_envelope,
    _terminal_reason,
    _tokens,
    _validate,
    _vector,
    apply_retrieval_orchestration_migration,
    canonical_sha256,
    order_key,
)
from .validation import ContractError

ROOT_SQL = SQL_009.parent / "010_catalog_coverage_disclosure.sql"
RERANK_K = 60
ENTER_CATALOG = {
    "candidate_limit",
    "vector_not_authorized",
    "vector_generation_unavailable",
    "no_authorized_candidates",
}
ENTRY_REASON = {
    "not_authorized": "document_not_authorized",
    "not_needed": "document_not_needed",
    "no_budget": "document_no_budget",
    "scope_rejected": "document_scope_rejected",
}


def orchestrate_document_expansion(
    conn: sqlite3.Connection,
    *,
    request: Mapping[str, Any],
    query_text: str,
    query_vector: Sequence[float] | None = None,
    store: Any = None,
    monotonic: Callable[[], float] | None = None,
    now: Callable[[], str] | None = None,
    new_id: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Run lexical-first memory, then Catalog, and publish one orchestration receipt."""
    clock = monotonic or time.monotonic
    stamp = now or _now
    mint = new_id or (lambda: str(uuid.uuid4()))
    if conn.in_transaction:
        raise ContractError("orchestration requires an idle connection")
    body = dict(request)
    _validate_request(body)
    tokens = _tokens(query_text)
    apply_retrieval_orchestration_migration(conn)
    conn.executescript(ROOT_SQL.read_text(encoding="utf-8"))
    if conn.row_factory is not sqlite3.Row:
        conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        receipt = _run(
            conn,
            request=body,
            tokens=tokens,
            query_text=query_text,
            query_vector=query_vector,
            store=store,
            clock=clock,
            stamp=stamp,
            mint=mint,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return receipt


def _validate_request(request: dict[str, Any]) -> None:
    _validate(REQUEST_SCHEMA, request)
    if (request["policy_id"], request["policy_version"], request["policy_sha256"]) != (
        "lexical-first",
        "1",
        POLICY_SHA256,
    ):
        raise ContractError("lexical-first policy digest mismatch")


def _run(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    tokens: list[str],
    query_text: str,
    query_vector: Sequence[float] | None,
    store: Any,
    clock: Callable[[], float],
    stamp: Callable[[], str],
    mint: Callable[[], str],
) -> dict[str, Any]:
    limits = request["aggregate_limits"]
    started = clock()
    deadline = started + limits["elapsed_ms"] / 1000.0
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
    memory_reason = _terminal_reason(
        decision=decision,
        wanted=wanted,
        allow_vector=bool(request["allow_vector_escalation"]),
        admitted=admitted,
        limits=limits,
        flags=flags,
        snapshot=snapshot,
    )
    memory_elapsed = min(limits["elapsed_ms"], r1_elapsed + r2_elapsed)
    memory_bytes = sum(_identity_bytes(item) for item in admitted)
    expansion, terminal_reason, catalog = _expand(
        conn,
        request=request,
        query_text=query_text,
        memory_reason=memory_reason,
        admitted=admitted,
        memory_bytes=memory_bytes,
        memory_elapsed=memory_elapsed,
        deadline=deadline,
        clock=clock,
    )
    ordered = sorted(admitted, key=order_key)
    document_identities = catalog["identities"] if catalog else []
    combined = sorted([*ordered, *document_identities], key=order_key)
    allow_rerank = bool(request.get("allow_rerank", False))
    r3_mark = clock()
    if allow_rerank:
        combined = _permute(combined, deadline, clock)
        _ensure_rerank_deadline(deadline, clock)
        r3_elapsed = _elapsed(r3_mark, clock(), limits["elapsed_ms"])
    else:
        r3_elapsed = 0
    for identity in ordered:
        identity.lexical_score = None
        identity.vector_score = None
    citation_ids = _citation_union(conn, request, ordered)
    _recheck_citations(conn, request, ordered, citation_ids)
    if catalog is not None:
        citation_ids = sorted(set(citation_ids).union(catalog["citation_ids"]))
    created = stamp()
    lexical_rows = [item for item in ordered if item.from_lexical]
    lexical_bytes = sum(_identity_bytes(item) for item in lexical_rows)
    vector_bytes = sum(_identity_bytes(item) for item in ordered if not item.from_lexical)
    r2_completed = (
        snapshot is not None
        and snapshot.generation_id is not None
        and snapshot.disposition in {"results", "no_authorized_candidates"}
    )
    r1 = _stage_envelope(
        request=request,
        stage="r1_lexical",
        disposition="completed",
        entry_reason="explicit_memory_layer",
        limits=_stage_counters(limits["lexical_candidates"], limits["results"], limits["returned_bytes"], limits["elapsed_ms"]),
        consumed=_stage_counters(len(lexical_rows), len(lexical_rows), lexical_bytes, r1_elapsed),
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
        disposition="completed" if r2_completed else "skipped",
        entry_reason=decision if r2_completed else _skipped_reason(memory_reason, decision),
        limits=_stage_counters(limits["vector_candidates"], limits["results"], limits["returned_bytes"], limits["elapsed_ms"]),
        consumed=_stage_counters(vector_admitted, len(vector_only), vector_bytes, r2_elapsed),
        input_count=r2_input,
        output_count=vector_admitted,
        identities=vector_ids,
        generation_id=None if snapshot is None or not r2_completed else snapshot.generation_id,
        generation_sha=None if snapshot is None or not r2_completed else snapshot.image_sha256,
        created=created,
        mint=mint,
    )
    document_stage = _document_stage(
        request=request,
        expansion=expansion,
        catalog=catalog,
        created=created,
        mint=mint,
    )
    r3 = _r3_stage(
        request=request,
        allow_rerank=allow_rerank,
        combined=combined,
        elapsed=r3_elapsed,
        created=created,
        mint=mint,
    )
    stages = [r1, r2, document_stage, r3]
    for stage in stages:
        _validate(STAGE_SCHEMA, stage)
    document_bytes = 0 if catalog is None else catalog["bytes"]
    aggregate_consumed = {
        "lexical_candidates": len(lexical_rows),
        "vector_candidates": vector_admitted,
        "fused_candidates": len(ordered),
        "results": len(combined),
        "document_files": 0 if catalog is None else catalog["files"],
        "document_blocks": 0 if catalog is None else len(document_identities),
        "returned_bytes": lexical_bytes + vector_bytes + document_bytes,
        "elapsed_ms": min(limits["elapsed_ms"], memory_elapsed + (0 if catalog is None else catalog["elapsed_ms"])),
    }
    _require_within(aggregate_consumed, limits)
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
        "allow_document_expansion": request["allow_document_expansion"],
        "stage_receipt_ids": [stage["stage_receipt_id"] for stage in stages],
        "stage_receipt_sha256s": [canonical_sha256(stage) for stage in stages],
        "aggregate_limits": limits,
        "aggregate_consumed": aggregate_consumed,
        "terminal_reason": terminal_reason,
        "result_refs": [item.ref() for item in combined],
        "citation_ids": citation_ids,
        "document_expansion": expansion,
        "catalog_receipt_id": None if catalog is None else catalog["receipt_id"],
        "catalog_receipt_sha256": None if catalog is None else catalog["receipt_sha256"],
        "created_at": created,
    }
    _validate(TERMINAL_SCHEMA, terminal)
    _ensure_rerank_deadline(deadline, clock)
    try:
        for stage in stages:
            _insert_stage(conn, stage)
        _insert_terminal(conn, terminal)
        for ordinal, stage in enumerate(stages):
            conn.execute(
                "INSERT INTO retrieval_orchestration_stage_link VALUES (?,?,?,?)",
                (terminal["receipt_id"], stage["stage_receipt_id"], ordinal, canonical_sha256(stage)),
            )
        conn.execute(
            "INSERT INTO retrieval_orchestration_query_id VALUES (?,?,?,?)",
            (request["workspace_id"], request["principal_id"], request["query_id"], terminal["receipt_id"]),
        )
    except sqlite3.IntegrityError as error:
        raise ContractError("query id already consumed") from error
    return terminal


def _version(identity: _Identity) -> str:
    return "" if identity.target_version_id is None else identity.target_version_id


def _ensure_rerank_deadline(deadline: float, clock: Callable[[], float]) -> None:
    if clock() >= deadline:
        raise ContractError("rerank deadline passed")


def _channel(identities: list[_Identity], score_name: str) -> list[_Identity]:
    present: list[tuple[float, _Identity]] = []
    for item in identities:
        score = getattr(item, score_name)
        if score is None:
            continue
        present.append((_finite(float(score)), item))
    present.sort(key=lambda pair: (-pair[0], pair[1].target_id, _version(pair[1])))
    return [item for _score, item in present]


def _identity_pair(item: _Identity) -> tuple[str, str]:
    return (item.target_id, _version(item))


def _permute(
    identities: list[_Identity],
    deadline: float,
    clock: Callable[[], float],
) -> list[_Identity]:
    _ensure_rerank_deadline(deadline, clock)
    lexical = {
        _identity_pair(item): rank
        for rank, item in enumerate(_channel(identities, "lexical_score"), start=1)
    }
    vector = {
        _identity_pair(item): rank
        for rank, item in enumerate(_channel(identities, "vector_score"), start=1)
    }

    def score(item: _Identity) -> float:
        total = 0.0
        key = _identity_pair(item)
        if key in lexical:
            total += 1.0 / (RERANK_K + lexical[key])
        if key in vector:
            total += 1.0 / (RERANK_K + vector[key])
        return total

    ordered = sorted(
        identities,
        key=lambda item: (1 if score(item) == 0.0 else 0, -score(item), item.target_id, _version(item)),
    )
    if sorted(map(_identity_pair, identities)) != sorted(map(_identity_pair, ordered)):
        raise ContractError("rerank identity set changed")
    return ordered


def _rerank_ids_sha(identities: list[_Identity]) -> str:
    payload = [
        {"target_id": item.target_id, "target_version_id": item.target_version_id}
        for item in sorted(identities, key=_identity_pair)
    ]
    return canonical_sha256(payload)


def _r3_stage(
    *,
    request: dict[str, Any],
    allow_rerank: bool,
    combined: list[_Identity],
    elapsed: int,
    created: str,
    mint: Callable[[], str],
) -> dict[str, Any]:
    limits = request["aggregate_limits"]
    if allow_rerank:
        count = len(combined)
        identities = combined
        stage_limits = _stage_counters(count, count, limits["returned_bytes"], limits["elapsed_ms"])
        consumed = _stage_counters(count, count, sum(_identity_bytes(item) for item in combined), elapsed)
        disposition = "completed"
        entry_reason = "authorized_rerank"
    else:
        count = 0
        identities = []
        stage_limits = _stage_counters(0, 0, 0, 0)
        consumed = _stage_counters(0, 0, 0, 0)
        disposition = "skipped"
        entry_reason = "rerank_not_configured"
    stage = _stage_envelope(
        request=request,
        stage="r3_rerank",
        disposition=disposition,
        entry_reason=entry_reason,
        limits=stage_limits,
        consumed=consumed,
        input_count=count,
        output_count=count,
        identities=identities,
        generation_id=None,
        generation_sha=None,
        created=created,
        mint=mint,
    )
    stage["profile"] = None
    stage["authorized_ids_sha256"] = _rerank_ids_sha(identities)
    return stage


def _expand(
    conn: sqlite3.Connection,
    *,
    request: dict[str, Any],
    query_text: str,
    memory_reason: str,
    admitted: list[_Identity],
    memory_bytes: int,
    memory_elapsed: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, str, dict[str, Any] | None]:
    limits = request["aggregate_limits"]
    allow = bool(request["allow_document_expansion"])
    if not allow:
        expansion = "not_needed" if memory_reason in {"lexical_sufficient", "vector_sufficient"} else "not_authorized"
        return expansion, memory_reason, None
    if memory_reason in {"lexical_sufficient", "vector_sufficient"}:
        return "not_needed", memory_reason, None
    result_remaining = limits["results"] - len(admitted)
    byte_remaining = limits["returned_bytes"] - memory_bytes
    elapsed_remaining = limits["elapsed_ms"] - memory_elapsed
    if memory_reason in {"time_limit", "result_limit", "byte_limit"} or limits["document_files"] == 0 or limits["document_blocks"] == 0 or result_remaining <= 0 or byte_remaining < 1 or elapsed_remaining < 1:
        return "no_budget", memory_reason, None
    roots = list(request["source_root_ids"])
    if len(roots) != 1 or not _root_allowed(conn, request["workspace_id"], roots[0]):
        return "scope_rejected", memory_reason, None
    if memory_reason not in ENTER_CATALOG:
        return "not_authorized", memory_reason, None
    started = clock()
    found = retrieve_in_snapshot(
        conn,
        workspace_id=request["workspace_id"],
        principal_id=request["principal_id"],
        source_root_id=roots[0],
        query=query_text,
        limits={
            "metadata_candidates": 100,
            "lexical_candidates": 30,
            "opened_files": limits["document_files"],
            "opened_blocks": min(limits["document_blocks"], result_remaining),
            "returned_bytes": byte_remaining,
            "elapsed_ms": elapsed_remaining,
        },
        deadline=deadline,
        clock=clock,
    )
    identities, citation_ids, files, used_bytes, refused = _admit(
        found["results"],
        result_remaining=result_remaining,
        byte_remaining=byte_remaining,
    )
    reason = _after_catalog(
        memory_reason=memory_reason,
        receipt=found["receipt"],
        disclosure=found["disclosure"],
        admitted=len(identities),
        refused=refused,
    )
    return "completed", reason, {
        "identities": identities,
        "citation_ids": citation_ids,
        "files": files,
        "bytes": used_bytes,
        "elapsed_ms": max(0, int((clock() - started) * 1000)),
        "receipt_id": found["receipt"]["receipt_id"],
        "receipt_sha256": found["disclosure"]["catalog_receipt_sha256"],
        "disclosure_id": found["disclosure_id"],
        "disclosure_sha256": found["disclosure_sha256"],
        "input_count": len(found["results"]),
    }


def _root_allowed(conn: sqlite3.Connection, workspace_id: str, source_root_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM source_root WHERE source_root_id=? AND workspace_id=? AND enabled=1",
        (source_root_id, workspace_id),
    ).fetchone()
    return row is not None


def _admit(
    results: list[dict[str, Any]],
    *,
    result_remaining: int,
    byte_remaining: int,
) -> tuple[list[_Identity], list[str], int, int, str | None]:
    identities: list[_Identity] = []
    citation_ids: list[str] = []
    files: set[str] = set()
    used = 0
    refused: str | None = None
    seen: dict[tuple[str, str, str], _Identity] = {}
    for item in results:
        citation = item["citation"]
        key = (citation["block_instance_id"], citation["source_version_id"], citation["quoted_text_sha256"])
        existing = seen.get(key)
        if existing is not None:
            citation_ids.append(citation["citation_id"])
            continue
        identity = _Identity(
            profile="document_block",
            contract="pdx_local_citation_v1",
            target_id=citation["block_instance_id"],
            target_version_id=citation["source_version_id"],
            content_sha256=citation["quoted_text_sha256"],
            content=item["text"],
            source_binding_id=None,
            provenance="document_grounded",
            from_lexical=False,
        )
        size = _identity_bytes(identity)
        if len(identities) >= result_remaining:
            refused = "result_limit"
            break
        if used + size > byte_remaining:
            refused = "byte_limit"
            break
        identities.append(identity)
        seen[key] = identity
        citation_ids.append(citation["citation_id"])
        files.add(str(citation["file_record_id"]))
        used += size
    return identities, citation_ids, len(files), used, refused


def _after_catalog(
    *,
    memory_reason: str,
    receipt: dict[str, Any],
    disclosure: dict[str, Any],
    admitted: int,
    refused: str | None,
) -> str:
    stop = receipt["execution"]["stop_reason"]
    sources = disclosure["sources"]
    if refused == "result_limit" or stop == "result_limit":
        return "result_limit"
    if refused == "byte_limit" or stop == "byte_limit":
        return "byte_limit"
    if stop in {"file_limit", "block_limit"}:
        return "source_coverage_insufficient"
    if any(row["coverage_disposition"] != "complete" for row in sources):
        return "source_coverage_insufficient"
    if stop in {"metadata_candidate_limit", "lexical_candidate_limit"}:
        return "candidate_limit"
    if sources and admitted >= 1 and all(row["coverage_disposition"] == "complete" for row in sources):
        return "document_sufficient"
    return memory_reason


def _document_stage(
    *,
    request: dict[str, Any],
    expansion: str,
    catalog: dict[str, Any] | None,
    created: str,
    mint: Callable[[], str],
) -> dict[str, Any]:
    limits = request["aggregate_limits"]
    completed = catalog is not None
    consumed_elapsed = 0 if catalog is None else min(catalog["elapsed_ms"], limits["elapsed_ms"])
    return {
        "schema_version": "pdx_local_retrieval_stage_receipt_v1",
        "stage_receipt_id": mint(),
        "request_id": request["request_id"],
        "query_id": request["query_id"],
        "workspace_id": request["workspace_id"],
        "principal_id": request["principal_id"],
        "stage": "document_catalog",
        "disposition": "completed" if completed else "skipped",
        "entry_reason": "authorized_document_expansion" if completed else ENTRY_REASON[expansion],
        "profile": None,
        "generation_id": None,
        "generation_sha256": None,
        "limits": {
            "candidates": 100 if completed else 0,
            "results": limits["results"],
            "document_files": limits["document_files"],
            "document_blocks": limits["document_blocks"],
            "returned_bytes": limits["returned_bytes"],
            "elapsed_ms": limits["elapsed_ms"],
        },
        "consumed": {
            "candidates": 0 if catalog is None else catalog["input_count"],
            "results": 0 if catalog is None else len(catalog["identities"]),
            "document_files": 0 if catalog is None else catalog["files"],
            "document_blocks": 0 if catalog is None else len(catalog["identities"]),
            "returned_bytes": 0 if catalog is None else catalog["bytes"],
            "elapsed_ms": consumed_elapsed,
        },
        "input_candidate_count": 0 if catalog is None else catalog["input_count"],
        "output_candidate_count": 0 if catalog is None else len(catalog["identities"]),
        "authorized_ids_sha256": _ids_sha([] if catalog is None else catalog["identities"]),
        "subreceipt_id": None if catalog is None else catalog["disclosure_id"],
        "subreceipt_sha256": None if catalog is None else catalog["disclosure_sha256"],
        "created_at": created,
    }
