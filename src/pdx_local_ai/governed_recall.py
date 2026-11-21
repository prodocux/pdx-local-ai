"""Gate 4B-3 explicit, bounded lexical recall for published L2 or L3 memory."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .validation import ContractError
from .paths import get_root

SCHEMA = (
    get_root()
    / "schemas"
    / "pdx_local_governed_recall_receipt_v2.schema.json"
)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fts_query(query: str) -> str:
    terms = re.findall(r"[\w]+", query, flags=re.UNICODE)
    if not terms:
        raise ContractError("governed recall query has no searchable terms")
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def _validate_receipt(
    receipt: dict[str, Any], materialized: list[dict[str, Any]] | None = None
) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            receipt
        ),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ContractError(f"invalid governed recall receipt: {errors[0].message}")
    layer = receipt["requested_layers"][0]
    if receipt["requested_layers"] != [layer] or receipt["searched_layers"] != [layer]:
        raise ContractError("governed recall must search exactly one requested layer")
    accounting = receipt["per_layer"].get(layer)
    if set(receipt["per_layer"]) != {layer} or accounting is None:
        raise ContractError("governed recall layer accounting mismatch")
    if accounting["limits"] != receipt["aggregate_limits"]:
        raise ContractError("governed recall limits do not aggregate")
    if accounting["consumed"] != receipt["aggregate_consumed"]:
        raise ContractError("governed recall consumption does not aggregate")
    limits, consumed = receipt["aggregate_limits"], receipt["aggregate_consumed"]
    if any(consumed[key] > limits[key] for key in limits):
        raise ContractError("governed recall budget exceeded")
    if receipt["result_count"] != len(receipt["results"]):
        raise ContractError("governed recall result count mismatch")
    if consumed["results"] != receipt["result_count"]:
        raise ContractError("governed recall result consumption mismatch")
    reason = receipt["stop_reason"]
    if reason == "no_candidates" and any(
        consumed[key] for key in ("candidates", "results", "returned_bytes")
    ):
        raise ContractError("invalid no-candidates receipt")
    if reason == "candidate_limit" and consumed["candidates"] != limits["candidates"]:
        raise ContractError("invalid candidate-limit receipt")
    if reason == "result_limit" and consumed["results"] != limits["results"]:
        raise ContractError("invalid result-limit receipt")
    if reason == "time_limit" and consumed["elapsed_ms"] != limits["elapsed_ms"]:
        raise ContractError("invalid time-limit receipt")
    if materialized is not None:
        if [item["metadata"] for item in materialized] != receipt["results"]:
            raise ContractError("governed recall metadata mismatch")
        actual_bytes = sum(
            len(item["content"].encode("utf-8")) for item in materialized
        )
        if actual_bytes != consumed["returned_bytes"]:
            raise ContractError("governed recall byte consumption mismatch")


def _candidate_rows(
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
              SELECT f.content_contract_version,f.target_id,NULL AS target_version_id,
                     bm25(governed_l2_fts) AS lexical_rank,m.updated_at
              FROM governed_l2_fts f
              JOIN memory_record m ON f.content_contract_version='pdx_local_memory_record_v1'
                   AND m.memory_id=f.target_id
              JOIN citation c ON c.citation_id=m.source_citation_id
                   AND c.workspace_id=m.workspace_id
              JOIN file_acl a ON a.file_record_id=c.file_record_id
                   AND a.workspace_id=c.workspace_id AND a.principal_id=m.principal_id
                   AND a.can_read=1
              WHERE governed_l2_fts MATCH ? AND m.workspace_id=? AND m.principal_id=?
                    AND m.status='active'
              UNION ALL
              SELECT f.content_contract_version,f.target_id,NULL AS target_version_id,
                     bm25(governed_l2_fts) AS lexical_rank,m.updated_at
              FROM governed_l2_fts f
              JOIN memory_record_v2 m ON f.content_contract_version='pdx_local_memory_record_v2'
                   AND m.memory_id=f.target_id
              JOIN memory_source_binding b ON b.source_binding_id=m.source_binding_id
                   AND b.memory_id=m.memory_id AND b.workspace_id=m.workspace_id
                   AND b.principal_id=m.principal_id
              WHERE governed_l2_fts MATCH ? AND m.workspace_id=? AND m.principal_id=?
                    AND m.status='active'
                    AND ((b.provenance_category='document_grounded'
                          AND EXISTS (SELECT 1 FROM memory_source_binding_citation x
                                      WHERE x.source_binding_id=b.source_binding_id)
                          AND NOT EXISTS (
                            SELECT 1 FROM memory_source_binding_citation x
                            LEFT JOIN citation c ON c.citation_id=x.citation_id
                                 AND c.workspace_id=b.workspace_id
                            LEFT JOIN file_acl a ON a.file_record_id=c.file_record_id
                                 AND a.workspace_id=c.workspace_id
                                 AND a.principal_id=b.principal_id AND a.can_read=1
                            WHERE x.source_binding_id=b.source_binding_id
                                  AND (c.citation_id IS NULL OR a.file_record_id IS NULL)))
                         OR (b.provenance_category IN ('user_stated','model_proposed')
                             AND NOT EXISTS (SELECT 1 FROM memory_source_binding_citation x
                                             WHERE x.source_binding_id=b.source_binding_id)))
            ) ORDER BY lexical_rank,content_contract_version,updated_at DESC,target_id LIMIT ?
            """,
            (
                fts_query,
                workspace_id,
                principal_id,
                fts_query,
                workspace_id,
                principal_id,
                limit,
            ),
        ).fetchall()
    return conn.execute(
        """
        SELECT 'pdx_local_canonical_knowledge_version_v1' AS content_contract_version,
               k.canonical_knowledge_id AS target_id,v.version_id AS target_version_id,
               bm25(governed_l3_fts) AS lexical_rank,k.updated_at
        FROM governed_l3_fts f
        JOIN canonical_knowledge_version v ON v.version_id=f.version_id
             AND v.canonical_knowledge_id=f.canonical_knowledge_id
        JOIN canonical_knowledge k ON k.canonical_knowledge_id=v.canonical_knowledge_id
             AND k.current_version_id=v.version_id
        WHERE governed_l3_fts MATCH ? AND k.workspace_id=? AND k.status='active'
              AND EXISTS (SELECT 1 FROM canonical_knowledge_version_citation x
                          WHERE x.version_id=v.version_id)
              AND NOT EXISTS (
                SELECT 1 FROM canonical_knowledge_version_citation x
                LEFT JOIN citation c ON c.citation_id=x.citation_id
                     AND c.workspace_id=k.workspace_id
                LEFT JOIN file_acl a ON a.file_record_id=c.file_record_id
                     AND a.workspace_id=c.workspace_id AND a.principal_id=? AND a.can_read=1
                WHERE x.version_id=v.version_id
                      AND (c.citation_id IS NULL OR a.file_record_id IS NULL))
        ORDER BY lexical_rank,k.updated_at DESC,k.canonical_knowledge_id,v.version_id LIMIT ?
        """,
        (fts_query, workspace_id, principal_id, limit),
    ).fetchall()


def _materialize_l2(
    conn: sqlite3.Connection,
    candidate: sqlite3.Row,
    workspace_id: str,
    principal_id: str,
) -> dict[str, Any] | None:
    if candidate["content_contract_version"] == "pdx_local_memory_record_v1":
        row = conn.execute(
            """
            SELECT m.*,c.citation_id FROM memory_record m
            JOIN citation c ON c.citation_id=m.source_citation_id AND c.workspace_id=m.workspace_id
            JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                 AND a.principal_id=m.principal_id AND a.can_read=1
            WHERE m.memory_id=? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
            """,
            (candidate["target_id"], workspace_id, principal_id),
        ).fetchone()
        if row is None:
            return None
        metadata = {
            "layer": "l2",
            "content_contract_version": "pdx_local_memory_record_v1",
            "target_id": row["memory_id"],
            "target_version_id": None,
            "source_binding_id": None,
            "content_sha256": row["content_sha256"],
            "provenance_category": "document_grounded",
            "verification_status": "citation_verified",
            "citation_ids": [row["citation_id"]],
            "authority_id": row["principal_id"],
            "approval_decision_id": None,
            "state": "active",
        }
        return {"content": row["content"], "metadata": metadata}
    row = conn.execute(
        """
        SELECT m.*,b.provenance_category,b.verification_status,b.authority_id,b.decision_id
        FROM memory_record_v2 m JOIN memory_source_binding b ON b.source_binding_id=m.source_binding_id
             AND b.memory_id=m.memory_id AND b.workspace_id=m.workspace_id
             AND b.principal_id=m.principal_id
        WHERE m.memory_id=? AND m.workspace_id=? AND m.principal_id=? AND m.status='active'
        """,
        (candidate["target_id"], workspace_id, principal_id),
    ).fetchone()
    if row is None:
        return None
    citations = [
        item[0]
        for item in conn.execute(
            "SELECT citation_id FROM memory_source_binding_citation WHERE source_binding_id=? "
            "ORDER BY ordinal",
            (row["source_binding_id"],),
        ).fetchall()
    ]
    if row["provenance_category"] == "document_grounded":
        authorized = conn.execute(
            """
            SELECT COUNT(*) FROM memory_source_binding_citation x
            JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=?
            JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
                 AND a.principal_id=? AND a.can_read=1
            WHERE x.source_binding_id=?
            """,
            (workspace_id, principal_id, row["source_binding_id"]),
        ).fetchone()[0]
        if not citations or authorized != len(citations):
            return None
    elif citations:
        return None
    metadata = {
        "layer": "l2",
        "content_contract_version": "pdx_local_memory_record_v2",
        "target_id": row["memory_id"],
        "target_version_id": None,
        "source_binding_id": row["source_binding_id"],
        "content_sha256": row["content_sha256"],
        "provenance_category": row["provenance_category"],
        "verification_status": row["verification_status"],
        "citation_ids": citations,
        "authority_id": row["authority_id"],
        "approval_decision_id": row["decision_id"],
        "state": "active",
    }
    return {"content": row["content"], "metadata": metadata}


def _materialize_l3(
    conn: sqlite3.Connection,
    candidate: sqlite3.Row,
    workspace_id: str,
    principal_id: str,
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT k.canonical_knowledge_id,k.workspace_authority_id,v.*,
               r.decision_id AS approval_decision_id
        FROM canonical_knowledge k
        JOIN canonical_knowledge_version v ON v.canonical_knowledge_id=k.canonical_knowledge_id
             AND v.version_id=k.current_version_id
        JOIN l3_publication_receipt r ON r.receipt_id=v.publication_receipt_id
             AND r.target_id=k.canonical_knowledge_id AND r.target_version_id=v.version_id
        WHERE k.canonical_knowledge_id=? AND v.version_id=? AND k.workspace_id=? AND k.status='active'
        """,
        (candidate["target_id"], candidate["target_version_id"], workspace_id),
    ).fetchone()
    if row is None:
        return None
    citations = [
        item[0]
        for item in conn.execute(
            "SELECT citation_id FROM canonical_knowledge_version_citation WHERE version_id=? "
            "ORDER BY ordinal",
            (row["version_id"],),
        ).fetchall()
    ]
    authorized = conn.execute(
        """
        SELECT COUNT(*) FROM canonical_knowledge_version_citation x
        JOIN citation c ON c.citation_id=x.citation_id AND c.workspace_id=?
        JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id
             AND a.principal_id=? AND a.can_read=1
        WHERE x.version_id=?
        """,
        (workspace_id, principal_id, row["version_id"]),
    ).fetchone()[0]
    if not citations or authorized != len(citations):
        return None
    metadata = {
        "layer": "l3",
        "content_contract_version": "pdx_local_canonical_knowledge_version_v1",
        "target_id": row["canonical_knowledge_id"],
        "target_version_id": row["version_id"],
        "source_binding_id": None,
        "content_sha256": row["content_sha256"],
        "provenance_category": "document_grounded",
        "verification_status": "citation_verified",
        "citation_ids": citations,
        "authority_id": row["workspace_authority_id"],
        "approval_decision_id": row["approval_decision_id"],
        "state": "active",
    }
    return {"content": row["content"], "metadata": metadata}


def recall_governed_memory(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    principal_id: str,
    requested_layer: str,
    query: str,
    candidate_limit: int = 40,
    result_limit: int = 8,
    returned_bytes_limit: int = 40_000,
    elapsed_ms_limit: int = 3_000,
    query_id: str | None = None,
) -> dict[str, Any]:
    if requested_layer not in {"l2", "l3"}:
        raise ContractError("governed recall requires exactly one l2 or l3 layer")
    if not 1 <= result_limit <= candidate_limit <= 500:
        raise ContractError("invalid governed recall limits")
    if returned_bytes_limit < 1 or elapsed_ms_limit < 1:
        raise ContractError("invalid governed recall limits")
    query_id = query_id or str(uuid.uuid4())
    try:
        uuid.UUID(query_id)
    except (ValueError, TypeError) as exc:
        raise ContractError("query_id must be a UUID") from exc
    fts_query = _fts_query(query)
    started = time.monotonic()
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute(
            "SELECT 1 FROM governed_recall_receipt WHERE workspace_id=? AND principal_id=? "
            "AND query_id=?",
            (workspace_id, principal_id, query_id),
        ).fetchone():
            raise ContractError("governed recall query_id is single-use")
        rows = _candidate_rows(
            conn,
            layer=requested_layer,
            workspace_id=workspace_id,
            principal_id=principal_id,
            fts_query=fts_query,
            limit=candidate_limit + 1,
        )
        candidate_stopped = len(rows) > candidate_limit
        candidates = rows[:candidate_limit]
        results: list[dict[str, Any]] = []
        public_results: list[dict[str, Any]] = []
        returned_bytes = 0
        time_stopped = result_stopped = byte_stopped = False
        for candidate in candidates:
            if _elapsed_ms(started) >= elapsed_ms_limit:
                time_stopped = True
                break
            if len(results) >= result_limit:
                result_stopped = True
                break
            item = (
                _materialize_l2(conn, candidate, workspace_id, principal_id)
                if requested_layer == "l2"
                else _materialize_l3(conn, candidate, workspace_id, principal_id)
            )
            if item is None:
                raise ContractError(
                    "authorized governed candidate changed inside snapshot"
                )
            size = len(item["content"].encode("utf-8"))
            if returned_bytes + size > returned_bytes_limit:
                byte_stopped = True
                break
            if _sha(item["content"]) != item["metadata"]["content_sha256"]:
                raise ContractError("governed content digest mismatch")
            results.append(item)
            public_results.append(item["metadata"])
            returned_bytes += size
        elapsed = min(elapsed_ms_limit, _elapsed_ms(started))
        if time_stopped:
            stop_reason = "time_limit"
        elif byte_stopped:
            stop_reason = "byte_limit"
        elif result_stopped:
            stop_reason = "result_limit"
        elif candidate_stopped:
            stop_reason = "candidate_limit"
        elif not candidates:
            stop_reason = "no_candidates"
        else:
            stop_reason = "results_satisfied"
        limits = {
            "candidates": candidate_limit,
            "results": result_limit,
            "returned_bytes": returned_bytes_limit,
            "elapsed_ms": elapsed_ms_limit,
        }
        consumed = {
            "candidates": len(candidates),
            "results": len(results),
            "returned_bytes": returned_bytes,
            "elapsed_ms": elapsed,
        }
        receipt_id, now = str(uuid.uuid4()), _now()
        receipt = {
            "schema_version": "pdx_local_governed_recall_receipt_v2",
            "receipt_id": receipt_id,
            "query_id": query_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "requested_layers": [requested_layer],
            "searched_layers": [requested_layer],
            "per_layer": {requested_layer: {"limits": limits, "consumed": consumed}},
            "aggregate_limits": limits,
            "aggregate_consumed": consumed,
            "result_count": len(results),
            "results": public_results,
            "document_retrieval_requested": False,
            "stop_reason": stop_reason,
            "created_at": now,
        }
        _validate_receipt(receipt, results)
        receipt_json = _json(receipt)
        conn.execute(
            "INSERT INTO governed_recall_receipt VALUES (?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                query_id,
                workspace_id,
                principal_id,
                requested_layer,
                receipt_json,
                _sha(receipt_json),
                now,
            ),
        )
        conn.commit()
        return {"query_id": query_id, "results": results, "receipt": receipt}
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ContractError(f"governed recall rejected: {exc}") from exc
    except Exception:
        conn.rollback()
        raise
