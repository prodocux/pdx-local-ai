from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from .validation import ContractError


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _id() -> str:
    return str(uuid.uuid4())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _split_budget(total: int, parts: int) -> list[int]:
    base, extra = divmod(total, parts)
    return [base + (1 if index < extra else 0) for index in range(parts)]


def validate_promotion_receipt(receipt: dict[str, Any]) -> None:
    expected = {
        "model_proposed": "unverified",
        "user_stated": "user_asserted",
        "document_grounded": "citation_verified",
    }.get(receipt.get("provenance_category"))
    if expected is None or receipt.get("verification_status") != expected:
        raise ContractError("promotion receipt provenance is inconsistent")
    if receipt.get("source_content_sha256") != receipt.get("target_content_sha256"):
        raise ContractError("Gate 4A promotion cannot rewrite content")


def validate_layered_recall_receipt(receipt: dict[str, Any]) -> None:
    searched = receipt.get("searched_layers", [])
    per_layer = receipt.get("per_layer", {})
    if set(searched) != set(per_layer):
        raise ContractError("searched layers and per-layer accounting differ")
    aggregate_limits = receipt.get("aggregate_limits", {})
    aggregate_consumed = receipt.get("aggregate_consumed", {})
    for dimension in ("candidates", "results", "returned_bytes", "elapsed_ms"):
        if sum(per_layer[layer]["limits"][dimension] for layer in searched) > aggregate_limits[dimension]:
            raise ContractError("per-layer limits exceed aggregate limit")
        if aggregate_consumed[dimension] > aggregate_limits[dimension]:
            raise ContractError("aggregate consumption exceeds limit")
        if any(
            per_layer[layer]["consumed"][dimension] > per_layer[layer]["limits"][dimension]
            for layer in searched
        ):
            raise ContractError("per-layer consumption exceeds limit")
    if receipt.get("result_count") != len(receipt.get("results", [])):
        raise ContractError("layered result count is inconsistent")
    if aggregate_consumed.get("results") != receipt.get("result_count"):
        raise ContractError("consumed results are inconsistent")
    if receipt.get("document_retrieval_requested") is not False:
        raise ContractError("Gate 4A cannot report document retrieval")
    if receipt.get("verified_only") and (
        "excluded_unverified" not in aggregate_consumed
        or any("excluded_unverified" not in per_layer[layer]["consumed"] for layer in searched)
    ):
        raise ContractError("verified-only exclusion accounting is missing")
    for result in receipt.get("results", []):
        expected = {
            "model_proposed": "unverified",
            "user_stated": "user_asserted",
            "document_grounded": "citation_verified",
        }.get(result.get("provenance_category"))
        if result.get("verification_status") != expected:
            raise ContractError("recall result provenance is inconsistent")


class LayeredMemoryStore:
    """Gate 4A L0/L1 store. It never invokes document retrieval."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: Callable[[], datetime] = _utc_now,
        max_session_items: int = 100,
        max_session_bytes: int = 200_000,
        max_scope_items: int = 500,
        max_scope_bytes: int = 1_000_000,
        max_ttl_seconds: int = 2_592_000,
        monotonic: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.conn = connection
        self.clock = clock
        self.max_session_items = max_session_items
        self.max_session_bytes = max_session_bytes
        self.max_scope_items = max_scope_items
        self.max_scope_bytes = max_scope_bytes
        self.max_ttl_seconds = max_ttl_seconds
        self.monotonic = monotonic

    def capture_session_item(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        session_id: str,
        content: str,
        provenance_category: str,
        ttl_seconds: int,
        source_citation_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = " ".join(content.split())
        if not normalized:
            raise ContractError("session memory content must not be empty")
        self._validate_ttl(ttl_seconds)
        now = self.clock()
        created_at, expires_at = _stamp(now), _stamp(now + timedelta(seconds=ttl_seconds))
        item_id = _id()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            verification = self._derive_verification(
                workspace_id, principal_id, provenance_category, source_citation_id
            )
            session = self.conn.execute(
                "SELECT state FROM layered_session WHERE workspace_id=? AND principal_id=? AND session_id=?",
                (workspace_id, principal_id, session_id),
            ).fetchone()
            if session is None:
                self.conn.execute(
                    "INSERT INTO layered_session VALUES (?,?,?,?,?,NULL)",
                    (workspace_id, principal_id, session_id, "open", created_at),
                )
            elif session["state"] != "open":
                raise ContractError("session is closed")
            count, used = self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(content AS BLOB))),0) "
                "FROM session_memory_item WHERE workspace_id=? AND principal_id=? "
                "AND session_id=? AND state='captured' AND expires_at>?",
                (workspace_id, principal_id, session_id, created_at),
            ).fetchone()
            size = len(normalized.encode("utf-8"))
            if count + 1 > self.max_session_items or used + size > self.max_session_bytes:
                raise ContractError("session memory capacity exceeded")
            self.conn.execute(
                "INSERT INTO session_memory_item VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (item_id, workspace_id, principal_id, session_id, normalized, _digest(normalized),
                 provenance_category, verification, source_citation_id, "captured", created_at,
                 expires_at),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return self._session_item(item_id)

    def promote_to_working(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        session_item_id: str,
        target_scope_id: str,
        idempotency_key: str,
        actor_id: str,
        requested_ttl_seconds: int,
    ) -> dict[str, Any]:
        if len(idempotency_key) < 16 or not target_scope_id or not actor_id:
            raise ContractError("invalid promotion request")
        self._validate_ttl(requested_ttl_seconds)
        fingerprint = _digest(_json({
            "session_item_id": session_item_id, "target_scope_id": target_scope_id,
            "actor_id": actor_id, "requested_ttl_seconds": requested_ttl_seconds,
        }))
        now = self.clock()
        now_text = _stamp(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            replay = self.conn.execute(
                "SELECT request_fingerprint, receipt_json FROM memory_promotion_receipt "
                "WHERE workspace_id=? AND principal_id=? AND idempotency_key=?",
                (workspace_id, principal_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if replay["request_fingerprint"] != fingerprint:
                    raise ContractError("promotion idempotency conflict")
                self.conn.commit()
                return json.loads(replay["receipt_json"])
            source = self.conn.execute(
                "SELECT * FROM session_memory_item WHERE session_item_id=? AND workspace_id=? "
                "AND principal_id=? AND state='captured' AND expires_at>?",
                (session_item_id, workspace_id, principal_id, now_text),
            ).fetchone()
            if source is None:
                raise ContractError("eligible session item not found")
            if source["provenance_category"] == "document_grounded":
                self._require_authorized_citation(
                    workspace_id, principal_id, source["source_citation_id"]
                )
            count, used = self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(content AS BLOB))),0) FROM working_memory "
                "WHERE workspace_id=? AND principal_id=? AND scope_id=? AND state='active' AND expires_at>?",
                (workspace_id, principal_id, target_scope_id, now_text),
            ).fetchone()
            size = len(source["content"].encode("utf-8"))
            if count + 1 > self.max_scope_items or used + size > self.max_scope_bytes:
                raise ContractError("working memory capacity exceeded")
            working_id, receipt_id = _id(), _id()
            expires_at = _stamp(now + timedelta(seconds=requested_ttl_seconds))
            self.conn.execute(
                "INSERT INTO working_memory VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (working_id, workspace_id, principal_id, target_scope_id, source["content"],
                 source["content_sha256"], source["provenance_category"],
                 source["verification_status"], source["source_citation_id"], session_item_id,
                 "active", now_text, expires_at),
            )
            receipt = {
                "schema_version": "pdx_local_memory_promotion_receipt_v1",
                "promotion_receipt_id": receipt_id, "workspace_id": workspace_id,
                "principal_id": principal_id, "idempotency_key": idempotency_key,
                "session_item_id": session_item_id, "working_memory_id": working_id,
                "target_scope_id": target_scope_id,
                "source_content_sha256": source["content_sha256"],
                "target_content_sha256": source["content_sha256"],
                "provenance_category": source["provenance_category"],
                "verification_status": source["verification_status"],
                "actor_id": actor_id, "created_at": now_text,
            }
            validate_promotion_receipt(receipt)
            self.conn.execute(
                "INSERT INTO memory_promotion_receipt VALUES (?,?,?,?,?,?,?,?,?)",
                (receipt_id, workspace_id, principal_id, idempotency_key, fingerprint,
                 session_item_id, working_id, _json(receipt), now_text),
            )
            self.conn.execute(
                "UPDATE session_memory_item SET state='promoted' WHERE session_item_id=?",
                (session_item_id,),
            )
            self.conn.commit()
            return receipt
        except Exception:
            self.conn.rollback()
            raise

    def recall_layered(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        requested_layers: Sequence[str],
        session_id: str | None = None,
        scope_id: str | None = None,
        verified_only: bool = False,
        candidate_limit: int = 40,
        result_limit: int = 8,
        returned_bytes_limit: int = 40_000,
        elapsed_ms_limit: int = 3_000,
    ) -> dict[str, Any]:
        layers = list(dict.fromkeys(requested_layers))
        if not layers or any(layer not in {"l0", "l1"} for layer in layers):
            raise ContractError("Gate 4A recall supports only explicit l0/l1 layers")
        if "l0" in layers and not session_id or "l1" in layers and not scope_id:
            raise ContractError("requested layer scope is missing")
        if not len(layers) <= candidate_limit <= 500:
            raise ContractError("invalid layered recall limits")
        if not len(layers) <= result_limit <= candidate_limit:
            raise ContractError("invalid layered recall limits")
        if returned_bytes_limit < len(layers):
            raise ContractError("invalid layered recall limits")
        if elapsed_ms_limit < 1:
            raise ContractError("invalid layered recall limits")
        started = self.monotonic()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            result = self._recall_in_snapshot(
                workspace_id=workspace_id, principal_id=principal_id, layers=layers,
                session_id=session_id, scope_id=scope_id, verified_only=verified_only,
                candidate_limit=candidate_limit, result_limit=result_limit,
                returned_bytes_limit=returned_bytes_limit,
                elapsed_ms_limit=elapsed_ms_limit, started=started,
            )
            self.conn.commit()
            return result
        except Exception:
            self.conn.rollback()
            raise

    def _recall_in_snapshot(
        self, *, workspace_id: str, principal_id: str, layers: list[str],
        session_id: str | None, scope_id: str | None, verified_only: bool,
        candidate_limit: int, result_limit: int, returned_bytes_limit: int,
        elapsed_ms_limit: int, started: float,
    ) -> dict[str, Any]:
        now = _stamp(self.clock())
        candidates: dict[str, list[dict[str, Any]]] = {}
        per_layer: dict[str, Any] = {}
        candidate_budgets = _split_budget(candidate_limit, len(layers))
        result_budgets = _split_budget(result_limit, len(layers))
        byte_budgets = _split_budget(returned_bytes_limit, len(layers))
        elapsed_budgets = _split_budget(elapsed_ms_limit, len(layers))
        candidate_truncated = False
        time_stopped = False
        searched_layers: list[str] = []
        for index, layer in enumerate(layers):
            if searched_layers and self._elapsed_ms(started) >= elapsed_ms_limit:
                time_stopped = True
                break
            layer_started = self.monotonic()
            layer_candidate_limit = candidate_budgets[index]
            if layer == "l0":
                rows = self.conn.execute(
                    "SELECT * FROM session_memory_item WHERE workspace_id=? AND principal_id=? "
                    "AND session_id=? AND state='captured' AND expires_at>? "
                    "ORDER BY created_at DESC, session_item_id LIMIT ?",
                    (workspace_id, principal_id, session_id, now, layer_candidate_limit + 1),
                ).fetchall()
                id_key = "session_item_id"
            else:
                rows = self.conn.execute(
                    "SELECT * FROM working_memory WHERE workspace_id=? AND principal_id=? "
                    "AND scope_id=? AND state='active' AND expires_at>? "
                    "ORDER BY created_at DESC, working_memory_id LIMIT ?",
                    (workspace_id, principal_id, scope_id, now, layer_candidate_limit + 1),
                ).fetchall()
                id_key = "working_memory_id"
            searched_layers.append(layer)
            candidate_truncated = candidate_truncated or len(rows) > layer_candidate_limit
            rows = rows[:layer_candidate_limit]
            excluded = sum(row["verification_status"] == "unverified" for row in rows) if verified_only else 0
            selected = [row for row in rows if not verified_only or row["verification_status"] != "unverified"]
            candidates[layer] = [{
                "layer": layer, "item_id": row[id_key], "content": row["content"],
                "content_sha256": row["content_sha256"],
                "provenance_category": row["provenance_category"],
                "verification_status": row["verification_status"],
                "expires_at": row["expires_at"],
            } for row in selected]
            consumed: dict[str, int] = {
                "candidates": len(rows), "results": 0, "returned_bytes": 0, "elapsed_ms": 0
            }
            if verified_only:
                consumed["excluded_unverified"] = excluded
            per_layer[layer] = {"limits": {
                "candidates": layer_candidate_limit, "results": result_budgets[index],
                "returned_bytes": byte_budgets[index], "elapsed_ms": elapsed_budgets[index],
            }, "consumed": consumed}
            consumed["elapsed_ms"] = min(
                elapsed_budgets[index], max(0, int((self.monotonic() - layer_started) * 1000))
            )
            if self._elapsed_ms(started) >= elapsed_ms_limit:
                time_stopped = True
                break
        results: list[dict[str, Any]] = []
        result_stopped = False
        byte_stopped = False
        for layer in searched_layers:
            limits = per_layer[layer]["limits"]
            consumed = per_layer[layer]["consumed"]
            for item in candidates[layer]:
                if self._elapsed_ms(started) >= elapsed_ms_limit:
                    time_stopped = True
                    break
                size = len(item["content"].encode("utf-8"))
                if consumed["results"] >= limits["results"]:
                    result_stopped = True
                    break
                if consumed["returned_bytes"] + size > limits["returned_bytes"]:
                    byte_stopped = True
                    break
                results.append(item)
                consumed["results"] += 1
                consumed["returned_bytes"] += size
            if time_stopped:
                break
        aggregate_consumed: dict[str, int] = {
            "candidates": sum(v["consumed"]["candidates"] for v in per_layer.values()),
            "results": len(results),
            "returned_bytes": sum(v["consumed"]["returned_bytes"] for v in per_layer.values()),
            "elapsed_ms": min(elapsed_ms_limit, self._elapsed_ms(started)),
        }
        if verified_only:
            aggregate_consumed["excluded_unverified"] = sum(
                v["consumed"]["excluded_unverified"] for v in per_layer.values()
            )
        if time_stopped:
            stop_reason = "time_limit"
        elif byte_stopped:
            stop_reason = "byte_limit"
        elif result_stopped:
            stop_reason = "result_limit"
        elif candidate_truncated:
            stop_reason = "candidate_limit"
        elif not any(candidates.values()):
            stop_reason = "no_candidates"
        else:
            stop_reason = "results_satisfied"
        receipt_id, query_id = _id(), _id()
        public_results = [{key: value for key, value in item.items() if key != "content"} for item in results]
        receipt = {
            "schema_version": "pdx_local_layered_recall_receipt_v1",
            "receipt_id": receipt_id, "query_id": query_id, "workspace_id": workspace_id,
            "principal_id": principal_id, "requested_layers": layers,
            "searched_layers": searched_layers,
            "verified_only": verified_only, "per_layer": per_layer,
            "aggregate_limits": {"candidates": candidate_limit, "results": result_limit,
                                 "returned_bytes": returned_bytes_limit,
                                 "elapsed_ms": elapsed_ms_limit},
            "aggregate_consumed": aggregate_consumed, "result_count": len(results),
            "results": public_results, "document_retrieval_requested": False,
            "stop_reason": stop_reason, "created_at": now,
        }
        validate_layered_recall_receipt(receipt)
        self.conn.execute(
            "INSERT INTO layered_recall_receipt VALUES (?,?,?,?,?,?)",
            (receipt_id, query_id, workspace_id, principal_id, _json(receipt), now),
        )
        return {"query_id": query_id, "results": results, "receipt": receipt}

    def _elapsed_ms(self, started: float) -> int:
        return max(0, int((self.monotonic() - started) * 1000))

    def close_session(self, *, workspace_id: str, principal_id: str, session_id: str) -> None:
        now = _stamp(self.clock())
        with self.conn:
            changed = self.conn.execute(
                "UPDATE layered_session SET state='closed', closed_at=? WHERE workspace_id=? "
                "AND principal_id=? AND session_id=? AND state='open'",
                (now, workspace_id, principal_id, session_id),
            ).rowcount
            if changed != 1:
                raise ContractError("open session not found")
            self.conn.execute(
                "UPDATE session_memory_item SET state='discarded' WHERE workspace_id=? "
                "AND principal_id=? AND session_id=? AND state='captured'",
                (workspace_id, principal_id, session_id),
            )

    def _derive_verification(
        self, workspace_id: str, principal_id: str, provenance: str,
        citation_id: str | None,
    ) -> str:
        if provenance == "model_proposed" and citation_id is None:
            return "unverified"
        if provenance == "user_stated" and citation_id is None:
            return "user_asserted"
        if provenance == "document_grounded" and citation_id is not None:
            self._require_authorized_citation(workspace_id, principal_id, citation_id)
            return "citation_verified"
        raise ContractError("provenance and citation are inconsistent")

    def _require_authorized_citation(
        self, workspace_id: str, principal_id: str, citation_id: str | None,
    ) -> None:
        row = self.conn.execute(
            "SELECT 1 FROM citation c JOIN file_acl a ON a.file_record_id=c.file_record_id "
            "AND a.workspace_id=c.workspace_id WHERE c.citation_id=? AND c.workspace_id=? "
            "AND a.principal_id=? AND a.can_read=1",
            (citation_id, workspace_id, principal_id),
        ).fetchone()
        if row is None:
            raise ContractError("document-grounded memory requires authorized citation")

    def _validate_ttl(self, ttl_seconds: int) -> None:
        if not 60 <= ttl_seconds <= self.max_ttl_seconds:
            raise ContractError("invalid memory TTL")

    def _session_item(self, item_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM session_memory_item WHERE session_item_id=?", (item_id,)
        ).fetchone()
        return dict(row)
