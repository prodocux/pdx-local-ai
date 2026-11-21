from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from .validation import ContractError


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _id() -> str:
    return str(uuid.uuid4())


class EmbeddingAdapter(Protocol):
    adapter_id: str

    def embed(self, text: str) -> Sequence[float]: ...


class MemoryStore:
    """Citation-grounded, scoped local memory with bounded hybrid recall."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        embedding_adapter: EmbeddingAdapter | None = None,
    ) -> None:
        self.conn = connection
        self.embedding_adapter = embedding_adapter

    def remember(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        memory_kind: str,
        content: str,
        source_citation_id: str,
        confidence: float = 1.0,
        salience: float = 0.5,
        supersedes_memory_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = " ".join(content.split())
        if not normalized:
            raise ContractError("memory content must not be empty")
        if memory_kind not in {"fact", "preference", "decision", "task", "note"}:
            raise ContractError("unsupported memory kind")
        if not 0 <= confidence <= 1 or not 0 <= salience <= 1:
            raise ContractError("memory confidence and salience must be within 0..1")
        citation = self.conn.execute(
            """
            SELECT 1 FROM citation c
            JOIN file_acl a ON a.file_record_id=c.file_record_id
                           AND a.workspace_id=c.workspace_id
            WHERE c.citation_id=? AND c.workspace_id=?
              AND a.principal_id=? AND a.can_read=1
            """,
            (source_citation_id, workspace_id, principal_id),
        ).fetchone()
        if citation is None:
            raise ContractError("memory citation is not authorized in principal scope")
        if supersedes_memory_id is not None:
            prior = self.conn.execute(
                "SELECT status FROM memory_record WHERE memory_id=? AND workspace_id=? AND principal_id=?",
                (supersedes_memory_id, workspace_id, principal_id),
            ).fetchone()
            if prior is None or prior[0] != "active":
                raise ContractError("superseded memory must be active in the same scope")

        memory_id, now = _id(), _now()
        vector = self._embed(normalized)
        with self.conn:
            if supersedes_memory_id is not None:
                self.conn.execute(
                    "UPDATE memory_record SET status='superseded', updated_at=? WHERE memory_id=?",
                    (now, supersedes_memory_id),
                )
                self._event(
                    memory_id=supersedes_memory_id,
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    event_type="superseded",
                    value={"replacement_memory_id": memory_id},
                    now=now,
                )
            self.conn.execute(
                "INSERT INTO memory_record VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    memory_id, workspace_id, principal_id, memory_kind, normalized,
                    hashlib.sha256(normalized.encode("utf-8")).hexdigest(), "active",
                    confidence, salience, source_citation_id, supersedes_memory_id,
                    now, now,
                ),
            )
            self.conn.execute("INSERT INTO memory_fts VALUES (?,?)", (memory_id, normalized))
            if vector is not None:
                self.conn.execute(
                    "INSERT INTO memory_embedding VALUES (?,?,?,?,?)",
                    (memory_id, self.embedding_adapter.adapter_id, len(vector), json.dumps(vector), now),
                )
            self._event(
                memory_id=memory_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                event_type="created",
                value={"source_citation_id": source_citation_id},
                now=now,
            )
        return self.get(memory_id, workspace_id=workspace_id, principal_id=principal_id)

    def retract(self, memory_id: str, *, workspace_id: str, principal_id: str) -> None:
        now = _now()
        with self.conn:
            changed = self.conn.execute(
                "UPDATE memory_record SET status='retracted', updated_at=? "
                "WHERE memory_id=? AND workspace_id=? AND principal_id=? AND status='active'",
                (now, memory_id, workspace_id, principal_id),
            ).rowcount
            if changed != 1:
                raise ContractError("active memory not found in scope")
            self._event(
                memory_id=memory_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                event_type="retracted",
                value={},
                now=now,
            )

    def recall(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        query: str,
        limit: int = 8,
        candidate_limit: int = 40,
    ) -> dict[str, Any]:
        if not 1 <= limit <= 50 or not limit <= candidate_limit <= 500:
            raise ContractError("invalid memory recall limits")
        terms = re.findall(r"[\w]+", query, flags=re.UNICODE)
        if not terms:
            raise ContractError("memory query has no searchable terms")
        fts = " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)
        lexical_budget = (candidate_limit + 1) // 2 if self.embedding_adapter else candidate_limit
        semantic_budget = candidate_limit - lexical_budget
        lexical_rows = self.conn.execute(
            """
            SELECT m.*, bm25(memory_fts) AS lexical_rank, e.adapter_id, e.vector_json
            FROM memory_fts
            JOIN memory_record m ON m.memory_id=memory_fts.memory_id
            LEFT JOIN memory_embedding e ON e.memory_id=m.memory_id
            WHERE memory_fts MATCH ? AND m.workspace_id=? AND m.principal_id=?
              AND m.status='active'
            ORDER BY lexical_rank, m.memory_id LIMIT ?
            """,
            (fts, workspace_id, principal_id, lexical_budget),
        ).fetchall()
        query_vector = self._embed(query)
        candidates = {str(row["memory_id"]): row for row in lexical_rows}
        if query_vector is not None and semantic_budget:
            semantic_rows = self.conn.execute(
                """
                SELECT m.*, NULL AS lexical_rank, e.adapter_id, e.vector_json
                FROM memory_record m JOIN memory_embedding e ON e.memory_id=m.memory_id
                WHERE m.workspace_id=? AND m.principal_id=? AND m.status='active'
                  AND e.adapter_id=?
                ORDER BY m.updated_at DESC, m.memory_id LIMIT ?
                """,
                (workspace_id, principal_id, self.embedding_adapter.adapter_id, semantic_budget),
            ).fetchall()
            for row in semantic_rows:
                candidates.setdefault(str(row["memory_id"]), row)
        scored: list[dict[str, Any]] = []
        for row in candidates.values():
            semantic = None
            if (
                query_vector is not None
                and row["adapter_id"] == self.embedding_adapter.adapter_id
                and row["vector_json"] is not None
            ):
                semantic = _cosine(query_vector, json.loads(row["vector_json"]))
            lexical = (
                0.0
                if row["lexical_rank"] is None
                else 1 / (1 + abs(float(row["lexical_rank"])))
            )
            hybrid = lexical if semantic is None else 0.6 * lexical + 0.4 * semantic
            hybrid *= 0.75 + 0.25 * float(row["salience"])
            scored.append({"memory": _row(row), "score": hybrid, "semantic_score": semantic})
        scored.sort(key=lambda item: (-item["score"], item["memory"]["memory_id"]))
        now, query_id, receipt_id = _now(), _id(), _id()
        receipt = {
                "schema_version": "pdx_local_memory_recall_receipt_v1",
                "receipt_id": receipt_id,
                "query_id": query_id,
                "workspace_id": workspace_id,
                "principal_id": principal_id,
                "mode": "hybrid" if query_vector is not None else "lexical",
                "candidate_limit": candidate_limit,
                "candidates_consumed": len(candidates),
                "result_limit": limit,
                "result_count": min(limit, len(scored)),
                "embedding_adapter_id": (
                    self.embedding_adapter.adapter_id if self.embedding_adapter else None
                ),
                "created_at": now,
        }
        with self.conn:
            self.conn.execute(
                "INSERT INTO memory_recall_receipt VALUES (?,?,?,?,?,?)",
                (receipt_id, query_id, workspace_id, principal_id,
                 json.dumps(receipt, sort_keys=True, separators=(",", ":")), now),
            )
        return {
            "query_id": query_id,
            "results": scored[:limit],
            "receipt": receipt,
        }

    def get(self, memory_id: str, *, workspace_id: str, principal_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM memory_record WHERE memory_id=? AND workspace_id=? AND principal_id=?",
            (memory_id, workspace_id, principal_id),
        ).fetchone()
        if row is None:
            raise ContractError("memory not found in scope")
        return _row(row)

    def _embed(self, text: str) -> list[float] | None:
        if self.embedding_adapter is None:
            return None
        values = [float(value) for value in self.embedding_adapter.embed(text)]
        if not values or len(values) > 4096 or any(not math.isfinite(value) for value in values):
            raise ContractError("embedding adapter returned an invalid vector")
        return values

    def _event(
        self, *, memory_id: str, workspace_id: str, principal_id: str,
        event_type: str, value: dict[str, Any], now: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO memory_event VALUES (?,?,?,?,?,?,?)",
            (_id(), memory_id, workspace_id, principal_id, event_type,
             json.dumps(value, sort_keys=True, separators=(",", ":")), now),
        )


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ContractError("embedding dimensions changed")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=True)) / (left_norm * right_norm)


def _row(row: sqlite3.Row) -> dict[str, Any]:
    value = {
        key: item
        for key, item in zip(row.keys(), row, strict=True)
        if key not in {"lexical_rank", "vector_json", "adapter_id"}
    }
    value["schema_version"] = "pdx_local_memory_record_v1"
    return value
