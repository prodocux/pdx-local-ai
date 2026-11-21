from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import unicodedata
import uuid
from datetime import UTC, datetime
from typing import Any

from .memory import EmbeddingAdapter
from .validation import ContractError, validate_citation_against_block


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class HybridRetrieval:
    """Bounded ACL-first lexical and semantic retrieval over published blocks."""

    def __init__(self, connection: sqlite3.Connection, embedding_adapter: EmbeddingAdapter) -> None:
        self.conn = connection
        self.adapter = embedding_adapter

    def refresh_embeddings(self, *, workspace_id: str, limit: int = 1000) -> int:
        if not 1 <= limit <= 10_000:
            raise ContractError("invalid embedding refresh limit")
        rows = self.conn.execute(
            """
            SELECT b.block_instance_id, b.source_version_id, b.text
            FROM block_instance b
            JOIN file_record f ON f.current_source_version_id=b.source_version_id
            LEFT JOIN block_embedding e ON e.block_instance_id=b.block_instance_id
                                      AND e.adapter_id=?
            WHERE b.workspace_id=? AND f.catalog_status='active' AND e.block_instance_id IS NULL
            ORDER BY b.block_instance_id LIMIT ?
            """,
            (self.adapter.adapter_id, workspace_id, limit),
        ).fetchall()
        now = _now()
        with self.conn:
            for row in rows:
                vector = _vector(self.adapter.embed(str(row["text"])))
                self.conn.execute(
                    "INSERT OR REPLACE INTO block_embedding VALUES (?,?,?,?,?,?)",
                    (
                        row["block_instance_id"], row["source_version_id"],
                        self.adapter.adapter_id, len(vector), json.dumps(vector), now,
                    ),
                )
        return len(rows)

    def retrieve(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        query: str,
        candidate_limit: int = 40,
        result_limit: int = 8,
    ) -> dict[str, Any]:
        if not 1 <= result_limit <= candidate_limit <= 500:
            raise ContractError("invalid hybrid retrieval limits")
        terms = re.findall(r"[\w]+", query, flags=re.UNICODE)
        if not terms:
            raise ContractError("hybrid query has no searchable terms")
        fts = " OR ".join(f'"{term}"' for term in terms)
        lexical_budget = (candidate_limit + 1) // 2
        semantic_budget = candidate_limit - lexical_budget
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            result = self._retrieve_in_snapshot(
                workspace_id=workspace_id,
                principal_id=principal_id,
                source_root_id=source_root_id,
                fts=fts,
                query=query,
                lexical_budget=lexical_budget,
                semantic_budget=semantic_budget,
                candidate_limit=candidate_limit,
                result_limit=result_limit,
            )
            self.conn.commit()
            return result
        except Exception:
            self.conn.rollback()
            raise

    def _retrieve_in_snapshot(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        source_root_id: str,
        fts: str,
        query: str,
        lexical_budget: int,
        semantic_budget: int,
        candidate_limit: int,
        result_limit: int,
    ) -> dict[str, Any]:
        root = self.conn.execute(
            "SELECT 1 FROM source_root WHERE source_root_id=? AND workspace_id=?",
            (source_root_id, workspace_id),
        ).fetchone()
        if root is None:
            raise ContractError("source root does not belong to workspace")
        lexical = self.conn.execute(
            """
            SELECT b.block_instance_id, bm25(block_fts) AS lexical_rank
            FROM block_fts JOIN block_instance b USING(block_instance_id)
            JOIN file_record f ON f.current_source_version_id=b.source_version_id
            JOIN file_acl a ON a.file_record_id=f.file_record_id
            WHERE block_fts MATCH ? AND a.workspace_id=? AND a.principal_id=?
              AND a.can_read=1 AND f.workspace_id=? AND f.source_root_id=?
              AND f.catalog_status='active'
            ORDER BY lexical_rank, b.block_instance_id LIMIT ?
            """,
            (fts, workspace_id, principal_id, workspace_id, source_root_id, lexical_budget),
        ).fetchall()
        semantic = [] if semantic_budget == 0 else self.conn.execute(
            """
            SELECT b.block_instance_id, e.vector_json
            FROM block_embedding e JOIN block_instance b USING(block_instance_id)
            JOIN file_record f ON f.current_source_version_id=b.source_version_id
            JOIN file_acl a ON a.file_record_id=f.file_record_id
            WHERE e.adapter_id=? AND a.workspace_id=? AND a.principal_id=?
              AND a.can_read=1 AND f.workspace_id=? AND f.source_root_id=?
              AND f.catalog_status='active'
            ORDER BY b.block_instance_id LIMIT ?
            """,
            (self.adapter.adapter_id, workspace_id, principal_id, workspace_id,
             source_root_id, semantic_budget),
        ).fetchall()
        scores: dict[str, dict[str, float | None]] = {}
        for row in lexical:
            scores[str(row["block_instance_id"])] = {
                "lexical": 1 / (1 + abs(float(row["lexical_rank"]))), "semantic": None
            }
        query_vector = _vector(self.adapter.embed(query))
        for row in semantic:
            item = scores.setdefault(str(row["block_instance_id"]), {"lexical": 0.0, "semantic": None})
            item["semantic"] = _cosine(query_vector, json.loads(row["vector_json"]))
        ranked = sorted(
            scores,
            key=lambda block_id: (
                -(0.6 * float(scores[block_id]["lexical"] or 0)
                  + 0.4 * float(scores[block_id]["semantic"] or 0)),
                block_id,
            ),
        )[:result_limit]
        results: list[dict[str, Any]] = []
        query_id, now = str(uuid.uuid4()), _now()
        for block_id in ranked:
            row = self.conn.execute(
                    """
                    SELECT b.*, f.file_record_id, f.source_root_id, sv.source_sha256,
                           p.parser_contract_name, p.parser_contract_version
                    FROM block_instance b
                    JOIN file_record f ON f.current_source_version_id=b.source_version_id
                    JOIN source_version sv USING(source_version_id)
                    JOIN projection p USING(projection_id)
                    JOIN file_acl a ON a.file_record_id=f.file_record_id
                    WHERE b.block_instance_id=? AND a.workspace_id=?
                      AND a.principal_id=? AND a.can_read=1
                      AND f.workspace_id=? AND f.source_root_id=?
                      AND f.catalog_status='active'
                    """,
                    (block_id, workspace_id, principal_id, workspace_id, source_root_id),
                ).fetchone()
            if row is None:
                raise ContractError("authorized candidate disappeared inside retrieval snapshot")
            normalized = unicodedata.normalize("NFC", str(row["text"]))
            citation = {
                    "schema_version": "pdx_local_citation_v1",
                    "citation_id": str(uuid.uuid4()), "workspace_id": workspace_id,
                    "source_root_id": row["source_root_id"], "file_record_id": row["file_record_id"],
                    "source_version_id": row["source_version_id"], "source_sha256": row["source_sha256"],
                    "projection_id": row["projection_id"],
                    "parser_contract": {"name": row["parser_contract_name"], "version": row["parser_contract_version"]},
                    "block_instance_id": block_id,
                    "locator": {"kind": row["locator_kind"], "value": row["locator_value"]},
                    "quote_start": 0, "quote_end": len(normalized),
                    "quote_normalization": "unicode_nfc_codepoint_v1",
                    "quoted_text_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            }
            text = validate_citation_against_block(citation, dict(row))
            self.conn.execute(
                    "INSERT INTO citation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (citation["citation_id"], query_id, workspace_id, row["source_root_id"],
                     row["file_record_id"], row["source_version_id"], row["source_sha256"],
                     row["projection_id"], row["parser_contract_name"], row["parser_contract_version"],
                     block_id, row["locator_kind"], row["locator_value"], 0, len(normalized),
                     "unicode_nfc_codepoint_v1", citation["quoted_text_sha256"], now),
            )
            results.append({"text": text, "citation": citation, "scores": scores[block_id]})
        receipt_id = str(uuid.uuid4())
        receipt = {
                "schema_version": "pdx_local_hybrid_retrieval_receipt_v1",
                "receipt_id": receipt_id,
                "query_id": query_id,
                "mode": "hybrid", "workspace_id": workspace_id,
                "principal_id": principal_id, "source_root_id": source_root_id,
                "embedding_adapter_id": self.adapter.adapter_id,
                "candidate_limit": candidate_limit,
                "lexical_candidates": len(lexical), "semantic_candidates": len(semantic),
                "unique_candidates": len(scores), "result_limit": result_limit,
                "result_count": len(results),
                "citation_ids": [item["citation"]["citation_id"] for item in results],
                "created_at": now,
        }
        self.conn.execute(
            "INSERT INTO retrieval_receipt VALUES (?,?,?,?,?)",
            (receipt_id, query_id, workspace_id,
             json.dumps(receipt, sort_keys=True, separators=(",", ":")), now),
        )
        return {
            "query_id": query_id,
            "results": results,
            "receipt": receipt,
        }


def _vector(values: Any) -> list[float]:
    vector = [float(value) for value in values]
    if not vector or len(vector) > 4096 or any(not math.isfinite(value) for value in vector):
        raise ContractError("embedding adapter returned an invalid vector")
    return vector


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ContractError("embedding dimensions changed")
    denominator = math.sqrt(sum(v * v for v in left)) * math.sqrt(sum(v * v for v in right))
    return 0.0 if denominator == 0 else sum(a * b for a, b in zip(left, right, strict=True)) / denominator
