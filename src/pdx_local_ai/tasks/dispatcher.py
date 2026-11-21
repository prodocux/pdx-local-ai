"""Controlled dispatcher: the only code that touches retrieval, memory and the Engine.

Agents name actions and arguments; the host decides roots, budgets, paths and ids.
Engine adapter facts (checked against the Engine pin in versions.py): we use the
public ``ArtifactRuntime.execute_plan`` + ``SkillRegistry`` with a host-registered
``pdx.task_candidate_seal`` executor and a ``pdx_execution_plan_v1`` plan. No private
Engine modules are imported. Local rejections carry ``origin=local_policy``; Engine
statuses carry ``origin=engine`` and ``completed_with_review`` never implies task success.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from ..service.contracts import AgentSearchRequest, SecurityContext
from .contracts import LIMITS, TaskError, canonical_json, utf8_len

ENGINE_SKILL = "pdx.task_candidate_seal"


class SearchBackend:
    """Bounded retrieval through the existing PdxLocalAgentService under the trusted context."""

    def __init__(self, agent_service: Any) -> None:
        self.agent_service = agent_service

    def search(self, context: SecurityContext, source_root_ids: list[str], query: str,
               allocation: dict[str, int]) -> dict[str, Any]:
        candidates = int(allocation["candidates"])
        meta = max(1, min(1000, (candidates * 2 + 2) // 3))
        lex = max(1, min(200, candidates - meta if candidates - meta > 0 else 1))
        opened_blocks = max(1, min(100, int(allocation["opened_blocks"])))
        request = AgentSearchRequest(
            workspace_id=context.workspace_id,
            principal_id=context.principal_id,
            source_root_ids=list(source_root_ids),
            query=query,
            timeout_ms=max(50, min(60_000, int(allocation["elapsed_ms"]))),
            limit=max(1, min(8, opened_blocks)),
            opened_files=max(1, min(50, int(allocation["opened_files"]))),
            opened_blocks=opened_blocks,
            returned_bytes=max(1, min(LIMITS["tool_return_bytes"] - 4096, int(allocation["returned_bytes"]))),
            metadata_candidates=meta,
            lexical_candidates=lex,
        )
        started = time.perf_counter()
        response = self.agent_service.search_documents(request, context=context, search_mode="background_refresh")
        wall_ms = int((time.perf_counter() - started) * 1000)
        consumed = {"candidates": 0, "opened_files": 0, "opened_blocks": 0, "returned_bytes": 0, "elapsed_ms": 0}
        have_receipt = False
        for receipt in response.receipts:
            c = receipt.get("consumed") or {}
            have_receipt = True
            consumed["candidates"] += int(c.get("metadata_candidates", 0)) + int(c.get("lexical_candidates", 0))
            consumed["opened_files"] += int(c.get("opened_files", 0))
            consumed["opened_blocks"] += int(c.get("opened_blocks", 0))
            consumed["returned_bytes"] += int(c.get("returned_bytes", 0))
            consumed["elapsed_ms"] += int(c.get("elapsed_ms", 0))
        if not have_receipt:
            # No receipt: charge the whole allocation rather than under-count.
            consumed = {k: int(allocation[k]) for k in consumed}
        consumed["elapsed_ms"] = max(consumed["elapsed_ms"], wall_ms)
        return {
            "status": response.status, "stop_reason": response.stop_reason,
            "warning": response.warning, "degraded": response.degraded,
            "results": [{
                "file_record_id": r.file_record_id, "source_root_id": r.source_root_id,
                "block_instance_id": r.block_instance_id, "score": r.score, "text": r.text,
                "citation": r.citation,
            } for r in response.results],
            "consumed": consumed,
            "receipt_ids": [r.get("receipt_id") for r in response.receipts if r.get("receipt_id")],
        }

    def acl_ok(self, context: SecurityContext, file_record_id: str) -> bool:
        row = self.agent_service.catalog.conn.execute(
            "SELECT 1 FROM file_acl WHERE workspace_id=? AND principal_id=? AND file_record_id=? AND can_read=1",
            (context.workspace_id, context.principal_id, file_record_id)).fetchone()
        return row is not None

    def roots_enabled(self, context: SecurityContext, root_ids: list[str]) -> list[str]:
        marks = ",".join("?" for _ in root_ids)
        rows = self.agent_service.catalog.conn.execute(
            f"SELECT source_root_id FROM source_root WHERE workspace_id=? AND enabled=1 "
            f"AND source_root_id IN ({marks})", (context.workspace_id, *root_ids)).fetchall()
        return [str(r[0]) for r in rows]


class MemoryBackend:
    """Layered memory recall and proposal-only promotion (never publishes)."""

    def __init__(self, catalog: Any) -> None:
        self.catalog = catalog

    def recall(self, context: SecurityContext, scope_id: str, limit: int) -> dict[str, Any]:
        from ..layered_memory import LayeredMemoryStore
        store = LayeredMemoryStore(self.catalog.conn)
        result = store.recall_layered(
            workspace_id=context.workspace_id, principal_id=context.principal_id,
            requested_layers=["l1"], scope_id=scope_id, candidate_limit=40,
            result_limit=max(1, min(8, limit)), returned_bytes_limit=20_000, elapsed_ms_limit=2000)
        items = [{"memory_id": r["item_id"], "content": r["content"],
                  "provenance_category": r.get("provenance_category"),
                  "verification_status": r.get("verification_status")} for r in result["results"]]
        return {"items": items, "receipt_id": result["receipt"].get("receipt_id")
                or result["receipt"].get("layered_recall_receipt_id")}

    def propose(self, *, workspace_id: str, principal_id: str, task_id: str, scope_id: str, content: str,
                citation_id: str, state: dict[str, Any], on_progress: Any) -> dict[str, Any]:
        """Capture -> promote -> propose. Resumable: ``state`` records completed steps."""
        from ..governed_memory import propose_from_working_memory
        from ..layered_memory import LayeredMemoryStore
        store = LayeredMemoryStore(self.catalog.conn)
        key_base = hashlib.sha256(f"{task_id}|{scope_id}|{content}".encode()).hexdigest()
        if "session_item_id" not in state:
            item = store.capture_session_item(
                workspace_id=workspace_id, principal_id=principal_id, session_id=f"task-{task_id}",
                content=content, provenance_category="document_grounded", ttl_seconds=7 * 86400,
                source_citation_id=citation_id)
            state["session_item_id"] = item["session_item_id"]
            on_progress(state)
        if "working_memory_id" not in state:
            receipt = store.promote_to_working(
                workspace_id=workspace_id, principal_id=principal_id,
                session_item_id=state["session_item_id"], target_scope_id=scope_id,
                idempotency_key=f"task-promote-{key_base[:32]}", actor_id=f"task:{task_id}",
                requested_ttl_seconds=7 * 86400)
            state["working_memory_id"] = receipt["working_memory_id"]
            on_progress(state)
        if "proposal_id" not in state:
            proposal = propose_from_working_memory(
                self.catalog.conn, workspace_id=workspace_id, principal_id=principal_id,
                working_memory_id=state["working_memory_id"], requested_memory_kind="note",
                proposer_actor_id=f"task:{task_id}", proposer_actor_kind="model",
                idempotency_key=f"task-propose-{key_base[:32]}")
            state["proposal_id"] = proposal["proposal_id"]
            state["proposal_state"] = proposal["state"]
            on_progress(state)
        return state


class EngineAdapter:
    """Seal a local candidate through ArtifactRuntime.

    External sends do not enter this method. Those actions use external_action,
    which keeps the original operation and provider key when the outcome is unknown.
    """

    def __init__(self, output_root: Path, *, required: bool = True) -> None:
        self.output_root = Path(output_root)
        self.required = required
        self._import_error: str | None = None
        try:
            import pdx_artifact_engine  # noqa: F401
            from pdx_artifact_engine import ArtifactRuntime  # noqa: F401
            from pdx_artifact_engine.registry import SkillDefinition, SkillRegistry  # noqa: F401
        except Exception as exc:  # pragma: no cover - environment dependent
            self._import_error = str(exc)

    @property
    def available(self) -> bool:
        return self._import_error is None

    def seal(self, *, task_id: str, attempt_id: str, name: str, data: bytes, sha256: str) -> dict[str, Any]:
        if not self.available:
            raise TaskError("ENGINE_UNAVAILABLE", f"artifact engine unavailable: {self._import_error}",
                            origin="engine")
        from pdx_artifact_engine import ArtifactRuntime
        from pdx_artifact_engine.registry import SkillDefinition, SkillRegistry

        skill = SkillDefinition.from_dict({
            "name": ENGINE_SKILL, "version": "1", "domain": "task_harness",
            "description": "Seal a host-validated candidate artifact", "entrypoint": "host",
            "inputs": ["candidate_name", "candidate_sha256"], "outputs": ["candidate"],
            "failure_codes": [{"code": "SEAL_FAILED", "meaning": "candidate could not be sealed"}],
        })

        def executor(inputs: dict[str, Any], output_dir: Path) -> dict[str, Any]:
            output_dir.mkdir(parents=True, exist_ok=True)
            target = output_dir / str(inputs["candidate_name"])
            target.write_bytes(data)
            if hashlib.sha256(target.read_bytes()).hexdigest() != inputs["candidate_sha256"]:
                raise ValueError("sealed bytes differ from declared digest")
            return {"result": {"status": "sealed", "sha256": inputs["candidate_sha256"]},
                    "files": [target], "outputs": {"candidate": target.as_posix()}}

        runtime = ArtifactRuntime(SkillRegistry([skill]), {ENGINE_SKILL: executor}, planner_name="task_host")
        request_id = f"task-{task_id}-{attempt_id}-{sha256[:16]}"
        plan = {
            "schema_version": "pdx_execution_plan_v1", "request_id": request_id,
            "producer": {"type": "pdx_local_task_host", "name": "task_harness"},
            "steps": [{"id": "seal", "kind": "tool", "tool": ENGINE_SKILL,
                       "inputs": {"candidate_name": name, "candidate_sha256": sha256},
                       "outputs": ["candidate"]}],
        }
        out_dir = self.output_root / task_id / attempt_id / f"engine-{sha256[:16]}"
        try:
            result = runtime.execute_plan(plan, out_dir)
        except Exception as exc:
            raise TaskError("ARTIFACT_REJECTED", f"engine run raised: {exc}", origin="engine") from exc
        run = result["run_manifest"]
        manifest = result["artifact_manifest"]
        status = str(run["status"])
        files = [{"path": f["path"], "sha256": f["sha256"]} for f in manifest.get("files", [])]
        digest = hashlib.sha256(canonical_json(files).encode()).hexdigest()
        if status not in {"completed", "completed_with_review"} or not files \
                or files[0]["sha256"] != sha256:
            raise TaskError("ARTIFACT_REJECTED", f"engine did not seal candidate (status={status})",
                            {"engine_status": status, "errors": run.get("errors", [])[:3]}, origin="engine")
        return {"run_id": run["run_id"], "engine_status": status,
                "engine_review": status == "completed_with_review",
                "manifest_files": files, "manifest_sha256": digest, "origin": "engine"}


def new_id() -> str:
    return str(uuid.uuid4())


def clip_response(payload: dict[str, Any], list_key: str) -> dict[str, Any]:
    """Enforce the 64 KiB tool-return cap by dropping tail list entries (never truncating mid-text)."""
    items = list(payload.get(list_key, []))
    while items and utf8_len(canonical_json({**payload, list_key: items})) > LIMITS["tool_return_bytes"]:
        items.pop()
    out = {**payload, list_key: items}
    out["response_truncated"] = len(items) != len(payload.get(list_key, []))
    if utf8_len(canonical_json(out)) > LIMITS["tool_return_bytes"]:
        raise TaskError("TASK_RESULT_TOO_LARGE", "tool result exceeds return limit")
    return out


__all__ = ["EngineAdapter", "MemoryBackend", "SearchBackend", "clip_response", "new_id", "json", "sqlite3"]
