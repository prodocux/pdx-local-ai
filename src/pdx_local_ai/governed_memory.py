"""Gate 4B-1 explicit, human-governed L1-to-L2v2 publication."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .validation import ContractError
from .paths import get_root

__all__ = [
    "propose_from_working_memory",
    "publish_approved_proposal",
    "record_human_decision",
    "request_publication",
]

KINDS = {"fact", "preference", "decision", "task", "note"}
SCHEMA_ROOT = get_root() / "schemas"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _id() -> str:
    return str(uuid.uuid4())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate(envelope: dict[str, Any], schema_name: str) -> None:
    schema = json.loads((SCHEMA_ROOT / schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(envelope),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ContractError(f"invalid governed envelope: {errors[0].message}")


def _begin(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")


def _replay(conn: sqlite3.Connection, table: str, workspace: str, principal: str,
            key: str, fingerprint_column: str, fingerprint: str,
            json_column: str) -> dict[str, Any] | None:
    row = conn.execute(
        f"SELECT {fingerprint_column},{json_column} FROM {table} "
        "WHERE workspace_id=? AND principal_id=? AND idempotency_key=?",
        (workspace, principal, key),
    ).fetchone()
    if row is None:
        return None
    if row[fingerprint_column] != fingerprint:
        raise ContractError("governed idempotency conflict")
    return json.loads(row[json_column])


def _authorized_citation(conn: sqlite3.Connection, workspace: str, principal: str,
                         citation_id: str | None) -> str:
    row = conn.execute(
        "SELECT c.citation_id,c.file_record_id,c.source_version_id FROM citation c "
        "JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id "
        "WHERE c.citation_id=? AND c.workspace_id=? AND a.principal_id=? AND a.can_read=1",
        (citation_id, workspace, principal),
    ).fetchone()
    if row is None:
        raise ContractError("authorized source citation not found")
    return _digest(_json(dict(row)))


def _target(conn: sqlite3.Connection, contract: str, memory_id: str,
            workspace: str, principal: str) -> sqlite3.Row | None:
    if contract == "pdx_local_memory_record_v1":
        return conn.execute(
            "SELECT memory_id,content_sha256,status,principal_id AS authority_id "
            "FROM memory_record WHERE memory_id=? AND workspace_id=? AND principal_id=?",
            (memory_id, workspace, principal),
        ).fetchone()
    if contract == "pdx_local_memory_record_v2":
        return conn.execute(
            "SELECT m.memory_id,m.content_sha256,m.status,b.authority_id "
            "FROM memory_record_v2 m JOIN memory_source_binding b "
            "ON b.source_binding_id=m.source_binding_id WHERE m.memory_id=? "
            "AND m.workspace_id=? AND m.principal_id=?",
            (memory_id, workspace, principal),
        ).fetchone()
    raise ContractError("unsupported target contract")


def propose_from_working_memory(
    conn: sqlite3.Connection, *, workspace_id: str, principal_id: str,
    working_memory_id: str, requested_memory_kind: str,
    proposer_actor_id: str, proposer_actor_kind: str, idempotency_key: str,
    target_id: str | None = None, target_contract_version: str | None = None,
) -> dict[str, Any]:
    if requested_memory_kind not in KINDS or proposer_actor_kind not in {"human", "model"}:
        raise ContractError("invalid governed proposal input")
    if len(idempotency_key) < 16 or not proposer_actor_id:
        raise ContractError("invalid governed proposal input")
    if (target_id is None) != (target_contract_version is None):
        raise ContractError("target id and contract must be supplied together")
    fingerprint = _digest(_json({
        "working_memory_id": working_memory_id, "requested_memory_kind": requested_memory_kind,
        "proposer_actor_id": proposer_actor_id, "proposer_actor_kind": proposer_actor_kind,
        "target_id": target_id, "target_contract_version": target_contract_version,
    }))
    _begin(conn)
    try:
        replay = _replay(conn, "governed_promotion_proposal", workspace_id, principal_id,
                         idempotency_key, "request_fingerprint", fingerprint, "payload_json")
        if replay is not None:
            conn.commit()
            return replay
        now = _now()
        source = conn.execute(
            "SELECT * FROM working_memory WHERE working_memory_id=? AND workspace_id=? "
            "AND principal_id=? AND state='active' AND expires_at>?",
            (working_memory_id, workspace_id, principal_id, now),
        ).fetchone()
        if source is None or _digest(source["content"]) != source["content_sha256"]:
            raise ContractError("eligible working memory not found")
        citation_ids: list[str] = []
        auth_digest: str | None = None
        if source["provenance_category"] == "document_grounded":
            auth_digest = _authorized_citation(
                conn, workspace_id, principal_id, source["source_citation_id"]
            )
            citation_ids = [source["source_citation_id"]]
        authority_id = principal_id
        if target_id is None:
            disposition, reason = "novel", "no_target_declared"
        else:
            prior = _target(
                conn, str(target_contract_version), target_id, workspace_id, principal_id
            )
            if prior is None or prior["status"] != "active":
                raise ContractError("active proposal target not found in scope")
            exact = (
                prior["content_sha256"] == source["content_sha256"]
                and prior["authority_id"] == authority_id
            )
            disposition, reason = (
                ("duplicate", "exact_content_and_authority") if exact
                else ("unresolved", "nonidentical_target_declared")
            )
        proposal_id, request_id = _id(), _id()
        envelope: dict[str, Any] = {
            "schema_version": "pdx_local_durable_promotion_proposal_v1",
            "proposal_id": proposal_id, "request_id": request_id,
            "workspace_id": workspace_id, "principal_id": principal_id,
            "source_bindings": [{"working_memory_id": working_memory_id,
                                 "content_sha256": source["content_sha256"],
                                 "state": "active", "expires_at": source["expires_at"]}],
            "target_kind": "l2_durable", "target_id": target_id,
            "proposed_content": source["content"],
            "proposed_content_sha256": source["content_sha256"],
            "authority_kind": "principal", "authority_id": authority_id,
            "provenance_category": source["provenance_category"],
            "verification_status": source["verification_status"],
            "proposer_actor_id": proposer_actor_id,
            "proposer_actor_kind": proposer_actor_kind,
            "deterministic_disposition": disposition, "disposition_reason": reason,
            "state": "pending_review", "request_fingerprint": fingerprint,
            "idempotency_key": idempotency_key, "created_at": now,
        }
        if citation_ids:
            envelope["citation_ids"] = citation_ids
            envelope["authorization_snapshot_sha256"] = auth_digest
        _validate(envelope, "pdx_local_durable_promotion_proposal_v1.schema.json")
        payload = _json(envelope)
        conn.execute(
            "INSERT INTO governed_promotion_proposal VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (proposal_id, request_id, workspace_id, principal_id, target_id,
             target_contract_version, source["content"], source["content_sha256"],
             requested_memory_kind, authority_id, source["provenance_category"],
             source["verification_status"], proposer_actor_id, proposer_actor_kind,
             disposition, "pending_review", fingerprint, idempotency_key, payload,
             _digest(payload), now, now),
        )
        conn.execute(
            "INSERT INTO governed_promotion_source VALUES (?,?,?,?,?,?)",
            (proposal_id, 0, working_memory_id, source["content_sha256"], "active",
             source["expires_at"]),
        )
        conn.commit()
        return envelope
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ContractError(f"governed proposal rejected: {exc}") from exc
    except Exception:
        conn.rollback()
        raise


def record_human_decision(
    conn: sqlite3.Connection, *, workspace_id: str, principal_id: str,
    proposal_id: str, reviewer_actor_id: str, decision: str,
    selected_disposition: str, idempotency_key: str,
) -> dict[str, Any]:
    if decision not in {"approve", "reject", "cancel"} or len(idempotency_key) < 16:
        raise ContractError("invalid governed decision input")
    fingerprint = _digest(_json({"proposal_id": proposal_id, "reviewer_actor_id": reviewer_actor_id,
                                 "decision": decision,
                                 "selected_disposition": selected_disposition}))
    _begin(conn)
    try:
        replay = _replay(conn, "governed_promotion_decision", workspace_id, principal_id,
                         idempotency_key, "decision_fingerprint", fingerprint, "payload_json")
        if replay is not None:
            conn.commit()
            return replay
        proposal = conn.execute(
            "SELECT * FROM governed_promotion_proposal WHERE proposal_id=? AND workspace_id=? "
            "AND principal_id=? AND state IN ('pending_review','approved')",
            (proposal_id, workspace_id, principal_id),
        ).fetchone()
        if proposal is None or (
            proposal["proposer_actor_kind"] == "model"
            and proposal["proposer_actor_id"] == reviewer_actor_id
        ):
            raise ContractError("eligible proposal or independent reviewer not found")
        allowed = {"novel": {"novel"}, "duplicate": {"duplicate"},
                   "unresolved": {"updates"}}[proposal["deterministic_disposition"]]
        if proposal["deterministic_disposition"] == "unresolved" and decision in {
            "reject", "cancel"
        }:
            allowed = {"updates", "conflicts", "unresolved"}
        if selected_disposition not in allowed:
            raise ContractError("unsupported decision disposition for Gate 4B-1")
        now, decision_id = _now(), _id()
        envelope = {
            "schema_version": "pdx_local_promotion_decision_v1",
            "decision_id": decision_id, "proposal_id": proposal_id,
            "workspace_id": workspace_id, "proposal_sha256": proposal["payload_sha256"],
            "proposal_deterministic_disposition": proposal["deterministic_disposition"],
            "proposal_verification_status": proposal["verification_status"],
            "target_kind": "l2_durable", "proposer_actor_id": proposal["proposer_actor_id"],
            "proposer_actor_kind": proposal["proposer_actor_kind"],
            "reviewer_actor_id": reviewer_actor_id, "actor_kind": "human",
            "decision": decision, "selected_disposition": selected_disposition,
            "verification_status": proposal["verification_status"],
            "authority_evidence_sha256": _digest(proposal["authority_id"]),
            "rationale_code": "human_review", "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(envelope, "pdx_local_promotion_decision_v1.schema.json")
        payload = _json(envelope)
        conn.execute(
            "INSERT INTO governed_promotion_decision VALUES (?,?,?,?,?,'human',?,?,?,?,?,?,?,?,?)",
            (decision_id, proposal_id, workspace_id, principal_id, reviewer_actor_id,
             decision, selected_disposition, proposal["verification_status"],
             proposal["payload_sha256"], fingerprint, idempotency_key, payload,
             _digest(payload), now),
        )
        conn.commit()
        return envelope
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ContractError(f"governed decision rejected: {exc}") from exc
    except Exception:
        conn.rollback()
        raise


def request_publication(
    conn: sqlite3.Connection, *, workspace_id: str, principal_id: str,
    proposal_id: str, decision_id: str, requesting_actor_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    fingerprint = _digest(_json({"proposal_id": proposal_id, "decision_id": decision_id,
                                 "requesting_actor_id": requesting_actor_id}))
    _begin(conn)
    try:
        replay = _replay(conn, "governed_publication_request", workspace_id, principal_id,
                         idempotency_key, "request_fingerprint", fingerprint, "payload_json")
        if replay is not None:
            conn.commit()
            return replay
        row = conn.execute(
            "SELECT d.decision,d.selected_disposition FROM governed_promotion_decision d "
            "JOIN governed_promotion_proposal p ON p.proposal_id=d.proposal_id "
            "WHERE d.decision_id=? AND d.proposal_id=? AND d.workspace_id=? "
            "AND d.principal_id=? AND d.decision IN ('approve','reject')",
            (decision_id, proposal_id, workspace_id, principal_id),
        ).fetchone()
        if row is None:
            raise ContractError("publishable decision not found")
        if row["decision"] == "reject" and row["selected_disposition"] in {
            "conflicts", "unresolved"
        }:
            raise ContractError("rejected conflict or unresolved decision is terminal")
        now, request_id = _now(), _id()
        envelope = {
            "schema_version": "pdx_local_durable_publication_request_v1",
            "publication_request_id": request_id, "workspace_id": workspace_id,
            "principal_id": principal_id, "proposal_id": proposal_id,
            "decision_id": decision_id, "requesting_actor_id": requesting_actor_id,
            "idempotency_key": idempotency_key, "created_at": now,
        }
        _validate(envelope, "pdx_local_durable_publication_request_v1.schema.json")
        payload = _json(envelope)
        conn.execute(
            "INSERT INTO governed_publication_request VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (request_id, proposal_id, decision_id, workspace_id, principal_id,
             requesting_actor_id, fingerprint, idempotency_key, payload,
             _digest(payload), now),
        )
        conn.commit()
        return envelope
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ContractError(f"governed publication request rejected: {exc}") from exc
    except Exception:
        conn.rollback()
        raise


def publish_approved_proposal(
    conn: sqlite3.Connection, *, workspace_id: str, principal_id: str,
    publication_request_id: str, idempotency_key: str,
) -> dict[str, Any]:
    fingerprint = _digest(_json({"publication_request_id": publication_request_id}))
    _begin(conn)
    try:
        replay = _replay(conn, "governed_publication_receipt_v2", workspace_id, principal_id,
                         idempotency_key, "publication_fingerprint", fingerprint,
                         "receipt_json")
        if replay is not None:
            conn.commit()
            return replay
        row = conn.execute(
            "SELECT p.*,d.decision_id,d.decision,d.selected_disposition,d.payload_sha256 AS "
            "decision_sha256,r.publication_request_id FROM governed_publication_request r "
            "JOIN governed_promotion_proposal p ON p.proposal_id=r.proposal_id "
            "JOIN governed_promotion_decision d ON d.decision_id=r.decision_id "
            "WHERE r.publication_request_id=? AND r.workspace_id=? AND r.principal_id=?",
            (publication_request_id, workspace_id, principal_id),
        ).fetchone()
        if row is None:
            raise ContractError("publication request not found")
        now, receipt_id = _now(), _id()
        terminal = "rejected" if row["decision"] == "reject" else ""
        source = conn.execute(
            "SELECT w.*,s.content_sha256 AS observed_digest,s.expires_at AS observed_expires "
            "FROM governed_promotion_source s JOIN working_memory w "
            "ON w.working_memory_id=s.working_memory_id WHERE s.proposal_id=?",
            (row["proposal_id"],),
        ).fetchone()
        source_valid = source is not None and source["state"] == "active" and (
            source["expires_at"] > now and source["content_sha256"] == row["proposed_content_sha256"]
            and source["observed_digest"] == row["proposed_content_sha256"]
            and source["workspace_id"] == workspace_id and source["principal_id"] == principal_id
        )
        auth_digest = None
        if source_valid and row["provenance_category"] == "document_grounded":
            try:
                auth_digest = _authorized_citation(
                    conn, workspace_id, principal_id, source["source_citation_id"]
                )
            except ContractError:
                source_valid = False
        if row["decision"] == "approve" and not source_valid:
            terminal = "stale"
        prior = None
        if row["target_id"] is not None:
            prior = _target(conn, row["target_contract_version"], row["target_id"],
                            workspace_id, principal_id)
        collision_v2 = conn.execute(
            "SELECT m.memory_id FROM memory_record_v2 m JOIN memory_source_binding b "
            "ON b.source_binding_id=m.source_binding_id WHERE m.workspace_id=? "
            "AND m.principal_id=? AND m.status='active' AND m.content_sha256=? "
            "AND b.authority_id=? LIMIT 1",
            (workspace_id, principal_id, row["proposed_content_sha256"], row["authority_id"]),
        ).fetchone()
        collision_v1 = conn.execute(
            "SELECT memory_id FROM memory_record WHERE workspace_id=? AND principal_id=? "
            "AND status='active' AND content_sha256=? LIMIT 1",
            (workspace_id, principal_id, row["proposed_content_sha256"]),
        ).fetchone()
        collision = collision_v2 or collision_v1
        selected = row["selected_disposition"]
        if row["decision"] == "approve" and terminal != "stale":
            if selected == "novel":
                terminal = "stale" if collision else "published_new"
            elif selected == "duplicate":
                exact = prior is not None and prior["status"] == "active" and (
                    prior["content_sha256"] == row["proposed_content_sha256"]
                    and prior["authority_id"] == row["authority_id"]
                )
                terminal = "duplicate_no_op" if exact else "stale"
            elif selected == "updates":
                terminal = "published_update" if prior is not None and prior["status"] == "active" else "stale"
        if selected not in {"novel", "duplicate", "updates"}:
            raise ContractError("decision disposition cannot be represented by publication receipt")
        disposition = selected
        memory_id = binding_id = None
        created: list[dict[str, str]] = []
        superseded: list[dict[str, str]] = []
        if terminal in {"published_new", "published_update"}:
            memory_id, binding_id = _id(), _id()
            supersedes_contract = row["target_contract_version"] if terminal == "published_update" else None
            supersedes_id = row["target_id"] if terminal == "published_update" else None
            conn.execute(
                "INSERT INTO memory_record_v2 VALUES (?,?,?,?,?,?,'active',1.0,0.5,?,?,?,?,?)",
                (memory_id, workspace_id, principal_id, row["memory_kind"],
                 row["proposed_content"], row["proposed_content_sha256"], binding_id,
                 supersedes_contract, supersedes_id, now, now),
            )
            conn.execute(
                "INSERT INTO memory_source_binding VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (binding_id, memory_id, workspace_id, principal_id,
                 row["provenance_category"], row["verification_status"], auth_digest,
                 row["authority_id"], row["decision_id"], receipt_id, now),
            )
            conn.execute(
                "INSERT INTO memory_source_binding_working VALUES (?,?,?,?,?,?)",
                (binding_id, 0, source["working_memory_id"], source["content_sha256"],
                 "active", source["expires_at"]),
            )
            if row["provenance_category"] == "document_grounded":
                conn.execute(
                    "INSERT INTO memory_source_binding_citation VALUES (?,?,?)",
                    (binding_id, 0, source["source_citation_id"]),
                )
            created = [{"content_contract_version": "pdx_local_memory_record_v2",
                        "memory_id": memory_id}]
            if supersedes_id:
                superseded = [{"content_contract_version": supersedes_contract,
                               "memory_id": supersedes_id}]
        envelope = {
            "schema_version": "pdx_local_durable_publication_receipt_v2",
            "receipt_id": receipt_id, "workspace_id": workspace_id,
            "proposal_id": row["proposal_id"], "decision_id": row["decision_id"],
            "publication_request_id": publication_request_id,
            "proposal_sha256": row["payload_sha256"],
            "decision_sha256": row["decision_sha256"],
            "decision_verification_status": row["verification_status"],
            "verification_status": row["verification_status"],
            "target_content_contract_version": "pdx_local_memory_record_v2",
            "target_id": memory_id, "source_binding_id": binding_id,
            "target_content_sha256": row["proposed_content_sha256"],
            "provenance_category": row["provenance_category"],
            "authority_id": row["authority_id"], "disposition": disposition,
            "terminal_result": terminal, "created_targets": created,
            "superseded_targets": superseded, "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(envelope, "pdx_local_durable_publication_receipt_v2.schema.json")
        payload = _json(envelope)
        conn.execute(
            "INSERT INTO governed_publication_receipt_v2 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (receipt_id, publication_request_id, row["proposal_id"], row["decision_id"],
             workspace_id, principal_id, terminal, disposition, memory_id, binding_id,
             row["target_contract_version"] if terminal == "published_update" else None,
             row["target_id"] if terminal == "published_update" else None,
             row["payload_sha256"], row["decision_sha256"], row["verification_status"],
             fingerprint, idempotency_key, payload, _digest(payload), now),
        )
        if terminal in {"published_new", "published_update"}:
            conn.execute(
                "INSERT INTO memory_v2_event VALUES (?,?,?,?,?,'{}',?)",
                (_id(), memory_id, workspace_id, principal_id, "created", now),
            )
        conn.commit()
        return envelope
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ContractError(f"governed publication rejected: {exc}") from exc
    except Exception:
        conn.rollback()
        raise
