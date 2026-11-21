"""Gate 4B-2 explicit, human-governed L1-to-L3 canonical publication."""

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
    "propose_canonical_from_working_memory",
    "publish_canonical_proposal",
    "record_canonical_human_decision",
    "withdraw_canonical_knowledge",
]

SCHEMAS = get_root() / "schemas"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _id() -> str:
    return str(uuid.uuid4())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate(value: dict[str, Any], name: str) -> None:
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ContractError(f"invalid L3 envelope: {errors[0].message}")


def _begin(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")


def _authorized_citation(
    conn: sqlite3.Connection,
    workspace_id: str,
    principal_id: str,
    citation_id: str | None,
) -> tuple[str, str]:
    row = conn.execute(
        "SELECT c.citation_id,c.file_record_id,c.source_version_id FROM citation c "
        "JOIN file_acl a ON a.file_record_id=c.file_record_id AND a.workspace_id=c.workspace_id "
        "WHERE c.citation_id=? AND c.workspace_id=? AND a.principal_id=? AND a.can_read=1",
        (citation_id, workspace_id, principal_id),
    ).fetchone()
    if row is None:
        raise ContractError("authorized L3 source citation not found")
    return str(row["citation_id"]), _digest(_json(dict(row)))


def _target(
    conn: sqlite3.Connection,
    target_id: str,
    workspace_id: str,
    authority_id: str,
    namespace: str,
    subject_key: str,
) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT k.*,v.version_number,v.content_sha256 FROM canonical_knowledge k "
        "JOIN canonical_knowledge_version v ON v.version_id=k.current_version_id "
        "WHERE k.canonical_knowledge_id=? AND k.workspace_id=? AND k.workspace_authority_id=? "
        "AND k.canonical_namespace=? AND k.subject_key=? AND k.status='active'",
        (target_id, workspace_id, authority_id, namespace, subject_key),
    ).fetchone()


def _rollback_as_contract(
    conn: sqlite3.Connection, label: str, exc: sqlite3.IntegrityError
) -> ContractError:
    conn.rollback()
    return ContractError(f"{label}: {exc}")


def propose_canonical_from_working_memory(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    principal_id: str,
    working_memory_id: str,
    canonical_namespace: str,
    subject_key: str,
    workspace_authority_id: str,
    proposer_actor_id: str,
    proposer_actor_kind: str,
    idempotency_key: str,
    target_id: str | None = None,
) -> dict[str, Any]:
    if proposer_actor_kind not in {"human", "model"} or len(idempotency_key) < 16:
        raise ContractError("invalid L3 proposal input")
    if not canonical_namespace or not subject_key or not workspace_authority_id:
        raise ContractError("invalid L3 identity input")
    fingerprint = _digest(
        _json(
            {
                "working_memory_id": working_memory_id,
                "canonical_namespace": canonical_namespace,
                "subject_key": subject_key,
                "workspace_authority_id": workspace_authority_id,
                "target_id": target_id,
                "proposer_actor_id": proposer_actor_id,
                "proposer_actor_kind": proposer_actor_kind,
            }
        )
    )
    _begin(conn)
    try:
        prior = conn.execute(
            "SELECT request_fingerprint,payload_json FROM l3_promotion_proposal "
            "WHERE workspace_id=? AND principal_id=? AND idempotency_key=?",
            (workspace_id, principal_id, idempotency_key),
        ).fetchone()
        if prior is not None:
            if prior["request_fingerprint"] != fingerprint:
                raise ContractError("L3 proposal idempotency conflict")
            conn.commit()
            return json.loads(prior["payload_json"])
        now = _now()
        source = conn.execute(
            "SELECT * FROM working_memory WHERE working_memory_id=? AND workspace_id=? "
            "AND principal_id=? AND state='active' AND expires_at>?",
            (working_memory_id, workspace_id, principal_id, now),
        ).fetchone()
        if (
            source is None
            or source["provenance_category"] != "document_grounded"
            or source["verification_status"] != "citation_verified"
            or _digest(source["content"]) != source["content_sha256"]
        ):
            raise ContractError("eligible grounded L1 source not found")
        citation_id, authorization_digest = _authorized_citation(
            conn, workspace_id, principal_id, source["source_citation_id"]
        )
        observed = None
        if target_id is None:
            disposition, reason = "novel", "no_target_declared"
        else:
            observed = _target(
                conn,
                target_id,
                workspace_id,
                workspace_authority_id,
                canonical_namespace,
                subject_key,
            )
            if observed is None:
                raise ContractError("active canonical target not found in scope")
            if observed["content_sha256"] == source["content_sha256"]:
                disposition, reason = "duplicate", "exact_content_and_authority"
            else:
                disposition, reason = "unresolved", "nonidentical_target_declared"
        proposal_id, request_id, binding_id = _id(), _id(), _id()
        proposal = {
            "schema_version": "pdx_local_durable_promotion_proposal_v1",
            "proposal_id": proposal_id,
            "request_id": request_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "source_bindings": [
                {
                    "working_memory_id": working_memory_id,
                    "content_sha256": source["content_sha256"],
                    "state": "active",
                    "expires_at": source["expires_at"],
                }
            ],
            "target_kind": "l3_canonical",
            "target_id": target_id,
            "proposed_content": source["content"],
            "proposed_content_sha256": source["content_sha256"],
            "authority_kind": "workspace",
            "authority_id": workspace_authority_id,
            "provenance_category": "document_grounded",
            "verification_status": "citation_verified",
            "citation_ids": [citation_id],
            "authorization_snapshot_sha256": authorization_digest,
            "proposer_actor_id": proposer_actor_id,
            "proposer_actor_kind": proposer_actor_kind,
            "deterministic_disposition": disposition,
            "disposition_reason": reason,
            "state": "pending_review",
            "request_fingerprint": fingerprint,
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(proposal, "pdx_local_durable_promotion_proposal_v1.schema.json")
        proposal_json = _json(proposal)
        proposal_sha = _digest(proposal_json)
        binding = {
            "schema_version": "pdx_local_l3_target_binding_v1",
            "binding_id": binding_id,
            "proposal_id": proposal_id,
            "proposal_sha256": proposal_sha,
            "workspace_id": workspace_id,
            "workspace_authority_id": workspace_authority_id,
            "canonical_namespace": canonical_namespace,
            "subject_key": subject_key,
            "deterministic_disposition": disposition,
            "canonical_knowledge_id": None
            if observed is None
            else observed["canonical_knowledge_id"],
            "current_version_id": None
            if observed is None
            else observed["current_version_id"],
            "current_version_number": None
            if observed is None
            else observed["version_number"],
            "current_content_sha256": None
            if observed is None
            else observed["content_sha256"],
            "source_working_memory_id": working_memory_id,
            "source_content_sha256": source["content_sha256"],
            "citation_ids": [citation_id],
            "authorization_snapshot_sha256": authorization_digest,
            "created_at": now,
        }
        _validate(binding, "pdx_local_l3_target_binding_v1.schema.json")
        binding_json = _json(binding)
        conn.execute(
            "INSERT INTO l3_promotion_proposal VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                proposal_id,
                request_id,
                workspace_id,
                principal_id,
                target_id,
                source["content"],
                source["content_sha256"],
                workspace_authority_id,
                canonical_namespace,
                subject_key,
                "document_grounded",
                "citation_verified",
                proposer_actor_id,
                proposer_actor_kind,
                disposition,
                "pending_review",
                fingerprint,
                idempotency_key,
                proposal_json,
                proposal_sha,
                now,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO l3_promotion_source VALUES (?,?,?,?,?)",
            (
                proposal_id,
                working_memory_id,
                source["content_sha256"],
                "active",
                source["expires_at"],
            ),
        )
        conn.execute(
            "INSERT INTO l3_promotion_citation VALUES (?,?,?)",
            (proposal_id, 0, citation_id),
        )
        conn.execute(
            "INSERT INTO l3_target_binding VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                binding_id,
                proposal_id,
                proposal_sha,
                workspace_id,
                workspace_authority_id,
                canonical_namespace,
                subject_key,
                disposition,
                binding["canonical_knowledge_id"],
                binding["current_version_id"],
                binding["current_version_number"],
                binding["current_content_sha256"],
                working_memory_id,
                source["content_sha256"],
                authorization_digest,
                binding_json,
                _digest(binding_json),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO l3_target_binding_citation VALUES (?,?,?)",
            (binding_id, 0, citation_id),
        )
        conn.commit()
        return proposal
    except sqlite3.IntegrityError as exc:
        raise _rollback_as_contract(conn, "L3 proposal rejected", exc) from exc
    except Exception:
        conn.rollback()
        raise


def record_canonical_human_decision(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    principal_id: str,
    proposal_id: str,
    reviewer_actor_id: str,
    reviewer_grant_id: str,
    decision: str,
    selected_disposition: str,
    idempotency_key: str,
) -> dict[str, Any]:
    if decision not in {"approve", "reject", "cancel"} or len(idempotency_key) < 16:
        raise ContractError("invalid L3 decision input")
    fingerprint = _digest(
        _json(
            {
                "proposal_id": proposal_id,
                "reviewer_actor_id": reviewer_actor_id,
                "reviewer_grant_id": reviewer_grant_id,
                "decision": decision,
                "selected_disposition": selected_disposition,
            }
        )
    )
    _begin(conn)
    try:
        existing = conn.execute(
            "SELECT decision_fingerprint,idempotency_key,payload_json FROM l3_promotion_decision "
            "WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if existing is not None:
            if (
                existing["idempotency_key"] == idempotency_key
                and existing["decision_fingerprint"] == fingerprint
            ):
                conn.commit()
                return json.loads(existing["payload_json"])
            raise ContractError("L3 proposal already has a decision")
        proposal = conn.execute(
            "SELECT p.*,b.binding_id FROM l3_promotion_proposal p JOIN l3_target_binding b "
            "ON b.proposal_id=p.proposal_id WHERE p.proposal_id=? AND p.workspace_id=? "
            "AND p.principal_id=? AND p.state='pending_review'",
            (proposal_id, workspace_id, principal_id),
        ).fetchone()
        if proposal is None or (
            proposal["proposer_actor_kind"] == "model"
            and proposal["proposer_actor_id"] == reviewer_actor_id
        ):
            raise ContractError("eligible proposal or independent reviewer not found")
        if _digest(proposal["payload_json"]) != proposal["payload_sha256"]:
            raise ContractError("stored L3 proposal digest mismatch")
        allowed = {
            "novel": {"novel"},
            "duplicate": {"duplicate"},
            "unresolved": {"updates"},
        }[proposal["deterministic_disposition"]]
        if proposal["deterministic_disposition"] == "unresolved" and decision in {
            "reject",
            "cancel",
        }:
            allowed = {"updates", "conflicts", "unresolved"}
        if selected_disposition not in allowed:
            raise ContractError("invalid L3 decision disposition")
        grant = conn.execute(
            "SELECT g.* FROM workspace_reviewer_grant g "
            "JOIN workspace_reviewer_grant_namespace n ON n.grant_id=g.grant_id "
            "WHERE g.grant_id=? AND g.workspace_id=? AND g.reviewer_actor_id=? "
            "AND g.workspace_authority_id=? AND g.status='active' AND n.namespace=?",
            (
                reviewer_grant_id,
                workspace_id,
                reviewer_actor_id,
                proposal["workspace_authority_id"],
                proposal["canonical_namespace"],
            ),
        ).fetchone()
        if grant is None:
            raise ContractError("caller-selected active reviewer grant not found")
        now, decision_id = _now(), _id()
        envelope = {
            "schema_version": "pdx_local_promotion_decision_v1",
            "decision_id": decision_id,
            "proposal_id": proposal_id,
            "workspace_id": workspace_id,
            "proposal_sha256": proposal["payload_sha256"],
            "proposal_deterministic_disposition": proposal["deterministic_disposition"],
            "proposal_verification_status": proposal["verification_status"],
            "target_kind": "l3_canonical",
            "proposer_actor_id": proposal["proposer_actor_id"],
            "proposer_actor_kind": proposal["proposer_actor_kind"],
            "reviewer_actor_id": reviewer_actor_id,
            "actor_kind": "human",
            "decision": decision,
            "selected_disposition": selected_disposition,
            "verification_status": proposal["verification_status"],
            "authority_evidence_sha256": _digest(
                _json(
                    {
                        "grant_id": reviewer_grant_id,
                        "payload_sha256": grant["payload_sha256"],
                    }
                )
            ),
            "workspace_reviewer_grant_id": reviewer_grant_id,
            "workspace_reviewer_grant_sha256": grant["payload_sha256"],
            "rationale_code": "human_review",
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(envelope, "pdx_local_promotion_decision_v1.schema.json")
        payload = _json(envelope)
        conn.execute(
            "INSERT INTO l3_promotion_decision VALUES (?,?,?,?,?,'human',?,?,?,?,?,?,?,?,?,?,?)",
            (
                decision_id,
                proposal_id,
                workspace_id,
                principal_id,
                reviewer_actor_id,
                decision,
                selected_disposition,
                proposal["verification_status"],
                proposal["payload_sha256"],
                reviewer_grant_id,
                grant["payload_sha256"],
                fingerprint,
                idempotency_key,
                payload,
                _digest(payload),
                now,
            ),
        )
        conn.commit()
        return envelope
    except sqlite3.IntegrityError as exc:
        raise _rollback_as_contract(conn, "L3 decision rejected", exc) from exc
    except Exception:
        conn.rollback()
        raise


def publish_canonical_proposal(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    principal_id: str,
    proposal_id: str,
    decision_id: str,
    requesting_actor_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    if len(idempotency_key) < 16:
        raise ContractError("invalid L3 publication input")
    fingerprint = _digest(
        _json(
            {
                "proposal_id": proposal_id,
                "decision_id": decision_id,
                "requesting_actor_id": requesting_actor_id,
            }
        )
    )
    _begin(conn)
    try:
        replay = conn.execute(
            "SELECT r.request_fingerprint,x.receipt_json FROM l3_publication_request r "
            "LEFT JOIN l3_publication_receipt x ON x.publication_request_id=r.publication_request_id "
            "WHERE r.workspace_id=? AND r.principal_id=? AND r.idempotency_key=?",
            (workspace_id, principal_id, idempotency_key),
        ).fetchone()
        if replay is not None:
            if (
                replay["request_fingerprint"] != fingerprint
                or replay["receipt_json"] is None
            ):
                raise ContractError("L3 publication idempotency conflict")
            conn.commit()
            return json.loads(replay["receipt_json"])
        row = conn.execute(
            "SELECT p.*,p.payload_sha256 AS proposal_payload_sha256,"
            "p.payload_json AS proposal_payload_json,"
            "d.decision_id,d.selected_disposition,d.payload_sha256 AS decision_sha256,"
            "d.payload_json AS decision_payload_json,"
            "d.reviewer_actor_id,d.workspace_reviewer_grant_id,"
            "d.workspace_reviewer_grant_sha256,b.binding_id,"
            "b.canonical_knowledge_id,b.current_version_id,b.current_version_number,"
            "b.current_content_sha256,b.authorization_snapshot_sha256,"
            "b.payload_json AS binding_payload_json,b.payload_sha256 AS binding_payload_sha256 "
            "FROM l3_promotion_proposal p JOIN l3_promotion_decision d ON d.proposal_id=p.proposal_id "
            "JOIN l3_target_binding b ON b.proposal_id=p.proposal_id "
            "WHERE p.proposal_id=? AND p.workspace_id=? AND p.principal_id=? "
            "AND p.state='approved' AND d.decision_id=? AND d.decision='approve'",
            (proposal_id, workspace_id, principal_id, decision_id),
        ).fetchone()
        if row is None:
            raise ContractError("approved L3 proposal not found")
        stored_digests = (
            (row["proposal_payload_json"], row["proposal_payload_sha256"]),
            (row["decision_payload_json"], row["decision_sha256"]),
            (row["binding_payload_json"], row["binding_payload_sha256"]),
        )
        if any(_digest(payload) != digest for payload, digest in stored_digests):
            raise ContractError("stored L3 governance digest mismatch")
        source = conn.execute(
            "SELECT w.*,s.content_sha256 AS observed_digest FROM l3_promotion_source s "
            "JOIN working_memory w ON w.working_memory_id=s.working_memory_id "
            "WHERE s.proposal_id=? AND w.workspace_id=? AND w.principal_id=?",
            (proposal_id, workspace_id, principal_id),
        ).fetchone()
        citation = conn.execute(
            "SELECT citation_id FROM l3_promotion_citation WHERE proposal_id=? ORDER BY ordinal",
            (proposal_id,),
        ).fetchone()
        stale = (
            source is None
            or citation is None
            or source["state"] != "active"
            or source["expires_at"] <= _now()
            or source["content_sha256"] != row["proposed_content_sha256"]
            or _digest(source["content"]) != source["content_sha256"]
        )
        if not stale:
            try:
                _, auth = _authorized_citation(
                    conn, workspace_id, principal_id, citation["citation_id"]
                )
                stale = auth != row["authorization_snapshot_sha256"]
            except ContractError:
                stale = True
        grant = conn.execute(
            "SELECT 1 FROM workspace_reviewer_grant g JOIN workspace_reviewer_grant_namespace n "
            "ON n.grant_id=g.grant_id WHERE g.grant_id=? AND g.status='active' "
            "AND g.payload_sha256=? AND g.workspace_id=? AND g.workspace_authority_id=? "
            "AND n.namespace=?",
            (
                row["workspace_reviewer_grant_id"],
                row["workspace_reviewer_grant_sha256"],
                workspace_id,
                row["workspace_authority_id"],
                row["canonical_namespace"],
            ),
        ).fetchone()
        stale = stale or grant is None
        selected = row["selected_disposition"]
        target = None
        if selected in {"duplicate", "updates"}:
            target = (
                _target(
                    conn,
                    row["canonical_knowledge_id"],
                    workspace_id,
                    row["workspace_authority_id"],
                    row["canonical_namespace"],
                    row["subject_key"],
                )
                if row["canonical_knowledge_id"]
                else None
            )
            stale = (
                stale
                or target is None
                or target["current_version_id"] != row["current_version_id"]
                or target["version_number"] != row["current_version_number"]
                or target["content_sha256"] != row["current_content_sha256"]
            )
        if selected == "novel" and not stale:
            collision = conn.execute(
                "SELECT 1 FROM canonical_knowledge WHERE workspace_id=? AND workspace_authority_id=? "
                "AND canonical_namespace=? AND subject_key=?",
                (
                    workspace_id,
                    row["workspace_authority_id"],
                    row["canonical_namespace"],
                    row["subject_key"],
                ),
            ).fetchone()
            stale = collision is not None
        publication_request_id, receipt_id, now = _id(), _id(), _now()
        request_envelope = {
            "schema_version": "pdx_local_durable_publication_request_v1",
            "publication_request_id": publication_request_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "proposal_id": proposal_id,
            "decision_id": decision_id,
            "requesting_actor_id": requesting_actor_id,
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(
            request_envelope, "pdx_local_durable_publication_request_v1.schema.json"
        )
        request_json = _json(request_envelope)
        conn.execute(
            "INSERT INTO l3_publication_request VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                publication_request_id,
                proposal_id,
                decision_id,
                workspace_id,
                principal_id,
                requesting_actor_id,
                fingerprint,
                idempotency_key,
                request_json,
                _digest(request_json),
                now,
            ),
        )
        terminal = "stale"
        target_id: str | None = row["canonical_knowledge_id"]
        version_id: str | None = None
        created: list[str] = []
        superseded: list[str] = []
        if not stale and selected == "novel":
            terminal, target_id, version_id = "published_new", _id(), _id()
            conn.execute(
                "INSERT INTO canonical_knowledge VALUES (?,?,?,?,?,?, 'active',?,?)",
                (
                    target_id,
                    workspace_id,
                    row["workspace_authority_id"],
                    row["canonical_namespace"],
                    row["subject_key"],
                    version_id,
                    now,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO canonical_knowledge_version VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    version_id,
                    target_id,
                    1,
                    workspace_id,
                    row["proposed_content"],
                    row["proposed_content_sha256"],
                    "document_grounded",
                    "citation_verified",
                    row["workspace_authority_id"],
                    row["reviewer_actor_id"],
                    row["workspace_reviewer_grant_sha256"],
                    None,
                    receipt_id,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO canonical_knowledge_version_citation VALUES (?,?,?)",
                (version_id, 0, citation["citation_id"]),
            )
            conn.execute(
                "INSERT INTO canonical_knowledge_event VALUES (?,?,?,?,?,?)",
                (_id(), target_id, version_id, "created", "{}", now),
            )
            created = [target_id, version_id]
        elif not stale and selected == "duplicate":
            terminal = "duplicate_no_op"
        elif not stale and selected == "updates":
            terminal, version_id = "published_update", _id()
            conn.execute(
                "INSERT INTO canonical_knowledge_version VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    version_id,
                    target_id,
                    row["current_version_number"] + 1,
                    workspace_id,
                    row["proposed_content"],
                    row["proposed_content_sha256"],
                    "document_grounded",
                    "citation_verified",
                    row["workspace_authority_id"],
                    row["reviewer_actor_id"],
                    row["workspace_reviewer_grant_sha256"],
                    row["current_version_id"],
                    receipt_id,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO canonical_knowledge_version_citation VALUES (?,?,?)",
                (version_id, 0, citation["citation_id"]),
            )
            conn.execute(
                "INSERT INTO canonical_knowledge_event VALUES (?,?,?,?,?,?)",
                (_id(), target_id, version_id, "version_published", "{}", now),
            )
            created, superseded = [version_id], [row["current_version_id"]]
        receipt = {
            "schema_version": "pdx_local_durable_publication_receipt_v1",
            "receipt_id": receipt_id,
            "workspace_id": workspace_id,
            "proposal_id": proposal_id,
            "decision_id": decision_id,
            "publication_request_id": publication_request_id,
            "proposal_sha256": row["proposal_payload_sha256"],
            "decision_sha256": row["decision_sha256"],
            "decision_verification_status": row["verification_status"],
            "target_kind": "l3_canonical",
            "target_id": target_id,
            "target_version_id": version_id,
            "target_content_sha256": row["proposed_content_sha256"],
            "provenance_category": "document_grounded",
            "verification_status": "citation_verified",
            "authority_id": row["workspace_authority_id"],
            "authority_binding_sha256": row["binding_payload_sha256"],
            "disposition": selected,
            "terminal_result": terminal,
            "created_target_ids": created,
            "superseded_target_ids": superseded,
            "citation_ids": [citation["citation_id"]],
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(receipt, "pdx_local_durable_publication_receipt_v1.schema.json")
        receipt_json = _json(receipt)
        conn.execute(
            "INSERT INTO l3_publication_receipt VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                publication_request_id,
                proposal_id,
                decision_id,
                row["binding_id"],
                workspace_id,
                principal_id,
                terminal,
                selected,
                target_id,
                version_id,
                row["proposed_content_sha256"],
                row["proposal_payload_sha256"],
                row["decision_sha256"],
                "citation_verified",
                row["workspace_authority_id"],
                row["binding_payload_sha256"],
                _json(created),
                _json(superseded),
                fingerprint,
                idempotency_key,
                receipt_json,
                _digest(receipt_json),
                now,
            ),
        )
        conn.commit()
        return receipt
    except sqlite3.IntegrityError as exc:
        raise _rollback_as_contract(conn, "L3 publication rejected", exc) from exc
    except Exception:
        conn.rollback()
        raise


def withdraw_canonical_knowledge(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    canonical_knowledge_id: str,
    observed_current_version_id: str,
    reviewer_actor_id: str,
    reviewer_grant_id: str,
    reason_code: str,
    idempotency_key: str,
) -> dict[str, Any]:
    if len(idempotency_key) < 16 or not reason_code:
        raise ContractError("invalid canonical withdrawal input")
    _begin(conn)
    try:
        identity = conn.execute(
            "SELECT * FROM canonical_knowledge WHERE canonical_knowledge_id=? AND workspace_id=?",
            (canonical_knowledge_id, workspace_id),
        ).fetchone()
        if identity is None:
            raise ContractError("canonical withdrawal target not found")
        fingerprint = _digest(
            _json(
                {
                    "canonical_knowledge_id": canonical_knowledge_id,
                    "observed_current_version_id": observed_current_version_id,
                    "reviewer_actor_id": reviewer_actor_id,
                    "reviewer_grant_id": reviewer_grant_id,
                    "reason_code": reason_code,
                }
            )
        )
        replay = conn.execute(
            "SELECT request_fingerprint,withdrawal_request_id FROM canonical_withdrawal_request "
            "WHERE workspace_id=? AND workspace_authority_id=? AND idempotency_key=?",
            (workspace_id, identity["workspace_authority_id"], idempotency_key),
        ).fetchone()
        if replay is not None:
            if replay["request_fingerprint"] != fingerprint:
                raise ContractError("withdrawal idempotency conflict")
            receipt = conn.execute(
                "SELECT receipt_json FROM canonical_withdrawal_receipt WHERE withdrawal_request_id=?",
                (replay["withdrawal_request_id"],),
            ).fetchone()
            if receipt is None:
                raise ContractError("incomplete withdrawal replay")
            conn.commit()
            return json.loads(receipt["receipt_json"])
        if (
            identity["status"] != "active"
            or identity["current_version_id"] != observed_current_version_id
        ):
            raise ContractError("active canonical withdrawal target not found")
        grant = conn.execute(
            "SELECT g.* FROM workspace_reviewer_grant g JOIN workspace_reviewer_grant_namespace n "
            "ON n.grant_id=g.grant_id WHERE g.grant_id=? AND g.workspace_id=? "
            "AND g.reviewer_actor_id=? AND g.workspace_authority_id=? AND g.status='active' "
            "AND n.namespace=?",
            (
                reviewer_grant_id,
                workspace_id,
                reviewer_actor_id,
                identity["workspace_authority_id"],
                identity["canonical_namespace"],
            ),
        ).fetchone()
        if grant is None:
            raise ContractError("caller-selected withdrawal grant not found")
        request_id, receipt_id, now = _id(), _id(), _now()
        request = {
            "schema_version": "pdx_local_canonical_withdrawal_request_v1",
            "withdrawal_request_id": request_id,
            "workspace_id": workspace_id,
            "canonical_knowledge_id": canonical_knowledge_id,
            "observed_current_version_id": observed_current_version_id,
            "canonical_namespace": identity["canonical_namespace"],
            "workspace_authority_id": identity["workspace_authority_id"],
            "reviewer_actor_id": reviewer_actor_id,
            "reviewer_actor_kind": "human",
            "workspace_reviewer_grant_id": reviewer_grant_id,
            "workspace_reviewer_grant_sha256": grant["payload_sha256"],
            "reason_code": reason_code,
            "idempotency_key": idempotency_key,
            "request_fingerprint": fingerprint,
            "created_at": now,
        }
        _validate(request, "pdx_local_canonical_withdrawal_request_v1.schema.json")
        request_json = _json(request)
        conn.execute(
            "INSERT INTO canonical_withdrawal_request VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request_id,
                workspace_id,
                canonical_knowledge_id,
                observed_current_version_id,
                identity["canonical_namespace"],
                identity["workspace_authority_id"],
                reviewer_actor_id,
                reviewer_grant_id,
                grant["payload_sha256"],
                reason_code,
                idempotency_key,
                fingerprint,
                request_json,
                _digest(request_json),
                now,
            ),
        )
        receipt = {
            "schema_version": "pdx_local_canonical_withdrawal_receipt_v1",
            "withdrawal_receipt_id": receipt_id,
            "withdrawal_request_id": request_id,
            "workspace_id": workspace_id,
            "canonical_knowledge_id": canonical_knowledge_id,
            "canonical_namespace": identity["canonical_namespace"],
            "workspace_authority_id": identity["workspace_authority_id"],
            "terminal_result": "withdrawn",
            "status_before": "active",
            "status_after": "withdrawn",
            "current_version_id_before": observed_current_version_id,
            "current_version_id_after": None,
            "workspace_reviewer_grant_id": reviewer_grant_id,
            "workspace_reviewer_grant_sha256": grant["payload_sha256"],
            "identity_snapshot_sha256": _digest(_json(dict(identity))),
            "mutation_applied": True,
            "idempotency_key": idempotency_key,
            "created_at": now,
        }
        _validate(receipt, "pdx_local_canonical_withdrawal_receipt_v1.schema.json")
        receipt_json = _json(receipt)
        conn.execute(
            "INSERT INTO canonical_withdrawal_receipt VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                request_id,
                workspace_id,
                canonical_knowledge_id,
                identity["workspace_authority_id"],
                "withdrawn",
                "active",
                "withdrawn",
                observed_current_version_id,
                None,
                reviewer_grant_id,
                grant["payload_sha256"],
                receipt["identity_snapshot_sha256"],
                1,
                idempotency_key,
                receipt_json,
                _digest(receipt_json),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO canonical_knowledge_event VALUES (?,?,?,?,?,?)",
            (
                _id(),
                canonical_knowledge_id,
                observed_current_version_id,
                "withdrawn",
                "{}",
                now,
            ),
        )
        conn.commit()
        return receipt
    except sqlite3.IntegrityError as exc:
        raise _rollback_as_contract(conn, "canonical withdrawal rejected", exc) from exc
    except Exception:
        conn.rollback()
        raise
