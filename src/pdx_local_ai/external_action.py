"""One external send per subject, through the Engine external-operation profile.

Local candidate files stay on ArtifactRuntime. This module does not start Farpals,
does not replace a provider key after an unknown result, and does not claim
exactly-once delivery. The provider profile is manual_only and has no query
adapter, so a returned adapter call is still needs_review until a person
reconciles it. A timeout or exception leaves that same operation in needs review.

Each subject records its own first-seen time. Replays of that subject keep the
original freshness and authorization. A later subject takes the clock at its own
first perform, so a database older than 25 seconds can still accept new work.
The anchor is written in the same perform that submits. The Engine freshness
window cannot exceed 30 seconds, so this host does not offer a separate step
that creates a subject and submits it an hour later.

_HMAC is the local workflow-lease constant the Engine requires. It is not a
provider credential and does not authenticate the external send.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any, Callable

import rfc8785

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_PAYLOAD_SCHEMA_ID = "local-external-action-payload"
_PAYLOAD_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["action", "body"],
    "properties": {
        "action": {"type": "string", "minLength": 1, "maxLength": 64},
        "body": {"type": "object"},
    },
}
_BUDGETS = {
    "max_query_calls": 20,
    "max_query_execution_seconds": 600,
    "max_scheduling_seconds": 86400,
    "max_observations": 64,
    "max_evidence_bytes": 1048576,
    "max_manual_records_per_case": 16,
    "max_manual_bytes_per_case": 1048576,
}
# Local workflow-lease bytes. Not a provider key and not an external credential.
_HMAC = b"pdx-local-external-host-hmac-v1!"
_TOOL = "external-action"


class ExternalActionError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, UTC).isoformat().replace("+00:00", "Z")


class ExternalActionHost:
    """Activate and submit one governed external action.

    The same subject and payload return the original operation. A different
    payload conflicts. The provider key persisted before the adapter call is
    reused; this host never supplies a replacement key.
    """

    def __init__(self, database, submit: Callable[[dict, str], None], *, clock=None) -> None:
        from pdx_artifact_engine.contracts.external_operations import validation as validation
        from pdx_artifact_engine.dynamic_dispatch import (
            DispatchTool,
            DispatchToolRegistry,
            DynamicDispatchService,
        )
        from pdx_artifact_engine.external_operations import (
            ExternalOperationService,
            Principal,
            ProviderAdapter,
        )
        from pdx_artifact_engine.runtime_workflows import (
            RuntimeWorkflowService,
            RuntimeWorkflowStore,
        )

        self._validation = validation
        self._clock = clock or (lambda: __import__("time").time())
        self._store = RuntimeWorkflowStore(database)
        self._workflow = RuntimeWorkflowService(self._store, _HMAC)
        self._controller = Principal("pdx-local-controller", "pdx-local-controller-1")
        self._issuer = Principal("pdx-local-issuer", "pdx-local-issuer-1")
        self._admin = Principal("pdx-local-administrator", "pdx-local-administrator-1")
        self._artifacts: dict[str, bytes] = {}
        deployment = self._deployment()
        tool = self._tool(deployment)
        self._registry = DispatchToolRegistry([
            DispatchTool(
                frozen_definition=tool,
                input_schema=_PAYLOAD_SCHEMA,
                output_schema={
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["accepted"],
                    "properties": {"accepted": {"type": "boolean"}},
                },
                executor=lambda arguments: {"accepted": True},
            )
        ])
        self._dispatch = DynamicDispatchService(self._store, self._registry)
        authority = {
            "schema_version": "pdx_er003_authority_config_draft_v2",
            "authority_id": "pdx-local-authority",
            "tenant_id": "pdx-local-tenant",
            "controller_principals": [self._controller.name],
            "issuer_principals": [self._issuer.name],
            "adapter_principals": ["pdx-local-adapter"],
            "manual_principals": ["pdx-local-manual"],
            "administrator_principals": [self._admin.name],
            "supervisor_principals": ["pdx-local-supervisor"],
            "reader_principals": ["pdx-local-reader"],
            "revision": 1,
        }
        adapter = ProviderAdapter(
            deployment,
            None,
            submit,
            query=None,
            lookup_proof=None,
        )
        self.service = ExternalOperationService(
            self._store,
            [authority],
            lambda art: self._artifacts[art["artifact_id"]],
            {_PAYLOAD_SCHEMA_ID: _PAYLOAD_SCHEMA},
            {"local-external": adapter},
            clock=self._clock,
            dispatch=self._dispatch,
        )
        self._tool_definition = tool
        self._register_provider(deployment)

    def close(self) -> None:
        self._store.close()

    def perform(self, subject_id: str, payload: dict) -> dict[str, Any]:
        """Submit the payload once for this subject, then return the same operation."""
        self._require_subject(subject_id)
        self._require_payload(payload)
        try:
            operation_id = self._activate(subject_id, payload)
            projection = self.service.submit(operation_id, self._controller)
        except self._validation.Invalid as exc:
            raise ExternalActionError(exc.code) from exc
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code:
                raise ExternalActionError(str(code)) from exc
            raise
        return {
            "operation_id": projection["operation_id"],
            "provider_key_digest": projection["provider_key_digest"],
            "submit_permits": projection["submit_permits"],
            "submission_evidence": projection["submission_evidence"],
            "provider_outcome": projection["provider_outcome"],
            "reconciliation_required": projection["reconciliation_required"],
            "disposition": "needs_review",
        }

    def _subject_opened(self, subject_id: str) -> float:
        """Remember the clock of this subject's first perform. Other subjects stay independent."""
        with self._store.transaction() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS pdx_local_external_anchor (
                    subject_id TEXT PRIMARY KEY,
                    opened_at REAL NOT NULL
                )"""
            )
            row = connection.execute(
                "SELECT opened_at FROM pdx_local_external_anchor WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
            if row is not None:
                return float(row[0])
            opened = float(self._clock())
            connection.execute(
                "INSERT INTO pdx_local_external_anchor VALUES (?, ?)",
                (subject_id, opened),
            )
            return opened

    def _register_provider(self, deployment: dict) -> None:
        policy = _digest({"name": _TOOL, "revision": 1})
        registered = self.service.register(
            "provider_register",
            {
                "schema_version": "pdx_er003_provider_register_draft_v2",
                "authority_id": "pdx-local-authority",
                "tenant_id": "pdx-local-tenant",
                "request_id": "register-local-external",
                "idempotency_key": "provider-local-external",
                "provider_profile_id": "local-external",
                "revision": 1,
                "account_alias": "local-sandbox",
                "environment": "sandbox",
                "submit_deployment": deployment,
                "query_deployment": None,
                "execution_policy_digest": policy,
                "lookup_proven": False,
                "lookup_proof": None,
                "recovery_mode": "manual_only",
                "endpoint_policy_digest": _digest({"endpoint": "manual"}),
                "outcome_mapping_digest": _digest({"outcome": "unconfirmed"}),
                "dedupe_retention_seconds": 86400,
                "provider_key_format": "lowercase_hex_32",
                "budgets": _BUDGETS,
            },
            self._admin,
        )
        self._execution_policy_digest = policy
        self._provider_digest = registered["record_digest"]

    def _activate(self, subject_id: str, payload: dict) -> str:
        artifact = self._artifact(payload)
        specification = {
            "payload_artifact": artifact,
            "payload_schema_id": _PAYLOAD_SCHEMA_ID,
            "payload_schema_digest": _digest(_PAYLOAD_SCHEMA),
            "evidence_artifacts": [],
            "provider_profile_id": "local-external",
            "provider_profile_revision": 1,
            "provider_profile_digest": self._provider_digest,
            "account_alias": "local-sandbox",
            "environment": "sandbox",
            "executor_identity_digest": self._tool_definition["deployment"]["identity_digest"],
            "execution_policy_digest": self._execution_policy_digest,
        }
        subject = {
            "schema_version": "pdx_er003_subject_register_draft_v2",
            "authority_id": "pdx-local-authority",
            "tenant_id": "pdx-local-tenant",
            "request_id": f"subject-request-{subject_id}",
            "idempotency_key": f"subject-{subject_id}",
            "operation_subject_id": subject_id,
            "specification": specification,
        }
        self.service.register("subject_register", subject, self._controller)
        operation_digest = self._validation.digest(specification)
        opened = self._subject_opened(subject_id)
        freshness = self._freshness(subject_id, opened)
        self.service.register("issuer_freshness", freshness, self._issuer)
        approval_id = f"approval-{subject_id}"
        issued = datetime.fromtimestamp(opened - 1, UTC)
        self.service.register(
            "authorization_register",
            {
                "schema_version": "pdx_er003_authorization_register_draft_v2",
                "authority_id": "pdx-local-authority",
                "tenant_id": "pdx-local-tenant",
                "request_id": f"approval-request-{subject_id}",
                "idempotency_key": f"approval-{subject_id}",
                "authorization_id": approval_id,
                "issuer_id": self._issuer.name,
                "actor_id": "pdx-local-operator",
                "operation_subject_id": subject_id,
                "operation_digest": operation_digest,
                "controller_principal": self._controller.name,
                "execution_policy_digest": self._execution_policy_digest,
                "issued_at": freshness["observed_at"],
                "expires_at": (issued + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "issuer_epoch": 1,
                "max_operations": 1,
            },
            self._issuer,
        )
        plan = self._plan(subject_id, operation_digest, self._provider_digest, approval_id)
        self._workflow.create({
            "schema_version": "pdx_internal_runtime_provider_workflow_create_request_v3",
            "request_id": f"workflow-request-{subject_id}",
            "correlation_id": f"workflow-corr-{subject_id}",
            "idempotency_key": f"workflow-{subject_id}",
            "operation_digest": plan["plan_digest"],
            "plan": plan,
        })
        policy = self._policy(subject_id, plan)
        registered = self._dispatch.register_policy(
            plan["workflow_job_id"],
            plan["steps"][0]["workflow_step_id"],
            policy,
            authenticated_principal=self._controller.name,
        )
        self._import_decision(plan, registered, payload, opened)
        activation = self.service.activate(
            {
                "schema_version": "pdx_external_operation_activation_request_draft_v1",
                "request_id": f"activate-{subject_id}",
                "authority_id": "pdx-local-authority",
                "tenant_id": "pdx-local-tenant",
                "operation_subject_id": subject_id,
                "operation_digest": operation_digest,
                "authorization_id": approval_id,
                "issuer_id": self._issuer.name,
                "workflow_job_id": plan["workflow_job_id"],
                "workflow_step_id": plan["steps"][0]["workflow_step_id"],
                "plan_digest": plan["plan_digest"],
                "idempotency_key": f"activate-{subject_id}",
            },
            self._controller,
        )
        return activation["operation_id"]

    def _freshness(self, subject_id: str, opened: float) -> dict:
        observed = datetime.fromtimestamp(opened - 1, UTC)
        return {
            "schema_version": "pdx_er003_issuer_freshness_draft_v2",
            "authority_id": "pdx-local-authority",
            "tenant_id": "pdx-local-tenant",
            "request_id": f"freshness-{subject_id}",
            "idempotency_key": f"freshness-{subject_id}",
            "issuer_id": self._issuer.name,
            "issuer_epoch": 1,
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "valid_until": (observed + timedelta(seconds=25)).isoformat().replace("+00:00", "Z"),
        }

    def _plan(self, subject_id: str, operation_digest: str, profile_digest: str, approval_id: str) -> dict:
        job_id = f"job-{subject_id}"
        step_id = f"step-{subject_id}"
        binding = {
            "schema_version": "pdx_er003_step_binding_draft_v2",
            "authority_id": "pdx-local-authority",
            "tenant_id": "pdx-local-tenant",
            "operation_subject_id": subject_id,
            "operation_digest": operation_digest,
            "provider_profile_digest": profile_digest,
            "authorization_id": approval_id,
            "issuer_id": self._issuer.name,
            "budgets": _BUDGETS,
        }
        plan = {
            "schema_version": "pdx_runtime_provider_workflow_plan_v3",
            "workflow_job_id": job_id,
            "task_id": f"task-{subject_id}",
            "run_id": f"run-{subject_id}",
            "steps": [{
                "workflow_step_id": step_id,
                "step_kind": "dispatch",
                "depends_on": [],
                "max_attempts": 1,
                "operation_digest": operation_digest,
                "dispatch_policy_id": f"policy-{subject_id}",
                "run_a_plan_digest": _digest({"subject": subject_id}),
                "decision_step_id": f"decide-{subject_id}",
                "external_operation_binding": binding,
            }],
            "budgets": {
                "max_provider_attempts": 1,
                "max_check_attempts": 0,
                "max_dispatch_attempts": 1,
                "max_concurrent_steps": 1,
                "max_repair_iterations": 0,
                "max_total_runtime_seconds": 600,
                "max_dispatch_runtime_seconds": 300,
                "max_total_event_bytes": 1048576,
                "max_total_artifact_bytes": 10485760,
                "max_cross_step_artifact_edges": 0,
                "max_external_operations": 1,
                "max_external_calls": 1,
            },
            "artifact_edges": [],
        }
        plan["plan_digest"] = self._validation.digest(
            {key: value for key, value in plan.items() if key != "plan_digest"}
        )
        return plan

    def _policy(self, subject_id: str, plan: dict) -> dict:
        step = plan["steps"][0]
        return {
            "schema_version": "pdx_dynamic_dispatch_policy_register_request_v1",
            "request_id": f"policy-request-{subject_id}",
            "dispatch_policy_id": step["dispatch_policy_id"],
            "workflow_job_id": plan["workflow_job_id"],
            "workflow_step_id": step["workflow_step_id"],
            "run_a_plan_digest": step["run_a_plan_digest"],
            "decision_step_id": step["decision_step_id"],
            "policy_revision_epoch": 1,
            "allowed_tool_names": [_TOOL],
            "allowed_tools": [self._tool_definition],
            "proposal_limits": {
                "max_depth": 8,
                "max_properties_per_object": 64,
                "max_total_keys": 256,
                "max_canonical_bytes": 65536,
                "max_secret_refs": 8,
                "max_array_length": 1024,
            },
            "expires_at": None,
            "caller_authority_id": self._controller.name,
        }

    def _import_decision(self, plan: dict, policy: dict, payload: dict, opened: float) -> None:
        step = plan["steps"][0]
        schema = resources.files("pdx_artifact_engine.contracts.dynamic_dispatch").joinpath(
            "pdx_dynamic_dispatch_tool_proposal_v1.schema.json"
        )
        proposal_digest = hashlib.sha256(schema.read_bytes()).hexdigest()
        manifest = self._artifact({
            "schema_version": "pdx_run_manifest_v0",
            "run_id": plan["run_id"],
            "request_id": f"decision-run-{plan['workflow_job_id']}",
            "status": "completed",
            "steps": [{
                "step_id": step["decision_step_id"],
                "kind": "tool",
                "name": "decide",
                "status": "completed",
            }],
            "verification": [],
            "artifact_manifest": "artifact_manifest.json",
        })
        proposal = {
            "proposal_schema_id": "https://prodocux.dev/schemas/pdx/dynamic-dispatch/tool-proposal-v1.json",
            "proposal_schema_digest": proposal_digest,
            "tool_name": _TOOL,
            "arguments": payload,
        }
        receipt = {
            "schema_version": "pdx_dynamic_dispatch_decision_receipt_v1",
            "decision_receipt_id": f"decision-{plan['workflow_job_id']}",
            "workflow_job_id": plan["workflow_job_id"],
            "workflow_step_id": step["workflow_step_id"],
            "source_run_id": plan["run_id"],
            "source_plan_digest": step["run_a_plan_digest"],
            "decision_step_id": step["decision_step_id"],
            "decision_attempt_number": 1,
            "dispatch_policy_id": policy["dispatch_policy_id"],
            "policy_revision_epoch": policy["policy_revision_epoch"],
            "policy_digest": policy["policy_digest"],
            "proposal_schema_id": proposal["proposal_schema_id"],
            "proposal_schema_digest": proposal_digest,
            "tool_name": _TOOL,
            "arguments": payload,
            "arguments_digest": _digest(payload),
            "canonical_proposal_digest": _digest(proposal),
            "source_manifest_artifact": manifest,
            "terminal_status": "completed",
            "credential_free_guarantee": True,
            "recorded_at": _iso(opened),
        }
        receipt["decision_receipt_digest"] = _digest(
            {key: value for key, value in receipt.items() if key != "decision_receipt_digest"}
        )
        self._dispatch.import_decision(
            plan["workflow_job_id"],
            step["workflow_step_id"],
            {
                "schema_version": "pdx_dynamic_dispatch_decision_import_request_v1",
                "request_id": f"decision-request-{plan['workflow_job_id']}",
                "workflow_job_id": plan["workflow_job_id"],
                "workflow_step_id": step["workflow_step_id"],
                "source_manifest_artifact": manifest,
                "decision_receipt": receipt,
                "caller_authority_id": self._controller.name,
            },
            authenticated_principal=self._controller.name,
        )

    def _artifact(self, value: Any) -> dict:
        raw = rfc8785.dumps(value)
        digest = hashlib.sha256(raw).hexdigest()
        artifact = {
            "schema_version": "prodocux_opaque_artifact_v1",
            "artifact_id": "art-" + digest,
            "uri": "artifact://local-external/" + digest,
            "sha256": digest,
            "size_bytes": len(raw),
            "media_type": "application/json",
        }
        self._artifacts[artifact["artifact_id"]] = raw
        return artifact

    def _deployment(self) -> dict:
        deployment = {
            "kind": "deployment_bundle",
            "bundle_name": "pdx-local-external",
            "bundle_version": "1.0.0",
            "bundle_digest": _digest({"bundle": "pdx-local-external", "version": "1.0.0"}),
            "registry_revision": 1,
            "entrypoint_symbol": "pdx_local_ai.external_action:submit",
        }
        deployment["identity_digest"] = _digest(
            {key: value for key, value in deployment.items() if key != "identity_digest"}
        )
        return deployment

    def _tool(self, deployment: dict) -> dict:
        output_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "required": ["accepted"],
            "properties": {"accepted": {"type": "boolean"}},
        }
        return {
            "name": _TOOL,
            "version": "1.0",
            "skill_definition_digest": _digest({"name": _TOOL, "version": "1.0"}),
            "input_schema_id": _PAYLOAD_SCHEMA_ID,
            "input_schema_digest": _digest(_PAYLOAD_SCHEMA),
            "output_schema_id": "local-external-action-output",
            "output_schema_digest": _digest(output_schema),
            "verification_hooks_digest": _digest({"hooks": []}),
            "deployment": deployment,
            "executor_kind": "in_process",
            "idempotent_read_only": False,
        }

    @staticmethod
    def _require_subject(subject_id: str) -> None:
        if not isinstance(subject_id, str) or _ID.fullmatch(subject_id) is None:
            raise ExternalActionError("REQUEST_INVALID")
        for prefix in (
            "job-", "step-", "policy-", "decide-", "task-", "run-", "approval-", "freshness-",
        ):
            if len(prefix + subject_id) > 128:
                raise ExternalActionError("REQUEST_INVALID")

    @staticmethod
    def _require_payload(payload: dict) -> None:
        from jsonschema import Draft202012Validator

        if not Draft202012Validator(_PAYLOAD_SCHEMA).is_valid(payload):
            raise ExternalActionError("REQUEST_INVALID")
