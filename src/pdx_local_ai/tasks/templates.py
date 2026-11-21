"""Host-managed, versioned task templates. Templates never grant permissions."""

from __future__ import annotations

import copy
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .contracts import LIMITS, TaskError, canonical_json, sha256_json, utf8_len

_SOURCE_ROOTS = {
    "type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 64},
}

# Conservative JSON-schema subset used for every action schema the host emits
# (type/properties/required/enum/min/max*/additionalProperties only). Structured
# output backends guarantee syntax only; the host re-validates every action.
ACTION_SCHEMAS: dict[str, dict[str, Any]] = {
    "search": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 300},
            "parent_hop_id": {"type": "string", "maxLength": 64},
            "entity": {"type": "string", "maxLength": 200},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
    "recall_memory": {
        "type": "object",
        "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 8}},
        "required": [],
        "additionalProperties": False,
    },
    "recall_published_memory": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 300},
            "limit": {"type": "integer", "minimum": 1, "maximum": 8},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
    "write_candidate": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 3, "maxLength": 69},
            "content": {"type": "string", "minLength": 1},
        },
        "required": ["name", "content"],
        "additionalProperties": False,
    },
    "submit_step": {
        "type": "object",
        "properties": {
            "artifact": {"type": "object"},
            "declare_incomplete": {"type": "boolean"},
            "reason": {"type": "string", "enum": [
                "missing_link", "budget_exhausted", "needs_input", "ambiguity_unresolved",
                "no_new_evidence", "hop_limit"]},
        },
        "required": ["artifact"],
        "additionalProperties": False,
    },
}

TEMPLATES: dict[str, dict[str, Any]] = {
    "doc_evidence_check": {
        "version": "1.0.0",
        "title": "Document evidence check",
        "description": "Answer named fields from authorized documents; every value must be quoted from cited evidence.",
        "context_mode": "bounded_retrieval",
        "auto_accept": True,
        "params_schema": {
            "type": "object",
            "properties": {
                "source_root_ids": _SOURCE_ROOTS,
                "questions": {
                    "type": "array", "minItems": 1, "maxItems": 16,
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": "string", "pattern": "^[a-z0-9_]{1,32}$"},
                            "question": {"type": "string", "minLength": 1, "maxLength": 500},
                        },
                        "required": ["field", "question"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["source_root_ids", "questions"],
            "additionalProperties": False,
        },
        "steps": [
            {"id": "gather", "kind": "retrieval", "depends_on": [],
             "actions": ["search", "submit_step"]},
            {"id": "report", "kind": "final", "depends_on": ["gather"],
             "actions": ["write_candidate", "submit_step"]},
        ],
        "final_artifact_schema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array", "minItems": 1, "maxItems": 16,
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": "string"},
                            "value": {"type": "string", "minLength": 1, "maxLength": 2000},
                            "evidence_ids": {"type": "array", "minItems": 1, "maxItems": 8,
                                             "items": {"type": "string"}},
                        },
                        "required": ["field", "value", "evidence_ids"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["items"],
            "additionalProperties": False,
        },
        "validators": ["json_schema", "required_fields", "evidence_values"],
    },
    "multihop_trace": {
        "version": "1.0.0",
        "title": "Cross-document multi-hop trace",
        "description": "Follow a dependent fact chain across documents under one shared retrieval ledger.",
        "context_mode": "bounded_multihop",
        "auto_accept": True,
        "params_schema": {
            "type": "object",
            "properties": {
                "source_root_ids": _SOURCE_ROOTS,
                "start_entity": {"type": "string", "minLength": 1, "maxLength": 200},
                "target_relation": {"type": "string", "minLength": 1, "maxLength": 200},
                "max_hops": {"type": "integer", "minimum": 1, "maximum": LIMITS["max_hops"]},
            },
            "required": ["source_root_ids", "start_entity", "target_relation"],
            "additionalProperties": False,
        },
        "steps": [
            {"id": "trace", "kind": "multihop", "depends_on": [],
             "actions": ["search", "submit_step"]},
            {"id": "report", "kind": "final", "depends_on": ["trace"],
             "actions": ["write_candidate", "submit_step"]},
        ],
        "trace_artifact_schema": {
            "type": "object",
            "properties": {
                "chain": {
                    "type": "array", "minItems": 1, "maxItems": LIMITS["max_hops"],
                    "items": {
                        "type": "object",
                        "properties": {
                            "hop_id": {"type": "string"},
                            "entity": {"type": "string", "minLength": 1, "maxLength": 200},
                            "evidence_ids": {"type": "array", "minItems": 1, "maxItems": 8,
                                             "items": {"type": "string"}},
                        },
                        "required": ["hop_id", "entity", "evidence_ids"],
                        "additionalProperties": False,
                    },
                },
                "answer": {"type": "string", "minLength": 1, "maxLength": 2000},
                "alternatives": {
                    "type": "array", "maxItems": 4,
                    "items": {"type": "object",
                              "properties": {"answer": {"type": "string"},
                                             "hop_ids": {"type": "array", "items": {"type": "string"}}},
                              "required": ["answer"], "additionalProperties": False},
                },
            },
            "required": ["chain", "answer"],
            "additionalProperties": False,
        },
        "final_artifact_schema": {
            "type": "object",
            "properties": {
                "answer": {"type": "string", "minLength": 1, "maxLength": 2000},
                "trace_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
            },
            "required": ["answer", "trace_sha256"],
            "additionalProperties": False,
        },
        "validators": ["json_schema", "trace_matches"],
    },
    "doc_memory_artifact": {
        "version": "1.0.0",
        "title": "Document + memory artifact",
        "description": "Combine authorized document evidence and recalled working memory into a structured candidate; memory is proposed, never auto-published.",
        "context_mode": "bounded_retrieval",
        "auto_accept": False,
        "params_schema": {
            "type": "object",
            "properties": {
                "source_root_ids": _SOURCE_ROOTS,
                "instruction": {"type": "string", "minLength": 1, "maxLength": 2000},
                "memory_scope_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "output_schema": {"type": "object"},
                "propose_memory": {"type": "boolean"},
            },
            "required": ["source_root_ids", "instruction", "memory_scope_id", "output_schema"],
            "additionalProperties": False,
        },
        "steps": [
            {"id": "gather", "kind": "retrieval", "depends_on": [],
             "actions": ["search", "recall_memory", "recall_published_memory", "submit_step"]},
            {"id": "produce", "kind": "final", "depends_on": ["gather"],
             "actions": ["write_candidate", "submit_step"]},
        ],
        "final_artifact_schema": {
            "type": "object",
            "properties": {
                "output": {"type": "object"},
                "evidence_ids": {"type": "array", "minItems": 1, "maxItems": 16,
                                 "items": {"type": "string"}},
                "memory_ids": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
            },
            "required": ["output", "evidence_ids"],
            "additionalProperties": False,
        },
        "validators": ["json_schema", "output_schema", "evidence_refs", "memory_refs"],
    },
}


def template_digest(template_id: str) -> str:
    return sha256_json(TEMPLATES[template_id])


def get_template(template_id: Any) -> dict[str, Any]:
    if not isinstance(template_id, str) or template_id not in TEMPLATES:
        raise TaskError("TEMPLATE_UNKNOWN", "unknown task template")
    return TEMPLATES[template_id]


def _walk_refs(node: Any) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if ref is not None and not (isinstance(ref, str) and ref.startswith("#")):
            raise TaskError("TASK_VALIDATION_ERROR", "output_schema may only use local $ref")
        for value in node.values():
            _walk_refs(value)
    elif isinstance(node, list):
        for value in node:
            _walk_refs(value)


def validate_params(template_id: str, params: Any) -> dict[str, Any]:
    template = get_template(template_id)
    if not isinstance(params, dict):
        raise TaskError("TASK_VALIDATION_ERROR", "params must be an object")
    text = canonical_json(params)
    if utf8_len(text) > LIMITS["params_bytes"]:
        raise TaskError("TASK_VALIDATION_ERROR", "params exceed size limit")
    errors = sorted(Draft202012Validator(template["params_schema"]).iter_errors(params),
                    key=lambda e: list(e.path))
    if errors:
        raise TaskError("TASK_VALIDATION_ERROR", f"invalid params: {errors[0].message}",
                        {"path": [str(p) for p in errors[0].path]})
    if template_id == "doc_evidence_check":
        fields = [q["field"] for q in params["questions"]]
        if len(set(fields)) != len(fields):
            raise TaskError("TASK_VALIDATION_ERROR", "duplicate question field")
    if template_id == "doc_memory_artifact":
        schema = params["output_schema"]
        if utf8_len(canonical_json(schema)) > 16 * 1024:
            raise TaskError("TASK_VALIDATION_ERROR", "output_schema too large")
        _walk_refs(schema)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise TaskError("TASK_VALIDATION_ERROR", f"invalid output_schema: {exc.message}") from exc
    normalized = copy.deepcopy(params)
    if template_id == "multihop_trace":
        normalized.setdefault("max_hops", LIMITS["max_hops"])
    if template_id == "doc_memory_artifact":
        normalized.setdefault("propose_memory", False)
    return normalized


def public_templates() -> list[dict[str, Any]]:
    out = []
    for tid in sorted(TEMPLATES):
        t = TEMPLATES[tid]
        out.append({
            "template_id": tid, "version": t["version"], "title": t["title"],
            "description": t["description"], "context_mode": t["context_mode"],
            "template_sha256": template_digest(tid),
            "steps": [{"id": s["id"], "kind": s["kind"], "depends_on": s["depends_on"],
                       "actions": s["actions"]} for s in t["steps"]],
            "params_schema": t["params_schema"],
            "grants_permissions": False,
        })
    return out
