"""Validate Gate 0 JSON Schemas and cross-field semantic fixtures."""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import sys
import unicodedata
from pathlib import Path, PureWindowsPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURE_DIR = ROOT / "tests" / "fixtures"
BUDGET_REASONS = {
    "metadata_candidate_limit",
    "lexical_candidate_limit",
    "file_limit",
    "block_limit",
    "byte_limit",
    "time_limit",
}
NON_BUDGET_REASONS = {"score_threshold", "score_margin", "no_candidates"}
DOS_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


def _safe_relative_path(value: str) -> bool:
    if not value or "\x00" in value or ":" in value:
        return False
    normalized = value.replace("/", "\\")
    if normalized.startswith("\\") or re.match(r"^[A-Za-z]:", normalized):
        return False
    path = PureWindowsPath(normalized)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _safe_source_root(value: str) -> bool:
    if not value or "\x00" in value or "/" in value:
        return False
    if value.startswith("\\") or not re.match(r"^[A-Za-z]:\\", value):
        return False
    if value.count(":") != 1 or ntpath.normpath(value) != value:
        return False
    for component in PureWindowsPath(value).parts[1:]:
        if component in {"", ".", ".."} or component.endswith((" ", ".")):
            return False
        base = component.split(".", 1)[0].rstrip(" .").upper()
        if base in DOS_DEVICES:
            return False
    return True


def semantic_errors(schema_version: str, value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if schema_version == "pdx_local_source_root_v1" and not _safe_source_root(
        str(value.get("canonical_path", ""))
    ):
        errors.append("canonical_path must be a canonical absolute local drive path")
    if schema_version == "pdx_local_file_record_v1" and not _safe_relative_path(
        str(value.get("relative_path", ""))
    ):
        errors.append("relative_path must be safe and relative")

    if (
        schema_version == "pdx_local_retrieval_request_v1"
        and len(value.get("eligible_source_root_ids", [])) != 1
    ):
        errors.append("Gate 0 requires exactly one eligible source root")

    if schema_version == "pdx_local_reconciliation_receipt_v1":
        passes = value.get("scan_passes", [])
        if value.get("stale_retries_consumed") != max(0, len(passes) - 1):
            errors.append("stale retries must match additional scan passes")
        if value.get("status") == "succeeded":
            integrity = value.get("integrity", {})
            last = passes[-1] if passes else {}
            if integrity.get("passed") is not True:
                errors.append("successful reconciliation requires passing integrity")
            if last.get("stale", 0) or last.get("failed", 0):
                errors.append("successful reconciliation cannot end with retryable work")

    if schema_version == "pdx_local_retrieval_receipt_v1":
        limits = value.get("limits", {})
        consumed = value.get("consumed", {})
        for key, limit in limits.items():
            if consumed.get(key, 0) > limit:
                errors.append(f"consumed.{key} exceeds limits.{key}")

        execution = value.get("execution", {})
        status = execution.get("status")
        exhausted = execution.get("budget_exhausted")
        reason = execution.get("stop_reason")
        if reason in BUDGET_REASONS and exhausted is not True:
            errors.append("budget stop reason requires budget_exhausted=true")
        if reason in NON_BUDGET_REASONS and exhausted is not False:
            errors.append("non-budget stop reason requires budget_exhausted=false")
        if reason == "error" and status != "failed":
            errors.append("error stop reason requires status=failed")
        if reason == "error" and exhausted is not False:
            errors.append("error is not a budget stop and requires budget_exhausted=false")
        if status == "failed" and reason != "error":
            errors.append("failed execution requires stop_reason=error")

        scope = value.get("scope_coverage", {})
        if scope.get("searched_roots", 0) > scope.get("eligible_roots", 0):
            errors.append("searched_roots exceeds eligible_roots")
        if value.get("result_count") != len(value.get("citation_ids", [])):
            errors.append("result_count must equal citation_ids length")
    if schema_version == "pdx_local_memory_recall_receipt_v1":
        if value.get("candidates_consumed", 0) > value.get("candidate_limit", 0):
            errors.append("candidates_consumed exceeds candidate_limit")
        if value.get("result_count", 0) > value.get("result_limit", 0):
            errors.append("result_count exceeds result_limit")
        if value.get("result_count", 0) > value.get("candidates_consumed", 0):
            errors.append("result_count exceeds candidates_consumed")
        if value.get("mode") == "lexical" and value.get("embedding_adapter_id") is not None:
            errors.append("lexical recall cannot name an embedding adapter")
        if value.get("mode") == "hybrid" and not value.get("embedding_adapter_id"):
            errors.append("hybrid recall requires an embedding adapter")
    if schema_version == "pdx_local_hybrid_retrieval_receipt_v1":
        if value.get("unique_candidates", 0) > value.get("candidate_limit", 0):
            errors.append("unique_candidates exceeds candidate_limit")
        if value.get("result_count", 0) > value.get("result_limit", 0):
            errors.append("result_count exceeds result_limit")
        if value.get("result_count") != len(value.get("citation_ids", [])):
            errors.append("result_count must equal citation_ids length")
    if (
        schema_version == "pdx_local_memory_promotion_receipt_v1"
        and value.get("source_content_sha256") != value.get("target_content_sha256")
    ):
        errors.append("Gate 4A promotion cannot rewrite content")
    if schema_version == "pdx_local_layered_recall_receipt_v1":
        searched = value.get("searched_layers", [])
        per_layer = value.get("per_layer", {})
        if set(searched) != set(per_layer):
            errors.append("searched layers and per-layer accounting differ")
        limits = value.get("aggregate_limits", {})
        consumed = value.get("aggregate_consumed", {})
        for dimension in ("candidates", "results", "returned_bytes", "elapsed_ms"):
            if consumed.get(dimension, 0) > limits.get(dimension, 0):
                errors.append(f"aggregate {dimension} consumption exceeds limit")
            if any(
                per_layer.get(layer, {}).get("consumed", {}).get(dimension, 0)
                > per_layer.get(layer, {}).get("limits", {}).get(dimension, 0)
                for layer in searched
            ):
                errors.append(f"per-layer {dimension} consumption exceeds limit")
        if value.get("result_count") != len(value.get("results", [])):
            errors.append("layered result_count does not match results")
        if consumed.get("results") != value.get("result_count"):
            errors.append("layered consumed results do not match result_count")
    if schema_version == "pdx_local_citation_v1":
        block_text = value.get("_fixture_block_text")
        if not isinstance(block_text, str):
            errors.append("citation validation requires authorized immutable block text")
        elif value.get("quote_normalization") != "unicode_nfc_codepoint_v1":
            errors.append("unsupported quote normalization")
        else:
            normalized = unicodedata.normalize("NFC", block_text)
            start = value.get("quote_start")
            end = value.get("quote_end")
            if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(normalized):
                errors.append("quote offsets are outside normalized block text")
            else:
                selected = normalized[start:end]
                digest = hashlib.sha256(selected.encode("utf-8")).hexdigest()
                if digest != value.get("quoted_text_sha256"):
                    errors.append("quoted_text_sha256 does not match selected block text")
    return errors


def main() -> int:
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        version = path.name.removesuffix(".schema.json")
        schemas[version] = schema
        print(f"SCHEMA OK {path.name}")

    cases: list[dict[str, Any]] = []
    for fixture_path in sorted(FIXTURE_DIR.glob("*_cases.json")):
        cases.extend(json.loads(fixture_path.read_text(encoding="utf-8")))
    failures: list[str] = []
    for case in cases:
        name = case["name"]
        version = case["schema_version"]
        value = case["value"]
        schema_value = {key: item for key, item in value.items() if not key.startswith("_fixture_")}
        validator = Draft202012Validator(schemas[version], format_checker=FormatChecker())
        shape_errors = [error.message for error in validator.iter_errors(schema_value)]
        errors = shape_errors + semantic_errors(version, value)
        actual_valid = not errors
        if actual_valid != case["expected_valid"]:
            failures.append(f"{name}: expected_valid={case['expected_valid']}, errors={errors}")
        else:
            print(f"CASE OK {name} expected_valid={case['expected_valid']}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"PASS schemas={len(schemas)} semantic_cases={len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
