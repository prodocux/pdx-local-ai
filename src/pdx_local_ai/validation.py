from __future__ import annotations

import hashlib
import json
import ntpath
import re
import unicodedata
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

DOS_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


class ContractError(ValueError):
    pass


BUDGET_STOP_FIELDS = {
    "metadata_candidate_limit": "metadata_candidates",
    "lexical_candidate_limit": "lexical_candidates",
    "file_limit": "opened_files",
    "block_limit": "opened_blocks",
    "byte_limit": "returned_bytes",
    "time_limit": "elapsed_ms",
}


def validate_source_root_path(value: str) -> None:
    if not value or "\x00" in value or "/" in value:
        raise ContractError("source root contains an invalid character")
    if value.startswith("\\") or not re.match(r"^[A-Za-z]:\\", value):
        raise ContractError("source root must be an absolute local drive path")
    if value.count(":") != 1 or ntpath.normpath(value) != value:
        raise ContractError("source root must be canonical and must not contain ADS")
    for component in PureWindowsPath(value).parts[1:]:
        if component in {"", ".", ".."} or component.endswith((" ", ".")):
            raise ContractError("source root contains a noncanonical component")
        if component.split(".", 1)[0].rstrip(" .").upper() in DOS_DEVICES:
            raise ContractError("source root contains a DOS device component")


def validate_relative_path(value: str) -> None:
    if not value or "\x00" in value or ":" in value:
        raise ContractError("relative path is empty, contains NUL, or contains ADS")
    normalized = value.replace("/", "\\")
    if normalized.startswith("\\") or re.match(r"^[A-Za-z]:", normalized):
        raise ContractError("path is not relative")
    path = PureWindowsPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ContractError("relative path contains traversal")


def _reject_unpaired_surrogates(value: str) -> None:
    for char in value:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise ContractError("unpaired Unicode surrogate is forbidden")


def validate_citation_against_block(
    citation: Mapping[str, Any], authorized_block: Mapping[str, Any]
) -> str:
    """Validate a citation against a block loaded by the trusted ACL query."""
    if citation.get("block_instance_id") != authorized_block.get("block_instance_id"):
        raise ContractError("citation block binding mismatch")
    if citation.get("projection_id") != authorized_block.get("projection_id"):
        raise ContractError("citation projection binding mismatch")
    if citation.get("quote_normalization") != "unicode_nfc_codepoint_v1":
        raise ContractError("unsupported quote normalization")
    text = str(authorized_block["text"])
    _reject_unpaired_surrogates(text)
    normalized = unicodedata.normalize("NFC", text)
    start = citation.get("quote_start")
    end = citation.get("quote_end")
    if not isinstance(start, int) or not isinstance(end, int):
        raise ContractError("quote offsets must be integers")
    if start < 0 or end <= start or end > len(normalized):
        raise ContractError("quote offsets are outside normalized block text")
    selected = normalized[start:end]
    _reject_unpaired_surrogates(selected)
    digest = hashlib.sha256(selected.encode("utf-8")).hexdigest()
    if digest != citation.get("quoted_text_sha256"):
        raise ContractError("quoted-text digest mismatch")
    return selected


from .paths import get_root

_TEXT_PARSER = "pdx_local_text_decoder"
_TEXT_LOCATOR = "text_line_codepoint_v1"
_TEXT_SCHEMA = "pdx_local_text_citation_v1"
_KERNEL_LOCATORS = frozenset({"page", "paragraph", "table", "cell", "structural"})
_TEXT_CITATION_SCHEMA_PATH = (
    get_root() / "schemas" / "pdx_local_text_citation_v1.schema.json"
)


def _text_citation_schema_validator() -> Draft202012Validator:
    validator = getattr(_text_citation_schema_validator, "cached", None)
    if validator is None:
        schema = json.loads(_TEXT_CITATION_SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        _text_citation_schema_validator.cached = validator  # type: ignore[attr-defined]
    return validator


def _text_citation_reason(citation: Mapping[str, Any], block: Mapping[str, Any]) -> str | None:
    locator = citation.get("locator") or {}
    parser = citation.get("parser_contract") or {}
    parser_name = str(parser.get("name"))
    locator_kind = str(locator.get("kind"))
    text_parser = parser_name == _TEXT_PARSER
    text_locator = locator_kind == _TEXT_LOCATOR
    if text_parser and text_locator:
        derived = _TEXT_SCHEMA
    elif text_parser or text_locator:
        return "text citation markers disagree"
    elif locator_kind not in _KERNEL_LOCATORS:
        return "locator kind is not a kernel citation"
    else:
        derived = "pdx_local_citation_v1"
    if citation.get("schema_version") != derived or derived != _TEXT_SCHEMA:
        return "citation schema does not match the stored markers"
    if block.get("authorized") is not True:
        return "text block is not authorized"
    if block.get("published") is not True:
        return "text block is not published"
    if block.get("drift") is True:
        return "text block is drifted"
    if block.get("current_source_version_id") != block.get("source_version_id"):
        return "text block is not current"
    for field in (
        "workspace_id",
        "source_root_id",
        "file_record_id",
        "source_version_id",
        "projection_id",
        "block_instance_id",
    ):
        if citation.get(field) != block.get(field):
            return f"{field} does not match the stored block"
    if parser.get("version") != "1" or block.get("parser_contract_version") != "1":
        return "parser contract does not match the projection"
    if block.get("parser_contract_name") != _TEXT_PARSER:
        return "projection parser is not the text decoder"
    line_start = locator.get("line_start")
    line_end = locator.get("line_end_exclusive")
    code_start = locator.get("source_codepoint_start")
    code_end = locator.get("source_codepoint_end_exclusive")
    if not all(isinstance(value, int) for value in (line_start, line_end, code_start, code_end)):
        return "locator values are not integers"
    if line_end <= line_start or code_end < code_start:
        return "locator range is reversed"
    for field, value in (
        ("line_start", line_start),
        ("line_end_exclusive", line_end),
        ("source_codepoint_start", code_start),
        ("source_codepoint_end_exclusive", code_end),
    ):
        if value != block.get(field):
            return "locator does not equal text_source_range"
    normalized = unicodedata.normalize("NFC", str(block.get("block_text")))
    if citation.get("quote_start") != 0 or citation.get("quote_end") != len(normalized):
        return "quote is not the complete block"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if citation.get("quoted_text_sha256") != digest:
        return "quoted-text digest mismatch"
    if citation.get("quote_normalization") != "unicode_nfc_codepoint_v1":
        return "quote normalization is not NFC"
    return None


def validate_text_citation_against_block(
    citation: Mapping[str, Any], authorized_text_block: Mapping[str, Any]
) -> str:
    """Validate a text citation against the active schema and the authorized block."""
    reason = _text_citation_reason(citation, authorized_text_block)
    if reason:
        raise ContractError(reason)
    schema_errors = list(_text_citation_schema_validator().iter_errors(citation))
    if schema_errors:
        raise ContractError(schema_errors[0].message)
    return unicodedata.normalize("NFC", str(authorized_text_block.get("block_text")))


def validate_retrieval_receipt(receipt: Mapping[str, Any]) -> None:
    limits = receipt["limits"]
    consumed = receipt["consumed"]
    for key, limit in limits.items():
        if consumed[key] > limit:
            raise ContractError(f"consumed.{key} exceeds its limit")
    execution = receipt["execution"]
    status = execution["status"]
    exhausted = execution["budget_exhausted"]
    reason = execution["stop_reason"]
    observed_elapsed = execution.get("observed_elapsed_ms")
    if not isinstance(observed_elapsed, int) or observed_elapsed < 0:
        raise ContractError("execution.observed_elapsed_ms is required")
    if observed_elapsed < consumed["elapsed_ms"]:
        raise ContractError("observed elapsed cannot be below consumed elapsed budget")
    if reason == "time_limit" and observed_elapsed < limits["elapsed_ms"]:
        raise ContractError("time_limit requires observed elapsed to reach the deadline")
    if reason in BUDGET_STOP_FIELDS:
        if exhausted is not True:
            raise ContractError("budget stop reason requires exhaustion")
        field = BUDGET_STOP_FIELDS[reason]
        if reason not in {"byte_limit", "time_limit"} and consumed[field] != limits[field]:
            raise ContractError(f"{reason} requires its consumed counter to reach the limit")
    elif reason == "error":
        if status != "failed" or exhausted is not False:
            raise ContractError("error requires failed and non-budget execution")
    elif exhausted is not False:
        raise ContractError("non-budget stop reason cannot report exhaustion")
    if status == "failed" and reason != "error":
        raise ContractError("failed execution requires error stop reason")
    scope = receipt["scope_coverage"]
    if scope["searched_roots"] > scope["eligible_roots"]:
        raise ContractError("searched roots exceed eligible roots")
    if receipt["result_count"] != len(receipt["citation_ids"]):
        raise ContractError("result and citation cardinality differ")
