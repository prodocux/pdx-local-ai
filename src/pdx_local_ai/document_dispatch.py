"""One document dispatch table over the installed Kernel projection APIs.

PDF and DOCX stay on KernelAdapter. This module does not open archives.
"""

from __future__ import annotations

import json
from hashlib import sha256
from importlib import metadata
from pathlib import Path

from .office_profiles import extract as office_extract
from .versions import KERNEL_VERSION

MEDIA = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".csv": "text/csv",
    ".html": "text/html",
    ".htm": "text/html",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".eml": "message/rfc822",
    ".epub": "application/epub+zip",
    ".srt": "application/x-subrip",
    ".vtt": "text/vtt",
    ".webvtt": "text/vtt",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".log": "text/plain",
    ".tsv": "text/tab-separated-values",
    ".rtf": "application/rtf",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
}
OPTIONAL = {".rtf", ".doc", ".xls", ".ppt", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}
OFFICE = {".csv", ".xlsx", ".pptx"}
PORTABLE = set(MEDIA) - OPTIONAL - OFFICE - {".pdf", ".docx"}
_READ_LIMITS = {
    "DOCUMENT_OUTPUT_LIMIT": "document_output_limit",
    "JSON_NODE_LIMIT": "json_node_limit",
    "JSONL_RECORD_LIMIT": "jsonl_record_limit",
    "INTAKE_PROJECTION_LIMIT": "intake_projection_limit",
    "LINE_EXCEEDS_BUDGET": "line_exceeds_budget",
}


def _require_kernel() -> None:
    observed = metadata.version("prodocux")
    if observed != KERNEL_VERSION:
        raise RuntimeError(f"prodocux {KERNEL_VERSION} required, got {observed}")


def _aggregate(raw: bytes, parser: dict, items: list, omissions=(), ocr: str = "not_applicable") -> dict:
    return {
        "schema_version": "pdx_local_kernel_projection_aggregate_v1",
        "kernel_version": KERNEL_VERSION,
        "source_sha256": sha256(raw).hexdigest(),
        "parser_contract": parser,
        "ranges": [{"unit": "source_bytes", "start": 0, "end": len(raw)}],
        "text_items": items,
        "coverage": {
            "disposition": "partial_unknown" if omissions else "complete",
            "warnings": list(omissions),
            "omitted_content_classes": list(omissions),
        },
        "ocr_disposition": ocr,
        "counts": {"processed_through_range_end": {"items": len(items)}, "known_total": {}},
        "archive_profile": "not_applicable",
        "catalog_revision": "",
    }


def dispatch_document(
    filename: str,
    raw: bytes,
    *,
    conversion: bool = False,
    ocr: bool = False,
    record_store=None,
) -> dict:
    """Project one non-archive document. PDF and DOCX raise so KernelAdapter keeps them."""
    _require_kernel()
    suffix = Path(filename).suffix.lower()
    if suffix in {".pdf", ".docx"}:
        raise ValueError("USE_EXISTING_PROJECTION_API")
    if suffix in OFFICE:
        result = office_extract(filename, raw, candidate=True)
        if result.get("kernel_version") != KERNEL_VERSION:
            raise RuntimeError("Kernel result version mismatch")
        result["archive_profile"] = "not_applicable"
        result["catalog_revision"] = ""
        return result
    if suffix in OPTIONAL:
        if record_store is None or not (conversion or ocr):
            raise ValueError("OPTIONAL_BACKEND_REQUIRED")
        return _backend(filename, raw, suffix, conversion=conversion, ocr=ocr, record_store=record_store)
    if suffix not in PORTABLE:
        raise ValueError("FORMAT_UNSUPPORTED")
    from prodocux_kernel.intake.documents import read_document

    cursor = None
    items: list = []
    omissions: set = set()
    parser = None
    for _ in range(64):
        try:
            result = read_document(filename, raw, cursor=cursor)
        except ValueError as error:
            code = str(error)
            if code not in _READ_LIMITS:
                raise
            omissions.add(_READ_LIMITS[code])
            return _aggregate(raw, parser or {"name": "projection_limit", "version": "1"}, items, sorted(omissions))
        parser = result["parser_contract"]
        items.extend(result["text_items"])
        omissions.update(result["coverage"]["omitted_content_classes"])
        if len(items) > 20000:
            omissions.add("projection_item_limit")
            return _aggregate(raw, parser, items[:20000], sorted(omissions))
        cursor = result["next_cursor"]
        if cursor is None:
            return _aggregate(raw, parser, items, sorted(omissions))
    omissions.add("projection_range_limit")
    return _aggregate(raw, parser or {"name": "projection_limit", "version": "1"}, items, sorted(omissions))


def _backend(filename, raw, suffix, *, conversion, ocr, record_store):
    from pdx_document_backend.admission import slot

    fmt = "tiff" if suffix == ".tif" else suffix[1:]
    policy = {"allow_conversion": conversion, "allow_ocr": ocr}
    with slot():
        record = record_store.project(fmt, raw, **policy)
        replay = record_store.backend.replay(fmt, raw, record, **policy)
    if record["items"] != replay["items"]:
        raise ValueError("BACKEND_REPLAY_MISMATCH")
    items = [
        {
            "source_locator": json.dumps(item["locator"], ensure_ascii=False, separators=(",", ":")),
            "text": item["text"],
            "type": "backend_source_unit",
        }
        for item in record["items"]
    ]
    ocr_state = "performed_partial" if fmt in {"pdf", "png", "jpg", "jpeg", "tiff"} else "not_applicable"
    return _aggregate(raw, {"name": record["parser"], "version": "1"}, items, record["omissions"], ocr_state)
