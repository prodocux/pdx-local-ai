"""In-process archive intake. Qualified execution stays on a Windows CPython host.

Packaged executables and missing opt-in fail closed. This module does not
start Kernel HTTP and does not read archive environment variables.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

_BLOCK = {
    "OCR_REQUIRED",
    "PROFILE_UNQUALIFIED",
    "BUDGET_EXHAUSTED",
    "INTEGRITY_FAILED",
    "EXECUTION_UNKNOWN",
    "PROFILE_NOT_IMPLEMENTED",
    "PROFILE_NOT_APPLICABLE",
}
_NATIVE = {".7z": "native-7z-copy-lzma-lzma2", ".rar": "native-rar5"}
_REPLAY_SUFFIXES = {".txt", ".md", ".markdown", ".log", ".tsv", ".pdf", ".docx"}
# Kernel ledger ceilings. Nested admits each receive a fresh session ledger, so the
# host keeps one task account and stops when the sum of observed costs crosses these.
_TASK_LIMITS = {
    "source_bytes": 256 << 20,
    "expanded_bytes": 512 << 20,
    "entries": 16_384,
    "elapsed_ms": 120_000,
}
ARCHIVE_READ_LIMIT = 64 << 20
# pypdf's glyph table raises MemoryError inside a 32MB job. The kernel ceiling is 512MB.
_PDF_WORKER_MEMORY = 128 << 20


def profile_for(filename: str, payload: bytes = b"") -> str | None:
    lower = filename.lower()
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "tar-gzip"
    if lower.endswith(".tar.bz2") or lower.endswith(".tbz2"):
        return "tar-bzip2"
    if lower.endswith(".tar.xz") or lower.endswith(".txz"):
        return "tar-xz"
    suffix = Path(filename).suffix.lower()
    if suffix == ".zip":
        return "zip64-store-deflate" if _zip64(payload) else "zip-store-deflate"
    return {
        ".tar": "tar-ustar-pax-gnu",
        ".gz": "gzip-single-member",
        ".bz2": "bzip2-single-stream",
        ".xz": "xz-single-stream",
    }.get(suffix)


def _zip64(payload: bytes) -> bool:
    """Detect ZIP64 from the tail signature only. Never parse a central directory here."""
    if not payload:
        return False
    tail = payload[-66_000:]
    return b"PK\x06\x06" in tail or b"PK\x06\x07" in tail


def _new_account() -> dict[str, int]:
    return {key: 0 for key in _TASK_LIMITS}


def _account_exhausted(account: dict[str, int] | None) -> bool:
    if account is None:
        return False
    return any(account[key] > limit for key, limit in _TASK_LIMITS.items())


def _observe(account: dict[str, int] | None, response: dict) -> bool:
    if account is None:
        return True
    observed = response.get("observed") or {}
    for key in _TASK_LIMITS:
        account[key] += int(observed.get(key) or 0)
    return not _account_exhausted(account)


def _gate_time(now: int, binding: dict, width: int) -> int | None:
    """Stay inside the catalog snapshot that was negotiated, and after it was issued."""
    gate_now = max(now, int(binding["issued_at_ms"]))
    if gate_now >= int(binding["expires_at_ms"]):
        return None
    if now - now % width != gate_now - gate_now % width:
        return None
    return gate_now


def qualification(*, enabled: bool, database) -> str:
    """Return eligible only for an explicit Windows CPython host with a database."""
    if not enabled or database is None:
        return "PROFILE_UNQUALIFIED"
    if getattr(sys, "frozen", False) or os.name != "nt":
        return "PROFILE_UNQUALIFIED"
    return "eligible"


def index_archive(
    filename: str,
    payload: bytes,
    *,
    enabled: bool = False,
    database=None,
    max_depth: int = 3,
    clock=None,
    depth: int = 1,
    replay: bool = False,
    claimed_source_sha256: str | None = None,
    account: dict[str, int] | None = None,
):
    """List and read an opted-in archive. Default and frozen hosts publish nothing."""
    status = qualification(enabled=enabled, database=database)
    native = _NATIVE.get(Path(filename).suffix.lower())
    if status != "eligible":
        return _closed("PROFILE_UNQUALIFIED", native or profile_for(filename))
    profile = profile_for(filename, payload)
    if native is not None:
        return _closed("PROFILE_NOT_IMPLEMENTED", native)
    if profile is None:
        return _closed("PROFILE_NOT_APPLICABLE", None)
    if not 1 <= depth <= max_depth <= 3:
        return _closed("BUDGET_EXHAUSTED", profile)
    tick = clock or (lambda: time.time_ns() // 1_000_000)
    from prodocux_kernel.archive_intake.authority import Identity
    from prodocux_kernel.archive_intake.contracts import digest
    from prodocux_kernel.archive_intake.decoders import ArchiveError
    from prodocux_kernel.archive_intake.negotiation import Negotiation
    from prodocux_kernel.archive_intake.sources import ArchiveSources

    from .kernel_adapter import KernelAdapter

    sources = ArchiveSources(database, ttl_ms=900_000)
    negotiation = Negotiation(sources, isolated_zip_read=True)
    owner = Identity("pdx-local-ai", "local", "indexer")
    adapter = KernelAdapter(
        engine_database=Path(database).with_suffix(".member-engine.sqlite3"),
        engine_artifact_root=Path(database).with_suffix(".member-artifacts"),
    )
    try:
        task = account if account is not None else _new_account()
        result = _read_tree(
            payload, sources, negotiation, owner, adapter, digest,
            profile=profile, max_depth=max_depth, clock=tick,
            depth=depth, error=ArchiveError, archive_name=filename, replay=replay,
            claimed_source_sha256=claimed_source_sha256,
            account=task,
        )
        if result["disposition"] != "PROFILE_MISMATCH" or profile not in {
            "zip-store-deflate", "zip64-store-deflate",
        }:
            return result
        other = "zip64-store-deflate" if profile == "zip-store-deflate" else "zip-store-deflate"
        return _read_tree(
            payload, sources, negotiation, owner, adapter, digest,
            profile=other, max_depth=max_depth, clock=tick,
            depth=depth, error=ArchiveError, archive_name=filename, replay=replay,
            claimed_source_sha256=claimed_source_sha256,
            account=task,
        )
    except ArchiveError as error:
        return _closed(str(error), profile, catalog_revision=negotiation.revision)
    finally:
        adapter.close()
        _cleanup_sidecars(database)


def _closed(reason: str, profile, *, catalog_revision=None) -> dict:
    return {
        "disposition": reason,
        "searchable": False,
        "archive_profile": profile,
        "catalog_revision": catalog_revision,
        "members": [],
        "omissions": [reason],
    }


def _read_tree(payload, sources, negotiation, owner, adapter, digest, *, profile, max_depth, clock, depth, error, archive_name, replay, claimed_source_sha256=None, account=None):
    if account is not None and account["source_bytes"] + len(payload) > _TASK_LIMITS["source_bytes"]:
        return _closed("BUDGET_EXHAUSTED", profile)
    lease = _admit(sources, owner, payload, clock)
    try:
        return _read_lease(
            sources, negotiation, owner, adapter, digest, lease,
            profile=profile, max_depth=max_depth, clock=clock, depth=depth,
            error=error, archive_name=archive_name,             replay=replay,
            claimed_source_sha256=claimed_source_sha256,
            account=account,
        )
    finally:
        try:
            sources.close(owner, lease["source_ref"])
        except error:
            pass


def _read_lease(sources, negotiation, owner, adapter, digest, lease, *, profile, max_depth, clock, depth, error, archive_name, replay, claimed_source_sha256=None, account=None):
    members = []
    omissions = []
    listed = _inventory(
        sources, negotiation, owner, lease, digest, profile, clock, error, account,
    )
    if listed["disposition"] != "succeeded":
        return _closed(listed["disposition"], profile, catalog_revision=negotiation.revision)
    counts: dict[str, int] = {}
    for row in listed["members"]:
        counts[row["selector"]["raw_name_sha256"]] = counts.get(row["selector"]["raw_name_sha256"], 0) + 1
    for row in listed["members"]:
        selector = row["selector"]
        raw_name = selector["raw_name_sha256"]
        display = selector["display_name"]
        if counts[raw_name] > 1 or _rejected_name(display):
            omissions.append("member_not_published")
            continue
        if row["kind"] != "file":
            continue
        size = int(row["declared_size_bytes"])
        if size <= 0 or size > 1 << 20:
            omissions.append("BUDGET_EXHAUSTED")
            continue
        if _account_exhausted(account):
            omissions.append("BUDGET_EXHAUSTED")
            break
        body = _read_member(
            negotiation, owner, lease, digest, profile, selector, size, clock, error, account,
        )
        if body["disposition"] != "full_member":
            omissions.append(body["disposition"])
            continue
        child_profile = profile_for(display, body["payload"])
        if child_profile is not None:
            if depth >= max_depth:
                omissions.append("BUDGET_EXHAUSTED")
                continue
            nested = _read_tree(
                body["payload"], sources, negotiation, owner, adapter, digest,
                profile=child_profile, max_depth=max_depth, clock=clock,
                depth=depth + 1, error=error, archive_name=display, replay=replay,
                claimed_source_sha256=claimed_source_sha256, account=account,
            )
            if nested["disposition"] != "complete":
                omissions.append(nested["disposition"])
            if replay and nested["members"]:
                chain = _replay_chain(
                    negotiation, owner, lease, digest, profile, selector, body,
                    nested["members"][0], clock, error, account,
                )
                nested["members"][0]["nested_replay"] = chain
                if chain["disposition"] != "succeeded":
                    omissions.append(chain["disposition"])
            members.extend(nested["members"])
            continue
        projection = _project_member(
            adapter, _document_name(archive_name, display, profile), body, profile, selector, negotiation.revision,
        )
        if projection is None:
            omissions.append("member_not_published")
            continue
        if replay and Path(display).suffix.lower() in _REPLAY_SUFFIXES:
            projection["replay"] = _replay_leaf(
                negotiation, owner, lease, digest, profile, selector, body, clock, error, account,
                claimed_source_sha256=claimed_source_sha256,
            )
            if projection["replay"]["disposition"] != "succeeded":
                omissions.append(projection["replay"]["disposition"])
        if projection.get("disclosure_only"):
            omissions.append(projection["coverage"].get("disposition") or "partial_unknown")
        members.append(projection)
    disposition = "complete" if not omissions else "partial_unknown"
    searchable = disposition == "complete" and bool(members)
    return {
        "disposition": disposition,
        "searchable": searchable,
        "archive_profile": profile,
        "catalog_revision": negotiation.revision,
        "members": members,
        "omissions": omissions,
    }


def _admit(sources, owner, payload, clock):
    from prodocux_kernel.archive_intake.sources import scope

    now = clock()
    session = f"local-{uuid4().hex}"
    pieces = []
    offset = 0
    limit = sources.chunk_limit
    while offset < len(payload):
        chunk = payload[offset:offset + limit]
        pieces.append({
            "volume_key": "part",
            "range": {"start": str(offset), "end": str(offset + len(chunk))},
            "sha256": sha256(chunk).hexdigest(),
            "data": chunk,
        })
        offset += len(chunk)
    plan = {
        "schema_version": "prodocux_archive_source_admission_v2",
        "session_id": session,
        "operation_id": f"op-{uuid4().hex}",
        "authority_binding": scope(owner),
        "policy_digest": sources.policy,
        "mode": "chunked_snapshot",
        "expires_at_ms": str(now + sources.ttl_ms),
        "volumes": [{"ordinal": "0", "volume_key": "part", "declared_size_bytes": str(len(payload))}],
        "upload_chunks": [{key: item[key] for key in ("volume_key", "range", "sha256")} for item in pieces],
        "expected_bundle_digest": None,
    }
    sources.create(owner, plan, now)
    for item in pieces:
        span = item["range"]
        sources.upload(
            owner, session, "part", int(span["start"]), int(span["end"]),
            item["sha256"], item["data"], clock(),
        )
    return sources.seal(owner, session, clock())


def _budget(ledger, source_size: int, *, returned: int, entries: int, depth_limit: int = 1, account=None, peak_floor: int = 32 << 20) -> dict | None:
    """Reserve one operation without asking for the whole ledger again."""
    if account is not None and (
        source_size > _TASK_LIMITS["source_bytes"] - account["source_bytes"]
        or entries > _TASK_LIMITS["entries"] - account["entries"]
        or account["elapsed_ms"] >= _TASK_LIMITS["elapsed_ms"]
        or account["expanded_bytes"] >= _TASK_LIMITS["expanded_bytes"]
    ):
        return None
    keys = (
        "source_bytes", "expanded_bytes", "returned_bytes", "metadata_bytes",
        "elapsed_ms", "peak_memory_bytes", "depth", "volumes", "entries",
    )
    limits = {key: int(ledger["limits"]["max_" + key]) for key in keys}
    used = {key: int(ledger["observed"][key]) for key in keys}

    def additive(key: str, want: int) -> int | None:
        room = limits[key] - used[key]
        if want <= 0 or want > room:
            return None
        return want

    source = additive("source_bytes", source_size)
    expanded = additive("expanded_bytes", min(1 << 20, max(limits["expanded_bytes"] - used["expanded_bytes"], 0)))
    returned_value = additive("returned_bytes", min(returned, 1 << 20))
    metadata = additive("metadata_bytes", min(1 << 16, max(limits["metadata_bytes"] - used["metadata_bytes"], 0)))
    host_elapsed = 30_000 if account is None else _TASK_LIMITS["elapsed_ms"] - account["elapsed_ms"]
    elapsed = additive("elapsed_ms", min(30_000, host_elapsed, max(limits["elapsed_ms"] - used["elapsed_ms"], 0)))
    volumes = additive("volumes", 1)
    entry_value = additive("entries", entries)
    peak = min(limits["peak_memory_bytes"], max(used["peak_memory_bytes"], peak_floor))
    if None in (source, expanded, returned_value, metadata, elapsed, volumes, entry_value):
        return None
    if peak <= 0 or peak > limits["peak_memory_bytes"] or used["depth"] > limits["depth"]:
        return None
    return {
        "max_source_bytes": str(source),
        "max_expanded_bytes": str(expanded),
        "max_returned_bytes": str(returned_value),
        "max_metadata_bytes": str(metadata),
        "max_elapsed_ms": str(elapsed),
        "max_peak_memory_bytes": str(peak),
        "max_depth": str(depth_limit),
        "max_volumes": "1",
        "max_entries": str(entry_value),
    }


def _envelope(lease, ledger, catalog, entry, digest, profile, request):
    context = {
        "schema_version": "prodocux_archive_request_context_v2",
        "request_id": request["request_id"],
        "operation_id": lease["operation_id"],
        "source_lease_digest": digest(lease),
        "profile_digest": entry["execution_profile_digest"],
        "ledger_digest": digest(ledger),
        "credential_ref": None,
        "external_binding_digests": [],
    }
    base = {
        "schema_version": "prodocux_archive_request_envelope_v2",
        "context": context,
        "request": request,
    }
    return {
        "schema_version": "prodocux_archive_negotiation_request_v3",
        "catalog_digest": digest(catalog),
        "profile_id": profile,
        "profile_contract": entry["definition"]["profile_contract"],
        "expected_profile_digest": entry["definition_digest"],
        "base_request": base,
    }


def _entry(catalog, profile):
    return next(item for item in catalog["profiles"] if item["definition"]["profile_id"] == profile)


def _accepted(negotiation, owner, lease, digest, profile, clock, error, account, build):
    """Negotiate and execute on one catalog snapshot. Retry once if the window edge moves."""
    width = negotiation.sources.ttl_ms
    crossed = False
    for _attempt in range(2):
        now = clock()
        catalog = negotiation.catalog(owner, now)
        entry = _entry(catalog, profile)
        ledger = negotiation.ledger(owner, lease["source_ref"], profile, now)
        built = build(ledger, account, catalog)
        if built is None:
            return {"disposition": "BUDGET_EXHAUSTED"}
        request, operation = built
        prepared = _envelope(lease, ledger, catalog, entry, digest, profile, request)
        try:
            negotiated = negotiation.negotiate(owner, prepared, now)
        except error as exc:
            return {"disposition": str(exc)}
        if negotiated["decision"] != "accepted":
            reason = (negotiated["availability"]["reason_codes"] or ["PROFILE_UNQUALIFIED"])[0]
            return {"disposition": reason}
        gate_now = _gate_time(now, negotiated["binding"], width)
        if gate_now is None:
            crossed = True
            continue
        try:
            receipt = negotiation.execution_gate(owner, {
                "schema_version": "prodocux_archive_request_envelope_v3",
                "mode": "negotiated",
                "base": prepared["base_request"],
                "profile_binding": negotiated["binding"],
            }, operation, gate_now)
        except error as exc:
            return {"disposition": str(exc)}
        response = receipt["base"]["response"]
        if not _observe(account, response):
            return {"disposition": "BUDGET_EXHAUSTED", "response": response}
        return {"disposition": "accepted", "response": response}
    return {"disposition": "CAPABILITY_CATALOG_CHANGED" if crossed else "NEGOTIATION_EXPIRED"}


def _inventory(sources, negotiation, owner, lease, digest, profile, clock, error, account):
    del sources
    cursor = None
    found = []
    for page in range(64):
        def build(ledger, task, catalog, page=page, cursor=cursor):
            del catalog
            budget = _budget(
                ledger, int(lease["bundle"]["volumes"][0]["size_bytes"]),
                returned=65536, entries=64, account=task,
            )
            if budget is None:
                return None
            request = {
                "schema_version": "prodocux_archive_list_request_v1",
                "operation": "list",
                "request_id": f"list-{page}",
                "source_ref": lease["source_ref"],
                "view": "container",
                "budget": budget,
                "parent_chain": [],
                "cursor": cursor,
                "max_entries": budget["max_entries"],
            }
            return request, "list"

        outcome = _accepted(
            negotiation, owner, lease, digest, profile, clock, error, account, build,
        )
        if outcome["disposition"] != "accepted":
            return {"disposition": outcome["disposition"], "members": []}
        response = outcome["response"]
        if response["outcome"] != "succeeded" or response["reason_codes"]:
            return {"disposition": (response["reason_codes"] or ["EXECUTION_UNKNOWN"])[0], "members": []}
        found.extend(response["result"]["members"])
        cursor = response["result"]["next_cursor"]
        if cursor is None:
            return {"disposition": "succeeded", "members": found}
    return {"disposition": "BUDGET_EXHAUSTED", "members": []}


def _read_member(negotiation, owner, lease, digest, profile, selector, size, clock, error, account):
    def build(ledger, task, catalog):
        del catalog
        budget = _budget(
            ledger, int(lease["bundle"]["volumes"][0]["size_bytes"]),
            returned=size, entries=1, account=task,
        )
        if budget is None:
            return None
        request = {
            "schema_version": "prodocux_archive_read_request_v1",
            "operation": "read",
            "request_id": f"read-{selector['ordinal']}",
            "source_ref": lease["source_ref"],
            "view": "container",
            "budget": budget,
            "parent_chain": [],
            "selector": selector,
            "link_policy": "metadata_only",
            "requested_range": {"start": "0", "end": str(size)},
        }
        return request, "read"

    outcome = _accepted(negotiation, owner, lease, digest, profile, clock, error, account, build)
    if outcome["disposition"] != "accepted":
        return {"disposition": outcome["disposition"]}
    response = outcome["response"]
    result = response["result"] or {}
    codes = set(response["reason_codes"])
    if codes & _BLOCK or result.get("integrity_scope") != "full_member":
        return {"disposition": (response["reason_codes"] or ["EXECUTION_UNKNOWN"])[0]}
    payload = base64.b64decode(result["bytes_b64"], validate=True)
    if sha256(payload).hexdigest() != result["member_sha256"]:
        return {"disposition": "INTEGRITY_FAILED"}
    return {"disposition": "full_member", "payload": payload, "member_sha256": result["member_sha256"]}


def _project_member(adapter, display, body, profile, selector, revision):
    try:
        projection = adapter.extract(display, body["payload"])
    except ValueError:
        return None
    coverage = projection.get("coverage") or {}
    warnings = set(coverage.get("warnings") or []) | set(coverage.get("omitted_content_classes") or [])
    ocr = projection.get("ocr_disposition")
    locator = {
        "kind": "archive_member",
        "archive_profile": profile,
        "member_ordinal": selector["ordinal"],
        "raw_name_sha256": selector["raw_name_sha256"],
        "member_sha256": body["member_sha256"],
        "parser_contract": projection.get("parser_contract"),
        "catalog_revision": revision,
    }
    if any(locator[key] in (None, "") for key in locator):
        return None
    kept = bool(projection.get("text_items")) or "OCR_REQUIRED" in warnings or ocr == "required"
    if not kept:
        return None
    projection["archive_profile"] = profile
    projection["catalog_revision"] = revision
    projection["archive_locator"] = locator
    projection["archive_selector"] = selector
    projection["isolated_member"] = body["payload"]
    projection["disclosure_only"] = coverage.get("disposition") != "complete" or bool(warnings & _BLOCK)
    return projection


def _document_name(archive_name: str, display: str, profile: str) -> str:
    """Single-stream members are named by the compressor, not by a document suffix."""
    if profile not in {"gzip-single-member", "bzip2-single-stream", "xz-single-stream"}:
        return display
    if Path(display).suffix:
        return display
    outer = Path(archive_name).name
    for suffix in (".gz", ".bz2", ".xz"):
        if outer.lower().endswith(suffix):
            return outer[: -len(suffix)]
    return display


def _quote_projection(name: str, payload: bytes):
    """Build the projection the archive worker hashes for document-leaf-handoff."""
    suffix = Path(name).suffix.lower()
    if suffix == ".pdf":
        from prodocux_kernel.intake.pdf_projection import extract_pdf_continuable_projection

        projection = extract_pdf_continuable_projection(payload)
        items = [
            {"source_locator": str(page["page_number"]), "text": page["text"]}
            for page in projection["pages"]
            if not page["ocr_required"]
        ]
        if not items and any(page.get("ocr_required") for page in projection["pages"]):
            return None, None, "OCR_REQUIRED"
        return projection, items, None
    if suffix == ".docx":
        from prodocux_kernel.intake.docx import profile_docx_bytes

        projection = profile_docx_bytes(payload, filename=name)
        projection["parser_contract"] = {"name": projection["schema_version"], "version": "1"}
        omitted = ["docx_non_paragraph_content_not_cited"]
        if projection.get("preview_truncated"):
            omitted.append("docx_preview_limit")
        projection["coverage"] = {
            "disposition": "partial_unknown",
            "omitted_content_classes": omitted,
        }
        items = [
            {"source_locator": f"paragraph:{row['index']}", "text": row["text"]}
            for row in projection["paragraphs"]
        ]
        return projection, items, None
    from prodocux_kernel.intake.documents import read_document

    projection = read_document(name, payload)
    items = [row for row in projection["text_items"] if row.get("text")]
    return projection, items, None


def _replay_receipt(profile_name, projection, quote, text):
    coverage = projection.get("coverage") or {}
    if text != quote:
        return {"disposition": "EXECUTION_UNKNOWN", "profile": profile_name}
    return {
        "disposition": "succeeded",
        "profile": profile_name,
        "quote": text,
        "verifier_source": "kernel",
        "omissions": list(coverage.get("omitted_content_classes") or []),
        "complete": coverage.get("disposition") == "complete",
    }


def _replay_leaf(negotiation, owner, lease, digest, profile, selector, body, clock, error, account, claimed_source_sha256=None):
    """Replay one PDF, DOCX preview, or UTF-8 leaf through document-leaf-handoff."""
    import rfc8785

    handoff = "document-leaf-handoff"
    try:
        projection, items, failure = _quote_projection(selector["display_name"], body["payload"])
    except ValueError as exc:
        return {"disposition": str(exc), "profile": handoff}
    if failure:
        return {"disposition": failure, "profile": handoff}
    item = next((row for row in items or [] if row.get("text")), None)
    if projection is None or item is None:
        return {"disposition": "LOCATOR_UNAVAILABLE", "profile": handoff}
    quote = item["text"]
    source_sha = claimed_source_sha256 or body["member_sha256"]

    def build(ledger, task, catalog):
        floor = _PDF_WORKER_MEMORY if Path(selector["display_name"]).suffix.lower() == ".pdf" else 32 << 20
        budget = _budget(
            ledger, int(lease["bundle"]["volumes"][0]["size_bytes"]),
            returned=min(1 << 20, max(len(body["payload"]), 65536)), entries=1, account=task,
            peak_floor=floor,
        )
        if budget is None:
            return None
        decoder = _entry(catalog, profile)
        request = {
            "schema_version": "prodocux_archive_resolve_request_v1",
            "operation": "resolve",
            "request_id": f"resolve-{selector['ordinal']}",
            "source_ref": lease["source_ref"],
            "view": "container",
            "budget": budget,
            "chain": [{
                "parent_digest": lease["bundle_digest"],
                "selector": selector,
                "decoder_attestation_digest": digest({"execution_profile_digest": decoder["execution_profile_digest"]}),
                "output_semantics": "embedded_bytes",
                "output_sha256": body["member_sha256"],
                "output_size_bytes": str(len(body["payload"])),
                "integrity": "verified",
            }],
            "document": {
                "source_sha256": source_sha,
                "parser_contract": projection["parser_contract"],
                "projection_digest": sha256(rfc8785.dumps(projection)).hexdigest(),
                "locator": item["source_locator"],
            },
            "quote": {
                "start": "0",
                "end": str(len(quote)),
                "normalization": "unicode_nfc_codepoint_v1",
                "sha256": sha256(quote.encode("utf-8")).hexdigest(),
            },
        }
        return request, "resolve"

    outcome = _accepted(negotiation, owner, lease, digest, handoff, clock, error, account, build)
    if outcome["disposition"] != "accepted":
        return {"disposition": outcome["disposition"], "profile": handoff}
    response = outcome["response"]
    text = (response.get("result") or {}).get("text")
    if response.get("outcome") not in {"succeeded", "partial"}:
        reason = (response.get("reason_codes") or ["EXECUTION_UNKNOWN"])[0]
        return {"disposition": reason, "profile": handoff}
    return _replay_receipt(handoff, projection, quote, text)


def _replay_chain(negotiation, owner, lease, digest, profile, selector, body, leaf, clock, error, account):
    """Resolve a nested archive leaf on the outer lease, using bytes the worker already read."""
    import rfc8785

    chain_profile = "nested-qualified-profiles"
    inner_selector = leaf.get("archive_selector")
    text_bytes = leaf.get("isolated_member")
    locator = leaf.get("archive_locator") or {}
    if inner_selector is None or not isinstance(text_bytes, (bytes, bytearray)) or not locator:
        return {"disposition": "LOCATOR_UNAVAILABLE", "profile": chain_profile}
    try:
        projection, items, failure = _quote_projection(inner_selector["display_name"], bytes(text_bytes))
    except ValueError as exc:
        return {"disposition": str(exc), "profile": chain_profile}
    if failure:
        return {"disposition": failure, "profile": chain_profile}
    item = next((row for row in items or [] if row.get("text")), None)
    if projection is None or item is None:
        return {"disposition": "LOCATOR_UNAVAILABLE", "profile": chain_profile}
    quote = item["text"]

    def build(ledger, task, catalog):
        # The worker charges every directory entry of each opened container.
        leaf_name = str((inner_selector or {}).get("display_name") or "")
        floor = _PDF_WORKER_MEMORY if Path(leaf_name).suffix.lower() == ".pdf" else 32 << 20
        budget = _budget(
            ledger, int(lease["bundle"]["volumes"][0]["size_bytes"]),
            returned=1 << 20, entries=128, depth_limit=2, account=task,
            peak_floor=floor,
        )
        if budget is None:
            return None
        outer_decoder = _entry(catalog, profile)
        inner_decoder = _entry(catalog, leaf.get("archive_profile") or profile)
        request = {
            "schema_version": "prodocux_archive_resolve_request_v1",
            "operation": "resolve",
            "request_id": f"nested-{selector['ordinal']}",
            "source_ref": lease["source_ref"],
            "view": "container",
            "budget": budget,
            "chain": [
                {
                    "parent_digest": lease["bundle_digest"],
                    "selector": selector,
                    "decoder_attestation_digest": digest({"execution_profile_digest": outer_decoder["execution_profile_digest"]}),
                    "output_semantics": "embedded_bytes",
                    "output_sha256": body["member_sha256"],
                    "output_size_bytes": str(len(body["payload"])),
                    "integrity": "verified",
                },
                {
                    "parent_digest": body["member_sha256"],
                    "selector": inner_selector,
                    "decoder_attestation_digest": digest({"execution_profile_digest": inner_decoder["execution_profile_digest"]}),
                    "output_semantics": "embedded_bytes",
                    "output_sha256": locator["member_sha256"],
                    "output_size_bytes": str(len(text_bytes)),
                    "integrity": "verified",
                },
            ],
            "document": {
                "source_sha256": locator["member_sha256"],
                "parser_contract": projection["parser_contract"],
                "projection_digest": sha256(rfc8785.dumps(projection)).hexdigest(),
                "locator": item["source_locator"],
            },
            "quote": {
                "start": "0",
                "end": str(len(quote)),
                "normalization": "unicode_nfc_codepoint_v1",
                "sha256": sha256(quote.encode("utf-8")).hexdigest(),
            },
        }
        return request, "resolve"

    outcome = _accepted(negotiation, owner, lease, digest, chain_profile, clock, error, account, build)
    if outcome["disposition"] != "accepted":
        return {"disposition": outcome["disposition"], "profile": chain_profile}
    response = outcome["response"]
    text = (response.get("result") or {}).get("text")
    if response.get("outcome") not in {"succeeded", "partial"}:
        reason = (response.get("reason_codes") or ["EXECUTION_UNKNOWN"])[0]
        return {"disposition": reason, "profile": chain_profile}
    return _replay_receipt(chain_profile, projection, quote, text)


def _cleanup_sidecars(database) -> None:
    if database is None:
        return
    root = Path(database)
    engine = root.with_suffix(".member-engine.sqlite3")
    artifacts = root.with_suffix(".member-artifacts")
    for path in (engine, Path(str(engine) + "-wal"), Path(str(engine) + "-shm")):
        if path.exists():
            path.unlink()
    if artifacts.exists():
        shutil.rmtree(artifacts, ignore_errors=True)


def set_archive_opt_in(catalog, source_root_id: str, enabled: bool) -> None:
    """Record source-root archive opt-in. Absence of the flag stays off."""
    row = catalog.conn.execute(
        "SELECT config_json FROM source_root WHERE source_root_id=?",
        (source_root_id,),
    ).fetchone()
    if row is None:
        raise ValueError("source root unavailable")
    config = json.loads(row[0])
    config["archive_enabled"] = bool(enabled)
    with catalog.conn:
        catalog.conn.execute(
            "UPDATE source_root SET config_json=? WHERE source_root_id=?",
            (json.dumps(config, ensure_ascii=False, sort_keys=True), source_root_id),
        )


def _citation_locator(projection: dict, item: dict) -> str | None:
    locator = dict(projection.get("archive_locator") or {})
    inner = item.get("source_locator")
    required = ("kind", "archive_profile", "member_ordinal", "raw_name_sha256", "member_sha256", "parser_contract")
    if not inner or any(locator.get(key) in (None, "") for key in required):
        return None
    locator["inner_locator"] = inner
    return json.dumps(locator, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _publish_archive(catalog, root_row, *, relative: str, source_sha: str, stable, result: dict) -> None:
    """Publish checked members through the existing catalog transaction."""
    from .versions import KERNEL_VERSION

    items = []
    omissions = [code for code in result.get("omissions") or [] if code != "partial_unknown"]
    ocr = "not_applicable"
    for member in result.get("members") or []:
        coverage = member.get("coverage") or {}
        if member.get("disclosure_only"):
            omissions.extend(coverage.get("omitted_content_classes") or [])
            if member.get("ocr_disposition") == "required" or "OCR_REQUIRED" in set(coverage.get("warnings") or []):
                ocr = "required"
            continue
        for item in member.get("text_items") or []:
            locator = _citation_locator(member, item)
            text = item.get("text")
            if locator is None or not text:
                continue
            items.append({
                "source_locator": locator,
                "text": text,
                "type": item.get("type") or "text",
            })
    if not items and not omissions:
        return
    published = {
        "schema_version": "pdx_local_kernel_projection_aggregate_v1",
        "kernel_version": KERNEL_VERSION,
        "source_sha256": source_sha,
        "parser_contract": {"name": "prodocux_archive_member_v1", "version": "1"},
        "ranges": [],
        "text_items": items,
        "coverage": {
            "disposition": "complete" if not omissions else "partial_unknown",
            "warnings": list(dict.fromkeys(omissions)),
            "omitted_content_classes": list(dict.fromkeys(omissions)),
        },
        "ocr_disposition": ocr,
        "counts": {"processed_through_range_end": {"items": len(items)}, "known_total": {}},
        "archive_profile": result.get("archive_profile") or "not_applicable",
        "catalog_revision": str(result.get("catalog_revision") or ""),
    }
    file_id = catalog._upsert_file_record(
        workspace_id=root_row["workspace_id"],
        root_id=root_row["source_root_id"],
        relative=relative,
        media_type="application/octet-stream",
        volume=str(stable.st_dev),
        file_identity=str(stable.st_ino),
        discovered_relatives={relative},
    )
    attempt_id = catalog._attempt(
        workspace_id=root_row["workspace_id"],
        root_id=root_row["source_root_id"],
        file_id=file_id,
        relative=relative,
    )
    catalog._publish(
        root_row=root_row,
        file_id=file_id,
        relative=relative,
        attempt_id=attempt_id,
        source_sha=source_sha,
        stable=stable,
        kernel_result=published,
    )


def consume_opted_in_archives(catalog, root_row, seen: set | None = None) -> None:
    """Index opted-in archives through the catalog's stable read and publication path."""
    from .catalog import SourceChanged
    from .validation import ContractError, validate_relative_path

    config = json.loads(root_row["config_json"])
    if config.get("archive_enabled") is not True:
        return
    root = Path(root_row["canonical_path"])
    database = Path(catalog.database).with_name(str(root_row["source_root_id"]) + ".archive.sqlite")
    records = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if not catalog._is_reparse(current_path / name))
        for name in sorted(files):
            path = current_path / name
            if profile_for(name) is None and Path(name).suffix.lower() not in _NATIVE:
                continue
            relative = str(path.relative_to(root)).replace("/", "\\")
            try:
                validate_relative_path(relative)
                if catalog._is_reparse(path):
                    raise ContractError("reparse-point file rejected")
                info = os.lstat(path)
                if info.st_size <= 0 or info.st_size > ARCHIVE_READ_LIMIT:
                    records.append({"relative_path": relative, "disposition": "BUDGET_EXHAUSTED", "omissions": ["BUDGET_EXHAUSTED"]})
                    continue
                payload, stable, source_sha = catalog._read_stable(root, path)
            except (ContractError, SourceChanged, OSError) as exc:
                records.append({"relative_path": relative, "disposition": "INTEGRITY_FAILED", "omissions": [str(exc)]})
                continue
            result = index_archive(name, payload, enabled=True, database=database)
            records.append({
                "relative_path": relative,
                "disposition": result["disposition"],
                "omissions": list(result.get("omissions") or []),
            })
            file_id = catalog._upsert_file_record(
                workspace_id=root_row["workspace_id"],
                root_id=root_row["source_root_id"],
                relative=relative,
                media_type="application/octet-stream",
                volume=str(stable.st_dev),
                file_identity=str(stable.st_ino),
                discovered_relatives={relative},
            )
            if seen is not None:
                seen.add(file_id)
            current_sha = catalog.conn.execute(
                "SELECT sv.source_sha256 FROM file_record f LEFT JOIN source_version sv ON sv.source_version_id=f.current_source_version_id WHERE f.file_record_id=?",
                (file_id,),
            ).fetchone()
            if current_sha and current_sha[0] == source_sha:
                continue
            try:
                _publish_archive(
                    catalog, root_row, relative=relative, source_sha=source_sha, stable=stable, result=result,
                )
            except (ContractError, SourceChanged, OSError, RuntimeError, ValueError):
                records[-1]["disposition"] = "INTEGRITY_FAILED"
    config["archive_enabled"] = True
    config["archive_files"] = records
    if records and all(row["disposition"] == "complete" for row in records):
        config["archive_last_disposition"] = "complete"
    elif records:
        config["archive_last_disposition"] = "partial_unknown"
    else:
        config.pop("archive_last_disposition", None)
    with catalog.conn:
        catalog.conn.execute(
            "UPDATE source_root SET config_json=? WHERE source_root_id=?",
            (json.dumps(config, ensure_ascii=False, sort_keys=True), root_row["source_root_id"]),
        )


def _rejected_name(name: str) -> bool:
    if name != name.strip() or "\\" in name or name.startswith("/"):
        return True
    parts = name.split("/")
    return any(part in {"", ".", ".."} for part in parts)
