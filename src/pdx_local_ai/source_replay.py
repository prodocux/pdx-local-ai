from hashlib import sha256
from pathlib import Path
import unicodedata

_PORTABLE_FALLBACK = {
    "USE_EXISTING_PROJECTION_API",
    "OPTIONAL_BACKEND_REQUIRED",
    "FORMAT_UNSUPPORTED",
    "FORMAT_CONTINUATION_UNSUPPORTED",
    "PARSER_CONTRACT_MISMATCH",
    "LOCATOR_UNAVAILABLE",
}


def _receipt(quote, verifier_source):
    """Name which component re-read the quote: the installed Kernel or Local AI."""
    return {"quote": quote, "verifier_source": verifier_source}


def _portable_quote(path: Path, payload: bytes, row):
    """Use Kernel resolve when the stored citation is inside its document contract."""
    from prodocux_kernel.intake.documents import resolve_document

    try:
        quote = resolve_document(
            path.name, payload,
            source_sha256=row["source_sha256"],
            parser_contract={
                "name": row["parser_contract_name"],
                "version": row["parser_contract_version"],
            },
            locator=row["locator_value"],
            quote_start=row["quote_start"],
            quote_end=row["quote_end"],
            quote_sha256=row["quoted_text_sha256"],
        )
    except ValueError as error:
        if str(error) in _PORTABLE_FALLBACK:
            return None
        raise
    return _receipt(quote, "kernel")


def resolve(catalog, citation_id, *, workspace_id, principal_id, root_id, candidate=False, extractor=None, acl_database=None):
    """Resolve a stored citation under the current ACL, from stable source bytes."""
    acl_table = "file_acl"
    if acl_database is not None:
        catalog.conn.execute("ATTACH DATABASE ? AS current_acl",
                             (Path(acl_database).resolve().as_uri() + "?mode=ro",))
        acl_table = "current_acl.file_acl"
    catalog.conn.execute("BEGIN")
    try:
        row = catalog.conn.execute(f"""
            SELECT c.*, f.relative_path, r.canonical_path
            FROM citation c
            JOIN file_record f ON f.file_record_id=c.file_record_id
              AND f.workspace_id=c.workspace_id AND f.source_root_id=c.source_root_id
              AND f.current_source_version_id=c.source_version_id
            JOIN block_instance b ON b.block_instance_id=c.block_instance_id
              AND b.workspace_id=c.workspace_id AND b.source_version_id=c.source_version_id
              AND b.projection_id=c.projection_id AND b.locator_kind=c.locator_kind
              AND b.locator_value=c.locator_value
            JOIN projection p ON p.projection_id=c.projection_id
              AND p.source_version_id=c.source_version_id AND p.source_sha256=c.source_sha256
              AND p.parser_contract_name=c.parser_contract_name
              AND p.parser_contract_version=c.parser_contract_version
            JOIN source_root r ON r.source_root_id=f.source_root_id AND r.workspace_id=f.workspace_id
            JOIN {acl_table} a ON a.file_record_id=f.file_record_id AND a.workspace_id=f.workspace_id
            WHERE c.citation_id=? AND c.workspace_id=? AND c.source_root_id=?
              AND a.principal_id=? AND a.can_read=1 AND r.enabled=1 AND f.catalog_status='active'
        """, (citation_id, workspace_id, root_id, principal_id)).fetchone()
        if row is None:
            raise ValueError("citation unavailable")
        root = Path(row["canonical_path"])
        path = root / row["relative_path"]
        payload, _, digest = catalog._read_stable(root, path)
        if digest != row["source_sha256"]:
            raise ValueError("stale source")
        portable = _portable_quote(path, payload, row)
        if portable is not None:
            return portable
        selected = catalog.extractor if extractor is None else extractor
        result = selected(path.name, payload)
        parser = result["parser_contract"]
        if (parser["name"], parser["version"]) != (
            row["parser_contract_name"], row["parser_contract_version"]
        ):
            raise ValueError("projection parser mismatch")
        item = next((item for item in result["text_items"]
                     if item["source_locator"] == row["locator_value"]), None)
        if item is None:
            raise ValueError("source locator unavailable")
        if row["quote_normalization"] != "unicode_nfc_codepoint_v1":
            raise ValueError("unsupported quote normalization")
        normalized = unicodedata.normalize("NFC", item["text"])
        start, end = row["quote_start"], row["quote_end"]
        if not 0 <= start < end <= len(normalized):
            raise ValueError("invalid quote span")
        quote = normalized[start:end]
        if sha256(quote.encode("utf-8")).hexdigest() != row["quoted_text_sha256"]:
            raise ValueError("quote digest mismatch")
        return _receipt(quote, "local_ai")
    finally:
        catalog.conn.rollback()
        if acl_database is not None:
            catalog.conn.execute("DETACH DATABASE current_acl")
