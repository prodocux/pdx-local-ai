import sqlite3
from hashlib import sha256
from pathlib import Path

import pytest

from pdx_local_ai.document_dispatch import OFFICE, dispatch_document
from pdx_local_ai.source_replay import resolve
from test_document_dispatch import CASES


def _catalog(payload):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE citation (
          citation_id TEXT, workspace_id TEXT, source_root_id TEXT, file_record_id TEXT,
          source_version_id TEXT, block_instance_id TEXT, projection_id TEXT,
          locator_kind TEXT, locator_value TEXT, source_sha256 TEXT,
          parser_contract_name TEXT, parser_contract_version TEXT,
          quote_start INTEGER, quote_end INTEGER, quoted_text_sha256 TEXT,
          quote_normalization TEXT
        );
        CREATE TABLE file_record (
          file_record_id TEXT, workspace_id TEXT, source_root_id TEXT,
          current_source_version_id TEXT, relative_path TEXT, catalog_status TEXT
        );
        CREATE TABLE block_instance (
          block_instance_id TEXT, workspace_id TEXT, source_version_id TEXT,
          projection_id TEXT, locator_kind TEXT, locator_value TEXT
        );
        CREATE TABLE projection (
          projection_id TEXT, source_version_id TEXT, source_sha256 TEXT,
          parser_contract_name TEXT, parser_contract_version TEXT
        );
        CREATE TABLE source_root (
          source_root_id TEXT, workspace_id TEXT, canonical_path TEXT, enabled INTEGER
        );
        CREATE TABLE file_acl (
          file_record_id TEXT, workspace_id TEXT, principal_id TEXT, can_read INTEGER
        );
        """
    )

    class Catalog:
        def __init__(self, data):
            self.conn = conn
            self.data = data

        def _read_stable(self, root, path):
            return self.data, None, sha256(self.data).hexdigest()

    return Catalog(payload)


def _store(catalog, filename, projection, item):
    quote = item["text"]
    parser = projection["parser_contract"]
    digest = projection["source_sha256"]
    catalog.conn.execute(
        "INSERT INTO citation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "cite", "ws", "root", "file", "version", "block", "projection",
            "source", item["source_locator"], digest, parser["name"], parser["version"],
            0, len(quote), sha256(quote.encode("utf-8")).hexdigest(), "unicode_nfc_codepoint_v1",
        ),
    )
    catalog.conn.execute(
        "INSERT INTO file_record VALUES (?,?,?,?,?,?)",
        ("file", "ws", "root", "version", filename, "active"),
    )
    catalog.conn.execute(
        "INSERT INTO block_instance VALUES (?,?,?,?,?,?)",
        ("block", "ws", "version", "projection", "source", item["source_locator"]),
    )
    catalog.conn.execute(
        "INSERT INTO projection VALUES (?,?,?,?,?)",
        ("projection", "version", digest, parser["name"], parser["version"]),
    )
    catalog.conn.execute(
        "INSERT INTO source_root VALUES (?,?,?,?)",
        ("root", "ws", "C:/sources/example/source", 1),
    )
    catalog.conn.execute("INSERT INTO file_acl VALUES (?,?,?,?)", ("file", "ws", "principal", 1))
    catalog.conn.commit()


def _owned(projection):
    return next(item for item in projection["text_items"] if "owned" in item["text"])


@pytest.mark.parametrize("filename,payload,_truncated,_omission", CASES, ids=[case[0] for case in CASES])
def test_resolve_document_replay_names_the_verifier(filename, payload, _truncated, _omission):
    projection = dispatch_document(filename, payload)
    item = _owned(projection)
    catalog = _catalog(payload)
    _store(catalog, filename, projection, item)
    suffix = Path(filename).suffix.lower()

    def extractor(name, raw):
        assert suffix in OFFICE
        return projection

    receipt = resolve(
        catalog, "cite", workspace_id="ws", principal_id="principal", root_id="root", extractor=extractor,
    )
    assert receipt["quote"] == item["text"]
    assert receipt["verifier_source"] == ("local_ai" if suffix in OFFICE else "kernel")


@pytest.mark.parametrize("filename,payload,_truncated,_omission", CASES, ids=[case[0] for case in CASES])
def test_changed_source_is_refused(filename, payload, _truncated, _omission):
    projection = dispatch_document(filename, payload)
    item = _owned(projection)
    catalog = _catalog(payload + b"!")
    _store(catalog, filename, projection, item)
    with pytest.raises(ValueError, match="stale source"):
        resolve(
            catalog, "cite", workspace_id="ws", principal_id="principal", root_id="root",
            extractor=lambda name, raw: (_ for _ in ()).throw(AssertionError("extractor ran")),
        )
