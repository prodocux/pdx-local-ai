import gzip
import json
import os
import sys
import tarfile
from io import BytesIO
from zipfile import ZipFile

from pdx_local_ai.archive_host import index_archive


def _zip() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("owned.txt", "archive marker")
    return buffer.getvalue()


def test_missing_opt_in_or_database_publishes_nothing(tmp_path) -> None:
    payload = _zip()
    for kwargs in (
        {"enabled": False, "database": tmp_path / "archive.sqlite"},
        {"enabled": True, "database": None},
    ):
        result = index_archive("owned.zip", payload, **kwargs)
        assert result["disposition"] == "PROFILE_UNQUALIFIED"
        assert result["searchable"] is False
        assert result["members"] == []


def test_frozen_executable_publishes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    frozen = index_archive("owned.zip", _zip(), enabled=True, database=tmp_path / "archive.sqlite")
    assert frozen["disposition"] == "PROFILE_UNQUALIFIED"
    assert frozen["members"] == []


def test_non_windows_publishes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    foreign = index_archive("owned.zip", _zip(), enabled=True, database=tmp_path / "archive.sqlite")
    assert foreign["disposition"] == "PROFILE_UNQUALIFIED"
    assert foreign["searchable"] is False


def test_native_profiles_stay_unimplemented(tmp_path) -> None:
    result = index_archive("sample.7z", b"7z", enabled=True, database=tmp_path / "archive.sqlite")
    assert result["disposition"] == "PROFILE_NOT_IMPLEMENTED"
    assert result["searchable"] is False
    assert result["members"] == []


def test_depth_above_three_publishes_nothing(tmp_path) -> None:
    result = index_archive(
        "owned.zip", _zip(), enabled=True, database=tmp_path / "archive.sqlite", depth=4,
    )
    assert result["disposition"] == "BUDGET_EXHAUSTED"
    assert result["searchable"] is False
    assert result["members"] == []


def test_traversal_and_duplicate_names_publish_nothing(tmp_path) -> None:
    escaped = BytesIO()
    with ZipFile(escaped, "w") as archive:
        archive.writestr("../owned.txt", "archive marker")
    duplicate = BytesIO()
    with ZipFile(duplicate, "w") as archive:
        archive.writestr("owned.txt", "one")
        archive.writestr("owned.txt", "two")
    for payload in (escaped.getvalue(), duplicate.getvalue()):
        result = index_archive("owned.zip", payload, enabled=True, database=tmp_path / "archive.sqlite")
        assert result["searchable"] is False
        assert result["members"] == []


def test_named_single_stream_publishes_the_outer_document(tmp_path) -> None:
    buffer = BytesIO()
    with gzip.GzipFile(filename="owned.txt", fileobj=buffer, mode="wb") as handle:
        handle.write(b"archive marker")
    result = index_archive(
        "owned.txt.gz", buffer.getvalue(), enabled=True, database=tmp_path / "archive.sqlite",
    )
    assert result["disposition"] == "complete", result["omissions"]
    assert result["archive_profile"] == "gzip-single-member"
    texts = [item["text"] for member in result["members"] for item in member["text_items"]]
    assert "archive marker" in "\n".join(texts)


def test_opted_in_tar_publishes_the_member_text(tmp_path) -> None:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        payload = b"archive marker"
        info = tarfile.TarInfo("owned.txt")
        info.size = len(payload)
        archive.addfile(info, BytesIO(payload))
    result = index_archive("owned.tar", buffer.getvalue(), enabled=True, database=tmp_path / "archive.sqlite")
    assert result["disposition"] == "complete", result["omissions"]
    assert result["archive_profile"] == "tar-ustar-pax-gnu"
    texts = [item["text"] for member in result["members"] for item in member["text_items"]]
    assert "archive marker" in "\n".join(texts)


def test_opted_in_windows_zip_publishes_only_a_full_member(tmp_path) -> None:
    result = index_archive("owned.zip", _zip(), enabled=True, database=tmp_path / "archive.sqlite")
    assert result["searchable"] is True
    assert result["disposition"] == "complete"
    texts = [item["text"] for member in result["members"] for item in member["text_items"]]
    assert "archive marker" in "\n".join(texts)
    locator = result["members"][0]["archive_locator"]
    assert locator["kind"] == "archive_member"
    assert locator["archive_profile"] == "zip-store-deflate"
    assert locator["member_sha256"]
    assert locator["raw_name_sha256"]


def _member(name: str, payload: bytes) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


def _tar(mode: str, suffix: str) -> tuple[str, bytes]:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        payload = b"archive marker"
        info = tarfile.TarInfo("owned.txt")
        info.size = len(payload)
        archive.addfile(info, BytesIO(payload))
    return f"owned.tar{suffix}", buffer.getvalue()


def _texts(result) -> str:
    return "\n".join(item["text"] for member in result["members"] for item in member.get("text_items") or [])


def test_remaining_required_profiles_publish_member_text(tmp_path) -> None:
    import bz2
    import lzma

    samples = {
        "owned.txt.bz2": bz2.compress(b"archive marker"),
        "owned.txt.xz": lzma.compress(b"archive marker"),
    }
    samples[_tar("w:gz", ".gz")[0]] = _tar("w:gz", ".gz")[1]
    samples[_tar("w:bz2", ".bz2")[0]] = _tar("w:bz2", ".bz2")[1]
    samples[_tar("w:xz", ".xz")[0]] = _tar("w:xz", ".xz")[1]
    expected = {
        "owned.txt.bz2": "bzip2-single-stream",
        "owned.txt.xz": "xz-single-stream",
        "owned.tar.gz": "tar-gzip",
        "owned.tar.bz2": "tar-bzip2",
        "owned.tar.xz": "tar-xz",
    }
    for name, payload in samples.items():
        result = index_archive(name, payload, enabled=True, database=tmp_path / f"{name}.sqlite")
        assert result["disposition"] == "complete", (name, result["omissions"])
        assert result["archive_profile"] == expected[name]
        assert "archive marker" in _texts(result)


def _zip64_payload() -> bytes:
    """Insert a real ZIP64 EOCD and locator in front of a normal end record."""
    import struct

    raw = bytearray(_zip())
    eocd = raw.rfind(b"PK\x05\x06")
    count = struct.unpack_from("<H", raw, eocd + 8)[0]
    size, offset = struct.unpack_from("<II", raw, eocd + 12)
    record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, offset)
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
    return bytes(raw[:eocd] + record + locator + raw[eocd:])


def test_zip64_profile_is_selected_and_read(tmp_path) -> None:
    payload = _zip64_payload()
    assert b"PK\x06\x06" in payload and b"PK\x06\x07" in payload
    result = index_archive("owned.zip", payload, enabled=True, database=tmp_path / "zip64.sqlite")
    assert result["archive_profile"] == "zip64-store-deflate", result
    assert result["disposition"] == "complete", result["omissions"]
    assert "archive marker" in _texts(result)


def test_nested_qualified_resolve_replays_the_inner_quote(tmp_path) -> None:
    payload = _member("inner.zip", _member("owned.txt", b"archive marker"))
    result = index_archive(
        "outer.zip", payload, enabled=True, database=tmp_path / "chain.sqlite", replay=True,
    )
    assert result["disposition"] == "complete", result["omissions"]
    replay = result["members"][0]["nested_replay"]
    assert replay["profile"] == "nested-qualified-profiles"
    assert replay["verifier_source"] == "kernel"
    assert replay["quote"] == "archive marker"


def test_nested_archive_reuses_one_ledger(tmp_path) -> None:
    payload = _member("inner.zip", _member("owned.txt", b"archive marker"))
    database = tmp_path / "shared.sqlite"
    result = index_archive("outer.zip", payload, enabled=True, database=database)
    assert result["disposition"] == "complete", result["omissions"]
    assert "archive marker" in _texts(result)
    assert list(tmp_path.glob("nested-*")) == []
    assert database.exists()


def test_four_deep_nest_does_not_publish_the_leaf(tmp_path) -> None:
    payload = _member("owned.txt", b"archive marker")
    for name in ("z1.zip", "z2.zip", "z3.zip"):
        payload = _member(name, payload)
    result = index_archive("outer.zip", payload, enabled=True, database=tmp_path / "deep.sqlite")
    assert result["searchable"] is False
    assert "archive marker" not in _texts(result)
    assert result["omissions"]


def test_zip_bomb_is_not_published(tmp_path) -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=8) as archive:
        archive.writestr("bomb.txt", b"\0" * 20000)
    result = index_archive("bomb.zip", buffer.getvalue(), enabled=True, database=tmp_path / "bomb.sqlite")
    assert result["searchable"] is False
    assert "BUDGET_EXHAUSTED" in result["omissions"]
    assert result["members"] == []


def test_document_leaf_resolve_replays_the_quote(tmp_path) -> None:
    result = index_archive(
        "owned.zip", _zip(), enabled=True, database=tmp_path / "replay.sqlite", replay=True,
    )
    assert result["disposition"] == "complete", result
    replay = result["members"][0]["replay"]
    assert replay["profile"] == "document-leaf-handoff"
    assert replay["verifier_source"] == "kernel"
    assert replay["quote"] == "archive marker"


def test_changed_member_hash_is_refused(tmp_path) -> None:
    result = index_archive(
        "owned.zip", _zip(), enabled=True, database=tmp_path / "changed.sqlite",
        replay=True, claimed_source_sha256="0" * 64,
    )
    assert result["searchable"] is False
    assert result["members"][0]["replay"]["disposition"] != "succeeded"


def test_expired_negotiation_publishes_nothing(tmp_path) -> None:
    import time

    calls = {"n": 0}
    start = time.time_ns() // 1_000_000

    def clock():
        calls["n"] += 1
        if calls["n"] <= 4:
            return start
        return start + 900_001

    result = index_archive("owned.zip", _zip(), enabled=True, database=tmp_path / "expired.sqlite", clock=clock)
    assert result["members"] == []
    assert {result["disposition"], *result["omissions"]} & {"NEGOTIATION_EXPIRED", "SOURCE_LEASE_EXPIRED"}


def test_catalog_digest_change_publishes_nothing(tmp_path, monkeypatch) -> None:
    from prodocux_kernel.archive_intake.negotiation import Negotiation

    real = Negotiation.catalog
    seen = {"n": 0}

    def wrapped(self, owner, now):
        seen["n"] += 1
        value = real(self, owner, now)
        if seen["n"] >= 2:
            value = dict(value)
            value["snapshot_id"] = "f" * 64
        return value

    monkeypatch.setattr(Negotiation, "catalog", wrapped)
    result = index_archive("owned.zip", _zip(), enabled=True, database=tmp_path / "catalog.sqlite")
    assert result["members"] == []
    assert result["disposition"] == "CAPABILITY_CATALOG_CHANGED"


def test_partial_docx_member_is_kept(tmp_path) -> None:
    from pdx_local_ai.archive_host import _project_member

    class Partial:
        def extract(self, filename, payload):
            return {
                "parser_contract": {"name": "prodocux_docx_projection_v1", "version": "1"},
                "coverage": {
                    "disposition": "partial_unknown",
                    "warnings": [],
                    "omitted_content_classes": ["OCR_REQUIRED"],
                },
                "ocr_disposition": "required",
                "text_items": [{"text": "archive marker", "source_locator": "paragraph:0"}],
            }

    kept = _project_member(
        Partial(), "owned.docx",
        {"payload": b"docx", "member_sha256": "ab" * 32},
        "zip-store-deflate",
        {"ordinal": "0", "raw_name_sha256": "cd" * 32},
        "revision",
    )
    assert kept is not None
    assert kept["disclosure_only"] is True
    assert "OCR_REQUIRED" in kept["coverage"]["omitted_content_classes"]
    assert kept["text_items"][0]["text"] == "archive marker"

    from docx import Document

    document = Document()
    document.add_paragraph("archive marker")
    buffer = BytesIO()
    document.save(buffer)
    result = index_archive(
        "owned.zip", _member("owned.docx", buffer.getvalue()),
        enabled=True, database=tmp_path / "docx.sqlite",
    )
    assert result["members"], result
    assert "archive marker" in _texts(result)


def test_source_root_opt_in_gates_archive_status_and_scan(tmp_path) -> None:
    from pdx_local_ai.archive_host import set_archive_opt_in
    from pdx_local_ai.catalog import Catalog
    from pdx_local_ai.service.agent_service import AgentService

    root = tmp_path / "root"
    root.mkdir()
    (root / "owned.zip").write_bytes(_zip())
    catalog = Catalog(tmp_path / "catalog.sqlite")
    root_id = catalog.add_root(workspace_id="ws", canonical_path=str(root))

    class Host:
        pass

    host = Host()
    host.catalog = catalog
    before = AgentService._format_coverage(host, "ws", root_id, "principal", True)
    assert before["archive"] == "PROFILE_UNQUALIFIED"
    assert before["archive_opt_in"] is False
    catalog.scan(source_root_id=root_id)
    assert list(tmp_path.glob("*.archive.sqlite")) == []
    set_archive_opt_in(catalog, root_id, True)
    after = AgentService._format_coverage(host, "ws", root_id, "principal", True)
    assert after["archive_opt_in"] is True
    assert after["archive"] == "eligible"
    catalog.scan(source_root_id=root_id)
    assert list(tmp_path.glob("*.archive.sqlite"))
    texts = catalog.conn.execute("SELECT text FROM block_instance").fetchall()
    assert any("archive marker" in row[0] for row in texts)
    coverage = catalog.conn.execute("SELECT coverage_disposition FROM source_version").fetchone()
    assert coverage[0] == "complete"
    saved = json.loads(catalog.conn.execute(
        "SELECT config_json FROM source_root WHERE source_root_id=?", (root_id,),
    ).fetchone()[0])
    assert saved["archive_files"][0]["disposition"] == "complete"
    assert saved["archive_last_disposition"] == "complete"
    catalog.close()


def test_unqualified_host_does_not_parse_the_zip(tmp_path, monkeypatch) -> None:
    import zipfile

    payload = _zip()

    def boom(*_args, **_kwargs):
        raise AssertionError("host parsed a zip")

    monkeypatch.setattr(zipfile, "ZipFile", boom)
    result = index_archive("owned.zip", payload, enabled=False, database=tmp_path / "closed.sqlite")
    assert result["disposition"] == "PROFILE_UNQUALIFIED"
    assert result["members"] == []


def test_catalog_digest_is_stable_for_one_timestamp(tmp_path) -> None:
    from prodocux_kernel.archive_intake.authority import Identity
    from prodocux_kernel.archive_intake.contracts import digest
    from prodocux_kernel.archive_intake.negotiation import Negotiation
    from prodocux_kernel.archive_intake.sources import ArchiveSources

    sources = ArchiveSources(tmp_path / "catalog.sqlite", ttl_ms=900_000)
    negotiation = Negotiation(sources, isolated_zip_read=True)
    owner = Identity("pdx-local-ai", "local", "indexer")
    now = 1_700_000_000_000
    assert digest(negotiation.catalog(owner, now)) == digest(negotiation.catalog(owner, now))
    later = digest(negotiation.catalog(owner, now + 900_000))
    assert later != digest(negotiation.catalog(owner, now))


def test_catalog_window_edge_still_publishes(tmp_path, monkeypatch) -> None:
    import prodocux_kernel.archive_intake.negotiation as negotiation

    width = 900_000
    edge = 1_700_000_000_000 - (1_700_000_000_000 % width) + width
    state = {"ticks": 0, "now": edge - 50}

    def clock():
        state["ticks"] += 1
        if state["ticks"] > 4:
            state["now"] = edge + 50
        return state["now"]

    monkeypatch.setattr(negotiation, "time_ns", lambda: state["now"] * 1_000_000)
    result = index_archive(
        "owned.zip", _zip(), enabled=True, database=tmp_path / "edge.sqlite", clock=clock,
    )
    assert result["disposition"] == "complete", result["omissions"]
    assert "archive marker" in _texts(result)


def test_host_budget_stops_before_a_fresh_kernel_ledger(tmp_path) -> None:
    from pdx_local_ai.archive_host import _TASK_LIMITS, _new_account

    account = _new_account()
    account["source_bytes"] = _TASK_LIMITS["source_bytes"]
    result = index_archive(
        "owned.zip", _zip(), enabled=True, database=tmp_path / "budget.sqlite", account=account,
    )
    assert result["disposition"] == "BUDGET_EXHAUSTED"
    assert result["members"] == []


def test_pdf_and_docx_preview_resolve(tmp_path) -> None:
    from docx import Document

    document = Document()
    document.add_paragraph("archive marker")
    from reportlab.pdfgen.canvas import Canvas

    docx_buffer = BytesIO()
    document.save(docx_buffer)
    pdf_buffer = BytesIO()
    sheet = Canvas(pdf_buffer)
    sheet.drawString(72, 72, "archive marker is readable")
    sheet.save()
    pdf = pdf_buffer.getvalue()
    docx_result = index_archive(
        "owned.zip", _member("owned.docx", docx_buffer.getvalue()),
        enabled=True, database=tmp_path / "docx.sqlite", replay=True,
    )
    assert docx_result["members"], docx_result
    docx_replay = docx_result["members"][0]["replay"]
    assert docx_replay["quote"] == "archive marker"
    assert docx_replay["complete"] is False
    assert "docx_non_paragraph_content_not_cited" in docx_replay["omissions"]
    pdf_result = index_archive(
        "owned.zip", _member("owned.pdf", pdf),
        enabled=True, database=tmp_path / "pdf.sqlite", replay=True,
    )
    assert pdf_result["members"], pdf_result["omissions"]
    assert pdf_result["members"][0]["replay"]["quote"].strip() == "archive marker is readable"


def test_oversize_and_symlink_archives_are_not_read(tmp_path, monkeypatch) -> None:
    from pdx_local_ai.archive_host import set_archive_opt_in
    from pdx_local_ai.catalog import Catalog

    root = tmp_path / "root"
    root.mkdir()
    (root / "big.zip").write_bytes(_zip())
    (root / "sample.7z").write_bytes(b"7z")
    outside = tmp_path / "outside.zip"
    outside.write_bytes(_member("secret.txt", b"outside marker"))
    link = root / "link.zip"
    try:
        os.symlink(outside, link)
    except OSError:
        link = None
    catalog = Catalog(tmp_path / "catalog.sqlite")
    root_id = catalog.add_root(workspace_id="ws", canonical_path=str(root))
    set_archive_opt_in(catalog, root_id, True)
    monkeypatch.setattr("pdx_local_ai.archive_host.ARCHIVE_READ_LIMIT", 8)
    catalog.scan(source_root_id=root_id)
    saved = json.loads(catalog.conn.execute(
        "SELECT config_json FROM source_root WHERE source_root_id=?", (root_id,),
    ).fetchone()[0])
    dispositions = {row["relative_path"]: row["disposition"] for row in saved["archive_files"]}
    assert dispositions["big.zip"] == "BUDGET_EXHAUSTED"
    assert dispositions["sample.7z"] == "PROFILE_NOT_IMPLEMENTED"
    assert saved["archive_last_disposition"] == "partial_unknown"
    if link is not None:
        assert dispositions["link.zip"] == "INTEGRITY_FAILED"
    texts = catalog.conn.execute("SELECT text FROM block_instance").fetchall()
    assert all("outside marker" not in row[0] for row in texts)
    catalog.close()
