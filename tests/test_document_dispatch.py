import io
import zipfile

import pytest
from openpyxl import Workbook
from pptx import Presentation
from pptx.util import Inches

from pdx_local_ai.document_dispatch import OPTIONAL, dispatch_document
from pdx_local_ai.expanded_formats import ExpandedFormats
from pdx_local_ai.versions import KERNEL_VERSION

NS_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
NS_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
NS_TABLE = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
LONG_TEXT = b"owned\n" * 20480


def _odf(kind, inner):
    root = {"text": "office:text", "spreadsheet": "office:spreadsheet", "presentation": "office:presentation"}[kind]
    content = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<office:document-content xmlns:office="{NS_OFFICE}" xmlns:text="{NS_TEXT}" xmlns:table="{NS_TABLE}">'
        f"<office:body><{root}>{inner}</{root}></office:body></office:document-content>"
    )
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
        f'<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.{kind}"/>'
        "</manifest:manifest>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as package:
        package.writestr("mimetype", f"application/vnd.oasis.opendocument.{kind}".encode())
        package.writestr("META-INF/manifest.xml", manifest)
        package.writestr("content.xml", content)
    return buf.getvalue()


def _epub():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as package:
        package.writestr("mimetype", b"application/epub+zip")
        package.writestr(
            "META-INF/container.xml",
            '<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
            '<rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles>'
            "</container>",
        )
        package.writestr(
            "OEBPS/content.opf",
            '<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0">'
            '<manifest><item id="c" href="chap.xhtml" media-type="application/xhtml+xml"/></manifest>'
            '<spine><itemref idref="c"/></spine></package>',
        )
        package.writestr("OEBPS/chap.xhtml", "<html><body><p>owned</p></body></html>")
    return buf.getvalue()


def _xlsx(columns):
    book = Workbook()
    sheet = book.active
    for column in range(1, columns + 1):
        sheet.cell(1, column, "owned" if column == 1 else "x")
    buf = io.BytesIO()
    book.save(buf)
    return buf.getvalue()


def _pptx(rows):
    deck = Presentation()
    slide = deck.slides.add_slide(deck.slide_layouts[6])
    table = slide.shapes.add_table(rows, 1, Inches(0), Inches(0), Inches(2), Inches(2)).table
    for row in range(rows):
        table.cell(row, 0).text = "owned" if row == 0 else "x"
    buf = io.BytesIO()
    deck.save(buf)
    return buf.getvalue()


def _eml(attachment):
    if not attachment:
        return b"From: a@b.c\r\nTo: d@e.f\r\nSubject: owned\r\n\r\nowned body\r\n"
    return (
        b"From: a@b.c\r\nTo: d@e.f\r\nSubject: owned\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=bound\r\n\r\n"
        b"--bound\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nowned body\r\n"
        b"--bound\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=a.bin\r\n\r\nAAAA\r\n--bound--\r\n"
    )


CASES = [
    ("note.txt", b"owned\n", LONG_TEXT, "projection_item_limit"),
    ("note.md", b"owned\n", LONG_TEXT, "projection_item_limit"),
    ("note.markdown", b"owned\n", LONG_TEXT, "projection_item_limit"),
    ("note.log", b"owned\n", LONG_TEXT, "projection_item_limit"),
    ("note.tsv", b"owned\n", LONG_TEXT, "projection_item_limit"),
    ("note.html", b"<p>owned</p>", b"<p>owned</p>", "html_css_layout_not_evaluated"),
    ("note.htm", b"<p>owned</p>", b"<p>owned</p>", "html_css_layout_not_evaluated"),
    ("note.json", b'{"label":"owned"}', ("{" + ",".join(f'"k{i}":{i}' for i in range(20000)) + "}").encode(), "json_node_limit"),
    ("note.jsonl", b'{"label":"owned"}\n', b'{"n":1}\n' * 1025, "jsonl_record_limit"),
    ("note.odt", _odf("text", "<text:p>owned</text:p>"), _odf("text", "<text:p>owned</text:p>"), "odf_nontext_and_layout_not_projected"),
    ("note.ods", _odf("spreadsheet", '<table:table table:name="S"><table:table-row><table:table-cell office:value-type="string" office:string-value="owned"><text:p>owned</text:p></table:table-cell></table:table-row></table:table>'), _odf("spreadsheet", '<table:table table:name="S"><table:table-row><table:table-cell office:value-type="string" office:string-value="owned"><text:p>owned</text:p></table:table-cell></table:table-row></table:table>'), "odf_nontext_and_layout_not_projected"),
    ("note.odp", _odf("presentation", '<draw:page xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><text:p>owned</text:p></draw:page>'), _odf("presentation", '<draw:page xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><text:p>owned</text:p></draw:page>'), "odf_nontext_and_layout_not_projected"),
    ("note.eml", _eml(False), _eml(True), "eml_attachment_or_message_not_expanded"),
    ("note.epub", _epub(), _epub(), "epub_non_spine_resources_not_projected"),
    ("note.srt", b"1\n00:00:01,000 --> 00:00:02,000\nowned\n\n", b"".join(f"{i}\n00:00:01,000 --> 00:00:02,000\nowned\n\n".encode() for i in range(1, 514)), "document_output_limit"),
    ("note.vtt", b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nowned\n\n", b"WEBVTT\n\n" + b"".join(f"00:00:01.000 --> 00:00:02.000\nowned\n\n".encode() for _ in range(513)), "document_output_limit"),
    ("note.webvtt", b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nowned\n\n", b"WEBVTT\n\n" + b"".join(f"00:00:01.000 --> 00:00:02.000\nowned\n\n".encode() for _ in range(513)), "document_output_limit"),
    ("note.csv", b"owned,other\n1,2\n", ("h" + ",h" * 32 + "\n" + "owned" + ",x" * 32 + "\n").encode(), "columns_beyond_limit"),
    ("sheet.xlsx", _xlsx(2), _xlsx(33), "columns_beyond_limit"),
    ("deck.pptx", _pptx(1), _pptx(51), "table_cells_beyond_limit"),
]


def test_plain_text_uses_the_pinned_kernel() -> None:
    result = dispatch_document("note.txt", b"hello\n")
    assert result["kernel_version"] == KERNEL_VERSION
    assert result["archive_profile"] == "not_applicable"
    assert result["coverage"]["disposition"] == "complete"
    assert any("hello" in item["text"] for item in result["text_items"])


def test_pdf_and_docx_remain_on_the_existing_adapter() -> None:
    with pytest.raises(ValueError, match="USE_EXISTING_PROJECTION_API"):
        dispatch_document("file.pdf", b"%PDF-1.4")
    with pytest.raises(ValueError, match="USE_EXISTING_PROJECTION_API"):
        dispatch_document("file.docx", b"PK")
    with pytest.raises(ValueError, match="USE_EXISTING_PROJECTION_API"):
        dispatch_document("file.pdf", b"%PDF-1.4", ocr=True, record_store=object())


@pytest.mark.parametrize("suffix", sorted(OPTIONAL))
def test_optional_backend_fails_closed_without_records(suffix) -> None:
    with pytest.raises(ValueError, match="OPTIONAL_BACKEND_REQUIRED"):
        dispatch_document(f"scan{suffix}", b"not-a-document")
    with pytest.raises(ValueError, match="OPTIONAL_BACKEND_REQUIRED"):
        dispatch_document(f"scan{suffix}", b"not-a-document", record_store=object())


def test_optional_backend_runs_only_when_a_flag_is_enabled(monkeypatch) -> None:
    seen = {}

    def fake(filename, raw, suffix, *, conversion, ocr, record_store):
        seen["call"] = (filename, conversion, ocr, record_store)
        return {"marker": True}

    monkeypatch.setattr("pdx_local_ai.document_dispatch._backend", fake)
    result = dispatch_document("scan.png", b"x", conversion=True, record_store="store")
    assert result == {"marker": True}
    assert seen["call"] == ("scan.png", True, False, "store")


def test_expanded_formats_stay_opt_in() -> None:
    with pytest.raises(ValueError, match="EXPANDED_FORMATS_DISABLED"):
        ExpandedFormats()


@pytest.mark.parametrize("filename,payload,_truncated,omission", CASES, ids=[case[0] for case in CASES])
def test_new_suffix_positive_projection(filename, payload, _truncated, omission) -> None:
    result = dispatch_document(filename, payload)
    assert result["kernel_version"] == KERNEL_VERSION
    assert result["archive_profile"] == "not_applicable"
    assert any("owned" in item["text"] for item in result["text_items"])
    if filename.endswith((".csv", ".xlsx")):
        assert result["parser_contract"]["version"] == "2"
    if omission == "projection_item_limit":
        assert result["coverage"]["disposition"] == "complete"


@pytest.mark.parametrize("filename,_payload,truncated,omission", CASES, ids=[case[0] for case in CASES])
def test_new_suffix_discloses_truncation(filename, _payload, truncated, omission) -> None:
    result = dispatch_document(filename, truncated)
    assert result["coverage"]["disposition"] == "partial_unknown"
    assert omission in result["coverage"]["omitted_content_classes"]
