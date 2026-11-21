from hashlib import sha256
import json
from pathlib import Path
from prodocux_kernel import __version__
from prodocux_kernel.intake import (
    extract_csv_continuable_projection, extract_pptx_continuable_projection,
    extract_xlsx_continuable_projection,
)
PARSERS = {
    ".csv": (extract_csv_continuable_projection, {"max_rows": 64}),
    ".xlsx": (extract_xlsx_continuable_projection, {"max_rows": 64}),
    ".pptx": (extract_pptx_continuable_projection, {"max_slides": 8}),
}

def cells(suffix, page):
    span = page["range"]
    if suffix == ".xlsx":
        for row, values in enumerate(page["rows"], span["start"]):
            for col, value in enumerate(values, 1):
                yield ["xlsx-cell", span["sheet_index"], span["sheet_name"], row, col], value
    elif suffix == ".csv":
        if span["start"] == 0:
            for col, value in enumerate(page["columns"], 1):
                yield ["csv-header", col], value
        for row, values in enumerate(page["rows"], span["start"] + 1):
            for col, value in enumerate(values, 1):
                yield ["csv-data-cell", row, col], value
    else:
        for slide in page["slides"]:
            number = slide["slide_number"]
            for shape in slide["shapes"]:
                shape_id = shape["shape_id"]
                yield ["pptx-shape", number, shape_id], shape["text"]
                for row, values in enumerate(shape["table"] or (), 1):
                    for col, value in enumerate(values, 1):
                        yield ["pptx-table-cell", number, shape_id, row, col], value
            yield ["pptx-notes", number], slide["speaker_notes"]


def extract(filename, payload, *, candidate=False):
    suffix = Path(filename).suffix.lower()
    parser, budget = PARSERS[suffix]
    if candidate and suffix in {".xlsx", ".csv"}:
        budget = {**budget, "contract_version": "2"}
    digest = sha256(payload).hexdigest()
    cursor = None
    seen = set()
    ranges, items = [], []
    omissions = set()
    text_bytes = 0
    for _ in range(64):
        page = parser(payload, cursor=cursor, **budget)
        if page["source_sha256"] != digest:
            raise ValueError("projection source mismatch")
        ranges.append(page["range"])
        omissions.update(page["coverage"]["omitted_content_classes"])
        visible = not candidate or suffix != ".xlsx" or page["range"]["sheet_visibility"] == "visible"
        if not visible:
            omissions.add("hidden_worksheet_excluded_by_host")
        for coordinates, value in cells(suffix, page) if visible else ():
            if value is None or value == "":
                continue
            text = str(value)
            locator = json.dumps(coordinates, ensure_ascii=False, separators=(",", ":"))
            text_bytes += len(text.encode("utf-8"))
            if text_bytes > 1024 * 1024 or len(items) >= 20_000:
                raise ValueError("projection budget exhausted")
            items.append({"source_locator": locator, "text": text, "type": coordinates[0]})
        cursor = page["next_cursor"]
        if cursor is None:
            break
        key = json.dumps(cursor, sort_keys=True)
        if key in seen:
            raise ValueError("repeated projection cursor")
        seen.add(key)
    else:
        raise ValueError("range budget exhausted")
    if len({item["source_locator"] for item in items}) != len(items):
        raise ValueError("duplicate projection locator")
    return {
        "schema_version": "pdx_local_kernel_projection_aggregate_v1",
        "kernel_version": __version__,
        "source_sha256": digest,
        "parser_contract": page["parser_contract"],
        "ranges": ranges,
        "text_items": items,
        "coverage": {"disposition": "partial_unknown" if omissions else "complete",
                     "warnings": sorted(omissions), "omitted_content_classes": sorted(omissions)},
        "counts": {"processed_through_range_end": {"items": len(items)}, "known_total": {}},
        "ocr_disposition": "not_applicable",
    }

