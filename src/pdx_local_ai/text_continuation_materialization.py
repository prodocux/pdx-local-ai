"""Gate 5A-2 Continuation Materialization Runtime Implementation Candidate.

Provides the canonical materialization runtime repository, connection authorizer,
two-stage length-checked BLOB ingestion, bounded streaming record iterator,
pre-decode closed schema enforcement, multi-phase transactional staging workflow,
and atomic marker publication for continuation retrieval storage (013_text_continuation_retrieval.sql).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from .validation import ContractError

# Pinned UUIDv5 Namespaces
UUID_NAMESPACE_CONTINUATION_PROJECTION: uuid.UUID = uuid.UUID("3b7f1e52-19e0-4a8a-b851-92b67f10bda4")
UUID_NAMESPACE_CONTINUATION_BLOCK: uuid.UUID = uuid.UUID("7a2c4e68-3d1f-4952-9b24-81d3f9e20a67")

# Governed Enforceable Budgets and Thresholds
MAX_SLICE_SOURCE_BYTES: int = 1048576  # 1 MiB source slice coverage
MAX_SLICE_RAW_JSON_BYTES: int = 786432  # 768 KiB raw JSON payload budget
MAX_SINGLE_RECORD_BYTES: int = 65536  # 64 KiB single record slice budget
MAX_SLICE_RECORD_COUNT: int = 5000  # 5,000 records per slice budget
MAX_GENERATION_RANGES: int = 100000  # 100,000 ranges per generation budget ceiling
MATERIALIZATION_TOTAL_TIMEOUT_MS: int = 60000  # 60 seconds total operation deadline
MATERIALIZATION_SLICE_TIMEOUT_MS: int = 5000  # 5 seconds per-slice deadline
MAX_MATERIALIZATION_BUFFER_BYTES: int = 2097152  # 2 MiB peak active working set limit

# Materialization Table Manifest
MATERIALIZATION_PRIMARY_TABLES: frozenset[str] = frozenset(
    {
        "text_continuation_projection",
        "text_continuation_block_instance",
        "text_continuation_source_range",
        "text_continuation_slice_receipt",
        "text_continuation_generation_accumulator",
        "text_continuation_materialization_marker",
        "text_continuation_fts_binding",
        "text_continuation_block_fts",
    }
)

ALL_CONTINUATION_TABLES: frozenset[str] = frozenset(
    {
        "text_range_artifact",
        "text_range_cursor",
        "text_range_generation",
        "text_range_generation_member",
        "text_range_generation_seal",
        "text_freshness_witness",
        "text_range_publication_event",
        "text_current_published_generation",
        *MATERIALIZATION_PRIMARY_TABLES,
    }
)


def _scan_string_literal(
    raw_bytes: bytes,
    pos: int,
    limit: int,
    start_pos: int,
    max_single_bytes: int,
) -> tuple[bytes, int]:
    """Scans a JSON string literal starting at pos (must be quote \")."""
    if pos >= limit or raw_bytes[pos] != 0x22:  # quote "
        raise ContractError("INVALID_RECORD_SCHEMA: expected string starting with quote")
    str_start = pos
    pos += 1
    escaped = False
    while pos < limit:
        if (pos - start_pos) > max_single_bytes:
            raise ContractError(
                f"RECORD_EXCEEDS_SINGLE_BUDGET: exceeded {max_single_bytes} bytes"
            )
        b = raw_bytes[pos]
        pos += 1
        if escaped:
            escaped = False
        elif b == 0x5C:  # backslash \
            escaped = True
        elif b == 0x22:  # quote "
            return raw_bytes[str_start:pos], pos
    raise ContractError("INVALID_RECORD_SCHEMA: unterminated string")


def _scan_closed_record(
    raw_bytes: bytes,
    start_pos: int,
    limit: int,
    max_single_bytes: int,
) -> tuple[bytes, int]:
    """Byte-level scanner enforcing the closed record schema BEFORE any AST decode.

    Rules strictly enforced:
    1. Only two levels of objects: outer record { } and inner locator { }.
    2. Strictly NO arrays [ ] permitted anywhere inside the record outside strings.
    3. Strictly NO third-level objects { } or nested structures permitted.
    4. Top-level keys strictly {"block_text", "source_range", "line_range", "locator"} (no duplicate keys, no unknown keys).
    5. block_text value must strictly be a JSON string (starts and ends with quote ").
    6. source_range and line_range values must strictly be 2-element non-negative integer arrays [start, end].
    7. locator value must strictly be a JSON object { }.
    8. locator keys strictly {"line_start", "line_end_exclusive", "code_point_start", "code_point_end_exclusive"}.
    9. locator values must strictly be non-negative integer digits [0-9] <= 10 digits and <= 2147483647.
    """
    pos = start_pos
    if pos >= limit or raw_bytes[pos] != 0x7B:  # {
        raise ContractError("INVALID_RECORD_SCHEMA: expected { at record start")
    pos += 1

    def skip_ws(p: int) -> int:
        while p < limit and raw_bytes[p] in b" \t\r\n":
            p += 1
        if (p - start_pos) > max_single_bytes:
            raise ContractError(
                f"RECORD_EXCEEDS_SINGLE_BUDGET: exceeded {max_single_bytes} bytes"
            )
        return p

    seen_record_keys: set[str] = set()

    while True:
        pos = skip_ws(pos)
        if pos >= limit:
            raise ContractError("INVALID_RECORD_SCHEMA: unterminated record object")
        if raw_bytes[pos] == 0x7D:  # }
            pos += 1
            break

        # Scan record key (must be string)
        key_bytes, pos = _scan_string_literal(raw_bytes, pos, limit, start_pos, max_single_bytes)
        if key_bytes == b'"block_text"':
            key_name = "block_text"
        elif key_bytes == b'"source_range"':
            key_name = "source_range"
        elif key_bytes == b'"line_range"':
            key_name = "line_range"
        elif key_bytes == b'"locator"':
            key_name = "locator"
        else:
            raise ContractError(
                f"INVALID_RECORD_SCHEMA: forbidden record key {key_bytes.decode('latin1', errors='replace')}"
            )

        if key_name in seen_record_keys:
            raise ContractError(f"INVALID_RECORD_SCHEMA: duplicate record key {key_name}")
        seen_record_keys.add(key_name)

        pos = skip_ws(pos)
        if pos >= limit or raw_bytes[pos] != 0x3A:  # :
            raise ContractError("INVALID_RECORD_SCHEMA: expected : after key")
        pos += 1
        pos = skip_ws(pos)

        if key_name == "block_text":
            # Strictly JSON string! Must begin with 0x22 (")
            if pos >= limit or raw_bytes[pos] != 0x22:
                raise ContractError("INVALID_RECORD_SCHEMA: block_text must be string")
            _, pos = _scan_string_literal(raw_bytes, pos, limit, start_pos, max_single_bytes)
        elif key_name in ("source_range", "line_range"):
            # Strictly 2-element non-negative integer array [start, end]
            if pos >= limit or raw_bytes[pos] != 0x5B:  # [
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} must be array starting with ["
                )
            pos += 1
            pos = skip_ws(pos)
            # Scan element 1
            if pos >= limit or not (0x30 <= raw_bytes[pos] <= 0x39):
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} element must be non-negative integer digits"
                )
            int1_start = pos
            while pos < limit and 0x30 <= raw_bytes[pos] <= 0x39:
                pos += 1
            if (pos - int1_start) > 10:
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} coordinate exceeds 10 digits"
                )
            val1 = int(raw_bytes[int1_start:pos])
            if val1 > 2147483647:
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} coordinate exceeds max int32"
                )

            pos = skip_ws(pos)
            if pos >= limit or raw_bytes[pos] != 0x2C:  # comma
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: coordinate range array must have exactly 2 elements separated by comma"
                )
            pos += 1
            pos = skip_ws(pos)

            # Scan element 2
            if pos >= limit or not (0x30 <= raw_bytes[pos] <= 0x39):
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} element must be non-negative integer digits"
                )
            int2_start = pos
            while pos < limit and 0x30 <= raw_bytes[pos] <= 0x39:
                pos += 1
            if (pos - int2_start) > 10:
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} coordinate exceeds 10 digits"
                )
            val2 = int(raw_bytes[int2_start:pos])
            if val2 > 2147483647:
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} coordinate exceeds max int32"
                )

            if val1 > val2:
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: {key_name} start cannot exceed end"
                )

            pos = skip_ws(pos)
            if pos >= limit or raw_bytes[pos] != 0x5D:  # ]
                raise ContractError(
                    f"INVALID_RECORD_SCHEMA: coordinate range array must have exactly 2 elements ending with ]"
                )
            pos += 1
        elif key_name == "locator":
            # Strictly JSON object! Must begin with 0x7B ({)
            if pos >= limit or raw_bytes[pos] != 0x7B:
                raise ContractError("INVALID_RECORD_SCHEMA: locator must be object")
            pos += 1
            seen_loc_keys: set[str] = set()
            while True:
                pos = skip_ws(pos)
                if pos >= limit:
                    raise ContractError("INVALID_RECORD_SCHEMA: unterminated locator")
                if raw_bytes[pos] == 0x7D:  # }
                    pos += 1
                    break

                loc_key_bytes, pos = _scan_string_literal(
                    raw_bytes, pos, limit, start_pos, max_single_bytes
                )
                if loc_key_bytes == b'"line_start"':
                    loc_name = "line_start"
                elif loc_key_bytes == b'"line_end_exclusive"':
                    loc_name = "line_end_exclusive"
                elif loc_key_bytes == b'"code_point_start"':
                    loc_name = "code_point_start"
                elif loc_key_bytes == b'"code_point_end_exclusive"':
                    loc_name = "code_point_end_exclusive"
                else:
                    raise ContractError(
                        f"INVALID_RECORD_SCHEMA: forbidden locator key {loc_key_bytes.decode('latin1', errors='replace')}"
                    )

                if loc_name in seen_loc_keys:
                    raise ContractError(
                        f"INVALID_RECORD_SCHEMA: duplicate locator key {loc_name}"
                    )
                seen_loc_keys.add(loc_name)

                pos = skip_ws(pos)
                if pos >= limit or raw_bytes[pos] != 0x3A:  # :
                    raise ContractError("INVALID_RECORD_SCHEMA: expected : after locator key")
                pos += 1
                pos = skip_ws(pos)

                # Strictly non-negative integer digits [0-9]
                if pos >= limit or not (0x30 <= raw_bytes[pos] <= 0x39):
                    raise ContractError(
                        "INVALID_RECORD_SCHEMA: locator coordinate must be non-negative integer digits"
                    )
                int_start = pos
                while pos < limit and 0x30 <= raw_bytes[pos] <= 0x39:
                    pos += 1
                if (pos - int_start) > 10:
                    raise ContractError(
                        "INVALID_RECORD_SCHEMA: locator coordinate exceeds 10 digits"
                    )
                num_val = int(raw_bytes[int_start:pos])
                if num_val > 2147483647:
                    raise ContractError(
                        "INVALID_RECORD_SCHEMA: locator coordinate exceeds max int32"
                    )

                pos = skip_ws(pos)
                if pos < limit and raw_bytes[pos] == 0x2C:  # comma
                    pos += 1
                    pos = skip_ws(pos)
                    if pos < limit and raw_bytes[pos] == 0x7D:  # trailing comma before }
                        raise ContractError("INVALID_RECORD_SCHEMA: trailing comma in locator")
                elif pos < limit and raw_bytes[pos] == 0x7D:  # }
                    pass
                else:
                    raise ContractError("INVALID_RECORD_SCHEMA: expected comma or } in locator")

            if seen_loc_keys != {
                "line_start",
                "line_end_exclusive",
                "code_point_start",
                "code_point_end_exclusive",
            }:
                raise ContractError("INVALID_RECORD_SCHEMA: locator missing required keys")

        pos = skip_ws(pos)
        if pos < limit and raw_bytes[pos] == 0x2C:  # comma
            pos += 1
            pos = skip_ws(pos)
            if pos < limit and raw_bytes[pos] == 0x7D:  # trailing comma before }
                raise ContractError("INVALID_RECORD_SCHEMA: trailing comma in record")
        elif pos < limit and raw_bytes[pos] == 0x7D:  # }
            pass
        else:
            raise ContractError("INVALID_RECORD_SCHEMA: expected comma or } in record")

    if seen_record_keys != {"block_text", "source_range", "line_range", "locator"}:
        raise ContractError("INVALID_RECORD_SCHEMA: record missing required keys")

    rec_bytes = raw_bytes[start_pos:pos]
    if len(rec_bytes) > max_single_bytes:
        raise ContractError(
            f"RECORD_EXCEEDS_SINGLE_BUDGET: {len(rec_bytes)} > {max_single_bytes}"
        )
    return rec_bytes, pos


def fetch_bounded_recomputed_records_blob(
    conn: sqlite3.Connection,
    range_artifact_id: str,
    max_raw_bytes: int = MAX_SLICE_RAW_JSON_BYTES,
    tracker: Any | None = None,
) -> bytes:
    """Two-stage length-checked fetch from SQLite text_range_artifact.

    1. In SQLite, queries `SELECT length(CAST(recomputed_records AS BLOB))` first.
       If the byte length exceeds `max_raw_bytes` (786,432 bytes / 768 KiB), rejects immediately
       with ContractError("RAW_JSON_EXCEEDS_SLICE_BUDGET") WITHOUT fetching the full BLOB payload.
    2. Only if the length check passes, executes `SELECT CAST(recomputed_records AS BLOB)`.
    3. Verifies fetched bytes length matches the pre-checked length and does not exceed `max_raw_bytes`.
    """
    if tracker is not None and hasattr(tracker, "length_query_executed"):
        tracker.length_query_executed = True

    row = conn.execute(
        "SELECT length(CAST(recomputed_records AS BLOB)) FROM text_range_artifact WHERE range_artifact_id = ?",
        (range_artifact_id,),
    ).fetchone()
    if row is None or row[0] is None:
        raise ContractError(f"ARTIFACT_NOT_FOUND: {range_artifact_id}")

    raw_len = row[0]
    if tracker is not None and hasattr(tracker, "length_result"):
        tracker.length_result = raw_len

    if raw_len > max_raw_bytes:
        raise ContractError(
            f"RAW_JSON_EXCEEDS_SLICE_BUDGET: SQLite BLOB length {raw_len} > {max_raw_bytes}"
        )

    if tracker is not None and hasattr(tracker, "blob_query_executed"):
        tracker.blob_query_executed = True

    blob_row = conn.execute(
        "SELECT CAST(recomputed_records AS BLOB) FROM text_range_artifact WHERE range_artifact_id = ?",
        (range_artifact_id,),
    ).fetchone()
    raw_bytes = blob_row[0]
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        raise ContractError("INVALID_BLOB_TYPE: expected bytes from SQLite BLOB cast")

    if tracker is not None and hasattr(tracker, "blob_bytes_fetched"):
        tracker.blob_bytes_fetched = len(raw_bytes)

    if len(raw_bytes) != raw_len or len(raw_bytes) > max_raw_bytes:
        raise ContractError(
            f"RAW_JSON_EXCEEDS_SLICE_BUDGET: fetched {len(raw_bytes)} bytes > {max_raw_bytes}"
        )
    return bytes(raw_bytes)


def bounded_recomputed_records_stream(
    raw_source: str | bytes | bytearray | memoryview | sqlite3.Connection,
    range_artifact_id: str | None = None,
    max_raw_bytes: int = MAX_SLICE_RAW_JSON_BYTES,
    max_single_record_bytes: int = MAX_SINGLE_RECORD_BYTES,
    max_slice_record_count: int = MAX_SLICE_RECORD_COUNT,
    decoder: Any | None = None,
    blob_tracker: Any | None = None,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Bounded streaming parser for recomputed_records JSON.

    Enforces:
    1. Pre-allocation raw input check <= max_raw_bytes (786,432 bytes / 768 KiB).
       When passed an SQLite Connection, enforces two-stage length check before BLOB fetch,
       ensuring oversized payloads (> 768 KiB) are NEVER returned into Python memory.
    2. Strict JSON array envelope (`[` ... `]`).
    3. Bounded byte scan enforcing closed schema on raw UTF-8 bytes BEFORE any AST decode.
    4. Pre-decode single record raw check <= max_single_record_bytes (64 KiB).
       Zero decode calls if any single record exceeds 64 KiB or violates schema.
    5. Strict record schema lock:
       - strictly `{"block_text", "source_range", "line_range", "locator"}`
       - block_text strictly string
       - source_range and line_range strictly 2-element non-negative integer arrays <= 2147483647
       - locator strictly object with 4 non-negative integer fields <= 2147483647
       - coordinate consistency: source_range and line_range must match locator coordinates
       - strictly NO arrays [ ] outside coordinate ranges or third-level objects { }
    6. Strict JSON array grammar:
       - No leading comma
       - No trailing comma
       - Mandatory single comma between records (no missing or consecutive commas).
    7. Slice record count <= max_slice_record_count (5000).
    8. Yields (record_ordinal, record_dict).
    """
    if decoder is None:
        decode_fn = json.loads
    elif hasattr(decoder, "decode"):
        decode_fn = decoder.decode
    else:
        decode_fn = decoder

    if isinstance(raw_source, sqlite3.Connection):
        if range_artifact_id is None:
            raise ContractError(
                "MISSING_RANGE_ARTIFACT_ID: range_artifact_id required when source is Connection"
            )
        raw_bytes = fetch_bounded_recomputed_records_blob(
            raw_source,
            range_artifact_id,
            max_raw_bytes=max_raw_bytes,
            tracker=blob_tracker,
        )
    elif isinstance(raw_source, str):
        # Guard against PEP 393 CPython Flexible String Representation 4-byte expansion:
        # If a caller passes a Python str, verify its actual heap memory allocation sys.getsizeof(raw_source)
        # does not exceed max_raw_bytes (786,432 bytes / 768 KiB).
        # Any string containing characters > U+FFFF (e.g. emoji) promotes the entire string to 4 bytes/char.
        # An oversized string is intercepted immediately with ZERO decode calls prior to allocating any
        # intermediate UTF-8 byte buffer.
        str_mem = sys.getsizeof(raw_source)
        if str_mem > max_raw_bytes:
            raise ContractError(
                f"RAW_STR_EXCEEDS_MEMORY_BUDGET: Python str heap allocation {str_mem} > {max_raw_bytes}"
            )
        raw_bytes = raw_source.encode("utf-8")
    elif isinstance(raw_source, (bytes, bytearray, memoryview)):
        raw_bytes = bytes(raw_source)
    else:
        raise ContractError(
            f"INVALID_INPUT_TYPE: expected bytes, str, or Connection, got {type(raw_source)}"
        )

    if len(raw_bytes) > max_raw_bytes:
        raise ContractError(
            f"RAW_JSON_EXCEEDS_SLICE_BUDGET: {len(raw_bytes)} > {max_raw_bytes}"
        )

    start = 0
    end = len(raw_bytes)
    while start < end and raw_bytes[start] in b" \t\r\n":
        start += 1
    while end > start and raw_bytes[end - 1] in b" \t\r\n":
        end -= 1

    if end - start < 2 or raw_bytes[start] != 0x5B or raw_bytes[end - 1] != 0x5D:  # [ and ]
        raise ContractError("INVALID_JSON_ARRAY: must start with [ and end with ]")

    pos = start + 1
    limit = end - 1
    count = 0

    while pos < limit and raw_bytes[pos] in b" \t\r\n":
        pos += 1

    if pos == limit:
        return

    if pos < limit and raw_bytes[pos] == 0x2C:  # comma
        raise ContractError("INVALID_JSON_ARRAY: leading comma before first record")

    while pos < limit:
        if raw_bytes[pos] != 0x7B:  # {
            raise ContractError(f"INVALID_JSON_ARRAY: expected '{{' at byte {pos}")

        # Scan and strictly validate closed record schema in raw bytes BEFORE calling decode
        rec_bytes, pos = _scan_closed_record(
            raw_bytes, pos, limit, max_single_record_bytes
        )

        try:
            rec_str = rec_bytes.decode("utf-8")
            rec_obj = decode_fn(rec_str)
        except Exception as e:
            if isinstance(e, ContractError):
                raise
            raise ContractError(f"INVALID_RECORD_JSON: {e}")

        loc = rec_obj["locator"]
        if (
            loc["line_start"] > loc["line_end_exclusive"]
            or loc["code_point_start"] > loc["code_point_end_exclusive"]
        ):
            raise ContractError("INVALID_RECORD_SCHEMA: locator start cannot exceed end")

        sr = rec_obj["source_range"]
        lr = rec_obj["line_range"]
        if (
            sr[0] != loc["code_point_start"]
            or sr[1] != loc["code_point_end_exclusive"]
            or lr[0] != loc["line_start"]
            or lr[1] != loc["line_end_exclusive"]
        ):
            raise ContractError(
                "INVALID_RECORD_COORDINATE_MISMATCH: source_range and line_range must match locator coordinates"
            )

        count += 1
        if count > max_slice_record_count:
            raise ContractError(
                f"RECORD_COUNT_EXCEEDS_SLICE_BUDGET: count {count} > {max_slice_record_count}"
            )

        yield count - 1, rec_obj

        while pos < limit and raw_bytes[pos] in b" \t\r\n":
            pos += 1

        if pos < limit:
            if raw_bytes[pos] != 0x2C:  # comma
                raise ContractError(
                    f"INVALID_JSON_ARRAY: missing comma delimiter at byte {pos}"
                )
            pos += 1
            while pos < limit and raw_bytes[pos] in b" \t\r\n":
                pos += 1
            if pos == limit:
                raise ContractError("INVALID_JSON_ARRAY: trailing comma at end of array")


def create_materialization_authorizer(
    get_current_phase: Callable[[], str],
) -> Callable[[int, str | None, str | None, str | None, str | None], int]:
    """Build SQLite authorizer callback enforcing the materialization security contract.

    Policies enforced:
    1. Prohibits all DDL operations (CREATE, DROP, ALTER, ATTACH, DETACH).
    2. Prohibits PRAGMA foreign_keys = OFF / 0. Allows approved read pragmas.
    3. Direct caller mutations against materialization and continuation tables are denied.
    4. Mutating operations are authorized strictly within trusted phases:
       - 'projection': permits INSERT into text_continuation_projection.
       - 'slice': permits INSERT into text_continuation_block_instance,
                  text_continuation_source_range, and text_continuation_slice_receipt.
                  Permits trigger-mediated sync into text_continuation_block_fts,
                  text_continuation_fts_binding, and text_continuation_generation_accumulator.
                  Permits FTS shadow tables operations performed by SQLite FTS5 engine.
       - 'marker': permits INSERT into text_continuation_materialization_marker.
       - 'idle': rejects all mutations.
    """

    def materialization_authorizer(
        action_code: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        trigger_name: str | None,
    ) -> int:
        # 1. Prohibit DDL & Database Attach/Detach
        if action_code in (
            sqlite3.SQLITE_ATTACH,
            sqlite3.SQLITE_DETACH,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_ALTER_TABLE,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_VIEW,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_DROP_INDEX,
        ):
            return sqlite3.SQLITE_DENY

        # 2. Strict PRAGMA foreign_keys = OFF denial
        if action_code == sqlite3.SQLITE_PRAGMA:
            if arg1 == "foreign_keys":
                if str(arg2).upper() in ("OFF", "0"):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            if arg1 in (
                "foreign_keys",
                "table_info",
                "busy_timeout",
                "data_version",
                "page_size",
                "cache_size",
            ):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        # 3. Read permissions, transaction control, standard SQL functions, and recursive queries are permitted
        if action_code in (
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
            sqlite3.SQLITE_TRANSACTION,
            sqlite3.SQLITE_FUNCTION,
            getattr(sqlite3, "SQLITE_RECURSIVE", 33),
        ):
            return sqlite3.SQLITE_OK

        # 4. Deletions on continuation or materialization tables are denied
        if action_code == sqlite3.SQLITE_DELETE:
            if arg1 and arg1.startswith("text_continuation_block_fts"):
                # SQLite FTS5 internal shadow table maintenance during slice staging
                if get_current_phase() == "slice":
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if arg1 in ALL_CONTINUATION_TABLES:
                return sqlite3.SQLITE_DENY

        phase = get_current_phase()

        # 5. Idle phase blocks ALL mutations
        if phase == "idle":
            return sqlite3.SQLITE_DENY

        # 6. Phase-specific authorizations
        if phase == "projection":
            if action_code == sqlite3.SQLITE_INSERT and arg1 == "text_continuation_projection":
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        if phase == "slice":
            # Direct repository slice inserts
            if action_code == sqlite3.SQLITE_INSERT:
                if arg1 in (
                    "text_continuation_block_instance",
                    "text_continuation_source_range",
                    "text_continuation_slice_receipt",
                ):
                    return sqlite3.SQLITE_OK

                # Trigger-mediated FTS and binding inserts
                if arg1 in ("text_continuation_block_fts", "text_continuation_fts_binding"):
                    if trigger_name == "trg_continuation_block_after_insert_sync_fts":
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY

                # Trigger-mediated accumulator initialization (ordinal 0)
                if arg1 == "text_continuation_generation_accumulator":
                    if trigger_name == "trg_receipt_advance_accumulator_insert":
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY

                # SQLite FTS5 internal shadow table inserts
                if arg1 and arg1.startswith("text_continuation_block_fts"):
                    return sqlite3.SQLITE_OK

            # Trigger-mediated accumulator advance (ordinal > 0)
            if action_code == sqlite3.SQLITE_UPDATE:
                if arg1 == "text_continuation_generation_accumulator":
                    if trigger_name == "trg_receipt_advance_accumulator_update":
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY

                # SQLite FTS5 internal shadow table updates
                if arg1 and arg1.startswith("text_continuation_block_fts"):
                    return sqlite3.SQLITE_OK

            return sqlite3.SQLITE_DENY

        if phase == "marker":
            if action_code == sqlite3.SQLITE_INSERT and arg1 == "text_continuation_materialization_marker":
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        return sqlite3.SQLITE_DENY

    return materialization_authorizer


class MaterializationRepository:
    """Canonical repository encapsulating SQLite connection and materialization runtime.

    Enforces private connection ownership, cached_statements=0, foreign keys ON,
    authorizer protection, and three-phase atomic materialization workflow.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if args or kwargs or "conn" in kwargs:
            raise ContractError("EXTERNAL_CONNECTION_PROHIBITED: repository enforces private connection ownership")

        path_str = str(db_path) if db_path is not None else ":memory:"
        # Mandatory cached_statements=0 to ensure authorizer evaluates every statement
        self._conn = sqlite3.connect(path_str, cached_statements=0)
        self._conn.execute("PRAGMA foreign_keys = ON")
        fk_status = self._conn.execute("PRAGMA foreign_keys").fetchone()[0]
        if fk_status != 1:
            self._conn.close()
            raise ContractError("FOREIGN_KEYS_ENFORCEMENT_REQUIRED: foreign_keys pragma is not active")

        self._current_phase: str = "idle"
        self._authorizer = create_materialization_authorizer(lambda: self._current_phase)
        self._conn.set_authorizer(self._authorizer)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> MaterializationRepository:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @property
    def in_transaction(self) -> bool:
        """Returns whether an active transaction is currently in flight."""
        return self._conn.in_transaction

    def execute_query(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[tuple[Any, ...]]:
        """Executes a controlled SQL query under active SQLite authorizer protection.

        Does not expose raw connection or authorizer detachment.
        Mutations, DDL, and unauthorized pragmas are strictly intercepted and denied.
        """
        cursor = self._conn.execute(sql, params)
        if cursor.description is not None:
            return cursor.fetchall()
        return []

    def materialize_generation(
        self,
        generation_id: str,
        *,
        clock: Callable[[], float] = time.perf_counter,
    ) -> dict[str, Any]:
        """Executes the full three-phase continuation materialization workflow.

        Phase 1: Transaction 0 — Projection Genesis
        Phase 2: Transactions 1..N — Incremental Slices (Range Ordinal 0..N-1)
        Phase 3: Transaction Final — Materialization Marker Commitment
        """
        total_start = clock()
        total_deadline = total_start + (MATERIALIZATION_TOTAL_TIMEOUT_MS / 1000.0)
        current_effective_deadline = total_deadline

        # Unified always-active progress handler covering all preflight, Phase 1, Phase 2, and Phase 3 SQL
        def progress_callback() -> int:
            return int(clock() >= current_effective_deadline)

        self._conn.set_progress_handler(progress_callback, 100)

        try:
            # 1. Prerequisite verification: generation and seal
            seal_row = self._conn.execute(
                """
                SELECT total_ranges, total_bytes, source_size_bytes, final_manifest_digest, sealed_at_unix_ms
                FROM text_range_generation_seal
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()
            if seal_row is None:
                raise ContractError(f"GENERATION_NOT_SEALED: generation {generation_id} has no seal")

            total_ranges, seal_total_bytes, source_size_bytes, final_manifest_digest, sealed_at_ms = seal_row

            if total_ranges <= 0:
                raise ContractError(f"INVALID_TOTAL_RANGES: generation {generation_id} has total_ranges <= 0")
            if total_ranges > MAX_GENERATION_RANGES:
                raise ContractError(
                    f"TOTAL_RANGES_EXCEEDS_BUDGET: total_ranges {total_ranges} > {MAX_GENERATION_RANGES}"
                )

            gen_row = self._conn.execute(
                """
                SELECT workspace_id, file_record_id, source_version_id, source_sha256
                FROM text_range_generation
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()
            if gen_row is None:
                raise ContractError(f"GENERATION_NOT_FOUND: {generation_id}")

            workspace_id, file_record_id, source_version_id, source_sha256 = gen_row

            # Bounded pre-check: verify member count, total source coverage, and total blocks in SQLite
            # WITHOUT fetching whole-generation member metadata rows into Python heap memory
            member_agg = self._conn.execute(
                """
                SELECT
                    count(m.range_ordinal),
                    coalesce(sum(m.range_end_exclusive - m.range_start), 0),
                    coalesce(sum(json_array_length(a.recomputed_records)), 0),
                    min(m.range_ordinal),
                    max(m.range_ordinal)
                FROM text_range_generation_member m
                JOIN text_range_artifact a ON a.range_artifact_id = m.range_artifact_id
                WHERE m.generation_id = ?
                """,
                (generation_id,),
            ).fetchone()

            if member_agg is None:
                raise ContractError(f"GENERATION_MEMBERS_NOT_FOUND: {generation_id}")

            (
                actual_member_count,
                covered_source_bytes_sum,
                total_blocks,
                min_ordinal,
                max_ordinal,
            ) = member_agg

            if actual_member_count != total_ranges:
                raise ContractError(
                    f"MEMBER_COUNT_MISMATCH: expected {total_ranges} members, found {actual_member_count}"
                )
            if covered_source_bytes_sum != seal_total_bytes:
                raise ContractError(
                    f"SOURCE_BYTES_MISMATCH: covered {covered_source_bytes_sum} != seal {seal_total_bytes}"
                )
            if min_ordinal != 0 or max_ordinal != total_ranges - 1:
                raise ContractError(
                    f"MEMBER_ORDINAL_RANGE_MISMATCH: expected ordinals 0..{total_ranges - 1}, found {min_ordinal}..{max_ordinal}"
                )
            if total_blocks <= 0:
                raise ContractError("ZERO_BLOCKS_DERIVED: generation has no blocks across member artifacts")

            # Deterministic continuation projection ID derivation
            projection_id = str(
                uuid.uuid5(
                    UUID_NAMESPACE_CONTINUATION_PROJECTION,
                    f"{workspace_id}:{source_version_id}:{generation_id}:{final_manifest_digest}",
                )
            )

            now_ms = int(time.time() * 1000)

            # ----------------------------------------------------------------------
            # Phase 1: Transaction 0 — Projection Genesis
            # ----------------------------------------------------------------------
            if clock() >= total_deadline:
                raise ContractError("MATERIALIZATION_TIMEOUT: expired before Phase 1 Transaction 0")

            self._current_phase = "projection"
            current_effective_deadline = total_deadline
            try:
                self._conn.execute("BEGIN IMMEDIATE")

                # CHECKPOINT_TX0_PRE_INSERT
                if clock() >= total_deadline:
                    self._conn.rollback()
                    raise ContractError("MATERIALIZATION_TIMEOUT: expired before projection insert")

                self._conn.execute(
                    """
                    INSERT INTO text_continuation_projection (
                        projection_id, generation_id, workspace_id, source_version_id,
                        source_sha256, block_count, final_manifest_digest, created_at_unix_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        projection_id,
                        generation_id,
                        workspace_id,
                        source_version_id,
                        source_sha256,
                        total_blocks,
                        final_manifest_digest,
                        now_ms,
                    ),
                )

                # CHECKPOINT_TX0_PRE_COMMIT
                if clock() >= total_deadline:
                    self._conn.rollback()
                    raise ContractError("MATERIALIZATION_TIMEOUT: expired before projection commit")

                self._conn.commit()
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                if self._conn.in_transaction:
                    self._conn.rollback()
                if "interrupted" in str(e).lower() or clock() >= total_deadline:
                    raise ContractError(f"MATERIALIZATION_TIMEOUT: projection SQLite execution timed out ({e})") from e
                raise
            except Exception:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise
            finally:
                current_effective_deadline = total_deadline
                self._current_phase = "idle"

            # ----------------------------------------------------------------------
            # Phase 2: Transactions 1..N — Incremental Slices (Range Ordinal 0..N-1)
            # ----------------------------------------------------------------------
            accumulated_text_bytes = 0

            # Bounded range-by-range iteration: read ONE member row per slice to keep active metadata memory O(1)
            for range_ordinal in range(total_ranges):
                member_row = self._conn.execute(
                    """
                    SELECT m.range_artifact_id, m.range_start, m.range_end_exclusive, m.manifest_digest
                    FROM text_range_generation_member m
                    WHERE m.generation_id = ? AND m.range_ordinal = ?
                    """,
                    (generation_id, range_ordinal),
                ).fetchone()

                if member_row is None:
                    raise ContractError(
                        f"MEMBER_NOT_FOUND: generation {generation_id} ordinal {range_ordinal}"
                    )

                range_artifact_id, range_start, range_end_exclusive, manifest_digest = member_row
                slice_covered_bytes = range_end_exclusive - range_start

                slice_start_time = clock()
                slice_nominal_deadline = slice_start_time + (MATERIALIZATION_SLICE_TIMEOUT_MS / 1000.0)
                slice_effective_deadline = min(total_deadline, slice_nominal_deadline)
                current_effective_deadline = slice_effective_deadline

                self._current_phase = "slice"

                try:
                    self._conn.execute("BEGIN IMMEDIATE")

                    # CHECKPOINT_PRE_FETCH
                    if clock() >= slice_effective_deadline:
                        self._conn.rollback()
                        raise ContractError("MATERIALIZATION_TIMEOUT: expired before slice pre-fetch")

                    slice_block_count = 0
                    slice_materialized_bytes = 0

                    # Bounded streaming record ingestion with two-stage length checked fetch
                    for block_ordinal, rec in bounded_recomputed_records_stream(
                        self._conn,
                        range_artifact_id,
                        max_raw_bytes=MAX_SLICE_RAW_JSON_BYTES,
                        max_single_record_bytes=MAX_SINGLE_RECORD_BYTES,
                        max_slice_record_count=MAX_SLICE_RECORD_COUNT,
                    ):
                        if clock() >= slice_effective_deadline:
                            self._conn.rollback()
                            raise ContractError("MATERIALIZATION_TIMEOUT: expired during slice record ingestion")

                        block_text = rec["block_text"]
                        text_bytes = len(block_text.encode("utf-8"))
                        codepoint_count = len(block_text)
                        block_sha256 = hashlib.sha256(block_text.encode("utf-8")).hexdigest()

                        block_instance_id = str(
                            uuid.uuid5(
                                UUID_NAMESPACE_CONTINUATION_BLOCK,
                                f"{projection_id}:{range_ordinal}:{block_ordinal}",
                            )
                        )

                        # Insert block instance (Triggers automatic FTS & binding synchronization)
                        self._conn.execute(
                            """
                            INSERT INTO text_continuation_block_instance (
                                block_instance_id, projection_id, generation_id, range_artifact_id,
                                range_ordinal, block_ordinal, text, byte_count, codepoint_count,
                                sha256, created_at_unix_ms
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                block_instance_id,
                                projection_id,
                                generation_id,
                                range_artifact_id,
                                range_ordinal,
                                block_ordinal,
                                block_text,
                                text_bytes,
                                codepoint_count,
                                block_sha256,
                                now_ms,
                            ),
                        )

                        # Insert source range locator
                        loc = rec["locator"]
                        self._conn.execute(
                            """
                            INSERT INTO text_continuation_source_range (
                                block_instance_id, projection_id, line_start, line_end_exclusive,
                                source_codepoint_start, source_codepoint_end_exclusive, created_at_unix_ms
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                block_instance_id,
                                projection_id,
                                loc["line_start"],
                                loc["line_end_exclusive"],
                                loc["code_point_start"],
                                loc["code_point_end_exclusive"],
                                now_ms,
                            ),
                        )

                        slice_block_count += 1
                        slice_materialized_bytes += text_bytes

                        # Immediate per-record release
                        del rec

                    # CHECKPOINT_POST_BLOCK_BUILD
                    if clock() >= slice_effective_deadline:
                        self._conn.rollback()
                        raise ContractError("MATERIALIZATION_TIMEOUT: expired after block staging")

                    # Insert slice receipt (Triggers automatic accumulator initialization / advance)
                    self._conn.execute(
                        """
                        INSERT INTO text_continuation_slice_receipt (
                            generation_id, range_ordinal, range_artifact_id, slice_block_count,
                            covered_source_bytes, materialized_text_bytes, slice_manifest_digest, created_at_unix_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            generation_id,
                            range_ordinal,
                            range_artifact_id,
                            slice_block_count,
                            slice_covered_bytes,
                            slice_materialized_bytes,
                            manifest_digest,
                            now_ms,
                        ),
                    )

                    # CHECKPOINT_PRE_COMMIT
                    if clock() >= slice_effective_deadline:
                        self._conn.rollback()
                        raise ContractError("MATERIALIZATION_TIMEOUT: expired before slice commit")

                    self._conn.commit()
                    accumulated_text_bytes += slice_materialized_bytes
                    del member_row  # Immediate per-slice release
                except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                    if self._conn.in_transaction:
                        self._conn.rollback()
                    if "interrupted" in str(e).lower() or clock() >= slice_effective_deadline:
                        raise ContractError(
                            f"MATERIALIZATION_TIMEOUT: slice {range_ordinal} SQLite execution timed out ({e})"
                        ) from e
                    raise
                except Exception:
                    if self._conn.in_transaction:
                        self._conn.rollback()
                    raise
                finally:
                    current_effective_deadline = total_deadline
                    self._current_phase = "idle"

            # ----------------------------------------------------------------------
            # Phase 3: Transaction Final — Materialization Marker Commitment
            # ----------------------------------------------------------------------
            # Prerequisite verification: all slices committed in accumulator
            acc_row = self._conn.execute(
                """
                SELECT completed_ranges, accumulated_blocks, accumulated_source_bytes, accumulated_text_bytes,
                       last_range_ordinal, last_slice_manifest_digest
                FROM text_continuation_generation_accumulator
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()

            if acc_row is None:
                raise ContractError(f"ACCUMULATOR_NOT_FOUND: generation {generation_id}")

            (
                acc_completed,
                acc_blocks,
                acc_source_bytes,
                acc_text_bytes,
                acc_last_ordinal,
                acc_last_digest,
            ) = acc_row

            if acc_completed != total_ranges:
                raise ContractError(
                    f"INCOMPLETE_ACCUMULATOR: completed {acc_completed} != total_ranges {total_ranges}"
                )
            if acc_blocks != total_blocks:
                raise ContractError(
                    f"ACCUMULATOR_BLOCKS_MISMATCH: accumulated {acc_blocks} != derived {total_blocks}"
                )
            if acc_source_bytes != seal_total_bytes:
                raise ContractError(
                    f"ACCUMULATOR_SOURCE_BYTES_MISMATCH: {acc_source_bytes} != seal {seal_total_bytes}"
                )

            self._current_phase = "marker"
            current_effective_deadline = total_deadline
            try:
                self._conn.execute("BEGIN IMMEDIATE")

                # CHECKPOINT_PRE_MARKER_INSERT
                if clock() >= total_deadline:
                    self._conn.rollback()
                    raise ContractError("MATERIALIZATION_TIMEOUT: expired before marker insert")

                # Insert materialization marker
                # Trigger trg_marker_verify_readiness runs full verification + drift view scan
                # Governed by progress_callback checking total_deadline every 100 opcodes
                self._conn.execute(
                    """
                    INSERT INTO text_continuation_materialization_marker (
                        projection_id, generation_id, total_ranges, total_blocks,
                        total_source_bytes, total_materialized_bytes,
                        final_manifest_digest, materialized_at_unix_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        projection_id,
                        generation_id,
                        total_ranges,
                        total_blocks,
                        seal_total_bytes,
                        acc_text_bytes,
                        final_manifest_digest,
                        now_ms,
                    ),
                )

                # CHECKPOINT_POST_MARKER_INSERT_PRE_COMMIT
                # Catches deadline expiration resulting from heavy trigger aggregations and drift scans
                if clock() >= total_deadline:
                    self._conn.rollback()
                    raise ContractError("MATERIALIZATION_TIMEOUT: expired after marker trigger evaluation")

                self._conn.commit()
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                if self._conn.in_transaction:
                    self._conn.rollback()
                if "interrupted" in str(e).lower() or clock() >= total_deadline:
                    raise ContractError(f"MATERIALIZATION_TIMEOUT: marker SQLite execution timed out ({e})") from e
                raise
            except Exception:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise
            finally:
                current_effective_deadline = total_deadline
                self._current_phase = "idle"

            return {
                "projection_id": projection_id,
                "generation_id": generation_id,
                "total_ranges": total_ranges,
                "total_blocks": total_blocks,
                "total_source_bytes": seal_total_bytes,
                "total_materialized_bytes": acc_text_bytes,
                "final_manifest_digest": final_manifest_digest,
                "status": "materialized",
            }
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            if "interrupted" in str(e).lower() or clock() >= total_deadline:
                raise ContractError(f"MATERIALIZATION_TIMEOUT: SQLite execution interrupted by deadline ({e})") from e
            raise
        finally:
            self._conn.set_progress_handler(None, 0)
            self._current_phase = "idle"

    def get_materialization_marker(self, generation_id: str) -> dict[str, Any] | None:
        """Query materialization marker for a generation."""
        row = self._conn.execute(
            """
            SELECT projection_id, generation_id, total_ranges, total_blocks,
                   total_source_bytes, total_materialized_bytes, final_manifest_digest, materialized_at_unix_ms
            FROM text_continuation_materialization_marker
            WHERE generation_id = ?
            """,
            (generation_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "projection_id": row[0],
            "generation_id": row[1],
            "total_ranges": row[2],
            "total_blocks": row[3],
            "total_source_bytes": row[4],
            "total_materialized_bytes": row[5],
            "final_manifest_digest": row[6],
            "materialized_at_unix_ms": row[7],
        }

    def get_generation_accumulator(self, generation_id: str) -> dict[str, Any] | None:
        """Query generation accumulator state."""
        row = self._conn.execute(
            """
            SELECT completed_ranges, accumulated_blocks, accumulated_source_bytes,
                   accumulated_text_bytes, last_range_ordinal, last_slice_manifest_digest, updated_at_unix_ms
            FROM text_continuation_generation_accumulator
            WHERE generation_id = ?
            """,
            (generation_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "completed_ranges": row[0],
            "accumulated_blocks": row[1],
            "accumulated_source_bytes": row[2],
            "accumulated_text_bytes": row[3],
            "last_range_ordinal": row[4],
            "last_slice_manifest_digest": row[5],
            "updated_at_unix_ms": row[6],
        }

    def get_slice_receipts(self, generation_id: str) -> list[dict[str, Any]]:
        """Query committed slice receipts for a generation in ascending order."""
        rows = self._conn.execute(
            """
            SELECT range_ordinal, range_artifact_id, slice_block_count,
                   covered_source_bytes, materialized_text_bytes, slice_manifest_digest, created_at_unix_ms
            FROM text_continuation_slice_receipt
            WHERE generation_id = ?
            ORDER BY range_ordinal ASC
            """,
            (generation_id,),
        ).fetchall()
        return [
            {
                "range_ordinal": r[0],
                "range_artifact_id": r[1],
                "slice_block_count": r[2],
                "covered_source_bytes": r[3],
                "materialized_text_bytes": r[4],
                "slice_manifest_digest": r[5],
                "created_at_unix_ms": r[6],
            }
            for r in rows
        ]

    def get_projection(self, projection_id: str) -> dict[str, Any] | None:
        """Query continuation projection metadata."""
        row = self._conn.execute(
            """
            SELECT projection_id, generation_id, workspace_id, source_version_id,
                   source_sha256, block_count, final_manifest_digest, created_at_unix_ms
            FROM text_continuation_projection
            WHERE projection_id = ?
            """,
            (projection_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "projection_id": row[0],
            "generation_id": row[1],
            "workspace_id": row[2],
            "source_version_id": row[3],
            "source_sha256": row[4],
            "block_count": row[5],
            "final_manifest_digest": row[6],
            "created_at_unix_ms": row[7],
        }

    def search_blocks(self, projection_id: str, fts_query: str) -> list[dict[str, Any]]:
        """Search materialized blocks via FTS virtual table (strictly marker-gated).

        Enforces mandatory JOIN against text_continuation_materialization_marker.
        If a generation is unmaterialized, incomplete, or unmarked, returns an empty list.
        """
        rows = self._conn.execute(
            """
            SELECT b.block_instance_id, b.range_ordinal, b.block_ordinal, b.text,
                   r.line_start, r.line_end_exclusive, r.source_codepoint_start, r.source_codepoint_end_exclusive
            FROM text_continuation_block_fts f
            JOIN text_continuation_block_instance b ON b.block_instance_id = f.block_instance_id
            JOIN text_continuation_materialization_marker m ON m.projection_id = b.projection_id
            JOIN text_continuation_source_range r ON r.block_instance_id = b.block_instance_id
            WHERE f.text MATCH ? AND b.projection_id = ?
            ORDER BY b.range_ordinal ASC, b.block_ordinal ASC
            """,
            (fts_query, projection_id),
        ).fetchall()
        return [
            {
                "block_instance_id": r[0],
                "range_ordinal": r[1],
                "block_ordinal": r[2],
                "text": r[3],
                "line_start": r[4],
                "line_end_exclusive": r[5],
                "source_codepoint_start": r[6],
                "source_codepoint_end_exclusive": r[7],
            }
            for r in rows
        ]
