"""Gate 5A-2 Continuation Runtime Implementation.

Provides the canonical runtime repository, connection authorizer, monotonic cursor advance,
stream-safe boundary cutting, source protection, hash-chain recomputation, and atomic publication
for text range continuation (012_text_range_continuation.sql).
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sqlite3
import sys
import time
import unicodedata
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .text_intake_decode import (
    LINE_CODEPOINT_BUDGET,
    PACK_LINE_BUDGET,
    _split_lines,
    _stored_length,
)
from .text_intake_route import (
    PROJECTION_BYTE_BUDGET,
    ControlledSnapshot,
    _handle_info,
    _mtime_ns,
    _read_file,
    _seek,
    _size_of,
)
from .validation import ContractError

GENESIS_TEXT: str = "pdx_local_aggregate_manifest_v1\n"
GENESIS_DIGEST_HEX: str = "f3207ab9220fdd13edba85174ea823e315e421bcde37c4dda94f452ab6f733ae"
PARSER_CONTRACT_NAME: str = "pdx_local_text_decoder"
PARSER_CONTRACT_VERSION: str = "1"
BUDGET_PROFILE_ID: str = "pdx_local_text_continuation_budget_v1"
NFC_STREAM_SAFE_PROFILE: str = "pdx_local_nfc_stream_safe_boundary_v1"
NFC_UNICODE_VERSION: str = "15.0.0"

CONTINUATION_TABLES: frozenset[str] = frozenset(
    {
        "text_range_artifact",
        "text_range_cursor",
        "text_range_generation",
        "text_range_generation_member",
        "text_range_generation_seal",
        "text_freshness_witness",
        "text_range_publication_event",
        "text_current_published_generation",
    }
)

FILE_SHARE_READ: int = 1
_STREAM_CHUNK_BYTES: int = 65536
DEFAULT_MAX_FRESHNESS_BYTES: int = 100 * 1024 * 1024
DEFAULT_MAX_FRESHNESS_TIMEOUT_MS: int = 30000


def _escape(text: str) -> str:
    pieces: list[str] = []
    for char in text:
        code = ord(char)
        if char == '"':
            pieces.append('\\"')
        elif char == "\\":
            pieces.append("\\\\")
        elif char == "\b":
            pieces.append("\\b")
        elif char == "\f":
            pieces.append("\\f")
        elif char == "\n":
            pieces.append("\\n")
        elif char == "\r":
            pieces.append("\\r")
        elif char == "\t":
            pieces.append("\\t")
        elif code < 0x20:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(char)
    return '"' + "".join(pieces) + '"'


def _integer(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError("manifest number is not a non-negative integer")
    return str(value)


def canonical_records(records: list[dict[str, Any]]) -> bytes:
    """Format recomputed records into canonical utf-8 bytes per pdx_local_aggregate_manifest_v1."""
    encoded: list[str] = []
    for record in records:
        locator = record["locator"]
        encoded.append(
            "{"
            + '"block_text":'
            + _escape(record["block_text"])
            + ',"source_range":['
            + _integer(record["source_range"][0])
            + ","
            + _integer(record["source_range"][1])
            + '],"line_range":['
            + _integer(record["line_range"][0])
            + ","
            + _integer(record["line_range"][1])
            + '],"locator":{"line_start":'
            + _integer(locator["line_start"])
            + ',"line_end_exclusive":'
            + _integer(locator["line_end_exclusive"])
            + ',"code_point_start":'
            + _integer(locator["code_point_start"])
            + ',"code_point_end_exclusive":'
            + _integer(locator["code_point_end_exclusive"])
            + "}}"
        )
    return ("[" + ",".join(encoded) + "]").encode("utf-8")


def genesis_digest() -> bytes:
    """Return the raw 32-byte binary genesis manifest digest."""
    return hashlib.sha256(GENESIS_TEXT.encode("ascii")).digest()


def fold_digest(previous: bytes, records: list[dict[str, Any]]) -> bytes:
    """Fold previous raw 32-byte manifest digest with canonical records bytes."""
    return hashlib.sha256(previous + canonical_records(records)).digest()


# Windows ByHandleInfo ctypes structures
class _FileTime(ctypes.Structure):
    _fields_ = (
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    )


class _ByHandleInfo(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FileTime),
        ("ftLastAccessTime", _FileTime),
        ("ftLastWriteTime", _FileTime),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    )


def _get_handle_info_windows(handle: int) -> tuple[str, int]:
    """Retrieve snapshot identity and file size in bytes directly from protected Windows handle."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    info = _ByHandleInfo()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    identity = f"{info.dwVolumeSerialNumber}:{info.nFileIndexHigh}:{info.nFileIndexLow}"
    size_bytes = (info.nFileSizeHigh << 32) | info.nFileSizeLow
    return identity, size_bytes


def _hash_handle_with_budget(
    kernel32: ctypes.WinDLL,
    handle: int,
    *,
    max_bytes_budget: int = DEFAULT_MAX_FRESHNESS_BYTES,
    max_time_budget_ms: int = DEFAULT_MAX_FRESHNESS_TIMEOUT_MS,
) -> tuple[str, int]:
    """Hash the entire handle content with explicit memory, byte and time limits."""
    digest = hashlib.sha256()
    size = 0
    start_time = time.monotonic()
    while True:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        if elapsed_ms > max_time_budget_ms:
            raise ContractError("FRESHNESS_TIME_BUDGET_EXCEEDED: snapshot hash time budget exceeded")
        block = ctypes.create_string_buffer(_STREAM_CHUNK_BYTES)
        payload = _read_file(kernel32, handle, block)
        if payload is None:
            raise ContractError("controlled snapshot spool is not intact")
        if not payload:
            return digest.hexdigest(), size
        digest.update(payload)
        size += len(payload)
        if size > max_bytes_budget:
            raise ContractError("FRESHNESS_BYTE_BUDGET_EXCEEDED: snapshot hash byte budget exceeded")


def chunk_continuation_slice(
    text: str,
    *,
    start_line: int = 1,
    in_unclosed_line: bool = False,
    in_hard_chunk_line: bool = False,
    start_codepoint: int = 0,
    max_blocks: int | None = None,
) -> tuple[list[dict[str, Any]], int, bool, int, bool]:
    """Applies pdx_local_text_chunker_v1 (40-line packing, 8192 hard chunking) across range boundaries.

    Returns: (records, next_line, next_in_unclosed_line, next_codepoint, next_in_hard_chunk_line)
    """
    raw_lines = _split_lines(text)
    if not raw_lines:
        return [], start_line, in_unclosed_line, start_codepoint, in_hard_chunk_line

    mapped_lines: list[tuple[str, int, int, int, bool]] = []
    cur_line = start_line
    for idx, (content, r_s, r_e) in enumerate(raw_lines):
        if idx == 0 and in_unclosed_line:
            line_num = cur_line
        elif idx == 0:
            line_num = cur_line
        else:
            cur_line += 1
            line_num = cur_line
        has_newline = (idx < len(raw_lines) - 1) or bool(text and text[-1] in "\r\n")
        mapped_lines.append((content, start_codepoint + r_s, start_codepoint + r_e, line_num, has_newline))

    ends_with_newline = bool(text and text[-1] in "\r\n")
    if ends_with_newline:
        next_line = cur_line + 1
        next_in_unclosed_line = False
    else:
        next_line = cur_line
        next_in_unclosed_line = True

    next_codepoint = start_codepoint + len(text)

    blocks: list[dict[str, Any]] = []
    pending: list[tuple[str, int, int, int]] = []

    def full() -> bool:
        return max_blocks is not None and len(blocks) >= max_blocks

    def emit(piece: str, l_start: int, l_end: int, c_start: int, c_end: int) -> bool:
        if full():
            return False
        blocks.append({
            "block_text": piece,
            "source_range": [c_start, c_end],
            "line_range": [l_start, l_end],
            "locator": {
                "line_start": l_start,
                "line_end_exclusive": l_end,
                "code_point_start": c_start,
                "code_point_end_exclusive": c_end,
            },
        })
        return True

    def close_pending() -> bool:
        if not pending:
            return True
        stored = "\n".join(item[0] for item in pending)
        l_start = pending[0][3]
        l_end = pending[-1][3] + 1
        c_start = pending[0][1]
        c_end = pending[-1][2]
        if not emit(stored, l_start, l_end, c_start, c_end):
            return False
        pending.clear()
        return True

    current_hard_chunk = in_hard_chunk_line

    for idx, (content, c_start, c_end, line_num, has_nl) in enumerate(mapped_lines):
        is_hard = False
        if idx == 0 and in_unclosed_line and in_hard_chunk_line:
            is_hard = True
        elif len(content) > LINE_CODEPOINT_BUDGET:
            is_hard = True
        elif len(content) >= LINE_CODEPOINT_BUDGET and not has_nl:
            is_hard = True

        if is_hard:
            if not close_pending():
                break
            offset = 0
            while offset < len(content):
                if full():
                    break
                piece = content[offset : offset + LINE_CODEPOINT_BUDGET]
                if not emit(piece, line_num, line_num + 1, c_start + offset, c_start + offset + len(piece)):
                    break
                offset += LINE_CODEPOINT_BUDGET

            if has_nl:
                current_hard_chunk = False
            else:
                current_hard_chunk = True
            continue

        candidate = [*pending, (content, c_start, c_end, line_num)]
        if pending and (len(candidate) > PACK_LINE_BUDGET or _stored_length(candidate) > LINE_CODEPOINT_BUDGET):
            if not close_pending():
                break
        if full():
            break
        pending.append((content, c_start, c_end, line_num))
        if has_nl:
            current_hard_chunk = False
        else:
            current_hard_chunk = False

    close_pending()
    next_in_hard_chunk_line = current_hard_chunk if next_in_unclosed_line else False
    return blocks, next_line, next_in_unclosed_line, next_codepoint, next_in_hard_chunk_line


def extract_snapshot_slice(snapshot: ControlledSnapshot, start: int, end_exclusive: int) -> bytes:
    """Extract byte slice [start:end_exclusive] from authoritative ControlledSnapshot."""
    if not isinstance(snapshot, ControlledSnapshot):
        raise ContractError("CONTROLLED_SNAPSHOT_REQUIRED: snapshot must be an authoritative ControlledSnapshot instance")
    if end_exclusive > snapshot.size or start < 0 or start >= end_exclusive:
        raise ContractError("SNAPSHOT_SLICE_OUT_OF_BOUNDS: requested slice beyond snapshot boundaries")
    limit = end_exclusive - start
    return snapshot.read_at(start, limit)


def recompute_causal_outputs(
    slice_bytes: bytes,
    *,
    range_ordinal: int,
    previous_manifest_digest: str,
    input_decoder_state: str,
    expected_decoder_profile: str | None = None,
) -> tuple[str, str, str, str, list[dict[str, Any]], str]:
    """Recomputes all causal outputs strictly from slice bytes and previous causal inputs.

    Returns:
    (owned_byte_slice_sha256, manifest_digest, next_decoder_state, decoder_profile, recomputed_records, input_decoder_state)
    """
    if range_ordinal == 0:
        if previous_manifest_digest != GENESIS_DIGEST_HEX:
            raise ContractError("GENESIS_MANIFEST_DIGEST_REQUIRED: ordinal 0 must use canonical genesis manifest digest")

        # BOM detection on ordinal 0 only
        if slice_bytes.startswith(b"\xef\xbb\xbf"):
            decoder_profile = "utf-8-bom"
            body = slice_bytes[3:]
            py_encoding = "utf-8"
        elif slice_bytes.startswith(b"\xff\xfe"):
            decoder_profile = "utf-16-le-bom"
            body = slice_bytes[2:]
            py_encoding = "utf-16-le"
        elif slice_bytes.startswith(b"\xfe\xff"):
            decoder_profile = "utf-16-be-bom"
            body = slice_bytes[2:]
            py_encoding = "utf-16-be"
        else:
            decoder_profile = expected_decoder_profile or "utf-8"
            body = slice_bytes
            py_encoding = (
                "utf-16-le" if "utf-16-le" in decoder_profile
                else ("utf-16-be" if "utf-16-be" in decoder_profile else "utf-8")
            )

        resolved_input_state = input_decoder_state or "initial"
        start_line = 1
        in_unclosed_line = False
        in_hard_chunk_line = False
        start_codepoint = 0
    else:
        # Ordinal >= 1: Extract decoder profile from input_decoder_state if not explicitly provided
        extracted_profile = None
        start_line = 1
        in_unclosed_line = False
        in_hard_chunk_line = False
        start_codepoint = 0
        if input_decoder_state and input_decoder_state != "initial":
            try:
                parsed = json.loads(input_decoder_state)
                if isinstance(parsed, dict):
                    extracted_profile = parsed.get("profile")
                    start_line = parsed.get("current_line", parsed.get("next_line", 1))
                    in_unclosed_line = parsed.get("in_unclosed_line", False)
                    in_hard_chunk_line = parsed.get("in_hard_chunk_line", False)
                    start_codepoint = parsed.get("current_codepoint", parsed.get("next_codepoint", 0))
            except Exception:
                pass

        decoder_profile = expected_decoder_profile or extracted_profile or "utf-8"
        py_encoding = (
            "utf-16-le" if "utf-16-le" in decoder_profile
            else ("utf-16-be" if "utf-16-be" in decoder_profile else "utf-8")
        )
        body = slice_bytes  # Ordinals >= 1 do not strip BOM
        resolved_input_state = input_decoder_state

    try:
        decoded_text = body.decode(py_encoding)
    except UnicodeDecodeError as e:
        raise ContractError(f"DECODE_ERROR: slice cannot be decoded as {py_encoding}: {e}")

    normalized_text = unicodedata.normalize("NFC", decoded_text)
    owned_byte_slice_sha256 = hashlib.sha256(slice_bytes).hexdigest()

    records, next_line, next_in_unclosed, next_codepoint, next_in_hard_chunk = chunk_continuation_slice(
        normalized_text,
        start_line=start_line,
        in_unclosed_line=in_unclosed_line,
        in_hard_chunk_line=in_hard_chunk_line,
        start_codepoint=start_codepoint,
    )

    next_decoder_state = json.dumps(
        {
            "current_codepoint": next_codepoint,
            "current_line": next_line,
            "in_hard_chunk_line": next_in_hard_chunk,
            "in_unclosed_line": next_in_unclosed,
            "profile": decoder_profile,
        },
        sort_keys=True,
    )
    manifest_digest = fold_digest(bytes.fromhex(previous_manifest_digest), records).hex()

    return (
        owned_byte_slice_sha256,
        manifest_digest,
        next_decoder_state,
        decoder_profile,
        records,
        resolved_input_state,
    )


def is_stream_safe_boundary(data: bytes, offset: int, encoding: str = "utf-8") -> bool:
    """Check boundary cutting safety per decoder-safe, CRLF, and NFC stream-safe Unicode 15.0 rules."""
    if offset <= 0 or offset >= len(data):
        return True

    py_encoding = (
        "utf-16-le" if "utf-16-le" in encoding
        else ("utf-16-be" if "utf-16-be" in encoding else "utf-8")
    )

    # 1. Encoding-level boundary checks
    if py_encoding == "utf-8":
        # Disallow cutting within multi-byte UTF-8 sequence (continuation bytes: 10xxxxxx)
        if 0x80 <= data[offset] <= 0xBF:
            return False
        # Disallow cutting between CRLF (\r\n)
        if data[offset - 1 : offset + 1] == b"\r\n":
            return False
    elif py_encoding.startswith("utf-16"):
        # UTF-16 code units must align on 2 bytes
        if offset % 2 != 0:
            return False
        if py_encoding == "utf-16-le":
            # Disallow cutting between CRLF in UTF-16LE (\r\x00\n\x00)
            if offset >= 2 and offset + 2 <= len(data):
                if data[offset - 2 : offset + 2] == b"\r\x00\n\x00":
                    return False
            # Disallow surrogate pair cut
            if offset >= 2:
                cu = int.from_bytes(data[offset - 2 : offset], "little")
                if 0xD800 <= cu <= 0xDBFF:
                    return False
        elif py_encoding == "utf-16-be":
            # Disallow cutting between CRLF in UTF-16BE (\x00\r\x00\n)
            if offset >= 2 and offset + 2 <= len(data):
                if data[offset - 2 : offset + 2] == b"\x00\r\x00\n":
                    return False
            if offset >= 2:
                cu = int.from_bytes(data[offset - 2 : offset], "big")
                if 0xD800 <= cu <= 0xDBFF:
                    return False

    # 2. Decode verification
    try:
        s1 = data[:offset].decode(py_encoding)
        s2 = data[offset:].decode(py_encoding)
    except UnicodeDecodeError:
        return False

    if not s1 or not s2:
        return True

    # 3. Unicode normalization segment safety
    # A cut is forbidden if normalizing the halves separately yields different NFC text than normalizing whole
    tail = s1[-4:]
    head = s2[:4]
    if unicodedata.normalize("NFC", tail + head) != (
        unicodedata.normalize("NFC", tail) + unicodedata.normalize("NFC", head)
    ):
        return False

    prev_char = s1[-1]
    curr_char = s2[0]

    # Explicit Hangul and Combining sequence rules
    # Hangul L (0x1100..0x1112) and V (0x1161..0x1175)
    if 0x1100 <= ord(prev_char) <= 0x1112 and 0x1161 <= ord(curr_char) <= 0x1175:
        return False

    # Hangul V (0x1161..0x1175) and T (0x11A8..0x11C2)
    if 0x1161 <= ord(prev_char) <= 0x1175 and 0x11A8 <= ord(curr_char) <= 0x11C2:
        return False

    # Hangul LV precomposed syllable and T
    prev_ord = ord(prev_char)
    if 0xAC00 <= prev_ord <= 0xD7A3:
        if (prev_ord - 0xAC00) % 28 == 0 and 0x11A8 <= ord(curr_char) <= 0x11C2:
            return False

    # Starter followed by combining non-starter
    if unicodedata.combining(curr_char) > 0:
        return False

    return True


def find_stream_safe_boundary(
    data: bytes,
    max_bytes: int,
    encoding: str = "utf-8",
) -> tuple[int, str | None]:
    """Find largest stream-safe byte boundary <= max_bytes within data.

    Returns (safe_offset, terminal_reason). If budget is exhausted before finding
    a non-empty safe boundary, returns (0, 'RANGE_UNIT_EXCEEDS_BUDGET').
    """
    limit = min(max_bytes, len(data))
    for offset in range(limit, 0, -1):
        if is_stream_safe_boundary(data, offset, encoding):
            return offset, None

    return 0, "RANGE_UNIT_EXCEEDS_BUDGET"


def is_approved_chunk_boundary(
    slice_text: str,
    lookahead_text: str,
    *,
    is_eof: bool,
    in_unclosed_line: bool = False,
    in_hard_chunk_line: bool = False,
) -> tuple[bool, str | None]:
    """Verify range end offset terminates on an approved chunker block boundary.

    Enforces that packed blocks emitted by pdx_local_text_chunker_v1 stay intact
    and are not arbitrarily fragmented across artifacts.
    """
    if is_eof:
        return True, None

    if in_unclosed_line:
        # Continuing an unclosed physical line from previous artifact
        first_nl = -1
        for i, ch in enumerate(slice_text):
            if ch in "\r\n":
                first_nl = i
                break

        if first_nl == -1:
            # Whole slice remains within unclosed physical line; must align on 8192-codepoint hard chunk
            if len(slice_text) > 0 and len(slice_text) % LINE_CODEPOINT_BUDGET == 0:
                return True, None
            return False, f"unapproved boundary: continuation unclosed line segment has {len(slice_text)} code points, not a multiple of 8192"

        # The unclosed line finishes at first_nl; inspect remaining lines after the newline
        rem_start = first_nl + 1
        if slice_text[first_nl] == "\r" and rem_start < len(slice_text) and slice_text[rem_start] == "\n":
            rem_start += 1
        rem_text = slice_text[rem_start:]
        return is_approved_chunk_boundary(rem_text, lookahead_text, is_eof=is_eof, in_unclosed_line=False, in_hard_chunk_line=False)

    # Standard case starting at physical line boundary
    if slice_text and slice_text[-1] not in "\r\n":
        last_nl = max(slice_text.rfind("\n"), slice_text.rfind("\r"))
        unclosed_len = len(slice_text) if last_nl == -1 else len(slice_text) - (last_nl + 1)
        if unclosed_len > 0 and unclosed_len % LINE_CODEPOINT_BUDGET == 0:
            return True, None
        return False, f"unapproved boundary: cut inside unclosed line segment of length {unclosed_len}, not a multiple of 8192"

    lines = _split_lines(slice_text)
    pending: list[tuple[str, int, int, int]] = []
    for number, (content, start, end) in enumerate(lines, start=1):
        if len(content) > LINE_CODEPOINT_BUDGET:
            pending.clear()
            continue
        candidate = [*pending, (content, start, end, number)]
        if pending and (len(candidate) > PACK_LINE_BUDGET or _stored_length(candidate) > LINE_CODEPOINT_BUDGET):
            pending.clear()
        pending.append((content, start, end, number))

    if not pending:
        return True, None

    if not lookahead_text:
        return False, "pending lines remain but not at EOF"

    next_lines = _split_lines(lookahead_text)
    if not next_lines:
        return False, "pending lines remain and no next line found in lookahead"

    next_content = next_lines[0][0]
    if len(next_content) > LINE_CODEPOINT_BUDGET:
        return True, None

    candidate = [*pending, (next_content, 0, len(next_content), len(pending) + 1)]
    if len(candidate) > PACK_LINE_BUDGET or _stored_length(candidate) > LINE_CODEPOINT_BUDGET:
        return True, None

    return (
        False,
        f"unapproved boundary: pending block has {len(pending)} lines ({_stored_length(pending)} code points) and next line fits; cut would split packed block",
    )


def create_continuation_authorizer(
    get_current_phase: Any,
) -> Any:
    """Build SQLite authorizer callback enforcing the continuation permission matrix.

    Default phase is 'idle' which strictly blocks all writes and mutations.
    """

    def continuation_authorizer(
        action_code: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        trigger_name: str | None,
    ) -> int:
        # 1. Prohibit DDL (SQLITE_CREATE_*, SQLITE_DROP_*, SQLITE_ALTER_TABLE, ATTACH, DETACH)
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
            if arg1 in ("foreign_keys", "table_info", "busy_timeout"):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        # 3. Read permissions, transaction control, and standard SQL functions are permitted across catalog
        if action_code in (
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
            sqlite3.SQLITE_TRANSACTION,
            sqlite3.SQLITE_FUNCTION,
        ):
            return sqlite3.SQLITE_OK

        # 4. Deletion is universally forbidden on continuation tables
        if action_code == sqlite3.SQLITE_DELETE:
            if arg1 in CONTINUATION_TABLES:
                return sqlite3.SQLITE_DENY

        phase = get_current_phase()

        # 5. Idle phase blocks ALL mutations
        if phase == "idle":
            return sqlite3.SQLITE_DENY

        # 6. Intent view insertions are authorized entry points exclusively during publish phase
        if action_code == sqlite3.SQLITE_INSERT:
            if arg1 in ("text_freshness_witness_intent", "text_range_publication_intent"):
                if phase == "publish_generation":
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY

        # 7. Internal trigger-mediated writes
        if action_code == sqlite3.SQLITE_INSERT:
            if arg1 == "text_freshness_witness":
                if trigger_name == "text_freshness_witness_intent_insert" and phase == "publish_generation":
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if arg1 == "text_range_publication_event":
                if trigger_name == "text_range_publication_intent_publish" and phase == "publish_generation":
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY

        if action_code in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE):
            if arg1 == "text_current_published_generation":
                if trigger_name == "text_range_publication_event_publish_pointer" and phase == "publish_generation":
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY

        # 8. Scoped phase-aware write access to base continuation tables
        if action_code == sqlite3.SQLITE_INSERT:
            if arg1 == "text_range_cursor":
                return sqlite3.SQLITE_OK if phase in ("initialize_cursor", "commit_range_artifact") else sqlite3.SQLITE_DENY
            if arg1 == "text_range_artifact":
                return sqlite3.SQLITE_OK if phase == "commit_range_artifact" else sqlite3.SQLITE_DENY
            if arg1 == "text_range_generation":
                return sqlite3.SQLITE_OK if phase == "create_generation" else sqlite3.SQLITE_DENY
            if arg1 == "text_range_generation_member":
                return sqlite3.SQLITE_OK if phase == "add_generation_member" else sqlite3.SQLITE_DENY
            if arg1 == "text_range_generation_seal":
                return sqlite3.SQLITE_OK if phase == "seal_generation" else sqlite3.SQLITE_DENY

        if action_code == sqlite3.SQLITE_UPDATE:
            if arg1 == "text_range_cursor":
                return sqlite3.SQLITE_OK if phase in ("commit_range_artifact", "record_terminal_transition") else sqlite3.SQLITE_DENY

        return sqlite3.SQLITE_DENY

    return continuation_authorizer


class ContinuationRepository:
    """Internal continuation repository encapsulating private database connection ownership.

    Enforces mandatory cached_statements=0, foreign_keys=1, private connection ownership,
    and fail-closed scoped authorizer checks. External connections are strictly rejected.
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
        # Mandatory cached_statements=0 to prevent statement cache bypass
        self._conn = sqlite3.connect(path_str, cached_statements=0)
        self._conn.execute("PRAGMA foreign_keys = ON")
        fk_status = self._conn.execute("PRAGMA foreign_keys").fetchone()[0]
        if fk_status != 1:
            self._conn.close()
            raise ContractError("FOREIGN_KEYS_ENFORCEMENT_REQUIRED: foreign_keys pragma is not active")

        self._current_phase: str = "idle"
        self._authorizer = create_continuation_authorizer(lambda: self._current_phase)
        self._conn.set_authorizer(self._authorizer)
        self._verified_snapshots: dict[str, str] = {}

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ContinuationRepository:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def commit_range_artifact(
        self,
        artifact: dict[str, Any] | None = None,
        cursor_update: dict[str, Any] | None = None,
        *,
        snapshot: ControlledSnapshot,
        **kwargs: Any,
    ) -> str:
        """Commit single range artifact and advance cursor atomically with full causal recomputation."""
        payload: dict[str, Any] = dict(artifact or {})
        payload.update(kwargs)
        cur_upd: dict[str, Any] = dict(cursor_update or {})

        snap = snapshot or payload.get("snapshot")
        # 1. P1-1: Reject arbitrary bytes or duck-typed provider; require authentic ControlledSnapshot
        if not isinstance(snap, ControlledSnapshot):
            raise ContractError("CONTROLLED_SNAPSHOT_REQUIRED: snapshot must be an authoritative ControlledSnapshot instance")
        if getattr(snap, "_closed", True) or getattr(snap, "_handle", None) is None:
            raise ContractError("CONTROLLED_SNAPSHOT_CLOSED: snapshot is closed")

        workspace_id = payload["workspace_id"]
        file_record_id = payload["file_record_id"]
        source_version_id = payload["source_version_id"]
        source_sha256 = payload["source_sha256"]
        snapshot_mode = payload["snapshot_mode"]
        range_ordinal = payload["range_ordinal"]
        range_start = payload["range_start"]
        range_end_exclusive = payload["range_end_exclusive"]
        range_artifact_id = payload["range_artifact_id"]
        created_at_unix_ms = payload["created_at_unix_ms"]
        cursor_updated_at_ms = cur_upd.get("updated_at_unix_ms", created_at_unix_ms)

        # 2. P1-1: Verify snapshot binding against source_version in database
        sv_row = self._conn.execute(
            """
            SELECT source_sha256, size_bytes, workspace_id, file_record_id
            FROM source_version
            WHERE source_version_id = ?
            """,
            (source_version_id,),
        ).fetchone()
        if sv_row is None:
            raise ContractError("SOURCE_VERSION_NOT_FOUND: source_version does not exist in catalog")

        sv_sha, sv_size, sv_ws, sv_file = sv_row

        # P1-1 & P1-2: Directly verify spool handle metadata and compute/verify cryptographic digest with budget
        kernel32 = snap._kernel32
        handle = snap._handle
        handle_info = _handle_info(kernel32, handle)
        handle_identity = f"{handle_info.nFileIndexHigh}:{handle_info.nFileIndexLow}"
        handle_size = _size_of(handle_info)
        handle_mtime = _mtime_ns(handle_info)
        snap_key = f"{handle_info.dwVolumeSerialNumber}:{handle_identity}:{handle_size}:{handle_mtime}"

        if (
            str(handle_info.dwVolumeSerialNumber) != snap.spool_volume_serial
            or handle_identity != snap.spool_file_index
            or handle_size != snap.size
            or handle_mtime != snap.spool_mtime_ns
        ):
            raise ContractError("SNAPSHOT_INTEGRITY_MISMATCH: spool metadata does not match handle")

        if handle_size != sv_size:
            raise ContractError(f"SOURCE_SIZE_MISMATCH: actual snapshot size {handle_size} != expected {sv_size}")

        if snap_key in self._verified_snapshots:
            verified_sha = self._verified_snapshots[snap_key]
        else:
            _seek(kernel32, handle, 0)
            verified_sha, actual_size = _hash_handle_with_budget(
                kernel32,
                handle,
                max_bytes_budget=DEFAULT_MAX_FRESHNESS_BYTES,
                max_time_budget_ms=DEFAULT_MAX_FRESHNESS_TIMEOUT_MS,
            )
            _seek(kernel32, handle, 0)
            if actual_size != sv_size:
                raise ContractError(f"SOURCE_SIZE_MISMATCH: actual snapshot size {actual_size} != expected {sv_size}")
            self._verified_snapshots[snap_key] = verified_sha

        if verified_sha != sv_sha or source_sha256 != sv_sha:
            raise ContractError(f"SOURCE_SHA_MISMATCH: actual snapshot sha {verified_sha} != expected {sv_sha}")
        if workspace_id != sv_ws or file_record_id != sv_file:
            raise ContractError("SOURCE_IDENTITY_MISMATCH: workspace_id or file_record_id does not match source_version")

        # 3. P1-2: Range interval & budget validation
        if not isinstance(range_start, int) or not isinstance(range_end_exclusive, int):
            raise ContractError("INVALID_RANGE_INTERVAL: range offsets must be integers")
        if range_start < 0 or range_end_exclusive <= range_start:
            raise ContractError("INVALID_RANGE_INTERVAL: range_end_exclusive must be strictly greater than range_start")
        if range_end_exclusive > sv_size:
            raise ContractError("RANGE_EXCEEDS_SOURCE_SIZE: range_end_exclusive exceeds snapshot size")
        if (range_end_exclusive - range_start) > PROJECTION_BYTE_BUDGET:
            raise ContractError("RANGE_BUDGET_EXCEEDED: range exceeds projection byte budget")

        # Determine effective profile from cursor or snapshot BOM
        cursor_row = self._conn.execute(
            """
            SELECT cursor_byte_offset, last_range_ordinal, manifest_digest, decoder_state, decoder_profile, terminal_reason
            FROM text_range_cursor
            WHERE workspace_id = ? AND file_record_id = ? AND source_version_id = ? AND source_sha256 = ?
              AND snapshot_mode = ?
            """,
            (workspace_id, file_record_id, source_version_id, source_sha256, snapshot_mode),
        ).fetchone()

        if cursor_row is not None and cursor_row[5] is not None:
            raise ContractError(
                f"CURSOR_TERMINAL_POST_UPDATE_REJECTED: cursor has terminated with {cursor_row[5]}; cannot commit further ranges"
            )

        if cursor_row is not None and cursor_row[4]:
            effective_profile = cursor_row[4]
        else:
            prefix = snap.read_at(0, min(4, snap.size))
            if prefix.startswith(b"\xef\xbb\xbf"):
                effective_profile = "utf-8-bom"
            elif prefix.startswith(b"\xff\xfe"):
                effective_profile = "utf-16-le-bom"
            elif prefix.startswith(b"\xfe\xff"):
                effective_profile = "utf-16-be-bom"
            elif payload.get("decoder_profile"):
                effective_profile = payload["decoder_profile"]
            else:
                effective_profile = "utf-8"

        effective_encoding = (
            "utf-16-le" if "utf-16-le" in effective_profile
            else ("utf-16-be" if "utf-16-be" in effective_profile else "utf-8")
        )

        # 4. P1-4: Check 9-tuple idempotency key FIRST before cursor checks
        existing = self._conn.execute(
            """
            SELECT range_artifact_id, owned_byte_slice_sha256, manifest_digest, recomputed_records,
                   previous_manifest_digest, input_decoder_state, next_decoder_state
            FROM text_range_artifact
            WHERE workspace_id = ?
              AND file_record_id = ?
              AND source_version_id = ?
              AND source_sha256 = ?
              AND parser_contract_name = ?
              AND parser_contract_version = ?
              AND budget_profile_id = ?
              AND snapshot_mode = ?
              AND range_ordinal = ?
              AND range_start = ?
              AND range_end_exclusive = ?
            """,
            (
                workspace_id,
                file_record_id,
                source_version_id,
                source_sha256,
                PARSER_CONTRACT_NAME,
                PARSER_CONTRACT_VERSION,
                BUDGET_PROFILE_ID,
                snapshot_mode,
                range_ordinal,
                range_start,
                range_end_exclusive,
            ),
        ).fetchone()

        if existing is not None:
            # Replay path: recompute using existing artifact's verified causal inputs
            stored_id, stored_slice_sha, stored_digest, stored_records_raw, stored_prev_digest, stored_in_state, stored_next_state = existing
            slice_bytes = extract_snapshot_slice(snap, range_start, range_end_exclusive)

            # Determine profile for replay: extract from stored state or effective profile (P1-2)
            replay_profile = None
            for state_json in (stored_next_state, stored_in_state):
                if state_json and state_json != "initial":
                    try:
                        parsed = json.loads(state_json)
                        if isinstance(parsed, dict) and "profile" in parsed:
                            replay_profile = parsed["profile"]
                            break
                    except Exception:
                        pass
            if replay_profile is None:
                replay_profile = effective_profile

            (
                rep_slice_sha,
                rep_digest,
                rep_next_state,
                _,
                rep_records,
                rep_in_state,
            ) = recompute_causal_outputs(
                slice_bytes,
                range_ordinal=range_ordinal,
                previous_manifest_digest=stored_prev_digest,
                input_decoder_state=stored_in_state,
                expected_decoder_profile=replay_profile,
            )

            stored_records = json.loads(stored_records_raw) if isinstance(stored_records_raw, str) else stored_records_raw
            if (
                stored_slice_sha != rep_slice_sha
                or stored_digest != rep_digest
                or canonical_records(stored_records) != canonical_records(rep_records)
                or stored_next_state != rep_next_state
            ):
                raise ContractError("IDEMPOTENCY_CONFLICT: stored artifact differs from recomputed causal outputs")

            # Check caller-provided claims against recomputed outputs if caller provided any
            if "owned_byte_slice_sha256" in payload and payload["owned_byte_slice_sha256"] != rep_slice_sha:
                raise ContractError("IDEMPOTENCY_CONFLICT: caller owned_byte_slice_sha256 conflict")
            if "manifest_digest" in payload and payload["manifest_digest"] != rep_digest:
                raise ContractError("IDEMPOTENCY_CONFLICT: caller manifest_digest conflict")
            if "recomputed_records" in payload and canonical_records(payload["recomputed_records"]) != canonical_records(rep_records):
                raise ContractError("IDEMPOTENCY_CONFLICT: caller recomputed_records conflict")

            return str(stored_id)

        # 5. Retrieve prior cursor state to enforce monotonic chaining for new artifact
        if range_ordinal == 0:
            if cursor_row is not None:
                raise ContractError("CURSOR_ALREADY_INITIALIZED: ordinal 0 cannot be committed when cursor already exists")
            previous_cursor = 0
            previous_manifest_digest = GENESIS_DIGEST_HEX
            input_decoder_state = payload.get("input_decoder_state", "initial")
            expected_profile = effective_profile
            prior_in_unclosed = False
            prior_in_hard_chunk = False
        else:
            if cursor_row is None:
                raise ContractError("CURSOR_NOT_FOUND: prior cursor must exist for range_ordinal > 0")
            if cursor_row[0] != range_start:
                raise ContractError(f"CURSOR_OFFSET_MISMATCH: expected {cursor_row[0]}, got range_start {range_start}")
            if cursor_row[1] != range_ordinal - 1:
                raise ContractError(f"CURSOR_ORDINAL_MISMATCH: expected {cursor_row[1] + 1}, got range_ordinal {range_ordinal}")
            previous_cursor = cursor_row[0]
            previous_manifest_digest = cursor_row[2]
            input_decoder_state = cursor_row[3]
            expected_profile = cursor_row[4]
            prior_in_unclosed = False
            prior_in_hard_chunk = False
            if input_decoder_state and input_decoder_state != "initial":
                try:
                    c_state = json.loads(input_decoder_state)
                    if isinstance(c_state, dict):
                        prior_in_unclosed = c_state.get("in_unclosed_line", False)
                        prior_in_hard_chunk = c_state.get("in_hard_chunk_line", False)
                except Exception:
                    pass

        # 6. Extract slice (within bounded projection budget)
        slice_bytes = extract_snapshot_slice(snap, range_start, range_end_exclusive)

        # 7. Bounded boundary validations
        if range_end_exclusive < sv_size:
            # 7.1 Stream-safe boundary check using bounded local tail and lookahead
            # Align start of slice_tail to decoder-safe boundary
            tail_len = min(len(slice_bytes), 64)
            start_idx = len(slice_bytes) - tail_len
            if effective_encoding == "utf-8":
                while start_idx < len(slice_bytes) and (slice_bytes[start_idx] & 0xC0 == 0x80):
                    start_idx += 1
            elif effective_encoding.startswith("utf-16"):
                if start_idx % 2 != 0:
                    start_idx += 1
                if start_idx + 2 <= len(slice_bytes):
                    cu = int.from_bytes(slice_bytes[start_idx : start_idx + 2], "little" if effective_encoding == "utf-16-le" else "big")
                    if 0xDC00 <= cu <= 0xDFFF:
                        start_idx += 2

            slice_tail = slice_bytes[start_idx:]
            cut_offset = len(slice_tail)

            # Align end of lookahead_stream to decoder-safe boundary
            raw_lookahead_len = min(sv_size - range_end_exclusive, 64)
            if raw_lookahead_len > 0:
                raw_lookahead = snap.read_at(range_end_exclusive, raw_lookahead_len)
                end_idx = len(raw_lookahead)
                if effective_encoding == "utf-8":
                    idx = end_idx - 1
                    cont = 0
                    while idx >= 0 and (raw_lookahead[idx] & 0xC0 == 0x80) and cont < 3:
                        cont += 1
                        idx -= 1
                    if idx >= 0:
                        lead = raw_lookahead[idx]
                        if lead & 0x80 == 0:
                            needed = 1
                        elif lead & 0xE0 == 0xC0:
                            needed = 2
                        elif lead & 0xF0 == 0xE0:
                            needed = 3
                        elif lead & 0xF8 == 0xF0:
                            needed = 4
                        else:
                            needed = 1
                        if end_idx - idx < needed:
                            end_idx = idx
                elif effective_encoding.startswith("utf-16"):
                    end_idx = end_idx - (end_idx % 2)
                    if end_idx >= 2:
                        cu = int.from_bytes(raw_lookahead[end_idx - 2 : end_idx], "little" if effective_encoding == "utf-16-le" else "big")
                        if 0xD800 <= cu <= 0xDBFF:
                            end_idx -= 2
                lookahead_stream = raw_lookahead[:end_idx]
            else:
                lookahead_stream = b""

            context_bytes = slice_tail + lookahead_stream
            if not is_stream_safe_boundary(context_bytes, cut_offset, encoding=effective_encoding):
                raise ContractError(
                    f"UNSAFE_RANGE_BOUNDARY: byte offset {range_end_exclusive} is not a stream-safe boundary"
                )

            # 7.2 Approved chunk boundary check (P1-1 & P1-3 & NFC)
            lookahead_chunk_len = min(sv_size - range_end_exclusive, 65536)
            lookahead_chunk_bytes = snap.read_at(range_end_exclusive, lookahead_chunk_len) if lookahead_chunk_len > 0 else b""

            body_slice = slice_bytes
            if range_ordinal == 0:
                if effective_profile == "utf-8-bom" and body_slice.startswith(b"\xef\xbb\xbf"):
                    body_slice = body_slice[3:]
                elif "utf-16" in effective_profile and (body_slice.startswith(b"\xff\xfe") or body_slice.startswith(b"\xfe\xff")):
                    body_slice = body_slice[2:]

            try:
                slice_text = body_slice.decode(effective_encoding)
            except UnicodeDecodeError as e:
                raise ContractError(f"DECODE_ERROR: cannot decode slice: {e}")

            lookahead_text = lookahead_chunk_bytes.decode(effective_encoding, errors="ignore")

            slice_nfc = unicodedata.normalize("NFC", slice_text)
            lookahead_nfc = unicodedata.normalize("NFC", lookahead_text)

            approved, reason = is_approved_chunk_boundary(
                slice_nfc,
                lookahead_nfc,
                is_eof=(range_end_exclusive == sv_size),
                in_unclosed_line=prior_in_unclosed,
                in_hard_chunk_line=prior_in_hard_chunk,
            )
            if not approved:
                raise ContractError(f"UNAPPROVED_CHUNK_BOUNDARY: {reason}")

        # 8. Recompute causal outputs with chunk_continuation_slice
        (
            recomputed_slice_sha,
            recomputed_manifest_digest,
            recomputed_next_decoder_state,
            decoder_profile,
            recomputed_records,
            recomputed_input_decoder_state,
        ) = recompute_causal_outputs(
            slice_bytes,
            range_ordinal=range_ordinal,
            previous_manifest_digest=previous_manifest_digest,
            input_decoder_state=input_decoder_state,
            expected_decoder_profile=expected_profile,
        )

        # 9. Reject any conflicting caller-supplied claims
        if "owned_byte_slice_sha256" in payload and payload["owned_byte_slice_sha256"] != recomputed_slice_sha:
            raise ContractError("FORGED_CAUSAL_OUTPUT: caller-provided owned_byte_slice_sha256 does not match snapshot slice")
        if "manifest_digest" in payload and payload["manifest_digest"] != recomputed_manifest_digest:
            raise ContractError("FORGED_CAUSAL_OUTPUT: caller-provided manifest_digest does not match recomputed digest")
        if "recomputed_records" in payload:
            claimed_records = payload["recomputed_records"]
            if canonical_records(claimed_records) != canonical_records(recomputed_records):
                raise ContractError("FORGED_CAUSAL_OUTPUT: caller-provided records do not match recomputed records from snapshot")

        # 10. Atomic transaction inserting artifact and updating cursor
        self._current_phase = "commit_range_artifact"
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                """
                INSERT INTO text_range_artifact (
                    range_artifact_id,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    parser_contract_name,
                    parser_contract_version,
                    budget_profile_id,
                    snapshot_mode,
                    range_ordinal,
                    range_start,
                    range_end_exclusive,
                    owned_byte_slice_sha256,
                    input_decoder_state,
                    previous_cursor,
                    previous_manifest_digest,
                    next_decoder_state,
                    next_cursor,
                    manifest_digest,
                    recomputed_records,
                    created_at_unix_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    range_artifact_id,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    PARSER_CONTRACT_NAME,
                    PARSER_CONTRACT_VERSION,
                    BUDGET_PROFILE_ID,
                    snapshot_mode,
                    range_ordinal,
                    range_start,
                    range_end_exclusive,
                    recomputed_slice_sha,
                    recomputed_input_decoder_state,
                    previous_cursor,
                    previous_manifest_digest,
                    recomputed_next_decoder_state,
                    range_end_exclusive,
                    recomputed_manifest_digest,
                    json.dumps(recomputed_records, ensure_ascii=False),
                    created_at_unix_ms,
                ),
            )

            if cursor_row is None:
                self._conn.execute(
                    """
                    INSERT INTO text_range_cursor (
                        workspace_id,
                        file_record_id,
                        source_version_id,
                        source_sha256,
                        parser_contract_name,
                        parser_contract_version,
                        budget_profile_id,
                        snapshot_mode,
                        cursor_byte_offset,
                        last_range_ordinal,
                        last_range_artifact_id,
                        decoder_profile,
                        manifest_digest,
                        decoder_state,
                        terminal_reason,
                        updated_at_unix_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id,
                        file_record_id,
                        source_version_id,
                        source_sha256,
                        PARSER_CONTRACT_NAME,
                        PARSER_CONTRACT_VERSION,
                        BUDGET_PROFILE_ID,
                        snapshot_mode,
                        range_end_exclusive,
                        range_ordinal,
                        range_artifact_id,
                        decoder_profile,
                        recomputed_manifest_digest,
                        recomputed_next_decoder_state,
                        cur_upd.get("terminal_reason"),
                        cursor_updated_at_ms,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE text_range_cursor SET
                        cursor_byte_offset = ?,
                        last_range_ordinal = ?,
                        last_range_artifact_id = ?,
                        manifest_digest = ?,
                        decoder_state = ?,
                        terminal_reason = ?,
                        updated_at_unix_ms = ?
                    WHERE workspace_id = ?
                      AND file_record_id = ?
                      AND source_version_id = ?
                      AND source_sha256 = ?
                      AND parser_contract_name = ?
                      AND parser_contract_version = ?
                      AND budget_profile_id = ?
                      AND snapshot_mode = ?
                    """,
                    (
                        range_end_exclusive,
                        range_ordinal,
                        range_artifact_id,
                        recomputed_manifest_digest,
                        recomputed_next_decoder_state,
                        cur_upd.get("terminal_reason"),
                        cursor_updated_at_ms,
                        workspace_id,
                        file_record_id,
                        source_version_id,
                        source_sha256,
                        PARSER_CONTRACT_NAME,
                        PARSER_CONTRACT_VERSION,
                        BUDGET_PROFILE_ID,
                        snapshot_mode,
                    ),
                )
            self._conn.commit()
            return str(range_artifact_id)
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise
        finally:
            self._current_phase = "idle"

    def record_terminal_transition(
        self,
        payload: dict[str, Any],
        *,
        terminal_reason: str = "RANGE_UNIT_EXCEEDS_BUDGET",
        updated_at_unix_ms: int | None = None,
    ) -> None:
        """Atomically records terminal transition on existing cursor without advancing offsets or creating artifacts."""
        if terminal_reason != "RANGE_UNIT_EXCEEDS_BUDGET":
            raise ContractError(f"INVALID_TERMINAL_REASON: unsupported terminal reason {terminal_reason}")

        workspace_id = payload["workspace_id"]
        file_record_id = payload["file_record_id"]
        source_version_id = payload["source_version_id"]
        source_sha256 = payload["source_sha256"]
        snapshot_mode = payload.get("snapshot_mode", "rebuild_controlled_snapshot_and_verify_source_sha256")

        self._current_phase = "record_terminal_transition"
        try:
            cursor_row = self._conn.execute(
                """
                SELECT cursor_byte_offset, last_range_ordinal, last_range_artifact_id,
                       manifest_digest, decoder_state, terminal_reason, updated_at_unix_ms
                FROM text_range_cursor
                WHERE workspace_id = ? AND file_record_id = ? AND source_version_id = ? AND source_sha256 = ?
                  AND snapshot_mode = ?
                """,
                (workspace_id, file_record_id, source_version_id, source_sha256, snapshot_mode),
            ).fetchone()

            if cursor_row is None:
                raise ContractError("CURSOR_NOT_FOUND: cannot transition non-existent cursor to terminal")

            if cursor_row[5] is not None:
                raise ContractError(f"CURSOR_ALREADY_TERMINAL: cursor is already in terminal state ({cursor_row[5]})")

            last_updated_ms = cursor_row[6]
            upd_time = updated_at_unix_ms if updated_at_unix_ms is not None else payload.get("updated_at_unix_ms")
            if upd_time is None:
                upd_time = max(int(time.time() * 1000), last_updated_ms + 1)
            elif upd_time <= last_updated_ms:
                raise ContractError(
                    f"INVALID_TIMESTAMP: updated_at_unix_ms ({upd_time}) must be strictly greater than last updated ({last_updated_ms})"
                )

            self._conn.execute(
                """
                UPDATE text_range_cursor SET
                    terminal_reason = ?,
                    updated_at_unix_ms = ?
                WHERE workspace_id = ?
                  AND file_record_id = ?
                  AND source_version_id = ?
                  AND source_sha256 = ?
                  AND parser_contract_name = ?
                  AND parser_contract_version = ?
                  AND budget_profile_id = ?
                  AND snapshot_mode = ?
                """,
                (
                    terminal_reason,
                    upd_time,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    PARSER_CONTRACT_NAME,
                    PARSER_CONTRACT_VERSION,
                    BUDGET_PROFILE_ID,
                    snapshot_mode,
                ),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise
        finally:
            self._current_phase = "idle"

    def create_generation(self, generation: dict[str, Any]) -> None:
        """Register candidate generation."""
        self._current_phase = "create_generation"
        try:
            self._conn.execute(
                """
                INSERT INTO text_range_generation (
                    generation_id,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    source_size_bytes,
                    parser_contract_name,
                    parser_contract_version,
                    budget_profile_id,
                    snapshot_mode,
                    total_ranges,
                    total_bytes,
                    final_manifest_digest,
                    terminal_reason,
                    created_at_unix_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    generation["generation_id"],
                    generation["workspace_id"],
                    generation["file_record_id"],
                    generation["source_version_id"],
                    generation["source_sha256"],
                    generation["source_size_bytes"],
                    PARSER_CONTRACT_NAME,
                    PARSER_CONTRACT_VERSION,
                    BUDGET_PROFILE_ID,
                    generation["snapshot_mode"],
                    generation["total_ranges"],
                    generation["total_bytes"],
                    generation["final_manifest_digest"],
                    generation.get("terminal_reason"),
                    generation["created_at_unix_ms"],
                ),
            )
            self._conn.commit()
        finally:
            self._current_phase = "idle"

    def add_generation_member(self, generation_id: str, member: dict[str, Any]) -> None:
        """Bind verified member artifact to generation."""
        self._current_phase = "add_generation_member"
        try:
            self._conn.execute(
                """
                INSERT INTO text_range_generation_member (
                    generation_id,
                    range_ordinal,
                    range_artifact_id,
                    range_start,
                    range_end_exclusive,
                    manifest_digest
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    generation_id,
                    member["range_ordinal"],
                    member["range_artifact_id"],
                    member["range_start"],
                    member["range_end_exclusive"],
                    member["manifest_digest"],
                ),
            )
            self._conn.commit()
        finally:
            self._current_phase = "idle"

    def seal_generation(
        self,
        generation_id: str,
        sealed_at_unix_ms: int,
    ) -> None:
        """Execute step-by-step hash-chain recomputation and insert 6-column seal atomically."""
        self._current_phase = "seal_generation"
        try:
            self._conn.execute("BEGIN IMMEDIATE")

            # 1. Fetch generation record with complete scope
            gen_row = self._conn.execute(
                """
                SELECT
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    parser_contract_name,
                    parser_contract_version,
                    budget_profile_id,
                    snapshot_mode,
                    total_ranges,
                    total_bytes,
                    source_size_bytes,
                    final_manifest_digest,
                    terminal_reason
                FROM text_range_generation
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()
            if gen_row is None:
                raise ContractError(f"GENERATION_NOT_FOUND: {generation_id}")

            (
                ws_id,
                file_id,
                sv_id,
                sv_sha,
                p_name,
                p_ver,
                b_id,
                snap_mode,
                total_ranges,
                total_bytes,
                source_size_bytes,
                expected_final_digest,
                gen_term,
            ) = gen_row

            if gen_term is not None:
                raise ContractError(f"CANNOT_SEAL_TERMINAL_GENERATION: generation {generation_id} terminated with {gen_term}")

            cur_term = self._conn.execute(
                """
                SELECT terminal_reason
                FROM text_range_cursor
                WHERE workspace_id = ?
                  AND file_record_id = ?
                  AND source_version_id = ?
                  AND source_sha256 = ?
                  AND parser_contract_name = ?
                  AND parser_contract_version = ?
                  AND budget_profile_id = ?
                  AND snapshot_mode = ?
                """,
                (ws_id, file_id, sv_id, sv_sha, p_name, p_ver, b_id, snap_mode),
            ).fetchone()
            if cur_term is not None and cur_term[0] is not None:
                raise ContractError(f"CANNOT_SEAL_TERMINAL_CURSOR: cursor for source_version {sv_id} terminated with {cur_term[0]}")

            # 2. Fetch member artifacts
            members = self._conn.execute(
                """
                SELECT
                    m.range_ordinal,
                    m.range_start,
                    m.range_end_exclusive,
                    m.manifest_digest,
                    a.previous_manifest_digest,
                    a.recomputed_records
                FROM text_range_generation_member m
                JOIN text_range_artifact a ON a.range_artifact_id = m.range_artifact_id
                WHERE m.generation_id = ?
                ORDER BY m.range_ordinal ASC
                """,
                (generation_id,),
            ).fetchall()

            # 3. Verify member count and coverage
            if len(members) != total_ranges:
                raise ContractError(f"MEMBER_COUNT_MISMATCH: expected {total_ranges}, got {len(members)}")

            # 4. Recompute hash-chain step-by-step
            current_digest_raw = genesis_digest()
            expected_cursor = 0

            for member in members:
                ordinal, start, end_excl, m_digest, prev_digest, raw_records = member
                if start != expected_cursor:
                    raise ContractError("COVERAGE_GAP_OR_OVERLAP: non-contiguous member intervals")
                expected_cursor = end_excl

                if current_digest_raw.hex() != prev_digest:
                    raise ContractError("HASH_CHAIN_PREVIOUS_DIGEST_MISMATCH")

                records_list = json.loads(raw_records) if isinstance(raw_records, str) else raw_records
                canonical_bytes = canonical_records(records_list)
                next_digest_raw = hashlib.sha256(current_digest_raw + canonical_bytes).digest()

                if next_digest_raw.hex() != m_digest:
                    raise ContractError("HASH_CHAIN_STEP_DIGEST_MISMATCH")

                current_digest_raw = next_digest_raw

            if expected_cursor != source_size_bytes:
                raise ContractError("COVERAGE_SHORT_OF_SOURCE_SIZE")

            # 5. Pre-insert generation final digest comparison
            recomputed_final_hex = current_digest_raw.hex()
            if recomputed_final_hex != expected_final_digest:
                raise ContractError("HASH_CHAIN_GENERATION_DIGEST_MISMATCH")

            # 6. Execute 6-column seal INSERT
            self._conn.execute(
                """
                INSERT INTO text_range_generation_seal (
                    generation_id,
                    total_ranges,
                    total_bytes,
                    source_size_bytes,
                    final_manifest_digest,
                    sealed_at_unix_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    generation_id,
                    total_ranges,
                    total_bytes,
                    source_size_bytes,
                    recomputed_final_hex,
                    sealed_at_unix_ms,
                ),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise
        finally:
            self._current_phase = "idle"

    def publish_generation(
        self,
        *,
        source_file: Path,
        expected_sha: str,
        generation_id: str,
        witness_id: str,
        publication_id: str,
        workspace_id: str,
        file_record_id: str,
        source_version_id: str,
        max_bytes_budget: int = DEFAULT_MAX_FRESHNESS_BYTES,
        max_time_budget_ms: int = DEFAULT_MAX_FRESHNESS_TIMEOUT_MS,
        claimed_snapshot_identity: str | None = None,
        claimed_source_size_bytes: int | None = None,
        platform_name: str | None = None,
    ) -> None:
        """Publish sealed generation atomically under mandatory enforceable source protection.

        Derives snapshot identity and size directly from held handle; streams hash with budgets.
        Fails closed on any error, leaving zero committed witnesses, zero events, and unmoved pointer.
        """
        platform = platform_name or sys.platform
        cleanup_handle = None

        if platform == "win32":
            import _winapi

            handle = _winapi.CreateFile(
                str(source_file),
                _winapi.GENERIC_READ,
                FILE_SHARE_READ,
                0,
                _winapi.OPEN_EXISTING,
                0,
                0,
            )
            cleanup_handle = handle

            # 1. Derive identity and size directly from the held handle
            actual_identity, actual_size = _get_handle_info_windows(handle)

            # Reject conflicting caller-claimed metadata
            if claimed_snapshot_identity is not None and claimed_snapshot_identity != actual_identity:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError("FORGED_SNAPSHOT_IDENTITY: caller claimed identity does not match handle")
            if claimed_source_size_bytes is not None and claimed_source_size_bytes != actual_size:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError("FORGED_SOURCE_SIZE: caller claimed size does not match handle")

            # 2. Verify against generation metadata in database before hashing
            gen_row = self._conn.execute(
                """
                SELECT source_size_bytes, source_sha256, terminal_reason, source_version_id
                FROM text_range_generation
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()
            if gen_row is None:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError(f"GENERATION_NOT_FOUND: {generation_id}")

            gen_size, gen_sha, gen_term, gen_sv = gen_row
            if gen_term is not None:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError(f"CANNOT_PUBLISH_TERMINAL_GENERATION: generation {generation_id} terminated with {gen_term}")

            cur_term = self._conn.execute(
                "SELECT terminal_reason FROM text_range_cursor WHERE source_version_id = ?",
                (gen_sv,),
            ).fetchone()
            if cur_term is not None and cur_term[0] is not None:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError(f"CANNOT_PUBLISH_TERMINAL_CURSOR: cursor for source_version {gen_sv} terminated with {cur_term[0]}")

            if gen_size != actual_size:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError("SOURCE_SIZE_MISMATCH: generation size differs from handle size")
            if gen_sha != expected_sha:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError("SOURCE_SHA_MISMATCH: generation sha differs from expected sha")

            # 3. Stream hash directly from held handle with memory and time budgets
            hasher = hashlib.sha256()
            total_read = 0
            start_time = time.monotonic()

            while True:
                elapsed_ms = (time.monotonic() - start_time) * 1000
                if elapsed_ms > max_time_budget_ms:
                    _winapi.CloseHandle(cleanup_handle)
                    raise ContractError("FRESHNESS_TIME_BUDGET_EXCEEDED")

                buf, err = _winapi.ReadFile(handle, _STREAM_CHUNK_BYTES)
                if not buf:
                    break
                buf_bytes = bytes(buf)
                total_read += len(buf_bytes)
                if total_read > max_bytes_budget:
                    _winapi.CloseHandle(cleanup_handle)
                    raise ContractError("FRESHNESS_BYTE_BUDGET_EXCEEDED")
                hasher.update(buf_bytes)

            if total_read != actual_size:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError("FRESHNESS_SIZE_INCOMPLETE: bytes read differ from handle size")

            freshness_hash = hasher.hexdigest()
            if freshness_hash != expected_sha:
                _winapi.CloseHandle(cleanup_handle)
                raise ContractError(f"SOURCE_DIGEST_MISMATCH: expected {expected_sha}, got {freshness_hash}")
        else:
            # Non-Windows platforms without mandatory protection fail closed immediately
            raise ContractError("ENFORCEABLE_SOURCE_PROTECTION_REQUIRED: platform lacks mandatory non-bypassable protection")

        self._current_phase = "publish_generation"
        try:
            self._conn.execute("BEGIN IMMEDIATE")

            # Re-check complete scope inside transaction AFTER BEGIN IMMEDIATE and BEFORE writing witness
            gen_row = self._conn.execute(
                """
                SELECT
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    source_sha256,
                    parser_contract_name,
                    parser_contract_version,
                    budget_profile_id,
                    snapshot_mode,
                    source_size_bytes,
                    terminal_reason
                FROM text_range_generation
                WHERE generation_id = ?
                """,
                (generation_id,),
            ).fetchone()
            if gen_row is None:
                raise ContractError(f"GENERATION_NOT_FOUND: {generation_id}")

            (
                g_ws,
                g_file,
                g_sv,
                g_sha,
                g_pname,
                g_pver,
                g_bprof,
                g_snap,
                g_size,
                g_term,
            ) = gen_row

            if g_ws != workspace_id or g_file != file_record_id or g_sv != source_version_id:
                raise ContractError("GENERATION_IDENTITY_MISMATCH: generation scope does not match publication caller scope")
            if g_sha != freshness_hash or g_size != actual_size:
                raise ContractError("GENERATION_CONTENT_MISMATCH: generation sha or size does not match verified source file")

            if g_term is not None:
                raise ContractError(f"CANNOT_PUBLISH_TERMINAL_GENERATION: generation {generation_id} terminated with {g_term}")

            cur_row = self._conn.execute(
                """
                SELECT terminal_reason
                FROM text_range_cursor
                WHERE workspace_id = ?
                  AND file_record_id = ?
                  AND source_version_id = ?
                  AND source_sha256 = ?
                  AND parser_contract_name = ?
                  AND parser_contract_version = ?
                  AND budget_profile_id = ?
                  AND snapshot_mode = ?
                """,
                (g_ws, g_file, g_sv, g_sha, g_pname, g_pver, g_bprof, g_snap),
            ).fetchone()

            if cur_row is not None and cur_row[0] is not None:
                raise ContractError(f"CANNOT_PUBLISH_TERMINAL_CURSOR: cursor for source_version {g_sv} terminated with {cur_row[0]}")

            # Route witness creation through intent view
            self._conn.execute(
                """
                INSERT INTO text_freshness_witness_intent (
                    witness_id,
                    generation_id,
                    source_sha256,
                    source_size_bytes,
                    snapshot_identity,
                    requested_ttl_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    witness_id,
                    generation_id,
                    freshness_hash,
                    actual_size,
                    actual_identity,
                    60000,
                ),
            )

            # Route publication through intent view
            self._conn.execute(
                """
                INSERT INTO text_range_publication_intent (
                    publication_id,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    generation_id,
                    witness_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    publication_id,
                    workspace_id,
                    file_record_id,
                    source_version_id,
                    generation_id,
                    witness_id,
                ),
            )

            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise
        finally:
            self._current_phase = "idle"
            if cleanup_handle is not None and platform == "win32":
                _winapi.CloseHandle(cleanup_handle)
