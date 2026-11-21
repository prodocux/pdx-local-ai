"""Bounded decoder and ``pdx_local_text_chunker_v1`` for Gate 5A-0 slice 3.

Decode reads the controlled snapshot already hashed by slice 2. It does
not open the source path, publish a projection, or scan past the
one-call budgets to learn a total. ``source_bytes.known_total`` is the
snapshot size observed while that hash was taken.
"""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass

from .text_intake_route import PROJECTION_BYTE_BUDGET, ControlledSnapshot

DECODER_NAME = "pdx_local_text_decoder"
DECODER_VERSION = "1"
CHUNKER_ID = "pdx_local_text_chunker_v1"
NORMALIZATION_PROFILE = "pdx_local_text_normalization_nfc_v1"
CHARACTER_BUDGET = 200_000
LINE_BUDGET = 10_000
BLOCK_BUDGET = 256
LINE_CODEPOINT_BUDGET = 8192
PACK_LINE_BUDGET = 40
_C0_ALLOWED = frozenset({0x09, 0x0A, 0x0D})


@dataclass(frozen=True)
class TextBlock:
    ordinal: int
    text: str
    text_sha256: str
    line_start: int
    line_end_exclusive: int
    source_codepoint_start: int
    source_codepoint_end_exclusive: int


@dataclass(frozen=True)
class CoverageLimit:
    limit_name: str
    observed_count: int
    known_total: int | None
    omitted_start: int | None
    omitted_end_exclusive: int | None
    truncation_reason: str | None
    coordinate_space: str
    boundary: str | None = None
    line_end_reached: bool | None = None


@dataclass(frozen=True)
class DecodeResult:
    outcome: str
    reason: str | None
    decoder_profile: str | None
    bom_removed: bool | None
    normalization_profile: str
    coverage_disposition: str | None
    unknown_remainder: bool
    limits: tuple[CoverageLimit, ...]
    blocks: tuple[TextBlock, ...]


def chunk_nfc(text: str, *, max_blocks: int | None = None) -> tuple[tuple[TextBlock, ...], bool]:
    """Pack one NFC string. The same string always yields the same blocks.

    ``max_blocks`` stops emission without counting blocks past the cap.
    """
    lines = _split_lines(text)
    blocks: list[TextBlock] = []
    pending: list[tuple[str, int, int, int]] = []
    stopped = False

    def full() -> bool:
        return max_blocks is not None and len(blocks) >= max_blocks

    def emit(piece: str, line_start: int, line_end: int, start: int, end: int) -> bool:
        if full():
            return False
        blocks.append(_block(len(blocks), piece, line_start, line_end, start, end))
        return True

    def close() -> bool:
        if not pending:
            return True
        stored = "\n".join(item[0] for item in pending)
        if not emit(stored, pending[0][3], pending[-1][3] + 1, pending[0][1], pending[-1][2]):
            return False
        pending.clear()
        return True

    for number, (content, start, end) in enumerate(lines, start=1):
        if len(content) > LINE_CODEPOINT_BUDGET:
            if not close():
                stopped = True
                break
            offset = 0
            while offset < len(content):
                if full():
                    stopped = True
                    break
                piece = content[offset:offset + LINE_CODEPOINT_BUDGET]
                if not emit(piece, number, number + 1, start + offset, start + offset + len(piece)):
                    stopped = True
                    break
                offset += LINE_CODEPOINT_BUDGET
            if stopped:
                break
            continue
        candidate = [*pending, (content, start, end, number)]
        if pending and (len(candidate) > PACK_LINE_BUDGET or _stored_length(candidate) > LINE_CODEPOINT_BUDGET):
            if not close():
                stopped = True
                break
        if full():
            stopped = True
            break
        pending.append((content, start, end, number))
    if not stopped:
        stopped = not close()
    return tuple(blocks), stopped


def decode_snapshot(snapshot: ControlledSnapshot) -> DecodeResult:
    """Decode and chunk one held snapshot. This writes no database rows."""
    raw = _read_bounded(snapshot)
    profile, bom_length, bom_removed = _profile(raw)
    body = raw[bom_length:]
    entire = snapshot.size <= PROJECTION_BYTE_BUDGET and len(raw) == snapshot.size
    if profile == "utf-8" or profile == "utf-8-bom":
        end = len(body) if entire else _utf8_safe_end(body)
        encoding = "utf-8"
    elif profile == "utf-16-le-bom":
        end = len(body) if entire else _utf16_safe_end(body, big=False)
        encoding = "utf-16-le"
    else:
        end = len(body) if entire else _utf16_safe_end(body, big=True)
        encoding = "utf-16-be"
    kept = body[:end]
    try:
        decoded = kept.decode(encoding)
    except UnicodeDecodeError:
        return _unsupported("UNSUPPORTED_ENCODING", profile, bom_removed)
    if "\x00" in decoded:
        return _unsupported("UNSUPPORTED_BINARY", profile, bom_removed)
    normalized = unicodedata.normalize("NFC", decoded)
    if _c0_ratio(normalized) > 0.01:
        return _unsupported("UNSUPPORTED_BINARY", profile, bom_removed)
    limits: list[CoverageLimit] = []
    observed_bytes = bom_length + len(kept)
    if observed_bytes < snapshot.size:
        limits.append(CoverageLimit(
            "source_bytes", observed_bytes, snapshot.size, observed_bytes, snapshot.size,
            "SOURCE_BYTES", "byte", "safe_decode", None,
        ))
    prefix, char_limited = _cap_characters(normalized)
    if char_limited:
        limits.append(CoverageLimit(
            "characters", len(prefix), None, None, None, "CHARACTER_COUNT", "code_point",
        ))
    prefix, line_limited = _cap_lines(prefix)
    if line_limited:
        limits.append(CoverageLimit(
            "lines", LINE_BUDGET, None, None, None, "LINE_COUNT", "line",
        ))
    blocks, blocked = chunk_nfc(prefix, max_blocks=BLOCK_BUDGET)
    if blocked:
        limits.append(CoverageLimit(
            "blocks", BLOCK_BUDGET, None, None, None, "BLOCK_COUNT", "line",
        ))
    disposition, unknown = _disposition(limits)
    return DecodeResult(
        "decoded", None, profile, bom_removed, NORMALIZATION_PROFILE,
        disposition, unknown, tuple(limits), blocks,
    )


def _read_bounded(snapshot: ControlledSnapshot) -> bytes:
    limit = min(snapshot.size, PROJECTION_BYTE_BUDGET)
    if limit <= 0:
        return b""
    parts: list[bytes] = []
    read = 0
    for chunk in snapshot.iter_chunks(offset=0, limit=limit):
        parts.append(chunk)
        read += len(chunk)
        if read >= limit:
            break
    return b"".join(parts)


def _profile(raw: bytes) -> tuple[str, int, bool]:
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-bom", 3, True
    if raw.startswith(b"\xff\xfe"):
        return "utf-16-le-bom", 2, True
    if raw.startswith(b"\xfe\xff"):
        return "utf-16-be-bom", 2, True
    return "utf-8", 0, False


def _utf8_safe_end(data: bytes) -> int:
    end = len(data)
    index = end - 1
    continuation = 0
    while index >= 0 and data[index] & 0xC0 == 0x80 and continuation < 3:
        continuation += 1
        index -= 1
    if index < 0:
        return 0
    lead = data[index]
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
    if end - index < needed:
        end = index
    if end > 0 and data[end - 1] == 0x0D:
        end -= 1
    return end


def _utf16_safe_end(data: bytes, *, big: bool) -> int:
    end = len(data) - (len(data) % 2)
    if end < 2:
        return 0
    unit = int.from_bytes(data[end - 2:end], "big" if big else "little")
    if unit == 0x000D or 0xD800 <= unit <= 0xDBFF:
        end -= 2
    return end


def _split_lines(text: str) -> list[tuple[str, int, int]]:
    lines: list[tuple[str, int, int]] = []
    start = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\r" and index + 1 < length and text[index + 1] == "\n":
            lines.append((text[start:index], start, index))
            index += 2
            start = index
        elif char in "\r\n":
            lines.append((text[start:index], start, index))
            index += 1
            start = index
        else:
            index += 1
    if start < length:
        lines.append((text[start:], start, length))
    return lines


def _stored_length(lines: list[tuple[str, int, int, int]]) -> int:
    return sum(len(item[0]) for item in lines) + max(0, len(lines) - 1)


def _block(ordinal: int, text: str, line_start: int, line_end: int, start: int, end: int) -> TextBlock:
    return TextBlock(
        ordinal, text, hashlib.sha256(text.encode("utf-8")).hexdigest(),
        line_start, line_end, start, end,
    )


def _c0_ratio(text: str) -> float:
    if not text:
        return 0.0
    bad = sum(1 for char in text if ord(char) < 32 and ord(char) not in _C0_ALLOWED)
    return bad / len(text)


def _cap_characters(text: str) -> tuple[str, bool]:
    if len(text) <= CHARACTER_BUDGET:
        return text, False
    end = CHARACTER_BUDGET
    if end > 0 and text[end - 1] == "\r" and end < len(text) and text[end] == "\n":
        end -= 1
    return text[:end], True


def _cap_lines(text: str) -> tuple[str, bool]:
    count = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\r" and index + 1 < length and text[index + 1] == "\n":
            count += 1
            index += 2
        elif char in "\r\n":
            count += 1
            index += 1
        else:
            index += 1
            continue
        if count == LINE_BUDGET:
            return text[:index], index < length
    return text, False


def _known(limit: CoverageLimit) -> bool:
    if limit.known_total is None or limit.omitted_start is None or limit.omitted_end_exclusive is None:
        return False
    if not (
        limit.known_total > limit.observed_count
        and limit.omitted_start == limit.observed_count
        and limit.omitted_end_exclusive == limit.known_total
    ):
        return False
    if limit.limit_name == "source_bytes":
        return limit.coordinate_space == "byte" and limit.boundary == "safe_decode"
    if limit.limit_name == "line_length":
        return limit.coordinate_space == "code_point" and limit.line_end_reached is True
    return False


def _disposition(limits: list[CoverageLimit]) -> tuple[str, bool]:
    if not limits:
        return "complete", False
    if all(_known(limit) for limit in limits):
        return "partial_known", False
    return "partial_unknown", True


def _unsupported(reason: str, profile: str, bom_removed: bool) -> DecodeResult:
    return DecodeResult(
        "unsupported", reason, profile, bom_removed, NORMALIZATION_PROFILE,
        "not_evaluated", False, (), (),
    )
