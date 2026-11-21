"""Bounded-exact vector generations stored in the Catalog database."""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
import sqlite3
import stat
import struct
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .validation import ContractError, validate_source_root_path

MAGIC = b"PDXG1IMG"
HEADER_LEN = 16
POINTER_BUDGET_BYTES = 12288
MAX_ENTRIES = 10000
DIMENSIONS = (384, 768)
BACKEND_KIND = "bounded_exact"
INITIAL_AUDIT = "0" * 64
LOCATOR_RE_TEXT = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.img$"
)
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

CONTRACT_CODE = {
    "pdx_local_memory_record_v1": 1,
    "pdx_local_memory_record_v2": 2,
    "pdx_local_canonical_knowledge_version_v1": 3,
}
CODE_CONTRACT = {code: name for name, code in CONTRACT_CODE.items()}
RECORD_LEN = {1: 97, 2: 97, 3: 113}


class VectorNormTooSmall(ContractError):
    def __init__(self) -> None:
        super().__init__("VECTOR_NORM_TOO_SMALL")


@dataclass(frozen=True)
class SnapshotQueryResult:
    """Typed generation query that leaves the caller transaction untouched."""

    disposition: str
    generation_id: str | None
    image_sha256: str | None
    dimensions: int | None
    backend_kind: str | None
    authorized_scored: int
    results: tuple[dict[str, Any], ...]


def _deadline_reached(deadline: float | None, monotonic: Callable[[], float]) -> bool:
    return deadline is not None and monotonic() >= deadline


def _snapshot_result(
    disposition: str,
    row: sqlite3.Row | None = None,
    authorized_scored: int = 0,
    results: tuple[dict[str, Any], ...] = (),
) -> SnapshotQueryResult:
    if row is None:
        return SnapshotQueryResult(disposition, None, None, None, None, authorized_scored, results)
    return SnapshotQueryResult(
        disposition,
        str(row["generation_id"]),
        str(row["image_sha256"]),
        int(row["dimensions"]),
        str(row["backend_kind"]),
        authorized_scored,
        results,
    )


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def durable_replace(source: Path, destination: Path) -> None:
    """Replace destination only after a durable same-directory rename."""
    if source.parent != destination.parent:
        raise ContractError("temporary image and final image must share a directory")
    if os.name == "nt":
        if source.drive != destination.drive:
            raise ContractError("temporary image and final image must share a volume")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        flags = 0x1 | 0x8
        if not kernel32.MoveFileExW(str(source), str(destination), flags):
            error = ctypes.get_last_error()
            raise ContractError(f"durable rename failed: {error}")
        return
    os.replace(source, destination)


def fold_digest(
    previous: str,
    generation_id: str,
    image_sha256: str,
    image_byte_size: int,
    purged_at: str,
) -> str:
    if len(previous) != 64 or len(image_sha256) != 64 or len(purged_at) != 27:
        raise ContractError("audit preimage width is invalid")
    material = f"{previous}{generation_id}{image_sha256}{image_byte_size}{purged_at}"
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def formula_cap(entry_count: int, dimensions: int) -> int:
    return entry_count * (dimensions * 4 + 128)


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(9):
        byte = data[offset + index]
        if index == 8:
            return (value << 8) | byte, offset + index + 1
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset + index + 1
    raise ContractError("truncated sqlite varint")


def _local_payload(payload_size: int, usable: int, kind: int) -> int:
    if kind == 0x0D:
        maximum = usable - 35
    else:
        maximum = ((usable - 12) * 64 // 255) - 23
    if payload_size <= maximum:
        return payload_size
    minimum = ((usable - 12) * 32 // 255) - 23
    local = minimum + ((payload_size - minimum) % (usable - 4))
    if local > maximum:
        local = minimum
    return local


def btree_pages(data: bytes, page_size: int, root: int) -> set[int]:
    """Pages owned by one btree, including overflow. CPython SQLite has no dbstat."""
    seen: set[int] = set()
    stack = [root]
    usable = page_size
    while stack:
        page = stack.pop()
        if page in seen or page < 1:
            continue
        seen.add(page)
        offset = (page - 1) * page_size
        header = 100 if page == 1 else 0
        kind = data[offset + header]
        if kind not in (0x02, 0x05, 0x0A, 0x0D):
            raise ContractError(f"unexpected btree page type {kind}")
        cell_count = int.from_bytes(data[offset + header + 3 : offset + header + 5], "big")
        pointer = header + (12 if kind in (0x02, 0x05) else 8)
        for index in range(cell_count):
            cell_at = int.from_bytes(
                data[offset + pointer + 2 * index : offset + pointer + 2 * index + 2],
                "big",
            )
            cell = offset + cell_at
            if kind in (0x02, 0x05):
                stack.append(int.from_bytes(data[cell : cell + 4], "big"))
                cell += 4
            if kind in (0x0A, 0x0D):
                payload_size, cell = _varint(data, cell)
                if kind == 0x0D:
                    _, cell = _varint(data, cell)
                local = _local_payload(payload_size, usable, kind)
                if local < payload_size:
                    overflow = int.from_bytes(data[cell + local : cell + local + 4], "big")
                    while overflow:
                        if overflow in seen:
                            break
                        seen.add(overflow)
                        overflow = int.from_bytes(
                            data[(overflow - 1) * page_size : (overflow - 1) * page_size + 4],
                            "big",
                        )
        if kind in (0x02, 0x05):
            stack.append(int.from_bytes(data[offset + header + 8 : offset + header + 12], "big"))
    return seen


def attributable_pointer_share(connection: sqlite3.Connection) -> int:
    """Ceiling share of vector_generation pages from the connection's snapshot."""
    listed = connection.execute("PRAGMA database_list").fetchone()
    database_file = listed[2] if listed is not None else ""
    if not database_file:
        raise ContractError("vector generation requires a file-backed catalog")
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    snapshot = connection.serialize()
    if len(snapshot) % page_size != 0:
        raise ContractError("catalog snapshot is truncated")
    pages: set[int] = set()
    roots = connection.execute(
        """
        SELECT rootpage FROM sqlite_schema
        WHERE tbl_name = 'vector_generation' AND rootpage > 0
        """
    ).fetchall()
    if len(roots) < 3:
        raise ContractError("vector generation indexes are incomplete")
    for (root,) in roots:
        pages |= btree_pages(snapshot, page_size, int(root))
    scopes = connection.execute(
        "SELECT COUNT(*) FROM (SELECT DISTINCT workspace_id, profile FROM vector_generation)"
    ).fetchone()[0]
    if scopes < 1:
        return 0
    return (len(pages) * page_size + scopes - 1) // scopes


def _is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return bool(getattr(info, "st_file_attributes", 0) & REPARSE) or stat.S_ISLNK(info.st_mode)


def _reject_reparse_chain(path: Path) -> None:
    resolved = path.absolute()
    chain = list(resolved.parents)
    for item in reversed(chain[:-1]):
        if item.exists() and _is_reparse(item):
            raise ContractError(f"reparse-point ancestor rejected: {item}")
    if resolved.exists() and _is_reparse(resolved):
        raise ContractError("image root is a reparse point")


def _id_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()[:16]


def _normalize(values: Sequence[float], dimensions: int) -> bytes:
    if len(values) != dimensions:
        raise ContractError("vector dimension mismatch")
    acc = 0.0
    numbers: list[float] = []
    for value in values:
        number = float(value)
        if not math.isfinite(number):
            raise ContractError("vector component is not finite")
        numbers.append(number)
        acc += number * number
    if not math.isfinite(acc):
        raise ContractError("vector norm is not finite")
    norm = math.sqrt(acc)
    if not math.isfinite(norm):
        raise ContractError("vector norm is not finite")
    if norm <= 1e-12:
        raise VectorNormTooSmall()
    return struct.pack(f"<{dimensions}f", *[number / norm for number in numbers])


def _pack_entry(
    code: int,
    target_id: str,
    version_id: str | None,
    content_sha256: str,
    vector_bytes: bytes,
) -> tuple[bytes, bytes]:
    if code in (1, 2) and version_id is not None:
        raise ContractError("L2 target_version_id must be absent")
    if code == 3 and not version_id:
        raise ContractError("L3 target_version_id is required")
    content = bytes.fromhex(content_sha256)
    if len(content) != 32:
        raise ContractError("content digest must be 32 bytes")
    target_hash = _id_hash(target_id)
    version_hash = _id_hash(version_id) if version_id is not None else b""
    vector_sha = hashlib.sha256(vector_bytes).digest()
    entry_id = hashlib.sha256(
        bytes([code]) + target_hash + version_hash + content + vector_sha
    ).digest()[:16]
    record = entry_id + bytes([code]) + target_hash + version_hash + content + vector_sha
    if len(record) != RECORD_LEN[code]:
        raise ContractError("entry record width mismatch")
    return entry_id, record


def _pack_image(dimensions: int, entries: Sequence[tuple[bytes, bytes]]) -> bytes:
    payload = bytearray(MAGIC)
    payload += struct.pack("<II", dimensions, len(entries))
    for vector, record in entries:
        payload += vector
        payload += record
    return bytes(payload)


def _iter_image(data: bytes, dimensions: int) -> list[tuple[bytes, bytes]]:
    if len(data) < HEADER_LEN or data[:8] != MAGIC:
        raise ContractError("corrupt image")
    stored_dim, count = struct.unpack_from("<II", data, 8)
    if stored_dim != dimensions:
        raise ContractError("image dimension mismatch")
    offset = HEADER_LEN
    entries: list[tuple[bytes, bytes]] = []
    for _ in range(count):
        vector_end = offset + dimensions * 4
        if vector_end + 17 > len(data):
            raise ContractError("short image")
        code = data[vector_end + 16]
        record_len = RECORD_LEN.get(code)
        if record_len is None or vector_end + record_len > len(data):
            raise ContractError("short image")
        entries.append((data[offset:vector_end], data[vector_end : vector_end + record_len]))
        offset = vector_end + record_len
    if offset != len(data):
        raise ContractError("corrupt image")
    return entries


def _unpack_record(record: bytes) -> dict[str, Any]:
    code = record[16]
    version_hash: bytes | None
    if code == 3:
        version_hash = record[33:49]
        content = record[49:81]
        vector_sha = record[81:113]
    else:
        version_hash = None
        content = record[33:65]
        vector_sha = record[65:97]
    return {
        "entry_id": record[:16],
        "code": code,
        "target_hash": record[17:33],
        "version_hash": version_hash,
        "content": content,
        "vector_sha": vector_sha,
    }


class VectorGenerationStore:
    """Build, publish, query, and retire workspace-scoped exact generations."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        image_root: str | Path,
        *,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._conn.isolation_level = None
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._clock = clock
        self._lock = threading.Lock()
        self._held: set[str] = set()
        self._pending: dict[str, dict[str, Any]] = {}
        self.image_root = self._require_root(Path(image_root))

    def start_build(
        self,
        *,
        workspace_id: str,
        profile: str,
        vectors: Mapping[tuple[str, str, str | None], Sequence[float]],
        _before_lock: Callable[[], None] | None = None,
        _pause: Callable[[], None] | None = None,
    ) -> str:
        if profile not in ("l2", "l3"):
            raise ContractError("profile must be l2 or l3")
        sources = _legal_sources(self._conn, workspace_id, profile)
        if len(sources) > MAX_ENTRIES:
            raise ContractError("entry count exceeds 10000")
        expected = {
            (source["contract"], source["target_id"], source["version_id"]) for source in sources
        }
        supplied = set(vectors)
        if not expected:
            raise ContractError("no legal active source")
        if supplied - expected:
            raise ContractError("generation includes a source outside the legal active set")
        if expected - supplied:
            raise ContractError("generation is missing a legal active source")
        dimensions = len(vectors[next(iter(expected))])
        if dimensions not in DIMENSIONS:
            raise ContractError("dimensions must be 384 or 768")
        ordered = sorted(sources, key=lambda item: (item["contract"], item["target_id"], item["version_id"] or ""))
        packed: list[tuple[bytes, bytes]] = []
        entry_ids: list[bytes] = []
        try:
            for source in ordered:
                key = (source["contract"], source["target_id"], source["version_id"])
                vector = _normalize(vectors[key], dimensions)
                entry_id, record = _pack_entry(
                    CONTRACT_CODE[source["contract"]],
                    source["target_id"],
                    source["version_id"],
                    source["content_sha256"],
                    vector,
                )
                packed.append((vector, record))
                entry_ids.append(entry_id)
        except VectorNormTooSmall:
            raise
        image = _pack_image(dimensions, packed)
        digest = hashlib.sha256(image).hexdigest()
        if len(image) + POINTER_BUDGET_BYTES > formula_cap(len(packed), dimensions):
            raise ContractError("generation exceeds the disk formula")
        generation_id = str(uuid.uuid4())
        locator = f"{generation_id}.img"
        manifest = hashlib.sha256(b"".join(entry_ids)).hexdigest()
        capability = hashlib.sha256(
            f"bounded_exact|float32|l2|cosine|{dimensions}".encode("ascii")
        ).hexdigest()
        stamp = self._clock()
        if _before_lock is not None:
            _before_lock()
        self._begin_immediate()
        try:
            fresh = _ordered_sources(self._conn, workspace_id, profile)
            if [_source_identity(source) for source in fresh] != [
                _source_identity(source) for source in ordered
            ]:
                raise ContractError("source snapshot drifted")
            _assert_image_matches_sources(image, dimensions, ordered)
            self._insert_building(
                generation_id=generation_id,
                workspace_id=workspace_id,
                profile=profile,
                dimensions=dimensions,
                entry_count=len(packed),
                manifest=manifest,
                capability=capability,
                image_sha256=digest,
                locator=locator,
                image_byte_size=len(image),
                stamp=stamp,
            )
            if _pause is not None:
                _pause()
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        self._pending[generation_id] = {
            "image": image,
            "sources": ordered,
            "dimensions": dimensions,
            "manifest": manifest,
            "digest": digest,
            "workspace_id": workspace_id,
            "profile": profile,
        }
        self.reconcile()
        return generation_id

    def publish(
        self,
        generation_id: str,
        _before_lock: Callable[[], None] | None = None,
        _pause: Callable[[], None] | None = None,
        _before_handle_check: Callable[[], None] | None = None,
    ) -> None:
        pending = self._pending.get(generation_id)
        if pending is None:
            raise ContractError("building image is not prepared")
        self._write_durable(generation_id, pending, _before_handle_check=_before_handle_check)
        if _before_lock is not None:
            _before_lock()
        self._publish_pointer(generation_id, pending, _pause=_pause)
        self._pending.pop(generation_id, None)
        self.reconcile()

    def fail_build(self, generation_id: str) -> None:
        stamp = self._clock()
        self._begin_immediate()
        try:
            cursor = self._conn.execute(
                """
                UPDATE vector_generation
                SET state = 'failed', updated_at = ?
                WHERE generation_id = ? AND state = 'building' AND is_current = 0
                """,
                (stamp, generation_id),
            )
            if cursor.rowcount != 1:
                raise ContractError("building generation is not fail-able")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        self._pending.pop(generation_id, None)

    def retire(self, *, workspace_id: str, profile: str) -> None:
        stamp = self._clock()
        self._begin_immediate()
        try:
            rows = self._scope_rows(workspace_id, profile)
            if any(row["state"] == "building" for row in rows):
                raise ContractError("build already in progress")
            current = [row for row in rows if row["is_current"] == 1]
            other = [row for row in rows if row["is_current"] == 0]
            if len(current) != 1:
                raise ContractError("scope has no current generation")
            if other:
                self._fold(current[0], other[0], stamp)
            cursor = self._conn.execute(
                """
                UPDATE vector_generation
                SET state = 'retired', is_current = 0, updated_at = ?
                WHERE generation_id = ? AND state = 'active' AND is_current = 1
                """,
                (stamp, current[0]["generation_id"]),
            )
            if cursor.rowcount != 1:
                raise ContractError("current generation was not retired")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def query(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        layer: str,
        query_context: Mapping[str, Any],
        k: int = 10,
        timeout_seconds: float | None = None,
        _monotonic: Callable[[], float] = time.monotonic,
    ) -> list[dict[str, Any]]:
        if layer not in ("l2", "l3"):
            raise ContractError("layer must be l2 or l3")
        if k < 1:
            raise ContractError("K must be positive")
        vector_values = query_context.get("vector")
        if not isinstance(vector_values, Sequence) or isinstance(vector_values, (str, bytes)):
            return []
        deadline = None if timeout_seconds is None else _monotonic() + timeout_seconds
        self._begin_immediate()
        try:
            try:
                outcome = self.query_in_snapshot(
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    layer=layer,
                    query_context=query_context,
                    k=k,
                    deadline=deadline,
                    _monotonic=_monotonic,
                )
            except ContractError:
                self._conn.commit()
                return []
            self._conn.commit()
            if outcome.disposition != "results":
                return []
            return [dict(item) for item in outcome.results]
        except Exception:
            self._conn.rollback()
            raise

    def query_in_snapshot(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        layer: str,
        query_context: Mapping[str, Any],
        k: int = 10,
        deadline: float | None = None,
        _monotonic: Callable[[], float] = time.monotonic,
    ) -> SnapshotQueryResult:
        """Score one generation inside the caller's open transaction."""
        if not self._conn.in_transaction:
            raise ContractError("snapshot query requires an open transaction")
        if layer not in ("l2", "l3"):
            raise ContractError("layer must be l2 or l3")
        if k < 1:
            raise ContractError("K must be positive")
        vector_values = query_context.get("vector")
        if not isinstance(vector_values, Sequence) or isinstance(vector_values, (str, bytes)):
            raise ContractError("query vector is required")
        if _deadline_reached(deadline, _monotonic):
            return _snapshot_result("time_limit")
        row = self._conn.execute(
            """
            SELECT * FROM vector_generation
            WHERE workspace_id = ? AND profile = ? AND state = 'active' AND is_current = 1
            """,
            (workspace_id, layer),
        ).fetchone()
        if row is None:
            return _snapshot_result("vector_generation_unavailable")
        if len(vector_values) != int(row["dimensions"]):
            raise ContractError("vector dimension mismatch")
        query_vector = _normalize(vector_values, int(row["dimensions"]))
        if _deadline_reached(deadline, _monotonic):
            return _snapshot_result("time_limit", row)
        locator = str(row["image_locator"])
        self._hold(locator)
        try:
            opened = _read_image(self._image_path(locator), int(row["image_byte_size"]), row["image_sha256"])
            if opened is None:
                raise ContractError("image verification failed")
            authorized = _authorization_set(self._conn, workspace_id, principal_id, layer)
            if _deadline_reached(deadline, _monotonic):
                return _snapshot_result("time_limit", row)
            parsed = _iter_image(opened, int(row["dimensions"]))
            hits: list[tuple[float, str, dict[str, Any]]] = []
            authorized_scored = 0
            for vector, record in parsed:
                if _deadline_reached(deadline, _monotonic):
                    return _snapshot_result("time_limit", row, authorized_scored)
                unpacked = _unpack_record(record)
                if hashlib.sha256(vector).digest() != unpacked["vector_sha"]:
                    raise ContractError("vector digest mismatch")
                key = (
                    unpacked["code"],
                    unpacked["target_hash"],
                    unpacked["version_hash"],
                    unpacked["content"],
                )
                source = authorized.get(key)
                if source is None:
                    continue
                authorized_scored += 1
                score = _dot(vector, query_vector)
                entry_uuid = str(uuid.UUID(bytes=unpacked["entry_id"]))
                hits.append((score, entry_uuid, source))
            hits.sort(key=lambda item: (-item[0], item[1]))
            admitted = tuple(
                {
                    "entry_id": entry_uuid,
                    "source_contract_version": source["contract"],
                    "target_id": source["target_id"],
                    "target_version_id": source["version_id"],
                    "score": score,
                }
                for score, entry_uuid, source in hits[:k]
            )
            if not hits:
                return _snapshot_result("no_authorized_candidates", row, authorized_scored)
            return _snapshot_result("results", row, authorized_scored, admitted)
        finally:
            self._release(locator)

    def reconcile(self) -> list[str]:
        locators = {
            row[0]
            for row in self._conn.execute("SELECT image_locator FROM vector_generation")
        }
        with self._lock:
            protected = set(self._held) | locators
        removed: list[str] = []
        for path in self.image_root.iterdir():
            if not path.is_file() or path.suffix not in {".img", ".tmp"}:
                continue
            if path.name in protected or _is_reparse(path):
                continue
            if path.suffix == ".img" and not _locator_ok(path.name):
                continue
            path.unlink()
            removed.append(path.name)
        return removed

    def hold_snapshot(self, locator: str) -> None:
        self._hold(locator)

    def release_snapshot(self, locator: str) -> None:
        self._release(locator)

    def _insert_building(
        self,
        *,
        generation_id: str,
        workspace_id: str,
        profile: str,
        dimensions: int,
        entry_count: int,
        manifest: str,
        capability: str,
        image_sha256: str,
        locator: str,
        image_byte_size: int,
        stamp: str,
    ) -> None:
        rows = self._scope_rows(workspace_id, profile)
        if len(rows) > 2:
            raise ContractError("scope row cap")
        current = [row for row in rows if row["is_current"] == 1]
        other = [row for row in rows if row["is_current"] == 0]
        if any(row["state"] == "building" for row in other):
            raise ContractError("build already in progress")
        if len(current) > 1 or len(other) > 1:
            raise ContractError("scope row cap")
        audit = INITIAL_AUDIT
        if other:
            if other[0]["state"] not in ("retired", "failed"):
                raise ContractError("unexpected non-current state")
            if current:
                self._fold(current[0], other[0], stamp)
            else:
                audit = fold_digest(
                    other[0]["audit_reconciliation_sha256"],
                    other[0]["generation_id"],
                    other[0]["image_sha256"],
                    int(other[0]["image_byte_size"]),
                    stamp,
                )
                self._conn.execute(
                    "DELETE FROM vector_generation WHERE generation_id = ?",
                    (other[0]["generation_id"],),
                )
        remaining = self._conn.execute(
            "SELECT COUNT(*) FROM vector_generation WHERE workspace_id = ? AND profile = ?",
            (workspace_id, profile),
        ).fetchone()[0]
        if remaining >= 2:
            raise ContractError("scope row cap")
        self._conn.execute(
            """
            INSERT INTO vector_generation (
                generation_id, workspace_id, profile, backend_kind, dimensions,
                encoding, normalization, metric, entry_count, state, is_current,
                build_manifest_digest, capability_digest, image_sha256, image_locator,
                image_byte_size, purged_at, created_at, updated_at,
                audit_reconciliation_sha256
            ) VALUES (?, ?, ?, ?, ?, 'float32', 'l2', 'cosine', ?, 'building', 0,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generation_id,
                workspace_id,
                profile,
                BACKEND_KIND,
                dimensions,
                entry_count,
                manifest,
                capability,
                image_sha256,
                locator,
                image_byte_size,
                stamp,
                stamp,
                stamp,
                audit,
            ),
        )

    def _fold(self, current: sqlite3.Row, other: sqlite3.Row, stamp: str) -> None:
        updated = fold_digest(
            current["audit_reconciliation_sha256"],
            other["generation_id"],
            other["image_sha256"],
            int(other["image_byte_size"]),
            stamp,
        )
        self._conn.execute(
            """
            UPDATE vector_generation
            SET audit_reconciliation_sha256 = ?, updated_at = ?
            WHERE generation_id = ?
            """,
            (updated, stamp, current["generation_id"]),
        )
        self._conn.execute(
            "DELETE FROM vector_generation WHERE generation_id = ?",
            (other["generation_id"],),
        )

    def _write_durable(
        self,
        generation_id: str,
        pending: Mapping[str, Any],
        _before_handle_check: Callable[[], None] | None = None,
    ) -> None:
        image = pending["image"]
        destination = self._image_path(f"{generation_id}.img")
        temporary = self.image_root / f"{generation_id}.tmp"
        if temporary.parent != destination.parent:
            raise ContractError("temporary image and final image must share a directory")
        if os.name == "nt" and temporary.drive != destination.drive:
            raise ContractError("temporary image and final image must share a volume")
        _reject_occupied_path(temporary)
        _reject_reparse_path(destination)
        try:
            handle = _open_exclusive_temp(temporary)
        except FileExistsError as exc:
            raise ContractError("temporary image path is already present") from exc
        except OSError as exc:
            raise ContractError("temporary image path is not a new file") from exc
        try:
            view = memoryview(image)
            while view:
                count = os.write(handle, view)
                if count <= 0:
                    raise ContractError("temporary image write was incomplete")
                view = view[count:]
            os.fsync(handle)
            if _before_handle_check is not None:
                _before_handle_check()
            if not _handle_matches_path(handle, temporary):
                raise ContractError("temporary image handle escaped the image root")
        finally:
            os.close(handle)
        if _is_reparse(temporary):
            raise ContractError("temporary image path is a reparse point")
        written = _read_image(temporary, len(image), pending["digest"])
        if written != image:
            _remove_ordinary_file(temporary)
            raise ContractError("image digest mismatch before rename")
        try:
            _reject_reparse_path(destination)
            durable_replace(temporary, destination)
        except Exception:
            _remove_ordinary_file(temporary)
            raise
        if _read_image(destination, len(image), pending["digest"]) != image:
            raise ContractError("durable rename was not confirmed")

    def _publish_pointer(
        self,
        generation_id: str,
        pending: Mapping[str, Any],
        _pause: Callable[[], None] | None = None,
    ) -> None:
        stamp = self._clock()
        self._begin_immediate()
        try:
            row = self._building_row(generation_id)
            if (
                row["workspace_id"] != pending["workspace_id"]
                or row["profile"] != pending["profile"]
                or row["build_manifest_digest"] != pending["manifest"]
                or row["image_sha256"] != pending["digest"]
                or int(row["dimensions"]) != pending["dimensions"]
                or int(row["entry_count"]) != len(pending["sources"])
                or int(row["image_byte_size"]) != len(pending["image"])
                or row["backend_kind"] != BACKEND_KIND
            ):
                raise ContractError("publication snapshot drifted")
            fresh = _ordered_sources(self._conn, row["workspace_id"], row["profile"])
            if [_source_identity(source) for source in fresh] != [
                _source_identity(source) for source in pending["sources"]
            ]:
                raise ContractError("source snapshot drifted")
            _assert_image_matches_sources(pending["image"], pending["dimensions"], fresh)
            path = self._image_path(row["image_locator"])
            if _read_image(path, int(row["image_byte_size"]), row["image_sha256"]) != pending["image"]:
                raise ContractError("image verification failed")
            share = attributable_pointer_share(self._conn)
            if share > POINTER_BUDGET_BYTES:
                raise ContractError("pointer share exceeds the 12288-byte budget")
            if int(row["image_byte_size"]) + share > formula_cap(
                int(row["entry_count"]), int(row["dimensions"])
            ):
                raise ContractError("generation exceeds the disk formula")
            current = self._conn.execute(
                """
                SELECT generation_id FROM vector_generation
                WHERE workspace_id = ? AND profile = ? AND is_current = 1
                """,
                (row["workspace_id"], row["profile"]),
            ).fetchone()
            if current is not None:
                retired = self._conn.execute(
                    """
                    UPDATE vector_generation
                    SET state = 'retired', is_current = 0, updated_at = ?
                    WHERE generation_id = ? AND state = 'active' AND is_current = 1
                    """,
                    (stamp, current["generation_id"]),
                )
                if retired.rowcount != 1:
                    raise ContractError("current generation was not retired")
            activated = self._conn.execute(
                """
                UPDATE vector_generation
                SET state = 'active', is_current = 1, updated_at = ?
                WHERE generation_id = ? AND state = 'building' AND is_current = 0
                  AND workspace_id = ? AND profile = ? AND backend_kind = ?
                  AND dimensions = ? AND entry_count = ? AND image_sha256 = ?
                  AND build_manifest_digest = ?
                  AND encoding = 'float32' AND normalization = 'l2' AND metric = 'cosine'
                """,
                (
                    stamp,
                    generation_id,
                    row["workspace_id"],
                    row["profile"],
                    BACKEND_KIND,
                    row["dimensions"],
                    row["entry_count"],
                    row["image_sha256"],
                    row["build_manifest_digest"],
                ),
            )
            if activated.rowcount != 1:
                raise ContractError("building generation was not published")
            if _pause is not None:
                _pause()
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _building_row(self, generation_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM vector_generation WHERE generation_id = ?",
            (generation_id,),
        ).fetchone()
        if row is None or row["state"] != "building" or row["is_current"] != 0:
            raise ContractError("building generation is absent")
        return row

    def _scope_rows(self, workspace_id: str, profile: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                """
                SELECT * FROM vector_generation
                WHERE workspace_id = ? AND profile = ?
                """,
                (workspace_id, profile),
            )
        )

    def _image_path(self, locator: str) -> Path:
        if not _locator_ok(locator):
            raise ContractError("image locator must be the generation id plus .img")
        path = self.image_root / locator
        if path.parent != self.image_root:
            raise ContractError("image path escapes the generation directory")
        return path

    def _begin_immediate(self) -> None:
        self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")

    def _hold(self, locator: str) -> None:
        with self._lock:
            self._held.add(locator)

    def _release(self, locator: str) -> None:
        with self._lock:
            self._held.discard(locator)

    @staticmethod
    def _require_root(path: Path) -> Path:
        text = str(path)
        if text.startswith("\\\\") or text.startswith("//"):
            raise ContractError("image root rejects a UNC path")
        lowered = text.lower()
        if "\\\\.\\" in lowered or "\\\\?\\" in lowered or lowered.startswith("\\\\.\\") or lowered.startswith("\\\\?\\"):
            raise ContractError("image root rejects a device namespace")
        validate_source_root_path(text)
        if not path.is_dir():
            raise ContractError("image root must be an existing directory")
        _reject_reparse_chain(path)
        return path


def _open_exclusive_temp(path: Path) -> int:
    """Create a new temp file. On Windows the handle shares delete so a replaced parent is visible."""
    if os.name != "nt":
        return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    opened = kernel32.CreateFileW(
        str(path),
        0x40000000,
        0x4,
        None,
        1,
        0x80,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not opened or opened == invalid:
        error = ctypes.get_last_error()
        if error in {80, 183}:
            raise FileExistsError(error, "file exists", str(path))
        raise OSError(error, "temporary image path is not a new file", str(path))
    return msvcrt.open_osfhandle(int(opened), getattr(os, "O_BINARY", 0))


def _reject_occupied_path(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise ContractError("temporary image path is already present")


def _reject_reparse_path(path: Path) -> None:
    try:
        if _is_reparse(path):
            raise ContractError("image path is a reparse point")
    except FileNotFoundError:
        return


def _remove_ordinary_file(path: Path) -> None:
    try:
        if _is_reparse(path):
            return
    except FileNotFoundError:
        return
    if path.is_file():
        path.unlink()


def _strip_extended_path(text: str) -> str:
    if text.startswith("\\\\?\\UNC\\"):
        return "\\\\" + text[8:]
    if text.startswith("\\\\?\\"):
        return text[4:]
    return text


def _final_path_from_handle(windows_handle: int) -> str | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetFinalPathNameByHandleW(windows_handle, buffer, len(buffer), 0)
    if length <= 0 or length >= len(buffer):
        return None
    return buffer.value


def _final_path(handle: int) -> str | None:
    if os.name != "nt":
        return None
    import msvcrt

    return _final_path_from_handle(msvcrt.get_osfhandle(handle))


def _directory_final_path(path: Path) -> str | None:
    if os.name != "nt":
        return str(path)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    opened = kernel32.CreateFileW(
        str(path),
        0x80000000,
        0x1 | 0x2 | 0x4,
        None,
        3,
        0x02000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not opened or opened == invalid:
        return None
    try:
        return _final_path_from_handle(opened)
    finally:
        kernel32.CloseHandle(opened)


def _handle_matches_path(handle: int, expected: Path) -> bool:
    if os.name != "nt":
        return True
    final = _final_path(handle)
    directory = _directory_final_path(expected.parent)
    if final is None or directory is None:
        return False
    file_path = Path(_strip_extended_path(final))
    directory_path = _strip_extended_path(directory)
    return (
        os.path.normcase(str(file_path.parent)) == os.path.normcase(os.path.normpath(directory_path))
        and os.path.normcase(file_path.name) == os.path.normcase(expected.name)
    )


def _source_identity(source: Mapping[str, Any]) -> tuple[str, str, str | None, str]:
    return (
        source["contract"],
        source["target_id"],
        source["version_id"],
        source["content_sha256"],
    )


def _ordered_sources(connection: sqlite3.Connection, workspace_id: str, profile: str) -> list[dict[str, Any]]:
    sources = _legal_sources(connection, workspace_id, profile)
    sources.sort(key=lambda item: (item["contract"], item["target_id"], item["version_id"] or ""))
    return sources


def _assert_image_matches_sources(
    image: bytes, dimensions: int, sources: Sequence[Mapping[str, Any]]
) -> None:
    try:
        entries = _iter_image(image, dimensions)
    except ContractError as exc:
        raise ContractError("source snapshot drifted") from exc
    if len(entries) != len(sources):
        raise ContractError("source snapshot drifted")
    for (vector, record), source in zip(entries, sources, strict=True):
        unpacked = _unpack_record(record)
        version_hash = _id_hash(source["version_id"]) if source["version_id"] is not None else None
        if (
            unpacked["content"] != bytes.fromhex(source["content_sha256"])
            or unpacked["target_hash"] != _id_hash(source["target_id"])
            or unpacked["version_hash"] != version_hash
            or hashlib.sha256(vector).digest() != unpacked["vector_sha"]
            or unpacked["code"] != CONTRACT_CODE[source["contract"]]
        ):
            raise ContractError("source snapshot drifted")


def _locator_ok(locator: str) -> bool:
    import re

    return re.fullmatch(LOCATOR_RE_TEXT, locator) is not None


def _read_image(path: Path, expected_size: int, expected_sha256: str) -> bytes | None:
    if not path.exists() or _is_reparse(path):
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        handle = os.open(path, flags)
    except OSError:
        return None
    try:
        linked = os.lstat(path)
        info = os.fstat(handle)
        if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
            return None
        if not _handle_matches_path(handle, path):
            return None
        if info.st_size != expected_size:
            return None
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while True:
            block = os.read(handle, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            chunks.append(block)
        if digest.hexdigest() != expected_sha256:
            return None
        return b"".join(chunks)
    finally:
        os.close(handle)


def _dot(left: bytes, right: bytes) -> float:
    total = 0.0
    for (one,), (two,) in zip(struct.iter_unpack("<f", left), struct.iter_unpack("<f", right), strict=True):
        total += float(one) * float(two)
    return total


def _legal_sources(
    connection: sqlite3.Connection, workspace_id: str, profile: str
) -> list[dict[str, Any]]:
    if profile == "l2":
        sources = [
            {
                "contract": "pdx_local_memory_record_v1",
                "target_id": row["memory_id"],
                "version_id": None,
                "content_sha256": row["content_sha256"],
            }
            for row in connection.execute(
                """
                SELECT memory_id, content_sha256 FROM memory_record
                WHERE workspace_id = ? AND status = 'active'
                """,
                (workspace_id,),
            )
        ]
        sources.extend(
            {
                "contract": "pdx_local_memory_record_v2",
                "target_id": row["memory_id"],
                "version_id": None,
                "content_sha256": row["content_sha256"],
            }
            for row in connection.execute(
                """
                SELECT memory_id, content_sha256 FROM memory_record_v2
                WHERE workspace_id = ? AND status = 'active'
                """,
                (workspace_id,),
            )
        )
        return sources
    return [
        {
            "contract": "pdx_local_canonical_knowledge_version_v1",
            "target_id": row["canonical_knowledge_id"],
            "version_id": row["version_id"],
            "content_sha256": row["content_sha256"],
        }
        for row in connection.execute(
            """
            SELECT k.canonical_knowledge_id, v.version_id, v.content_sha256
            FROM canonical_knowledge k
            JOIN canonical_knowledge_version v
              ON v.version_id = k.current_version_id
             AND v.canonical_knowledge_id = k.canonical_knowledge_id
            WHERE k.workspace_id = ? AND k.status = 'active'
            """,
            (workspace_id,),
        )
    ]


def _authorization_set(
    connection: sqlite3.Connection, workspace_id: str, principal_id: str, layer: str
) -> dict[tuple[Any, ...], dict[str, Any]]:
    if layer == "l2":
        sources = _authorized_l2(connection, workspace_id, principal_id)
    else:
        sources = _authorized_l3(connection, workspace_id, principal_id)
    authorized: dict[tuple[Any, ...], dict[str, Any]] = {}
    for source in sources:
        code = CONTRACT_CODE[source["contract"]]
        version_hash = _id_hash(source["version_id"]) if source["version_id"] is not None else None
        authorized[
            (code, _id_hash(source["target_id"]), version_hash, bytes.fromhex(source["content_sha256"]))
        ] = source
    return authorized


def _authorized_l2(
    connection: sqlite3.Connection, workspace_id: str, principal_id: str
) -> list[dict[str, Any]]:
    sources = [
        {
            "contract": "pdx_local_memory_record_v1",
            "target_id": row["memory_id"],
            "version_id": None,
            "content_sha256": row["content_sha256"],
        }
        for row in connection.execute(
            """
            SELECT m.memory_id, m.content_sha256
            FROM memory_record m
            JOIN citation c ON c.citation_id = m.source_citation_id AND c.workspace_id = m.workspace_id
            JOIN file_acl a ON a.file_record_id = c.file_record_id
                 AND a.workspace_id = c.workspace_id
                 AND a.principal_id = m.principal_id AND a.can_read = 1
            WHERE m.workspace_id = ? AND m.principal_id = ? AND m.status = 'active'
            """,
            (workspace_id, principal_id),
        )
    ]
    sources.extend(
        {
            "contract": "pdx_local_memory_record_v2",
            "target_id": row["memory_id"],
            "version_id": None,
            "content_sha256": row["content_sha256"],
        }
        for row in connection.execute(
            """
            SELECT m.memory_id, m.content_sha256
            FROM memory_record_v2 m
            JOIN memory_source_binding b ON b.source_binding_id = m.source_binding_id
                 AND b.memory_id = m.memory_id AND b.workspace_id = m.workspace_id
                 AND b.principal_id = m.principal_id
            WHERE m.workspace_id = ? AND m.principal_id = ? AND m.status = 'active'
              AND ((b.provenance_category = 'document_grounded'
                    AND EXISTS (
                      SELECT 1 FROM memory_source_binding_citation x
                      WHERE x.source_binding_id = b.source_binding_id)
                    AND NOT EXISTS (
                      SELECT 1 FROM memory_source_binding_citation x
                      LEFT JOIN citation c ON c.citation_id = x.citation_id
                           AND c.workspace_id = b.workspace_id
                      LEFT JOIN file_acl a ON a.file_record_id = c.file_record_id
                           AND a.workspace_id = c.workspace_id
                           AND a.principal_id = b.principal_id AND a.can_read = 1
                      WHERE x.source_binding_id = b.source_binding_id
                        AND (c.citation_id IS NULL OR a.file_record_id IS NULL)))
                   OR (b.provenance_category IN ('user_stated', 'model_proposed')
                       AND NOT EXISTS (
                         SELECT 1 FROM memory_source_binding_citation x
                         WHERE x.source_binding_id = b.source_binding_id)))
            """,
            (workspace_id, principal_id),
        )
    )
    return sources


def _authorized_l3(
    connection: sqlite3.Connection, workspace_id: str, principal_id: str
) -> list[dict[str, Any]]:
    return [
        {
            "contract": "pdx_local_canonical_knowledge_version_v1",
            "target_id": row["canonical_knowledge_id"],
            "version_id": row["version_id"],
            "content_sha256": row["content_sha256"],
        }
        for row in connection.execute(
            """
            SELECT k.canonical_knowledge_id, v.version_id, v.content_sha256
            FROM canonical_knowledge k
            JOIN canonical_knowledge_version v ON v.version_id = k.current_version_id
                 AND v.canonical_knowledge_id = k.canonical_knowledge_id
            WHERE k.workspace_id = ? AND k.status = 'active'
              AND EXISTS (
                SELECT 1 FROM canonical_knowledge_version_citation x
                WHERE x.version_id = v.version_id)
              AND NOT EXISTS (
                SELECT 1 FROM canonical_knowledge_version_citation x
                LEFT JOIN citation c ON c.citation_id = x.citation_id
                     AND c.workspace_id = k.workspace_id
                LEFT JOIN file_acl a ON a.file_record_id = c.file_record_id
                     AND a.workspace_id = c.workspace_id
                     AND a.principal_id = ? AND a.can_read = 1
                WHERE x.version_id = v.version_id
                  AND (c.citation_id IS NULL OR a.file_record_id IS NULL))
            """,
            (workspace_id, principal_id),
        )
    ]
