"""Safe entry and extension routing for Gate 5A-0 slice 2.

The caller supplies a source-root id and a relative path. The canonical
root, workspace, enabled flag, and denylist relaxation come from the
source_root row. Lexical denylist, reparse, short-name expansion, and
extension routing all happen before a content handle is opened.

Only a text-allowlist file gets an immutable spool. That spool is the
controlled byte snapshot: later decode reads it, not the original path.
``.csv`` is classified for the existing Kernel intake and is not opened
here. Unsupported paths are not opened or hashed. A denial writes only
``secret_denylist_audit``.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .validation import ContractError, validate_source_root_path

ALLOWLIST_ID = "pdx_local_text_allowlist_v1"
PROJECTION_BYTE_BUDGET = 1_048_576
_STREAM_CHUNK = 64 * 1024
TEXT_EXTENSIONS = frozenset({
    "txt", "md", "markdown", "rst",
    "py", "js", "ts", "tsx", "jsx", "java", "cs", "go", "rs", "cpp", "c", "h",
    "ps1", "sh", "bat", "cmd",
    "yaml", "yml", "toml", "ini", "cfg",
    "log", "tsv",
})
FILENAME_RULES = (
    ("filename:.env", lambda name: name == ".env"),
    ("filename:.env.*", lambda name: name.startswith(".env.") and len(name) > 5),
    ("filename:.pem", lambda name: name == ".pem"),
    ("filename:.key", lambda name: name == ".key"),
    ("filename:.p12", lambda name: name == ".p12"),
    ("filename:.pfx", lambda name: name == ".pfx"),
    ("filename:id_rsa", lambda name: name == "id_rsa"),
    ("filename:id_dsa", lambda name: name == "id_dsa"),
    ("filename:id_ecdsa", lambda name: name == "id_ecdsa"),
    ("filename:id_ed25519", lambda name: name == "id_ed25519"),
    ("filename:credentials.json", lambda name: name == "credentials.json"),
    ("filename:secrets.json", lambda name: name == "secrets.json"),
)
COMPONENT_RULES = {
    ".ssh": "component:.ssh",
    ".aws": "component:.aws",
    ".gnupg": "component:.gnupg",
    "secrets": "component:secrets",
}
CONTAINMENT_RULES = frozenset({
    "path_normalization_failed",
    "device_path",
    "unc_path",
    "alternate_data_stream",
    "reparse_point",
    "short_name_unresolved",
    "path_escaped_root",
})
_SHORT_COMPONENT = re.compile(r"^[^\\/:*?\"<>|]{1,6}~\d+(\.[^\\/:*?\"<>|]{1,3})?$", re.IGNORECASE)
_DOS_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_ATTRIBUTES = 0x80
_FILE_SHARE_NONE = 0
_FILE_SHARE_ALL = 0x00000007
_OPEN_EXISTING = 3
_CREATE_NEW = 1
_FILE_BEGIN = 0
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_READONLY = 0x1
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _FileTime(ctypes.Structure):
    _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))


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


class _FindData(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FileTime),
        ("ftLastAccessTime", _FileTime),
        ("ftLastWriteTime", _FileTime),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", wintypes.WCHAR * 260),
        ("cAlternateFileName", wintypes.WCHAR * 14),
    )


@dataclass(frozen=True)
class _Policy:
    relaxed_rule_ids: frozenset[str]


class ControlledSnapshot:
    """Immutable spool of the bytes read from one source handle."""

    def __init__(
        self,
        *,
        relative_path: str,
        final_path: str,
        spool_path: str,
        size: int,
        mtime_ns: int,
        volume_serial: str,
        file_index: str,
        spool_volume_serial: str,
        spool_file_index: str,
        spool_mtime_ns: int,
        source_sha256: str,
        kernel32: ctypes.WinDLL,
        handle: int,
    ) -> None:
        self.relative_path = relative_path
        self.final_path = final_path
        self.spool_path = spool_path
        self.size = size
        self.mtime_ns = mtime_ns
        self.volume_serial = volume_serial
        self.file_index = file_index
        self.spool_volume_serial = spool_volume_serial
        self.spool_file_index = spool_file_index
        self.spool_mtime_ns = spool_mtime_ns
        self.source_sha256 = source_sha256
        self._kernel32 = kernel32
        self._handle = handle
        self._closed = False

    def read_prefix(self, limit: int) -> bytes:
        """Read at most one projection budget from the spool, not the source path."""
        return self.read_at(0, limit)

    def read_at(self, offset: int, limit: int) -> bytes:
        """Read a bounded slice. ``limit`` cannot exceed the projection budget."""
        if self._closed:
            raise ContractError("controlled snapshot is closed")
        if not isinstance(offset, int) or offset < 0:
            raise ContractError("snapshot read exceeds projection budget")
        if not isinstance(limit, int) or limit < 0 or limit > PROJECTION_BYTE_BUDGET:
            raise ContractError("snapshot read exceeds projection budget")
        if limit == 0:
            return b""
        payload = bytearray()
        for chunk in self.iter_chunks(offset=offset, limit=limit):
            payload.extend(chunk)
        return bytes(payload)

    def iter_chunks(self, *, offset: int = 0, limit: int, chunk_size: int = _STREAM_CHUNK) -> Iterator[bytes]:
        """Stream the spool in bounded chunks. This does not open the source path."""
        if self._closed:
            raise ContractError("controlled snapshot is closed")
        if (
            not isinstance(offset, int) or offset < 0
            or not isinstance(limit, int) or limit < 0 or limit > PROJECTION_BYTE_BUDGET
            or not isinstance(chunk_size, int) or chunk_size <= 0 or chunk_size > PROJECTION_BYTE_BUDGET
        ):
            raise ContractError("snapshot read exceeds projection budget")
        if self._handle is None:
            raise ContractError("controlled snapshot is closed")
        info = _handle_info(self._kernel32, self._handle)
        identity = f"{info.nFileIndexHigh}:{info.nFileIndexLow}"
        if (
            str(info.dwVolumeSerialNumber) != self.spool_volume_serial
            or identity != self.spool_file_index
            or _size_of(info) != self.size
            or _mtime_ns(info) != self.spool_mtime_ns
        ):
            raise ContractError("controlled snapshot spool is not intact")
        remaining = limit
        _seek(self._kernel32, self._handle, offset)
        while remaining:
            block = ctypes.create_string_buffer(min(chunk_size, remaining))
            got = _read_file(self._kernel32, self._handle, block)
            if got is None:
                raise ContractError("controlled snapshot spool is not intact")
            if not got:
                break
            remaining -= len(got)
            yield got

    def cleanup(self) -> None:
        """Close the held spool handle, then delete the file."""
        if self._closed:
            return
        self._closed = True
        handle = self._handle
        self._handle = None
        if handle:
            self._kernel32.CloseHandle(handle)
        _discard_spool(self.spool_path)


@dataclass(frozen=True)
class TextRouteResult:
    disposition: str
    route: str | None
    owner: str | None
    allowlist: str | None
    matched_rule_id: str | None
    audit_id: str | None
    relative_path: str | None
    snapshot: ControlledSnapshot | None


@contextmanager
def prepare_text_route(
    conn: sqlite3.Connection,
    *,
    source_root_id: str,
    relative_path: str,
    **caller_overrides: object,
) -> Iterator[TextRouteResult]:
    """Route one relative path. Extra keywords are caller overrides and fail."""
    if caller_overrides:
        raise ContractError("caller cannot override denylist authority")
    root = _load_root(conn, source_root_id)
    snapshot: ControlledSnapshot | None = None
    try:
        result, snapshot = _prepare(conn, root, relative_path)
        yield result
    finally:
        if snapshot is not None:
            snapshot.cleanup()


def final_extension(relative_path: str) -> str:
    """Final extension using the same trailing-dot and trailing-space rule as 011."""
    name = _strip_tail(relative_path.replace("/", "\\").rsplit("\\", 1)[-1])
    dot = name.rfind(".")
    if dot <= 0:
        return ""
    return name[dot + 1:].casefold()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _strip_tail(name: str) -> str:
    while name.endswith((" ", ".")):
        name = name[:-1]
    return name


def _reject_unrelaxable(rule_ids: frozenset[str]) -> None:
    for rule_id in rule_ids:
        if rule_id in CONTAINMENT_RULES or not (
            rule_id.startswith("filename:") or rule_id.startswith("component:")
        ):
            raise ContractError("control plane cannot relax path containment")


def _root_row(conn: sqlite3.Connection, source_root_id: str) -> sqlite3.Row:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM source_root WHERE source_root_id=?",
        (source_root_id,),
    ).fetchone()
    if row is None:
        raise ContractError("enabled source root not found")
    return row


def _load_root(conn: sqlite3.Connection, source_root_id: str) -> dict[str, object]:
    row = _root_row(conn, source_root_id)
    if int(row["enabled"]) != 1:
        raise ContractError("source root is disabled")
    stored = str(row["canonical_path"])
    validate_source_root_path(stored)
    canonical, volume_serial, file_index = _root_authority(stored)
    config = json.loads(row["config_json"])
    relaxed = frozenset(str(item) for item in config.get("denylist_relaxed_rule_ids", []))
    _reject_unrelaxable(relaxed)
    return {
        "source_root_id": str(row["source_root_id"]),
        "workspace_id": str(row["workspace_id"]),
        "canonical_path": canonical,
        "volume_serial": volume_serial,
        "file_index": file_index,
        "policy": _Policy(relaxed),
    }


def _root_authority(stored: str) -> tuple[str, int, str]:
    """Use the configured root directory handle as the containment authority.

    Routing does not reopen operating-system ancestors above this root.
    """
    kernel32 = _kernel32()
    handle = _try_open_info(kernel32, stored)
    if handle is None:
        raise ContractError("source root could not be opened")
    try:
        info = _handle_info(kernel32, handle)
        if not info.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise ContractError("source root canonical path does not match")
        if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ContractError("source root is a reparse point")
        final = _final_from_handle(kernel32, handle)
        if not _local_drive(final):
            raise ContractError("source root canonical path does not match")
        identity = f"{info.nFileIndexHigh}:{info.nFileIndexLow}"
        return final, int(info.dwVolumeSerialNumber), identity
    finally:
        kernel32.CloseHandle(handle)


def _prepare(
    conn: sqlite3.Connection,
    root: dict[str, object],
    relative_path: str,
) -> tuple[TextRouteResult, ControlledSnapshot | None]:
    policy = root["policy"]
    assert isinstance(policy, _Policy)
    workspace_id = str(root["workspace_id"])
    source_root_id = str(root["source_root_id"])
    root_path = Path(str(root["canonical_path"]))
    root_volume = int(root["volume_serial"])
    failure = _normalization_failure(relative_path)
    if failure is not None:
        return _deny(conn, workspace_id, source_root_id, failure, policy), None
    component_failure, components = _components(relative_path)
    if component_failure is not None:
        return _deny(conn, workspace_id, source_root_id, component_failure, policy), None
    lexical_rule = _unrelaxed_rule(components, policy)
    if lexical_rule is not None:
        return _deny(conn, workspace_id, source_root_id, lexical_rule, policy), None
    expanded, expand_failure = _expand(root_path, components, root_volume)
    if expand_failure is not None:
        return _deny(conn, workspace_id, source_root_id, expand_failure, policy), None
    assert expanded is not None
    expanded_rule = _unrelaxed_rule(expanded, policy)
    if expanded_rule is not None:
        return _deny(conn, workspace_id, source_root_id, expanded_rule, policy), None
    relative = "\\".join(expanded)
    extension = final_extension(relative)
    if extension == "csv":
        return TextRouteResult("kernel", "kernel", "prodocux", None, None, None, relative, None), None
    if extension not in TEXT_EXTENSIONS:
        return TextRouteResult("unsupported", "unsupported", None, None, None, None, relative, None), None
    snapshot = _spool_text(root_path.joinpath(*expanded), relative, root_path)
    return (
        TextRouteResult("text", "text", None, ALLOWLIST_ID, None, None, relative, snapshot),
        snapshot,
    )


def _normalization_failure(value: str) -> str | None:
    if not value or "\x00" in value:
        return "path_normalization_failed"
    slashed = value.replace("/", "\\")
    if slashed.startswith("\\\\?\\") or slashed.startswith("\\\\.\\"):
        return "device_path"
    if slashed.startswith("\\\\"):
        return "unc_path"
    if any(char in slashed for char in '*?"<>|'):
        return "path_normalization_failed"
    if re.match(r"^[A-Za-z]:", slashed):
        return "path_normalization_failed"
    if ":" in slashed:
        return "alternate_data_stream"
    return None


def _components(value: str) -> tuple[str | None, list[str]]:
    parts = [_strip_tail(part) for part in value.replace("/", "\\").split("\\")]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return "path_normalization_failed", []
    for part in parts:
        stem = part.split(".", 1)[0].rstrip(" .").upper()
        if stem in _DOS_DEVICES:
            return "device_path", []
    return None, parts


def _expand(
    root: Path, components: list[str], root_volume: int,
) -> tuple[list[str] | None, str | None]:
    kernel32 = _kernel32()
    current = str(root)
    expanded: list[str] = []
    for part in components:
        handle = _try_open_info(kernel32, str(Path(current) / part))
        if handle is None:
            if _SHORT_COMPONENT.match(part):
                return None, "short_name_unresolved"
            raise ContractError("source path is missing")
        try:
            info = _handle_info(kernel32, handle)
            if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                return None, "reparse_point"
            if int(info.dwVolumeSerialNumber) != root_volume:
                return None, "path_escaped_root"
            final = _final_from_handle(kernel32, handle)
            if not _local_drive(final) or not _under(str(root), final):
                return None, "path_escaped_root"
            parent, name = final.rsplit("\\", 1)
            if os.path.normcase(parent) != os.path.normcase(current):
                return None, "path_escaped_root"
            if _SHORT_COMPONENT.match(name):
                found = _find_child(current, part)
                if found is not None and not _SHORT_COMPONENT.match(found[0]):
                    name = found[0]
                else:
                    return None, "short_name_unresolved"
            if name in {"", ".", ".."}:
                return None, "path_normalization_failed"
        finally:
            kernel32.CloseHandle(handle)
        expanded.append(name)
        current = str(Path(parent) / name)
    return expanded, None


def _find_child(directory: str, name: str) -> tuple[str, int] | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.FindFirstFileW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_FindData)]
    kernel32.FindFirstFileW.restype = wintypes.HANDLE
    kernel32.FindClose.argtypes = [wintypes.HANDLE]
    kernel32.FindClose.restype = wintypes.BOOL
    data = _FindData()
    handle = kernel32.FindFirstFileW(os.path.normpath(directory) + "\\" + name, ctypes.byref(data))
    if not handle or handle == _INVALID_HANDLE:
        return None
    try:
        found = str(data.cFileName).split("\x00", 1)[0]
    finally:
        kernel32.FindClose(handle)
    if not found:
        return None
    return found, int(data.dwFileAttributes)


def _matching_rules(components: list[str]) -> list[str]:
    found: list[str] = []
    for part in components:
        rule = COMPONENT_RULES.get(part.casefold())
        if rule is not None and rule not in found:
            found.append(rule)
    name = components[-1].casefold()
    for rule_id, predicate in FILENAME_RULES:
        if predicate(name):
            found.append(rule_id)
    return found


def _unrelaxed_rule(components: list[str], policy: _Policy) -> str | None:
    for rule_id in _matching_rules(components):
        if rule_id not in policy.relaxed_rule_ids:
            return rule_id
    return None


def _deny(
    conn: sqlite3.Connection,
    workspace_id: str,
    source_root_id: str,
    rule_id: str,
    policy: _Policy,
) -> TextRouteResult:
    if rule_id in policy.relaxed_rule_ids:
        raise ContractError("control plane cannot relax path containment")
    audit_id = str(uuid.uuid4())
    owns_transaction = not conn.in_transaction
    if owns_transaction:
        conn.execute("BEGIN")
    try:
        conn.execute(
            "INSERT INTO secret_denylist_audit VALUES (?,?,?,?,?)",
            (audit_id, workspace_id, source_root_id, rule_id, _now()),
        )
        if owns_transaction:
            conn.commit()
    except Exception:
        if owns_transaction and conn.in_transaction:
            conn.rollback()
        raise
    return TextRouteResult("denied", None, None, None, rule_id, audit_id, None, None)


def _spool_text(path: Path, relative_path: str, root: Path) -> ControlledSnapshot:
    kernel32 = _kernel32()
    handle = _open_read(kernel32, str(path), reparse=True)
    spool_path: str | None = None
    spool_handle = None
    try:
        before = _handle_info(kernel32, handle)
        if before.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ContractError("opened handle is a reparse point")
        final_path = _final_handle_path(kernel32, handle, root)
        descriptor, spool_path = tempfile.mkstemp(prefix="pdx-text-snapshot-")
        os.close(descriptor)
        Path(spool_path).unlink()
        spool_handle = kernel32.CreateFileW(
            spool_path, _GENERIC_READ | _GENERIC_WRITE, _FILE_SHARE_NONE, None, _CREATE_NEW, 0x80, None,
        )
        if not spool_handle or spool_handle == _INVALID_HANDLE:
            raise ContractError("controlled snapshot spool could not be created")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = ctypes.create_string_buffer(_STREAM_CHUNK)
            payload = _read_file(kernel32, handle, block)
            if payload is None:
                raise ContractError("source changed while creating controlled byte snapshot")
            if not payload:
                break
            if not _write_file(kernel32, spool_handle, payload):
                raise ContractError("controlled snapshot spool could not be created")
            digest.update(payload)
            size += len(payload)
        after = _handle_info(kernel32, handle)
        if _identity(before) != _identity(after) or _size_of(before) != size or _size_of(after) != size:
            raise ContractError("source changed while creating controlled byte snapshot")
        if _mtime_ns(before) != _mtime_ns(after):
            raise ContractError("source changed while creating controlled byte snapshot")
        if not kernel32.FlushFileBuffers(spool_handle):
            raise ContractError("controlled snapshot spool could not be created")
        spool_info = _handle_info(kernel32, spool_handle)
        _seek(kernel32, spool_handle, 0)
        verified = _hash_handle(kernel32, spool_handle)
        if verified != (digest.hexdigest(), size) or _size_of(spool_info) != size:
            raise ContractError("controlled snapshot spool is not intact")
        os.chmod(spool_path, stat.S_IREAD)
        ctypes.windll.kernel32.SetFileAttributesW(spool_path, _FILE_ATTRIBUTE_READONLY)
        sealed = _handle_info(kernel32, spool_handle)
        if (
            _identity(sealed) != _identity(spool_info)
            or _size_of(sealed) != size
        ):
            raise ContractError("controlled snapshot spool is not intact")
        snapshot = ControlledSnapshot(
            relative_path=relative_path,
            final_path=final_path,
            spool_path=spool_path,
            size=size,
            mtime_ns=_mtime_ns(before),
            volume_serial=str(before.dwVolumeSerialNumber),
            file_index=f"{before.nFileIndexHigh}:{before.nFileIndexLow}",
            spool_volume_serial=str(sealed.dwVolumeSerialNumber),
            spool_file_index=f"{sealed.nFileIndexHigh}:{sealed.nFileIndexLow}",
            spool_mtime_ns=_mtime_ns(sealed),
            source_sha256=digest.hexdigest(),
            kernel32=kernel32,
            handle=spool_handle,
        )
        spool_handle = None
    except Exception:
        if spool_handle and spool_handle != _INVALID_HANDLE:
            kernel32.CloseHandle(spool_handle)
            spool_handle = None
        if spool_path is not None:
            _discard_spool(spool_path)
        raise
    finally:
        kernel32.CloseHandle(handle)
    return snapshot


def _write_file(kernel32: ctypes.WinDLL, handle: int, payload: bytes) -> bool:
    written = wintypes.DWORD()
    buffer = ctypes.create_string_buffer(payload)
    ok = kernel32.WriteFile(handle, buffer, len(payload), ctypes.byref(written), None)
    return bool(ok) and written.value == len(payload)


def _handle_info(kernel32: ctypes.WinDLL, handle: int) -> _ByHandleInfo:
    info = _ByHandleInfo()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info


def _identity(info: _ByHandleInfo) -> tuple[int, int, int]:
    return info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow


def _size_of(info: _ByHandleInfo) -> int:
    return (info.nFileSizeHigh << 32) | info.nFileSizeLow


def _mtime_ns(info: _ByHandleInfo) -> int:
    ticks = (info.ftLastWriteTime.dwHighDateTime << 32) | info.ftLastWriteTime.dwLowDateTime
    return ticks * 100


def _final_handle_path(kernel32: ctypes.WinDLL, handle: int, root: Path) -> str:
    get_final = kernel32.GetFinalPathNameByHandleW
    get_final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final.restype = wintypes.DWORD
    needed = get_final(handle, None, 0, 0)
    if not needed:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = get_final(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    final_name = os.path.normpath(_plain(buffer.value))
    if not _local_drive(final_name) or not _under(str(root), final_name):
        raise ContractError("opened handle escaped source root")
    return final_name


def _plain(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _local_drive(path: str) -> bool:
    plain = os.path.normpath(_plain(path))
    return not plain.startswith("\\\\") and re.match(r"^[A-Za-z]:\\", plain) is not None


def _under(root: str, child: str) -> bool:
    root_key = os.path.normcase(os.path.normpath(root))
    child_key = os.path.normcase(os.path.normpath(child))
    prefix = root_key if root_key.endswith("\\") else root_key + "\\"
    return child_key.startswith(prefix)


def _try_open_info(kernel32: ctypes.WinDLL, path: str) -> int | None:
    handle = kernel32.CreateFileW(
        os.path.normpath(path),
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if not handle or handle == _INVALID_HANDLE:
        return None
    return handle


def _final_from_handle(kernel32: ctypes.WinDLL, handle: int) -> str:
    get_final = kernel32.GetFinalPathNameByHandleW
    buffer = ctypes.create_unicode_buffer(32768)
    written = get_final(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise ContractError("source root canonical path does not match")
    return os.path.normpath(_plain(buffer.value))


def _kernel32() -> ctypes.WinDLL:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleInfo)]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.SetFilePointer.argtypes = [wintypes.HANDLE, wintypes.LONG, ctypes.POINTER(wintypes.LONG), wintypes.DWORD]
    kernel32.SetFilePointer.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    return kernel32


def _open_read(kernel32: ctypes.WinDLL, path: str, *, reparse: bool = False) -> int:
    flags = _FILE_FLAG_OPEN_REPARSE_POINT if reparse else 0
    handle = kernel32.CreateFileW(
        os.path.normpath(path), _GENERIC_READ, _FILE_SHARE_ALL, None, _OPEN_EXISTING, flags, None,
    )
    if not handle or handle == _INVALID_HANDLE:
        raise ContractError("source path could not be opened without following a reparse point")
    return handle


def _read_file(kernel32: ctypes.WinDLL, handle: int, block: ctypes.Array[bytes]) -> bytes | None:
    read = wintypes.DWORD()
    if not kernel32.ReadFile(handle, block, len(block), ctypes.byref(read), None):
        return None
    return block.raw[: read.value]


def _seek(kernel32: ctypes.WinDLL, handle: int, offset: int) -> None:
    high = wintypes.LONG(offset >> 32)
    moved = kernel32.SetFilePointer(handle, offset & 0xFFFFFFFF, ctypes.byref(high), _FILE_BEGIN)
    if moved == 0xFFFFFFFF and ctypes.get_last_error():
        raise ContractError("controlled snapshot spool is not intact")


def _hash_handle(kernel32: ctypes.WinDLL, handle: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        block = ctypes.create_string_buffer(_STREAM_CHUNK)
        payload = _read_file(kernel32, handle, block)
        if payload is None:
            raise ContractError("controlled snapshot spool is not intact")
        if not payload:
            return digest.hexdigest(), size
        digest.update(payload)
        size += len(payload)


def _discard_spool(path: str) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x80)
        Path(path).unlink(missing_ok=True)
    except OSError:
        return
