"""Process identity verification and safe termination engine for ProDocuX Local AI.

Security contracts:
1. Exact full-path executable match required (never match by basename or partial name).
2. Both expected_exe AND expected_create_time are mandatory.
3. OpenProcess NULL result is examined with GetLastError to distinguish:
     ERROR_INVALID_PARAMETER (87) = PID does not exist → GONE
     ERROR_ACCESS_DENIED      (5) = process exists but inaccessible → UNKNOWN
     other error codes            = UNKNOWN
4. Process termination is confirmed via GetExitCodeProcess (STILL_ACTIVE = 259 test),
   not by relying on QueryFullProcessImageNameW error codes.
5. check_process_identity() returns a 4-state CheckIdentityResult instead of bool,
   so callers can distinguish MATCHED / UNMATCHED / GONE / UNKNOWN explicitly.
   UNKNOWN must never be silently treated as GONE.
6. Force-kill path re-verifies identity immediately before /F to prevent
   terminating a recycled PID.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from enum import Enum, auto
import os
from pathlib import Path
import subprocess
import sys
import time


# ── Windows error codes ──────────────────────────────────────────────────────
_ERROR_INVALID_PARAMETER = 87   # PID does not exist on this system
_ERROR_ACCESS_DENIED     = 5    # Process exists but cannot be opened
_STILL_ACTIVE            = 259  # GetExitCodeProcess: process is still running


# Sentinel returned by get_process_info() when the query itself failed
# (access denied, handle limit, etc.) — distinct from "process not running" (None, None).
_QUERY_FAILED = "__query_failed__"


class CheckIdentityResult(Enum):
    """4-state result of check_process_identity().

    Callers must handle every state:
    MATCHED   — PID exe + create_time both match the session record.
    UNMATCHED — PID is alive but exe or create_time differs (recycled PID).
    GONE      — PID is no longer running.
    UNKNOWN   — Cannot determine identity (access denied, query error, etc.).
                Must be treated conservatively — never delete sessions, never
                assume the process is gone.
    """
    MATCHED   = auto()
    UNMATCHED = auto()
    GONE      = auto()
    UNKNOWN   = auto()


def _is_process_alive_win32(handle: int) -> bool | None:
    """Return True if handle is a running process, False if exited, None if uncertain.

    Uses GetExitCodeProcess which works with PROCESS_QUERY_LIMITED_INFORMATION.
    Returns None when the API call itself fails.
    """
    kernel32 = ctypes.windll.kernel32
    exit_code = wintypes.DWORD(0)
    if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        return exit_code.value == _STILL_ACTIVE
    return None  # GetExitCodeProcess itself failed


def get_process_info(pid: int) -> tuple[str | None, float | None]:
    """Return (exe_path, create_epoch) for a running PID.

    Returns:
    - (exe_path, create_ts)  : process is alive, info retrieved.
    - (None, None)           : process is definitively not running.
    - (_QUERY_FAILED, None)  : process may be alive but identity cannot be queried
                               (access denied, or API call failed for other reason).

    Callers MUST use is_query_failed() to distinguish the third case.

    Windows OpenProcess NULL:
    - ERROR_INVALID_PARAMETER (87) = PID does not exist → (None, None)
    - ERROR_ACCESS_DENIED     (5)  = process exists, no rights → (_QUERY_FAILED, None)
    - other errors                 = (_QUERY_FAILED, None)

    Windows QueryFullProcessImageNameW failure after successful OpenProcess:
    - GetExitCodeProcess is used to confirm whether the process has exited.
    - If confirmed exited  → (None, None)
    - If still running     → (_QUERY_FAILED, None)
    - If confirmation fails → (_QUERY_FAILED, None)
    """
    if pid <= 0:
        return None, None
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        ctypes.windll.kernel32.SetLastError(0)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = ctypes.GetLastError()
            if err == _ERROR_INVALID_PARAMETER:
                return None, None          # PID genuinely gone
            # ERROR_ACCESS_DENIED (5) or any other code → UNKNOWN
            return _QUERY_FAILED, None     # type: ignore[return-value]

        try:
            # ── Step 1: confirm process is still alive before querying name ──
            alive = _is_process_alive_win32(handle)
            if alive is False:
                return None, None    # GetExitCodeProcess confirmed exit
            # alive is True or None — proceed with QueryFullProcessImageNameW

            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                # Name query failed — re-check alive state to decide
                alive2 = _is_process_alive_win32(handle)
                if alive2 is False:
                    return None, None   # Exited between our two checks
                return _QUERY_FAILED, None  # type: ignore[return-value]

            exe_path: str = buf.value

            ft_create = wintypes.FILETIME()
            ft_exit   = wintypes.FILETIME()
            ft_kernel = wintypes.FILETIME()
            ft_user   = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(ft_create),
                ctypes.byref(ft_exit),
                ctypes.byref(ft_kernel),
                ctypes.byref(ft_user),
            ):
                # GetProcessTimes failed — check alive state
                alive3 = _is_process_alive_win32(handle)
                if alive3 is False:
                    return None, None
                return _QUERY_FAILED, None  # type: ignore[return-value]

            val = (ft_create.dwHighDateTime << 32) + ft_create.dwLowDateTime
            # Windows FILETIME epoch (1601-01-01) → Unix epoch (1970-01-01)
            create_ts = (val - 116_444_736_000_000_000) / 10_000_000.0
            return exe_path, create_ts

        finally:
            kernel32.CloseHandle(handle)

    else:
        # POSIX fallback (Linux/macOS)
        try:
            proc_p = Path(f"/proc/{pid}")
            if not proc_p.exists():
                return None, None
            exe_path = str(proc_p.joinpath("exe").resolve())
            create_ts = proc_p.stat().st_ctime
            return exe_path, create_ts
        except PermissionError:
            return _QUERY_FAILED, None  # type: ignore[return-value]
        except Exception:
            return _QUERY_FAILED, None  # type: ignore[return-value]


def is_query_failed(exe: str | None) -> bool:
    """Return True when get_process_info() indicated a query failure (uncertain state)."""
    return exe == _QUERY_FAILED


def check_process_identity(
    pid: int,
    expected_exe: str,
    expected_create_time: float,
    tolerance_sec: float = 2.5,
) -> CheckIdentityResult:
    """4-state identity check for a running PID against session-record credentials.

    Returns:
    - MATCHED   : process is alive, exe path and creation time both match.
    - UNMATCHED : process is alive, but exe or creation time does NOT match
                  (PID has been recycled by a different process).
    - GONE      : process is no longer running.
    - UNKNOWN   : identity cannot be determined (query failed, access denied, etc.).
                  Callers MUST treat this as blocking — never delete sessions
                  or assume the process is gone.
    """
    if pid <= 0:
        return CheckIdentityResult.GONE

    actual_exe, actual_create_time = get_process_info(pid)

    if is_query_failed(actual_exe):
        return CheckIdentityResult.UNKNOWN

    if actual_exe is None:
        return CheckIdentityResult.GONE

    # Full path comparison (case-insensitive on Windows)
    try:
        norm_actual   = str(Path(actual_exe).resolve()).lower()
        norm_expected = str(Path(expected_exe).resolve()).lower()
    except Exception:
        norm_actual   = actual_exe.lower()
        norm_expected = expected_exe.lower()

    if norm_actual != norm_expected:
        return CheckIdentityResult.UNMATCHED

    # Creation time check
    if actual_create_time is None:
        return CheckIdentityResult.UNKNOWN

    if abs(actual_create_time - expected_create_time) > tolerance_sec:
        return CheckIdentityResult.UNMATCHED

    return CheckIdentityResult.MATCHED


def verify_process_identity(
    pid: int,
    expected_exe: str,
    expected_create_time: float,
    tolerance_sec: float = 2.5,
) -> bool:
    """Convenience wrapper: return True only for CheckIdentityResult.MATCHED.

    Prefer check_process_identity() when callers need to distinguish all 4 states.
    """
    return check_process_identity(
        pid, expected_exe, expected_create_time, tolerance_sec
    ) == CheckIdentityResult.MATCHED


def terminate_process(
    pid: int,
    expected_exe: str,
    expected_create_time: float,
    timeout_sec: float = 5.0,
) -> bool:
    """Terminate a verified process gracefully, then force-kill if needed.

    Returns True only when the process is confirmed gone.
    Returns False if:
    - Identity check is not MATCHED before first signal.
    - Process query returns UNKNOWN at any point in the termination flow.
    - Force-kill identity re-check is not MATCHED (PID may have been recycled).
    - Process is still alive after the full timeout + force kill.

    Alive confirmation after each step uses GetExitCodeProcess, not
    QueryFullProcessImageNameW, to avoid false UNKNOWN from handle-still-open races.
    """
    result = check_process_identity(pid, expected_exe, expected_create_time)
    if result != CheckIdentityResult.MATCHED:
        # GONE → nothing to do (caller treats as success? no — return False,
        # caller can inspect session; but GONE == already stopped is benign)
        if result == CheckIdentityResult.GONE:
            return True   # Nothing to terminate — already gone
        return False      # UNMATCHED or UNKNOWN → do not proceed

    # Safety: never terminate the current installer process itself
    if pid == os.getpid():
        return False

    if sys.platform == "win32":
        # Graceful signal
        try:
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True, timeout=2.0)
        except Exception:
            pass

        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            r = check_process_identity(pid, expected_exe, expected_create_time)
            if r == CheckIdentityResult.GONE:
                return True
            if r == CheckIdentityResult.UNKNOWN:
                return False   # Cannot confirm — abort
            if r == CheckIdentityResult.UNMATCHED:
                # PID recycled after our signal; original process is gone
                return True
            time.sleep(0.1)

        # Graceful timeout: re-verify before force kill
        r2 = check_process_identity(pid, expected_exe, expected_create_time)
        if r2 == CheckIdentityResult.GONE:
            return True
        if r2 != CheckIdentityResult.MATCHED:
            # UNMATCHED → original process is gone (PID recycled)
            # UNKNOWN   → cannot safely force-kill
            return r2 == CheckIdentityResult.UNMATCHED

        # Still matched — safe to force-kill
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=2.0)
        except Exception:
            pass

        # Confirm with GetExitCodeProcess via check_process_identity
        confirm_deadline = time.monotonic() + 1.0
        while time.monotonic() < confirm_deadline:
            r3 = check_process_identity(pid, expected_exe, expected_create_time)
            if r3 == CheckIdentityResult.GONE:
                return True
            if r3 == CheckIdentityResult.UNMATCHED:
                return True   # PID recycled after /F; original process is gone
            if r3 == CheckIdentityResult.UNKNOWN:
                return False
            time.sleep(0.05)

        return False   # Still MATCHED (alive) after 1 s

    else:
        import signal as _signal

        try:
            os.kill(pid, _signal.SIGTERM)
        except OSError:
            pass

        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            r = check_process_identity(pid, expected_exe, expected_create_time)
            if r == CheckIdentityResult.GONE:
                return True
            if r == CheckIdentityResult.UNKNOWN:
                return False
            if r == CheckIdentityResult.UNMATCHED:
                return True
            time.sleep(0.1)

        r2 = check_process_identity(pid, expected_exe, expected_create_time)
        if r2 == CheckIdentityResult.GONE:
            return True
        if r2 != CheckIdentityResult.MATCHED:
            return r2 == CheckIdentityResult.UNMATCHED

        try:
            os.kill(pid, _signal.SIGKILL)
        except OSError:
            pass

        confirm_deadline = time.monotonic() + 1.0
        while time.monotonic() < confirm_deadline:
            r3 = check_process_identity(pid, expected_exe, expected_create_time)
            if r3 == CheckIdentityResult.GONE:
                return True
            if r3 == CheckIdentityResult.UNMATCHED:
                return True
            if r3 == CheckIdentityResult.UNKNOWN:
                return False
            time.sleep(0.05)

        return False
