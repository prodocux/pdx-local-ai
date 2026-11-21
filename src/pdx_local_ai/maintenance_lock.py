from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import sys
import time
from pathlib import Path
from typing import Any

# Windows file locking constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_ALWAYS = 4
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None


class CrossProcessMaintenanceLock:
    """True cross-process exclusive lock using OS-level file handle reservation.

    On Windows, uses CreateFileW with share_mode=0 (exclusive lock).
    Any other process attempting to acquire will fail immediately or wait.
    Process crash automatically releases the kernel file handle.
    """

    def __init__(self, lock_file_path: str | Path) -> None:
        self.lock_path = Path(lock_file_path).resolve()
        self.handle: Any = None
        self._fd: int | None = None

    def acquire(self, timeout_sec: float = 5.0) -> bool:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        start_t = time.monotonic()
        while time.monotonic() - start_t < timeout_sec:
            if sys.platform == "win32":
                handle = kernel32.CreateFileW(
                    str(self.lock_path),
                    GENERIC_READ | GENERIC_WRITE,
                    0,  # 0 = Exclusive: No other process can read or write!
                    None,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
                if handle != INVALID_HANDLE_VALUE:
                    self.handle = handle
                    # Write locking process info
                    info = f"pid={os.getpid()};started={time.time()}\n".encode("utf-8")
                    written = wintypes.DWORD()
                    kernel32.WriteFile(handle, info, len(info), ctypes.byref(written), None)
                    kernel32.FlushFileBuffers(handle)
                    return True
            else:
                import fcntl
                try:
                    fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._fd = fd
                    return True
                except (BlockingIOError, OSError):
                    pass
            time.sleep(0.05)
        return False

    def release(self) -> None:
        if sys.platform == "win32" and self.handle and self.handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(self.handle)
            self.handle = None
            try:
                self.lock_path.unlink(missing_ok=True)
            except Exception:
                pass
        elif self._fd is not None:
            import fcntl
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
            try:
                self.lock_path.unlink(missing_ok=True)
            except Exception:
                pass

    @staticmethod
    def is_locked(lock_file_path: str | Path) -> bool:
        """Non-blocking check if a maintenance lock is actively held by another process."""
        path = Path(lock_file_path).resolve()
        if not path.exists():
            return False
        if sys.platform == "win32":
            handle = kernel32.CreateFileW(
                str(path),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                3,  # OPEN_EXISTING
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle == INVALID_HANDLE_VALUE:
                err = kernel32.GetLastError()
                if err == 32:  # ERROR_SHARING_VIOLATION
                    return True
                return False
            kernel32.CloseHandle(handle)
            return False
        else:
            import fcntl
            try:
                fd = os.open(path, os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    return False
                except (BlockingIOError, OSError):
                    return True
                finally:
                    os.close(fd)
            except OSError:
                return False

    def __enter__(self) -> CrossProcessMaintenanceLock:
        if not self.acquire():
            raise RuntimeError(f"Failed to acquire maintenance lock on {self.lock_path}")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
