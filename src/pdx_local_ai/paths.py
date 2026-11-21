"""Path resolution helpers supporting both source checkout and PyInstaller frozen bundle."""

from __future__ import annotations

import sys
from pathlib import Path


def get_root() -> Path:
    """Return root directory containing sql/ and schemas/."""
    packaged = Path(__file__).resolve().parent / "resources"
    if (packaged / "sql/001_gate0.sql").is_file():
        return packaged
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            meipass = Path(sys._MEIPASS)
            if (meipass / "sql" / "001_gate0.sql").is_file():
                return meipass
        exe_dir = Path(sys.executable).parent
        if (exe_dir / "sql" / "001_gate0.sql").is_file():
            return exe_dir
        if (exe_dir / "_internal" / "sql" / "001_gate0.sql").is_file():
            return exe_dir / "_internal"

    curr = Path(__file__).resolve()
    for parent in (curr, *curr.parents):
        if (parent / "sql" / "001_gate0.sql").is_file():
            return parent
        if (parent / "_internal" / "sql" / "001_gate0.sql").is_file():
            return parent / "_internal"
    return curr.parents[2] if len(curr.parents) > 2 else curr.parent
