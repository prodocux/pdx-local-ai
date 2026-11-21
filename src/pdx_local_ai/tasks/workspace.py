"""Bounded task workspace. Agents never choose paths; hosts derive them from validated ids."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import uuid
from pathlib import Path

from .contracts import LIMITS, TaskError, utf8_len, validate_candidate_name

_ID_RE = re.compile(r"^[0-9a-f\-]{36}$")


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & flag) or stat.S_ISLNK(info.st_mode)


class TaskWorkspace:
    """``<profile>/tasks/<task_id>/<attempt_id>/candidate/<name>`` only."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if _is_reparse_or_symlink(self.root):
            raise TaskError("ARTIFACT_REJECTED", "workspace root is a reparse point or symlink")
        self._real_root = self.root.resolve()

    def _dir(self, task_id: str, attempt_id: str) -> Path:
        if not _ID_RE.match(task_id) or not _ID_RE.match(attempt_id):
            raise TaskError("ARTIFACT_REJECTED", "invalid workspace identifier")
        target = self.root / task_id / attempt_id / "candidate"
        return target

    def _ensure_dir(self, target: Path) -> Path:
        # Create level by level, refusing to traverse any reparse point.
        current = self.root
        for part in target.relative_to(self.root).parts:
            current = current / part
            if _is_reparse_or_symlink(current):
                raise TaskError("ARTIFACT_REJECTED", "workspace path contains a reparse point")
            current.mkdir(exist_ok=True)
        real = target.resolve()
        try:
            real.relative_to(self._real_root)
        except ValueError as exc:
            raise TaskError("ARTIFACT_REJECTED", "workspace path escapes the workspace root") from exc
        return target

    def write_candidate(self, task_id: str, attempt_id: str, name: str, content: str,
                        *, used_bytes: int) -> tuple[str, str, int]:
        name = validate_candidate_name(name)
        data = content.encode("utf-8")
        if used_bytes + len(data) > LIMITS["candidate_output_bytes"]:
            raise TaskError("TASK_QUOTA_EXCEEDED", "candidate output quota exceeded",
                            {"limit_bytes": LIMITS["candidate_output_bytes"]})
        if utf8_len(content) != len(data):  # pragma: no cover - defensive
            raise TaskError("ARTIFACT_REJECTED", "encoding mismatch")
        target_dir = self._ensure_dir(self._dir(task_id, attempt_id))
        target = target_dir / name
        sha = hashlib.sha256(data).hexdigest()
        if target.exists() or _is_reparse_or_symlink(target):
            if _is_reparse_or_symlink(target) or not target.is_file() or os.lstat(target).st_nlink > 1:
                raise TaskError("ARTIFACT_REJECTED", "existing candidate path is not a plain file")
            if hashlib.sha256(target.read_bytes()).hexdigest() == sha:
                return f"{task_id}/{attempt_id}/candidate/{name}", sha, len(data)  # idempotent replay
            raise TaskError("ARTIFACT_REJECTED", "candidate artifacts are immutable per attempt")
        tmp = target_dir / f".tmp-{uuid.uuid4().hex}"
        try:
            with open(tmp, "xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return f"{task_id}/{attempt_id}/candidate/{name}", sha, len(data)

    def read_candidate(self, rel_path: str, expected_sha: str) -> bytes:
        parts = Path(rel_path).parts
        if len(parts) != 4 or parts[2] != "candidate" or not _ID_RE.match(parts[0]) \
                or not _ID_RE.match(parts[1]):
            raise TaskError("ARTIFACT_REJECTED", "invalid artifact path")
        path = self.root.joinpath(*parts)
        if _is_reparse_or_symlink(path) or not path.is_file():
            raise TaskError("ARTIFACT_REJECTED", "artifact missing or unsafe")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sha:
            raise TaskError("ARTIFACT_REJECTED", "artifact digest mismatch")
        return data

    def remove_task(self, task_id: str) -> None:
        if not _ID_RE.match(task_id):
            return
        target = self.root / task_id
        if not target.exists():
            return
        for p in [target, *target.rglob("*")]:
            if _is_reparse_or_symlink(p):
                raise TaskError("ARTIFACT_REJECTED", "refusing to delete workspace with reparse point")
        shutil.rmtree(target, ignore_errors=True)

    def list_orphans(self, known_task_ids: set[str]) -> list[str]:
        return sorted(p.name for p in self.root.iterdir()
                      if p.is_dir() and _ID_RE.match(p.name) and p.name not in known_task_ids)
