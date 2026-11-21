"""Explicit allowlist export, without Git operations; audit before copying.

Creates only a NEW independent directory. Reparse points, private path classes,
credentials and developer-specific paths are rejected. No source files edited.
An audit mode performs no writes. Export compares every byte and rejects extras.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
DENIED = {".git", ".venv", "__pycache__", "dist", "build", "private", ".tmp", "superseded"}
PATTERNS = {
    "developer_path": re.compile(r"(?:[A-Z]:[\\/]ProDocuX[\\/]|[A-Z]:[\\/]Users[\\/](?!<|\.\.\.|example))", re.I),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
}


def folded_identity(text: str) -> str:
    """Case/width fold, ignoring separators and invisible formatting characters."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return "".join(c for c in text if c.isalnum())


def inventory(root: Path = ROOT, denylist: Path | None = None) -> tuple[list[str], list[str]]:
    paths = [line.strip() for line in (root / "public-export.allowlist").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    errors = []
    private_list = denylist or root / ".tmp/private-export-denylist.json"
    identities = []
    if denylist is not None or private_list.exists():
        data = json.loads(private_list.read_text(encoding="utf-8-sig"))
        identities = [folded_identity(value) for value in data["aliases"]]
        if not identities or any(len(value) < 4 for value in identities):
            raise ValueError("Invalid private identity denylist")
    if len(paths) != len(set(paths)):
        errors.append("Duplicate allowlist entries")
    for name in paths:
        rel = PurePosixPath(name)
        source = root / name
        if rel.is_absolute() or ".." in rel.parts or "\\" in name or any(p in DENIED for p in rel.parts):
            errors.append(f"Forbidden export path: {name}")
            continue
        if name.startswith("docs/evidence/") or name.endswith((".db", ".sqlite", ".pyc", ".log")):
            errors.append(f"Private evidence/state: {name}")
            continue
        chain = [source, *source.parents]
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in chain):
            errors.append(f"Reparse path: {name}")
            continue
        if not source.is_file() or not source.resolve().is_relative_to(root.resolve()):
            errors.append(f"Missing/non-file: {name}")
            continue
        try:
            text = source.read_text(encoding="utf-8-sig")
        except UnicodeError:
            errors.append(f"Non-text export requires explicit review: {name}")
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{label}: {name}")
        if identities and any(value in folded_identity(text) or value in folded_identity(name)
                              for value in identities):
            errors.append(f"Private account identity: {name}")
    listed = set(paths)
    # Fail on omitted product modules: no stale partial public product tree.
    for source in (root / "src/pdx_local_ai").rglob("*.py"):
        if "__pycache__" not in source.parts:
            name = source.relative_to(root).as_posix()
            if name not in listed:
                errors.append(f"Product module omitted: {name}")
    for name in paths:
        if name.endswith(".py") and (root / name).is_file():
            try:
                ast.parse((root / name).read_text(encoding="utf-8-sig"))
            except SyntaxError:
                errors.append(f"Python syntax error: {name}")
    for folder in ("sql", "schemas"):
        for source in (root / folder).rglob("*"):
            if source.is_file() and source.suffix in {".sql", ".json"}:
                if source.relative_to(root).as_posix() not in listed:
                    errors.append(f"Runtime resource omitted: {source.relative_to(root).as_posix()}")
    return paths, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--destination", type=Path)
    mode.add_argument("--verify-root", type=Path)
    parser.add_argument("--report", type=Path, help="Exclusive new report outside public root")
    parser.add_argument("--denylist", type=Path, help="Private local account aliases; never exported")
    args = parser.parse_args()
    if args.denylist and args.denylist.resolve().is_relative_to(ROOT):
        rel = args.denylist.resolve().relative_to(ROOT).as_posix()
        if rel in (ROOT / "public-export.allowlist").read_text(encoding="utf-8").splitlines():
            raise ValueError("Private denylist cannot be allowlisted")
    paths, errors = inventory(denylist=args.denylist)
    if errors:
        print(json.dumps({"passed": False, "errors": errors}, indent=2))
        return 1
    digests = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths}
    if args.destination or args.verify_root:
        target = (args.destination or args.verify_root).resolve()
        if target.is_relative_to(ROOT) or ROOT.is_relative_to(target):
            raise ValueError("Public root must be separate from incubator")
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in [target, *target.parents]):
            raise ValueError("Public root cannot traverse reparse points")
        if args.destination:
            target.mkdir(parents=True, exist_ok=False)
            for name in paths:
                dest = target / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dest)
        for name in paths:
            if hashlib.sha256((target / name).read_bytes()).hexdigest() != digests[name]:
                raise RuntimeError(f"Byte mismatch: {name}")
        actual = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
        if actual != set(paths):
            raise RuntimeError("Public tree has extra or missing files")
    report = {"passed": True, "files_count": len(paths), "sha256": digests}
    if args.report:
        report_path = args.report.resolve()
        if (args.destination or args.verify_root) and report_path.is_relative_to(target):
            raise ValueError("Report must be outside public root")
        with report_path.open("x", encoding="utf-8") as out:
            json.dump(report, out, indent=2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
