"""Package distribution script for ProDocuX Local AI Windows x64.

Builds a self-contained distribution zip containing:
- bin/ (contents of dist/pdx-local, stripped of developer-only metadata)
- install.ps1
- uninstall.ps1
- THIRD-PARTY-NOTICES.txt          (required; abort if missing)
- RELEASE_MANIFEST.json
- SHA-256 integrity checksum file  (<package-name>.sha256)

Usage
-----
    python scripts/package_distribution.py [--batch LABEL]

    --batch LABEL   Suffix appended to the ZIP name, e.g. "batch7" produces
                    pdx-local-ai-windows-x64-v0.0.1-batch7.zip
                    If omitted the ZIP is named without a batch suffix.

Atomicity and batch immutability
---------------------------------
Named batches (--batch) are **immutable**: once a batch artifact (.zip or
.sha256) exists it cannot be overwritten or replaced.  The script enforces
this with two complementary layers:

1. A per-batch lock file (<package>-<batch>.lock) created exclusively
   (O_CREAT|O_EXCL) before any work begins.  A concurrent process that
   loses the race sees FileExistsError and exits immediately without
   touching any artifact.

2. The ZIP is opened with mode "x" (exclusive create) and the .sha256
   sidecar with open(..., "x").  Even if the lock layer is somehow
   bypassed, the OS-level exclusive create prevents silent overwrite.

The staging directory is per-batch (dist/<pkg>-<batch>/) so concurrent
named builds cannot corrupt each other's staging areas.

Unnamed builds (no --batch) are mutable staging artifacts: no lock is
used and existing files are overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import zipfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_DIST = _ROOT / "dist"
_BIN_SRC = _DIST / "pdx-local"

# Files matched against the relative-to-bin-src path (forward slashes, lower-case)
# that must NOT appear in the distribution package.
_EXCLUDED_RELATIVE: set[str] = {
    # pip direct_url records dev-machine wheel install paths.
    "direct_url.json",
    # Acceptance belongs to the recipient, never the build machine.
    "windows-runtime-acceptance.json",
}

# Directory names excluded in their entirety (any path component, lower-case).
_EXCLUDED_DIR_COMPONENTS: set[str] = {
    "__pycache__",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _should_exclude(rel_path: str) -> bool:
    """Return True if *rel_path* should be excluded from the package."""
    parts = rel_path.replace("\\", "/").lower().split("/")
    if any(p in _EXCLUDED_DIR_COMPONENTS for p in parts):
        return True
    if parts[-1] in _EXCLUDED_RELATIVE:
        return True
    return False


def main(argv: list[str] | None = None) -> int:  # noqa: C901 – intentionally linear
    parser = argparse.ArgumentParser(description="Build pdx-local-ai distribution ZIP")
    parser.add_argument(
        "--batch",
        metavar="LABEL",
        default="",
        help='Batch label, e.g. "batch7" → pdx-local-ai-...-batch7.zip',
    )
    parser.add_argument("--binary-dir", type=Path, default=_BIN_SRC,
                        help="Explicit onedir build to package")
    parser.add_argument("--output-dir", type=Path, default=_DIST,
                        help="Output directory (must already exist)")
    args = parser.parse_args(argv)
    if args.batch and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.batch):
        parser.error("Batch must be a simple alphanumeric/hyphen/underscore label")
    bin_source = args.binary_dir.resolve()
    output_dir = args.output_dir.resolve()
    if not output_dir.is_dir():
        parser.error("Output directory must already exist")

    batch_suffix = f"-{args.batch}" if args.batch else ""
    version = "0.0.1"
    package_name = f"pdx-local-ai-windows-x64-v{version}"

    zip_path = output_dir / f"{package_name}{batch_suffix}.zip"
    sha256_path = output_dir / f"{package_name}{batch_suffix}.sha256"
    lock_path = output_dir / f"{package_name}{batch_suffix}.lock"

    # Named batches use per-batch staging; unnamed use the shared staging dir.
    stage_dir = output_dir / (f"{package_name}{batch_suffix}" if args.batch else package_name)

    # ── Pre-flight checks (before acquiring any lock) ────────────────────────
    if not (bin_source / "pdx-local.exe").exists():
        print(
            f"[ERROR] Binary not found at {bin_source / 'pdx-local.exe'}. "
            "Run PyInstaller build first.",
            file=sys.stderr,
        )
        return 1

    notices_src = _ROOT / "THIRD-PARTY-NOTICES.txt"
    terms_src = _ROOT / 'WINDOWS-RUNTIME-TERMS.txt'
    policy_src = _ROOT / 'docs' / 'WINDOWS_RUNTIME_MAINTENANCE.md'
    bundled_terms = bin_source / '_internal' / 'windows-runtime' / 'WINDOWS-RUNTIME-TERMS.txt'
    if not terms_src.is_file() or not policy_src.is_file() or not bundled_terms.is_file():
        print('[ERROR] Windows runtime terms/policy missing; rebuild the binary first.', file=sys.stderr)
        return 1
    if _sha256(terms_src) != _sha256(bundled_terms):
        print('[ERROR] Bundled and root Windows runtime terms differ.', file=sys.stderr)
        return 1
    bundled_notices = bundled_terms.parent / 'THIRD-PARTY-NOTICES.txt'
    if not notices_src.is_file() or not bundled_notices.is_file() or _sha256(notices_src) != _sha256(bundled_notices):
        print('[ERROR] Bundled and root third-party notices missing or different.', file=sys.stderr)
        return 1
    if not notices_src.exists():
        print(
            f"[ERROR] THIRD-PARTY-NOTICES.txt not found at {notices_src}. "
            "Generate it before packaging.",
            file=sys.stderr,
        )
        return 1

    # Fast pre-flight collision check (non-atomic; the lock below is the real guard).
    if args.batch and (zip_path.exists() or sha256_path.exists()):
        existing_sha = _sha256(zip_path) if zip_path.exists() else "(zip not present)"
        print(
            f"[ERROR] Batch artifact already exists: {zip_path}\n"
            f"        Existing ZIP SHA-256 : {existing_sha}\n"
            f"        Refusing to overwrite.  Choose a new --batch label.",
            file=sys.stderr,
        )
        return 1

    # ── Acquire exclusive batch lock (named batches only) ────────────────────
    lock_fd = None
    if args.batch:
        try:
            # open(..., "x") maps to O_CREAT|O_EXCL — atomic on POSIX and Windows NTFS.
            lock_fd = open(lock_path, "x", encoding="utf-8")  # noqa: WPS515
            lock_fd.write(
                f"pid={os.getpid()}\n"
                f"batch={args.batch}\n"
                f"started={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            )
            lock_fd.flush()
        except FileExistsError:
            try:
                lock_info = lock_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                lock_info = "(unreadable)"
            print(
                f"[ERROR] Build lock already held for batch '{args.batch}': {lock_path}\n"
                f"        Lock contents:\n"
                + "\n".join(f"          {l}" for l in lock_info.splitlines())
                + "\n        If this is a stale lock from a crashed build, "
                "delete the .lock file manually.",
                file=sys.stderr,
            )
            return 1

    try:
        # ── 1. Prepare staging directory ─────────────────────────────────────
        if stage_dir.is_symlink() or (hasattr(stage_dir, "is_junction") and stage_dir.is_junction()):
            raise ValueError("Staging directory cannot be a reparse point")
        if not stage_dir.resolve().is_relative_to(output_dir):
            raise ValueError("Staging directory escapes output directory")
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)

        # ── 2. Copy bin/ (excluding policy-filtered files) ───────────────────
        bin_dest = stage_dir / "bin"
        bin_dest.mkdir()
        excluded_count = 0
        for item in bin_source.rglob("*"):
            if not item.is_file():
                continue
            rel = str(item.relative_to(bin_source)).replace("\\", "/")
            if _should_exclude(rel):
                excluded_count += 1
                continue
            dest = bin_dest / item.relative_to(bin_source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest)
        print(f"[INFO] Copied bin/ ({excluded_count} files excluded by policy)")

        # ── 3. Copy installer scripts ─────────────────────────────────────────
        shutil.copy2(_ROOT / "scripts" / "install.ps1", stage_dir / "install.ps1")
        shutil.copy2(_ROOT / "scripts" / "uninstall.ps1", stage_dir / "uninstall.ps1")

        # ── 4. Copy THIRD-PARTY-NOTICES.txt ──────────────────────────────────
        shutil.copy2(notices_src, stage_dir / "THIRD-PARTY-NOTICES.txt")
        shutil.copy2(terms_src, stage_dir / 'WINDOWS-RUNTIME-TERMS.txt')
        shutil.copy2(policy_src, stage_dir / 'WINDOWS_RUNTIME_MAINTENANCE.md')

        # ── 5. Compute file manifest ──────────────────────────────────────────
        file_manifest: dict[str, dict[str, str | int]] = {}
        for item in stage_dir.rglob("*"):
            if item.is_file():
                rel = str(item.relative_to(stage_dir)).replace("\\", "/")
                file_manifest[rel] = {
                    "size_bytes": item.stat().st_size,
                    "sha256": _sha256(item),
                }

        pkg_manifest = {
            "schema_version": "pdx_local_release_manifest_v1",
            "product": "pdx-local-ai",
            "version": version,
            "batch": args.batch or None,
            "platform": "windows-x64",
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "entry_point": "bin/pdx-local.exe",
            "files_count": len(file_manifest),
            "files": file_manifest,
        }
        manifest_path = stage_dir / "RELEASE_MANIFEST.json"
        manifest_path.write_text(json.dumps(pkg_manifest, indent=2), encoding="utf-8")

        # ── 6. Create ZIP archive (exclusive for named batches) ───────────────
        zip_mode = "x" if args.batch else "w"
        try:
            with zipfile.ZipFile(zip_path, zip_mode, zipfile.ZIP_DEFLATED) as zf:
                for item in stage_dir.rglob("*"):
                    if item.is_file():
                        arcname = (
                            f"{package_name}/"
                            + str(item.relative_to(stage_dir)).replace("\\", "/")
                        )
                        zf.write(item, arcname)
        except FileExistsError:
            print(
                f"[ERROR] ZIP appeared between pre-flight check and creation: {zip_path}\n"
                "        Another concurrent build may have completed first.",
                file=sys.stderr,
            )
            return 1

        # ── 7. Write .sha256 sidecar (exclusive for named batches) ────────────
        zip_sha = _sha256(zip_path)
        zip_size = zip_path.stat().st_size
        sha256_open_mode = "x" if args.batch else "w"
        try:
            with open(sha256_path, sha256_open_mode, encoding="utf-8") as fh:
                fh.write(f"sha256: {zip_sha}\n")
        except FileExistsError:
            print(
                f"[ERROR] SHA-256 sidecar appeared between pre-flight and creation: {sha256_path}",
                file=sys.stderr,
            )
            zip_path.unlink(missing_ok=True)
            return 1

        print("[SUCCESS] Distribution package created:")
        print(f"  Archive  : {zip_path}")
        print(f"  SHA-256  : {zip_sha}")
        print(f"  Checksum : {sha256_path}")
        print(f"  Size     : {zip_size:,} bytes ({round(zip_size / 1024 / 1024, 2)} MB)")
        print(f"  Files    : {len(file_manifest)}")
        if args.batch:
            print(f"  Batch    : {args.batch}")
        return 0

    finally:
        # Always release the lock (even on failure paths).
        if lock_fd is not None:
            lock_fd.close()
            lock_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
