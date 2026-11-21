"""The P0 consumer manifest is recomputed from the tree and the installed wheel."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import prodocux_kernel

from pdx_local_ai.catalog import SUPPORTED
from pdx_local_ai.versions import (
    ENGINE_VERSION,
    ENGINE_WHEEL,
    ENGINE_WHEEL_BYTES,
    ENGINE_WHEEL_SHA256,
    KERNEL_VERSION,
    KERNEL_WHEEL,
    KERNEL_WHEEL_BYTES,
    KERNEL_WHEEL_SHA256,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "lock" / "pypi-distributions.json"
UPSTREAM_PREFIXES = ("prodocux_kernel", "pdx_artifact", "pdx_adapter", "api")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _imports(root: Path) -> list[dict[str, object]]:
    found: dict[str, set[str]] = {}
    for path in sorted((root / "src" / "pdx_local_ai").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(UPSTREAM_PREFIXES):
                found.setdefault(node.module, set()).update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(UPSTREAM_PREFIXES):
                        found.setdefault(alias.name, set())
    return [{"module": module, "names": sorted(names)} for module, names in sorted(found.items())]


REQUIRED_ARCHIVE_PROFILES = {
    "zip-store-deflate",
    "zip64-store-deflate",
    "tar-ustar-pax-gnu",
    "gzip-single-member",
    "bzip2-single-stream",
    "xz-single-stream",
    "tar-gzip",
    "tar-bzip2",
    "tar-xz",
    "nested-qualified-profiles",
    "document-leaf-handoff",
}


def _archive_wired(root: Path) -> bool:
    catalog = (root / "src" / "pdx_local_ai" / "catalog.py").read_text(encoding="utf-8")
    return "consume_opted_in_archives" in catalog


def build_manifest(root: Path = ROOT) -> dict:
    targets = json.loads(
        (Path(prodocux_kernel.__file__).parent / "schemas" / "archive_profile_targets.json").read_text(encoding="utf-8")
    )
    schemas = {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted((root / "schemas").glob("*.schema.json"))
    }
    policy = Path("docs/proposals/gate4c3/lexical-first-policy-v1.json")
    lock = (root / "requirements-ci.lock").read_text(encoding="utf-8")
    rfc_line = next(line for line in lock.splitlines() if line.startswith("rfc8785=="))
    return {
        "recorded_at": "2026-11-18",
        "index": "https://pypi.org/simple",
        "stage": "p4",
        "distributions": [
            {
                "project": "prodocux",
                "version": KERNEL_VERSION,
                "filename": KERNEL_WHEEL,
                "project_release_url": f"https://pypi.org/project/prodocux/{KERNEL_VERSION}/#files",
                "sha256": KERNEL_WHEEL_SHA256,
                "size_bytes": KERNEL_WHEEL_BYTES,
            },
            {
                "project": "pdx-artifact-engine",
                "version": ENGINE_VERSION,
                "filename": ENGINE_WHEEL,
                "project_release_url": f"https://pypi.org/project/pdx-artifact-engine/{ENGINE_VERSION}/#files",
                "sha256": ENGINE_WHEEL_SHA256,
                "size_bytes": ENGINE_WHEEL_BYTES,
            },
        ],
        "locked_dependencies": [{"requirement": rfc_line}],
        "imports": _imports(root),
        "endpoints": {
            "kernel_http_archive": "not_used",
            "in_process_imports": _imports(root),
        },
        "profiles": {
            "default_catalog_scan": sorted(SUPPORTED),
            "archive_adoption": "source_root_opt_in" if _archive_wired(root) else "present_unwired",
            "installed_archive_profiles": [
                {
                    "profile_id": row["profile_id"],
                    "release_target": row["release_target"],
                    "adopted": row["profile_id"] in REQUIRED_ARCHIVE_PROFILES,
                }
                for row in targets
            ],
        },
        "schema_digests": schemas,
        "policy_sha256": _sha256(root / policy),
        "note": (
            "P4 consumer surface. Wheel filename, size, and hash come from the published "
            "distributions named in versions.py. Catalog scan adopts .docx and .pdf by default. "
            "Archive profiles are adopted only after a source root sets archive_enabled. "
            "source_replay.resolve returns {quote, verifier_source}. "
            "Local candidate seals stay on ArtifactRuntime. External sends use one "
            "external operation per subject and do not claim exactly-once delivery. "
            "Vector escalation keeps the lexical insufficiency on the stage receipt and "
            "the policy outcome on the terminal receipt. Rerank and document expansion "
            "stay unauthorized. This file does not authorize public export."
        ),
    }


def test_consumer_manifest_matches_the_tree_and_installed_wheel() -> None:
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert recorded == build_manifest()
    assert recorded["profiles"]["archive_adoption"] == "source_root_opt_in"
    assert recorded["profiles"]["default_catalog_scan"] == [".docx", ".pdf"]
    assert recorded["endpoints"]["kernel_http_archive"] == "not_used"
    adopted = {item["profile_id"] for item in recorded["profiles"]["installed_archive_profiles"] if item["adopted"]}
    assert adopted == REQUIRED_ARCHIVE_PROFILES
