from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from scripts.ci_delivery_probe import verify_package
from scripts.export_public_root import folded_identity, inventory
from scripts.package_distribution import main as package_main


def package(tmp_path: Path, extra: str | None = None) -> Path:
    path = tmp_path / "candidate.zip"
    payload = b"sample"
    manifest = {"files_count": 1, "files": {"bin/test.txt": {
        "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}}
    with zipfile.ZipFile(path, "x") as out:
        out.writestr("candidate/bin/test.txt", payload)
        out.writestr("candidate/RELEASE_MANIFEST.json", json.dumps(manifest))
        if extra:
            out.writestr(extra, "unexpected")
    return path


def test_package_digest_and_manifest(tmp_path):
    path = package(tmp_path)
    root = verify_package(path, hashlib.sha256(path.read_bytes()).hexdigest(), tmp_path / "extract")
    assert (root / "bin/test.txt").read_bytes() == b"sample"


def test_bad_digest_rejected(tmp_path):
    path = package(tmp_path)
    with pytest.raises(ValueError, match="SHA-256"):
        verify_package(path, "0" * 64, tmp_path / "extract")


@pytest.mark.parametrize("extra", ["candidate/unlisted.txt", "../outside.txt"])
def test_extra_or_traversal_rejected(tmp_path, extra):
    path = package(tmp_path, extra)
    with pytest.raises(ValueError):
        verify_package(path, hashlib.sha256(path.read_bytes()).hexdigest(), tmp_path / "extract")


def test_public_inventory_closed():
    paths, errors = inventory()
    assert not errors, errors
    assert ".github/workflows/ci.yml" in paths


def test_export_rejects_private_paths(tmp_path):
    (tmp_path / "public-export.allowlist").write_text("dist/private.zip\n", encoding="utf-8")
    _, errors = inventory(tmp_path)
    assert any("Forbidden" in error for error in errors)


def test_packager_rejects_path_like_batch_before_writes(tmp_path):
    with pytest.raises(SystemExit):
        package_main(["--batch", "../../outside", "--output-dir", str(tmp_path)])
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("variant", ["SampleHandle123", "SAMPLE_HANDLE", "sample.handle",
                                    "s a m p l e h a n d l e", "ｓａｍｐｌｅｈａｎｄｌｅ", "sample\u200bhandle"])
def test_private_alias_variations_rejected(tmp_path, variant):
    (tmp_path / "public-export.allowlist").write_text("public.txt\n", encoding="utf-8")
    (tmp_path / "public.txt").write_text(variant, encoding="utf-8")
    private = tmp_path / "private.json"
    private.write_text(json.dumps({"aliases": ["samplehandle"]}), encoding="utf-8")
    _, errors = inventory(tmp_path, private)
    assert any("Private account identity" in error for error in errors)
    assert "samplehandle" in folded_identity(variant)
