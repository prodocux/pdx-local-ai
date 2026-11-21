from pathlib import Path

from pdx_local_ai.versions import (
    ENGINE_VERSION,
    ENGINE_WHEEL,
    ENGINE_WHEEL_SHA256,
    KERNEL_VERSION,
    KERNEL_WHEEL,
    KERNEL_WHEEL_SHA256,
)

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("0.3.0rc10", "0.3.0a11", "0.3.0rc12")


def test_runtime_modules_have_one_version_authority() -> None:
    offenders = []
    for path in (ROOT / "src" / "pdx_local_ai").rglob("*.py"):
        if path.name == "versions.py":
            continue
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in FORBIDDEN):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
    authority = (ROOT / "src" / "pdx_local_ai" / "versions.py").read_text(encoding="utf-8")
    assert KERNEL_VERSION in authority and ENGINE_VERSION in authority


def test_install_metadata_matches_the_published_wheels() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    lock = (ROOT / "requirements-ci.lock").read_text(encoding="utf-8")
    manifest = (ROOT / "docs" / "lock" / "pypi-distributions.json").read_text(encoding="utf-8")
    assert f"prodocux=={KERNEL_VERSION}" in pyproject
    assert f"pdx-artifact-engine=={ENGINE_VERSION}" in pyproject
    assert f"prodocux=={KERNEL_VERSION}" in requirements
    assert f"pdx-artifact-engine=={ENGINE_VERSION}" in requirements
    assert f"rfc8785==0.1.4" in requirements
    assert f"prodocux=={KERNEL_VERSION} --hash=sha256:{KERNEL_WHEEL_SHA256}" in lock
    assert f"pdx-artifact-engine=={ENGINE_VERSION} --hash=sha256:{ENGINE_WHEEL_SHA256}" in lock
    assert "rfc8785==0.1.4 --hash=sha256:520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48" in lock
    assert KERNEL_WHEEL in manifest and ENGINE_WHEEL in manifest
    assert KERNEL_WHEEL_SHA256 in manifest and ENGINE_WHEEL_SHA256 in manifest


def test_elevation_plan_is_not_public() -> None:
    allowlist = (ROOT / "public-export.allowlist").read_text(encoding="utf-8").splitlines()
    assert "docs/KERNEL_RC13_ENGINE_A13_PRODUCT_ELEVATION_PLAN.md" not in allowlist
    for line in allowlist:
        assert "D:/" not in line and "D:\\" not in line
