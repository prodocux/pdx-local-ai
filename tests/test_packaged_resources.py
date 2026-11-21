import hashlib
from pathlib import Path

from pdx_local_ai.paths import get_root

ROOT = Path(__file__).resolve().parents[1]
PACKAGED = ROOT / "src" / "pdx_local_ai" / "resources"


def _pairs(relative: str):
    source = ROOT / relative
    copy = PACKAGED / relative
    left = {path.relative_to(source).as_posix(): path for path in source.rglob("*") if path.is_file()}
    right = {path.relative_to(copy).as_posix(): path for path in copy.rglob("*") if path.is_file()}
    assert left.keys() == right.keys()
    for name in left:
        assert hashlib.sha256(left[name].read_bytes()).digest() == hashlib.sha256(right[name].read_bytes()).digest()


def test_packaged_sql_schemas_and_policy_match_the_checkout() -> None:
    _pairs("sql")
    _pairs("schemas")
    policy = Path("docs/proposals/gate4c3/lexical-first-policy-v1.json")
    assert (PACKAGED / policy).read_bytes() == (ROOT / policy).read_bytes()
    assert get_root() == PACKAGED
    assert (get_root() / policy).is_file()
