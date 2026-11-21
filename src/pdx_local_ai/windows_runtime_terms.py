"""Windows frozen-delivery policy only; not an ACL or anti-tampering boundary."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

TERMS_VERSION = '2026-10-14.3'
PRODUCT_VERSION = '0.0.1'
TERMS_FILE = 'WINDOWS-RUNTIME-TERMS.txt'
RECORD_FILE = 'windows-runtime-acceptance.json'


class RuntimeTermsError(ValueError):
    pass


def applies() -> bool:
    return sys.platform == 'win32' and bool(getattr(sys, 'frozen', False))


def terms_path() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS) / 'windows-runtime' / TERMS_FILE
    return Path(__file__).resolve().parents[2] / TERMS_FILE


def terms_info(path: Path | None = None) -> tuple[str, str]:
    data = (path or terms_path()).read_bytes()
    text = data.decode('utf-8')
    if f'Terms version: {TERMS_VERSION}' not in text:
        raise RuntimeTermsError('Missing or incompatible Windows runtime terms version')
    return text, hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def acceptance_valid(directory: Path, terms_sha256: str, version: str) -> bool:
    try:
        record = json.loads((directory / RECORD_FILE).read_text(encoding='utf-8'))
        return (record.get('schema_version') == 'pdx_windows_runtime_acceptance_v1'
                and record.get('accepted') is True
                and record.get('terms_version') == TERMS_VERSION
                and record.get('terms_sha256') == terms_sha256
                and record.get('product_version') == version
                and record.get('binary_sha256') == file_digest(directory / 'pdx-local.exe'))
    except (OSError, ValueError, TypeError):
        return False


def write_acceptance(directory: Path, terms_sha256: str, version: str, method: str) -> None:
    if acceptance_valid(directory, terms_sha256, version):
        return
    record = {'schema_version': 'pdx_windows_runtime_acceptance_v1',
              'accepted': True, 'terms_version': TERMS_VERSION,
              'terms_sha256': terms_sha256, 'product_version': version,
              'binary_sha256': file_digest(directory / 'pdx-local.exe'),
              'accepted_at': datetime.now(timezone.utc).isoformat(),
              'method': method}
    # Never silently replace an existing, invalid acceptance record.
    with (directory / RECORD_FILE).open('x', encoding='utf-8') as out:
        json.dump(record, out, indent=2)
        out.write('\n')


def require_acceptance() -> None:
    if not applies():
        return
    _, digest = terms_info()
    directory = Path(sys.executable).resolve().parent
    # Version comes from the installation manifest, if present; portable builds
    # use the product build version. Upgrades are also bound to the EXE digest.
    version = PRODUCT_VERSION
    manifest = directory / 'install-manifest.json'
    if manifest.exists():
        version = json.loads(manifest.read_text(encoding='utf-8'))['version']
    if not acceptance_valid(directory, digest, version):
        raise RuntimeTermsError('Windows runtime terms not accepted for this binary. '
                                'Read: pdx-local terms show; then explicitly run '
                                f'pdx-local terms accept --terms-sha256 {digest}')


def accept_portable(expected_digest: str, accepted: bool) -> None:
    if not applies():
        raise RuntimeTermsError('Acceptance applies only to the frozen Windows distribution')
    _, digest = terms_info()
    if not accepted or expected_digest != digest:
        raise RuntimeTermsError('Explicit acceptance and the displayed terms SHA-256 are required')
    directory = Path(sys.executable).resolve().parent
    version = PRODUCT_VERSION
    manifest = directory / 'install-manifest.json'
    if manifest.exists():
        version = json.loads(manifest.read_text(encoding='utf-8'))['version']
    write_acceptance(directory, digest, version, 'explicit_terms_command')
