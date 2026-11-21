"""Run package acceptance with explicit artifact identity and fail on skips."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import re
import zipfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--accept-windows-runtime-terms', action='store_true',
                        help='Explicit consent for isolated Windows test fixtures only')
    args = parser.parse_args()
    if not os.environ.get("PDX_DELIVERY_ZIP") or not os.environ.get("PDX_DELIVERY_SHA256"):
        raise RuntimeError("Explicit delivery ZIP and SHA-256 required")
    binary_dir = Path(os.environ.get('PDX_DELIVERY_BINARY_DIR', 'dist/pdx-local'))
    binary = binary_dir / 'pdx-local.exe'
    if not binary.is_file():
        raise RuntimeError("Exact extracted package binary required")
    package = Path(os.environ['PDX_DELIVERY_ZIP'])
    if hashlib.sha256(package.read_bytes()).hexdigest() != os.environ['PDX_DELIVERY_SHA256'].lower():
        raise RuntimeError('Delivery ZIP SHA mismatch')
    with zipfile.ZipFile(package) as archive:
        names = [n for n in archive.namelist() if n.endswith('/bin/pdx-local.exe')]
        if len(names) != 1 or archive.read(names[0]) != binary.read_bytes():
            raise RuntimeError('Acceptance executable does not match the exact ZIP')
    if sys.platform == 'win32':
        if not args.accept_windows_runtime_terms:
            raise RuntimeError('Explicit Windows runtime terms acceptance required for test fixtures')
        shown = subprocess.run([str(binary), 'terms', 'show'], capture_output=True, text=True,
                               encoding='utf-8', timeout=30, check=True)
        digest = re.search(r'SHA-256: ([0-9a-f]{64})', shown.stdout)
        if not digest:
            raise RuntimeError('Runtime terms SHA not displayed')
        subprocess.run([str(binary), 'terms', 'accept', '--accept-windows-runtime-terms',
                        '--terms-sha256', digest[1]], timeout=30, check=True)
    result = subprocess.run([sys.executable, "-m", "pytest", "tests/test_delivery_and_maintenance.py",
                             "-v", "--tb=short", "--junitxml=delivery-results.xml"], timeout=600)
    if result.returncode:
        return result.returncode
    suites = ET.parse("delivery-results.xml").getroot()
    cases = list(suites.iter("testcase"))
    if len(cases) < 15 or any(case.find("skipped") is not None for case in cases):
        raise RuntimeError("Incomplete acceptance coverage or skipped package test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
