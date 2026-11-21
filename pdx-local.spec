# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

packages = [
    'pdx_local_ai',
    'pdx_adapter_prodocux',
    'pdx_artifact_core',
    'pdx_artifact_engine',
    'prodocux_kernel',
    'prodocux',
    'jsonschema',
]

hiddenimports = []
datas = []

for pkg in packages:
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass
    try:
        datas += collect_data_files(pkg)
    except Exception:
        pass

def collect_dir(src_dir, target_prefix):
    res = []
    p = Path(src_dir)
    for f in p.rglob('*'):
        if f.is_file():
            rel = f.relative_to(p).parent
            target_dir = os.path.join(target_prefix, str(rel)) if str(rel) != '.' else target_prefix
            res.append((str(f), target_dir))
    return res

datas += collect_dir('sql', 'sql')
datas += collect_dir('schemas', 'schemas')
datas += [('WINDOWS-RUNTIME-TERMS.txt', 'windows-runtime')]
datas += [('THIRD-PARTY-NOTICES.txt', 'windows-runtime')]
datas += [('docs/WINDOWS_RUNTIME_MAINTENANCE.md', 'windows-runtime')]

def collect_dir_no_dev(src_dir, target_prefix):
    """Like collect_dir but excludes developer-only files (.py, .md).
    This prevents developer scripts (e.g. validate_receipt_activation.py)
    and documentation from being bundled, while preserving runtime JSON data.
    """
    res = []
    p = Path(src_dir)
    _dev_suffixes = {'.py', '.md'}
    for f in p.rglob('*'):
        if f.is_file() and f.suffix.lower() not in _dev_suffixes:
            rel = f.relative_to(p).parent
            target_dir = os.path.join(target_prefix, str(rel)) if str(rel) != '.' else target_prefix
            res.append((str(f), target_dir))
    return res

datas += [('docs/proposals/gate4c3/lexical-first-policy-v1.json', 'docs/proposals/gate4c3')]

a = Analysis(
    ['src/pdx_local_ai/cli/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='pdx-local',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='pdx-local',
)
