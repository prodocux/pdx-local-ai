from __future__ import annotations

import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from pdx_local_ai import windows_runtime_terms as terms
from pdx_local_ai.installer import Installer
from scripts.package_distribution import _should_exclude, main as package_main


def test_terms_readable_with_hash():
    text, digest = terms.terms_info()
    assert len(digest) == 64
    assert 'Microsoft Distributable Code' in text
    assert 'They do not apply to Linux or macOS distributions' in text
    assert 'Terms version: 2026-10-14.3' in text


def test_install_denied_before_target_or_profile_created(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'pdx-local.exe').write_bytes(b'fixture')
    target, profile = tmp_path/'install', tmp_path/'profile'
    with patch.object(sys, 'platform', 'win32'):
        ok, reason = Installer(target,profile).install(source)
    assert not ok and 'explicit acceptance' in reason
    assert not target.exists() and not profile.exists()


def test_old_terms_acceptance_requires_reacceptance(tmp_path):
    (tmp_path/'pdx-local.exe').write_bytes(b'fixture')
    digest = terms.terms_info()[1]
    terms.write_acceptance(tmp_path, digest, '0.0.1', 'test_explicit_consent')
    path = tmp_path/terms.RECORD_FILE
    record = json.loads(path.read_text())
    record['terms_version'] = '2026-10-14.1'
    path.write_text(json.dumps(record), encoding='utf-8')
    before = path.read_bytes()
    assert not terms.acceptance_valid(tmp_path, digest, '0.0.1')
    with pytest.raises(FileExistsError):
        terms.write_acceptance(tmp_path, digest, '0.0.1', 'test_explicit_consent')
    assert path.read_bytes() == before


def test_install_missing_terms_refuses_even_with_flag(tmp_path):
    source=tmp_path/'source'
    source.mkdir()
    (source/'pdx-local.exe').write_bytes(b'fixture')
    with patch.object(sys,'platform','win32'):
        ok, reason=Installer(tmp_path/'target',tmp_path/'profile').install(source,accept_windows_runtime_terms=True)
    assert not ok and 'unavailable' in reason
    assert not (tmp_path/'target').exists() and not (tmp_path/'profile').exists()


def test_acceptance_is_exclusive_bound_and_has_no_identity(tmp_path):
    (tmp_path/'pdx-local.exe').write_bytes(b'fixture')
    digest=terms.terms_info()[1]
    terms.write_acceptance(tmp_path,digest,'0.0.1','test_explicit_consent')
    first=(tmp_path/terms.RECORD_FILE).read_bytes()
    terms.write_acceptance(tmp_path,digest,'0.0.1','test_explicit_consent')
    assert (tmp_path/terms.RECORD_FILE).read_bytes()==first
    record=json.loads(first)
    assert 'accepted_at' in record and not {'principal_id','ip','machine','username'} & record.keys()
    assert terms.acceptance_valid(tmp_path,digest,'0.0.1')
    assert not terms.acceptance_valid(tmp_path,'0'*64,'0.0.1')
    assert not terms.acceptance_valid(tmp_path,digest,'0.0.2')
    (tmp_path/'pdx-local.exe').write_bytes(b'different')
    assert not terms.acceptance_valid(tmp_path,digest,'0.0.1')
    with pytest.raises(FileExistsError):
        terms.write_acceptance(tmp_path,digest,'0.0.1','test_explicit_consent')
    assert (tmp_path/terms.RECORD_FILE).read_bytes()==first


@pytest.mark.parametrize('platform',['linux','darwin'])
def test_non_windows_platforms_are_not_gated(platform):
    with patch.object(sys,'platform',platform),patch.object(sys,'frozen',True,create=True),patch.object(terms,'terms_info',side_effect=AssertionError('not needed')):
        terms.require_acceptance()


def test_portable_explicit_acceptance_and_sha_required(tmp_path):
    (tmp_path/'pdx-local.exe').write_bytes(b'fixture')
    digest=terms.terms_info()[1]
    with patch.object(terms,'applies',return_value=True),patch.object(sys,'executable',str(tmp_path/'pdx-local.exe')):
        with pytest.raises(terms.RuntimeTermsError):
            terms.accept_portable(digest,False)
        with pytest.raises(terms.RuntimeTermsError):
            terms.accept_portable('0'*64,True)
        assert not (tmp_path/terms.RECORD_FILE).exists()
        terms.accept_portable(digest,True)
        terms.require_acceptance()


def test_missing_terms_and_corrupt_record_fail_closed(tmp_path):
    with pytest.raises(OSError):
        terms.terms_info(tmp_path/'missing.txt')
    (tmp_path/terms.RECORD_FILE).write_text('{invalid')
    assert not terms.acceptance_valid(tmp_path,'0'*64,'0.0.1')


def test_packager_excludes_builder_acceptance_record():
    assert _should_exclude('windows-runtime-acceptance.json')
    assert _should_exclude('nested/windows-runtime-acceptance.json')


def test_packager_requires_rebuilt_terms_before_output(tmp_path):
    source=tmp_path/'binary'
    source.mkdir()
    (source/'pdx-local.exe').write_bytes(b'fixture')
    output=tmp_path/'output'
    output.mkdir()
    assert package_main(['--binary-dir',str(source),'--output-dir',str(output),'--batch','terms-negative'])==1
    assert not list(output.iterdir())
