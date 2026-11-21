"""Frozen Windows EXE refusal/acceptance smoke checks in an isolated copy."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary-dir',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    args=parser.parse_args()
    args.work_dir.mkdir(parents=True,exist_ok=False)
    sandbox=args.work_dir/'portable'
    shutil.copytree(args.binary_dir,sandbox,ignore=shutil.ignore_patterns('windows-runtime-acceptance.json'))
    exe=sandbox/'pdx-local.exe'
    calls=[]
    def run(arguments,label,expected):
        proc=subprocess.run([str(exe),*arguments],capture_output=True,timeout=45)
        for channel in ('stdout','stderr'):
            with (args.work_dir/f'{label}-{channel}.log').open('xb') as out:
                out.write(getattr(proc,channel))
        calls.append({'name':label,'exit_code':proc.returncode,'expected':expected})
        assert proc.returncode==expected, (label,proc.returncode,proc.stderr)
        return proc.stdout.decode('utf-8')
    text=run(['terms','show'],'show',0)
    digest=hashlib.sha256((sandbox/'_internal/windows-runtime/WINDOWS-RUNTIME-TERMS.txt').read_bytes()).hexdigest()
    assert 'SHA-256: '+digest in text
    negative=args.work_dir/'must-not-exist'
    run(['init','--profile-dir',str(negative)],'portable-refusal',1)
    assert not negative.exists()
    install_target=args.work_dir/'install-refused'
    install_profile=args.work_dir/'profile-refused'
    install_args=['installer','install','--source-dist',str(sandbox),'--target-dir',str(install_target),'--profile-dir',str(install_profile)]
    run(install_args,'direct-installer-refusal',1)
    assert not install_target.exists() and not install_profile.exists()
    run(['terms','accept','--terms-sha256',digest],'missing-explicit-consent',1)
    run(['terms','accept','--accept-windows-runtime-terms','--terms-sha256','0'*64],'wrong-terms-sha',1)
    record=sandbox/'windows-runtime-acceptance.json'
    assert not record.exists()
    terms=sandbox/'_internal/windows-runtime/WINDOWS-RUNTIME-TERMS.txt'
    saved=terms.read_bytes()
    terms.unlink()
    run(install_args+['--accept-windows-runtime-terms'],'missing-terms-refusal',1)
    assert not install_target.exists() and not install_profile.exists()
    with terms.open('xb') as out: out.write(saved)
    run(['terms','accept','--accept-windows-runtime-terms','--terms-sha256',digest],'explicit-acceptance',0)
    data=json.loads(record.read_text())
    assert data['accepted'] is True and data['terms_sha256']==digest
    assert data['binary_sha256']==hashlib.sha256(exe.read_bytes()).hexdigest()
    assert not {'principal_id','username','machine','ip'} & data.keys()
    run(['init','--profile-dir',str(args.work_dir/'accepted-profile')],'accepted-init',0)
    # Ordinary record tampering invalidates delivery-policy checks.
    data['terms_sha256']='0'*64
    record.write_text(json.dumps(data),encoding='utf-8')
    run(['init','--profile-dir',str(negative)],'invalid-record-refusal',1)
    assert not negative.exists()
    with (args.work_dir/'summary.json').open('x',encoding='utf-8') as out:
        json.dump({'passed':True,'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'checks':calls,'boundary':'local Windows compiled EXE; not clean-OS RG-1; explicit consent for test fixture only'},out,indent=2)
    print(f'{len(calls)} compiled-entry checks passed')
    return 0


if __name__=='__main__':
    sys.exit(main())
