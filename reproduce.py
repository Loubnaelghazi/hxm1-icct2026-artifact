"""Isolated reproduction infrastructure; original constructions/tests are unchanged."""
import argparse
from collections import Counter
from contextlib import redirect_stdout, redirect_stderr
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"
sys.path.insert(0, str(SOURCE))
ARCHIVE_SHA256 = '315e7c6db3390cbbeea829a456925643b74f547ee33342efb264d6ded230ad17'


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', choices=('all', 'unit', 'javascript', 'functional', 'vectors', 'attacks', 'bound', 'hpke', 'cms', 'evidence', 'fuzz', 'performance'), required=True)
    parser.add_argument('--output', type=Path, required=True, help='New directory, preferably below /tmp; must not exist')
    parser.add_argument('--trials', type=int, default=3000, help='Trials PER SEED for fuzz (use 60 for smoke validation)')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("Output must be outside the release package")
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    suites = ('unit', 'javascript', 'functional', 'vectors', 'attacks', 'bound', 'hpke', 'cms', 'evidence', 'fuzz', 'performance') if args.suite == 'all' else (args.suite,)
    results = []
    command_number = 0
    import os
    os.umask(0o077)
    os.chdir(output)

    def command(argv, cwd, *, input_text=None):
        nonlocal command_number
        command_number += 1
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                                input=input_text, start_new_session=True)
        (output/f'command_{command_number:03}.stdout.txt').write_text(result.stdout)
        (output/f'command_{command_number:03}.stderr.txt').write_text(result.stderr)
        with (output/'commands.jsonl').open('a') as stream:
            stream.write(json.dumps({'argv': argv, 'cwd': str(cwd), 'returncode': result.returncode,
                                     'stdout': f'command_{command_number:03}.stdout.txt', 'stderr': f'command_{command_number:03}.stderr.txt'})+'\n')
        return result

    def checked(argv, cwd, **kwargs):
        result = command(argv, cwd, **kwargs)
        if result.returncode:
            raise RuntimeError(f'Command exited {result.returncode}; inspect command logs')
        return result

    def fresh_cms_keys(folder):
        folder.mkdir()
        checked(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=HXM1 disposable reproduction fixture', '-days', '3650', '-keyout', str(folder/'rsa_priv.pem'), '-out', str(folder/'cert.pem')], output)
        (folder/'rsa_priv.pem').chmod(0o600)

    for suite in suites:
        dest = output/suite
        dest.mkdir()
        print('START', suite, flush=True)
        details = {}
        try:
            with (dest/'python.stdout.txt').open('x') as stdout, (dest/'python.stderr.txt').open('x') as stderr, redirect_stdout(stdout), redirect_stderr(stderr):
                if suite == 'unit':
                    import compare_bound_control as comparison
                    original_run = comparison.run
                    def isolated_run(output_dir='results_bound_control_verified'):
                        return original_run(output_dir=dest/Path(output_dir).name)
                    comparison.run = isolated_run
                    try:
                        tests = unittest.defaultTestLoader.loadTestsFromNames(['test_security_regressions', 'test_comparison_verified'])
                        observed = unittest.TextTestRunner(stream=stderr, verbosity=2).run(tests)
                        assert observed.wasSuccessful() and observed.testsRun == 13 and not observed.skipped
                        details = {'tests': observed.testsRun, 'failures': len(observed.failures), 'errors': len(observed.errors), 'skipped_tests': len(observed.skipped)}
                    finally:
                        comparison.run = original_run
                elif suite == 'javascript':
                    r = checked(['node', str(SOURCE/'test_hxm1_parser.js')], dest)
                    match = re.search(r'^# tests (\d+)$', r.stdout, re.M)
                    assert match and int(match[1]) == 9
                    assert re.search(r'^# fail 0$', r.stdout, re.M)
                    details = {'tests': 9}
                elif suite == 'functional':
                    from run_experiments import self_test, downgrade_tests
                    functional = self_test(); modes = downgrade_tests()
                    assert len(functional) == 16 and len(modes) == 9
                    assert all(r['result'] == 'PASS' for r in functional+modes)
                    save(dest/'results.json', {'functional': functional, 'modes': modes})
                    details = {'functional': 16, 'mode_matrix': 9}
                elif suite == 'vectors':
                    from hybrid_rsa_mlkem import PrivateKeyBundle, decrypt, package_info
                    fresh = dest/'fresh'; fresh.mkdir()
                    checked([sys.executable, '-B', str(SOURCE/'make_test_vectors.py')], fresh)
                    reports=[]
                    for label, folder in [('stored',SOURCE/'test_vectors'), ('fresh',fresh/'test_vectors')]:
                        vectors=json.loads((folder/'vectors.json').read_text())
                        plaintext=(folder/'plaintext.bin').read_bytes()
                        assert hashlib.sha256(plaintext).hexdigest()==vectors['plaintext_sha256']
                        private=PrivateKeyBundle.from_json((folder/'private_key.json').read_text()) if label=='fresh' else None
                        for mode,record in vectors['modes'].items():
                            ciphertext=(folder/record['package_file']).read_bytes()
                            assert hashlib.sha256(ciphertext).hexdigest()==record['package_sha256']
                            assert package_info(ciphertext)==record['package_info']
                            if private is not None:
                                assert decrypt(mode,private,ciphertext,vectors['aad_utf8'].encode())==plaintext
                            reports.append({'set':label,'mode':mode,'hash_and_metadata':'PASS',
                                            'decryption':'PASS' if private else 'SKIPPED',
                                            'reason':None if private else 'Matching historical private fixture excluded'})
                            if mode=='hybrid':
                                assert len(ciphertext)-len(plaintext)==1515
                        assert len(vectors['modes'])==3
                    for name in ('hxm1_parser.js','test_hxm1_parser.js'):shutil.copyfile(SOURCE/name,fresh/name)
                    r=checked(['node','test_hxm1_parser.js'],fresh)
                    assert re.search(r'^# tests 9$',r.stdout,re.M) and re.search(r'^# fail 0$',r.stdout,re.M)
                    save(dest/'vector_checks.json',reports)
                    details={'stored_hash_metadata_checks':3,'fresh_roundtrips':3,'fresh_javascript_tests':9,
                             'hybrid_overhead_bytes':1515,'overhead_sets_verified':2,
                             'skipped':[{'check':'historical stored-vector decryptions','count':3,'reason':'Matching private fixture excluded'}]}
                elif suite == 'attacks':
                    from attack_experiments import run_attacks
                    result = run_attacks(); rows = result['rows']
                    baseline = [r for r in rows if r['target'] != 'HXM1']; hxm1 = [r for r in rows if r['target'] == 'HXM1']
                    assert len(rows) == 16 and len(baseline) == 5 and len(hxm1) == 11
                    assert all(r['attack_result'] == 'VULNERABLE' for r in baseline)
                    assert all(r['attack_result'] == 'EXPECTED_REJECTION' for r in hxm1)
                    save(dest/'results.json', result)
                    details = {'total': 16, 'baseline_acceptances': 5, 'hxm1_rejections': 11}
                elif suite == 'bound':
                    import compare_bound_control as comparison
                    rows = comparison.run(output_dir=dest/'results')
                    assert len(rows) == 12 and all(r['outcome'] == 'EXPECTED_REJECTION' for r in rows)
                    details = {'exact_expected_rejections': 12}
                elif suite == 'hpke':
                    checked([sys.executable, '-B', str(SOURCE/'test_hpke_reference.py')], dest)
                    r = json.loads((dest/'results_hpke_reference/hpke_reference.json').read_text())
                    assert r['pyhpke_version'] == '0.6.5' and [x['result'] for x in r['tests']] == ['PASS', 'EXPECTED_REJECTION', 'EXPECTED_REJECTION']
                    details = {'checks': 3, 'library_version': r['pyhpke_version']}
                elif suite == 'cms':
                    fresh_cms_keys(dest/'keys')
                    message = b'This is a CMS AuthEnvelopedData tampering test.'
                    (dest/'plaintext.bin').write_bytes(message)
                    recipient = ['-recip', str(dest/'keys/cert.pem')]
                    checked(['openssl','cms','-encrypt','-in',str(dest/'plaintext.bin'),'-out',str(dest/'original.cms'),*recipient,'-aes-256-gcm','-binary','-outform','DER','-keyopt','rsa_padding_mode:oaep'],dest)
                    structure = checked(['openssl','asn1parse','-inform','DER','-in',str(dest/'original.cms')],dest).stdout
                    m = re.search(r'^\s*(\d+):d=4\s+hl=(\d+) l=\s*(\d+) prim: cont \[ 0 \]',structure,re.M)
                    assert m, 'Cannot identify encryptedContent'
                    position, header, size = map(int,m.groups()); start = position+header
                    original = (dest/'original.cms').read_bytes(); mutant = bytearray(original); mutant[start] ^= 1
                    assert original[:start] == mutant[:start] and original[start+size:] == mutant[start+size:]
                    (dest/'modified.cms').write_bytes(mutant)
                    attempts = []
                    for name in ('original','modified'):
                        argv = ['openssl','cms','-decrypt','-in',str(dest/f'{name}.cms'),'-out',str(dest/f'{name}.dec'),*recipient,'-inkey',str(dest/'keys/rsa_priv.pem'),'-binary','-inform','DER','-keyopt','rsa_padding_mode:oaep']
                        attempts.append(command(argv,dest))
                    assert attempts[0].returncode == 0 and (dest/'original.dec').read_bytes() == message
                    assert attempts[1].returncode != 0
                    failed_output=dest/'modified.dec'
                    discarded_bytes=failed_output.stat().st_size if failed_output.exists() else 0
                    if failed_output.exists():failed_output.unlink()
                    details = {'normal_roundtrip': True, 'changed_content_rejected': True, 'modified_offset': start, 'tag_and_nonce_unchanged': True, 'tampered_exit_code': attempts[1].returncode, 'failed_output_discarded': True, 'discarded_bytes':discarded_bytes}
                elif suite == 'evidence':
                    checked([sys.executable,'-B',str(ROOT/'verify_evidence.py'),'--output',str(dest/'verified')],dest)
                    verified=json.loads((dest/'verified/results.json').read_text())
                    details={k:v for k,v in verified.items() if k!='historical_performance'}
                elif suite == 'fuzz':
                    from fuzz_hxm1_parser import _load_local_replay_key, FUZZ_AAD, FUZZ_PLAINTEXT
                    from hybrid_rsa_mlkem import decrypt_hybrid
                    reports = []
                    for seed in (42,7):
                        passphrase = secrets.token_urlsafe(32)
                        keypath = dest/f'seed{seed}.replay-key'
                        # Fuzzer requires private replay files outside its project root.
                        if keypath.is_relative_to(SOURCE.parent):
                            raise ValueError('Use a fresh /tmp output directory outside the candidate workspace for fuzz')
                        passpath = dest/f'seed{seed}.passphrase'
                        with passpath.open('x') as stream: stream.write(passphrase+'\n')
                        passpath.chmod(0o600)
                        checked([sys.executable,'-B',str(SOURCE/'fuzz_hxm1_parser.py'),'--trials',str(args.trials),'--seed',str(seed),'--jsonl',str(dest/f'seed{seed}.jsonl'),'--replay-key',str(keypath)],dest,input_text=passphrase+'\n'+passphrase+'\n')
                        rows = [json.loads(line) for line in (dest/f'seed{seed}.jsonl').read_text().splitlines()]
                        assert len(rows) == args.trials and [r['trial_number'] for r in rows] == list(range(1,args.trials+1))
                        key = _load_local_replay_key(keypath,passphrase)
                        counts = Counter(r['outcome'] for r in rows)
                        for row in rows:
                            assert row['outcome'] in ('EXPECTED_REJECTION','UNCHANGED_VALID_PACKAGE')
                            if row['exception_type'] is None:
                                mutant=base64.b64decode(row['mutated_package_base64'],validate=True)
                                assert mutant == base64.b64decode(row['original_package_base64'],validate=True)
                                assert decrypt_hybrid(key,mutant,FUZZ_AAD) == FUZZ_PLAINTEXT
                        from verify_evidence import fuzz_records
                        reconstructed, _, _ = fuzz_records(dest, seed, args.trials)
                        reports.append(reconstructed)
                    details = {'runs': reports, 'new_observations_not_historical_reproduction': True}
                elif suite == 'performance':
                    workspace = dest/'workspace'
                    shutil.copytree(SOURCE,workspace,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
                    cms = workspace/'openssl_cms_bench'
                    # Required paths are fresh; original CMS private key is absent.
                    keyfolder = dest/'fresh_keys'; fresh_cms_keys(keyfolder)
                    for name in ('cert.pem','rsa_priv.pem'): shutil.copyfile(keyfolder/name,cms/name)
                    (cms/'rsa_priv.pem').chmod(0o600)
                    measurements = dest/'measurements';measurements.mkdir()
                    result = command([sys.executable,'-B',str(ROOT/'historical/evidence/performance/benchmark_campaign.py'),'--project',str(workspace),'--output',str(measurements),'--repetitions','30','--warmups','3'],dest)
                    save(measurements/'exit_code.json',{'exit_code':result.returncode})
                    assert result.returncode == 0
                    shutil.copyfile(ROOT/'historical/evidence/performance/benchmark_campaign.py',measurements/'benchmark_campaign.py')
                    from verify_evidence import performance
                    validation=performance(measurements)
                    save(measurements/'portable_validation.json',validation)
                    details={k:v for k,v in validation.items() if k!='recalculated_summaries'}
            results.append({'suite':suite,'status':'PASS','details':details})
            print('PASS',suite,json.dumps(details),flush=True)
        except Exception as exc:
            results.append({'suite':suite,'status':'FAIL','exception_type':type(exc).__name__,'message':str(exc)})
            save(output/'results.json',{'results':results,'failed_suite':suite})
            raise
    skipped=[item for result in results for item in result['details'].get('skipped',[])]
    save(output/'results.json',{'results':results,'exit_code':0,'skipped_checks':skipped,
                               'skipped_count':sum(x['count'] for x in skipped)})


if __name__ == '__main__':
    main()
