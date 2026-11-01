"""Run new experiments from the archive without overwriting recorded evidence."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', choices=('hpke', 'cms', 'checks', 'fuzz', 'performance'), required=True)
    parser.add_argument('--output', type=Path, required=True, help='A directory that must not exist')
    args = parser.parse_args()
    archive = Path(__file__).resolve().parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = archive/'source'

    def run(argv, cwd=out):
        with (out/'commands.jsonl').open('a') as log:
            log.write(json.dumps({'argv': argv, 'cwd': str(cwd)})+'\n')
        return subprocess.run(argv, cwd=cwd, check=True)

    def python(code):
        return run([sys.executable, '-B', '-c', 'import sys; sys.path.insert(0, '+repr(str(source))+'); '+code])

    def fresh_cms_keys(dest):
        dest.mkdir(parents=True, exist_ok=True)
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=HXM1 public reproduction test fixture', '-days', '3650', '-keyout', str(dest/'rsa_priv.pem'), '-out', str(dest/'cert.pem')])
        (dest/'rsa_priv.pem').chmod(0o600)

    if args.suite == 'hpke':
        run([sys.executable, '-B', str(source/'test_hpke_reference.py')])
    elif args.suite == 'checks':
        run([sys.executable, '-B', '-m', 'unittest', '-v', 'test_security_regressions'], cwd=source)
        run(['node', '--test', str(source/'test_hxm1_parser.js')])
        python('import compare_bound_control as c; c.run(output_dir='+repr(str(out/'bound_control'))+')')
        python('import json, attack_experiments as a; from pathlib import Path; r=a.run_attacks(); assert all(x["attack_result"]=="EXPECTED_REJECTION" for x in r["rows"] if x["target"]=="HXM1"); Path('+repr(str(out/'attacks.json'))+').write_text(json.dumps(r,indent=2))')
    elif args.suite == 'fuzz':
        # Existing CLI securely prompts for each new local replay-key passphrase.
        for seed in (42, 7):
            run([sys.executable, '-B', str(source/'fuzz_hxm1_parser.py'), '--trials', '3000', '--seed', str(seed), '--jsonl', str(out/f'seed{seed}.jsonl'), '--replay-key', str(out/f'seed{seed}.replay-key')])
    elif args.suite == 'performance':
        workspace = out/'workspace'
        shutil.copytree(source, workspace)
        fresh_cms_keys(workspace/'openssl_cms_bench')
        measurements = out/'measurements'
        measurements.mkdir()
        run([sys.executable, '-B', str(archive/'evidence/performance/benchmark_campaign.py'), '--project', str(workspace), '--output', str(measurements), '--repetitions', '30', '--warmups', '3'])
    elif args.suite == 'cms':
        fresh_cms_keys(out/'keys')
        message = b'This is a CMS AuthEnvelopedData tampering test.'
        (out/'plaintext.bin').write_bytes(message)
        common = ['-recip', str(out/'keys/cert.pem')]
        run(['openssl', 'cms', '-encrypt', '-in', str(out/'plaintext.bin'), '-out', str(out/'original.cms'), *common, '-aes-256-gcm', '-binary', '-outform', 'DER', '-keyopt', 'rsa_padding_mode:oaep'])
        command = ['openssl', 'asn1parse', '-inform', 'DER', '-in', str(out/'original.cms')]
        structure = subprocess.run(command, capture_output=True, text=True, check=True).stdout
        (out/'asn1parse.txt').write_text(structure)
        match = re.search(r'^\s*(\d+):d=4\s+hl=(\d+) l=\s*(\d+) prim: cont \[ 0 \]', structure, re.M)
        assert match, 'Cannot locate encrypted content: refusing arbitrary byte modification'
        position, header, length = map(int, match.groups())
        original = (out/'original.cms').read_bytes()
        mutant = bytearray(original)
        mutant[position+header] ^= 1
        assert original[:position+header] == mutant[:position+header]
        assert original[position+header+length:] == mutant[position+header+length:]
        (out/'modified.cms').write_bytes(mutant)
        results=[]
        for label in ('original','modified'):
            command=['openssl','cms','-decrypt','-in',str(out/f'{label}.cms'),'-out',str(out/f'{label}.dec'),*common,'-inkey',str(out/'keys/rsa_priv.pem'),'-binary','-inform','DER','-keyopt','rsa_padding_mode:oaep']
            result=subprocess.run(command,capture_output=True,text=True)
            results.append({'command':command,'returncode':result.returncode,'stderr':result.stderr})
        assert results[0]['returncode']==0 and (out/'original.dec').read_bytes()==message
        assert results[1]['returncode']!=0
        (out/'results.json').write_text(json.dumps({'result':'PASS','changed_offset':position+header,'commands':results},indent=2)+'\n')
        print('PASS: original roundtrip and modified-content rejection; never consume failed decryption output')


if __name__ == '__main__':
    main()
