"""Portable validation of the archived measurements and fuzz records."""
from collections import Counter, defaultdict
import base64
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

root=Path(__file__).resolve().parent
sys.path.insert(0,str(root/'source'))
from hybrid_rsa_mlkem import PrivateKeyBundle, decrypt_hybrid

manifest=json.loads((root/'MANIFEST.sha256.json').read_text())
for relative,expected in manifest.items():
    assert hashlib.sha256((root/relative).read_bytes()).hexdigest()==expected, relative

fuzz=[]
all_inputs=[]
for seed in (42,7):
    folder=root/'evidence/fuzz'
    records=[json.loads(line) for line in (folder/f'seed{seed}.jsonl').read_text().splitlines()]
    assert len(records)==3000 and [r['trial_number'] for r in records]==list(range(1,3001))
    key=PrivateKeyBundle.from_json((folder/f'public_test_key_seed{seed}.json').read_text())
    counts=Counter(); inputs=[]; unchanged=0
    for row in records:
        original=base64.b64decode(row['original_package_base64'],validate=True)
        mutant=base64.b64decode(row['mutated_package_base64'],validate=True)
        assert row['seed']==seed and row['package_unchanged']==(original==mutant)
        unchanged+=original==mutant;inputs.append(mutant);counts[row['outcome']]+=1
        if row['exception_type'] is None:
            expected=b'fuzzing reference message for HXM1 parser robustness testing'
            assert decrypt_hybrid(key,mutant,b'fuzz-aad')==expected
            assert row['recovered_plaintext_matches_reference']
    assert unchanged==(0 if seed==42 else 2)
    assert counts==({'EXPECTED_REJECTION':3000} if seed==42 else {'EXPECTED_REJECTION':2998,'UNCHANGED_VALID_PACKAGE':2})
    assert len(set(inputs))==(2635 if seed==42 else 2629)
    all_inputs.extend(inputs)
    fuzz.append({'seed':seed,'records':len(records),'outcomes':dict(counts),'unique':len(set(inputs))})
assert len(set(all_inputs))==5259

folder=root/'evidence/performance'
records=[json.loads(line) for line in (folder/'raw_samples.jsonl').read_text().splitlines()]
assert len(records)==990 and all(r['status']=='PASS' for r in records)
groups=defaultdict(list)
for row in records:
    if row['phase']=='measured':groups[row['configuration'],row['operation']].append(row['elapsed_ns']/1e6)
    if row['operation']=='decrypt':assert row['plaintext_matches'] and row['plaintext_sha256']==row['recovered_plaintext_sha256']
summary=json.loads((folder/'summary.json').read_text())
assert len(groups)==30 and all(len(v)==30 for v in groups.values())
for saved in summary['summaries']:
    v=groups[saved['configuration'],saved['operation']]
    for name,value in {'median_ms':statistics.median(v),'mean_ms':statistics.fmean(v),'sample_stdev_ms':statistics.stdev(v),'min_ms':min(v),'max_ms':max(v)}.items():
        assert math.isclose(saved[name],value,rel_tol=1e-12,abs_tol=1e-12)
assert (folder/'failures.jsonl').stat().st_size==0

hpke=json.loads((root/'evidence/hpke/results_hpke_reference/hpke_reference.json').read_text())
assert hpke['pyhpke_version']=='0.6.5' and [x['result'] for x in hpke['tests']]==['PASS','EXPECTED_REJECTION','EXPECTED_REJECTION']
folder=root/'evidence/cms'
report=json.loads((folder/'verification.json').read_text())
original=(folder/'tamper_original.cms').read_bytes();mutant=(folder/'tamper_modified.cms').read_bytes()
assert len(original)==len(mutant)
assert [i for i,(a,b) in enumerate(zip(original,mutant)) if a!=b]==report['changed_offsets']==[540]
assert original[540]^mutant[540]==1
start,end=report['tag_range'];assert original[start:end]==mutant[start:end]
assert report['commands'][0]['returncode']==0 and report['commands'][1]['returncode']!=0
assert (folder/'independent_original.dec').read_bytes()==(folder/'tamper_plain.bin').read_bytes()
print(json.dumps({'manifest_files_verified':len(manifest),'fuzz':fuzz,'performance_samples':len(records),'performance_summaries_verified':30,'hpke_record':'3/3 checks from new run','cms_record':'original succeeds; modified content rejected; tag preserved','result':'PASS'},indent=2))
