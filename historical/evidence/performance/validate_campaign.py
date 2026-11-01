"""Validate preserved evidence without running a new benchmark."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
provenance = json.loads((root/'provenance.json').read_text())
summary = json.loads((root/'summary.json').read_text())
completion = json.loads((root/'completion.json').read_text())
assert json.loads((root/'exit_code.json').read_text())['exit_code'] == 0
assert completion['failure_count'] == summary['failure_count'] == 0
assert completion['project_files_unchanged']
assert (root/'failures.jsonl').read_bytes() == b''
rows = [json.loads(line) for line in (root/'raw_samples.jsonl').read_text().splitlines()]
assert len(rows) == 990
assert all(row['status'] == 'PASS' and row['elapsed_ns'] > 0 for row in rows)
groups = defaultdict(list)
overheads = defaultdict(set)
for row in rows:
    groups[row['configuration'], row['operation'], row['phase']].append(row)
    if row['operation'] == 'encrypt':
        assert row['ciphertext_bytes'] - row['payload_bytes'] == row['overhead_bytes']
        overheads[row['configuration']].add(row['overhead_bytes'])
        if not row['implementation'].startswith('cms_'):
            assert row['overhead_bytes'] == {'hybrid':1515, 'rsa':427, 'mlkem':1131}[row['implementation']]
    else:
        assert row['plaintext_matches']
        assert row['recovered_plaintext_sha256'] == row['plaintext_sha256']
    if row['implementation'].startswith('cms_'):
        assert row['returncode'] == 0
        command = row['command']
        output = Path(command[command.index('-out')+1])
        assert output.is_file()
        expected = row['ciphertext_sha256'] if row['operation']=='encrypt' else row['plaintext_sha256']
        assert hashlib.sha256(output.read_bytes()).hexdigest() == expected

assert len(groups) == 60
for (configuration, operation, phase), group in groups.items():
    expected = 30 if phase == 'measured' else 3
    assert len(group) == expected
    assert [r['iteration'] for r in group] == list(range(1, expected+1))
assert summary['warmup_rows'] == 90 and summary['measured_rows'] == 900

recalculated = []
for stored in summary['summaries']:
    values = sorted(row['elapsed_ns']/1_000_000 for row in groups[stored['configuration'], stored['operation'], 'measured'])
    n = len(values)
    mean = math.fsum(values)/n
    actual = {'n': n, 'median_ms': (values[n//2-1]+values[n//2])/2,
              'mean_ms': mean, 'sample_stdev_ms': math.sqrt(math.fsum((x-mean)**2 for x in values)/(n-1)),
              'min_ms':values[0], 'max_ms':values[-1]}
    for field, value in actual.items():
        assert math.isclose(stored[field], value, rel_tol=1e-12, abs_tol=1e-12), (stored, field, value)
    recalculated.append(dict(configuration=stored['configuration'], operation=stored['operation'], **actual))
assert len(recalculated) == 30
with (root/'summary.csv').open('x', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(recalculated[0]))
    writer.writeheader()
    writer.writerows(recalculated)

lookup = {(r['configuration'],r['operation']):r['median_ms'] for r in recalculated}
ratios = []
for size in (128,16384,1048576):
    for denominator in ('cms_cbc','cms_gcm','rsa','mlkem'):
        for operation in ('encrypt','decrypt'):
            numerator_ms=lookup[f'hybrid_{size}B',operation]
            denominator_ms=lookup[f'{denominator}_{size}B',operation]
            ratios.append({'payload_bytes':size,'numerator':f'hybrid {operation}',
                           'denominator':f'{denominator} {operation}',
                           'numerator_median_ms':numerator_ms,'denominator_median_ms':denominator_ms,
                           'ratio_of_medians':numerator_ms/denominator_ms,
                           'boundary': 'in-memory API / CLI with startup and file I/O' if denominator.startswith('cms_') else 'in-memory API / in-memory API; different KEM modes'})
with (root/'ratios.json').open('x') as stream:
    json.dump({'ratios':ratios},stream,indent=2);stream.write('\n')

project = Path(provenance['project'])
now={str(p.relative_to(project)):hashlib.sha256(p.read_bytes()).hexdigest()
     for p in project.rglob('*') if p.is_file() and '.venv' not in p.parts and '__pycache__' not in p.parts}
assert now == provenance['project_sha256_before']
for relative, expected in provenance['source_hashes'].items():
    source=root/'benchmark_campaign.py' if relative=='benchmark_campaign.py' else root/'sources'/relative
    assert hashlib.sha256(source.read_bytes()).hexdigest()==expected

inspection = []
openssl = rows[-1]['command'][0]
for mode in ('cms_cbc','cms_gcm'):
    for size in (128,16384,1048576):
        path=root/f'{mode}_{size}B'/'measured_001.cms'
        command=[openssl,'cms','-cmsout','-print','-inform','DER','-in',str(path)]
        result=subprocess.run(command,capture_output=True,text=True,check=True)
        lines=[line.strip() for line in result.stdout.splitlines() if 'algorithm:' in line or 'contentType:' in line]
        assert any(('aes-256-cbc' if mode=='cms_cbc' else 'aes-256-gcm') in line for line in lines)
        assert any('rsaesOaep' in line for line in lines)
        inspection.append({'command':command,'returncode':result.returncode,'selected_fields':lines})
with (root/'cms_structure_checks.json').open('x') as stream:
    json.dump(inspection,stream,indent=2);stream.write('\n')

validation={'command':[sys.executable,'-B',str(Path(__file__).resolve())],
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'measured_operation_samples':900,'warmup_operation_samples':90,
            'measured_verified_roundtrips':450,'warmup_verified_roundtrips':45,
            'configurations':15,'measured_samples_per_operation_per_configuration':30,
            'failed_runs':0,'summary_statistics_match_raw':True,
            'all_decryptions_match_plaintext':True,'project_files_unchanged':True,
            'overhead_bytes':{k:sorted(v) for k,v in sorted(overheads.items())},
            'files':[{'path':str(p.relative_to(root)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in sorted(root.rglob('*')) if p.is_file()]}
with (root/'validation.json').open('x') as stream:
    json.dump(validation,stream,indent=2);stream.write('\n')
print(json.dumps({k:v for k,v in validation.items() if k!='files'},indent=2))
print('MEDIAN_MS')
for size in (128,16384,1048576):
    for mode in ('hybrid','rsa','mlkem','cms_cbc','cms_gcm'):
        print(size,mode,lookup[f'{mode}_{size}B','encrypt'],lookup[f'{mode}_{size}B','decrypt'])
