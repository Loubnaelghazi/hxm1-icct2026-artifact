"""Release verification infrastructure; never edits source or archived records.
Historical private fixtures are intentionally absent. Recorded outcomes are
validated as records; cryptographic replay without the original key is SKIPPED.
"""
from collections import Counter, defaultdict
from pathlib import Path
import argparse, base64, csv, hashlib, json, math, random, statistics, sys
ROOT=Path(__file__).resolve().parent

def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(Path(path).read_text())
def fuzz_records(folder,seed,trials,historical=False):
    rows=[json.loads(s) for s in (folder/f'seed{seed}.jsonl').read_text().splitlines()]
    assert len(rows)==trials
    rng=random.Random(seed);inputs=[];counts=Counter();accepts=[]
    reference=base64.b64decode(rows[0]['original_package_base64'],validate=True)
    for i,row in enumerate(rows,1):
        assert row['trial_number']==i and row['seed']==seed
        original=base64.b64decode(row['original_package_base64'],validate=True)
        mutated=base64.b64decode(row['mutated_package_base64'],validate=True)
        assert original==reference
        d=row['mutation_details'];choice=rng.random()
        if choice<0.4:
            assert row['mutation_branch']==d['branch']=='truncate'
            cut=rng.randrange(1,len(original));assert cut==d['cut_offset']
            reconstructed=original[:cut]
        elif choice<0.8:
            assert row['mutation_branch']==d['branch']=='extend'
            count=rng.randint(1,64);extra=base64.b64decode(d['appended_bytes_base64'],validate=True)
            assert count==d['appended_length']==len(extra)
            reconstructed=original+extra
        else:
            assert row['mutation_branch']==d['branch']=='byte_mutation'
            count=rng.randint(1,4);assert count==d['operation_count']==len(d['operations'])
            data=bytearray(original)
            for number,op in enumerate(d['operations'],1):
                pos=rng.randrange(len(data));assigned=rng.randrange(256)
                assert op['operation']==number and op['position']==pos and op['assigned_byte']==assigned
                assert op['before_byte']==data[pos] and op['changed_at_operation']==(data[pos]!=assigned)
                data[pos]=assigned;assert op['after_byte']==assigned
            reconstructed=bytes(data)
        assert reconstructed==mutated
        unchanged=original==mutated
        assert row['package_unchanged']==unchanged and d['final_package_changed']==(not unchanged)
        if row['exception_type'] is None:
            assert unchanged and row['outcome']=='UNCHANGED_VALID_PACKAGE'
            assert row['recovered_plaintext_matches_reference'] is True
            accepts.append(row)
        else:
            assert row['outcome']=='EXPECTED_REJECTION' and row['exception_type'] in ('ValueError','InvalidTag')
        inputs.append(mutated);counts[row['outcome']]+=1
    if historical:
        assert trials==3000
        assert counts==({'EXPECTED_REJECTION':3000} if seed==42 else {'EXPECTED_REJECTION':2998,'UNCHANGED_VALID_PACKAGE':2})
        assert len(set(inputs))==(2635 if seed==42 else 2629)
    return {'seed':seed,'completed':len(rows),'outcomes':dict(counts),'distinct_inputs':len(set(inputs)),
            'changed':sum(base64.b64decode(r['original_package_base64'])!=x for r,x in zip(rows,inputs)),
            'recorded_acceptances':len(accepts)},inputs,accepts

def performance(folder,historical=False):
    rows=[json.loads(s) for s in (folder/'raw_samples.jsonl').read_text().splitlines()]
    summary=read(folder/'summary.json');provenance=read(folder/'provenance.json');completion=read(folder/'completion.json')
    assert len(rows)==990 and all(r['status']=='PASS' and r['elapsed_ns']>0 for r in rows)
    assert summary['failure_count']==completion['failure_count']==0
    assert completion['project_files_unchanged'] is True
    assert summary['measured_rows']==900 and summary['warmup_rows']==90
    assert (folder/'failures.jsonl').read_bytes()==b''
    assert read(folder/'exit_code.json')['exit_code']==0
    groups=defaultdict(list);overheads=defaultdict(set)
    for r in rows:
        groups[r['configuration'],r['operation'],r['phase']].append(r)
        if r['operation']=='decrypt':
            assert r['plaintext_matches'] and r['plaintext_sha256']==r['recovered_plaintext_sha256']
        else:
            assert r['ciphertext_bytes']-r['payload_bytes']==r['overhead_bytes']
            overheads[r['configuration']].add(r['overhead_bytes'])
            if not r['implementation'].startswith('cms_'):
                assert r['overhead_bytes']=={'hybrid':1515,'rsa':427,'mlkem':1131}[r['implementation']]
        if r['implementation'].startswith('cms_'):
            assert r['returncode']==0
            recorded_output=Path(r['command'][r['command'].index('-out')+1])
            # Historical absolute prefixes are provenance only, never accessed.
            path=folder/r['configuration']/recorded_output.name
            assert path.is_file(),str(path)
            assert sha(path.read_bytes())==r['ciphertext_sha256' if r['operation']=='encrypt' else 'plaintext_sha256']
    assert len(groups)==60
    for (config,op,phase),items in groups.items():
        n=30 if phase=='measured' else 3
        assert len(items)==n and [r['iteration'] for r in items]==list(range(1,n+1))
    assert len(summary['summaries'])==30
    recalculated=[]
    for stored in summary['summaries']:
        vals=[r['elapsed_ns']/1e6 for r in groups[stored['configuration'],stored['operation'],'measured']]
        actual={'n':len(vals),'median_ms':statistics.median(vals),'mean_ms':statistics.fmean(vals),
                'sample_stdev_ms':statistics.stdev(vals),'min_ms':min(vals),'max_ms':max(vals)}
        for k,v in actual.items():assert math.isclose(stored[k],v,rel_tol=1e-12,abs_tol=1e-12),(stored['configuration'],k)
        recalculated.append(dict(configuration=stored['configuration'],operation=stored['operation'],**actual))
    if historical:
        csv_rows=list(csv.DictReader((folder/'summary.csv').open()))
        assert len(csv_rows)==30
        lookup={(r['configuration'],r['operation']):r for r in csv_rows}
        for row in recalculated:
            stored=lookup[row['configuration'],row['operation']]
            for k in ('n','median_ms','mean_ms','sample_stdev_ms','min_ms','max_ms'):
                assert math.isclose(float(stored[k]),row[k],rel_tol=1e-12,abs_tol=1e-12)
    for rel,expected in provenance['source_hashes'].items():
        p=folder/'benchmark_campaign.py' if rel=='benchmark_campaign.py' else folder/'sources'/rel
        assert sha(p.read_bytes())==expected,rel
    if not historical:
        project=Path(provenance['project'])
        now={str(p.relative_to(project)):sha(p.read_bytes()) for p in project.rglob('*') if p.is_file() and '.venv' not in p.parts and '__pycache__' not in p.parts}
        assert now==provenance['project_sha256_before']
    return {'raw_samples':len(rows),'measured_samples':900,'warmup_samples':90,'verified_roundtrips':495,
            'summaries_recalculated':30,'failures':0,'overheads':{k:sorted(v) for k,v in overheads.items()},
            'recalculated_summaries':recalculated,'scope':'historical records' if historical else 'fresh measurements'}

def verify():
    original=read(ROOT/'historical/MANIFEST.sha256.json');inputs=read(ROOT/'provenance/INPUTS.json')
    archive_map={}
    for row in inputs['included_originals']:
        p=ROOT/row['path'];assert p.is_file() and sha(p.read_bytes())==row['sha256'],row['path']
        if row['origin']=='verified_experimental_archive':
            rel=row['original_path'];archive_map[rel]=row
            if rel!='MANIFEST.sha256.json':assert row['sha256']==original[rel]
    excluded=read(ROOT/'provenance/EXCLUDED_FILES.json')
    excluded_map={r['original_path']:r for r in excluded}
    assert len(original)==516
    assert set(original)==(set(archive_map)-{'MANIFEST.sha256.json'})|set(excluded_map)
    for rel,row in excluded_map.items():assert original[rel]==row['sha256']
    reports=[];allinputs=[]
    for seed in (42,7):
        report,values,_=fuzz_records(ROOT/'historical/evidence/fuzz',seed,3000,True)
        reports.append(report);allinputs.extend(values)
    assert len(set(allinputs))==5259
    perf=performance(ROOT/'historical/evidence/performance',True)
    hpke=read(ROOT/'historical/evidence/hpke/results_hpke_reference/hpke_reference.json')
    assert hpke['pyhpke_version']=='0.6.5'
    assert [r['result'] for r in hpke['tests']]==['PASS','EXPECTED_REJECTION','EXPECTED_REJECTION']
    cms=ROOT/'historical/evidence/cms';r=read(cms/'verification.json')
    a=(cms/'tamper_original.cms').read_bytes();b=(cms/'tamper_modified.cms').read_bytes()
    assert len(a)==len(b) and [i for i,(x,y) in enumerate(zip(a,b)) if x!=y]==r['changed_offsets']==[540]
    assert a[540]^b[540]==1
    start,end=r['encrypted_content_range'];assert start<=540<end
    assert a[:start]==b[:start] and a[end:]==b[end:] and r['nonce_unchanged'] and r['tag_unchanged']
    start,end=r['tag_range'];assert a[start:end]==b[start:end]
    assert r['commands'][0]['returncode']==0 and r['commands'][1]['returncode']==4
    assert (cms/'independent_original.dec').read_bytes()==(cms/'tamper_plain.bin').read_bytes()
    attacks=read(ROOT/'historical/evidence/results_attacks/attack_results.json')['rows']
    assert len(attacks)==16
    assert sum(x['attack_result']=='VULNERABLE' and x['target']!='HXM1' for x in attacks)==5
    assert sum(x['attack_result']=='EXPECTED_REJECTION' and x['target']=='HXM1' for x in attacks)==11
    bound=read(ROOT/'historical/evidence/results_bound_control_verified/comparison.json')['rows']
    assert len(bound)==12 and all(x['outcome']=='EXPECTED_REJECTION' for x in bound)
    return {'status':'PASS','original_manifest_entries_accounted':516,'imported_files_verified':len(inputs['included_originals']),
            'excluded_archive_files':len(excluded),'historical_fuzz':reports,'combined_distinct_inputs':5259,
            'historical_performance':perf,'hpke_record_checks':3,'cms_record_and_structure_checks':2,
            'targeted_attack_records':16,'bound_control_records':12,
            'skipped':[{'check':'historical accepted fuzz cryptographic replay','count':2,'reason':'All pre-existing private replay keys excluded'},
                       {'check':'historical CMS decryption rerun','count':2,'reason':'Matching historical private key excluded; archived outcomes/structure verified and fresh CMS tested separately'}]}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    assert not args.output.resolve().is_relative_to(ROOT),'Output must be outside the package'
    args.output.mkdir(parents=True,exist_ok=False)
    result=verify()
    (args.output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='historical_performance'},indent=2))
if __name__=='__main__':main()
