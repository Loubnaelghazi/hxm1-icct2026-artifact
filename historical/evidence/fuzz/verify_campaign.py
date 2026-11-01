from pathlib import Path
from collections import Counter
import base64, hashlib, json, random, re, sys

root = Path(__file__).resolve().parent
provenance = json.loads((root/'provenance.json').read_text())
project = Path(provenance['project'])
sys.path.insert(0, str(project))
from fuzz_hxm1_parser import _load_local_replay_key, classify_success, FUZZ_AAD, FUZZ_PLAINTEXT
from hybrid_rsa_mlkem import decrypt_hybrid

def decode(s):
    return base64.b64decode(s, validate=True)

def printed_counts(text, start, end):
    section = text.split(start,1)[1].split(end,1)[0]
    return dict((k,int(v)) for k,v in re.findall(r'^  ([A-Za-z_]+): (\d+)$',section,re.M))

results = []
all_inputs = []
for seed in (42,7):
    stem=root/f'seed{seed}'
    execution=json.loads(Path(str(stem)+'.execution.json').read_text())
    assert execution['returncode']==0
    rows=[json.loads(line) for line in Path(str(stem)+'.jsonl').read_text().splitlines()]
    assert len(rows)==3000
    assert [r['trial_number'] for r in rows]==list(range(1,3001))
    original=decode(rows[0]['original_package_base64'])
    passphrase=Path(str(stem)+'.passphrase').read_text().rstrip('\n')
    sk=_load_local_replay_key(Path(str(stem)+'.replay-key'),passphrase)
    assert decrypt_hybrid(sk,original,FUZZ_AAD)==FUZZ_PLAINTEXT
    outcomes=Counter(); legacy=Counter(); exceptions=Counter(); branches=Counter()
    inputs=[]; accepts=[]; unchanged=0; rng=random.Random(seed)
    for r in rows:
        assert r['seed']==seed
        assert decode(r['original_package_base64'])==original
        assert r['replay_key_file']==str(stem)+'.replay-key'
        mutant=decode(r['mutated_package_base64']); inputs.append(mutant)
        d=r['mutation_details']; branch=r['mutation_branch']; branches[branch]+=1
        assert d['branch']==branch
        choice=rng.random()
        if choice<0.4:
            assert branch=='truncate'
            cut=rng.randrange(1,len(original))
            assert cut==d['cut_offset']
            reconstructed=original[:cut]
            assert d['original_length']==len(original) and d['mutated_length']==len(mutant)
        elif choice<0.8:
            assert branch=='extend'
            n=rng.randint(1,64)
            extra=decode(d['appended_bytes_base64'])
            assert n==d['appended_length']==len(extra)
            reconstructed=original+extra
            assert d['original_length']==len(original) and d['mutated_length']==len(mutant)
        else:
            assert branch=='byte_mutation'
            n=rng.randint(1,4)
            assert n==d['operation_count']==len(d['operations'])
            data=bytearray(original)
            for i,op in enumerate(d['operations'],1):
                pos=rng.randrange(len(data)); assigned=rng.randrange(256)
                assert op['operation']==i and op['position']==pos and op['assigned_byte']==assigned
                assert op['before_byte']==data[pos]
                assert op['changed_at_operation']==(data[pos]!=assigned)
                data[pos]=assigned
                assert op['after_byte']==data[pos]
            reconstructed=bytes(data)
        assert reconstructed==mutant
        is_unchanged=mutant==original
        assert r['package_unchanged']==is_unchanged
        assert d['final_package_changed']==(not is_unchanged)
        unchanged+=is_unchanged
        outcomes[r['outcome']]+=1
        if r['exception_type'] is None:
            recovered=decrypt_hybrid(sk,mutant,FUZZ_AAD)
            assert classify_success(original,mutant,recovered,FUZZ_PLAINTEXT)==r['outcome']
            assert r['recovered_plaintext_matches_reference']==(recovered==FUZZ_PLAINTEXT)
            cause='unchanged input: every assignment was a no-op' if is_unchanged and all(not op['changed_at_operation'] for op in d.get('operations',[])) else 'unchanged input after assignments' if is_unchanged else 'changed input accepted: cause unexplained'
            accepts.append({'trial':r['trial_number'],'outcome':r['outcome'],'unchanged':is_unchanged,'plaintext_matches':recovered==FUZZ_PLAINTEXT,'cause':cause,'mutation_details':d,'input_sha256':hashlib.sha256(mutant).hexdigest()})
            legacy['ACCEPTED_AND_CORRECT' if recovered==FUZZ_PLAINTEXT else 'ACCEPTED_BUT_WRONG_PLAINTEXT']+=1
        else:
            assert r['outcome'] in ('EXPECTED_REJECTION','UNEXPECTED_EXCEPTION')
            exceptions[r['exception_type']]+=1
            assert (r['exception_type'] in ('ValueError','InvalidTag'))==(r['outcome']=='EXPECTED_REJECTION')
            legacy[('SAFE_REJECT_' if r['outcome']=='EXPECTED_REJECTION' else 'UNEXPECTED_')+r['exception_type']]+=1
    stdout=Path(str(stem)+'.stdout.txt').read_text()
    assert re.search(rf'^Trials: 3000  Seed: {seed}  Elapsed:',stdout,re.M)
    assert printed_counts(stdout,'Classified outcomes:','Aggregate outcomes (legacy buckets):')==dict(outcomes)
    assert printed_counts(stdout,'Aggregate outcomes (legacy buckets):','JSONL audit:')==dict(legacy)
    freq=Counter(inputs); all_inputs.extend(inputs)
    results.append({'seed':seed,'requested':3000,'generated':len(rows),'submitted':len(rows),'completed':len(rows),'changed':len(rows)-unchanged,'unchanged':unchanged,'unique_inputs':len(freq),'duplicate_occurrences_beyond_first':len(rows)-len(freq),'distinct_inputs_repeated':sum(n>1 for n in freq.values()),'rejected':outcomes['EXPECTED_REJECTION'],'accepted':len(accepts),'unexpected_exceptions':outcomes['UNEXPECTED_EXCEPTION'],'accepted_wrong_plaintext':sum(not a['plaintext_matches'] for a in accepts),'unexplained_accepts':sum(not a['unchanged'] for a in accepts),'outcomes':dict(outcomes),'exceptions':dict(exceptions),'branches':dict(branches),'accepted_cases':accepts,'stdout_matches_jsonl':True,'seeded_mutations_reconstructed':True,'exit_code':execution['returncode']})

now={str(p.relative_to(project)):hashlib.sha256(p.read_bytes()).hexdigest() for p in project.rglob('*') if p.is_file() and '.venv' not in p.parts and '__pycache__' not in p.parts}
assert now==provenance['project_sha256_before'], 'Project files changed'
report={'runs':results,'combined_unique_inputs':len(set(all_inputs)),'combined_duplicate_occurrences_beyond_first':len(all_inputs)-len(set(all_inputs)),'project_files_unchanged':True,'files':[{'path':str(p),'bytes':p.stat().st_size,'mode':oct(p.stat().st_mode&0o777),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.iterdir()) if p.is_file()]}
with (root/'verification.json').open('x') as f: json.dump(report,f,indent=2); f.write('\n')
print(json.dumps(report,indent=2))
