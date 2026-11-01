"""Read-only manifest and bounded sensitive-data checks for a tree or ZIP.
Never prints matching contents. Not a guarantee against all secret formats.
"""
from pathlib import Path,PurePosixPath
import argparse,base64,hashlib,io,json,re,stat,tokenize,zipfile
PATTERNS={
 'private_pem':re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
 'aws_access_key':re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
 'github_token':re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'),
 'slack_token':re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{10,}'),
 'credential_assignment':re.compile(rb'''(?i)\b(?:password|passwd|api_key|api_secret|access_token|secret_key)\s*[:=]\s*["']([^"'\r\n]{8,})["']''')}
FORBIDDEN_PARTS={'.git','.venv','venv','__pycache__','.pytest_cache','.mypy_cache','node_modules'}
FORBIDDEN_NAMES={'rsa_priv.pem','private_key.json','hxm1_private.json'}
PRIVATE_FIELDS={'rsa_private_pem','mlkem_secret_key','private_key','private_key_pem','password','passphrase','api_key','access_token','secret_key'}

def scan(files):
    findings=[];file_count=0
    for name,data in files.items():
        file_count+=1;p=PurePosixPath(name)
        def report(rule):findings.append({'file':name,'rule':rule})
        if any(x in FORBIDDEN_PARTS for x in p.parts) or p.name in FORBIDDEN_NAMES or p.suffix in ('.pyc','.passphrase','.replay-key') or p.name.startswith('public_test_key_seed'):report('forbidden_path')
        for rule,pattern in PATTERNS.items():
            if pattern.search(data):report(rule)
        def walk(obj):
            if isinstance(obj,dict):
                for key,value in obj.items():
                    if str(key).lower() in PRIVATE_FIELDS and isinstance(value,str) and value.strip():report('private_or_credential_json_field')
                    walk(value)
            elif isinstance(obj,list):
                for value in obj:walk(value)
            elif isinstance(obj,str):
                if obj.startswith('-----BEGIN') and PATTERNS['private_pem'].search(obj.encode()):report('private_pem_json')
                if len(obj)>=40:
                    try:
                        decoded=base64.b64decode(obj,validate=True)
                        if PATTERNS['private_pem'].search(decoded):report('base64_private_pem')
                        if decoded.startswith(b'{'):
                            candidate=json.loads(decoded)
                            if isinstance(candidate,dict) and any(k in PRIVATE_FIELDS for k in candidate):report('base64_private_bundle')
                    except (ValueError,UnicodeError):pass
        if p.suffix in ('.json','.jsonl'):
            try:
                if p.suffix=='.json':walk(json.loads(data))
                else:
                    for line in data.splitlines():
                        if line.strip():walk(json.loads(line))
            except (ValueError,UnicodeError):report('malformed_json')
    return {'files_scanned':file_count,'finding_count':len(findings),'findings':findings,
            'scope':'All member bytes, paths, JSON fields, base64 private PEM/bundles, common token formats, literal credential assignments; no secret values printed'}

def load_tree(folder):return {str(p.relative_to(folder)):p.read_bytes() for p in sorted(folder.rglob('*')) if p.is_file()}
def load_zip(path):
    with zipfile.ZipFile(path) as z:
        names=z.namelist();assert len(names)==len(set(names)),'Duplicate ZIP members'
        assert z.testzip() is None,'ZIP CRC error'
        result={}
        for info in z.infolist():
            p=PurePosixPath(info.filename)
            assert not p.is_absolute() and '..' not in p.parts,'Unsafe ZIP path'
            assert not stat.S_ISLNK(info.external_attr>>16),'ZIP symlink'
            if not info.is_dir():
                assert p.parts[0]=='hxm1-icct2026'
                result[str(PurePosixPath(*p.parts[1:]))]=z.read(info)
        return result

def verify_manifest(files):
    lines=files['MANIFEST.sha256'].decode().splitlines();expected={}
    for line in lines:
        digest,name=line.split('  ',1);assert name not in expected;expected[name]=digest
    assert set(expected)==set(files)-{'MANIFEST.sha256'},'Manifest membership differs'
    for name,digest in expected.items():assert hashlib.sha256(files[name]).hexdigest()==digest,name
    return len(expected)
def main():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--tree',type=Path);g.add_argument('--zip',type=Path);args=p.parse_args()
    files=load_tree(args.tree) if args.tree else load_zip(args.zip)
    result=scan(files);result['manifest_files_verified']=verify_manifest(files)
    result['status']='PASS' if not result['finding_count'] else 'FAIL'
    print(json.dumps(result,indent=2));raise SystemExit(bool(result['finding_count']))
if __name__=='__main__':main()
