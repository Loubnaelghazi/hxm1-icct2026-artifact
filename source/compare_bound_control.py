"""Strict, reproducible targeted comparison. Not a cryptographic security proof."""
import json
import struct
from pathlib import Path
from cryptography.exceptions import InvalidTag
from hybrid_rsa_mlkem import generate_keypair, encrypt, decrypt
from bound_envelope_control import encrypt_control, decrypt_control

FMT = '>4sBBHHBI'
HEADER_SIZE = struct.calcsize(FMT)
AAD = b'recipient=alice;document=paper'
MESSAGE = b'controlled profile comparison'
SCENARIOS = (
    'version changed', 'mode changed', 'ML-KEM bytes modified',
    'ML-KEM bytes removed with consistent lengths', 'AAD changed', 'trailing byte',
)
EXPECTED = {
 'HXM1': {
  'version changed': ('ValueError', 'unsupported HXM1 package'),
  'mode changed': ('ValueError', 'unexpected ML-KEM component in RSA-only mode'),
  'ML-KEM bytes modified': ('InvalidTag',''),
  'ML-KEM bytes removed with consistent lengths': ('ValueError','invalid ML-KEM ciphertext length'),
  'AAD changed': ('InvalidTag',''),
  'trailing byte': ('ValueError','invalid HXM1 package length'),
 },
 'Bound control (not a standard)': {
  'version changed': ('ValueError','unsupported control mode/version'),
  'mode changed': ('ValueError','unsupported control mode/version'),
  'ML-KEM bytes modified': ('InvalidTag',''),
  'ML-KEM bytes removed with consistent lengths': ('ValueError','invalid control component lengths'),
  'AAD changed': ('InvalidTag',''),
  'trailing byte': ('ValueError','invalid control total length'),
 },
}

def fields(pkg):
    header = pkg[:HEADER_SIZE]
    _, _, _, nr, npq, nn, nc = struct.unpack(FMT, header)
    offset = HEADER_SIZE
    rsa = pkg[offset:offset+nr]; offset += nr
    pq = pkg[offset:offset+npq]; offset += npq
    nonce = pkg[offset:offset+nn]; offset += nn
    sealed = pkg[offset:offset+nc]
    assert offset+nc == len(pkg), 'inconsistent input framing'
    return (header,rsa,pq,nonce,sealed)

def mutation(original, scenario):
    header, rsa, pq, nonce, sealed = fields(original)
    b = bytearray(original)
    aad = AAD
    if scenario == 'version changed': b[4]=0
    elif scenario == 'mode changed': b[5]=1
    elif scenario == 'ML-KEM bytes modified': b[HEADER_SIZE+len(rsa)] ^= 1
    elif scenario == 'ML-KEM bytes removed with consistent lengths':
        assert len(pq)==1088
        del b[HEADER_SIZE+len(rsa):HEADER_SIZE+len(rsa)+len(pq)]
        b[8:10] = (0).to_bytes(2,'big')
        updated = fields(bytes(b))
        assert updated[1] == rsa and updated[2] == b''
        assert updated[3] == nonce and updated[4] == sealed
        assert updated[0][5] == header[5] == 3  # hybrid mode unchanged
        assert len(b) == len(original)-1088
    elif scenario == 'AAD changed': aad=b'recipient=bob;document=paper'
    elif scenario == 'trailing byte': b.append(0)
    else: raise ValueError(scenario)
    if scenario != 'ML-KEM bytes removed with consistent lengths' and scenario != 'trailing byte':
        assert len(b)==len(original)
    return bytes(b),aad

def run(output_dir='results_bound_control_verified'):
    pk,sk=generate_keypair()
    cases={
      'HXM1': (encrypt('hybrid',pk,MESSAGE,AAD),lambda c,a:decrypt('hybrid',sk,c,a)),
      'Bound control (not a standard)':(encrypt_control(pk,MESSAGE,AAD),lambda c,a:decrypt_control(sk,c,a)),
    }
    rows=[]
    for label,(original,decryptor) in cases.items():
        if decryptor(original,AAD)!=MESSAGE: raise AssertionError('round-trip mismatch: '+label)
        for scenario in SCENARIOS:
            pkg,aad=mutation(original,scenario)
            expected_type, expected_text=EXPECTED[label][scenario]
            try:
                plaintext=decryptor(pkg,aad)
                observed='ACCEPTED (unexpected)'
                detail=f'plaintext length={len(plaintext)}'
            except Exception as exc:
                detail=type(exc).__name__+': '+str(exc)
                observed='EXPECTED_REJECTION' if type(exc).__name__==expected_type and str(exc)==expected_text else 'WRONG_EXCEPTION'
            rows.append({'system':label,'mutation':scenario,'outcome':observed,'detail':detail,'expected':expected_type+': '+expected_text})
    dest=Path(output_dir);dest.mkdir(parents=True,exist_ok=True)
    (dest/'comparison.json').write_text(json.dumps({'rows':rows,'note':'Targeted parser/context observations only. No IND-CCA or standard conformance claim.'},indent=2)+'\n')
    lines=['# Strict targeted comparison','','Neither envelope is claimed to be a standard or a proven IND-CCA combiner. The control uses the same experimental component KEM implementations.','', '| System | Mutation | Outcome | Exception |','|---|---|---|---|']
    for r in rows: lines.append('| '+ ' | '.join(str(r[k]) for k in ['system','mutation','outcome','detail']) + ' |')
    (dest/'comparison.md').write_text('\n'.join(lines)+'\n')
    failed=[r for r in rows if r['outcome']!='EXPECTED_REJECTION']
    print(f'{len(rows)-len(failed)}/{len(rows)} exact expected rejections; output: {dest}')
    if failed:raise AssertionError(f'Unexpected outcomes: {failed}')
    return rows

if __name__=='__main__':run()
