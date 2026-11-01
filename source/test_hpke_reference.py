"""Independent HPKE RFC 9180 control: X25519/HKDF-SHA256/AES-256-GCM.

No RSA-KEM or ML-KEM is present in this suite. This is NOT a feature-
equivalent baseline for HXM1; it checks HPKE's normal/AAD/integrity behavior.
"""
import json
import sys
from pathlib import Path
from importlib.metadata import version

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.exceptions import InvalidTag
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, OpenError


MESSAGE = b"HXM1 publication reference check"
INFO = b"HXM1-study|HPKE-reference|v1"
AAD = b"document-id:demo-01"


def run():
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM,
    )
    recipient_sk = x25519.X25519PrivateKey.generate()
    skr = KEMKey.from_pyca_cryptography_key(recipient_sk)
    pkr = KEMKey.from_pyca_cryptography_key(recipient_sk.public_key())
    enc, sender = suite.create_sender_context(pkr, info=INFO)
    ct = sender.seal(MESSAGE, aad=AAD)

    results = []
    def decrypt(ciphertext, aad):
        # A *fresh* recipient context is necessary for each check so that
        # the HPKE message counter stays at zero, matching sender.seal().
        return suite.create_recipient_context(enc, skr, info=INFO).open(ciphertext, aad=aad)

    assert decrypt(ct, AAD) == MESSAGE, 'normal round trip failed'
    results.append({'test': 'normal round trip', 'result': 'PASS'})

    def expected_auth_failure(test_name, ciphertext, aad):
        try:
            decrypt(ciphertext, aad)
        except (OpenError, InvalidTag) as exc:
            results.append({'test': test_name, 'result': 'EXPECTED_REJECTION',
                            'exception': type(exc).__name__})
            return
        # Reject other unexpected exceptions: do not mask implementation bugs.
        raise AssertionError(f'{test_name}: unexpected successful decryption')

    expected_auth_failure('wrong AAD', ct, AAD + b'-modified')
    edited_ct = bytearray(ct)
    edited_ct[0] ^= 1
    expected_auth_failure('modified ciphertext', bytes(edited_ct), AAD)

    return {'purpose': 'non-feature-equivalent RFC 9180 behavior reference',
            'suite': 'Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM',
            'library': 'pyhpke', 'pyhpke_version': version('pyhpke'),
            'tests': results, 'summary': '3/3 checks passed'}


def main():
    outcome = run()
    dest = Path('results_hpke_reference')
    dest.mkdir(parents=True, exist_ok=True)
    (dest / 'hpke_reference.json').write_text(json.dumps(outcome, indent=2) + '\n', encoding='utf-8')
    print(outcome['summary'])
    print(f"saved {dest / 'hpke_reference.json'}")


if __name__ == '__main__':
    main()
