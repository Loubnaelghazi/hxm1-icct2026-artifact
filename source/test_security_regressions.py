"""Focused checks of observed HXM1 parser/context behavior, not a cryptographic proof."""
import struct
import unittest
from unittest.mock import patch

import attack_experiments as attacks
from hybrid_rsa_mlkem import (
    encrypt, decrypt, encrypt_hybrid, encrypt_rsa_only, generate_keypair,
    MODE_HYBRID, PublicKeyBundle,
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SecurityRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = generate_keypair()
        cls.aad = b"recipient=alice;document=paper"
        cls.msg = b"test content"
        cls.package = encrypt("hybrid", cls.pub, cls.msg, cls.aad)

    def test_stripped_component_exact_error_and_preserved_fields(self):
        fmt = ">4sBBHHBI"
        header_len = struct.calcsize(fmt)
        magic, ver, mode, rsa_len, pq_len, nonce_len, ct_len = struct.unpack(fmt, self.package[:header_len])
        self.assertEqual(mode, MODE_HYBRID)
        self.assertEqual(pq_len, 1088)
        stripped = attacks._remove_hxm1_mlkem_component(self.package)
        new_head = struct.unpack(fmt, stripped[:header_len])
        self.assertEqual(new_head, (magic, ver, mode, rsa_len, 0, nonce_len, ct_len))
        self.assertEqual(len(stripped), len(self.package) - pq_len)
        self.assertEqual(stripped[header_len:], self.package[:header_len][0:0] + self.package[header_len:header_len+rsa_len] + self.package[header_len+rsa_len+pq_len:])
        with self.assertRaisesRegex(ValueError, '^invalid ML-KEM ciphertext length$'):
            decrypt('hybrid', self.priv, stripped, self.aad)

    def test_fixed_ciphertext_aad_mismatch(self):
        with self.assertRaises(InvalidTag):
            decrypt('hybrid', self.priv, self.package, b'recipient=bob;document=paper')

    def test_public_key_can_create_fresh_valid_context(self):
        chosen = b'recipient=bob;document=paper'
        new_ciphertext = encrypt('hybrid', self.pub, self.msg, chosen)
        self.assertEqual(decrypt('hybrid', self.priv, new_ciphertext, chosen), self.msg)

    def test_wrong_mode(self):
        with self.assertRaisesRegex(ValueError, '^wrong HXM1 mode$'):
            decrypt('rsa', self.priv, self.package, self.aad)

    def test_unsupported_rsa_key_generation_rejected_early(self):
        with patch('hybrid_rsa_mlkem.rsa.generate_private_key') as keygen:
            for bits in (2048, 4096):
                with self.subTest(bits=bits), self.assertRaisesRegex(
                    ValueError, '^HXM1 requires RSA-3072 keys$'
                ):
                    generate_keypair(bits)
            keygen.assert_not_called()

    def test_rsa2048_encryption_rejected_early(self):
        rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = rsa2048.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        bundle = PublicKeyBundle(public_pem, self.pub.mlkem_public_key)
        encryptors = (
            lambda: encrypt_hybrid(bundle, self.msg, self.aad),
            lambda: encrypt_rsa_only(bundle, self.msg, self.aad),
            lambda: encrypt('hybrid', bundle, self.msg, self.aad),
            lambda: encrypt('rsa', bundle, self.msg, self.aad),
        )
        with patch('hybrid_rsa_mlkem._rsa_kem_encaps') as encaps:
            for index, encryptor in enumerate(encryptors):
                with self.subTest(encryptor=index), self.assertRaisesRegex(
                    ValueError, '^HXM1 requires RSA-3072 keys$'
                ):
                    encryptor()
            encaps.assert_not_called()

    def test_rsa3072_roundtrip(self):
        pub, priv = generate_keypair(3072)
        for mode in ('rsa', 'hybrid'):
            with self.subTest(mode=mode):
                package = encrypt(mode, pub, self.msg, self.aad)
                self.assertEqual(struct.unpack('>H', package[6:8])[0], 384)
                self.assertEqual(decrypt(mode, priv, package, self.aad), self.msg)

    def test_script_fails_on_unexpected_result(self):
        with patch.object(attacks, 'run_attacks', return_value={'rows':[{'failure':'test', 'target':'HXM1', 'attack_result':'UNEXPECTED_ERROR', 'expected_defense':'reject'}]}), patch.object(attacks, 'write_markdown'):
            with self.assertRaises(SystemExit) as ctx:
                attacks.main()
            self.assertEqual(ctx.exception.code, 1)

    def test_script_fails_on_accepted_ciphertext(self):
        with patch.object(attacks, 'run_attacks', return_value={'rows':[{'failure':'test', 'target':'HXM1', 'attack_result':'VULNERABLE', 'expected_defense':'reject'}]}), patch.object(attacks, 'write_markdown'):
            with self.assertRaises(SystemExit) as ctx:
                attacks.main()
            self.assertEqual(ctx.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
