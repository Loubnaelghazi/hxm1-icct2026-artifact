"""Independent envelope framing control for migration-policy experiments.

This is NOT an HPKE or CMS implementation, a standardized KEM combiner, or
an independently proven IND-CCA construction. It reuses the same research KEM
components as HXM1 for a controlled comparison of framing, mode, and AAD.
"""
import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768
from hybrid_rsa_mlkem import (
    PublicKeyBundle, PrivateKeyBundle, _rsa_kem_encaps, _rsa_kem_decaps,
    _load_rsa_public_key, _load_rsa_private_key,
)

MAGIC = b'BND1'
VERSION = 1
HYBRID_MODE = 3
FMT = '>4sBBHHBI'
PREFIX = struct.calcsize(FMT)


def _context(header: bytes, c_rsa: bytes, c_pq: bytes, aad: bytes) -> bytes:
    # Length-delimited AAD, explicit ciphertexts, serialized protocol header.
    return (b'BND1-test-control-v1' + header + c_rsa + c_pq
            + len(aad).to_bytes(4, 'big') + aad)


def _key(ss_rsa: bytes, ss_pq: bytes, context: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=context).derive(ss_rsa + ss_pq)


def encrypt_control(pk: PublicKeyBundle, message: bytes, aad: bytes) -> bytes:
    rsa_key = _load_rsa_public_key(pk.rsa_public_pem)
    ss_rsa, c_rsa = _rsa_kem_encaps(rsa_key)
    ss_pq, c_pq = ML_KEM_768.encaps(pk.mlkem_public_key)
    nonce = os.urandom(12)
    header = struct.pack(FMT, MAGIC, VERSION, HYBRID_MODE, len(c_rsa), len(c_pq), 12, len(message)+16)
    context = _context(header, c_rsa, c_pq, aad)
    sealed = AESGCM(_key(ss_rsa, ss_pq, context)).encrypt(nonce, message, context)
    return header + c_rsa + c_pq + nonce + sealed


def decrypt_control(sk: PrivateKeyBundle, package: bytes, aad: bytes) -> bytes:
    if len(package) < PREFIX:
        raise ValueError('truncated control header')
    header = package[:PREFIX]
    magic, version, mode, rsa_len, pq_len, nonce_len, sealed_len = struct.unpack(FMT, header)
    if magic != MAGIC or version != VERSION or mode != HYBRID_MODE:
        raise ValueError('unsupported control mode/version')
    if rsa_len != 384 or pq_len != 1088 or nonce_len != 12 or sealed_len < 16:
        raise ValueError('invalid control component lengths')
    if len(package) != PREFIX + rsa_len + pq_len + nonce_len + sealed_len:
        raise ValueError('invalid control total length')
    off = PREFIX
    c_rsa = package[off:off+rsa_len]; off += rsa_len
    c_pq = package[off:off+pq_len]; off += pq_len
    nonce = package[off:off+nonce_len]; off += nonce_len
    sealed = package[off:]
    ss_rsa = _rsa_kem_decaps(_load_rsa_private_key(sk.rsa_private_pem), c_rsa)
    ss_pq = ML_KEM_768.decaps(sk.mlkem_secret_key, c_pq)
    context = _context(header, c_rsa, c_pq, aad)
    return AESGCM(_key(ss_rsa, ss_pq, context)).decrypt(nonce, sealed, context)
