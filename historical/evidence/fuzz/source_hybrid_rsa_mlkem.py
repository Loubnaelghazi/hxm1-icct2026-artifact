from __future__ import annotations

import base64
import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768


VERSION = 1
RSA_SECRET_LEN = 32
AES_KEY_LEN = 32
NONCE_LEN = 12
MAGIC = b"HXM1"
MODE_RSA_ONLY = 1
MODE_MLKEM_ONLY = 2
MODE_HYBRID = 3
MODE_NAMES = {
    MODE_RSA_ONLY: "RSA-KEM+HKDF-SHA256+AES-256-GCM",
    MODE_MLKEM_ONLY: "ML-KEM-768+HKDF-SHA256+AES-256-GCM",
    MODE_HYBRID: "RSA-KEM+ML-KEM-768+HKDF-SHA256+AES-256-GCM",
}
MODE_BY_NAME = {
    "rsa": MODE_RSA_ONLY,
    "mlkem": MODE_MLKEM_ONLY,
    "hybrid": MODE_HYBRID,
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(secrets: list[bytes], header: dict[str, Any], aad: bytes) -> bytes:
    info = b"rsa-mlkem-hybrid-v1|" + _canonical_json(header) + b"|" + aad
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=info,
    ).derive(b"".join(secrets))


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _os2ip(value: bytes) -> int:
    return int.from_bytes(value, "big")


def _rsa_kem_kdf(z_bytes: bytes, rsa_bits: int) -> bytes:
    info = f"rsa-kem-rfc9690-inspired|rsa_bits={rsa_bits}|ss_len={RSA_SECRET_LEN}".encode("ascii")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=RSA_SECRET_LEN,
        salt=None,
        info=info,
    ).derive(z_bytes)


def _rsa_kem_encaps(public_key: rsa.RSAPublicKey) -> tuple[bytes, bytes]:
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e
    k = (public_key.key_size + 7) // 8
    while True:
        z = _os2ip(os.urandom(k))
        if 1 <= z < n:
            break
    c = pow(z, e, n)
    z_bytes = _i2osp(z, k)
    c_bytes = _i2osp(c, k)
    return _rsa_kem_kdf(z_bytes, public_key.key_size), c_bytes


def _rsa_kem_decaps(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    numbers = private_key.private_numbers()
    n = numbers.public_numbers.n
    p = numbers.p
    q = numbers.q
    dmp1 = numbers.dmp1
    dmq1 = numbers.dmq1
    iqmp = numbers.iqmp
    k = (private_key.key_size + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("invalid RSA-KEM ciphertext length")
    c = _os2ip(ciphertext)
    if not 0 <= c < n:
        raise ValueError("invalid RSA-KEM ciphertext representative")
    m1 = pow(c % p, dmp1, p)
    m2 = pow(c % q, dmq1, q)
    h = ((m1 - m2) * iqmp) % p
    z = m2 + q * h
    z_bytes = _i2osp(z, k)
    return _rsa_kem_kdf(z_bytes, private_key.key_size)



def rsa_oaep_reference_encrypt(public_key: rsa.RSAPublicKey, secret: bytes) -> bytes:
    """Reference-only: standard RSA-OAEP encryption via OpenSSL (cryptography
    library), NOT part of the HXM1 format. Used purely as a performance
    baseline to isolate implementation cost (pure-Python pow()) from the
    underlying RSA private-key operation cost (OpenSSL, hardware-accelerated).
    """
    return public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_reference_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Reference-only: standard RSA-OAEP decryption via OpenSSL (cryptography
    library), NOT part of the HXM1 format. See rsa_oaep_reference_encrypt.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _header(mode_id: int, rsa_bits: int | None = None) -> dict[str, Any]:
    header = {
        "version": VERSION,
        "mode_id": mode_id,
        "mode": MODE_NAMES[mode_id],
        "format": "HXM1 binary v1",
        "kdf": "HKDF-SHA256",
        "aead": "AES-256-GCM",
    }
    if rsa_bits is not None:
        header["rsa_bits"] = rsa_bits
    if mode_id in (MODE_MLKEM_ONLY, MODE_HYBRID):
        header["mlkem"] = "ML-KEM-768"
    return header


def _pack(mode_id: int, c_rsa: bytes, c_mlkem: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if len(c_rsa) > 65535 or len(c_mlkem) > 65535 or len(nonce) > 255:
        raise ValueError("field too large for HXM1 binary v1")
    prefix = struct.pack(
        ">4sBBHHBI",
        MAGIC,
        VERSION,
        mode_id,
        len(c_rsa),
        len(c_mlkem),
        len(nonce),
        len(ciphertext),
    )
    return prefix + c_rsa + c_mlkem + nonce + ciphertext

#######################################################################
def _unpack(package: bytes) -> tuple[int, bytes, bytes, bytes, bytes]:

    prefix_len = struct.calcsize(">4sBBHHBI")
    if len(package) < prefix_len:
        raise ValueError("truncated HXM1 package")
    magic, version, mode_id, c_rsa_len, c_mlkem_len, nonce_len, ciphertext_len = struct.unpack(
        ">4sBBHHBI", package[:prefix_len]
    )
    if magic != MAGIC or version != VERSION or mode_id not in MODE_NAMES:
        raise ValueError("unsupported HXM1 package")
    offset = prefix_len
    c_rsa = package[offset : offset + c_rsa_len]
    offset += c_rsa_len
    c_mlkem = package[offset : offset + c_mlkem_len]
    offset += c_mlkem_len
    nonce = package[offset : offset + nonce_len]
    offset += nonce_len
    ciphertext = package[offset : offset + ciphertext_len]
    offset += ciphertext_len

    if offset != len(package):
        raise ValueError("invalid HXM1 package length")

    # Strict component validation
    if len(nonce) != NONCE_LEN:
        raise ValueError("invalid nonce length")

    if len(ciphertext) < 16:
        raise ValueError("invalid AEAD ciphertext length")
    
    if mode_id == MODE_RSA_ONLY:
        if len(c_rsa) != 384:
            raise ValueError("invalid RSA-KEM ciphertext length")
        if len(c_mlkem) != 0:
            raise ValueError("unexpected ML-KEM component in RSA-only mode")

    elif mode_id == MODE_MLKEM_ONLY:
        if len(c_rsa) != 0:
            raise ValueError("unexpected RSA component in ML-KEM-only mode")
        if len(c_mlkem) != 1088:
            raise ValueError("invalid ML-KEM ciphertext length")

    elif mode_id == MODE_HYBRID:
        if len(c_rsa) != 384:
            raise ValueError("invalid RSA-KEM ciphertext length")
        if len(c_mlkem) != 1088:
            raise ValueError("invalid ML-KEM ciphertext length")

    return mode_id, c_rsa, c_mlkem, nonce, ciphertext

def package_info(package: bytes) -> dict[str, Any]:
    mode_id, c_rsa, c_mlkem, nonce, ciphertext = _unpack(package)
    return {
        "format": "HXM1 binary v1",
        "version": VERSION,
        "mode_id": mode_id,
        "mode": MODE_NAMES[mode_id],
        "c_rsa_bytes": len(c_rsa),
        "c_mlkem_bytes": len(c_mlkem),
        "nonce_bytes": len(nonce),
        "ciphertext_and_tag_bytes": len(ciphertext),
        "total_bytes": len(package),
    }


def encrypt(mode: str, public_key: PublicKeyBundle, plaintext: bytes, aad: bytes = b"") -> bytes:
    mode_id = MODE_BY_NAME[mode]
    if mode_id == MODE_RSA_ONLY:
        return encrypt_rsa_only(public_key, plaintext, aad)
    if mode_id == MODE_MLKEM_ONLY:
        return encrypt_mlkem_only(public_key, plaintext, aad)
    if mode_id == MODE_HYBRID:
        return encrypt_hybrid(public_key, plaintext, aad)
    raise ValueError(f"unsupported mode: {mode}")


def decrypt(mode: str, private_key: PrivateKeyBundle, package: bytes, aad: bytes = b"") -> bytes:
    mode_id = MODE_BY_NAME[mode]
    if mode_id == MODE_RSA_ONLY:
        return decrypt_rsa_only(private_key, package, aad)
    if mode_id == MODE_MLKEM_ONLY:
        return decrypt_mlkem_only(private_key, package, aad)
    if mode_id == MODE_HYBRID:
        return decrypt_hybrid(private_key, package, aad)
    raise ValueError(f"unsupported mode: {mode}")


def _rsa_public_key_bytes(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,)


def _rsa_private_key_bytes(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),)


def _load_rsa_public_key(data: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected RSA public key")
    
    return key


def _load_rsa_private_key(data: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected RSA private key")
    return key


@dataclass(frozen=True)
class PublicKeyBundle:
    rsa_public_pem: bytes
    mlkem_public_key: bytes

    def to_json(self) -> str:
        return json.dumps(
            {
                "rsa_public_pem": _b64(self.rsa_public_pem),
                "mlkem_public_key": _b64(self.mlkem_public_key),
            },
            sort_keys=True, )


    @classmethod
    def from_json(cls, data: str) -> "PublicKeyBundle":
        obj = json.loads(data)
        return cls(
            rsa_public_pem=_unb64(obj["rsa_public_pem"]),
            mlkem_public_key=_unb64(obj["mlkem_public_key"]),
        )


@dataclass(frozen=True)
class PrivateKeyBundle:
    rsa_private_pem: bytes
    mlkem_secret_key: bytes

    def to_json(self) -> str:
        return json.dumps(
            {
                "rsa_private_pem": _b64(self.rsa_private_pem),
                "mlkem_secret_key": _b64(self.mlkem_secret_key),
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, data: str) -> "PrivateKeyBundle":
        obj = json.loads(data)
        return cls(
            rsa_private_pem=_unb64(obj["rsa_private_pem"]),
            mlkem_secret_key=_unb64(obj["mlkem_secret_key"]),
        )


def _require_rsa3072(rsa_bits: int) -> None:
    if rsa_bits != 3072:
        raise ValueError("HXM1 requires RSA-3072 keys")


def generate_keypair(rsa_bits: int = 3072) -> tuple[PublicKeyBundle, PrivateKeyBundle]:
    _require_rsa3072(rsa_bits)
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    mlkem_public, mlkem_secret = ML_KEM_768.keygen()
    return (
        PublicKeyBundle(
            rsa_public_pem=_rsa_public_key_bytes(rsa_private.public_key()),
            mlkem_public_key=mlkem_public,
        ),
        PrivateKeyBundle(
            rsa_private_pem=_rsa_private_key_bytes(rsa_private),
            mlkem_secret_key=mlkem_secret,
        ),
    )


def encrypt_hybrid(public_key: PublicKeyBundle, plaintext: bytes, aad: bytes = b"") -> bytes:
    rsa_public = _load_rsa_public_key(public_key.rsa_public_pem)
    _require_rsa3072(rsa_public.key_size)
    rsa_secret, c_rsa = _rsa_kem_encaps(rsa_public)
    mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    header = _header(MODE_HYBRID, rsa_public.key_size)
    key = _derive_key([rsa_secret, mlkem_secret], header, aad)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _canonical_json(header) + aad)
    return _pack(MODE_HYBRID, c_rsa, c_mlkem, nonce, ciphertext)


def decrypt_hybrid(private_key: PrivateKeyBundle, package: bytes, aad: bytes = b"") -> bytes:
    mode_id, c_rsa, c_mlkem, nonce, ciphertext = _unpack(package)
    if mode_id != MODE_HYBRID:
        raise ValueError("wrong HXM1 mode")
    rsa_private = _load_rsa_private_key(private_key.rsa_private_pem)
    header = _header(MODE_HYBRID, rsa_private.key_size)
    rsa_secret = _rsa_kem_decaps(rsa_private, c_rsa)
    mlkem_secret = ML_KEM_768.decaps(private_key.mlkem_secret_key, c_mlkem)
    key = _derive_key([rsa_secret, mlkem_secret], header, aad)
    return AESGCM(key).decrypt(nonce, ciphertext, _canonical_json(header) + aad)


def encrypt_rsa_only(public_key: PublicKeyBundle, plaintext: bytes, aad: bytes = b"") -> bytes:
    rsa_public = _load_rsa_public_key(public_key.rsa_public_pem)
    _require_rsa3072(rsa_public.key_size)
    rsa_secret, c_rsa = _rsa_kem_encaps(rsa_public)
    header = _header(MODE_RSA_ONLY, rsa_public.key_size)
    key = _derive_key([rsa_secret], header, aad)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _canonical_json(header) + aad)
    return _pack(MODE_RSA_ONLY, c_rsa, b"", nonce, ciphertext)


def decrypt_rsa_only(private_key: PrivateKeyBundle, package: bytes, aad: bytes = b"") -> bytes:
    mode_id, c_rsa, c_mlkem, nonce, ciphertext = _unpack(package)
    if mode_id != MODE_RSA_ONLY or c_mlkem:
        raise ValueError("wrong HXM1 mode")
    rsa_private = _load_rsa_private_key(private_key.rsa_private_pem)
    header = _header(MODE_RSA_ONLY, rsa_private.key_size)
    rsa_secret = _rsa_kem_decaps(rsa_private, c_rsa)
    key = _derive_key([rsa_secret], header, aad)
    return AESGCM(key).decrypt(nonce, ciphertext, _canonical_json(header) + aad)


def encrypt_mlkem_only(public_key: PublicKeyBundle, plaintext: bytes, aad: bytes = b"") -> bytes:

    mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    header = _header(MODE_MLKEM_ONLY)
    key = _derive_key([mlkem_secret], header, aad)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _canonical_json(header) + aad)

    return _pack(MODE_MLKEM_ONLY, b"", c_mlkem, nonce, ciphertext)


def decrypt_mlkem_only(private_key: PrivateKeyBundle, package: bytes, aad: bytes = b"") -> bytes:
    mode_id, c_rsa, c_mlkem, nonce, ciphertext = _unpack(package)
    if mode_id != MODE_MLKEM_ONLY or c_rsa:
        raise ValueError("wrong HXM1 mode")
    
    header = _header(MODE_MLKEM_ONLY)
    mlkem_secret = ML_KEM_768.decaps(private_key.mlkem_secret_key, c_mlkem)
    key = _derive_key([mlkem_secret], header, aad)

    return AESGCM(key).decrypt(nonce, ciphertext, _canonical_json(header) + aad)
