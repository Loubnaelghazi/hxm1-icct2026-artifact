from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hybrid_rsa_mlkem import (
    AES_KEY_LEN,
    NONCE_LEN,
    PrivateKeyBundle,
    PublicKeyBundle,
    _canonical_json,
    _derive_key,
    _load_rsa_private_key,
    _load_rsa_public_key,
    _rsa_kem_decaps,
    _rsa_kem_encaps,
)
from kyber_py.ml_kem import ML_KEM_768


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _weak_key(secret: bytes) -> bytes:
    return secret[:AES_KEY_LEN]


def encrypt_naive_a_header_not_authenticated(public_key: PublicKeyBundle, plaintext: bytes, mode: str = "hybrid") -> bytes:
    rsa_secret = b""
    mlkem_secret = b""
    c_rsa = b""
    c_mlkem = b""
    if mode in ("rsa", "hybrid"):
        rsa_secret, c_rsa = _rsa_kem_encaps(_load_rsa_public_key(public_key.rsa_public_pem))
    if mode in ("mlkem", "hybrid"):
        mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    header = {"version": 1, "mode": mode, "alg": "naive-a"}
    key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-a"}, b"")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return _canonical_json(
        {
            "header": header,
            "c_rsa": _b64(c_rsa),
            "c_mlkem": _b64(c_mlkem),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
    )


def decrypt_naive_a_header_not_authenticated(private_key: PrivateKeyBundle, package: bytes) -> bytes:
    obj = json.loads(package)
    mode = obj["header"]["mode"]
    secrets = []
    if mode in ("rsa", "hybrid"):
        secrets.append(_rsa_kem_decaps(_load_rsa_private_key(private_key.rsa_private_pem), _unb64(obj["c_rsa"])))
    if mode in ("mlkem", "hybrid"):
        secrets.append(ML_KEM_768.decaps(private_key.mlkem_secret_key, _unb64(obj["c_mlkem"])))
    key = _derive_key(secrets, {"alg": "naive-a"}, b"")
    return AESGCM(key).decrypt(_unb64(obj["nonce"]), _unb64(obj["ciphertext"]), None)


def encrypt_naive_b_decryptor_mode(public_key: PublicKeyBundle, plaintext: bytes) -> bytes:
    rsa_secret, c_rsa = _rsa_kem_encaps(_load_rsa_public_key(public_key.rsa_public_pem))
    mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    rsa_key = _weak_key(rsa_secret)
    hybrid_key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-b"}, b"")
    nonce = os.urandom(NONCE_LEN)
    return _canonical_json(
        {
            "header": {"version": 1, "claimed_mode": "hybrid", "alg": "naive-b"},
            "c_rsa": _b64(c_rsa),
            "c_mlkem": _b64(c_mlkem),
            "nonce": _b64(nonce),
            "rsa_ciphertext": _b64(AESGCM(rsa_key).encrypt(nonce, plaintext, None)),
            "hybrid_ciphertext": _b64(AESGCM(hybrid_key).encrypt(nonce, plaintext, None)),
        }
    )


def decrypt_naive_b_decryptor_mode(private_key: PrivateKeyBundle, package: bytes, requested_mode: str) -> bytes:
    obj = json.loads(package)
    rsa_secret = _rsa_kem_decaps(_load_rsa_private_key(private_key.rsa_private_pem), _unb64(obj["c_rsa"]))
    if requested_mode == "rsa":
        return AESGCM(_weak_key(rsa_secret)).decrypt(
            _unb64(obj["nonce"]), _unb64(obj["rsa_ciphertext"]), None
        )
    if requested_mode == "hybrid":
        mlkem_secret = ML_KEM_768.decaps(private_key.mlkem_secret_key, _unb64(obj["c_mlkem"]))
        key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-b"}, b"")
        return AESGCM(key).decrypt(_unb64(obj["nonce"]), _unb64(obj["hybrid_ciphertext"]), None)
    raise ValueError("unsupported mode")


def encrypt_naive_c_optional_pq(public_key: PublicKeyBundle, plaintext: bytes) -> bytes:
    rsa_secret, c_rsa = _rsa_kem_encaps(_load_rsa_public_key(public_key.rsa_public_pem))
    mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    header = {"version": 1, "mode": "hybrid-if-present", "alg": "naive-c"}
    key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-c", "mode": "hybrid-if-present"}, b"")
    nonce = os.urandom(NONCE_LEN)
    return _canonical_json(
        {
            "header": header,
            "c_rsa": _b64(c_rsa),
            "c_mlkem": _b64(c_mlkem),
            "nonce": _b64(nonce),
            "ciphertext": _b64(AESGCM(key).encrypt(nonce, plaintext, None)),
        }
    )


def decrypt_naive_c_optional_pq(private_key: PrivateKeyBundle, package: bytes) -> bytes:
    obj = json.loads(package)
    secrets = [_rsa_kem_decaps(_load_rsa_private_key(private_key.rsa_private_pem), _unb64(obj["c_rsa"]))]
    if obj.get("c_mlkem"):
        secrets.append(ML_KEM_768.decaps(private_key.mlkem_secret_key, _unb64(obj["c_mlkem"])))
    header_for_key: dict[str, Any] = {"alg": "naive-c", "mode": "hybrid-if-present"}
    if not obj.get("c_mlkem"):
        header_for_key["mode"] = "rsa-fallback"
    key = _derive_key(secrets, header_for_key, b"")
    return AESGCM(key).decrypt(_unb64(obj["nonce"]), _unb64(obj["ciphertext"]), None)


def attacker_strip_pq_from_naive_c(public_key: PublicKeyBundle, package: bytes, plaintext: bytes) -> bytes:
    obj = json.loads(package)
    rsa_secret, c_rsa = _rsa_kem_encaps(_load_rsa_public_key(public_key.rsa_public_pem))
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key([rsa_secret], {"alg": "naive-c", "mode": "rsa-fallback"}, b"")
    obj["header"]["mode"] = "rsa-fallback"
    obj["c_rsa"] = _b64(c_rsa)
    obj["c_mlkem"] = ""
    obj["nonce"] = _b64(nonce)
    obj["ciphertext"] = _b64(AESGCM(key).encrypt(nonce, plaintext, None))
    return _canonical_json(obj)


def tamper_header_alg_naive_a(package: bytes, new_alg: str = "rsa-only") -> bytes:
    obj = json.loads(package)
    obj["header"]["alg"] = new_alg
    obj["header"]["note"] = "modified without invalidating ciphertext"
    return _canonical_json(obj)


def encrypt_naive_d_aad_not_bound(public_key: PublicKeyBundle, plaintext: bytes, aad: bytes) -> bytes:
    rsa_secret, c_rsa = _rsa_kem_encaps(_load_rsa_public_key(public_key.rsa_public_pem))
    mlkem_secret, c_mlkem = ML_KEM_768.encaps(public_key.mlkem_public_key)
    header = {"version": 1, "mode": "hybrid", "alg": "naive-d", "aad_label": aad.decode("utf-8", "ignore")}
    key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-d"}, b"")
    nonce = os.urandom(NONCE_LEN)
    return _canonical_json(
        {
            "header": header,
            "c_rsa": _b64(c_rsa),
            "c_mlkem": _b64(c_mlkem),
            "nonce": _b64(nonce),
            "ciphertext": _b64(AESGCM(key).encrypt(nonce, plaintext, None)),
        }
    )


def decrypt_naive_d_aad_not_bound(private_key: PrivateKeyBundle, package: bytes, aad: bytes) -> bytes:
    obj = json.loads(package)
    rsa_secret = _rsa_kem_decaps(_load_rsa_private_key(private_key.rsa_private_pem), _unb64(obj["c_rsa"]))
    mlkem_secret = ML_KEM_768.decaps(private_key.mlkem_secret_key, _unb64(obj["c_mlkem"]))
    key = _derive_key([rsa_secret, mlkem_secret], {"alg": "naive-d"}, b"")
    return AESGCM(key).decrypt(_unb64(obj["nonce"]), _unb64(obj["ciphertext"]), None)


def tamper_aad_label_naive_d(package: bytes, new_label: str) -> bytes:
    obj = json.loads(package)
    obj["header"]["aad_label"] = new_label
    return _canonical_json(obj)


def tamper_version_naive_a(package: bytes, new_version: int = 0) -> bytes:
    obj = json.loads(package)
    obj["header"]["version"] = new_version
    obj["header"]["legacy_accepted"] = True
    return _canonical_json(obj)
