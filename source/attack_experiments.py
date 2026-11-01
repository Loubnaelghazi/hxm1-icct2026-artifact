from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag

from hybrid_rsa_mlkem import MODE_HYBRID, decrypt, encrypt, generate_keypair
from run_experiments import _tamper_binary
from vulnerable_baselines import (
    attacker_strip_pq_from_naive_c,
    decrypt_naive_a_header_not_authenticated,
    decrypt_naive_b_decryptor_mode,
    decrypt_naive_c_optional_pq,
    decrypt_naive_d_aad_not_bound,
    encrypt_naive_a_header_not_authenticated,
    encrypt_naive_b_decryptor_mode,
    encrypt_naive_c_optional_pq, encrypt_naive_d_aad_not_bound,tamper_aad_label_naive_d,tamper_header_alg_naive_a,tamper_version_naive_a,)

# HXM1's design says a manipulated package must be rejected via exactly one of
# these two paths: the strict binary parser / mode check in `_unpack` and the
# mode dispatchers (which raise ValueError), or AEAD authentication failure
# (which raises InvalidTag). Any other exception type escaping a decrypt call
# is a sign of an implementation bug, not a demonstrated security property, so
# it must never be silently folded into "REJECTED".


EXPECTED_SECURITY_REJECTIONS = (ValueError, InvalidTag)


def _status(condition: bool) -> str:
    return "VULNERABLE" if condition else "REJECTED"


def _attempt_decrypt(fn: Callable[[], bytes]) -> tuple[str, str]:
    """Run a decryption attempt and classify the outcome.

    Returns (status, detail):
      - "REJECTED": failed via an expected, documented security check
        (ValueError from the strict parser/mode checks, or InvalidTag from
        AEAD authentication failure).
      - "VULNERABLE": decryption succeeded and returned plaintext.
      - "UNEXPECTED_ERROR": failed, but not via one of the exception types
        HXM1's design claims to reject through. Reported separately instead
        of being counted as a security success, since it may indicate a
        parsing bug rather than an authenticated rejection.
    """
    try:
        fn()
    except EXPECTED_SECURITY_REJECTIONS as exc:
        return "REJECTED", f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 - intentionally broad, but reported, not hidden
        return "UNEXPECTED_ERROR", f"{type(exc).__name__}: {exc}"
    else:
        return "VULNERABLE", "decryption succeeded and returned plaintext"


def _tamper_hxm1_version(package: bytes, version: int = 0) -> bytes:
    data = bytearray(package)
    data[4] = version
    return bytes(data)


# HXM1 binary header layout (see hybrid_rsa_mlkem._pack / struct format
# ">4sBBHHBI"): magic(4) version(1) mode(1) c_rsa_len(2) c_mlkem_len(2)
# nonce_len(1) ciphertext_len(4).
_LENGTH_FIELD_OFFSETS = {
    "c_rsa_len": (6, 2),
    "c_mlkem_len": (8, 2),
    "nonce_len": (10, 1),
    "ciphertext_len": (11, 4),
}


def _tamper_hxm1_field_length(package: bytes, field: str, length: int) -> bytes:
    """Corrupt a single length field in the HXM1 binary header without
    touching the actual bytes that follow it, so the parser sees a header
    that disagrees with the real package layout."""
    start, size = _LENGTH_FIELD_OFFSETS[field]
    max_value = (1 << (size * 8)) - 1
    if not 0 <= length <= max_value:
        raise ValueError(f"length {length} does not fit in {size}-byte field")
    data = bytearray(package)
    data[start : start + size] = length.to_bytes(size, "big")
    return bytes(data)


def _remove_hxm1_mlkem_component(package: bytes) -> bytes:
    """Reframe a hybrid package with its ML-KEM bytes physically removed."""
    header_format = ">4sBBHHBI"
    prefix_len = struct.calcsize(header_format)
    magic, version, mode_id, c_rsa_len, c_mlkem_len, nonce_len, ciphertext_len = struct.unpack(
        header_format, package[:prefix_len]
    )
    if mode_id != MODE_HYBRID or c_rsa_len != 384 or c_mlkem_len != 1088:
        raise ValueError("expected a well-formed HXM1 hybrid package")

    c_rsa_start = prefix_len
    c_mlkem_start = c_rsa_start + c_rsa_len
    nonce_start = c_mlkem_start + c_mlkem_len
    ciphertext_start = nonce_start + nonce_len
    c_rsa = package[c_rsa_start:c_mlkem_start]
    nonce = package[nonce_start:ciphertext_start]
    ciphertext = package[ciphertext_start:ciphertext_start + ciphertext_len]
    if len(c_rsa) != c_rsa_len or len(nonce) != nonce_len or len(ciphertext) != ciphertext_len:
        raise ValueError("malformed HXM1 package while removing ML-KEM component")

    # Keep hybrid mode, remove the ML-KEM field bytes, and encode the resulting
    # field lengths consistently so parsing reaches hybrid component validation.
    prefix = struct.pack(
        header_format, magic, version, mode_id, c_rsa_len, 0, nonce_len, ciphertext_len
    )
    return prefix + c_rsa + nonce + ciphertext


def _attempt_missing_mlkem_decrypt(fn: Callable[[], bytes]) -> tuple[str, str]:
    """Require the parser's specific missing-ML-KEM rejection."""
    try:
        fn()
    except ValueError as exc:
        if str(exc) == "invalid ML-KEM ciphertext length":
            return "REJECTED", f"ValueError: {exc}"
        return "UNEXPECTED_ERROR", f"ValueError: {exc}"
    except Exception as exc:  # noqa: BLE001 - classify unexpected behavior explicitly
        return "UNEXPECTED_ERROR", f"{type(exc).__name__}: {exc}"
    return "VULNERABLE", "decryption succeeded and returned plaintext"


def run_attacks() -> dict[str, object]:
    public_key, private_key = generate_keypair()
    plaintext = b"conference-grade migration attack demonstration"
    aad = b"recipient=alice;document=paper"
    rows = []

    # Naive-A: metadata is not authenticated, so attacker can alter it without invalidating ciphertext.
    package_a = encrypt_naive_a_header_not_authenticated(public_key, plaintext, mode="hybrid")
    tampered_a = tamper_header_alg_naive_a(package_a)
    recovered = decrypt_naive_a_header_not_authenticated(private_key, tampered_a)
    rows.append(
        {
            "failure": "unauthenticated header modification",
            "target": "Naive-A",
            "attack_result": _status(recovered == plaintext),
            "expected_defense": "metadata changes must invalidate package",
        }
    )

    # Naive-B: decryptor chooses the mode externally and accepts RSA-only decryption of a hybrid package.
    package_b = encrypt_naive_b_decryptor_mode(public_key, plaintext)
    recovered_b = decrypt_naive_b_decryptor_mode(private_key, package_b, requested_mode="rsa")
    rows.append(
        {
            "failure": "decryptor-selected downgrade",
            "target": "Naive-B",
            "attack_result": _status(recovered_b == plaintext),
            "expected_defense": "ciphertext mode must be authenticated and enforced",
        }
    )

    # Naive-C: optional PQ component allows an attacker-originated RSA fallback package.
    package_c = encrypt_naive_c_optional_pq(public_key, plaintext)
    stripped_c = attacker_strip_pq_from_naive_c(public_key, package_c, plaintext)
    recovered_c = decrypt_naive_c_optional_pq(private_key, stripped_c)
    rows.append(
        {
            "failure": "component stripping / RSA fallback",
            "target": "Naive-C",
            "attack_result": _status(recovered_c == plaintext),
            "expected_defense": "hybrid profile must require both KEM components",
        }
    )

    # Naive-A also accepts version rollback because version metadata is not authenticated or enforced.
    rollback_a = tamper_version_naive_a(package_a, new_version=0)
    recovered_rollback = decrypt_naive_a_header_not_authenticated(private_key, rollback_a)
    rows.append(
        {
            "failure": "version rollback",
            "target": "Naive-A",
            "attack_result": _status(recovered_rollback == plaintext),
            "expected_defense": "unsupported versions must be rejected and authenticated",
        }
    )

    # Naive-D records AAD-like context in metadata but does not bind it to KDF or AEAD.
    package_d = encrypt_naive_d_aad_not_bound(public_key, plaintext, aad)
    rebound_d = tamper_aad_label_naive_d(package_d, "recipient=bob;document=paper")
    recovered_d = decrypt_naive_d_aad_not_bound(private_key, rebound_d, b"recipient=bob;document=paper")
    rows.append(
        {
            "failure": "recipient/AAD misbinding",
            "target": "Naive-D",
            "attack_result": _status(recovered_d == plaintext),
            "expected_defense": "recipient and AAD context must be authenticated",
        }
    )

    # HXM1 rejects the same classes via authenticated mode/header and strict parsing.
    hxm1 = encrypt("hybrid", public_key, plaintext, aad)

    status, detail = _attempt_decrypt(lambda: decrypt("hybrid", private_key, _tamper_binary(hxm1, "header"), aad))
    rows.append(
        {
            "failure": "unauthenticated header modification",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "metadata changes must invalidate package",
        }
    )

    status, detail = _attempt_decrypt(lambda: decrypt("rsa", private_key, hxm1, aad))
    rows.append(
        {
            "failure": "decryptor-selected downgrade",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "ciphertext mode must be authenticated and enforced",
        }
    )

    status, detail = _attempt_decrypt(lambda: decrypt("hybrid", private_key, _tamper_binary(hxm1, "c_mlkem"), aad))
    rows.append(
        {
            "failure": "ML-KEM ciphertext bit modification",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "authentication must reject a modified ML-KEM ciphertext",
        }
    )

    stripped_mlkem = _remove_hxm1_mlkem_component(hxm1)
    status, detail = _attempt_missing_mlkem_decrypt(
        lambda: decrypt("hybrid", private_key, stripped_mlkem, aad)
    )
    rows.append(
        {
            "failure": "missing ML-KEM component",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "hybrid parser must reject an invalid ML-KEM ciphertext length",
        }
    )

    status, detail = _attempt_decrypt(lambda: decrypt("hybrid", private_key, _tamper_hxm1_version(hxm1), aad))
    rows.append(
        {
            "failure": "version rollback",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "unsupported versions must be rejected and authenticated",
        }
    )

    status, detail = _attempt_decrypt(lambda: decrypt("hybrid", private_key, hxm1, b"recipient=bob;document=paper"))
    rows.append(
        {
            "failure": "recipient/AAD misbinding",
            "target": "HXM1",
            "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
            "detail": detail,
            "expected_defense": "recipient and AAD context must be authenticated",
        }
    )

    # Malformed length field: exercise several corruption modes rather than a single arbitrary value.
    length_scenarios = {
        "c_rsa_len=0": ("c_rsa_len", 0),
        "c_rsa_len=1 (too small)": ("c_rsa_len", 1),
        "c_rsa_len=max_uint16 (too large)": ("c_rsa_len", 0xFFFF),
        "c_mlkem_len=0": ("c_mlkem_len", 0),
        "nonce_len=0": ("nonce_len", 0),
    }
    for scenario_name, (field, bad_length) in length_scenarios.items():
        status, detail = _attempt_decrypt(
            lambda field=field, bad_length=bad_length: decrypt(
                "hybrid", private_key, _tamper_hxm1_field_length(hxm1, field, bad_length), aad
            )
        )
        rows.append(
            {
                "failure": f"malformed length field ({scenario_name})",
                "target": "HXM1",
                "attack_result": "EXPECTED_REJECTION" if status == "REJECTED" else status,
                "detail": detail,
                "expected_defense": "strict parser must reject inconsistent field lengths",
            }
        )

    return {"rows": rows}


def write_markdown(results: dict[str, object], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "attack_results.md"
    lines = [
        "# Migration-Layer Attack Experiments",
        "",
        "| Failure class | Target | Result | Detail | Expected defense |",
        "|---|---|---:|---|---|",
    ]
    for row in results["rows"]:
        lines.append(
            f"| {row['failure']} | {row['target']} | {row['attack_result']} | "
            f"{row.get('detail', '')} | {row['expected_defense']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output_dir / "attack_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return path


def main() -> None:
    output_dir = Path("results_attacks")
    results = run_attacks()
    path = write_markdown(results, output_dir)
    unexpected = [row for row in results["rows"] if row["target"] == "HXM1" and row["attack_result"] != "EXPECTED_REJECTION"]
    if unexpected:
        print(
            f"FAIL: {len(unexpected)} HXM1 scenario(s) did not produce the expected rejection. "
            "Inspect attack_results.md before reporting the experiments."
        )
    print(f"wrote {path}")
    if unexpected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
