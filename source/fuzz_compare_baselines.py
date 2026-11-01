"""
Comparative fuzzing: HXM1 vs the four naive baselines.

Two complementary experiments are run for each system:

1. RANDOM ROBUSTNESS (comparable to fuzz_hxm1_parser.py): random byte-level
   mutation / truncation / extension applied to a valid package. Measures
   whether corruption is safely rejected, causes an unexpected crash, or
   -- worst case -- is silently accepted.

2. TARGETED METADATA TAMPERING: reuses the existing tamper_* / attacker_*
   helpers from vulnerable_baselines.py, which is the actual attack class
   the paper is about (unauthenticated header/mode/version/AAD). This is
   NOT the same thing as random fuzzing and is reported separately.

Run: python fuzz_compare_baselines.py
"""
import json
import os
import random
import time
from collections import Counter

from cryptography.exceptions import InvalidTag

from hybrid_rsa_mlkem import generate_keypair, encrypt_hybrid, decrypt_hybrid
from vulnerable_baselines import (
    encrypt_naive_a_header_not_authenticated,
    decrypt_naive_a_header_not_authenticated,
    encrypt_naive_b_decryptor_mode,
    decrypt_naive_b_decryptor_mode,
    encrypt_naive_c_optional_pq,
    decrypt_naive_c_optional_pq,
    encrypt_naive_d_aad_not_bound,
    decrypt_naive_d_aad_not_bound,
    tamper_header_alg_naive_a,
    tamper_version_naive_a,
    tamper_aad_label_naive_d,
    attacker_strip_pq_from_naive_c,
)

# Exceptions we consider a "safe, expected rejection" for byte-soup input.
# JSONDecodeError is a subclass of ValueError, binascii.Error too in py3,
# so ValueError already covers most malformed-JSON / bad-base64 cases.
SAFE_REJECT_TYPES = (ValueError, InvalidTag, KeyError, UnicodeDecodeError)

PLAINTEXT = b"fuzzing reference message for baseline comparison"
AAD = b"fuzz-aad"


def mutate(package: bytes, rng: random.Random) -> bytes:
    data = bytearray(package)
    for _ in range(rng.randint(1, 4)):
        pos = rng.randrange(len(data))
        original = data[pos]
        new_byte = rng.randrange(256)
        while new_byte == original:
            new_byte = rng.randrange(256)
        data[pos] = new_byte
    return bytes(data)


def truncate_or_extend(package: bytes, rng: random.Random) -> bytes:
    choice = rng.random()
    if choice < 0.4:
        cut = rng.randrange(1, len(package))
        return package[:cut]
    elif choice < 0.8:
        return package + os.urandom(rng.randint(1, 64))
    return mutate(package, rng)


def run_random_fuzz(name, decrypt_fn, package: bytes, n_trials: int, seed: int) -> dict:
    rng = random.Random(seed)
    outcomes = Counter()
    accepted_examples = []
    for _ in range(n_trials):
        mutant = truncate_or_extend(package, rng)
        try:
            recovered = decrypt_fn(mutant)
            if recovered == PLAINTEXT:
                outcomes["ACCEPTED_CORRECT_PLAINTEXT"] += 1
                accepted_examples.append(mutant[:80])
            else:
                outcomes["ACCEPTED_WRONG_PLAINTEXT"] += 1
                accepted_examples.append(mutant[:80])
        except SAFE_REJECT_TYPES as exc:
            outcomes[f"SAFE_REJECT_{type(exc).__name__}"] += 1
        except Exception as exc:  # noqa: BLE001
            outcomes[f"UNEXPECTED_{type(exc).__name__}"] += 1
    return {"system": name, "n_trials": n_trials, "outcomes": dict(outcomes),
             "accepted_examples": accepted_examples[:3]}


def print_report(report: dict) -> None:
    print(f"\n== {report['system']} (n={report['n_trials']}) ==")
    for k, v in sorted(report["outcomes"].items(), key=lambda x: -x[1]):
        pct = 100 * v / report["n_trials"]
        print(f"  {k}: {v} ({pct:.2f}%)")
    if report["accepted_examples"]:
        print("  !!! packages accepted despite corruption (examples truncated):")
        for ex in report["accepted_examples"]:
            print(f"    {ex!r}")


#change #seed here 

def main():
    N = 3000
    SEED = 42
    public_key, private_key = generate_keypair()

    reports = []

    # --- HXM1 (reference) ---
    pkg_hxm1 = encrypt_hybrid(public_key, PLAINTEXT, AAD)
    reports.append(run_random_fuzz(
        "HXM1", lambda m: decrypt_hybrid(private_key, m, AAD), pkg_hxm1, N, SEED))

    # --- Naive-A: header not authenticated ---
    pkg_a = encrypt_naive_a_header_not_authenticated(public_key, PLAINTEXT, mode="hybrid")
    reports.append(run_random_fuzz(
        "Naive-A", lambda m: decrypt_naive_a_header_not_authenticated(private_key, m), pkg_a, N, SEED))

    # --- Naive-B: decryptor picks the mode ---
    pkg_b = encrypt_naive_b_decryptor_mode(public_key, PLAINTEXT)
    reports.append(run_random_fuzz(
        "Naive-B", lambda m: decrypt_naive_b_decryptor_mode(private_key, m, "hybrid"), pkg_b, N, SEED))

    # --- Naive-C: optional PQ / silent RSA fallback ---
    pkg_c = encrypt_naive_c_optional_pq(public_key, PLAINTEXT)
    reports.append(run_random_fuzz(
        "Naive-C", lambda m: decrypt_naive_c_optional_pq(private_key, m), pkg_c, N, SEED))

    # --- Naive-D: AAD not bound ---
    pkg_d = encrypt_naive_d_aad_not_bound(public_key, PLAINTEXT, AAD)
    reports.append(run_random_fuzz(
        "Naive-D", lambda m: decrypt_naive_d_aad_not_bound(private_key, m, AAD), pkg_d, N, SEED))

    print("=" * 60)
    print("PART 1 -- RANDOM BYTE-LEVEL ROBUSTNESS (n={} per system)".format(N))
    print("=" * 60)
    for r in reports:
        print_report(r)

    # PART 2: targeted metadata tampering (the paper's actual attack

    print("\n" + "=" * 60)
    print("PART 2 -- TARGETED METADATA TAMPERING (structured attacks)")
    print("=" * 60)

    targeted = []

    # Naive-A: flip the declared algorithm in the header; ciphertext/tag
    # are untouched, and naive-a's key derivation never reads the header,
    # so decryption still succeeds -- silently accepting a relabeled package.


    tampered_a = tamper_header_alg_naive_a(pkg_a, new_alg="rsa-only-claimed")
    try:
        out = decrypt_naive_a_header_not_authenticated(private_key, tampered_a)
        status = "ACCEPTED (plaintext correct)" if out == PLAINTEXT else "ACCEPTED (wrong plaintext)"
    except Exception as exc:
        status = f"REJECTED ({type(exc).__name__})"
    targeted.append(("Naive-A: header.alg tampered", status))

    # Naive-A: silent version rollback.
    tampered_v = tamper_version_naive_a(pkg_a, new_version=0)
    try:
        out = decrypt_naive_a_header_not_authenticated(private_key, tampered_v)
        status = "ACCEPTED (plaintext correct)" if out == PLAINTEXT else "ACCEPTED (wrong plaintext)"
    except Exception as exc:
        status = f"REJECTED ({type(exc).__name__})"
    targeted.append(("Naive-A: version rollback", status))

    # Naive-C: attacker strips the PQ component and forces RSA-only fallback.
    tampered_c = attacker_strip_pq_from_naive_c(public_key, pkg_c, PLAINTEXT)
    try:
        out = decrypt_naive_c_optional_pq(private_key, tampered_c)
        status = "ACCEPTED (plaintext correct)" if out == PLAINTEXT else "ACCEPTED (wrong plaintext)"
    except Exception as exc:
        status = f"REJECTED ({type(exc).__name__})"
    targeted.append(("Naive-C: PQ component stripped", status))

    # Naive-D: AAD/context label rebinding without invalidating the tag.
    tampered_d = tamper_aad_label_naive_d(pkg_d, new_label="different-recipient")
    try:
        out = decrypt_naive_d_aad_not_bound(private_key, tampered_d, AAD)
        status = "ACCEPTED (plaintext correct)" if out == PLAINTEXT else "ACCEPTED (wrong plaintext)"
    except Exception as exc:
        status = f"REJECTED ({type(exc).__name__})"
    targeted.append(("Naive-D: AAD label rebinding", status))

    # HXM1 equivalent: try to decrypt under a mismatched AAD (the authenticated
    # control -- should always fail).
    try:
        out = decrypt_hybrid(private_key, pkg_hxm1, b"different-recipient")
        status = "ACCEPTED (plaintext correct)" if out == PLAINTEXT else "ACCEPTED (wrong plaintext)"
    except Exception as exc:
        status = f"REJECTED ({type(exc).__name__})"
    targeted.append(("HXM1: AAD mismatch (control)", status))

    for label, status in targeted:
        print(f"  {label}: {status}")


if __name__ == "__main__":
    main()