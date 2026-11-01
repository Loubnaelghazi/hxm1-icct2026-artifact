"""Fuzz the HXM1 binary parser and preserve replayable per-trial evidence.

The JSONL audit file contains ciphertext inputs and mutation metadata, never
private keys. A separate Scrypt/AES-GCM-encrypted replay-key file is created
outside the project tree (mode 0600 on POSIX) so a recorded trial can be
decrypted again locally. The user supplies its passphrase when creating or
loading the key file.

The seed controls Python's ``random.Random`` choices (branch, cuts, mutation
count, positions, and replacement bytes). It does not control OS randomness
used for RSA/ML-KEM key generation, encapsulation, the AES-GCM nonce, or
trailing extension bytes. Exact original/mutated packages plus the matching
local replay key allow a trial to be replayed despite those random sources.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import stat
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from hybrid_rsa_mlkem import (
    PrivateKeyBundle,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_keypair,
)


EXPECTED_SAFE_REJECTIONS = (ValueError, InvalidTag)
FUZZ_AAD = b"fuzz-aad"
FUZZ_PLAINTEXT = b"fuzzing reference message for HXM1 parser robustness testing"
REPLAY_KEY_MAGIC = b"HXM1-FUZZ-KEY-v1\0"
REPLAY_KEY_AAD = b"HXM1 fuzz local replay key v1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def mutate(package: bytes, rng: random.Random) -> tuple[bytes, dict[str, object]]:
    """Apply 1-4 seeded byte assignments and record every actual assignment."""
    data = bytearray(package)
    n_mutations = rng.randint(1, 4)
    operations = []
    for operation_number in range(1, n_mutations + 1):
        pos = rng.randrange(len(data))
        before = data[pos]
        assigned = rng.randrange(256)
        data[pos] = assigned
        operations.append(
            {
                "operation": operation_number,
                "position": pos,
                "before_byte": before,
                "assigned_byte": assigned,
                "after_byte": data[pos],
                "changed_at_operation": before != data[pos],
            }
        )
    mutant = bytes(data)
    return mutant, {
        "branch": "byte_mutation",
        "operation_count": n_mutations,
        "operations": operations,
        "final_package_changed": mutant != package,
    }


def truncate_or_extend(
    package: bytes, rng: random.Random
) -> tuple[bytes, dict[str, object]]:
    """Preserve the existing 40/40/20 strategy and describe what happened."""
    choice = rng.random()
    if choice < 0.4:
        cut = rng.randrange(1, len(package))
        mutant = package[:cut]
        return mutant, {
            "branch": "truncate",
            "cut_offset": cut,
            "original_length": len(package),
            "mutated_length": len(mutant),
            "final_package_changed": mutant != package,
        }

    if choice < 0.8:
        extra = os.urandom(rng.randint(1, 64))
        mutant = package + extra
        return mutant, {
            "branch": "extend",
            "appended_bytes_base64": _b64(extra),
            "appended_length": len(extra),
            "original_length": len(package),
            "mutated_length": len(mutant),
            "final_package_changed": mutant != package,
            "randomness_note": "appended bytes come from os.urandom and are not seed-controlled",
        }

    return mutate(package, rng)


def classify_success(
    original: bytes, mutant: bytes, recovered: bytes, expected_plaintext: bytes
) -> str:
    """Classify successful decryptions without conflating no-op trials."""
    unchanged = mutant == original
    if unchanged and recovered == expected_plaintext:
        return "UNCHANGED_VALID_PACKAGE"
    if unchanged:
        return "UNCHANGED_ACCEPTED_WRONG_PLAINTEXT"
    if recovered == expected_plaintext:
        return "CHANGED_ACCEPTED_CORRECT"
    return "CHANGED_ACCEPTED_WRONG_PLAINTEXT"


def _test_success_classification() -> None:
    """Small in-file regression check: no-op and changed successes differ."""
    original = b"valid package"
    assert classify_success(original, original, b"plaintext", b"plaintext") == (
        "UNCHANGED_VALID_PACKAGE"
    )
    assert classify_success(original, b"changed package", b"plaintext", b"plaintext") == (
        "CHANGED_ACCEPTED_CORRECT"
    )
    assert classify_success(original, b"changed package", b"other", b"plaintext") == (
        "CHANGED_ACCEPTED_WRONG_PLAINTEXT"
    )


def _check_local_key_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return resolved
    raise ValueError(
        f"replay key must be outside the project tree ({PROJECT_ROOT}) to keep it out of version control"
    )


def _derive_replay_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def _save_local_replay_key(path: Path, private_key: PrivateKeyBundle, passphrase: str) -> Path:
    """Persist the matching private bundle encrypted, separately from JSONL."""
    path = _check_local_key_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_replay_key(passphrase, salt)
    encrypted = AESGCM(key).encrypt(nonce, private_key.to_json().encode("utf-8"), REPLAY_KEY_AAD)
    payload = REPLAY_KEY_MAGIC + salt + nonce + encrypted

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if os.name == "posix":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def _load_local_replay_key(path: Path, passphrase: str) -> PrivateKeyBundle:
    """Load a replay key only from a protected path outside the project tree."""
    path = _check_local_key_path(path)
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise PermissionError("replay-key file must have mode 0600")
    payload = path.read_bytes()
    min_len = len(REPLAY_KEY_MAGIC) + 16 + 12 + 16
    if len(payload) < min_len or not payload.startswith(REPLAY_KEY_MAGIC):
        raise ValueError("invalid HXM1 fuzz replay-key file")
    offset = len(REPLAY_KEY_MAGIC)
    salt, nonce = payload[offset : offset + 16], payload[offset + 16 : offset + 28]
    encrypted = payload[offset + 28 :]
    raw_bundle = AESGCM(_derive_replay_key(passphrase, salt)).decrypt(
        nonce, encrypted, REPLAY_KEY_AAD
    )
    return PrivateKeyBundle.from_json(raw_bundle.decode("utf-8"))


def _outcome_for_exception(exc: Exception) -> str:
    return "EXPECTED_REJECTION" if isinstance(exc, EXPECTED_SAFE_REJECTIONS) else "UNEXPECTED_EXCEPTION"


def run_fuzz(
    n_trials: int,
    seed: int = 42,
    jsonl_path: Path | None = None,
    replay_key_path: Path | None = None,
    replay_passphrase: str | None = None,
) -> dict[str, object]:
    if n_trials < 1:
        raise ValueError("n_trials must be positive")
    if jsonl_path is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        jsonl_path = Path(tempfile.gettempdir()) / f"hxm1_parser_fuzz_{stamp}.jsonl"
    jsonl_path = jsonl_path.expanduser().resolve()
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    if replay_key_path is None:
        replay_key_path = jsonl_path.with_suffix(".replay-key")
    if replay_passphrase is None:
        replay_passphrase = getpass("Passphrase for encrypted local replay key: ")
        confirmation = getpass("Repeat replay-key passphrase: ")
        if not replay_passphrase or replay_passphrase != confirmation:
            raise ValueError("replay-key passphrases must be non-empty and match")

    rng = random.Random(seed)
    public_key, private_key = generate_keypair()
    package = encrypt_hybrid(public_key, FUZZ_PLAINTEXT, FUZZ_AAD)
    replay_key_path = _save_local_replay_key(replay_key_path, private_key, replay_passphrase)

    legacy_outcomes = Counter()
    classified_outcomes = Counter()
    unexpected_examples = []
    accepted_examples = []
    start = time.perf_counter()

    with jsonl_path.open("x", encoding="utf-8") as audit:
        for trial_number in range(1, n_trials + 1):
            mutant, mutation = truncate_or_extend(package, rng)
            unchanged = mutant == package
            row: dict[str, object] = {
                "seed": seed,
                "trial_number": trial_number,
                "mutation_branch": mutation["branch"],
                "mutation_details": mutation,
                "original_package_base64": _b64(package),
                "mutated_package_base64": _b64(mutant),
                "package_unchanged": unchanged,
                "replay_key_file": str(replay_key_path),
            }
            try:
                recovered = decrypt_hybrid(private_key, mutant, FUZZ_AAD)
            except Exception as exc:  # Report every exception with its concrete type.
                outcome = _outcome_for_exception(exc)
                row.update(
                    {
                        "outcome": outcome,
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                    }
                )
                classified_outcomes[outcome] += 1
                if outcome == "EXPECTED_REJECTION":
                    legacy_outcomes[f"SAFE_REJECT_{type(exc).__name__}"] += 1
                else:
                    legacy_outcomes[f"UNEXPECTED_{type(exc).__name__}"] += 1
                    if len(unexpected_examples) < 5:
                        unexpected_examples.append(
                            (type(exc).__name__, str(exc), mutant.hex()[:80])
                        )
            else:
                outcome = classify_success(package, mutant, recovered, FUZZ_PLAINTEXT)
                row.update(
                    {
                        "outcome": outcome,
                        "exception_type": None,
                        "exception_message": None,
                        "recovered_plaintext_matches_reference": recovered == FUZZ_PLAINTEXT,
                    }
                )
                classified_outcomes[outcome] += 1
                if outcome in ("UNCHANGED_VALID_PACKAGE", "CHANGED_ACCEPTED_CORRECT"):
                    legacy_outcomes["ACCEPTED_AND_CORRECT"] += 1
                else:
                    legacy_outcomes["ACCEPTED_BUT_WRONG_PLAINTEXT"] += 1
                    if len(accepted_examples) < 5:
                        accepted_examples.append(mutant.hex()[:80])

            audit.write(json.dumps(row, sort_keys=True) + "\n")
            audit.flush()

    elapsed = time.perf_counter() - start
    return {
        "n_trials": n_trials,
        "seed": seed,
        "elapsed_s": elapsed,
        "outcomes": dict(legacy_outcomes),
        "classified_outcomes": dict(classified_outcomes),
        "unexpected_examples": unexpected_examples,
        "accepted_examples": accepted_examples,
        "jsonl_path": str(jsonl_path),
        "replay_key_path": str(replay_key_path),
    }


def replay_trial(jsonl_path: Path, replay_key_path: Path, trial_number: int) -> dict[str, object]:
    """Replay one recorded mutant using the separately encrypted local key."""
    passphrase = getpass("Passphrase for encrypted local replay key: ")
    private_key = _load_local_replay_key(replay_key_path, passphrase)
    selected = None
    with jsonl_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["trial_number"] == trial_number:
                selected = row
                break
    if selected is None:
        raise ValueError(f"trial {trial_number} not found in {jsonl_path}")
    original = _unb64(selected["original_package_base64"])
    mutant = _unb64(selected["mutated_package_base64"])
    try:
        recovered = decrypt_hybrid(private_key, mutant, FUZZ_AAD)
    except Exception as exc:
        replayed_outcome = _outcome_for_exception(exc)
        return {
            "trial_number": trial_number,
            "outcome": replayed_outcome,
            "recorded_outcome": selected["outcome"],
            "matches_recorded_outcome": replayed_outcome == selected["outcome"],
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "package_unchanged": mutant == original,
        }
    replayed_outcome = classify_success(original, mutant, recovered, FUZZ_PLAINTEXT)
    return {
        "trial_number": trial_number,
        "outcome": replayed_outcome,
        "recorded_outcome": selected["outcome"],
        "matches_recorded_outcome": replayed_outcome == selected["outcome"],
        "package_unchanged": mutant == original,
        "recovered_plaintext_matches_reference": recovered == FUZZ_PLAINTEXT,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=3_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--jsonl", type=Path, help="per-trial JSONL output (default: unique file in system temp)")
    parser.add_argument("--replay-key", type=Path, help="encrypted local replay key path (default: JSONL sibling)")
    parser.add_argument("--replay-trial", type=int, help="replay this 1-based trial instead of fuzzing")
    args = parser.parse_args()

    _test_success_classification()
    if args.replay_trial is not None:
        if args.jsonl is None or args.replay_key is None:
            parser.error("--replay-trial requires --jsonl and --replay-key")
        print(json.dumps(replay_trial(args.jsonl, args.replay_key, args.replay_trial), sort_keys=True))
        return

    result = run_fuzz(args.trials, args.seed, args.jsonl, args.replay_key)
    print(f"Trials: {result['n_trials']}  Seed: {result['seed']}  Elapsed: {result['elapsed_s']:.1f}s")
    print("Classified outcomes:")
    for outcome, count in sorted(result["classified_outcomes"].items()):
        print(f"  {outcome}: {count}")
    print("Aggregate outcomes (legacy buckets):")
    for outcome, count in sorted(result["outcomes"].items()):
        print(f"  {outcome}: {count}")
    print(f"JSONL audit: {result['jsonl_path']}")
    print(f"Encrypted local replay key: {result['replay_key_path']}")
    if result["unexpected_examples"]:
        print("\nUNEXPECTED exception examples:")
        for exc_type, msg, hexdata in result["unexpected_examples"]:
            print(f"  {exc_type}: {msg} | mutant(hex, truncated): {hexdata}")
    if result["accepted_examples"]:
        print("\nAccepted package examples (hex, truncated):")
        for hexdata in result["accepted_examples"]:
            print(f"  {hexdata}")


if __name__ == "__main__":
    main()
