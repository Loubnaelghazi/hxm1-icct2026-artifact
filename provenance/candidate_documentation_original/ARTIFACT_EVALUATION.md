# Artifact Evaluation — Safe Reproduction

This repository contains a prototype, not a complete immutable release. The authoritative full experimental record is in a separately validated archive (public URL / DOI to be added after publication).

## Setup

Create a fresh virtual environment, install `requirements.txt`, and use a scratch copy for all writing experiments. Some scripts overwrite fixed paths in their working directory; importing the CMS inspection/tampering scripts can also write files. Never use blind test discovery across those modules.

## Read-only checks

```bash
node --test test_hxm1_parser.js
python -m unittest test_security_regressions
```

`test_comparison_verified.py` writes to fixed `/tmp` locations, so run it only in an isolated environment with those paths available for safe use; preferably use the archived reproduction wrapper. The comparison runner supports `run(output_dir=...)`; choose a new directory if invoking it directly.

## Targeted attacks

`attack_experiments.run_attacks()` returns the rows without invoking the script's result-writing CLI. Expected: five accepted deliberately vulnerable baseline scenarios, eleven HXM1 rejections. The Naive-C baseline reconstructs a new RSA-only encrypted package with known plaintext; it does not achieve stripping of an unchanged hybrid ciphertext. HXM1 tests actual ML-KEM component removal with consistent framing separately.

## Independent comparisons

HPKE reference: `test_hpke_reference.run()` uses PyHPKE 0.6.5 and checks one normal operation, wrong AAD, and a modified ciphertext. CMS-GCM reference checks a valid decryption and authentication rejection under a ciphertext change. A failed CMS command may still write partial output; **never treat this output as authenticated plaintext**. Use a scratch workspace and generate fresh CMS credentials. `Bound Control` shares experimental components with HXM1; it is not independent at the KEM implementation level.

## Fuzzing and benchmarks

Preserve the archived raw JSONL/CSV/JSON measurements, source hashes and environment details. The fresh HXM1 fuzzing campaigns submitted 6,000 attempts: 5,998 changed inputs were rejected; two unchanged inputs were accepted. A total of 5,259 distinct byte strings were submitted. The 15-configuration performance campaign recorded 900 measured operation timings (30 each for encryption and decryption) and 90 warm-up timings. Python API and OpenSSL CLI operation boundaries differ; timing ratios are implementation-level observations only.

**Never overwrite historical aggregates and never claim these raw campaigns reproduce the old result files.** A public immutable artifact URL has not yet been assigned.

## Missing private fixtures

The public candidate excludes the original stored-vector private key and the legacy OpenSSL private key. JavaScript metadata/parser checks work without them. Old ciphertext exact decryption cannot be repeated in this candidate. For new disposable vectors, run the vector generator in a *new temporary copy*, not on retained fixtures.
