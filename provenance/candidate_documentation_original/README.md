# HXM1 — Experimental RSA / ML-KEM migration envelope

HXM1 is a research prototype for exploring RSA-legacy post-quantum migration. It combines a custom RSA-KEM-style component and ML-KEM-768 in a mandatory hybrid profile using HKDF-SHA256 and AES-256-GCM. It is **not** a standardized, audited, production-ready cryptographic product, and it has **no formal IND-CCA or one-secure-component security proof**.

## Requirements

Python 3.13, Node.js, OpenSSL CLI with CMS-GCM support, and dependencies in `requirements.txt`. Use a disposable environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Layout

- `hybrid_rsa_mlkem.py`, `hxm1_cli.py`, `hxm1_parser.js`: prototype and independent binary parser.
- `vulnerable_baselines.py`, `attack_experiments.py`: intentionally vulnerable research examples and targeted attacks.
- `bound_envelope_control.py`, `compare_bound_control.py`: experimental bound-envelope control, **not** a standardized implementation or security proof.
- `test_security_regressions.py`, `test_comparison_verified.py`, `test_hxm1_parser.js`: regression tests.
- `test_hpke_reference.py`, `openssl_cms_bench/`: independent reference behaviors; **not feature-equivalent** to HXM1.
- `fuzz_hxm1_parser.py`, `fuzz_compare_baselines.py`: robustness experiments. Random mutations test parser/decryption behavior, not general cryptographic security.
- `run_experiments.py`: functional/mode checks and legacy benchmark runner. Performance results depend on implementation boundaries.

RSA-only and ML-KEM-only wire modes are **experimental reference modes**, not fallback modes for the mandatory hybrid profile.

## Safe tests

```bash
node --test test_hxm1_parser.js
python -m unittest test_security_regressions
```

**Do not run** `make_test_vectors.py`, `attack_experiments.py` as a CLI, `run_experiments.py` with an existing output directory, or CMS utilities in this directory: they may overwrite results or generate files. See `ARTIFACT_EVALUATION.md` for isolated-output procedures. `test_comparison_verified.py` uses fixed `/tmp` paths; its two tests should be run in a disposable working environment.

## Reproducibility and recorded evidence

A separate immutable, validated artifact archive includes new raw fuzzing and performance samples, source snapshots, environment provenance, checksums, and reproduction helpers. **Public archive URL and version identifier: TO BE ADDED AFTER PUBLICATION.** No old aggregate benchmark results are represented as the new campaigns.

The updated experimental summaries are: targeted attacks (five baseline acceptances and eleven HXM1 rejections), 12 bound-control targeted rejections, new HXM1 fuzzing (6,000 attempts: 5,998 changed-input rejections and two no-op acceptances), and 900 new measured performance operation timings. These are observational outcomes, not proof of hybrid-combiner security.

## Test fixtures and publication safety

Private vector bundle `test_vectors/private_key.json` and old CMS private key `openssl_cms_bench/rsa_priv.pem` are intentionally omitted. Existing test vectors can still be parsed by JavaScript, but **exact decryption of the old saved ciphertexts requires the excluded matching private bundle**. Generate *new disposable vectors* in a scratch copy if needed. CMS tests require freshly generated RSA key/certificate pairs in an isolated directory; do not assume a fixed ciphertext byte offset for newly generated CMS files.

The project has no declared license until authors select one. Do not distribute or rely on the code for production encryption.
