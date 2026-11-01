# HXM1 — ICCT2026 research artifact for review

Repository: https://github.com/Loubnaelghazi/hxm1-icct2026-artifact

This is the complete review snapshot derived from the locally validated full package. All 198 archived CMS benchmark ciphertexts and all raw historical timing/fuzzing records are included. Pre-existing private keys remain excluded. See `REVIEW_STATUS.md` for validation scope and the distinction between historical campaigns and fresh checks.

This package supports the revised paper **HXM1: A Hardened Hybrid Migration Profile for RSA-Legacy Post-Quantum Content Encryption**. HXM1 is an experimental store-and-forward envelope combining a custom RSA-KEM-style component with ML-KEM-768, HKDF-SHA256 and AES-256-GCM. Its fixed hybrid overhead is 1515 bytes.

“Hardened” refers to the tested mode-consistency, version, framing and context checks. This is not a production cryptographic library, a standardized or interoperable CMS/HPKE profile, a validated cryptographic module, a side-channel-hardened implementation, or a proven IND-CCA/one-secure-component combiner. RSA-only and ML-KEM-only wire modes are experimental references, not automatic fallbacks. Authentic recipient public keys and application-selected expected AAD are assumed. Sender authentication and replay protection are not provided.

## What is included

- `source/`: cleaned research sources, unchanged cryptographic implementation, unchanged regression tests, public stored vectors and reference observations.
- `reproduce.py`: release orchestration for new isolated experiments, with actual command/exit-code logs.
- `verify_evidence.py`: portable, read-only verification of historical evidence, with new outputs written externally.
- `check_release.py`: file-manifest verification and bounded sensitive-data scanning of this tree or ZIP.
- `historical/evidence/`: byte-preserved raw fuzzing logs, benchmark samples and source snapshots, original summaries, HPKE/CMS observations, attacks and Bound Control records.
- `historical/`: original archive guide, manifest, validators and packaging observations. These are provenance, not the recommended execution entry points. Some original validators use historical absolute paths, require excluded private keys, or write beside records.
- `provenance/`: exact input-archive identity, per-file import hashes, exclusions and release-tool provenance. Original candidate documentation is retained here as historical context; this root README supersedes its instructions.

No manuscript, private keys, passphrases, virtual environments, or dependency wheels are bundled. Licensing is **pending author approval**; no license is added or implied. This repository provides public access to a research artifact for review, with the owner's authorization. It is not a DOI-bearing archival deposit and no DOI is assigned. A license decision remains separate from providing review access.

## Downloading a clean review snapshot

For review, use GitHub **Code > Download ZIP**, extract it, and run the commands below from the extracted root (the directory containing this README). The extracted folder name can differ from `hxm1-icct2026`; the commands use its actual path.

For a Git clone, first export a clean snapshot so Git's internal `.git/` directory is not treated as unmanifested release data:

```bash
git archive --format=zip --prefix=hxm1-icct2026/ --output=../hxm1-review-snapshot.zip HEAD
```

Extract that ZIP for manifest/sensitive-data checks. For GitHub-generated ZIPs with GitHub's own root-folder name, use `check_release.py --tree` after extraction. The direct `--zip` check expects the `hxm1-icct2026/` prefix created by the command above.

## Requirements and installation

Tested target: Linux/WSL2, Python 3.13, Node.js 20+, and an OpenSSL CLI supporting RSA-3072/OAEP and CMS AES-256-GCM. The archived benchmark scripts inspect `/proc/cpuinfo` and Linux CPU affinity; they are not portable to every operating system. Python packages are pinned in `source/requirements.txt`: `cryptography==48.0.0`, `kyber-py==1.2.0`, `pyhpke==0.6.5`. `kyber_py.ml_kem.ML_KEM_768` is used; this is not a claim of module validation. Node tests use only built-in modules. CLI OpenSSL and the Python cryptography backend may be different versions.

From the extracted `hxm1-icct2026/` directory, run the following in one Bash session. Every experiment writes into a NEW directory outside the package. Installing dependencies requires network/package-index access.

```bash
HXM1_PACKAGE_DIR="$PWD"
HXM1_RUN_ROOT="$(mktemp -d /tmp/hxm1-icct2026-runs-XXXXXXXX)"
python3.13 -m venv "$HXM1_RUN_ROOT/venv"
HXM1_PYTHON="$HXM1_RUN_ROOT/venv/bin/python"
"$HXM1_PYTHON" -m pip install -r "$HXM1_PACKAGE_DIR/source/requirements.txt"
"$HXM1_PYTHON" -m pip check
node --version
openssl version
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/check_release.py" --tree "$HXM1_PACKAGE_DIR"
```

Do not run blind test discovery: legacy CMS modules perform work at import time. Do not run output-producing legacy CLIs in `source/` or `historical/`. The release wrapper preserves test assertions and redirects only comparison-test output paths in memory.

## Verify historical evidence independently

```bash
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/verify_evidence.py" --output "$HXM1_RUN_ROOT/historical-verification"
```

This checks imported bytes against the original manifest, accounts explicitly for excluded members, reconstructs seeded fuzz mutations, verifies record counts and input identity, recalculates all 30 benchmark summaries from 990 raw operation samples, checks preserved CMS output hashes, and validates saved HPKE, attack, Bound Control and CMS structure/outcome records. It never changes archived samples or summaries and never follows their old absolute paths.

Historical counts belong only to the archived experiments: seeds 42 and 7 each completed 3000 submissions; 5998 changed inputs were rejected, two unchanged inputs accepted, and 5259 inputs were distinct overall. The benchmark has 900 measured and 90 warm-up operation timings across 15 configurations. These records support the manuscript's reported values; they are not newly measured timings.

All pre-existing private keys are excluded, including the archive's disposable fuzz replay bundles. Therefore cryptographic replay of the two historical accepted fuzz cases and two historical CMS decryption attempts is explicitly SKIPPED. Recorded identities, hashes, statistics and CMS mutation structure remain verifiable. The original full archive manifest records exclusions; it is preserved, not silently rewritten to claim the reduced package is the original archive.

## Run the complete NEW campaign

```bash
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite all --trials 3000 --output "$HXM1_RUN_ROOT/fresh-all"
```

This runs the checks below. The full fuzz and benchmark campaigns can take several minutes. Fresh keys, OS randomness and current machine conditions yield new ciphertexts, mutation strings, counts and timings; no historical counts or timing equality are imposed on new experiments. A changed-input acceptance, unexpected exception, incorrect result, or benchmark failure fails validation. Rejection assertions are not weakened.

For separate suites, use these exact commands, each with a new output directory:

```bash
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite unit --output "$HXM1_RUN_ROOT/unit"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite javascript --output "$HXM1_RUN_ROOT/javascript"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite functional --output "$HXM1_RUN_ROOT/functional"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite vectors --output "$HXM1_RUN_ROOT/vectors"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite attacks --output "$HXM1_RUN_ROOT/attacks"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite bound --output "$HXM1_RUN_ROOT/bound"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite hpke --output "$HXM1_RUN_ROOT/hpke"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite cms --output "$HXM1_RUN_ROOT/cms"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite fuzz --trials 3000 --output "$HXM1_RUN_ROOT/fuzz"
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/reproduce.py" --suite performance --output "$HXM1_RUN_ROOT/performance"
```

- **Unit:** 9 security-regression and 4 comparison tests, with their original assertions. Negative self-tests intentionally simulate bad outcomes; the unittest result determines success.
- **JavaScript:** 9 stored-vector parser/hash tests, including high-bit magic aliases and malformed framing. Parsing does not authenticate a ciphertext.
- **Functional:** 16 checks plus all 9 package/decryptor mode combinations.
- **Vectors:** 3 stored hash/metadata checks; 3 fresh disposable round trips; 9 JavaScript checks on fresh vectors; 1515-byte overhead on stored and fresh hybrid packages.
- **Attacks:** 16 targeted observations: 5 intended acceptances in deliberately vulnerable baselines and 11 HXM1 rejections. Naive-B retains a classical-only encrypted copy. Naive-C constructs a fresh fallback with known plaintext; it is not stripping an unknown plaintext's unchanged ciphertext. These are not flaws in deployed CMS/HPKE.
- **Bound Control:** 6 mutations per envelope, 12 exact expected exception types/messages. The control binds framing/context and KEM ciphertexts but shares the experimental component KEMs; no independent security proof is claimed.
- **HPKE:** PyHPKE 0.6.5 Base X25519/HKDF-SHA256/AES-256-GCM round trip, wrong AAD and modified ciphertext, 3 checks. This is not a feature-equivalent hybrid benchmark.
- **CMS:** fresh RSA-3072 credentials, normal equality, dynamically located encryptedContent bit flip, unchanged nonce/tag and nonzero tampered-decryption exit. OpenSSL can emit bytes before failure: ALL failed-decrypt output is discarded.
- **Fuzz:** 3000 completed submissions per seed (42 and 7), exact mutation reconstruction, actual classification counts and replay of accepted fresh inputs. Seeds control Python mutation choices, not cryptographic or OS randomness. New encrypted replay keys and random passphrases stay private in the external run directory and are never logged. Random rejection is a parser sanity check, not a security proof.
- **Performance:** unchanged archived `benchmark_campaign.py`, 3 warm-up and 30 measured round trips for 128 B, 16 KiB and 1 MiB, across RSA-only, ML-KEM-only, hybrid, CMS-CBC and CMS-GCM. All 990 operation samples and round trips are checked; statistics are recalculated from actual new measurements. HXM1 in-memory API timing includes PEM loading/KEM/KDF/AEAD/framing; CMS timing includes CLI startup, file I/O, certificate/key loading and DER. Ratios are implementation observations, not intrinsic algorithmic comparisons. Fresh certificate metadata can change CMS overhead.

## Historical stored vectors and disposable replacement

`source/test_vectors/private_key.json` is intentionally absent. Exact decryption of the THREE retained historical RSA-only, ML-KEM-only and hybrid ciphertexts is SKIPPED, not a cryptographic failure. Hash/metadata and JS checks still apply. Fresh vectors cannot decrypt those historical packages.

The `vectors` suite handles this safely. To generate another independent set manually:

```bash
HXM1_VECTOR_DIR="$(mktemp -d /tmp/hxm1-disposable-vectors-XXXXXXXX)"
(cd "$HXM1_VECTOR_DIR" && "$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/source/make_test_vectors.py")
```

The unchanged generator creates a new `test_vectors/` directory containing disposable private/public keys, all three randomized packages, metadata and successful round-trip checks. Keep the generated private key local; never copy this directory into a release. The old CMS private key is also excluded; use the CMS suite to generate a fresh matching certificate/key pair.

## Integrity and sensitive-data checks

`MANIFEST.sha256` covers every included file except itself. The ZIP's external `SHA256SUMS.txt` covers the ZIP and release report. Original archive identity and the inventory are in `provenance/INPUTS.json`; exclusions are in `provenance/EXCLUDED_FILES.json`.

```bash
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/check_release.py" --tree "$HXM1_PACKAGE_DIR"
# Supply the actual local ZIP path to inspect the archive directly:
"$HXM1_PYTHON" -B "$HXM1_PACKAGE_DIR/check_release.py" --zip /absolute/path/hxm1-icct2026-reproducibility.zip
```

The scanner checks all bytes and paths, private PEM markers, JSON secret fields and base64 private bundles, common AWS/GitHub/Slack token formats, and literal credential assignments without printing matching values. This bounded scan is not a universal guarantee of absence of secrets. Git history is not bundled or scanned as part of this ZIP. Do not upload external fresh-run directories: they intentionally contain local disposable credentials.
