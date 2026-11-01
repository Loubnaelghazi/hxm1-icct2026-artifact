# HXM1 experimental artifact — 24 October 2026

This is an unpublished release candidate. It contains source snapshots and NEW measured evidence, not a reconstruction of historical campaigns. No manuscript or bibliography is included.

## Setup

Use Python 3.10 or newer (the measurements used Python 3.13.13), Node.js for the JavaScript tests, and an OpenSSL CLI supporting CMS AES-GCM. Create your own virtual environment and install:

    python -m pip install -r source/requirements.txt

No dependencies are bundled. Exact measured environment versions and source hashes are in evidence/performance/provenance.json. API cryptography/OpenSSL and CLI OpenSSL are different backends; do not conflate their versions.

## Verify preserved evidence

    python -B verify_evidence.py

This verifies the SHA-256 manifest, recalculates performance summaries, checks fuzz record counts and input identity, replays accepted fuzz cases, and checks the fresh HPKE/CMS records. It does not re-execute every rejected fuzz case or remeasure timings.

## Run NEW experiments

Each --output directory must NOT exist. Choose unique absolute paths, preferably outside this archive. These commands never overwrite the evidence/ directory:

    python -B reproduce.py --suite checks --output /tmp/hxm1-new-checks-UNIQUE
    python -B reproduce.py --suite hpke --output /tmp/hxm1-new-hpke-UNIQUE
    python -B reproduce.py --suite cms --output /tmp/hxm1-new-cms-UNIQUE
    python -B reproduce.py --suite fuzz --output /tmp/hxm1-new-fuzz-UNIQUE
    python -B reproduce.py --suite performance --output /tmp/hxm1-new-performance-UNIQUE

The fuzz CLI prompts for replay-key passphrases. The performance suite generates fresh RSA-3072 CMS test keys in a fresh workspace, then runs the archived benchmark infrastructure with three warm-up and thirty measured roundtrips per configuration. New cryptographic randomness and machine conditions mean outputs and timings will differ. Certificate metadata can change CMS overhead; original overhead values apply only to the measured artifacts.

## Evidence and interpretation

- Fuzzing: 6,000 completed trials; 5,998 changed-input rejections; two unchanged valid packages accepted; 5,259 distinct submitted byte strings. The public_test_key_seed*.json files are PUBLIC, disposable keys generated solely for these fuzz campaigns. They are intentionally included to replay the published experiment, and MUST NEVER protect real data. No original passphrase files are included.
- Performance: 900 measured operation samples and 90 warm-up samples; 450 measured and 45 warm-up verified roundtrips; zero failures. raw_samples.jsonl and summary.csv preserve all requested statistics. In-memory HXM1 API boundaries differ from CMS CLI process/file boundaries. Fresh encryption and matching decryption alternate; this differs from the old runner's batched/fixed-ciphertext procedure.
- HPKE: NEW PyHPKE 0.6.5 run: normal roundtrip succeeds; wrong AAD and changed ciphertext produce OpenError. Installed only in an isolated temporary directory for that verification; system packages were unchanged.
- CMS-GCM: NEW original-message decryption succeeds; exactly one encrypted-content bit is changed; nonce and tag are unchanged; modified decryption exits 4. OpenSSL emitted 47 bytes before reporting authentication failure: always discard ALL output on a nonzero decryption exit status.
- Targeted attacks and Bound Control: saved records are included separately; the checks suite runs new observations into a fresh directory. The custom control shares the experimental component KEMs.

Original performance/CMS private-key assets are deliberately excluded. Public certificates, commands, ciphertexts, outputs, fingerprints and validations remain available; new CMS experiments generate fresh test keys. The supplied historical test-vector private bundle is also excluded; make_test_vectors.py can generate new test vectors in a scratch directory. Original provenance records retain absolute paths from execution; these are historical metadata, not paths required by reproduce.py.

The original campaign-specific verification helpers are preserved as provenance but may reference their original paths. verify_evidence.py is the portable entry point. This archive does not establish IND-CCA security, robust-combiner security, sender authentication, standards equivalence, or intrinsic algorithmic superiority.

## Publication checklist

The authors must choose an appropriate license and verify rights to distribute the original project source before public deposit. No license grant is invented here. Third-party packages retain their own licenses and are installed separately. Publish this exact archive with its SHA-256 and a versioned permanent identifier; update manuscript links only after deposit. No publication has been performed.
