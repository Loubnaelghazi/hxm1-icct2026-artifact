# Comparison With Real Libraries, Standards, and Deployment Work

Search date: 2026-06-01

This comparison supports the paper's gap claim: recent work provides PQC algorithms,
hybrid TLS key exchange, and general KEM guidance, but does not directly provide a
small RSA-legacy store-and-forward content-encryption profile with downgrade tests,
test vectors, and a strict binary format like HXM1.

## Standards and protocol work

| Source | What it provides | Relevance to HXM1 | Gap HXM1 addresses |
|---|---|---|---|
| NIST FIPS 203 | ML-KEM standard and parameter sets | HXM1 uses ML-KEM-768 | Does not define RSA-legacy content-encryption packaging |
| NIST SP 800-227 | General KEM definitions, properties, and usage recommendations | Supports KEM/DEM framing | Does not define a concrete hybrid file/message profile |
| RFC 9180 HPKE | KEM/KDF/AEAD public-key encryption framework | HXM1 follows the KEM/KDF/AEAD discipline | HPKE is not an RSA-KEM + ML-KEM legacy content profile |
| RFC 9690 | RSA-KEM for CMS | HXM1 uses RSA-KEM as classical component | Does not combine RSA-KEM with ML-KEM or study PQ downgrade cases |
| IETF hybrid TLS drafts | Hybrid TLS key exchange, mainly ECDHE/X25519 + ML-KEM | Motivates downgrade-resistant hybrid design | Focuses on interactive TLS, not store-and-forward RSA content encryption |

## Library ecosystem

| Library/project | Observed PQC/hybrid support | HXM1 relevance |
|---|---|---|
| OpenSSL 3.5+ | Documents ML-KEM and hybrid ML-KEM support, especially for TLS/key establishment | Shows production libraries are moving to ML-KEM, but not HXM1's RSA-legacy file profile |
| Open Quantum Safe/liboqs | Provides ML-KEM and other PQC implementations for prototyping | A future HXM1 implementation should replace `kyber-py` with liboqs for speed and maturity |
| OQS provider for OpenSSL | Integrates PQC/hybrid algorithms into OpenSSL workflows | Useful future backend, but current HXM1 profile remains independent |
| Bouncy Castle | Provides Java cryptographic primitives and PQC support in recent versions | Candidate second implementation for future HXM1 interop |
| Botan/Crypto++/wolfSSL/MbedTLS | PQC readiness varies across libraries according to recent surveys | Supports the need for explicit profiles and tests rather than assuming uniform support |

## Gap statement

Recent standards and libraries increasingly support ML-KEM and hybrid key establishment,
but the ecosystem is still fragmented around:

- migration tooling,
- protocol integration,
- hybrid mode binding,
- test vectors for complete application profiles,
- explicit downgrade and format-confusion tests.

HXM1 targets that gap for one narrow but practical setting: RSA-legacy store-and-forward
content encryption.

## What HXM1 contributes relative to libraries

HXM1 does not compete with OpenSSL, liboqs, HPKE, CMS, or TLS. It contributes:

1. a concrete binary profile;
2. strict parsing rules;
3. mode and component binding;
4. downgrade and format-confusion negative tests;
5. randomized test vectors;
6. CLI artifact for file encryption demonstrations;
7. a profile that can later be implemented on top of vetted libraries.

## Sources used

- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST SP 800-227: https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 9180 HPKE: https://www.ietf.org/rfc/rfc9180.html
- RFC 9690 RSA-KEM: https://www.rfc-editor.org/rfc/rfc9690
- IETF hybrid TLS draft: https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-13.html
- IETF ECDHE + ML-KEM draft: https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-03
- OpenSSL ML-KEM documentation: https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/
- Open Quantum Safe ML-KEM: https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html
- Survey of PQC support in cryptographic libraries: https://arxiv.org/abs/2508.16078
