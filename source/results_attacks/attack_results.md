# Migration-Layer Attack Experiments

| Failure class | Target | Result | Detail | Expected defense |
|---|---|---:|---|---|
| unauthenticated header modification | Naive-A | VULNERABLE |  | metadata changes must invalidate package |
| decryptor-selected downgrade | Naive-B | VULNERABLE |  | ciphertext mode must be authenticated and enforced |
| component stripping / RSA fallback | Naive-C | VULNERABLE |  | hybrid profile must require both KEM components |
| version rollback | Naive-A | VULNERABLE |  | unsupported versions must be rejected and authenticated |
| recipient/AAD misbinding | Naive-D | VULNERABLE |  | recipient and AAD context must be authenticated |
| unauthenticated header modification | HXM1 | EXPECTED_REJECTION | ValueError: unsupported HXM1 package | metadata changes must invalidate package |
| decryptor-selected downgrade | HXM1 | EXPECTED_REJECTION | ValueError: wrong HXM1 mode | ciphertext mode must be authenticated and enforced |
| ML-KEM ciphertext bit modification | HXM1 | EXPECTED_REJECTION | InvalidTag:  | authentication must reject a modified ML-KEM ciphertext |
| missing ML-KEM component | HXM1 | EXPECTED_REJECTION | ValueError: invalid ML-KEM ciphertext length | hybrid parser must reject an invalid ML-KEM ciphertext length |
| version rollback | HXM1 | EXPECTED_REJECTION | ValueError: unsupported HXM1 package | unsupported versions must be rejected and authenticated |
| recipient/AAD misbinding | HXM1 | EXPECTED_REJECTION | InvalidTag:  | recipient and AAD context must be authenticated |
| malformed length field (c_rsa_len=0) | HXM1 | EXPECTED_REJECTION | ValueError: invalid HXM1 package length | strict parser must reject inconsistent field lengths |
| malformed length field (c_rsa_len=1 (too small)) | HXM1 | EXPECTED_REJECTION | ValueError: invalid HXM1 package length | strict parser must reject inconsistent field lengths |
| malformed length field (c_rsa_len=max_uint16 (too large)) | HXM1 | EXPECTED_REJECTION | ValueError: invalid HXM1 package length | strict parser must reject inconsistent field lengths |
| malformed length field (c_mlkem_len=0) | HXM1 | EXPECTED_REJECTION | ValueError: invalid HXM1 package length | strict parser must reject inconsistent field lengths |
| malformed length field (nonce_len=0) | HXM1 | EXPECTED_REJECTION | ValueError: invalid HXM1 package length | strict parser must reject inconsistent field lengths |
