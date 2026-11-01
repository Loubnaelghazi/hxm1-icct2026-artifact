# Strict targeted comparison

Neither envelope is claimed to be a standard or a proven IND-CCA combiner. The control uses the same experimental component KEM implementations.

| System | Mutation | Outcome | Exception |
|---|---|---|---|
| HXM1 | version changed | EXPECTED_REJECTION | ValueError: unsupported HXM1 package |
| HXM1 | mode changed | EXPECTED_REJECTION | ValueError: unexpected ML-KEM component in RSA-only mode |
| HXM1 | ML-KEM bytes modified | EXPECTED_REJECTION | InvalidTag:  |
| HXM1 | ML-KEM bytes removed with consistent lengths | EXPECTED_REJECTION | ValueError: invalid ML-KEM ciphertext length |
| HXM1 | AAD changed | EXPECTED_REJECTION | InvalidTag:  |
| HXM1 | trailing byte | EXPECTED_REJECTION | ValueError: invalid HXM1 package length |
| Bound control (not a standard) | version changed | EXPECTED_REJECTION | ValueError: unsupported control mode/version |
| Bound control (not a standard) | mode changed | EXPECTED_REJECTION | ValueError: unsupported control mode/version |
| Bound control (not a standard) | ML-KEM bytes modified | EXPECTED_REJECTION | InvalidTag:  |
| Bound control (not a standard) | ML-KEM bytes removed with consistent lengths | EXPECTED_REJECTION | ValueError: invalid control component lengths |
| Bound control (not a standard) | AAD changed | EXPECTED_REJECTION | InvalidTag:  |
| Bound control (not a standard) | trailing byte | EXPECTED_REJECTION | ValueError: invalid control total length |
