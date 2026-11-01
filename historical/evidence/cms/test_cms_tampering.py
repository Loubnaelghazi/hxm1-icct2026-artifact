import shutil
import subprocess


CERT = "cert.pem"
PRIV = "rsa_priv.pem"

PLAIN = "tamper_plain.bin"
CMS = "tamper_original.cms"
CMS_TAMPERED = "tamper_modified.cms"

DEC_ORIGINAL = "tamper_original.dec"
DEC_TAMPERED = "tamper_modified.dec"


def run(cmd):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )


def decrypt(cms_path, output_path):
    return run([
        "openssl", "cms",
        "-decrypt",
        "-in", cms_path,
        "-out", output_path,
        "-recip", CERT,
        "-inkey", PRIV,
        "-binary",
        "-inform", "DER",
        "-keyopt", "rsa_padding_mode:oaep",
    ])


# =========================================================
# 1. Create plaintext
# =========================================================

with open(PLAIN, "wb") as f:
    f.write(
        b"This is a CMS AuthEnvelopedData tampering test."
    )


# =========================================================
# 2. Generate CMS AuthEnvelopedData
# =========================================================

result = run([
    "openssl", "cms",
    "-encrypt",
    "-in", PLAIN,
    "-out", CMS,
    "-recip", CERT,
    "-aes-256-gcm",
    "-binary",
    "-outform", "DER",
    "-keyopt", "rsa_padding_mode:oaep",
])

if result.returncode != 0:
    print("CMS generation failed:")
    print(result.stderr)
    raise SystemExit(1)

print("Original CMS generated.")


# =========================================================
# 3. Verify original CMS
# =========================================================

result = decrypt(CMS, DEC_ORIGINAL)

print()
print("=== ORIGINAL CMS ===")

if result.returncode == 0:

    with open(PLAIN, "rb") as f1, open(DEC_ORIGINAL, "rb") as f2:
        original_ok = f1.read() == f2.read()

    print("Decryption:", "SUCCESS" if original_ok else "PLAINTEXT MISMATCH")

else:

    original_ok = False

    print("Decryption FAILED")
    print(result.stderr)


# =========================================================
# 4. Create tampered CMS
# =========================================================

shutil.copyfile(CMS, CMS_TAMPERED)

with open(CMS_TAMPERED, "r+b") as f:

    data = bytearray(f.read())

    # From OpenSSL asn1parse:
    #
    # 538:d=4  hl=2 l=43 prim: cont [0]
    #
    # Therefore:
    #   byte 538 = tag
    #   byte 539 = length
    #   bytes 540..582 = encryptedContent
    #   bytes 583..598 = GCM authentication tag
    #
    # We modify ONLY the first ciphertext byte.

    CIPHERTEXT_OFFSET = 540

    original_byte = data[CIPHERTEXT_OFFSET]

    data[CIPHERTEXT_OFFSET] ^= 0x01

    modified_byte = data[CIPHERTEXT_OFFSET]

    f.seek(0)
    f.write(data)


print()
print("Tampering performed:")
print(f"  ciphertext offset : {CIPHERTEXT_OFFSET}")
print(f"  original byte     : 0x{original_byte:02X}")
print(f"  modified byte     : 0x{modified_byte:02X}")
print("  modification      : 1-bit flip")
print("  authentication tag : UNCHANGED")


# =========================================================
# 5. Verify tampered CMS
# =========================================================

result = decrypt(CMS_TAMPERED, DEC_TAMPERED)

print()
print("=== TAMPERED CMS ===")

if result.returncode == 0:

    tampered_rejected = False

    print("WARNING: tampered CMS was ACCEPTED!")
    print(result.stderr)

else:

    tampered_rejected = True

    print("Decryption rejected tampered CMS.")
    print("OpenSSL error:")
    print(result.stderr.strip())


# =========================================================
# 6. Final result
# =========================================================

print()
print("=" * 60)
print("CMS AUTHENTICITY SANITY CHECK")
print("=" * 60)

print(f"Original accepted : {original_ok}")
print(f"Tampered rejected : {tampered_rejected}")

if original_ok and tampered_rejected:

    print()
    print("RESULT: PASS")

else:

    print()
    print("RESULT: FAIL")