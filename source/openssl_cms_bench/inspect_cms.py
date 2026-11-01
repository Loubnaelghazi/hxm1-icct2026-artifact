import os
import subprocess

CERT = "cert.pem"
PRIV = "rsa_priv.pem"

PLAIN = "inspect_message.bin"
CMS = "inspect_message.cms"
DEC = "inspect_message.dec"


def run(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    return result


# 1. Create a small deterministic message
with open(PLAIN, "wb") as f:
    f.write(b"CMS authenticated attribute inspection test")

# 2. Create CMS AES-256-GCM envelope
result = run([
    "openssl", "cms", "-encrypt",
    "-in", PLAIN,
    "-out", CMS,
    "-recip", CERT,
    "-aes-256-gcm",
    "-binary",
    "-outform", "DER",
    "-keyopt", "rsa_padding_mode:oaep",
])

if result.returncode != 0:
    print("Encryption failed:")
    print(result.stderr)
    raise SystemExit(1)

print("CMS envelope created:", CMS)
print()

# 3. Print the CMS structure
result = run([
    "openssl", "cms",
    "-cmsout",
    "-inform", "DER",
    "-in", CMS,
    "-print",
])

if result.returncode != 0:
    print("CMS inspection failed:")
    print(result.stderr)
    raise SystemExit(1)

print(result.stdout)

# 4. Verify normal decryption
result = run([
    "openssl", "cms", "-decrypt",
    "-in", CMS,
    "-out", DEC,
    "-recip", CERT,
    "-inkey", PRIV,
    "-binary",
    "-inform", "DER",
    "-keyopt", "rsa_padding_mode:oaep",
])

print()
print("Normal decryption return code:", result.returncode)

if result.returncode == 0:
    with open(PLAIN, "rb") as f1, open(DEC, "rb") as f2:
        print("Round-trip correct:", f1.read() == f2.read())
else:
    print(result.stderr)