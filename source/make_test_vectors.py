from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hybrid_rsa_mlkem import decrypt, encrypt, generate_keypair, package_info


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    output_dir = Path("test_vectors")
    output_dir.mkdir(exist_ok=True)
    public_key, private_key = generate_keypair()
    plaintext = b"HXM1 test vector message for RSA legacy post-quantum migration.\n"
    aad = b"hxm1-profile=v1;recipient=demo"
    (output_dir / "public_key.json").write_text(public_key.to_json(), encoding="utf-8")
    (output_dir / "private_key.json").write_text(private_key.to_json(), encoding="utf-8")
    (output_dir / "plaintext.bin").write_bytes(plaintext)
    vectors = {
        "note": "Randomized test vectors. Ciphertext bytes change on each generation; hashes and metadata verify round trip behavior.",
        "aad_utf8": aad.decode("utf-8"),
        "plaintext_sha256": sha256(plaintext),
        "modes": {},
    }
    for mode in ("rsa", "mlkem", "hybrid"):
        package = encrypt(mode, public_key, plaintext, aad)
        recovered = decrypt(mode, private_key, package, aad)
        if recovered != plaintext:
            raise RuntimeError(f"round trip failed for {mode}")
        package_path = output_dir / f"{mode}.hxm1"
        package_path.write_bytes(package)
        vectors["modes"][mode] = {
            "package_file": package_path.name,
            "package_sha256": sha256(package),
            "package_info": package_info(package),
        }
    (output_dir / "vectors.json").write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    print(f"wrote {output_dir / 'vectors.json'}")


if __name__ == "__main__":
    main()
