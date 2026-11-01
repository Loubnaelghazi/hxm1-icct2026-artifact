from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag

from hybrid_rsa_mlkem import (
    PrivateKeyBundle,
    PublicKeyBundle,
    decrypt,
    encrypt,
    generate_keypair,
    package_info,
)


def _read_aad(value: str | None) -> bytes:
    return b"" if value is None else value.encode("utf-8")


def cmd_keygen(args: argparse.Namespace) -> None:
    public_key, private_key = generate_keypair(args.rsa_bits)
    args.public_key.write_text(public_key.to_json(), encoding="utf-8")
    args.private_key.write_text(private_key.to_json(), encoding="utf-8")
    print(f"wrote public key: {args.public_key}")
    print(f"wrote private key: {args.private_key}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    public_key = PublicKeyBundle.from_json(args.public_key.read_text(encoding="utf-8"))
    plaintext = args.input.read_bytes()
    package = encrypt(args.mode, public_key, plaintext, _read_aad(args.aad))
    args.output.write_bytes(package)
    print(json.dumps(package_info(package), indent=2))


def cmd_decrypt(args: argparse.Namespace) -> None:
    private_key = PrivateKeyBundle.from_json(args.private_key.read_text(encoding="utf-8"))
    package = args.input.read_bytes()
    try:
        plaintext = decrypt(args.mode, private_key, package, _read_aad(args.aad))
    except InvalidTag as exc:
        raise SystemExit("decryption failed: authentication tag mismatch") from exc
    args.output.write_bytes(plaintext)
    print(f"wrote plaintext: {args.output}")


def cmd_info(args: argparse.Namespace) -> None:
    print(json.dumps(package_info(args.input.read_bytes()), indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HXM1 hybrid RSA-KEM/ML-KEM file encryption CLI")
    sub = parser.add_subparsers(required=True)

    keygen = sub.add_parser("keygen", help="generate a composite RSA + ML-KEM key pair")
    keygen.add_argument("--public-key", type=Path, default=Path("hxm1_public.json"))
    keygen.add_argument("--private-key", type=Path, default=Path("hxm1_private.json"))
    keygen.add_argument("--rsa-bits", type=int, default=3072)
    keygen.set_defaults(func=cmd_keygen)

    enc = sub.add_parser("encrypt", help="encrypt a file")
    enc.add_argument("--mode", choices=["rsa", "mlkem", "hybrid"], default="hybrid")
    enc.add_argument("--public-key", type=Path, required=True)
    enc.add_argument("--input", type=Path, required=True)
    enc.add_argument("--output", type=Path, required=True)
    enc.add_argument("--aad", help="associated data bound to authentication")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt a file")
    dec.add_argument("--mode", choices=["rsa", "mlkem", "hybrid"], default="hybrid")
    dec.add_argument("--private-key", type=Path, required=True)
    dec.add_argument("--input", type=Path, required=True)
    dec.add_argument("--output", type=Path, required=True)
    dec.add_argument("--aad", help="associated data bound to authentication")
    dec.set_defaults(func=cmd_decrypt)

    info = sub.add_parser("info", help="inspect an HXM1 package")
    info.add_argument("--input", type=Path, required=True)
    info.set_defaults(func=cmd_info)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
