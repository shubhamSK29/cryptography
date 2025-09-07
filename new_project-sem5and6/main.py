import argparse
import base64
import sys

from encryptor import encrypt_password, decrypt_password, EncryptorError


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data_str: str) -> bytes:
    try:
        return base64.b64decode(data_str.encode("ascii"), validate=True)
    except Exception as exc:
        raise EncryptorError("Invalid Base64 input") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Encrypt/decrypt password with Argon2id + AES-GCM")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a password; outputs Base64 blob")
    enc.add_argument("password", help="Password string to encrypt")

    dec = subparsers.add_parser("decrypt", help="Decrypt a Base64 blob using password")
    dec.add_argument("password", help="Password used for encryption")
    dec.add_argument("blob_b64", help="Base64-encoded encrypted blob")

    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            blob = encrypt_password(args.password)
            print(_b64encode(blob))
        elif args.command == "decrypt":
            blob = _b64decode(args.blob_b64)
            plaintext = decrypt_password(args.password, blob)
            print(plaintext)
        else:
            parser.error("Unknown command")
    except EncryptorError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


