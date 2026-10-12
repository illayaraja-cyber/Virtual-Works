"""Educational password-based file protection using stdlib primitives.

For production, prefer an audited AEAD library such as cryptography. This example
uses PBKDF2-HMAC-SHA256 for key derivation, a SHA-256 keystream, and HMAC for
integrity; it is intended to teach the concepts, not replace audited encryption.
"""

from pathlib import Path
import argparse
import hashlib
import hmac
import os
import struct

MAGIC = b"CSP1"
ITERATIONS = 300_000
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32


def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("password must not be empty")
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=32)


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        block = hashlib.sha256(key + nonce + struct.pack(">Q", counter)).digest()
        output.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    key = _key(password, salt)
    ciphertext = _xor_stream(data, key, nonce)
    header = MAGIC + salt + nonce
    return header + ciphertext + hmac.new(key, header + ciphertext, hashlib.sha256).digest()


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    minimum = len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(blob) < minimum or blob[:4] != MAGIC:
        raise ValueError("invalid or unsupported protected file")
    salt = blob[4:20]
    nonce = blob[20:36]
    ciphertext, tag = blob[36:-TAG_SIZE], blob[-TAG_SIZE:]
    key = _key(password, salt)
    expected = hmac.new(key, blob[:-TAG_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("wrong password or corrupted file")
    return _xor_stream(ciphertext, key, nonce)


def protect_file(source: str | Path, destination: str | Path, password: str) -> None:
    Path(destination).write_bytes(encrypt_bytes(Path(source).read_bytes(), password))


def restore_file(source: str | Path, destination: str | Path, password: str) -> None:
    Path(destination).write_bytes(decrypt_bytes(Path(source).read_bytes(), password))


def main() -> None:
    parser = argparse.ArgumentParser(description="Protect or restore one file.")
    parser.add_argument("mode", choices=("encrypt", "decrypt"))
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("password")
    args = parser.parse_args()
    if args.mode == "encrypt":
        protect_file(args.source, args.destination, args.password)
    else:
        restore_file(args.source, args.destination, args.password)
    print(f"Wrote {args.destination}")


if __name__ == "__main__":
    main()
