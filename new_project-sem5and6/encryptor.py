import os
from dataclasses import dataclass
from typing import Tuple

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptorError(Exception):
    """Raised for encryption/decryption errors."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3  # iterations
    memory_cost: int = 64 * 1024  # kibibytes (64 MiB)
    parallelism: int = 2
    salt_len: int = 16
    key_len: int = 32  # AES-256


VERSION_BYTE = 1  # for future-proofing format changes
NONCE_LEN = 12  # AES-GCM recommended nonce size


def _derive_key(password: str, salt: bytes, params: KdfParams = KdfParams()) -> bytes:
    if not isinstance(password, str) or password == "":
        raise EncryptorError("Password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != params.salt_len:
        raise EncryptorError("Invalid salt length")

    password_bytes = password.encode("utf-8")
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.key_len,
        type=Argon2Type.ID,
    )
    return key


def encrypt_password(password: str) -> bytes:
    """
    Derive a strong key with Argon2id and encrypt with AES-GCM.

    Input: password string
    Output: bytes formatted as: [version(1)][salt(16)][nonce(12)][ciphertext(+tag)]
    """
    params = KdfParams()
    salt = os.urandom(params.salt_len)
    key = _derive_key(password=password, salt=salt, params=params)

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    # We encrypt the UTF-8 bytes of the password to produce deterministic decryptability
    plaintext = password.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce=nonce, data=plaintext, associated_data=None)

    return bytes([VERSION_BYTE]) + salt + nonce + ciphertext


def decrypt_password(password: str, blob: bytes) -> str:
    """
    Decrypt data created by encrypt_password using the provided password.
    Returns the original password string.
    """
    if not isinstance(blob, bytes) or len(blob) < 1 + KdfParams.salt_len + NONCE_LEN + 16:
        # +16 to roughly account for GCM tag; exact length checked below
        raise EncryptorError("Encrypted blob is too short or invalid")

    version = blob[0]
    if version != VERSION_BYTE:
        raise EncryptorError("Unsupported data version")

    params = KdfParams()
    salt_start = 1
    salt_end = salt_start + params.salt_len
    nonce_end = salt_end + NONCE_LEN

    salt = blob[salt_start:salt_end]
    nonce = blob[salt_end:nonce_end]
    ciphertext = blob[nonce_end:]

    key = _derive_key(password=password, salt=salt, params=params)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
    except Exception as exc:  # cryptography raises InternalError/InvalidTag
        raise EncryptorError("Decryption failed: integrity check failed") from exc

    return plaintext.decode("utf-8")


__all__ = [
    "EncryptorError",
    "encrypt_password",
    "decrypt_password",
]


