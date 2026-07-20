"""Paket U4: Notfall-Code (Diceware) und Notfall-KEK-Wraps."""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import envelope

_AAD_EMERGENCY_KEK = b"docu9-emergency-kek-wrap"
_CODE_WORDS = 10
_ARGON2_TIME = 3
_ARGON2_MEMORY = 65536
_ARGON2_PARALLELISM = 1
_SALT_LEN = 16

_hasher = PasswordHasher(
    time_cost=_ARGON2_TIME,
    memory_cost=_ARGON2_MEMORY,
    parallelism=_ARGON2_PARALLELISM,
)


@lru_cache(maxsize=1)
def _wordlist() -> tuple[str, ...]:
    path = Path(__file__).with_name("eff_wordlist.txt")
    words = [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(words) < 1024:
        raise RuntimeError("Diceware-Wortliste fehlt oder ist zu kurz.")
    return tuple(words)


def normalize_code(code: str) -> str:
    return " ".join(code.strip().lower().split())


def generate_code() -> str:
    words = _wordlist()
    picks = [words[secrets.randbelow(len(words))] for _ in range(_CODE_WORDS)]
    return " ".join(picks)


def hash_code(code: str) -> str:
    return _hasher.hash(normalize_code(code))


def verify_code(code: str, code_hash: str) -> bool:
    try:
        _hasher.verify(code_hash, normalize_code(code))
        return True
    except Exception:
        return False


def _derive_code_key(code: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=normalize_code(code).encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEMORY,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def wrap_emergency_kek_for_owner(emergency_kek: bytes, wrapped_owner_kek: bytes) -> bytes:
    owner_kek = envelope.unwrap_kek(wrapped_owner_kek)
    nonce = os.urandom(12)
    return nonce + AESGCM(owner_kek).encrypt(nonce, emergency_kek, _AAD_EMERGENCY_KEK)


def unwrap_emergency_kek_for_owner(wrapped: bytes, wrapped_owner_kek: bytes) -> bytes:
    owner_kek = envelope.unwrap_kek(wrapped_owner_kek)
    nonce, ct = wrapped[:12], wrapped[12:]
    return AESGCM(owner_kek).decrypt(nonce, ct, _AAD_EMERGENCY_KEK)


def wrap_emergency_kek_for_code(emergency_kek: bytes, code: str) -> bytes:
    salt = os.urandom(_SALT_LEN)
    key = _derive_code_key(code, salt)
    nonce = os.urandom(12)
    ct = nonce + AESGCM(key).encrypt(nonce, emergency_kek, _AAD_EMERGENCY_KEK)
    return salt + ct


def unwrap_emergency_kek_for_code(wrapped: bytes, code: str) -> bytes:
    salt, ct = wrapped[:_SALT_LEN], wrapped[_SALT_LEN:]
    key = _derive_code_key(code, salt)
    nonce, payload = ct[:12], ct[12:]
    return AESGCM(key).decrypt(nonce, payload, _AAD_EMERGENCY_KEK)


def wrap_dek_under_emergency_kek(dek: bytes, emergency_kek: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(emergency_kek).encrypt(nonce, dek, b"docu9-dek-wrap")


def unwrap_dek_with_emergency_kek(wrapped_dek: bytes, emergency_kek: bytes) -> bytes:
    nonce, ct = wrapped_dek[:12], wrapped_dek[12:]
    return AESGCM(emergency_kek).decrypt(nonce, ct, b"docu9-dek-wrap")


def wrap_document_dek_for_emergency(
    doc_wrapped_dek: bytes,
    doc_owner_wrapped_kek: bytes,
    emergency_kek: bytes,
) -> bytes:
    dek = envelope.unwrap_dek(doc_wrapped_dek, doc_owner_wrapped_kek)
    return wrap_dek_under_emergency_kek(dek, emergency_kek)


def rewrap_emergency_kek_owner_blob(wrapped: bytes, old_wrapped_owner_kek: bytes, new_wrapped_owner_kek: bytes) -> bytes:
    emergency_kek = unwrap_emergency_kek_for_owner(wrapped, old_wrapped_owner_kek)
    return wrap_emergency_kek_for_owner(emergency_kek, new_wrapped_owner_kek)
