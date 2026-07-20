"""Envelope-Verschlüsselung (ADR-09, Security-Doku §2).

Hierarchie: Master-Key (KMS) → KEK pro Nutzer → DEK pro Dokument → Daten (AES-256-GCM).
Klartext existiert ausschließlich transient im Prozess-Speicher.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto.kms import get_kms

_AAD = b"docu9-data"


def generate_kek_wrapped() -> bytes:
    """Erzeugt einen neuen Nutzer-KEK und gibt ihn gewrappt (Master-Key) zurück."""
    return get_kms().wrap(os.urandom(32))


def unwrap_kek(wrapped_kek: bytes) -> bytes:
    return get_kms().unwrap(wrapped_kek)


def generate_dek_wrapped(wrapped_kek: bytes) -> tuple[bytes, bytes]:
    """Erzeugt einen Dokument-DEK; Rückgabe: (dek_plain, dek_wrapped_mit_kek)."""
    dek = os.urandom(32)
    kek = unwrap_kek(wrapped_kek)
    nonce = os.urandom(12)
    wrapped = nonce + AESGCM(kek).encrypt(nonce, dek, b"docu9-dek-wrap")
    return dek, wrapped


def unwrap_dek(wrapped_dek: bytes, wrapped_kek: bytes) -> bytes:
    kek = unwrap_kek(wrapped_kek)
    nonce, ct = wrapped_dek[:12], wrapped_dek[12:]
    return AESGCM(kek).decrypt(nonce, ct, b"docu9-dek-wrap")


def rewrap_dek(wrapped_dek: bytes, old_wrapped_kek: bytes, new_wrapped_kek: bytes) -> bytes:
    """AA4: Dokument-DEK unter neuem Nutzer-KEK speichern — Klartext-DEK nur transient."""
    dek = unwrap_dek(wrapped_dek, old_wrapped_kek)
    new_kek = unwrap_kek(new_wrapped_kek)
    nonce = os.urandom(12)
    return nonce + AESGCM(new_kek).encrypt(nonce, dek, b"docu9-dek-wrap")


def rewrap_kek(wrapped_kek: bytes) -> bytes:
    """AA4: Nutzer-KEK auf aktuelle Master-Key-/Vault-Version heben."""
    from app.crypto.kms import rewrap_master

    return rewrap_master(wrapped_kek)


def encrypt(dek: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(dek).encrypt(nonce, plaintext, _AAD)


def decrypt(dek: bytes, ciphertext: bytes) -> bytes:
    nonce, ct = ciphertext[:12], ciphertext[12:]
    return AESGCM(dek).decrypt(nonce, ct, _AAD)


def encrypt_text(dek: bytes, text: str) -> bytes:
    return encrypt(dek, text.encode("utf-8"))


def decrypt_text(dek: bytes, ciphertext: bytes) -> str:
    return decrypt(dek, ciphertext).decode("utf-8")
