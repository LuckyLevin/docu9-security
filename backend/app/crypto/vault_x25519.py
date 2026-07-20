"""X25519-Hilfen für Tresor-Betreiber-Recovery (kompatibel mit Web Crypto im Browser)."""

from __future__ import annotations

import base64

import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_private_key

AAD_VAULT_DEK = b"docu9-vault-dek"


def _aes_key_from_shared(shared: bytes) -> bytes:
    """Web Crypto: X25519 deriveKey → AES-GCM-256 nutzt die rohen 32 Shared-Secret-Bytes."""
    if len(shared) != 32:
        raise ValueError("X25519 shared secret muss 32 Bytes sein.")
    return shared


def unwrap_ephemeral_x25519_wrap(wrap_blob: bytes, private_key_raw: bytes) -> bytes:
    """Entschlüsselt ein Ephemeral-X25519-Wrap (32 Byte ephPub + 12 Byte nonce + ct)."""
    if len(wrap_blob) < 32 + 12 + 16:
        raise ValueError("Wrap-Blob zu kurz.")
    eph_pub = wrap_blob[:32]
    nonce = wrap_blob[32:44]
    ct = wrap_blob[44:]
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_raw)
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(eph_pub)
    shared = private_key.exchange(ephemeral_public)
    key = _aes_key_from_shared(shared)
    return AESGCM(key).decrypt(nonce, ct, AAD_VAULT_DEK)


def unwrap_ephemeral_x25519_wrap_b64(wrap_blob_b64: str, private_key_raw: bytes) -> bytes:
    return unwrap_ephemeral_x25519_wrap(base64.b64decode(wrap_blob_b64), private_key_raw)


def wrap_bytes_for_public_key(data: bytes, public_key_raw: bytes) -> str:
    """Ephemeral-X25519-Wrap — kompatibel mit frontend wrapBytesForPublicKey."""
    if len(public_key_raw) != 32:
        raise ValueError("Public-Key muss 32 Bytes sein.")
    ephemeral_private = x25519.X25519PrivateKey.generate()
    operator_public = x25519.X25519PublicKey.from_public_bytes(public_key_raw)
    shared = ephemeral_private.exchange(operator_public)
    key = _aes_key_from_shared(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, AAD_VAULT_DEK)
    eph_pub = ephemeral_private.public_key().public_bytes_raw()
    wrap = eph_pub + nonce + ct
    return base64.b64encode(wrap).decode("ascii")


def operator_recovery_private_key() -> bytes | None:
    from app.config import get_settings

    raw = (get_settings().vault_operator_recovery_private_key_hex or "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return None
    return key if len(key) == 32 else None


def unwrap_operator_recovery_wrap(wrap_blob_b64: str) -> bytes:
    """Tresor-Private-Key (PKCS#8) aus Betreiber-Recovery-Wrap."""
    private_key = operator_recovery_private_key()
    if private_key is None:
        raise ValueError("Betreiber-Recovery-Schlüssel nicht konfiguriert.")
    return unwrap_ephemeral_x25519_wrap_b64(wrap_blob_b64, private_key)


def load_x25519_private_raw_from_pkcs8(pkcs8_der: bytes) -> bytes:
    key = load_der_private_key(pkcs8_der, None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ValueError("Kein X25519-Private-Key.")
    return key.private_bytes_raw()
