"""KMS-Abstraktion (ADR-09).

Lokal: Master-Key aus der Umgebung (setup.sh erzeugt ihn). In Produktion wird dieses
Interface gegen HashiCorp Vault Transit implementiert (AA1) — die restliche Anwendung
kennt nur wrap/unwrap. Der Master-Key verlässt Vault dann nie und liegt in keinem
Prozess-Speicher von `api`/`worker` mehr.
"""

import base64
import os
import threading
import time
from typing import Protocol

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings


class Kms(Protocol):
    def wrap(self, key: bytes) -> bytes: ...
    def unwrap(self, wrapped: bytes) -> bytes: ...


class LocalKms:
    """AES-256-GCM-Wrapping mit einem Master-Key aus der Umgebung."""

    def __init__(self, master_key_b64: str):
        master_key = base64.b64decode(master_key_b64)
        if len(master_key) != 32:
            raise ValueError("DOCU9_MASTER_KEY muss 32 Bytes (base64) sein")
        self._aead = AESGCM(master_key)

    def wrap(self, key: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, key, b"docu9-kek-wrap")

    def unwrap(self, wrapped: bytes) -> bytes:
        nonce, ct = wrapped[:12], wrapped[12:]
        return self._aead.decrypt(nonce, ct, b"docu9-kek-wrap")


class VaultKms:
    """HashiCorp Vault Transit-Engine (AA1).

    `wrap`/`unwrap` laufen als API-Calls gegen Vault — der Master-Key (KEK-Wrapping-Key)
    verlässt Vault nie. AuthN via AppRole (kurzlebige Tokens, hier gecacht bis kurz vor
    Ablauf) oder ein statisches Token (Dev). Policy in Produktion: nur
    `transit/encrypt/<key>` + `transit/decrypt/<key>`, keine Export-Rechte.

    Speicherformat: Vault liefert Chiffrate als String `vault:v1:<base64>`. Wir speichern
    diesen String utf-8-kodiert in den bestehenden LargeBinary-Spalten (`wrapped_kek`,
    `wrapped_dek`), sodass kein Schema-Wechsel nötig ist.
    """

    def __init__(
        self,
        *,
        addr: str,
        transit_mount: str,
        transit_key: str,
        role_id: str = "",
        secret_id: str = "",
        token: str = "",
        approle_mount: str = "approle",
    ):
        self._addr = addr.rstrip("/")
        self._mount = transit_mount.strip("/")
        self._key = transit_key
        self._role_id = role_id
        self._secret_id = secret_id
        self._static_token = token
        self._approle_mount = approle_mount.strip("/")
        self._client = httpx.Client(base_url=self._addr, timeout=10.0)
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_expiry: float = 0.0

    # --- AuthN -----------------------------------------------------------------

    def _current_token(self) -> str:
        if self._static_token:
            return self._static_token
        with self._lock:
            # 30s Sicherheitsabstand vor Ablauf, dann neu einloggen
            if self._token and time.monotonic() < self._token_expiry - 30:
                return self._token
            if not (self._role_id and self._secret_id):
                raise KmsError("Vault AppRole nicht konfiguriert (role_id/secret_id fehlen)")
            resp = self._client.post(
                f"/v1/auth/{self._approle_mount}/login",
                json={"role_id": self._role_id, "secret_id": self._secret_id},
            )
            if resp.status_code != 200:
                raise KmsError(f"Vault AppRole-Login fehlgeschlagen: {resp.status_code} {resp.text[:200]}")
            auth = resp.json()["auth"]
            self._token = auth["client_token"]
            self._token_expiry = time.monotonic() + int(auth.get("lease_duration", 3600))
            return self._token

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._current_token()}

    # --- wrap/unwrap -----------------------------------------------------------

    def wrap(self, key: bytes) -> bytes:
        payload = {"plaintext": base64.b64encode(key).decode("ascii")}
        resp = self._client.post(
            f"/v1/{self._mount}/encrypt/{self._key}", json=payload, headers=self._headers()
        )
        if resp.status_code != 200:
            raise KmsError(f"Vault encrypt fehlgeschlagen: {resp.status_code} {resp.text[:200]}")
        ciphertext = resp.json()["data"]["ciphertext"]
        return ciphertext.encode("utf-8")

    def unwrap(self, wrapped: bytes) -> bytes:
        payload = {"ciphertext": wrapped.decode("utf-8")}
        resp = self._client.post(
            f"/v1/{self._mount}/decrypt/{self._key}", json=payload, headers=self._headers()
        )
        if resp.status_code != 200:
            raise KmsError(f"Vault decrypt fehlgeschlagen: {resp.status_code} {resp.text[:200]}")
        return base64.b64decode(resp.json()["data"]["plaintext"])

    def rewrap(self, wrapped: bytes) -> bytes:
        """AA4: Re-Wrap auf die aktuelle Transit-Key-Version, ohne den DEK zu sehen.

        Master-Key-Rotation in Vault erzeugt eine neue Key-Version; bestehende Chiffrate
        bleiben entschlüsselbar, lassen sich aber per `rewrap` auf die neue Version heben.
        """
        payload = {"ciphertext": wrapped.decode("utf-8")}
        resp = self._client.post(
            f"/v1/{self._mount}/rewrap/{self._key}", json=payload, headers=self._headers()
        )
        if resp.status_code != 200:
            raise KmsError(f"Vault rewrap fehlgeschlagen: {resp.status_code} {resp.text[:200]}")
        return resp.json()["data"]["ciphertext"].encode("utf-8")


class KmsError(RuntimeError):
    pass


_kms: Kms | None = None


def _build_kms() -> Kms:
    s = get_settings()
    if s.kms == "vault":
        return VaultKms(
            addr=s.vault_addr,
            transit_mount=s.vault_transit_mount,
            transit_key=s.vault_transit_key,
            role_id=s.vault_role_id,
            secret_id=s.vault_secret_id,
            token=s.vault_token,
            approle_mount=s.vault_approle_mount,
        )
    return LocalKms(s.master_key)


def get_kms() -> Kms:
    global _kms
    if _kms is None:
        _kms = _build_kms()
    return _kms


def rewrap_master(wrapped: bytes) -> bytes:
    """AA4: Master-Key-Rotation — Chiffrate auf die aktuelle KMS-/Vault-Key-Version heben.

    Bei LocalKms oder nicht-Vault-Format: No-Op (Bytes unverändert). Vault Transit
    benötigt das `vault:v…`-Stringformat aus `VaultKms.wrap`.
    """
    kms = get_kms()
    rewrap_fn = getattr(kms, "rewrap", None)
    if rewrap_fn is None:
        return wrapped
    try:
        text = wrapped.decode("utf-8")
    except UnicodeDecodeError:
        return wrapped
    if not text.startswith("vault:v"):
        return wrapped
    return rewrap_fn(wrapped)
