# docu9 — öffentlich nachprüfbare Sicherheitsfunktionen

Dieses Repository ist ein **kuratierter Code-Spiegel** aus dem privaten docu9-Monorepo.

Es enthält ausschließlich die Sicherheits-Implementierung:

- `backend/app/crypto` — Server-Krypto (Envelope, KMS, Notfall-Code)
- `frontend/lib/vault` — Client-Tresor (WebCrypto / Passkey-PRF)

Es enthält **nicht**:

- Architektur- oder Prozess-Dokumentation
- die vollständige Webanwendung
- Infrastruktur-Secrets oder Nutzerdaten

## Wie der Spiegel entsteht

1. Quelle der Wahrheit: privates Monorepo (Crypto-/Vault-Pfade)
2. Allowlist: `docs/public-security/manifest.json` → Abschnitt `codeTrees`
3. `infra/scripts/sync-public-security.sh` bereitet den Staging-Stand vor
4. `infra/scripts/publish-public-security.sh` veröffentlicht ihn hierher (Deploy)

Produktbeschreibung und Erläuterungen stehen auf [docu9.de/sicherheit](https://docu9.de/sicherheit) — nicht in diesem Repo.

## Lizenz / Nutzung

Nur zur Nachprüfung der Sicherheitsfunktionen. Kein Anspruch auf ein lauffähiges Produkt-Setup.
