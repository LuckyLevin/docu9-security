# docu9 — öffentlich nachprüfbare Sicherheitsquellen

Dieses Repository ist ein **kuratierter Spiegel** aus dem privaten docu9-Monorepo.

Es enthält:

- ausgewählte Architektur-Dokumente zu Verschlüsselung, Tresor, Krypto-Betrieb und Notfallkit
- die zugehörigen Code-Pfade `backend/app/crypto` und `frontend/lib/vault`

Es enthält **nicht** die vollständige Webanwendung, keine Infrastruktur-Secrets und keine Nutzerdaten.

## Wie der Spiegel entsteht

1. Quelle der Wahrheit: privates Monorepo (`docs/architecture/…`, Crypto-Pfade)
2. Allowlist: `docs/public-security/manifest.json`
3. `infra/scripts/sync-public-security.sh` kopiert die Allowlist nach `frontend/content/public-security` (Website-Build)
4. `infra/scripts/publish-public-security.sh` veröffentlicht denselben Stand hierher (Deploy)

Damit stimmen die Texte auf [docu9.de/sicherheit](https://docu9.de/sicherheit) und dieser Spiegel überein.

## Lizenz / Nutzung

Nur zur Nachprüfung des Sicherheitsmodells. Kein Anspruch auf ein lauffähiges Produkt-Setup.
