# 08 — Runbook: Krypto-Betrieb (Paket AA)

Operatives Handbuch für Master-Key-Verwahrung (Vault), Entschlüsselungs-Audit,
Backups und Key-Rotation. Zielgruppe: Betreiber vor Livegang.

## Übersicht

| Schritt | Inhalt | Status |
|---|---|---|
| AA1 | Master-Key in HashiCorp Vault Transit | Dev-Profil + `VaultKms` |
| AA2 | Entschlüsselungs-Audit-Log | umgesetzt |
| AA3 | Verschlüsselte Backups (`age`/`restic`) | umgesetzt (`infra/scripts/backup*.sh`) |
| AA4 | Key-Rotation (Transit-Rewrap, KEK-Rewrap) | umgesetzt |

---

## AA1 — Vault Transit (Master-Key)

### Architektur

- Anwendung kennt nur `Kms.wrap()` / `Kms.unwrap()` (`app/crypto/kms.py`).
- **Lokal/Dev:** `DOCU9_KMS=local` — Master-Key aus `DOCU9_MASTER_KEY` (`.env`, von `setup.sh`).
- **Produktion / Vault-Test:** `DOCU9_KMS=vault` — Wrap/Unwrap läuft gegen Vault Transit;
  der Master-Key verlässt Vault nie.

Chiffrate-Format: Vault liefert `vault:v1:…`; gespeichert als UTF-8 in `users.wrapped_kek`
und `documents.wrapped_dek` (kein Schema-Wechsel nötig).

### Lokaler Vault-Test (Compose-Profil)

```bash
# 1) Vault starten (Dev-Modus — nur für Entwicklung, nicht für Produktion)
docker compose --profile vault up -d vault

# 2) Transit-Engine, Policy, AppRole einrichten
./infra/scripts/vault-init-dev.sh

# 3) API + Worker mit Vault-KMS neu starten
docker compose --profile vault up -d --build api worker
```

Prüfen: Admin → Übersicht → Systemstatus sollte `vault_kms: ok` zeigen (wenn `DOCU9_KMS=vault`).

### Umgebungsvariablen

| Variable | Bedeutung |
|---|---|
| `DOCU9_KMS` | `local` (Default) oder `vault` |
| `DOCU9_VAULT_ADDR` | z. B. `http://vault:8200` im Compose-Netz |
| `DOCU9_VAULT_TRANSIT_KEY` | Transit-Key-Name (Default: `docu9-kek`) |
| `DOCU9_VAULT_TOKEN` | Statisches Token (nur Dev) |
| `DOCU9_VAULT_ROLE_ID` / `DOCU9_VAULT_SECRET_ID` | AppRole (Produktion) |

### Wechsel Local → Vault

**Bestehende Nutzer-KEKs aus LocalKms sind mit Vault nicht lesbar.** Optionen:

1. Frische Installation / leere DB für Vault-Tests.
2. AA4 Master-Key-Rotation mit Migrationspfad (Re-Wrap aller KEKs) — nur wenn Klartext-KEKs
   kurz verfügbar sind (Wartungsfenster).

### Produktion (Checkliste)

- [ ] Vault mit persistentem Storage, Unseal-Quorum (kein `-dev`-Modus).
- [ ] Transit-Key `docu9-kek` anlegen; **Export deaktiviert**.
- [ ] Policy: nur `transit/encrypt|decrypt|rewrap/docu9-kek`, kein `read` auf Key-Material.
- [ ] AppRole für `api`/`worker`; kein Root-Token in Containern.
- [ ] Vault Audit-Device aktiv (Datei/syslog).
- [ ] `DOCU9_MASTER_KEY` aus Produktions-`.env` entfernen, wenn `DOCU9_KMS=vault`.

---

## AA2 — Entschlüsselungs-Audit

- Tabelle `crypto_audit` (Migration 0016).
- Nutzer: Dokument-Detailseite → „Verschlüsselung nachprüfen“ → Protokoll.
- Admin: Tab „Entschlüsselungen“ (`GET /admin/crypto-audit`).

---

## AA3 — Verschlüsselte Backups

Ziel: PostgreSQL-Dumps und MinIO-Objekte mit einem **eigenen Backup-Schlüssel**
sichern — getrennt vom Master-Key (`DOCU9_MASTER_KEY`) und von Vault.

| Komponente | Werkzeug | Schlüssel |
|---|---|---|
| PostgreSQL (`docu9`, `keycloak`) | `pg_dump` → **age** | age-Privatschlüssel offline |
| MinIO (`docu9-documents`) | **restic** (lokales Repo unter `backups/restic-repo`) | Restic-Passwort offline |

### Einmalig: Schlüssel erzeugen

```bash
./infra/scripts/backup-keygen.sh
# → backups/keys/backup-key.txt       (PRIVAT — nie auf Produktionsserver)
# → backups/keys/backup-recipient.txt (öffentlich — darf für Cron auf Server)
# → backups/keys/restic-password.txt  (PRIVAT)
```

In Produktion: Privatschlüssel und Restic-Passwort **offline** (Safe, Passwort-Manager).
Auf dem Server nur `backup-recipient.txt` für geplante Backups.

Abhängigkeiten: `brew install age restic`

### Backup ausführen

Stack muss laufen (`docker compose up`).

```bash
export BACKUP_AGE_RECIPIENT=./backups/keys/backup-recipient.txt
export RESTIC_PASSWORD_FILE=./backups/keys/restic-password.txt
./infra/scripts/backup.sh
```

Erzeugt:

```
backups/
  restic-repo/              # verschlüsseltes Restic-Repo (MinIO-Snapshots)
  20260705T101500Z/
    manifest.json
    docu9.dump.age
    keycloak.dump.age         # falls vorhanden
```

### Restore-Probe (quartalsweise empfohlen)

Prüft Entschlüsselung und Archivintegrität — **ohne** Live-System zu überschreiben.

```bash
export BACKUP_AGE_KEY=./backups/keys/backup-key.txt
export RESTIC_PASSWORD_FILE=./backups/keys/restic-password.txt
./infra/scripts/backup-restore-probe.sh
# oder: ./infra/scripts/backup-restore-probe.sh backups/20260705T101500Z
```

### Vollständiger Restore (Notfall)

1. Postgres: `age -d -i backup-key.txt -o dump.sql docu9.dump.age` → `pg_restore -d docu9 dump`
2. MinIO: `restic restore latest --target /ziel/pfad`
3. Master-Key/Vault und Backup-Key sind **unabhängig** — beide werden für einen vollständigen Betrieb benötigt.

---

---

## AA4 — Key-Rotation

Zwei unabhängige Vorgänge:

### Master-Key (Vault Transit Re-Wrap)

Nach `vault write -f transit/keys/docu9-kek/rotate` in Vault eine neue Key-Version
erzeugen, dann alle `users.wrapped_kek` per Transit-`rewrap` auf die aktuelle Version
heben — **ohne** Dokument-DEKs anzufassen.

Voraussetzungen:

- `DOCU9_KMS=vault`
- Vault-Policy enthält `transit/rewrap/docu9-kek` (siehe `vault-init-dev.sh`)
- Verarbeitung pausieren empfohlen (Admin → Kill-Switch)

Ausführung:

```bash
# Admin-UI: Tab „Entschlüsselungen“ → Master Re-Wrap
# oder direkt:
./infra/scripts/rotate-master-keks.sh
# oder im Container:
docker compose exec api python scripts/rotate_keys.py rewrap-master
```

Bei `DOCU9_KMS=local` ist der Lauf ein No-Op (kein Vault-Format).

### Nutzer-KEK (auf Verlangen)

Neuer Zufalls-KEK pro Nutzer; alle `documents.wrapped_dek` und `export_jobs.wrapped_dek`
des Nutzers werden re-wrapped. Funktioniert mit LocalKms und Vault.

```bash
./infra/scripts/rotate-user-kek.sh <user-uuid>
# Admin-API: POST /admin/crypto/rotate-user-kek/{user_id}
```

Nutzer bleiben eingeloggt; bestehende Sessions sind unverändert. Offene Export-Jobs
mit altem DEK-Hüllen-Material werden mitrotiert.

### Celery-Tasks

| Task | Zweck |
|---|---|
| `pipeline.rewrap_master_keks` | Batch Re-Wrap aller Nutzer-KEKs |
| `pipeline.rotate_user_kek` | Ein Nutzer, alle DEKs |

Auslösung über Admin-API (`POST /admin/crypto/…`) — landet im Admin-Audit-Log.

---
