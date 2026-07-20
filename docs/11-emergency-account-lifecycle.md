# Notfallzugriff & Konto-Lebenszyklus (Abo, Kosten, Sperre)

Stand: Paket U+ — Konzept für den Zeitraum **nach** freigegebenem Notfall-Lesezugriff.

## Ausgangslage

Wenn eine Vertrauensperson den Notfallzugriff anstößt und die Warteschleife ohne Veto abläuft, entsteht ein **read-only Notfallportal** (Kit-Dokumente + Notfallinfos). Der Haushalts-Inhaber ist in dieser Phase oft **nicht mehr handlungsfähig** — das ist der Sinn des Features.

Gleichzeitig läuft das docu9-Konto technisch weiter: Speicher, Datenbank, ggf. Credits oder (Phase 2) ein Abo kosten den Betrieb Geld.

**Kernfrage:** Soll das Konto eingefroren, gekündigt oder unverändert weiterlaufen?

## Leitprinzipien

1. **Notfallportal ≠ Konto-Sperre.** Vertrauenspersonen brauchen stabilen Lesezugriff; ein hartes „Account freeze“ darf den Kit-Zugriff nicht versehentlich beenden.
2. **Kein automatisches Löschen.** Daten können für Erben, Versicherungen und Behörden noch relevant sein — Löschung nur nach explizitem, nachvollziehbarem Wunsch (Inhaber zu Lebzeiten, Erben, Vollmacht).
3. **Kosten ehrlich, aber menschlich.** Der Betrieb soll nicht unbegrenzt zulasten Dritter laufen — aber Hinterbliebene sollen nicht in der Trauer mit Kündigungsfristen kämpfen müssen.
4. **Inhaber-Rückkehr bleibt möglich.** Veto ist vorbei, aber der Inhaber kann sich jederzeit wieder anmelden (z. B. Fehlalarm).

## Zustandsmodell (vorgeschlagen)

| Phase | Auslöser | Inhaber-Login | Notfallportal | KI / Auto-Verarbeitung | Abrechnung |
|---|---|---|---|---|---|
| **Normal** | — | ja | inaktiv | normal | normal |
| **Warteschleife** | Anfrage gestartet | ja (+ Veto) | noch gesperrt | normal | normal |
| **Notfall-Lesezugriff aktiv** | Warteschleife abgelaufen | ja | read-only für VP | **pausiert** (empfohlen) | **Ruhephase** (s. u.) |
| **Ruhephase beendet** | VP-Zugriff abgelaufen oder manuell beendet | ja | inaktiv | wieder normal oder Konto archiviert | siehe unten |

Technisch ableitbar aus `EmergencyAccessRequest.status == approved` (optional mit `expires_at == NULL` im Endlos-Modus).

## Empfohlene Policy: „Ruhephase“ statt Kontosperre

### Was weiter funktioniert

- **Notfallportal** (Token + Code) — unverändert, bis Lesezugriff endet oder Endlos-Modus vom Inhaber widerrufen wird.
- **Inhaber-Login** — ja, inkl. Export, Protokoll einsehen, Veto war nur in der Warteschleife relevant.
- **Speicher & Kit** — bleiben erhalten; kein automatisches Purge.

### Was pausiert wird (Kosten senken)

- **Auto-Verarbeitung / LLM-Pipeline** für den Space — keine neuen Analysen, keine Embedding-Jobs.
- **E-Mail-Ingest-Verarbeitung** (wenn aktiv) — optional nur Annahme, ohne Pipeline.
- **Credit-Abbuchungen** für KI — aussetzen während aktivem Notfall-Lesezugriff.

### Abo / Subscription (Phase 1.6 heute, Stripe Phase 2)

**Heute (Credits, kein Stripe-Abo):**

- Keine automatische Tier-Änderung.
- Während aktivem Notfall-Lesezugriff: **keine KI-Nutzung → keine Credit-Kosten**.
- Speicher-Kosten bleiben; im UI Hinweis an Vertrauenspersonen / Erben über Kontaktformular.

**Phase 2 (Stripe-Abo):**

| Option | Empfehlung |
|---|---|
| Abo läuft ungehindert weiter | ❌ — unfair gegenüber Hinterbliebenen, teuer für Betrieb |
| Sofortige Hard-Sperre | ❌ — blockiert Export, Portal, ggf. Rechtsnachfolger |
| **Ruhephase (Grace)** | ✅ — empfohlen |

**Ruhephase im Abo:**

- Ab **Freigabe** des Notfall-Lesezugriffs: Stripe-Abo in **`paused`** (Stripe Billing Pause) oder internes Flag `subscription_pause_reason = emergency` — **keine neuen Abbuchungen**.
- **Leistung:** Read-only Notfallportal + Voll-Export für eingeloggte Space-Mitglieder + Datenhaltung.
- **Dauer:** Mindestens bis Ende des konfigurierten Lesezugriffs; im **Endlos-Modus** 12 Monate Grace, danach E-Mail an hinterlegte Kontakte + docu9-Kontakt — Kündigung oder Verlängerung durch Erben/Vollmacht, nicht automatisch.
- **Reaktivierung:** Inhaber meldet sich → normaler Betrieb, Abo pause aufheben.
- **Kein Inhaber, kein Kontakt:** Nach dokumentiertem Fristablauf → Konto **archivieren** (kein Login, Portal bleibt read-only bis VP-Zugriff endet), dann **Löschung nach gesetzlicher Aufbewahrungsfrist** (Export-Angebot vorher).

## Wer kann was entscheiden?

| Aktion | Wer |
|---|---|
| Veto in Warteschleife | Inhaber (Link / Login) |
| Lesezugriff Endlos vs. Tage | Inhaber (Einstellungen) |
| Abo pausieren / beenden | Inhaber zu Lebzeiten; danach Erben mit Nachweis über Support |
| Daten exportieren | Space-Mitglieder mit Login; VP nur Kit via Portal |
| Konto endgültig löschen | Nur nach explizitem Antrag + Wartezeit (Datenhoheit-Paket) |

## UI / Kommunikation

- In `/notfall` (Ehrlichkeits-Hinweis): Kurzfassung — „Aktiver Notfall-Lesezugriff pausiert KI-Kosten; das Konto wird nicht automatisch gelöscht.“
- In Freigabe-Mail / Portal: Hinweis auf Ruhephase, Kontaktformular docu9.de.
- Im Portal: VP kann **Ruhephase beantragen** (optional mit Nachricht) — **Inhaber freigibt in Notfall → Verwaltung**; nichts automatisch.
- Für Erben: Support-Prozess (Identität / Vollmacht), kein Self-Service-Löschen durch VP — siehe [12-support-tickets-anforderungen.md](12-support-tickets-anforderungen.md).

## Umsetzungs-Roadmap

| Stufe | Inhalt |
|---|---|
| **U+ (jetzt)** | Endlos-Modus Lesezugriff; Konzept-Dokument; UI-Hinweis |
| **U8 (teilweise)** | Ruhephase-Antrag durch VP, Freigabe durch Inhaber, `emergency_ruhephase_active`, Pipeline-Skip; Stripe Pause offen |
| **Phase 2** | Stripe Pause Webhook; Grace-Timer; Erben-Support-Workflow |

## Offene Rechtsfragen (extern klären)

- Pflicht zur Datenweitergabe an Erben vs. DSGVO-Löschrecht.
- Ob Ruhephase als „berechtigtes Interesse“ am Erhalt von Vorsorgeunterlagen ausreicht.
- Mindestfrist vor endgültiger Löschung inaktiver Konten.

---

*Verwandt: [06-roadmap.md](06-roadmap.md) Paket U, [07-zero-knowledge.md](07-zero-knowledge.md) §3.7 Notfallkit.*
