# Sandbox-Design (Paket E — nur Design, kein ausführender Code)

> Vermerk: **Diese Phase enthält keinen ausführenden Code.**
> Kein Container-/Prozess-Spawn, keine PoC-Ausführung, keine
> `verify_fix`-Automatik vor Umsetzung dieses Designs (REVIEW M-6).
> Ziel: E3-Validierung (PoC-Reproduktion) unter Isolation.

## 1. Threat Model

**Annahmen:** PoCs sind nicht vertrauenswürdig — sie stammen aus
Triage-Modellvorschlägen oder externen Reports und können
Schadverhalten enthalten (absichtlich oder via Halluzination).

**Angreiferziele / REVIEW-§4-Abdeckung:**

| # | Bedrohung (REVIEW §4 „Sandbox-Escape“) | Abdeckung |
|---|---|---|
| T1 | Host-Dateizugriff (Lesen/Schreiben außerhalb Scratch, z. B. `/etc/passwd`, SSH-Keys, Repo-Überschreiben) | §2 read-only Mounts, §3 N1 |
| T2 | Netzwerk-Egress (Exfiltration von Findings/Secrets, Malware-Download) | §2 kein Netz, §3 N2 |
| T3 | Ressourcen-Erschöpfung (Fork-Bombe, RAM-/Disk-Füllen → Host-DoS) | §2 Limits, Kill-Policy, §3 N3 |
| T4 | Persistenz/Escape (Cron, Autostart, Container-Breakout via Kernel-Exploit, Mount-Tricks) | §2 Drop-Caps/seccomp, ephemeral, §3 N4 |
| T5 | Secrets-Leak über PoC-Logs (Secrets in stdout → Report/Prompt) | Redaction (`cate-core::redact`) auf allen Sandbox-Logs vor Persistenz |

**Nicht-Ziele (explizit out of scope):** Kernel-Zero-Day-Resistenz,
Seitenkanal-Härtung, Windows-Host-Isolation im MVP (Linux-Container Pflicht).

## 2. Isolations-Architektur

- **Laufzeit:** ephemerer Linux-Container pro Run (ein PoC = ein Container,
  danach verwerfen; keine Wiederverwendung).
- **Netzwerk:** kein Netz (`--network none`); DNS/Loopback ebenfalls
  blockiert; Egress-deny ist Default, keine Allowlist im MVP.
- **Dateisystem:** Repo und Toolchain **read-only** gemountet;
  genau ein beschreibbares `scratch/`-Verzeichnis (Size-Quota);
  kein Mount von `$HOME`, `/etc`, Docker-Socket.
- **Privilegien:** non-root User, Drop all Capabilities,
  seccomp-Profil (Default-Deny), `no-new-privileges`.
- **Limits:** CPU-Quota (z. B. 1 CPU), RAM-Limit (z. B. 512 MiB),
  Wall-Clock-Timeout (Default 120 s, max 600 s), max Output-Bytes
  (z. B. 1 MiB, danach trunkiert).
- **Kill-Policy:** bei Timeout/Limitüberschreitung SIGKILL an die
  Container-Gruppe, Run als `TIMEOUT` werten (kein E3-Upgrade,
  kein E4); Exit-Code ≠ 0 des PoC ≠ Re-Test-bestanden.
- **Beobachtbarkeit:** nur Exit-Code + trunkierter stdout/stderr +
  Ressourcen-Peak; alles durch Secrets-Redaction vor Ablage im Report.

## 3. Negativ-Tests (müssen fehlschlagen / blockiert werden)

Jeder Test läuft als PoC in der Sandbox; erwartet ist jeweils die
**Blockade**, nicht die Ausführung:

- **N1 Host-Read:** PoC versucht `cat /etc/passwd` bzw. liest eine
  außerhalb `scratch/` gelegene Canary-Datei.
  Erwartet: Lesefehler / leeres Ergebnis; Canary unverändert.
- **N2 Netz-Egress:** PoC versucht `curl https://example.com`
  (bzw. DNS-Lookup + TCP-Connect auf öffentliche IP).
  Erwartet: Verbindungsfehler/Timeout; kein Paket verlässt den Host.
- **N3 Fork-Bombe / RAM-Fresser:** PoC startet `:(){ :|:& };:` bzw.
  allokiert fortlaufend Speicher.
  Erwartet: Prozessgruppe wird per Limit gekillt (OOM-Kill oder
  PIDs-Limit), Run endet als `TIMEOUT`/Kill, Host bleibt reaktionsfähig.
- **N4 Persistenz/Escape:** PoC schreibt Cron-/Autostart-Eintrag,
  mountet Host-Pfade oder liest den Docker-Socket.
  Erwartet: Schreib-/Mount-Fehler (read-only), Socket nicht vorhanden;
  Folge-Run startet ohne Artefakte des Vorlaufs (Ephemeralität).

Abnahme: Alle vier Negativ-Tests sind dokumentiert und werden bei
Umsetzung der Sandbox (Phase 4+) als Gate ausgeführt — ein
bestandenes N1–N4 (d. h. Escape gelingt) blockiert das Release.

## 4. Bezug zu `verify_fix` / E3→E4

- E3 (reproduziert) setzt einen Sandbox-Run mit PoC-Erfolg voraus.
- E4 setzt `verify_fix` mit Sandbox-Re-Test voraus (Spec: `docs/MCP_TOOLS.md`).
- Ohne verfügbare Sandbox antwortet `verify_fix` mit `NO_SANDBOX`;
  es gibt keinen Host-Fallback.
