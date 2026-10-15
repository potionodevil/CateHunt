# Sandbox-Design (Paket E — Design + M-6-Prozess-Sandbox)

> Stand M-6 (2026-10-15): Die minimale **Prozess-Sandbox** ist
> implementiert (`crates/cate-sandbox/`): argv-Array (nie Shell-String),
> Allowlist oder expliziter Pfad, Timeout + Kill, Output-Cap, isoliertes
> Scratch-Verzeichnis (Path-Jail), Audit-Log-Eintrag pro Run.
> Container-Isolation (Netz-Deny, read-only Mounts, seccomp,
> Prozessgruppen-Kill per Job-Objekt/cgroups) bleibt Phase 5+ und ist
> unten als Restrisiko vermerkt.
>
> Urspruenglicher Vermerk (weiter gueltig fuer Container-Stufe): **Kein
> Container-/Prozess-Spawn ... vor Umsetzung dieses Designs (REVIEW M-6).**
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

## 3a. Gate-Umsetzung S3 (`ci/sandbox/`, Workflow `sandbox-n1n4`)

- **Profil:** `ci/sandbox/run.sh` — ein PoC = ein ephemerer Container
  (`docker create` + Trap-`rm -f`, `--rm`-äquivalent), `--network none`,
  `--read-only` + genau ein tmpfs-`scratch` mit `size=`-Quota, `--user 65532`,
  `--cap-drop ALL`, `no-new-privileges`, `seccomp.json` (Default-Deny),
  `--memory/--cpus/--pids-limit`, Wall-Clock-Timeout + sofortiges SIGKILL
  (Kill-Budget < 5 s, gemessen). Runtime `runsc` (gVisor) wenn vorhanden,
  sonst runc mit Warnung. Image `Dockerfile` per Digest gepinnt.
- **Checks:** `n1_host_read.sh` … `n4_persist.sh`, Konvention Exit 0 =
  Blockade (PASS), Exit 1 = Escape (FAIL, blockiert Release).
  `gate.sh` orchestriert: `--self-check` (Syntax/JSON), `--dry-run`
  (statischer Profil-Check ohne Daemon), Voll-Lauf (Linux + Daemon).
- **SKIP-Regel:** ohne Linux oder ohne Daemon meldet das Gate laut
  `GATE_STATUS=SKIP` mit `::warning::` — nie still-fein. Echte Prüfung nur
  auf dem Linux-CI-Runner (`.github/workflows/sandbox-n1n4.yml`, ergänzt
  `harness.yml`, baut ihn nicht um).
- **Betrieb:** Checkliste (Kill < 5 s, Egress-Log, Pinning+Signatur, p99,
  keine Standing Credentials) in `ci/sandbox/README.md`; dort auch die
  ehrliche Liste, was CI-seitig noch fehlt (runsc-Install, cosign,
  Egress-Shipping, p99-Zahl, seccomp-Smoke-Bestätigung).

## 4. Bezug zu `verify_fix` / E3→E4

- E3 (reproduziert) setzt einen Sandbox-Run mit PoC-Erfolg voraus.
- E4 setzt `verify_fix` mit Sandbox-Re-Test voraus (Spec: `docs/MCP_TOOLS.md`).
- Ohne verfügbare Sandbox antwortet `verify_fix` mit `NO_SANDBOX`;
  es gibt keinen Host-Fallback.

> Umsetzung M-6 (`crates/cate-mcp/src/lib.rs`): `catehunt_verify_fix_with`
> mit injizierbarem `RetestRunner` (Prod: `SandboxRetestRunner` auf Basis
> `cate-sandbox`; Tests: Mock, kein echter Exec). E3→E4 nur bei
> bestandenem Re-Test (Exit 0, kein Timeout); sonst bleibt E3. Ohne Runner
> weiter `NO_SANDBOX` (Fail-Closed). `params.test_command` wird nie als
> Shell ausgefuehrt — der Runner nutzt Operator-argv.

## 5. M-6/S2-Implementierung (`crates/cate-sandbox`): Garantien + Restrisiken

Garantiert M-6 (getestet in `crates/cate-sandbox/tests/sandbox.rs`):

- **Kein Shell-String:** API nimmt `program` + `args: &[&str]`; es gibt
  keinen Codepfad, der einen Shell-String baut (`Command` direkt).
- **Binary-Policy:** blosser Name nur bei Allowlist-Treffer, sonst
  `BinaryNotAllowed` (Negativ-Test, kein Spawn); absoluter Pfad nur bei
  existierender Datei; relative Pfade mit Separator (`sub/tool`, `../x`)
  immer abgelehnt.
- **Scratch-Jail:** `resolve_in_scratch` lehnt absolut, `..`, Laufwerk,
  Tilde und NUL ab (Negativ-Test); Runs laufen mit `current_dir = scratch`.
- **Timeout + Kill:** Poll (10 ms), danach Kill + `timed_out=true`,
  Run zaehlt als nicht bestanden (Negativ-Test: 30-s-Sleep bei 2-s-Timeout).
- **Output-Cap:** pro Stream (Default 1 MiB), Reader-Threads drainen weiter
  (kein Pipe-Deadlock); `truncated`-Flag + Audit-Eintrag.
- **Audit:** pro Run `{run_id, program, argv_len, timeout, exit, timed_out,
  truncated, started_unix_ms}` als JSON.

Garantiert S2-Haertung (2026-10-15, getestet ebd.):

- **R4 Env-Hygiene (geschlossen):** `env_clear` + explizite Allowlist
  (`default_env_allowlist`: `PATH`, `SystemRoot`/`SystemDrive`/`COMSPEC`/
  `PATHEXT`/`OS`, `TEMP`/`TMP`/`TMPDIR`, `LANG`/`LC_ALL`/`TZ`,
  `HOME`/`USER`/`USERNAME`); Operator-Zusatz nur via `extra_env`.
  Tests: Canary-Env im Kind unsichtbar, Eltern-Secret erreicht Kind nie
  (mit `extra_env`-Positivkontrolle), Proxy-Creds (`HTTP(S)_PROXY`,
  `ALL_PROXY`) nie vererbt. Secrets-Redaction vor Persistenz bleibt
  Pflicht (Defense-in-Depth, unveraendert).
- **R1 Kind-Kill (geschlossen):** Windows Job-Objekt
  (`KILL_ON_JOB_CLOSE`, Guard bis Run-Ende, expliziter Drop vor Drain),
  Unix eigene Prozessgruppe (`setpgid` pre-exec, fail-closed) + SIGKILL
  an die Gruppe. Fail-closed: kein Job/keine Gruppe → kein Run
  (`SpawnFailed`) statt uncontained. Test: Spawner-Enkel mit Heartbeat
  stirbt mit dem Timeout (kein Beat nach Kill + Nachfrist).
- **R3 Limits (teilweise geschlossen, Rest dokumentiert):** Windows
  `ActiveProcessLimit` (Default 64, pro Job sicher) + optional
  `ProcessMemoryLimit`; Linux `setrlimit` (`NPROC`/`AS`/`FSIZE`/`CPU`,
  opt-in, kein NPROC-Default wegen Pro-UID-Semantik). Tests: begrenzte
  Fork-Bombe stirbt (Windows: Quota-Fehler → Fail-Exit in Sekunden;
  Linux: Gruppen-Kill), Disk-Fueller stoppt an `RLIMIT_FSIZE`
  (Linux-Test), Host bleibt reaktiv (Folge-Run-Test).
  Zusaetzlich: Drain-Grace (3 s) — Enkel-vererbte Pipes koennen
  `join()` sonst ueber das Kind-Ende hinaus blockieren (beobachtet:
  60-s-Enkel-Pings); Abandon zaehlt als `truncated`, nie als Haenger.
- **R2 Light (teilweise, kein Egress-Deny):** Kind erbt keine
  Proxy-Umgebung (keine ambient Proxy-Creds/Weiterleitung); Doku,
  dass echtes Netz-Deny erst S3 kann (s. Restrisiken).

Offene Restrisiken (S3-Container-Pflicht bleibt):

- **R2 Egress:** auf Prozessebene nicht blockiert (N2). Loopback kann
  prozesslokal nicht auf einen Scratch-Portbereich eingeschraenkt
  werden — S3 (`--network none`) ist das einzige ehrliche Deny.
- **R1 Session-Escape (Linux):** Enkel mit eigenem `setsid`/neuer
  Session entkommen der Prozessgruppe (SIGKILL an PGID erreicht sie
  nicht) — braucht cgroups/`pids`-Controller (S3).
- **R3 harte RAM-/CPU-Kappen:** kein Default (braeche legitime
  Toolchains: `RLIMIT_AS` pro Prozess, `RLIMIT_NPROC` pro UID sind
  keine Sandbox-Semantik); echte `memory.max`/`cpu.max` erst S3.
  Clean-Exit mit daemonisierenden Enkeln (Unix): kein Gruppen-Kill
  nach Erfolg, nur Drain-Grace — verwaiste Enkel reaped `init`
  (S3-Ephemeralitaet loest das sauber).
- **R1/R3 Host-in-Job:** laeuft der Host selbst in einem Windows-Job
  ohne Nested-Job-Support, schlaegt jeder Spawn fail-closed fehl
  (sicher, aber S3-Deployment muss Nested-Jobs erlauben).
- **N1/N4-Erzwingung:** Host-Read/Persistenz ausserhalb Scratch sind
  per Policy (Allowlist, Jail), nicht per read-only Mounts/seccomp
  erzwungen — S3-Gate N1–N4 bleibt bindend.

Die Container-Negativ-Tests N1–N4 (§3) bleiben Abnahme-Gate fuer S3;
M-6 deckt die Prozess-Schicht (Binary-, Pfad-, Timeout-, Cap-Tests) ab,
S2 die Haertungsschicht (Env-, Kind-Kill-, Limit-, Drain-Tests).

## 6. S4 — Staged Confinement (Stufen-Matrix, Dry-Run-Regel)

Faehigkeiten trennen statt vertrauen (Sandlock-Prinzip): Eine Stufe mit
Netz sieht nie Findings/Secrets, eine Stufe mit Findings hat nie Netz —
das bricht die lethal trifecta bei Prompt-Injection. Umsetzung ohne
S3-CI als Typ-/API-Regel in `crates/cate-triage/src/pipeline.rs`
(`StageCaps`, `stage_caps`/`fallback_caps`, `check_chain_caps`,
`assert_prompt_secret_free`); Dry-Run als reiner Datentyp in
`crates/cate-graph/src/proposal.rs` (`ApplyPreview`,
`preview_apply`/`apply_with_preview`).

### Stufen-Matrix

| Stufe | Netz | Roh-Daten (Findings/Secrets) | Kontext |
|---|---|---|---|
| Ollama | JA (nur Loopback) | NEIN | nur redigierter Prompt (`build_prompt` + `assert_prompt_secret_free`) |
| Gemini | JA (CLI-Subprozess, Cloud) | NEIN | nur redigierter Prompt (ebd.) |
| Deep | JA (CLI-Subprozess, Cloud) | NEIN | nur redigierter Prompt (ebd.) |
| Deterministischer Fallback | NEIN (rein, kein Spawn/Netz) | JA (Cache + Snippet lokal) | volle lokale Daten, nie versendet |

`StageCaps::new(true, true)` ist undarstellbar (`None`), `check` und
`check_chain_caps` lehnen verbotene Kombinationen zur Laufzeit ab
(Stufen-Matrix-Test: Netz-Stufe ohne Daten / Daten-Stufe ohne Netz;
redact-Test: kein Secret in ollama-/gemini-/deep-Prompts).

### Dry-Run-Regel

Fix-Anwendung nur als Preview-then-Apply: `preview_apply` beschreibt
den Effekt, ohne zu schreiben (kein Statuswechsel, read-only); `apply`
(`apply_with_preview`) erst mit passender Preview (id-Match) aus
`Approved` — sonst `APPROVAL_REQUIRED`. Reiner Datentyp + Tests
(Dry-Run-Roundtrip: Preview → JSON-Roundtrip → Apply; fremde Preview
und Apply-ohne-Approval scheitern); keine UI-Aenderung.

### Was S4 noch von S3 braucht

Die S4-Trennung ist auf Prozessebene eine API-/Konventions-Garantie
(redigierte Prompts, Caps-Checks), keine erzwungene Isolation: Erst
S3 (`--network none`, read-only Mounts, seccomp, N1–N4-Gate in
`ci/sandbox/`) macht aus Netz-NEIN/Daten-JA eine Container-Garantie
(s. §5 Restrisiken R1/R2/R3, §3/§3a). S4 aendert nichts am Gate:
Kein S4-Release ohne bestandenes N1–N4-Gate.

### S4-2026 Ergaenzung: Sandbox-Profilschicht (`crates/cate-sandbox`)

Neben der API-Regel-Trennung (oben, `cate-triage`) traegt `cate-sandbox`
die Stufen sich direkt (getestet: `tests/stage_profile.rs`):

- **`StageProfile`** (`Network` | `Data` | `Neutral`): Confinement-Profil
  einer Pipeline-Stufe, mit `config_for_profile` abgeleiteter
  `SandboxConfig` (S2-Default-Limits + Profil-Env-Allowlist). Stufen-Matrix:

  | Profil    | Netz | Roh-Daten | Kontext |
  |-----------|------|-----------|---------|
  | `Network` | JA   | NEIN      | nur `RedactionOutput`-argv |
  | `Data`    | NEIN | JA        | Rohtext lokal (scratch-only), nie versendet |
  | `Neutral` | NEIN | NEIN      | weder noch (Cleanup-/Hilfs-Stufe) |

  Alle Profile erben bewusst STETS KEINE Proxy-Variablen
  (`HTTP(S)_PROXY`/`ALL_PROXY`, R2-light) und keine Secret-/Token-Variablen
  (R4, Defense in Depth) — auch `Data` nicht. `Data` bekommt zusaetzlich
  Home-Mapping (`HOME`/`USER`/`USERNAME`/`PATHEXT`) für lokale Tools.
- **`RedactionOutput`**: Datenkontakt-Typ, aus dem Netz-Stufen ihre
  argv ausschliesslich bauen — Roh-Findings/Secrets sind am Spawn-
  Zeitpunkt bereits redigiert («redacted:…»). Roh-args via
  Netz-Stufe sind über die Runner-API nicht darstellbar.
- **`FixDryRunPreview` / `FixDryRunEffects`** (`capture_effects`): Dry-
  Run-/COW-Ebene für Fix-Vorschlaege — Effekte eines Preview-Run
  (Exit-Code, Output-Laengen, Trunkierungs-Flags, nie Inhalte)
  werden als serde-Datensatz gecaptured und roundtript; Apply stammt
  weiterhin ausschliesslich aus dem `cate-mcp` ProposalStore
  (Approval-Gate + Audit unveraendert); hier nur die
  Capture-Ebene ohne Schreibeffekt (getestet: JSON-Roundtrip,
  kein Run-Inhalt im Preview-Datensatz).
- **TOCTOU-sichere exec-Pruefung** (`toctou_resolve`): Pfad-NACH-
  Aufloesung gegen Allowlist/Pfad-Regel — `resolve_program` →
  `symlink_metadata` → `File::open` → `canonicalize` →
  Abweichungs-/Escape-Check (Windows case-insensitive, `\\?\`-Praefix-
  tolerant; Unix Byte-vergleich). Fail-closed: Abweichung, fehlendes
  Ziel, Oeffnen- oder Kanonisierungs-Fehler → `BinaryNotAllowed`
  (kein Zurueckfallen auf den ungeprueften Pfad). Der Spawn nutzt den
  aufgelösten Pfad statt des Raw-Strings, sodass zwischen Prüfen und
  Spawnen kein Zeitfenster mehr offen ist. Tests (`tests/toctou.rs`,
  Windows-kompatibel via Junctions): Kanonische-Auflösung,
  Symlink-/Junction-Austausch nach Pruefung → verweigert und
  fehlendes Ziel → fail-closed.

Wichtig: Die S4-Profilschicht ist ein Policy-Layer, der die
Container-Gate-Pflicht NICHT ersetzen kann — `Network` blockt
Netz-Draehte nicht auf Prozessebene (§5-R2-Restrisiko) und liest
`Data` weiterhin auch ausserhalb scratch liegende Dateien (N1/N4,
§5-Restrisiko N1/N4) bis zur S3-Laufzeit-Erzwingung. S3-Gate N1–N4
bleibt bindend.
