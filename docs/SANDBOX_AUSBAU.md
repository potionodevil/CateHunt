# Sandbox-Ausbau (Phasen S1–S4, Stand 2026-10-15)

> Follow-up zu `docs/SANDBOX_DESIGN.md`. S1 (Prozess-Sandbox,
> `crates/cate-sandbox/`) ist implementiert und getestet. Dieses Dokument
> plant S2–S4. Recherche-Basis: gVisor/Firecracker-Vergleiche (fly.io),
> Agent-Sandbox-Praxis (E2B/Modal/Kata, Vercel/AWS-Lambda-Muster),
> Sandlock-Paper (staged confinement, COW, seccomp-supervisor),
> On-Prem-Checklisten (no standing credentials, default-deny egress,
> ephemeral state, hard limits, audit everything).

## S1 — Prozess-Schicht (FERTIG)

`crates/cate-sandbox/`: argv ohne Shell, Allowlist, Timeout+Kill,
Output-Cap, Scratch-Jail, JSON-Audit. `verify_fix` nutzt
`SandboxRetestRunner`, sonst `NO_SANDBOX` (Fail-Closed).
Abnahme: 6 Negativ-Tests in `crates/cate-sandbox/tests/sandbox.rs` fein.

## S2 — Prozess-Härtung (nächster Schritt, Aufwand S–M)

Schliesst R1/R3/R4 ohne Container (Windows + Linux):

- **R4 Env-Hygiene:** `env_clear` + explizite Allowlist (`PATH`, `SystemRoot`,
  `TEMP`); Secrets nie ans Kind (Test: Canary-Env im Kind unsichtbar).
- **R1 Kind-Kill:** Windows Job-Objekt (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`),
  Linux Prozessgruppe (`setpgid` + Kill an Gruppe); Test: Spawner mit
  Kind überlebt Timeout nicht.
- **R3 Limits:** PIDs-/Speicher-Limits wo OS-seitig möglich
  (Windows Job-Limits, Linux `setrlimit` + cgroup wo verfügbar);
  Fallback dokumentieren. Test: Fork-Bombe stirbt, Host bleibt reaktiv.
- **R2 Light:** Loopback auf Scratch-Portbereich einschränken, Doku dass
  echtes Egress-Deny erst S3 kann (kein falsches Versprechen).
- **Abnahme:** erweiterte `sandbox.rs`-Negativ-Tests (Env, Kind-Kill,
  Fork-Bombe) fein; `SANDBOX_DESIGN.md` §5 R-Liste aktualisiert.

## S3 — Container-Stufe (Aufwand M–L, Linux-Pflicht)

Erst wenn S2 fein. Ein PoC = ein ephemerer Container, danach verwerfen.

- **Runtime-Wahl:** Docker/`runsc` (gVisor) als Default (OCI-kompatibel,
  kein KVM nötig); Firecracker/Kata als Option für maximale Isolation
  (KVM-Host). Entscheidung pro Deployment, nicht pro Run.
- **Profil:** `--network none`, Repo/Toolchain read-only, genau ein
  `scratch/`-Quota-Volume, non-root, `cap-drop ALL`, `no-new-privileges`,
  seccomp Default-Deny, CPU/RAM/timeout-Limits.
- **Abnahme-Gate N1–N4** (`SANDBOX_DESIGN.md` §3) als CI-Gate:
  Host-Read, Egress, Fork-Bombe, Persistenz — jeder bestandene Escape
  blockiert das Release.
- **Betriebs-Checkliste** (aus Recherche): Kill < 5 s, Egress-Log
  queryable, Image-Pinning + Signatur, Cold-Start-p99 dokumentiert,
  keine Standing Credentials (kurzlebige Task-Secrets via Broker).

## S4 — Staged Confinement (Aufwand M, nach S3)

Aus Sandlock-Paper übernommen: **Fähigkeiten trennen statt vertrauen.**

- Triage-Pipeline in Stufen mit unterschiedlichem Confinement:
  Stufe mit Netz sieht nie Findings/Secrets, Stufe mit Findings hat
  nie Netz (bricht die „lethal trifecta“ bei Prompt-Injection).
- COW-/Dry-Run für Fix-Vorschläge: Effekte capturen, previewen,
  commiten oder verwerfen (`apply` erst nach Preview).
- TOCTOU-sichere `exec`-Prüfung (Pfad nach Auflösung gegen Allowlist).
- **Abnahme:** Stufen-Matrix-Test (Netz-Stufe ohne Daten, Daten-Stufe
  ohne Netz), Dry-Run-Roundtrip-Test, Doku in `SANDBOX_DESIGN.md` §6.

## Reihenfolge (bindend)

S2 → S3 (inkl. N1–N4-Gate) → S4. Kein S3 ohne S2-Abnahme, kein S4
ohne N1–N4-Gate. `verify_fix` bleibt bis S3 bei `NO_SANDBOX`-Default
mit Runner-Override (heutiger Stand, getestet).
