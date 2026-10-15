# S3 Container-Stufe (`ci/sandbox/`)

Ein PoC = ein ephemerer Container, danach verwerfen. Linux-Pflicht im Gate;
lokal (Windows/macOS ohne Daemon) nur Dry-Run, ehrlich als solcher markiert.

## Dateien

| Datei | Zweck |
|---|---|
| `Dockerfile` | Runner-Image, per Digest gepinnt (`alpine:3.21@sha256:ce64…`, 2026-10-15 via Registry-API verifiziert), non-root `USER`, `curl` nur für N2 |
| `seccomp.json` | Default-Deny (`SCMP_ACT_ERRNO`); `mount`/`ptrace`/`unshare`/`setns`/`chroot`/`bpf`/`reboot` explizit verweigert. Review-Profil — Smoke-Beweis ist der CI-Run |
| `run.sh` | Ephemerer Run: `--network none`, `--read-only` + genau ein tmpfs-`scratch` mit `size=`-Quota, `--user 65532`, `--cap-drop ALL`, `no-new-privileges`, seccomp, `--memory/--cpus/--pids-limit`, Timeout + SIGKILL, `runsc` wenn vorhanden (sonst Warnung) |
| `n1_host_read.sh` … `n4_persist.sh` | Negativ-PoCs aus `SANDBOX_DESIGN.md` §3 als ausführbare Gate-Checks (Exit 0 = Blockade/PASS, Exit 1 = Escape/FAIL) |
| `gate.sh` | Orchestrierung: `--self-check` (Syntax/JSON), `--dry-run` (statischer Profil-Check ohne Daemon), Voll-Lauf (Linux + Daemon) |

## Gebrauch

```bash
bash ci/sandbox/gate.sh --self-check   # immer möglich
bash ci/sandbox/gate.sh --dry-run      # ohne Docker-Daemon (Profil-Review)
bash ci/sandbox/gate.sh                # Linux + Docker-Daemon: baut Image, fährt N1–N4
```

SKIP-Regel: ohne Linux oder ohne Daemon meldet `gate.sh` laut `GATE_STATUS=SKIP`
mit `::warning::`-Annotation — **nie still-fein**. Echte Prüfung nur auf dem
Linux-CI-Runner (`.github/workflows/sandbox-n1n4.yml`).

## Runtime-Wahl (runsc-Hinweis)

Default: `runsc` (gVisor, OCI-kompatibel, kein KVM nötig) — `run.sh` nutzt sie
automatisch, wenn der Daemon sie anbietet. Sonst runc mit Warnung (Gate-Test ok,
kein Prod). Firecracker/Kata nur als Deployment-Option bei KVM-Host (nicht pro Run).

## Betriebs-Checkliste (Abnahme S3)

- [ ] **Kill < 5 s:** `run.sh` misst die SIGKILL-Dauer nach Timeout; Überschreitung warnt. CI-Protokoll prüfen.
- [ ] **Egress-Log queryable:** N2 beweist Deny; für Prod zusätzlich Egress-Versuche des Hosts loggen/shipping einrichten (siehe "Noch fehlt").
- [ ] **Image-Pinning + Signatur:** Digest-Pin vorhanden; Signatur (cosign) noch offen.
- [ ] **Cold-Start-p99 dokumentiert:** Build- + Startzeiten aus CI über min. 20 Läufe messen, p99 hier eintragen (noch offen).
- [ ] **Keine Standing Credentials:** Gate braucht keine Secrets; PoC-Runs bekommen keine Env-Secrets (Env-Hygiene ist S2). Kurzlebige Task-Secrets nur via Broker (noch offen, S4).

## Was CI-seitig noch fehlt (ehrlich)

1. `runsc` auf dem Runner installieren statt nur erkennen (härtere Isolation als runc-Fallback).
2. Image-Signatur (`cosign sign` + `verify` im Gate) und Digest-Drift-Wächter (Renovate/Dependabot für `alpine:3.21`).
3. Egress-Log-Shipping (queryable, z. B. Runner-Netzlog oder Daemon-Audit).
4. Cold-Start-p99-Messung über ≥ 20 Läufe, als Zahl in diese Datei.
5. `seccomp.json` gegen Daemon smoke-getestet bestätigen (erster grüner CI-Lauf) und Version des Docker-Default-Profils als Ableitungsbasis vermerken.
