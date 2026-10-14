# MCP-Tools: `verify_fix` + `check_dependencies` (Spec, Paket D)

> Status: reine Spezifikation, keine Implementierung (Phase 5).
> Referenz-Signaturen: `docs/PLAN.md` §3.
> Konventionen: JSON-RPC-ähnliche Calls, `snake_case`-Parameter,
> Fehler als `{ "code": "...", "message": "..." }`.

## Gemeinsame Regeln

- Alle Pfade sind relativ zum Scan-Root (Path-Jail, s. Paket B);
  absolute Pfade und `..`-Escapes → `INVALID_PATH`.
- Kein Netz im Default (local-only); `check_dependencies` nutzt
  ausschließlich eine lokale Advisory-DB.
- Secrets in Ein-/Ausgaben werden nach `cate-core::redact` redigiert.
- Evidence-Regeln: Triage/Sandbox dürfen höchstens E2 vorschlagen;
  E3 nur per Sandbox-PoC, E4 nur per `verify_fix` (s. unten).

## Fehlercodes (beide Tools)

| Code | Bedeutung |
|---|---|
| `INVALID_PARAMS` | Pflichtparameter fehlt / Typ falsch |
| `INVALID_PATH` | Pfad außerhalb Scan-Root oder nicht existent |
| `NOT_FOUND` | Finding-ID / Lockfile-Eintrag unbekannt |
| `NO_SANDBOX` | `verify_fix` ohne verfügbare Sandbox (Phase 4+) |
| `TIMEOUT` | Re-Test überschreitet Zeitlimit |
| `INTERNAL` | unerwarteter Fehler, kein Finding-Upgrade |

---

## 1. `verify_fix`

Hebt ein Finding **E3 → E4** — ausschließlich nach bestandenem Re-Test
in der Sandbox. Jeder andere Übergang wird abgelehnt.

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VerifyFixInput",
  "type": "object",
  "required": ["finding_id", "fix_commit"],
  "properties": {
    "finding_id": { "type": "string", "minLength": 1 },
    "fix_commit": { "type": "string", "minLength": 1 },
    "test_command": { "type": "string" },
    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600, "default": 120 }
  },
  "additionalProperties": false
}
```

Beispiel-Call:

```json
{ "tool": "verify_fix", "params": { "finding_id": "semgrep:cwe-798:src/auth.py:41", "fix_commit": "abc1234", "timeout_secs": 120 } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VerifyFixOutput",
  "type": "object",
  "required": ["finding_id", "verified", "evidence_after", "details"],
  "properties": {
    "finding_id": { "type": "string" },
    "verified": { "type": "boolean" },
    "evidence_after": { "type": "string", "enum": ["E3", "E4"] },
    "details": {
      "type": "object",
      "required": ["retest_passed", "sandbox_run_id"],
      "properties": {
        "retest_passed": { "type": "boolean" },
        "sandbox_run_id": { "type": "string" },
        "log_excerpt": { "type": "string", "maxLength": 2000 }
      }
    }
  },
  "additionalProperties": false
}
```

Beispiel-Antwort (erfolgreich):

```json
{ "finding_id": "semgrep:cwe-798:src/auth.py:41", "verified": true, "evidence_after": "E4", "details": { "retest_passed": true, "sandbox_run_id": "sbx-2026-001", "log_excerpt": "PoC exit 0: secret no longer hardcoded" } }
```

### Evidence-Regeln

1. Nur Findings mit aktuellem Level **E3** sind zulässig; E0/E1/E2 → Fehler `INVALID_PARAMS` (kein Überspringen der Stufen).
2. `verified=true` genau dann, wenn der ursprüngliche PoC/Re-Test in der Sandbox **besteht** (Fix belegt); sonst bleibt E3.
3. `E4` ist terminal für die Review-Workbench (grün/geschlossen); Re-Öffnen nur per neuem Finding.
4. Ohne Sandbox (Phase < 4) antwortet das Tool `NO_SANDBOX`; es führt **niemals** Tests auf dem Host aus.

---

## 2. `check_dependencies`

Prüft Lockfile-Einträge gegen eine **lokale (offline)** Advisory-DB.
Kein Registry-Netzverkehr.

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CheckDependenciesInput",
  "type": "object",
  "required": ["lockfile"],
  "properties": {
    "lockfile": { "type": "string", "enum": ["Cargo.lock", "package-lock.json"] },
    "project_path": { "type": "string", "default": "." }
  },
  "additionalProperties": false
}
```

Beispiel-Call:

```json
{ "tool": "check_dependencies", "params": { "lockfile": "Cargo.lock", "project_path": "." } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CheckDependenciesOutput",
  "type": "object",
  "required": ["lockfile", "packages_checked", "advisories"],
  "properties": {
    "lockfile": { "type": "string" },
    "packages_checked": { "type": "integer", "minimum": 0 },
    "advisories": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["package", "version", "advisory_id", "severity", "summary"],
        "properties": {
          "package": { "type": "string" },
          "version": { "type": "string" },
          "advisory_id": { "type": "string" },
          "aliases": { "type": "array", "items": { "type": "string" } },
          "severity": { "type": "string", "enum": ["low", "moderate", "high", "critical"] },
          "summary": { "type": "string" },
          "patched_in": { "type": "array", "items": { "type": "string" } }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}
```

Beispiel-Antwort:

```json
{ "lockfile": "Cargo.lock", "packages_checked": 87, "advisories": [{ "package": "serde", "version": "1.0.100", "advisory_id": "RUSTSEC-20XX-0001", "aliases": ["CVE-20XX-0001"], "severity": "high", "summary": "Beispiel-Eintrag", "patched_in": ["1.0.101"] }] }
```

### Advisory-Format / Regeln

1. Quelle ist eine **offline-DB** (z. B. `advisories/*.json`, Stand-Datum im Report); Alter der DB wird im Report vermerkt (`db_age_days`).
2. Unbekannte Pakete (nicht in DB) ergeben **kein** Advisory (kein False Alarm); sie werden nur in `packages_checked` gezählt.
3. Typosquat-Hinweise aus `cate-deps` bleiben separat (Heuristik, kein Advisory).
4. Findings aus Advisories starten als **E1** (Tool-Behauptung, Provenienz `"deps"`); Upgrade nur über Triage-Regeln.
