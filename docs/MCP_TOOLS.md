# MCP-Tools: `verify_fix` + `check_dependencies` + `audit_diff` / `get_graph` / `explain_nesting` / `apply_proposal` (Spec, Paket D + Masterplan-Angleich)

> Status: reine Spezifikation, keine Implementierung (Phase 5).
> Referenz-Signaturen: `docs/PLAN.md` §3.
> Masterplan-MCP-Contracts: `catehunt_audit_diff` (Pfade + Changed-Files → JSON-Issues),
> `catehunt_get_graph` (Modulbaum + Health), `catehunt_explain_nesting` (Tiefen-Inspektion + Patch).
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

---

## Abweichungen Masterplan ↔ PLAN.md §3 ↔ Bestand (markiert)

| # | Punkt | Stand |
|---|---|---|
| A1 | Masterplan fordert `catehunt_audit_diff` / `catehunt_get_graph` / `catehunt_explain_nesting`; `docs/PLAN.md` §3 fixiert dagegen `audit_diff(base, head)` / `get_graph(file)` / `explain_finding(id)` | **Abweichung:** diese Spec übernimmt die Masterplan-Namen als kanonisch (`audit_diff`, `get_graph`, `explain_nesting`); `explain_finding(id)` aus PLAN.md §3 bleibt als Alias/offen vermerkt (§5), keine Streichung. |
| A2 | `verify_fix` / `check_dependencies` existieren nur hier (`docs/MCP_TOOLS.md`), nicht im Masterplan-Contract-Trio | **Abweichung:** bestehende Spec (§1–§2) bleibt unverändert gültig; Masterplan-Trio (§3–§5) kommt hinzu, kein Ersatz. |
| A3 | `get_graph`-Backend `cate-graph` ist nur RED-Stub (keine Graph-API), `audit_diff`-Backend `scope.rs` nur Stufe 0 (diff-Parse + Lockfile-Inventar, keine Issues) | **Nur Spec-Mapping, keine Implementierung** (s. Mapping-Tabellen in §3/§4). |

Tool-Namensregel: MCP-Name ohne Präfix (`audit_diff`), Rust-Funktion mit Masterplan-Präfix (`catehunt_audit_diff`) — analog `get_graph` / `explain_nesting`.

---

## 3. `audit_diff` (`catehunt_audit_diff`)

Scope aus `git diff` + Lockfile-Inventar → changed-files + JSON-Issues (Stufe-0-Anteil deterministisch, Issues als E0/E1-Kandidaten ohne Sandbox).

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AuditDiffInput",
  "type": "object",
  "required": ["base"],
  "properties": {
    "base": { "type": "string", "minLength": 1 },
    "head": { "type": "string", "default": "HEAD" },
    "paths": { "type": "array", "items": { "type": "string" } },
    "include_lockfiles": { "type": "boolean", "default": true }
  },
  "additionalProperties": false
}
```

Beispiel-Call:

```json
{ "tool": "audit_diff", "params": { "base": "main", "head": "HEAD", "paths": ["crates/"], "include_lockfiles": true } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AuditDiffOutput",
  "type": "object",
  "required": ["base", "head", "changed_files", "inventory", "issues"],
  "properties": {
    "base": { "type": "string" },
    "head": { "type": "string" },
    "changed_files": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["status", "path"],
        "properties": {
          "status": { "type": "string", "enum": ["A", "M", "D", "R", "C", "T", "U", "X", "B"] },
          "path": { "type": "string", "minLength": 1 }
        },
        "additionalProperties": false
      }
    },
    "inventory": {
      "type": "object",
      "required": ["lockfiles", "has_cargo_lock", "has_package_lock"],
      "properties": {
        "lockfiles": { "type": "array", "items": { "type": "string" } },
        "has_cargo_lock": { "type": "boolean" },
        "has_package_lock": { "type": "boolean" }
      },
      "additionalProperties": false
    },
    "issues": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "rule_id", "file", "severity", "message"],
        "properties": {
          "id": { "type": "string" },
          "rule_id": { "type": "string" },
          "file": { "type": "string" },
          "line": { "type": "integer", "minimum": 1 },
          "severity": { "type": "string", "enum": ["E0", "E1"] },
          "message": { "type": "string" }
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
{ "base": "main", "head": "HEAD", "changed_files": [{ "status": "M", "path": "crates/cate-core/src/lib.rs" }, { "status": "A", "path": "crates/cate-graph/Cargo.toml" }], "inventory": { "lockfiles": ["Cargo.lock"], "has_cargo_lock": true, "has_package_lock": false }, "issues": [{ "id": "metrics:nesting:crates/cate-core/src/lib.rs:74", "rule_id": "nesting-depth", "file": "crates/cate-core/src/lib.rs", "line": 74, "severity": "E0", "message": "nesting_depth 5 ueber Richtwert 4" }] }
```

### Spec-Mapping gegen `scope.rs` (nur Mapping, keine Implementierung)

| Spec-Feld | Quelle in `crates/cate-core/src/scope.rs` |
|---|---|
| `changed_files[].status` / `.path` | `ChangedFile { status: char, path: String }`, Parser `parse_git_diff_name_status()` (A/M/D/R/C/T/U/X/B, Rename → neuer Pfad) |
| `changed_files` gesamt | `changed_files_since(dir, base)` = `git -C <dir> diff --name-status <base>` |
| `inventory` | `inventory(dir)` → `Inventory { lockfiles, has_cargo_lock, has_package_lock }` (Existenz-Check `Cargo.lock` / `package-lock.json`) |
| `params.paths` | kein Äquivalent in `scope.rs` → Filter nach Parse, Spec-only |
| `params.head`, `issues[]` | kein Äquivalent in `scope.rs` (nur `base`; keine Issue-Ableitung) → Spec-only, Issues starten als E0/E1 |

Fehler: `INVALID_PARAMS` (base leer), `NOT_FOUND` (unbekannte Rev / kein Repo — `changed_files_since`-Err-String), `INVALID_PATH` (Pfad außerhalb Scan-Root).

---

## 4. `get_graph` (`catehunt_get_graph`)

Modulbaum + Health zu Datei/Verzeichnis als JSON (read-only, local-only).

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "GetGraphInput",
  "type": "object",
  "required": ["path"],
  "properties": {
    "path": { "type": "string", "minLength": 1 },
    "max_depth": { "type": "integer", "minimum": 1, "maximum": 32, "default": 8 }
  },
  "additionalProperties": false
}
```

Beispiel-Call:

```json
{ "tool": "get_graph", "params": { "path": "crates/cate-core/src", "max_depth": 8 } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "GetGraphOutput",
  "type": "object",
  "required": ["root", "nodes", "edges", "health"],
  "properties": {
    "root": { "type": "string" },
    "nodes": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["path", "kind"],
        "properties": {
          "path": { "type": "string" },
          "kind": { "type": "string", "enum": ["file", "module", "function"] },
          "metrics": {
            "type": "object",
            "properties": {
              "function_length": { "type": "integer", "minimum": 0 },
              "nesting_depth": { "type": "integer", "minimum": 0 }
            },
            "additionalProperties": false
          }
        },
        "additionalProperties": false
      }
    },
    "edges": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["from", "to"],
        "properties": {
          "from": { "type": "string" },
          "to": { "type": "string" },
          "kind": { "type": "string", "enum": ["contains", "calls"] }
        },
        "additionalProperties": false
      }
    },
    "health": {
      "type": "object",
      "required": ["total_e2_plus", "score_0_100"],
      "properties": {
        "total_e2_plus": { "type": "integer", "minimum": 0 },
        "score_0_100": { "type": "integer", "minimum": 0, "maximum": 100 }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
```

Beispiel-Antwort:

```json
{ "root": "crates/cate-core/src", "nodes": [{ "path": "crates/cate-core/src/lib.rs", "kind": "file" }, { "path": "crates/cate-core/src/lib.rs::nesting_depth", "kind": "function", "metrics": { "function_length": 12, "nesting_depth": 3 } }], "edges": [{ "from": "crates/cate-core/src/lib.rs", "to": "crates/cate-core/src/lib.rs::nesting_depth", "kind": "contains" }], "health": { "total_e2_plus": 0, "score_0_100": 95 } }
```

### Spec-Mapping gegen `cate-graph` (nur Mapping, keine Implementierung)

| Spec-Feld | Quelle |
|---|---|
| Gesamt-Tool | Crate `crates/cate-graph/` ist RED-Stub (nur `red_tests::red_health_color_thresholds`, kein Graph-Typ, keine API) → **keine Implementierung aus Spec ableitbar** |
| `nodes[].metrics` (function_length, nesting_depth) | künftig via `cate-core`: `scan_functions()` → `FunctionMetric`, `analyze_file()` → `FileMetrics { max_nesting_depth, ... }`, `nesting_depth()` |
| `health` | künftig via `cate-core::health_score()` / `health_score_stub()` (`HealthScore { total_e2_plus, score_0_100, ... }`, nur E2+ zählt) |
| `edges[].kind=calls` | kein Call-Graph-Extraktor im Bestand → Spec-only (Phase 5+) |

Fehler: `INVALID_PATH` (Pfad außerhalb Scan-Root / nicht existent), `INVALID_PARAMS` (Pfad leer).

---

## 5. `explain_nesting` (`catehunt_explain_nesting`)

Tiefen-Inspektion einer Funktion/Datei + Patch-Vorschlag (read-only, kein Code-Write durch das Tool; Verschachtelungstiefe + Guard-/Extract-Empfehlung).

> Abweichung: `docs/PLAN.md` §3 fixiert `explain_finding(id) -> String` (natürliche Erklärung + Evidence-Begründung). Diese Spec implementiert den Masterplan-Contract `explain_nesting` (Tiefen-Fokus + Patch-Vorschlag). `explain_finding` bleibt als Alias/offen bestehen und wird hier nicht gestrichen.

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ExplainNestingInput",
  "type": "object",
  "required": ["file"],
  "properties": {
    "file": { "type": "string", "minLength": 1 },
    "line": { "type": "integer", "minimum": 1 },
    "max_allowed": { "type": "integer", "minimum": 1, "maximum": 16, "default": 4 }
  },
  "additionalProperties": false
}
```

Beispiel-Call:

```json
{ "tool": "explain_nesting", "params": { "file": "crates/cate-core/src/lib.rs", "line": 74, "max_allowed": 4 } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ExplainNestingOutput",
  "type": "object",
  "required": ["file", "function", "nesting_depth", "max_allowed", "exceeds", "chain", "patch_suggestion", "rationale"],
  "properties": {
    "file": { "type": "string" },
    "function": { "type": "string" },
    "nesting_depth": { "type": "integer", "minimum": 0 },
    "max_allowed": { "type": "integer", "minimum": 1 },
    "exceeds": { "type": "boolean" },
    "chain": { "type": "array", "items": { "type": "string" } },
    "patch_suggestion": { "type": "string", "minLength": 1 },
    "rationale": { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```

Beispiel-Antwort:

```json
{ "file": "crates/cate-core/src/lib.rs", "function": "nesting_depth", "nesting_depth": 5, "max_allowed": 4, "exceeds": true, "chain": ["fn nesting_depth", "for line", "if open", "if close", "if depth > max"], "patch_suggestion": "Guard-Clauses einfuehren und innere Bedingung in Hilfsfunktion extrahieren", "rationale": "Tiefe 5 > Richtwert 4: Lesbarkeit/Review-Aufwand steigt, Extract reduziert Tiefe um 1-2" }
```

### Spec-Mapping (nur Mapping, keine Implementierung)

| Spec-Feld | Quelle in `crates/cate-core/src/lib.rs` |
|---|---|
| `nesting_depth` | `nesting_depth(source)` (`{`/`}`-Heuristik; Tree-sitter offen) |
| `function` / `chain` | `scan_functions()` → `FunctionMetric { nesting_depth, ... }`, `analyze_file()` → `FileMetrics { max_nesting_depth }` |
| `max_allowed` default 4 | Health-Regel `max_nesting_depth > 4 → penalty` (`health_score`) |
| `patch_suggestion` | kein Generator im Bestand → Spec-only (Textvorschlag, kein Write) |

Fehler: `INVALID_PATH` (Datei außerhalb Scan-Root / nicht existent), `INVALID_PARAMS` (file leer).

---

## 6. `apply_proposal` (`catehunt_apply_proposal`)

Wendet einen zuvor erstellten Patch-Vorschlag (z. B. aus `explain_nesting`) an. Genehmigungspflicht: ohne `approved_by`, oder bei `auto_apply=false` ohne vorherige Genehmigung → Fehler `APPROVAL_REQUIRED`. Jede Anwendung wird audit-geloggt (append-only, inkl. proposal_id, approved_by, Zeitstempel, Ergebnis).

### Input-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ApplyProposalInput",
  "type": "object",
  "required": ["proposal_id"],
  "properties": {
    "proposal_id": { "type": "string", "minLength": 1 },
    "approved_by": { "type": "string", "minLength": 1 },
    "auto_apply": { "type": "boolean", "default": false }
  },
  "additionalProperties": false
}
```

Beispiel-Call (genehmigt):

```json
{ "tool": "apply_proposal", "params": { "proposal_id": "nest-2026-001", "approved_by": "r.siepmann", "auto_apply": false } }
```

Beispiel-Call (ohne Genehmigung → `APPROVAL_REQUIRED`):

```json
{ "tool": "apply_proposal", "params": { "proposal_id": "nest-2026-001" } }
```

### Output-Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ApplyProposalOutput",
  "type": "object",
  "required": ["proposal_id", "applied", "audit_log_id"],
  "properties": {
    "proposal_id": { "type": "string" },
    "applied": { "type": "boolean" },
    "audit_log_id": { "type": "string", "minLength": 1 },
    "files_changed": { "type": "array", "items": { "type": "string" } },
    "message": { "type": "string" }
  },
  "additionalProperties": false
}
```

Beispiel-Antwort (erfolgreich):

```json
{ "proposal_id": "nest-2026-001", "applied": true, "audit_log_id": "audit-2026-00042", "files_changed": ["crates/cate-core/src/lib.rs"], "message": "Proposal angewendet und audit-geloggt" }
```

Beispiel-Fehler (fehlende Genehmigung):

```json
{ "code": "APPROVAL_REQUIRED", "message": "apply_proposal erfordert approved_by oder vorherige Genehmigung (auto_apply=false)" }
```

### Regeln

1. `approved_by` fehlt UND keine vorherige Genehmigung zu `proposal_id` hinterlegt → Fehler `APPROVAL_REQUIRED` (kein Write).
2. `auto_apply=true` ohne `approved_by` → ebenfalls `APPROVAL_REQUIRED` (auto-apply ersetzt keine Genehmigung).
3. Jede Anwendung (erfolgreich oder abgelehnt) erzeugt einen Audit-Log-Eintrag (append-only): `{ audit_log_id, proposal_id, approved_by|null, applied, at }`; `audit_log_id` wird in der Antwort zurückgegeben.
4. Unbekannte `proposal_id` → Fehler `NOT_FOUND`; Pfadverstöße im Proposal → `INVALID_PATH`; sonst `INTERNAL` (kein stiller Teil-Apply).
5. Fehlercode-Tabelle (§ Gemeinsame Regeln) gilt plus `APPROVAL_REQUIRED` nur für dieses Tool.
