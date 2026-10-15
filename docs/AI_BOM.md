# AI-BOM / Provenienz (M-4)

Stand: 2026-10-15. Review M-4: kein Finding/Verdict ohne Modell-/
Tool-Version, Commit-SHA, Timestamp.

## 1. Zweck

Jedes KI-erzeugte Finding (`cate_core::ScoredFinding`) und jeder
Triage-Verdict (`cate_triage::Verdict`) traegt einen
`ProvenanceRecord`: WER (Tool + Version + Modell) hat WANN
(UTC-Timestamp) aus WELCHEM Stand (Commit-SHA) entschieden.
Das ist der minimale AI-BOM-Eintrag pro Einzelbefund.

## 2. Record-Schema

| Feld | Quelle | Fallback |
|---|---|---|
| `tool_name` | Konstante `cate_core::PROVENANCE_TOOL_NAME` (`"cate"`) | — (fix) |
| `tool_version` | `cate_core::tool_version()` = `env!("CARGO_PKG_VERSION")` (Compile-Zeit) | — (fix, bricht Build ohne Cargo nie) |
| `model` | `cate_core::ProvenanceRecord::current_with_model(..)` bzw. `CATE_MODEL`-Env | `"unknown"` |
| `commit_sha` | `cate_core::commit_sha()` = `CATE_COMMIT_SHA` aus `crates/cate-core/build.rs` (`git rev-parse HEAD`) | `"unknown"` (ohne Git kein Buildbruch) |
| `timestamp` | `cate_core::utc_now_rfc3339()` (SystemTime, keine Extra-Deps) | Epoch-0-Format bei kaputter Uhr |

Typ: `cate_core::ProvenanceRecord` (serde, alle Felder `String`).
`Finding`/`Verdict` fuehren es als
`#[serde(default, skip_serializing_if = "Option::is_none")]`
`provenance: Option<ProvenanceRecord>` — alte JSON/Cache-Zeilen ohne
Feld parsen zu `None`, `None` wird nicht serialisiert (Goldens/Cache
bleiben byte-stabil).

## 3. Beispiel-Record

```json
{
  "tool_name": "cate",
  "tool_version": "0.1.0",
  "model": "ollama/qwen2.5-coder:7b",
  "commit_sha": "9fe6f5a4d52bafc4c301430faf1ea0b89512fcc4",
  "timestamp": "2026-10-15T12:00:00Z"
}
```

Erzeugt per Helper (fuer CLI-Output/MCP-Dispatch, keine Logikaenderung):

```rust
// Aktueller Record als JSON (Modell aus CATE_MODEL-Env, sonst "unknown"):
let p: serde_json::Value = cate_core::provenance_record();
// Mit explizitem Modellnamen:
let p: serde_json::Value = cate_core::provenance_record_for("ollama/qwen2.5-coder:7b");

// An Typen anhaengen (Builder oder mutabel):
let v = verdict.with_provenance(cate_core::ProvenanceRecord::current_with_model(model));
finding.attach_provenance(cate_core::ProvenanceRecord::current());
```

## 4. Regel

**Kein Finding ohne Provenienz ab Phase T (Triage):** jeder
Triage-Verdict und jedes in den Health-Score einfliessende
`ScoredFinding`, das ab jetzt neu erzeugt wird, MUSS `provenance`
tragen (`Some`). Legacy-Bestaende (Cache-Zeilen, Goldens ohne Feld)
bleiben lesbar, werden aber beim naechsten Store-Vorgang mit
Provenienz zurueckgeschrieben. Ein CI-Gate (`provenance is not none`
fuer alle neuen Records) ist naechster Schritt, sobald CLI/MCP
verdrahtet sind (s. §5).

## 5. Verdrahtung (offen, Parent/Owner-Agenten)

1. **CLI Finding-Mapping** (`crates/cate-cli/src/main.rs`, zwei
   `ScoredFinding`-Literale: Scan-Pfad + `audit`-Pfad): `provenance`
   mit `ProvenanceRecord::current_with_model(..)` belegen statt `None`
   (Markierung `M-4 Provenienz` im Code).
2. **CLI Verdict-Erzeugung** (`crates/cate-cli/src/main.rs`,
   `CacheRecord`/`Verdict`-Literal im Triage-Miss-Pfad): `.with_provenance(...)`
   mit dem angefragten Modellnamen; `created_at` analog auf
   `utc_now_rfc3339()` umstellen (derzeit fix verdrahtet).
3. **MCP-Dispatch + Triage-Backends**: `crates/cate-mcp/src/lib.rs`
   (`handle_request`, sobald Triage-Verdicts ausgegeben werden) per
   `provenance_record()` ins Response-JSON; `crates/cate-triage/src/`
   Backends (`ollama.rs`, `gemini.rs`, `deep_engines.rs`,
   `pipeline.rs`) setzen das jeweils bekannte Modell (`M-4`-Marker).
   Ausser Scope hier: `cate-sarif::SarifFinding` (eigener Crate)
   braucht analog ein optionales `provenance`-Feld.
