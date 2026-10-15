# Check-Layering & Relation (Stand 2026-10-15)

> Wie Bug-Bounty-Hunter arbeiten — als Pipeline internalisiert:
> Recon → Surface-Map → gezieltes Testen → **Chainen** → Validieren →
> Report. Recherche-Basis: Sn1per-Phasen-Pipeline (passiv vor aktiv,
> jede Phase füttert die nächste), chs.us-Methodik (Chain & Escalate,
> 7-Fragen-Validierung), Semgrep-Supply-Chain (Reachability: nur
> erreichbare Vulns zählen), Invicti DAST→SAST-Korrelation über
> Call-Graphen, Kontrast/Pixee (Exploitability-Filter schlägt
> reine Pattern-Menge, −90 % Noise).

## Prinzipien

1. **Billig zuerst:** jede Stufe ist teurer als die vorige und läuft
   nur auf der reduzierten Menge der Vorstufe (Prefilter → Tiefgang).
2. **Relation statt Liste:** Findings werden über Call-Graph und
   gemeinsame Sinks korreliert (ein Sink, viele Quellen = ein Problem),
   Duplikate per Fingerprint vereint.
3. **Nur Erreichbares zählt:** Dependency-Vulns ohne Pfad vom eigenen
   Code → notiert, nicht eskaliert (Reachability-Regel).
4. **Jede Eskalation braucht Beleg:** E2 Datenfluss-Beleg, E3 Sandbox-PoC,
   E4 Sandbox-Re-Test (Evidence-Gate, keine Prosa-Eskalation).

## Schichten (Soll, mit Ist-Mapping)

| Schicht | Aufgabe | Ist | Lücke |
|---|---|---|---|
| L0 Inventar | Scope (`base..HEAD`), Lockfiles | `scope.rs`, `audit --scope-out` ✅ | — |
| L1 Prefilter | billige Metriken (Nesting/Länge), SARIF-Import | `cate-core`, `cate-sarif` ✅ | Tree-sitter (Spike: annehmen, s. `TREESITTER_SPIKE.md`) |
| L2 Adapter | Scanner nur orchestriert (Version-Pinning) | Semgrep/CodeQL-Import ✅ + `pins.rs` (S-2, Offline-Probe) ✅ | — |
| L3 Reachability | Pfad eigenes Code → Sink/Dep-Vuln? | `reach.rs` ✅ (BFS Befund→Sink, Dep-Use-Pfad, unreachable = de-eskaliert, `demote_severity`) | Golden über `testprojekt/` nachziehen |
| L4 Chaining | Lows zu Pfaden kombinieren (Quelle→Sink über Module) | `chain.rs` ✅ (Angriffspfade aus `ModuleGraph`, E1+E1→E2-Kandidat, Konfidenz HIGH/MEDIUM/LOW nach Pfadlänge, Kill-Kriterien: kein Sink/Test-Pfad/Dead-Code → `killed:true` + Begründung) | — |
| L5 Validierung | PoC in Sandbox (E3), Re-Test (E4) | `verify_fix`-Gerüst ✅ | S3-Container-Erstlauf in CI |
| L6 Triage | Deny-Cap, Cache, Provenienz, Trend | ✅ (+`trend.py`, `AI_BOM.md`, S-5 `contested:true` in `pipeline.rs`/`severity.rs`) | — |

## Korrelations-Regeln (für L3/L4-Implementierung)

- **Gleicher Sink:** Findings mit identischem `(Datei, Zeile, Regelklasse)`
  am selben Sink → ein Issue, Quellen als Evidenzliste.
- **Graph-Distanz:** Findings im Abstand ≤ 2 Kanten mit passenden
  Kategorien (Source→Sink) → Chain-Kandidat, Konfidenz steigt mit
  Pfadkürze.
- **Dep-Reachability:** Advisory trifft Paket P; kein Import-Pfad vom
  eigenen Code zu P → `reachable:false`, kein E2+.
- **Widerspruch:** zwei Adapter, gegensätzliche Severity → deterministisch
  höhere gewinnen + `contested:true` (S-5), nie still mitteln.
- **Kill-Kriterien:** Chain ohne Sink, Pfad nur durch Test-Code,
  Sink in Dead Code (kein Caller im Graph) → kein Bug, nur Notiz.

## Nächste Schritte (Reihenfolge, Stand 2026-10-15)

1. ~~Tree-sitter-Entscheid~~ ✅ umgesetzt (default-an, `metrics_ts.rs`, Heuristik-Fallback).
2. ~~Reachability-Engine~~ ✅ `reach.rs` (BFS + Dep-Use-Pfad, Tests mit reachable/unreachable).
3. ~~Chaining-Engine~~ ✅ `chain.rs` (Pfadbau + Kill-Kriterien; Golden über `testprojekt/` noch nachziehen).
4. ~~S-2 Adapter-Pinning~~ ✅ `pins.rs`; L5 scharf schalten mit S3-Container-Erstlauf in CI.
