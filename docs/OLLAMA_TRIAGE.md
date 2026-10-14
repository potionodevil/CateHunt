# Ollama-Triage (Phase 2, Stand 2026-10-14)

## Modul

`crates/cate-triage/src/ollama.rs` (std-only, keine neue Dependency):

- `OllamaConfig { base_url, model, prompt_version, timeout_ms }` —
  Default `http://127.0.0.1:11434`, Modell `qwen2.5-coder:7b`.
- `check_base_url` — lässt nur `http://localhost|127.0.0.1|::1` zu;
  https und Remote-Hosts werden abgelehnt (Default offline-lokal).
- `FindingContext { rule_id, cwe, file, start_line, message, code_snippet }` +
  `build_prompt` — Prompt aus Finding-Kontext, **redigiert** via
  `cate-core::redact` (keine Roh-Secrets ans Modell), Snippet auf 2000 Zeichen
  gekappt, Antwortformat JSON-only vorgegeben.
- `parse_proposal` — parst Modell-JSON (tolerant gegen Prosa drumherum);
  **Cap:** `evidence_proposed` E3/E4 → E2; **Deny-List-Check vor suppress:**
  `suppress` auf Deny-CWE → `escalate` + `policy_override=true`
  (alle CWE-Schreibweisen via `normalize_cwe`); `reason` max 280 Zeichen.
- `decide_with_cache` — **Cache-Anbindung:** Fingerprint-Lookup zuerst
  (`FindingContext::fingerprint` aus rule_id/code_hash/cwe); bei Hit kein
  Modell-Parse, bei Miss Record-Bau + doppelte Policy-Absicherung
  (`apply_policy` auf Record-Ebene).
- `query_ollama` — minimaler `POST /api/generate` via `TcpStream`
  (einzige Netzoperation, nur Loopback, read-only, kein Code-Write).

## Was läuft (verifiziert)

- `cargo test -p cate-triage`: 20 Unit + 2 Integration grün (darunter 10 neue
  Ollama-Tests: Prompt-Kontext, Secret-Redaction, E2-Cap, Deny-vor-suppress,
  alle CWE-Schreibweisen, Loopback-Only, Cache-Hit ohne Modell-Call,
  Record-Bau mit Policy, reason-Cap, Fehlerfälle).
- Ollama-Daemon selbst ist **nicht** Teil der Tests (kein Netz im Test);
  `query_ollama` nur gegen laufenden `ollama serve` auf 127.0.0.1 manuell prüfbar.

## Beispiel

```rust
let ctx = FindingContext { rule_id: "semgrep:x".into(), cwe: "CWE-328".into(), .. };
let cfg = OllamaConfig::default();
let prompt = build_prompt(&ctx, &cfg.model);
let raw = query_ollama(&cfg, &prompt)?;          // nur localhost
let out = decide_with_cache(&cache, &ctx, &raw, &cfg.model)?;
cate_triage::store_verdict(&cache_path, &out.record)?; // Policy schon angewendet
```
