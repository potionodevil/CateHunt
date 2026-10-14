<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung -->
<!-- oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# P1 Fuzz-Notiz: deterministische Vektor-Suiten statt cargo-fuzz

Stand: 2026-10-14. `cargo-fuzz` (libfuzzer) ist in dieser Umgebung nicht
installiert (`cargo fuzz` → unbekanntes Kommando) und braucht Nightly +
Netzwerk fürs Corpus-Management. Stattdessen decken **deterministische
Vektor-Suiten** die Fuzz-Ziele aus `TESTING.md §1.2` ab — offline,
reproduzierbar, CI-tauglich (Sekunden statt 60 s/Target).

## Abdeckung

| Ziel (TESTING.md §1.2) | Suite | Vektoren |
|---|---|---|
| Path-Jail (`../`, absolut, UNC, Symlink-Ketten, overlong) | `cate-cli` Unit-Tests in `src/main.rs` (`jail_vectors_*`, `symlink_chain_stays_in_jail`) | `../`-Payloads, Absolutpfade, UNC `\\?\`, 300-Zeichen-Namen, Symlink→aussen, Symlink-Kette, toter Link |
| Redact (Secrets, Idempotenz, No-Panic) | `cate-core/tests/vectors_redact_diff.rs` | `sk-`/`ghp_`/`AKIA`/PEM/`password=`-Muster, 7-vs-8-Zeichen-Grenze, Idempotenz über alle Vektoren |
| Diff-Parser (leere/riesige/garbled Diffs, CRLF, Binärmarker) | `cate-core/tests/vectors_redact_diff.rs` | 20 wilde Hände + 5000 deterministische PRNG-Zeilen (xorshift64, Seed fix) |
| E2-Cap E3/E4→E2 über alle Adapter | `cate-triage/tests/e2cap_cache.rs` | ollama/gemini/deep_engines × {E0..E4} × {deny, non-deny} |
| Cache-Hit ohne Modell-Call, Miss-Matrix | `cate-triage/tests/e2cap_cache.rs` | Garbage-Output bei Hit, panickender Runner, geänderter Input→Miss |

Invarianten wie in §1.2: Jail-Reject ausserhalb Root, kein Secret im Output,
`redact(redact(x)) == redact(x)`, Diff-Parser nie Panic (nur typisierte
Ergebnisse), E2-Cap hart.

## Befehle

```powershell
cargo test -p cate-core --test vectors_redact_diff
cargo test -p cate-cli jail_vectors
cargo test -p cate-triage --test e2cap_cache
cargo test -p cate-core --test golden -p cate-sarif --test golden -p cate-graph --test golden
UPDATE_GOLDEN=1 cargo test -p cate-graph --test golden  # nur lokal + Review
```

## Follow-up (wenn cargo-fuzz verfügbar)

`fuzz/fuzz_targets/{path_jail,redact,diff_parser}.rs` mit den hiesigen
Vektoren als Seed-Corpus (`fuzz/artifacts/`), CI-Kurzmodus 60 s/Target.
`proptest` als Zwischenschritt braucht nur ein dev-Dependency und läuft auf
Stable — Kandidat, falls echte Zufallsabdeckung gewünscht wird.
