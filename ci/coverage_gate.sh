# Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
# oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
# Coverage-Gate, Linux-Variante (siehe coverage_gate.ps1 fuer Doku).
# Gebrauch: bash ci/coverage_gate.sh
set -euo pipefail
cd "$(dirname "$0")"

declare -A MIN=(
  [cate-core]=65 [cate-cli]=20 [cate-sarif]=14 [cate-deps]=12
  [cate-triage]=100 [cate-graph]=70 [cate-stages]=19
  [cate-mcp]=45 [cate-sandbox]=21
)

if cargo tarpaulin --version >/dev/null 2>&1; then
  echo "== Pfad A: cargo-tarpaulin"
  cargo tarpaulin --workspace --exclude-files 'src-tauri/*' \
    --out Xml --output-dir target/coverage --fail-under 70
  echo "COVERAGE-GATE (tarpaulin): BESTANDEN"
  exit 0
fi

echo "== Pfad B: Testzahl-Gate (tarpaulin offline nicht verfuegbar)"
fail=0
for crate in "${!MIN[@]}"; do
  out=$(cargo test -p "$crate" 2>&1)
  passed=$(echo "$out" | grep -oP '\d+(?= passed)' | awk '{s+=$1} END {print s+0}')
  failed=$(echo "$out" | grep -oP '\d+(?= failed)' | awk '{s+=$1} END {print s+0}')
  status="ok"
  if [ "$failed" -gt 0 ] || [ "$passed" -lt "${MIN[$crate]}" ]; then status="FAIL"; fail=1; fi
  printf "%-4s %-12s: passed=%s (min %s) failed=%s\n" "$status" "$crate" "$passed" "${MIN[$crate]}" "$failed"
done
if [ "$fail" -ne 0 ]; then echo "COVERAGE-GATE: FAILED" >&2; exit 1; fi
echo "COVERAGE-GATE (Testzahlen): BESTANDEN"
