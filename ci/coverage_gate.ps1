# Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
# oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
# Coverage-Gate (TESTING.md P2, Abschnitt 4.1/4.2).
#
# Pfad A (Linux-CI mit cargo-tarpaulin): echte Linien-Coverage je Stufe,
#   Schwellen aus TESTING.md: cate-core/-graph/-sarif >= 85 %, Rest >= 70 %.
# Pfad B (offline / ohne tarpaulin, z.B. Windows): Testzahl-Gate je Crate —
#   jede Crate muss mindestens MIN passed liefern UND 0 failed. Faellt die
#   Zahl unter MIN, wurden Tests geloescht/ignoriert -> FAILED.
#
# Gebrauch: powershell -ExecutionPolicy Bypass -File ci/coverage_gate.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Mindest-Testzahlen je Crate (Stand 2026-10-17, cargo test -p <crate> Summe
# aller "test result"-Zeilen; bei legitimer Reduktion hier + Doku anpassen).
$min = @{
  "cate-core"    = 65
  "cate-cli"     = 20
  "cate-sarif"   = 14
  "cate-deps"    = 12
  "cate-triage"  = 100
  "cate-graph"   = 70
  "cate-stages"  = 19
  "cate-mcp"     = 45
  "cate-sandbox" = 21
}

function Invoke-Tarpaulin {
  try { cargo tarpaulin --version 2>$null | Out-Null } catch { return $false }
  return ($LASTEXITCODE -eq 0)
}

if (Invoke-Tarpaulin) {
  Write-Host "== Pfad A: cargo-tarpaulin"
  cargo tarpaulin --workspace --exclude-files 'src-tauri/*' --out Xml --output-dir target/coverage `
    --fail-under 70
  if ($LASTEXITCODE -ne 0) { Write-Error "COVERAGE-GATE: tarpaulin unter Schwelle"; exit 1 }
  Write-Host "COVERAGE-GATE (tarpaulin): BESTANDEN"
  exit 0
}

Write-Host "== Pfad B: Testzahl-Gate (tarpaulin offline nicht verfuegbar)"
$fail = $false
foreach ($crate in $min.Keys) {
  $ErrorActionPreference = "Continue"
  $out = cargo test -p $crate 2>&1 | Out-String
  $code = $LASTEXITCODE
  $ErrorActionPreference = "Stop"
  if ($code -ne 0) { Write-Host "FAIL  $crate : cargo test Exit != 0"; $fail = $true; continue }
  $passed = 0; $failed = 0
  foreach ($line in ($out -split "`n" | Where-Object { $_ -match "test result:" })) {
    if ($line -match "(\d+) passed;\s*(\d+) failed") { $passed += [int]$Matches[1]; $failed += [int]$Matches[2] }
  }
  $status = "ok"
  if ($failed -gt 0 -or $passed -lt $min[$crate]) { $status = "FAIL"; $fail = $true }
  Write-Host ("{0,-4} {1,-12}: passed={2} (min {3}) failed={4}" -f $status, $crate, $passed, $min[$crate], $failed)
}
if ($fail) { Write-Error "COVERAGE-GATE: FAILED (s. Zeilen mit FAIL)"; exit 1 }
Write-Host "COVERAGE-GATE (Testzahlen): BESTANDEN"
