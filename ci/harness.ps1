# Paket C — CI-Gate (kein Remote: lokales Gate statt GitHub Actions).
# 1) Demo-Fixtures muessen PASSED sein (Deny nie close, Fix darf close).
# 2) Fail-Fixture muss FAILED sein (Negativ-Check: Gate schlaegt an).
# 3) Korpus-Lauf end-to-end muss PASSED sein.
# Gebrauch: powershell -ExecutionPolicy Bypass -File ci/harness.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location (Join-Path $root "harness")

function Invoke-Gate($label, $gateArgs, $expectExit) {
  Write-Host "== $label"
  python harness.py @gateArgs
  $code = $LASTEXITCODE
  if ($code -ne $expectExit) {
    Write-Error "GATE-FEHLER '$label': exit=$code, erwartet=$expectExit"
    exit 1
  }
}

Invoke-Gate "demo-passthrough" @("--verdicts", "tests/fixtures/verdicts_demo.jsonl", "--labels", "tests/fixtures/labels.csv") 0
Invoke-Gate "negativ-suppression" @("--verdicts", "tests/fixtures/verdicts_fail.jsonl", "--labels", "tests/fixtures/labels_fail.csv") 1
Invoke-Gate "korpus" @("--corpus", "../corpus/manifest.json") 0
Write-Host "CI-GATE: ALLE TORE BESTANDEN"
