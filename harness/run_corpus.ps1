# Paket C — Korpus-Lauf (Deny-Faelle muessen PASSED bleiben).
# Gebrauch: powershell -ExecutionPolicy Bypass -File harness/run_corpus.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
python harness.py --corpus ../corpus/manifest.json
exit $LASTEXITCODE
