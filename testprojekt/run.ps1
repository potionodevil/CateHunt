# Testprojekt-Runner (Windows): Offline-E2E ohne Netz/Modell.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
cargo test -p cate-core -p cate-triage -p cate-stages 2>&1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p cate-stages --test testprojekt_e2e 2>&1
