#!/usr/bin/env bash
# Paket C — Korpus-Lauf (Deny-Faelle muessen PASSED bleiben).
# Gebrauch: ./harness/run_corpus.sh
set -euo pipefail
cd "$(dirname "$0")"
python3 harness.py --corpus ../corpus/manifest.json
