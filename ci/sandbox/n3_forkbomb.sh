#!/usr/bin/env bash
# N3 Fork-Bombe / RAM-Fresser: PoC versucht Host-DoS.
# Erwartet: PIDs-Limit (64) + RAM-Limit (512 MiB) + Wall-Clock-Timeout killen den
# Run (Exit 124/TIMEOUT oder 137/OOM), der Host bleibt reaktiv.
# Exit 0 = eingedaemmt (PASS), Exit 1 = Host beeintraechtigt (FAIL).
# Gebrauch: n3_forkbomb.sh [--image NAME]  (braucht Docker-Daemon)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="catehunt-poc:latest"
[[ "${1:-}" == "--image" ]] && { IMAGE="$2"; shift 2; }

POC=':(){ :|:& };:; sleep 25; echo STILL_ALIVE'

START="$(date +%s)"
set +e
bash "$HERE/run.sh" --image "$IMAGE" --timeout 30 --pids-limit 64 --mem 512m -- /bin/bash -c "$POC" >/tmp/n3_out_$$.log 2>&1
RC=$?
set -e
DUR=$(( $(date +%s) - START ))
echo "--- PoC-Output (erste 5 Zeilen):"; head -5 /tmp/n3_out_$$.log; rm -f /tmp/n3_out_$$.log
echo "RESULT rc=$RC dauer=${DUR}s"

# Reaktivitaet: Daemon antwortet, danach ein harmloser Run gelingt.
if ! docker info >/dev/null 2>&1; then echo "N3 FAIL: Daemon nach Fork-Bombe nicht erreichbar"; exit 1; fi
if ! bash "$HERE/run.sh" --image "$IMAGE" --timeout 30 -- /bin/sh -c 'echo ALIVE' 2>/dev/null | grep -q ALIVE; then
  echo "N3 FAIL: Folge-Run gelingt nicht — Host/Runner beeintraechtigt"; exit 1
fi
if [[ $RC -eq 124 || $RC -eq 137 || $RC -ne 0 ]]; then
  echo "N3 PASS: Fork-Bombe eingedaemmt (rc=$RC, ${DUR}s, Host reaktiv)"
  exit 0
else
  echo "N3 FAIL: PoC lief 25 s ungekilled durch (rc=0) — Limits unwirksam"
  exit 1
fi
