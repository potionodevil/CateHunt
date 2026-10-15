#!/usr/bin/env bash
# N2 Netz-Egress: PoC versucht DNS-Lookup + TCP-Connect + HTTPS.
# Profil: --network none (DNS/Loopback ebenfalls blockiert, Default-Deny, keine Allowlist).
# Exit 0 = Blockade bestaetigt (PASS), Exit 1 = Escape (FAIL, blockiert Release).
# Gebrauch: n2_egress.sh [--image NAME]  (braucht Docker-Daemon)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="catehunt-poc:latest"
[[ "${1:-}" == "--image" ]] && { IMAGE="$2"; shift 2; }

# HINWEIS: /bin/sh ist busybox-ash (kein /dev/tcp, kein getent) — daher
# nslookup + curl. Ohne Netz scheitern alle drei (DNS-Aufloesung, TCP, TLS).
POC='echo "--- a: DNS (muss scheitern)"; nslookup example.com 2>&1; A=$?;
echo "--- b: TCP-Connect auf oeff. IP (muss scheitern)"; curl -m 8 -sS -o /dev/null http://93.184.215.14/ 2>&1; B=$?;
echo "--- c: HTTPS via curl (muss scheitern)"; curl -m 8 -sS -o /dev/null https://example.com 2>&1; C=$?;
echo "RESULT a=$A b=$B c=$C"; if [ $A -ne 0 ] && [ $B -ne 0 ] && [ $C -ne 0 ]; then echo "BLOCKED"; else echo "ESCAPED"; fi'

OUT="$(bash "$HERE/run.sh" --image "$IMAGE" --timeout 60 -- /bin/sh -c "$POC" 2>&1)" || true
echo "$OUT"
if echo "$OUT" | grep -q "^BLOCKED$"; then
  echo "N2 PASS: Egress blockiert (DNS + TCP + HTTPS scheitern, --network none)"
  exit 0
else
  echo "N2 FAIL: Egress moeglich — Release blockiert"
  exit 1
fi
