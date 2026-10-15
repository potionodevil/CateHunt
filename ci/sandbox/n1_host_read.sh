#!/usr/bin/env bash
# N1 Host-Read: PoC versucht, ausserhalb von /work zu lesen/schreiben.
# Konvention (alle N-Skripte): Exit 0 = Blockade bestaetigt (Gate-PASS),
#                              Exit 1 = Escape GELUNGEN (Gate-FAIL, blockiert Release).
# Gebrauch: n1_host_read.sh [--image NAME]  (braucht Docker-Daemon)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="catehunt-poc:latest"
[[ "${1:-}" == "--image" ]] && { IMAGE="$2"; shift 2; }

CANARY_VALUE="host-canary-$RANDOM-$RANDOM"
CANARY_HOST="$(mktemp)"; echo "$CANARY_VALUE" > "$CANARY_HOST"
REPO_TMP="$(mktemp -d)"
trap 'rm -f "$CANARY_HOST"; rm -rf "$REPO_TMP"' EXIT

# HINWEIS: Die Canary wird bewusst NICHT in den Container gemountet.
# Der PoC versucht (a) eine NICHT gemountete Host-Datei zu lesen,
# (b) ins read-only /repo zu schreiben, (c) den Docker-Socket zu sehen.
POC='echo "--- a: /canary lesen (muss fehlen)"; cat /canary 2>&1; A=$?;
echo "--- b: nach /repo schreiben (muss read-only scheitern)"; echo pwned > /repo/pwned 2>&1; B=$?;
echo "--- c: docker.sock (muss fehlen)"; ls /var/run/docker.sock 2>&1; C=$?;
echo "RESULT a=$A b=$B c=$C"; if [ $A -ne 0 ] && [ $B -ne 0 ] && [ $C -ne 0 ]; then echo "BLOCKED"; else echo "ESCAPED"; fi'

OUT="$(bash "$HERE/run.sh" --image "$IMAGE" --timeout 60 --repo-ro "$REPO_TMP" -- /bin/sh -c "$POC" 2>&1)" || true
echo "$OUT"
if echo "$OUT" | grep -q "^BLOCKED$"; then
  if [[ -f "$REPO_TMP/pwned" ]]; then echo "N1 FAIL: /repo-Artefakt auf Host sichtbar"; exit 1; fi
  if [[ "$(cat "$CANARY_HOST")" != "$CANARY_VALUE" ]]; then echo "N1 FAIL: Host-Canary veraendert"; exit 1; fi
  echo "N1 PASS: Host-Read blockiert (kein Lesen ausserhalb /work, /repo read-only)"
  exit 0
else
  echo "N1 FAIL: Escape gelungen — Release blockiert"
  exit 1
fi
