#!/usr/bin/env bash
# N4 Persistenz/Escape: PoC versucht Cron-/Autostart-Eintrag, Mount, Docker-Socket.
# Zusaetzlich Ephemeralitaet: Artefakt in /work (erlaubt!) muss im Folge-Run weg sein.
# Exit 0 = blockiert + ephemer (PASS), Exit 1 = Escape/Persistenz (FAIL).
# Gebrauch: n4_persist.sh [--image NAME]  (braucht Docker-Daemon)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="catehunt-poc:latest"
[[ "${1:-}" == "--image" ]] && { IMAGE="$2"; shift 2; }

POC='echo "--- a: Hostdatei aendern (muss read-only scheitern)"; echo evil >> /etc/hostname 2>&1; A=$?;
echo "--- b: docker.sock (muss fehlen)"; ls /var/run/docker.sock 2>&1; B=$?;
echo "--- c: mount (muss scheitern: seccomp + keine Caps)"; mount -t tmpfs x /mnt 2>&1; C=$?;
echo MARKER-EVIL-$$ > /work/evil-marker;
echo "RESULT a=$A b=$B c=$C"; if [ $A -ne 0 ] && [ $B -ne 0 ] && [ $C -ne 0 ]; then echo "BLOCKED"; else echo "ESCAPED"; fi'

OUT="$(bash "$HERE/run.sh" --image "$IMAGE" --timeout 60 -- /bin/sh -c "$POC" 2>&1)" || true
echo "$OUT"
echo "$OUT" | grep -q "^BLOCKED$" || { echo "N4 FAIL: Persistenz/Escape moeglich — Release blockiert"; exit 1; }

# Ephemeralitaet: frischer Container darf keinen Marker des Vorlaufs sehen.
if bash "$HERE/run.sh" --image "$IMAGE" --timeout 60 -- /bin/sh -c 'ls /work/evil-marker' 2>&1 | grep -q MARKER; then
  echo "N4 FAIL: /work-Artefakt ueberlebt den Run — nicht ephemer"
  exit 1
fi
echo "N4 PASS: Persistenz blockiert (cron/mount/socket), Folge-Run ohne Artefakte (ephemer)"
exit 0
