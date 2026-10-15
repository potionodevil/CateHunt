#!/usr/bin/env bash
# S3 PoC-Runner: ein PoC = ein ephemerer Container, danach verwerfen.
#
# Profil (aus docs/SANDBOX_DESIGN.md §2):
#   --network none | --read-only + genau ein tmpfs-scratch mit Quota |
#   non-root | --cap-drop ALL | no-new-privileges | seccomp Default-Deny |
#   CPU/RAM/PIDs-Limits | Wall-Clock-Timeout + SIGKILL (< 5 s) | --rm (ephemeral)
#
# Runtime: runsc (gVisor) wenn der Daemon sie anbietet, sonst runc mit WARNUNG.
#   gVisor installieren: https://gvisor.dev/docs/user_guide/install/
#   docker daemon.json: { "runtimes": { "runsc": { "path": "runsc" } } }
#
# Gebrauch:
#   run.sh [--timeout SECS] [--mem 512m] [--cpus 1.0] [--pids-limit 64]
#          [--scratch-mb 64] [--repo-ro DIR] [--image NAME] [--name NAME]
#          -- <programm> [args...]
# Exit: Exit-Code des PoC; 124 bei Wall-Clock-Timeout (Kill folgt sofort).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${SANDBOX_IMAGE:-catehunt-poc:latest}"
TIMEOUT_SECS=120
MEM="512m"
CPUS="1.0"
PIDS=64
SCRATCH_MB=64
REPO_DIR=""
CNAME="poc-run-$$-$RANDOM"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)     TIMEOUT_SECS="$2"; shift 2 ;;
    --mem)         MEM="$2"; shift 2 ;;
    --cpus)        CPUS="$2"; shift 2 ;;
    --pids-limit)  PIDS="$2"; shift 2 ;;
    --scratch-mb)  SCRATCH_MB="$2"; shift 2 ;;
    --repo-ro)     REPO_DIR="$2"; shift 2 ;;
    --image)       IMAGE="$2"; shift 2 ;;
    --name)        CNAME="$2"; shift 2 ;;
    --)            shift; break ;;
    *) echo "run.sh: unbekannte Option: $1" >&2; exit 2 ;;
  esac
done
if [[ $# -eq 0 ]]; then echo "run.sh: kein PoC-Befehl angegeben" >&2; exit 2; fi

command -v docker >/dev/null || { echo "run.sh: docker fehlt" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "run.sh: docker-Daemon nicht erreichbar" >&2; exit 3; }

# --- Runtime-Wahl: runsc bevorzugt, runc nur mit Warnung ---
RUNTIME_FLAG=()
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  RUNTIME_FLAG=(--runtime=runsc)
  echo "run.sh: runtime=runsc (gVisor)" >&2
else
  echo "run.sh: WARNUNG: keine runsc-Runtime am Daemon — Fallback runc (schwaechere Isolation, nur Gate-Test, kein Prod)" >&2
fi

REPO_FLAG=()
if [[ -n "$REPO_DIR" ]]; then
  REPO_FLAG=(-v "${REPO_DIR}:/repo:ro")
fi

# create (nicht run): damit der Cleanup-Trap auch bei Timeout greift.
# --rm bei create ist ungueltig, daher explizites `docker rm -f` im Trap.
CID="$(docker create --name "$CNAME" \
  "${RUNTIME_FLAG[@]}" \
  --network none \
  --read-only \
  --tmpfs "/work:rw,size=${SCRATCH_MB}m,mode=1777" \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt "seccomp=${HERE}/seccomp.json" \
  --memory "$MEM" --memory-swap "$MEM" \
  --cpus "$CPUS" --pids-limit "$PIDS" \
  --hostname poc --workdir /work \
  "${REPO_FLAG[@]}" \
  "$IMAGE" "$@")"

cleanup() { docker rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Wall-Clock-Timeout: `timeout` killt nur die attach-Sitzung; der Container
# bekommt danach SOFORT SIGKILL (Kill-Policy, Ziel < 5 s, gemessen).
RC=0
if timeout "${TIMEOUT_SECS}s" docker start --attach "$CID"; then
  RC=0
else
  RC=$?
  if [[ $RC -eq 124 ]]; then
    echo "run.sh: Wall-Clock-Timeout nach ${TIMEOUT_SECS}s — SIGKILL ..." >&2
    KILL_START="$(date +%s)"
    docker kill "$CID" >/dev/null 2>&1 || true
    KILL_SECS=$(( $(date +%s) - KILL_START ))
    echo "run.sh: Kill-Dauer ca. ${KILL_SECS}s (Budget < 5 s)" >&2
    if [[ $KILL_SECS -ge 5 ]]; then
      echo "run.sh: WARNUNG: Kill-Budget ueberschritten" >&2
    fi
  fi
fi
exit "$RC"
