#!/usr/bin/env bash
# S3 N1–N4-Gate: jeder bestandene Escape blockiert das Release.
#
# Modi:
#   gate.sh                 voller Gate-Lauf (braucht Linux + Docker-Daemon)
#   gate.sh --dry-run       statischer Profil-Check OHNE Daemon (fuer lokale
#                           Verifikation auf Maschinen ohne Docker)
#   gate.sh --self-check    nur Syntax (bash -n) + JSON-Validitaet
#
# SKIP-Regel (nie still-fein): Ohne Linux oder ohne erreichbaren Docker-Daemon
# wird das Gate als SKIP gewertet — mit fetter WARNUNG auf stderr, ::warning::
# Annotation (GitHub) und Exit 0. Ein SKIP ist im Workflow-Log unuebersehbar,
# aber blockiert kein Release (echte Pruefung läuft auf dem Linux-CI-Runner).
# Exit-Codes: 0 = PASS oder dokumentierter SKIP; 1 = Escape gelungen / Gate-Fehler.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Windows/git-bash: MSYS-Pfad (/c/...) in nativen Pfad (C:/...) wandeln, damit
# native Tools (python, docker) die Dateien finden. Auf Linux ein No-Op.
if command -v cygpath >/dev/null 2>&1; then HERE="$(cygpath -m "$HERE")"; fi
IMAGE="catehunt-poc:latest"
MODE="full"

for a in "$@"; do
  case "$a" in
    --dry-run) MODE="dry" ;;
    --self-check) MODE="self" ;;
  esac
done
# (Der Voll-Lauf nimmt optional `--image NAME` als einzige Option.)
if [[ "${1:-}" == "--image" ]]; then IMAGE="${2:-$IMAGE}"; fi

warn() { echo "GATE-WARNUNG: $*" >&2; }
gh_warn() { echo "::warning::S3-Gate: $*"; warn "$*"; }

self_check() {
  local fail=0
  for f in run.sh n1_host_read.sh n2_egress.sh n3_forkbomb.sh n4_persist.sh gate.sh; do
    bash -n "$HERE/$f" && echo "self-check: $f Syntax OK" || { echo "self-check: $f SYNTAXFEHLER" >&2; fail=1; }
  done
  python3 -c "import json; json.load(open('$HERE/seccomp.json')); print('self-check: seccomp.json JSON OK')" \
    || { echo "self-check: seccomp.json UNGUELTIG" >&2; fail=1; }
  grep -q . "$HERE/Dockerfile" || { echo "self-check: Dockerfile fehlt" >&2; fail=1; }
  return $fail
}

# Statischer Profil-Check: beweist ohne Daemon, dass das Profil die in
# SANDBOX_DESIGN.md §2 geforderten Flags enthaelt (kein Ersatz fuer den echten Run).
dry_run() {
  local fail=0
  chk() { grep -q -- "$2" "$HERE/$1" && echo "dry-run PASS: $3" || { echo "dry-run FAIL: $3 fehlt ($1: $2)" >&2; fail=1; }; }
  echo "=== S3-Gate DRY-RUN (statisch, ohne Docker-Daemon) ==="
  chk run.sh "--network none"            "kein Netz"
  chk run.sh "--read-only"              "read-only Root-FS"
  chk run.sh "--tmpfs"                  "genau ein scratch-tmpfs mit Quota (size=)"
  chk run.sh "size="                     "scratch-Quota (size=)"
  chk run.sh "--user 65532"             "non-root User"
  chk run.sh -- "--cap-drop ALL"        "cap-drop ALL"
  chk run.sh "no-new-privileges"        "no-new-privileges"
  chk run.sh "seccomp="                 "seccomp-Profil"
  chk run.sh "--pids-limit"             "PIDs-Limit"
  chk run.sh "--memory"                 "RAM-Limit"
  chk run.sh "--cpus"                   "CPU-Limit"
  chk run.sh "docker kill"              "Kill-Policy (SIGKILL nach Timeout)"
  chk run.sh "runsc"                    "runsc-Hinweis (gVisor bevorzugt)"
  chk Dockerfile "@sha256:"             "Image-Pinning per Digest"
  chk Dockerfile "^USER "               "non-root Default im Image"
  chk Dockerfile "apk add --no-cache"   "kein apk-Cache im Image"
  python3 -c "
import json; p=json.load(open('$HERE/seccomp.json'))
assert p['defaultAction']=='SCMP_ACT_ERRNO', 'kein Default-Deny'
names={s for g in p['syscalls'] for s in g['names']}
for bad in ['mount','ptrace','unshare','setns','chroot','bpf','reboot','kexec_load']:
    assert bad not in names, bad+' erlaubt!'
print('dry-run PASS: seccomp Default-Deny, Escape-Syscalls verweigert')" \
    || fail=1
  for n in n1_host_read n2_egress n4_persist; do
    chk "$n.sh" "BLOCKED" "$n meldet Blockade-vs-Escape"
  done
  chk "n3_forkbomb.sh" "N3 PASS" "n3 meldet Eindaemmung-vs-Escape"
  if [[ $fail -eq 0 ]]; then echo "=== DRY-RUN: alle statischen Profil-Checks PASS (echter Container-Run steht aus) ==="; else
    echo "=== DRY-RUN: FEHLER gefunden ===" >&2; fi
  return $fail
}

if [[ "$MODE" == "self" ]]; then self_check; exit $?; fi
if [[ "$MODE" == "dry" ]]; then self_check && dry_run; exit $?; fi

# ---------- voller Gate-Lauf ----------
echo "=== S3-Gate N1–N4 (Linux + Docker-Daemon erforderlich) ==="
if [[ "$(uname -s)" != "Linux" ]]; then
  gh_warn "SKIP: kein Linux-Runner ($(uname -s)) — Container-Gate nicht aussagekraeftig. Echter Gate-Lauf nur auf Linux-CI."
  echo "GATE_STATUS=SKIP (kein Linux)" ; exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  gh_warn "SKIP: Docker-Daemon nicht erreichbar — N1–N4 konnten NICHT ausgefuehrt werden. Das ist KEIN PASS."
  echo "GATE_STATUS=SKIP (kein Docker-Daemon)"; exit 0
fi

echo "--- Image-Build (gepinnt, kein Pull-latest) ---"
docker build --pull --tag "$IMAGE" "$HERE" || { echo "GATE FAIL: Image-Build scheitert" >&2; exit 1; }

PASS=0; FAIL=0
run_n() {
  local name="$1"
  echo "##### $name #####"
  if "bash" "$HERE/$name.sh" --image "$IMAGE"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "##### $name: ESCAPE — Release blockiert #####" >&2; fi
}
run_n n1_host_read
run_n n2_egress
run_n n3_forkbomb
run_n n4_persist

echo "=== GATE-ERGEBNIS: $PASS PASS, $FAIL FAIL ==="
if [[ $FAIL -gt 0 ]]; then echo "GATE FAIL: $FAIL Escape(s) gelungen — Release BLOCKIERT" >&2; exit 1; fi
echo "GATE PASS: alle N1–N4-Angriffe blockiert"
echo "GATE_STATUS=PASS"
