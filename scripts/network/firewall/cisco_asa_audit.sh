#!/usr/bin/env bash
# Cisco ASA audit via SSH - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() { cat <<'EOF'
Usage:
  cisco_asa_audit.sh --sw-id SW00001234 --host 10.0.0.10 --user admin [--port 22] [--ssh-key ~/.ssh/id_rsa] [--out-dir DIR]

Notes:
  - Prefer SSH key-based authentication.
  - This script collects evidence (show commands). Interpretation may be manual by policy.
EOF
}

SW_ID=""
HOST=""
USER=""
PORT="22"
SSH_KEY=""
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --host) HOST="${2:-}"; shift 2 ;;
    --user) USER="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done
[[ -z "$SW_ID" || -z "$HOST" || -z "$USER" ]] && { echo "Missing required args"; usage; exit 2; }

DATE="$(date +%Y%m%d_%H%M%S)"
RUN_HOST="$(hostname)"
GUIDE_VER="Network device baseline (operator-tailored)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOST}__CiscoASA__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section(){ echo -e "\n============================================================================\n[$1] $2\n위험도: ${3:-}\n============================================================================\n" >>"$OUTFILE"; }
result_line(){ echo -e "★ [$1] 점검 결과: $2\n----------------------------------------------------------------------------\n${3:-}\n" >>"$OUTFILE"; }

SSH_OPTS=(-p "$PORT" -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
[[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")

run_ssh() {
  local cmd="$1"
  echo "▶ $cmd" >>"$OUTFILE"
  echo "\$ ssh ${USER}@${HOST} -p ${PORT} ..." >>"$OUTFILE"
  ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$cmd" >>"$OUTFILE" 2>&1 || true
  echo "" >>"$OUTFILE"
}

{
  echo "############################################################################"
  echo "  Cisco ASA 취약점 점검 결과(증적 수집 중심)"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "실행 호스트: ${RUN_HOST}"
  echo "대상 장비: ${HOST}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

section "ASA-01" "버전/하드웨어 정보" "중"
run_ssh "show version"

section "ASA-02" "원격관리(SSH/Telnet) 설정" "상"
run_ssh "show run | include ^ssh|^telnet|^http server|^http "
result_line "ASA-02" "수동" "telnet 미사용, SSHv2 사용, 관리망 제한(허용 IP) 여부를 확인"

section "ASA-03" "AAA/인증 정책" "상"
run_ssh "show run aaa"
result_line "ASA-03" "수동" "TACACS+/RADIUS 등 중앙 인증, 로컬 계정 최소화, MFA/명령권한 설정 확인"

section "ASA-04" "암호/키 설정(노출 주의)" "상"
run_ssh "show run | include enable password|username|passwd|secret"
result_line "ASA-04" "수동" "enable password/secret 정책(강도/주기), 암호화 저장 여부 확인. 출력은 민감정보 포함 가능 - 보관/마스킹 필요"

echo "[INFO] 완료: $OUTFILE"
