#!/usr/bin/env bash
# Juniper SRX audit via SSH - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() { cat <<'EOF'
Usage:
  juniper_srx_audit.sh --sw-id SW00001234 --host 10.0.0.20 --user admin [--port 22] [--ssh-key ~/.ssh/id_rsa] [--out-dir DIR]
EOF
}

SW_ID=""; HOST=""; USER=""; PORT="22"; SSH_KEY=""; OUT_DIR="$(pwd)"
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
OUTFILE="${OUT_DIR}/${SW_ID}__${HOST}__JuniperSRX__${DATE}__result.txt"
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
  echo "  Juniper SRX 취약점 점검 결과(증적 수집 중심)"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "실행 호스트: ${RUN_HOST}"
  echo "대상 장비: ${HOST}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

section "SRX-01" "버전" "중"
run_ssh "show version"

section "SRX-02" "관리 서비스(SSH/NETCONF/Telnet) 설정" "상"
run_ssh "show configuration system services | display set | match \"ssh|telnet|netconf|web-management\""
result_line "SRX-02" "수동" "불필요 서비스 비활성, 관리망 제한(ACL), SSH 강한 KEX/Cipher 정책 확인"

section "SRX-03" "로컬 사용자/권한 클래스" "상"
run_ssh "show configuration system login | display set"
result_line "SRX-03" "수동" "권한 클래스 최소화, 비밀번호 정책, 외부 인증(TACACS/RADIUS) 사용 여부 확인"

section "SRX-04" "로그/감사(수동)" "중"
run_ssh "show configuration system syslog | display set"
result_line "SRX-04" "수동" "syslog 원격 전송/보관 정책 확인"

echo "[INFO] 완료: $OUTFILE"
