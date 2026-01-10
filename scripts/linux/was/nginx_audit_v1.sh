#!/usr/bin/env bash
# Nginx audit (Linux/Unix) - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() { cat <<'EOF'
Usage:
  nginx_audit_v1.sh --sw-id SW00001234 [--conf /etc/nginx/nginx.conf] [--out-dir DIR]
EOF
}

SW_ID=""
NGINX_CONF="/etc/nginx/nginx.conf"
OUT_DIR="$(pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --conf) NGINX_CONF="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done
[[ -z "$SW_ID" ]] && { echo "Missing --sw-id"; usage; exit 2; }

DATE="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname)"
GUIDE_VER="KR baseline (operator-tailored) - Nginx hardening"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__Nginx__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section(){ echo -e "\n============================================================================\n[$1] $2\n위험도: ${3:-}\n============================================================================\n" >>"$OUTFILE"; }
result_line(){ echo -e "★ [$1] 점검 결과: $2\n----------------------------------------------------------------------------\n${3:-}\n" >>"$OUTFILE"; }
append_cmd(){ local label="$1"; shift; { echo "▶ $label"; echo "\$ $*"; } >>"$OUTFILE"; "$@" >>"$OUTFILE" 2>&1 || true; echo "" >>"$OUTFILE"; }

{
  echo "############################################################################"
  echo "  Nginx 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

if ! command -v nginx >/dev/null 2>&1; then
  section "NG-00" "사전 점검" "상"
  result_line "NG-00" "수동" "nginx 명령어 미발견. Nginx 미설치 또는 PATH 미설정"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

section "NG-01" "버전/빌드 옵션" "중"
append_cmd "nginx -V" bash -lc "nginx -V 2>&1"
result_line "NG-01" "주의" "버전/패치 수준 및 불필요 모듈 제거 여부 확인"

section "NG-02" "server_tokens 비활성화" "중"
if [[ -r "$NGINX_CONF" ]]; then
  append_cmd "server_tokens 검색" bash -lc "grep -RInE '^\s*server_tokens\b' \"$(dirname "$NGINX_CONF")\" 2>/dev/null | head -n 50"
  if grep -RqsE '^\s*server_tokens\s+off\s*;' "$(dirname "$NGINX_CONF")" 2>/dev/null; then
    result_line "NG-02" "양호" "server_tokens off 설정 존재"
  else
    result_line "NG-02" "주의" "server_tokens off 미확인(Include 파일 포함 종합 확인 필요)"
  fi
else
  result_line "NG-02" "수동" "nginx.conf 읽기 불가: $NGINX_CONF"
fi

section "NG-03" "TLS 프로토콜/취약 Cipher" "상"
append_cmd "ssl_protocols/ssl_ciphers 검색" bash -lc "grep -RInE '^\s*(ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers)\b' \"$(dirname "$NGINX_CONF")\" 2>/dev/null | head -n 80"
result_line "NG-03" "주의" "TLS1.0/1.1 비활성 및 약한 Cipher 제거 여부를 실제 설정/스캐너로 교차검증 권고"

section "NG-04" "autoindex(디렉터리 리스팅) 비활성화" "상"
append_cmd "autoindex 검색" bash -lc "grep -RInE '^\s*autoindex\b' \"$(dirname "$NGINX_CONF")\" 2>/dev/null | head -n 80"
if grep -RqsE '^\s*autoindex\s+on\s*;' "$(dirname "$NGINX_CONF")" 2>/dev/null; then
  result_line "NG-04" "취약" "autoindex on 설정 존재"
else
  result_line "NG-04" "주의" "autoindex on 미확인(서버 블록별 설정 포함 확인)"
fi

echo "[INFO] 완료: $OUTFILE"
