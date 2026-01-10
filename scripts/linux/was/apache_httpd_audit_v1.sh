#!/usr/bin/env bash
# Apache HTTP Server audit (Linux/Unix) - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  apache_httpd_audit_v1.sh --sw-id SW00001234 [--out-dir DIR]
EOF
}

SW_ID=""
OUT_DIR="$(pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done
[[ -z "$SW_ID" ]] && { echo "Missing --sw-id"; usage; exit 2; }

DATE="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname)"
GUIDE_VER="KR baseline (operator-tailored) - Apache hardening"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__Apache__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section(){ echo -e "\n============================================================================\n[$1] $2\n위험도: ${3:-}\n============================================================================\n" >>"$OUTFILE"; }
result_line(){ echo -e "★ [$1] 점검 결과: $2\n----------------------------------------------------------------------------\n${3:-}\n" >>"$OUTFILE"; }
append_cmd(){ local label="$1"; shift; { echo "▶ $label"; echo "\$ $*"; } >>"$OUTFILE"; "$@" >>"$OUTFILE" 2>&1 || true; echo "" >>"$OUTFILE"; }

{
  echo "############################################################################"
  echo "  Apache HTTP Server 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

APACHECTL=""
if command -v apachectl >/dev/null 2>&1; then APACHECTL="apachectl"; fi
if [[ -z "$APACHECTL" && -x /usr/sbin/apache2ctl ]]; then APACHECTL="/usr/sbin/apache2ctl"; fi
if [[ -z "$APACHECTL" ]]; then
  section "AP-00" "사전 점검" "상"
  result_line "AP-00" "수동" "apachectl/apache2ctl 미발견. Apache 미설치 또는 PATH 미설정"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

section "AP-01" "버전/모듈" "중"
append_cmd "버전" $APACHECTL -v
append_cmd "로드 모듈" $APACHECTL -M
result_line "AP-01" "주의" "버전/패치 수준 및 불필요 모듈 제거 여부 확인"

# config file discovery
cfg="$($APACHECTL -V 2>/dev/null | awk -F\" '/SERVER_CONFIG_FILE/{print $2}' | tail -n1)"
rootdir="$($APACHECTL -V 2>/dev/null | awk -F\" '/HTTPD_ROOT/{print $2}' | tail -n1)"
cfg_path="$cfg"
if [[ -n "$rootdir" && -n "$cfg" && "$cfg" != /* ]]; then cfg_path="$rootdir/$cfg"; fi

section "AP-02" "ServerTokens/ServerSignature" "중"
if [[ -r "$cfg_path" ]]; then
  append_cmd "설정 검색" bash -lc "grep -RInE '^\s*(ServerTokens|ServerSignature)\b' \"$cfg_path\" \"${rootdir:-/etc/apache2}\" 2>/dev/null | head -n 50"
  tokens="$(grep -RIsE '^\s*ServerTokens\s+' "$cfg_path" "${rootdir:-/etc/apache2}" 2>/dev/null | tail -n1 || true)"
  sig="$(grep -RIsE '^\s*ServerSignature\s+' "$cfg_path" "${rootdir:-/etc/apache2}" 2>/dev/null | tail -n1 || true)"
  if echo "$tokens" | grep -qi 'Prod' && echo "$sig" | grep -qi 'Off'; then
    result_line "AP-02" "양호" "ServerTokens Prod, ServerSignature Off 추정"
  else
    result_line "AP-02" "주의" "ServerTokens/Signature 설정이 명확하지 않음(Include 파일 포함 종합 확인 필요)"
  fi
else
  result_line "AP-02" "수동" "설정 파일 읽기 불가: $cfg_path"
fi

section "AP-03" "Directory Listing 비활성화(Options Indexes)" "상"
if [[ -n "${rootdir:-}" ]]; then
  append_cmd "Options Indexes 검색" bash -lc "grep -RInE '^\s*Options\b.*\bIndexes\b' \"$rootdir\" 2>/dev/null | head -n 50"
  result_line "AP-03" "수동" "Options Indexes 존재 시 제거(또는 -Indexes) 및 디렉터리별 정책 확인"
else
  result_line "AP-03" "수동" "HTTPD_ROOT 확인 불가"
fi

section "AP-04" "TLS 프로토콜/취약 Cipher" "상"
append_cmd "SSL 설정 검색" bash -lc "grep -RInE '^\s*(SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder)\b' \"$rootdir\" 2>/dev/null | head -n 80"
result_line "AP-04" "주의" "TLS1.0/1.1 비활성 및 약한 Cipher 제거 여부를 실제 설정/스캐너로 교차검증 권고"

echo "[INFO] 완료: $OUTFILE"
