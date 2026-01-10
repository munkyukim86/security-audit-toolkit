#!/usr/bin/env bash
# =============================================================================
# nginx_audit_v1.sh
# Nginx 보안 점검 스크립트 (Linux) - 단독 실행
# 기준: KISA/KCIS 2021 + Cloud Guide 2024 + TLP Network 2024 (웹/WAS 기본 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__Nginx__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash nginx_audit_v1.sh --sw-id SW00001234
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + Cloud Guide 2024 + TLP Network 2024"
NOW="$(date +%Y%m%d_%H%M%S)"

OUT_DIR="results"
SW_ID=""

usage() {
  cat <<'USAGE'
Usage:
  nginx_audit_v1.sh --sw-id <SWID> [--out-dir <dir>]

Options:
  --sw-id    업무관리번호(필수)
  --out-dir  결과 저장 디렉토리 (기본: ./results)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 2;;
  esac
done

if [ -z "${SW_ID}" ]; then
  echo "[ERROR] --sw-id is required"
  usage
  exit 2
fi

if ! command -v nginx >/dev/null 2>&1; then
  echo "[ERROR] nginx not found."
  exit 2
fi

mkdir -p "${OUT_DIR}"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__Nginx__${NOW}__result.txt"

append() { printf '%s\n' "$*" >> "${OUTFILE}"; }
section() { append ""; append "============================================================================"; append "[$1] $2"; append "위험도: $3"; append "============================================================================"; }
result_line() {
  append ""; append "★ [$1] 점검 결과: $2"; append "----------------------------------------------------------------------------"; [ -n "${3:-}" ] && append "$3"; append ""
  case "$2" in
    *양호*) printf '[OK]   %s %s\n' "$1" "$2";;
    *취약*) printf '[VULN] %s %s\n' "$1" "$2";;
    *수동*) printf '[MAN]  %s %s\n' "$1" "$2";;
    *)      printf '[INFO] %s %s\n' "$1" "$2";;
  esac
}
kv() { append "- $1: ${2:-}"; }

nginx_V() { nginx -V 2>&1 || true; }
nginx_T() { nginx -T 2>&1 || true; }

CONFIG_DUMP=""
prepare_dump() {
  # nginx -T 출력은 stderr로도 나오므로 2>&1로 통합
  CONFIG_DUMP="$(nginx_T)"
}

dump_grep() {
  # grep pattern in config dump
  echo "${CONFIG_DUMP}" | grep -nE "$1" 2>/dev/null | head -n "${2:-120}" || true
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  Nginx 보안 취약점 점검 결과 (Linux)
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
버전: $(nginx -v 2>&1)
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
}

check_NG_01() {
  section "NG-01" "버전 정보 노출(server_tokens)" "상"
  append "▶ 증적"
  dump_grep '^\s*server_tokens\s+' 50 >> "${OUTFILE}" || true
  if echo "${CONFIG_DUMP}" | grep -Eq '^\s*server_tokens\s+off\s*;'; then
    result_line "NG-01" "양호 - server_tokens off"
  else
    result_line "NG-01" "수동 점검 필요 - server_tokens off 권고"
  fi
}

check_NG_02() {
  section "NG-02" "Directory Listing(autoindex) 비활성화" "상"
  append "▶ 증적"
  dump_grep '^\s*autoindex\s+' 80 >> "${OUTFILE}" || true
  if echo "${CONFIG_DUMP}" | grep -Eq '^\s*autoindex\s+on\s*;'; then
    result_line "NG-02" "취약 - autoindex on"
  else
    result_line "NG-02" "양호 - autoindex on 미탐지(추정)"
  fi
}

check_NG_03() {
  section "NG-03" "불필요/기본 컨텐츠 제거" "중"
  append "▶ 증적(대표 루트)"
  for d in /usr/share/nginx/html /var/www/html; do
    [ -d "$d" ] && ls -l "$d" 2>/dev/null | head -n 20 >> "${OUTFILE}" || true
  done
  result_line "NG-03" "수동 점검 필요 - 예제/디폴트 페이지 제거 여부 확인"
}

check_NG_04() {
  section "NG-04" "권한 분리(user directive) 및 root 실행 최소화" "상"
  append "▶ 증적"
  dump_grep '^\s*user\s+' 20 >> "${OUTFILE}" || true
  ps -eo user,comm,args 2>/dev/null | grep -E '[n]ginx: master process|[n]ginx: worker process' | head -n 20 >> "${OUTFILE}" || true
  result_line "NG-04" "수동 점검 필요 - worker 비root 실행 확인"
}

check_NG_05() {
  section "NG-05" "HTTPS TLS 프로토콜/암호군 설정" "상"
  append "▶ 증적"
  dump_grep '^\s*ssl_protocols\s+' 50 >> "${OUTFILE}" || true
  dump_grep '^\s*ssl_ciphers\s+' 50 >> "${OUTFILE}" || true
  dump_grep '^\s*ssl_prefer_server_ciphers\s+' 50 >> "${OUTFILE}" || true
  result_line "NG-05" "수동 점검 필요 - TLS1.2+ 강제 및 약한 cipher 제거"
}

check_NG_06() {
  section "NG-06" "HSTS/보안 헤더 적용(권고)" "중"
  append "▶ 증적"
  dump_grep 'add_header\s+(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Referrer-Policy)' 120 >> "${OUTFILE}" || true
  result_line "NG-06" "수동 점검 필요 - 보안 헤더 적용 여부 검토"
}

check_NG_07() {
  section "NG-07" "요청 제한/DoS 완화(리밋/타임아웃)" "하"
  append "▶ 증적"
  dump_grep '(limit_req_zone|limit_conn_zone|limit_req|limit_conn|client_body_timeout|client_header_timeout|keepalive_timeout|send_timeout)' 160 >> "${OUTFILE}" || true
  result_line "NG-07" "수동 점검 필요 - 서비스 특성에 맞는 제한 설정 권고"
}

check_NG_08() {
  section "NG-08" "로그 설정(access_log/error_log)" "중"
  append "▶ 증적"
  dump_grep '^\s*(access_log|error_log)\s+' 120 >> "${OUTFILE}" || true
  result_line "NG-08" "수동 점검 필요 - 로그 보관/마스킹/중앙수집 정책 확인"
}

check_NG_09() {
  section "NG-09" "프록시/업스트림 보안(헤더 전달 등)" "하"
  append "▶ 증적"
  dump_grep 'proxy_set_header|proxy_hide_header|proxy_pass' 160 >> "${OUTFILE}" || true
  result_line "NG-09" "수동 점검 필요 - 내부 헤더 노출/오픈 프록시 방지"
}

check_NG_10() {
  section "NG-10" "업로드 제한(client_max_body_size 등)" "하"
  append "▶ 증적"
  dump_grep 'client_max_body_size|client_body_buffer_size' 80 >> "${OUTFILE}" || true
  result_line "NG-10" "수동 점검 필요 - 업로드 정책에 맞는 제한 설정"
}

check_NG_11() {
  section "NG-11" "디렉토리/파일 접근 통제(location, deny/allow)" "상"
  append "▶ 증적"
  dump_grep '^\s*(deny|allow)\s+' 120 >> "${OUTFILE}" || true
  result_line "NG-11" "수동 점검 필요 - 민감 경로 접근 통제 및 기본 deny 정책 검토"
}

check_NG_12() {
  section "NG-12" "WAF/보안 모듈(모듈/클라우드 WAF) 연계" "하"
  append "▶ 증적"
  nginx_V | head -n 80 >> "${OUTFILE}" || true
  result_line "NG-12" "수동 점검 필요 - ModSecurity/클라우드 WAF/리버스프록시 통제 적용 검토"
}

check_NG_13() {
  section "NG-13" "설정 파일 권한(nginx.conf 등)" "중"
  append "▶ 증적"
  for f in /etc/nginx/nginx.conf /etc/nginx/conf.d /etc/nginx/sites-enabled; do
    [ -e "$f" ] && ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
  done
  result_line "NG-13" "수동 점검 필요 - 설정 파일 권한(600/640) 및 변경 통제 확인"
}

check_NG_14() {
  section "NG-14" "리스닝 포트/노출 현황" "중"
  append "▶ 증적"
  if command -v ss >/dev/null 2>&1; then
    ss -lntp 2>/dev/null | grep -E 'nginx|:(80|443)\b' | head -n 80 >> "${OUTFILE}" || true
  fi
  result_line "NG-14" "수동 점검 필요 - 불필요 포트 차단 및 접근제어(보안그룹/방화벽) 확인"
}

check_NG_15() {
  section "NG-15" "버전/패치 수준(수동 확인)" "상"
  append "▶ 증적"
  nginx_V >> "${OUTFILE}" || true
  result_line "NG-15" "수동 점검 필요 - 최신 보안 패치 적용 여부 확인"
}

write_summary() {
  section "요약" "점검 결과 요약" "-"
  local good vuln manual info
  good="$(grep -c '점검 결과: 양호' "${OUTFILE}" 2>/dev/null || echo 0)"
  vuln="$(grep -c '점검 결과: 취약' "${OUTFILE}" 2>/dev/null || echo 0)"
  manual="$(grep -c '점검 결과: 수동' "${OUTFILE}" 2>/dev/null || echo 0)"
  info="$(grep -c '점검 결과: 정보' "${OUTFILE}" 2>/dev/null || echo 0)"
  append "양호: ${good}"
  append "취약: ${vuln}"
  append "수동: ${manual}"
  append "정보: ${info}"
  append ""
  append "취약 항목(상위 20):"
  grep '점검 결과: 취약' "${OUTFILE}" 2>/dev/null | head -n 20 >> "${OUTFILE}" || true
  printf "\nSummary: OK=%s VULN=%s MANUAL=%s INFO=%s\n" "${good}" "${vuln}" "${manual}" "${info}"
}

main() {
  banner
  prepare_dump
  # 전체 덤프 저장(일부 환경에서 매우 길 수 있어 상위 400줄만)
  section "NG-DUMP" "nginx -T 요약(상위 400줄)" "-"
  echo "${CONFIG_DUMP}" | head -n 400 >> "${OUTFILE}" || true

  printf "\n=== Nginx Audit: NG-01 ~ NG-15 ===\n"
  check_NG_01
  check_NG_02
  check_NG_03
  check_NG_04
  check_NG_05
  check_NG_06
  check_NG_07
  check_NG_08
  check_NG_09
  check_NG_10
  check_NG_11
  check_NG_12
  check_NG_13
  check_NG_14
  check_NG_15
  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
