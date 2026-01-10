#!/usr/bin/env bash
# =============================================================================
# apache_httpd_audit_v1.sh
# Apache HTTP Server(httpd/apache2) 보안 점검 스크립트 (Linux) - 단독 실행
# 기준: KISA/KCIS 2021 + Cloud Guide 2024 + TLP Network 2024 (웹/WAS 기본 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__Apache__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash apache_httpd_audit_v1.sh --sw-id SW00001234
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
  apache_httpd_audit_v1.sh --sw-id <SWID> [--out-dir <dir>]

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

APACHE_CTL=""
if command -v apachectl >/dev/null 2>&1; then
  APACHE_CTL="apachectl"
elif command -v apache2ctl >/dev/null 2>&1; then
  APACHE_CTL="apache2ctl"
fi
if [ -z "${APACHE_CTL}" ]; then
  echo "[ERROR] apachectl/apache2ctl not found."
  exit 2
fi

mkdir -p "${OUT_DIR}"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__Apache__${NOW}__result.txt"

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

apache_v() { ${APACHE_CTL} -v 2>/dev/null || true; }
apache_V() { ${APACHE_CTL} -V 2>/dev/null || true; }
apache_M() { ${APACHE_CTL} -M 2>/dev/null || true; }
apache_T() { ${APACHE_CTL} -t -D DUMP_RUN_CFG 2>/dev/null || true; }

detect_config() {
  local root conf
  root="$(apache_V | sed -n 's/.*-D HTTPD_ROOT="\([^"]*\)".*/\1/p' | head -n 1)"
  conf="$(apache_V | sed -n 's/.*-D SERVER_CONFIG_FILE="\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -n "$root" ] && [ -n "$conf" ]; then
    echo "${root%/}/${conf}"
  elif [ -n "$conf" ] && [ -f "$conf" ]; then
    echo "$conf"
  else
    echo ""
  fi
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  Apache HTTP Server 보안 취약점 점검 결과 (Linux)
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
apachectl: ${APACHE_CTL}
버전: $(apache_v | head -n 1)
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
}

# Checks
check_AP_01() {
  section "AP-01" "버전 정보 노출(ServerTokens/ServerSignature)" "상"
  append "▶ 증적"
  local conf
  conf="$(detect_config)"
  kv "config" "${conf:-"(unknown)"}"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*(ServerTokens|ServerSignature)\b' "$conf" 2>/dev/null >> "${OUTFILE}" || true
  local st ss
  st="$(apache_T | sed -n 's/.*ServerTokens\s\+\(.*\)$/\1/p' | tail -n 1 || true)"
  ss="$(apache_T | sed -n 's/.*ServerSignature\s\+\(.*\)$/\1/p' | tail -n 1 || true)"
  [ -n "$st" ] && kv "Effective ServerTokens" "$st"
  [ -n "$ss" ] && kv "Effective ServerSignature" "$ss"
  if echo "$st" | grep -qi '^Prod' && echo "$ss" | grep -qi '^Off'; then
    result_line "AP-01" "양호 - ServerTokens Prod & ServerSignature Off(추정)"
  else
    result_line "AP-01" "수동 점검 필요 - 정보 노출 최소화 권고" "권고: ServerTokens Prod, ServerSignature Off"
  fi
}

check_AP_02() {
  section "AP-02" "Directory Listing(Indexes) 비활성화" "상"
  append "▶ 증적"
  apache_T | grep -E 'Options\s+Indexes|Options\s+\+Indexes' | head -n 50 >> "${OUTFILE}" || true
  if apache_T | grep -Eq 'Options\s+.*Indexes'; then
    result_line "AP-02" "수동 점검 필요 - Indexes 사용 구간 검토" "권고: 필요 구간만 제한적으로 사용 또는 비활성"
  else
    result_line "AP-02" "양호 - Indexes 옵션 미탐지(추정)"
  fi
}

check_AP_03() {
  section "AP-03" "기본/예제 컨텐츠 제거" "중"
  append "▶ 증적(대표 경로)"
  for d in /var/www/html /usr/share/httpd/noindex /usr/share/apache2/default-site; do
    [ -d "$d" ] && ls -l "$d" 2>/dev/null | head -n 20 >> "${OUTFILE}" || true
  done
  result_line "AP-03" "수동 점검 필요 - 불필요 예제/디렉토리 제거 여부 확인"
}

check_AP_04() {
  section "AP-04" "불필요 모듈 비활성화" "중"
  append "▶ 증적(Loaded modules 상위 200)"
  apache_M | head -n 200 >> "${OUTFILE}" || true
  result_line "AP-04" "수동 점검 필요 - mod_status/mod_info 등 불필요 모듈/핸들러 비활성화"
}

check_AP_05() {
  section "AP-05" "관리/상태 페이지 접근통제(mod_status 등)" "상"
  append "▶ 증적"
  apache_T | grep -nE '(Location\s+/(server-status|server-info)|SetHandler\s+(server-status|server-info))' | head -n 80 >> "${OUTFILE}" || true
  result_line "AP-05" "수동 점검 필요 - server-status/server-info 접근 IP 제한 및 인증 적용"
}

check_AP_06() {
  section "AP-06" "권한 분리(User/Group) 및 root 실행 최소화" "상"
  append "▶ 증적"
  apache_T | grep -nE '^(User|Group)\s+' | head -n 20 >> "${OUTFILE}" || true
  ps -eo user,comm,args 2>/dev/null | grep -E '[a]pache2\b|[h]ttpd\b' | head -n 20 >> "${OUTFILE}" || true
  result_line "AP-06" "수동 점검 필요 - Worker 프로세스 비root 계정 실행 확인"
}

check_AP_07() {
  section "AP-07" "문서 루트/설정 파일 권한" "중"
  append "▶ 증적"
  local conf
  conf="$(detect_config)"
  [ -n "$conf" ] && ls -l "$conf" 2>/dev/null >> "${OUTFILE}" || true
  apache_T | grep -nE '^\s*DocumentRoot\s+' | head -n 10 >> "${OUTFILE}" || true
  result_line "AP-07" "수동 점검 필요 - 설정파일 640 이하, 문서루트 쓰기권한 최소화"
}

check_AP_08() {
  section "AP-08" "SSL/TLS 프로토콜 및 Cipher 설정(HTTPS 운영 시)" "상"
  append "▶ 증적"
  apache_T | grep -nE 'SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder' | head -n 120 >> "${OUTFILE}" || true
  result_line "AP-08" "수동 점검 필요 - TLS1.2+ 강제 및 약한 Cipher 제거"
}

check_AP_09() {
  section "AP-09" "HTTP 보안 헤더 적용(권고)" "중"
  append "▶ 증적"
  apache_T | grep -nE 'Header\s+(set|always set)\s+(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|Referrer-Policy)' | head -n 120 >> "${OUTFILE}" || true
  result_line "AP-09" "수동 점검 필요 - 보안 헤더 적용 여부 검토(업무 영향 고려)"
}

check_AP_10() {
  section "AP-10" "Trace/Track 비활성화" "중"
  append "▶ 증적"
  apache_T | grep -nE '^\s*TraceEnable\s+' | head -n 20 >> "${OUTFILE}" || true
  if apache_T | grep -Eq '^\s*TraceEnable\s+on\b'; then
    result_line "AP-10" "취약 - TraceEnable On"
  else
    result_line "AP-10" "양호 - TraceEnable on 미탐지(추정)"
  fi
}

check_AP_11() {
  section "AP-11" "요청 제한/DoS 완화(Timeout, KeepAlive 등)" "하"
  append "▶ 증적"
  apache_T | grep -nE '^\s*(Timeout|KeepAlive|MaxKeepAliveRequests|KeepAliveTimeout|RequestReadTimeout)\s+' | head -n 80 >> "${OUTFILE}" || true
  result_line "AP-11" "수동 점검 필요 - 트래픽 특성에 맞게 설정"
}

check_AP_12() {
  section "AP-12" "로그 설정 및 중앙수집" "중"
  append "▶ 증적"
  apache_T | grep -nE '^\s*(ErrorLog|CustomLog|LogFormat)\s+' | head -n 120 >> "${OUTFILE}" || true
  result_line "AP-12" "수동 점검 필요 - 로그 보관/마스킹/중앙수집 정책 준수 여부 확인"
}

check_AP_13() {
  section "AP-13" "접근 제어(Require, Directory/Files 매칭)" "상"
  append "▶ 증적"
  apache_T | grep -nE '^\s*<Directory\b|^\s*Require\s+' | head -n 120 >> "${OUTFILE}" || true
  result_line "AP-13" "수동 점검 필요 - 민감 경로 접근 통제 및 기본 deny 정책 확인"
}

check_AP_14() {
  section "AP-14" "WAF/보안 모듈(mod_security 등) 적용(선택)" "하"
  append "▶ 증적"
  apache_M | grep -i security | head -n 50 >> "${OUTFILE}" || true
  result_line "AP-14" "수동 점검 필요 - 조직 정책에 따라 WAF/보안모듈 적용"
}

check_AP_15() {
  section "AP-15" "버전/패치 수준(수동 확인)" "상"
  append "▶ 증적"
  apache_v >> "${OUTFILE}" || true
  result_line "AP-15" "수동 점검 필요 - 최신 보안 패치 적용 여부 확인"
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
  printf "\n=== Apache Audit: AP-01 ~ AP-15 ===\n"
  check_AP_01
  check_AP_02
  check_AP_03
  check_AP_04
  check_AP_05
  check_AP_06
  check_AP_07
  check_AP_08
  check_AP_09
  check_AP_10
  check_AP_11
  check_AP_12
  check_AP_13
  check_AP_14
  check_AP_15
  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
