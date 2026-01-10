#!/usr/bin/env bash
# MySQL/MariaDB security audit (Linux/Unix) - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  mysql_audit_v8_linux.sh --sw-id SW00001234 --user USER [--host HOST] [--port PORT] [--out-dir DIR]

Behavior:
  - Prompts for password securely.
  - Uses a temp defaults-extra-file to avoid password exposure via process list.
EOF
}

SW_ID=""
DB_HOST="localhost"
DB_PORT="3306"
DB_USER=""
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --host) DB_HOST="${2:-}"; shift 2 ;;
    --port) DB_PORT="${2:-}"; shift 2 ;;
    --user) DB_USER="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$SW_ID" || -z "$DB_USER" ]]; then
  echo "Missing required args."; usage; exit 2
fi

DATE="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname)"
GUIDE_VER="KR baseline (KCIS/KISA-style) + Cloud Guide 2024 (operator-tailored)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__MySQL__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section() {
  local id="$1" title="$2" severity="${3:-}"
  {
    echo ""
    echo "============================================================================"
    echo "[$id] $title"
    [[ -n "$severity" ]] && echo "위험도: $severity"
    echo "============================================================================"
    echo ""
  } >>"$OUTFILE"
}

result_line() {
  local id="$1" res="$2" details="${3:-}"
  {
    echo "★ [$id] 점검 결과: $res"
    echo "----------------------------------------------------------------------------"
    [[ -n "$details" ]] && echo "$details"
    echo ""
  } >>"$OUTFILE"
}

append() { echo "$1" >>"$OUTFILE"; }

if ! command -v mysql >/dev/null 2>&1; then
  echo "[ERROR] mysql client not found. Install mysql client first." >&2
  exit 1
fi

read -r -s -p "MySQL 패스워드 입력: " DB_PWD
echo ""

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
MYSQL_CNF="$TMP_DIR/.mysql_audit.cnf"
cat >"$MYSQL_CNF" <<CNF
[client]
user=${DB_USER}
password=${DB_PWD}
host=${DB_HOST}
port=${DB_PORT}
CNF
chmod 600 "$MYSQL_CNF"

MYSQL=(mysql --defaults-extra-file="$MYSQL_CNF" -t)
MYSQL_NB=(mysql --defaults-extra-file="$MYSQL_CNF" --batch --raw --skip-column-names)

if ! "${MYSQL[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
  echo "[ERROR] MySQL 접속 실패. 계정/비밀번호/권한/네트워크 확인 필요." >&2
  exit 1
fi

version="$("${MYSQL_NB[@]}" -e "SELECT VERSION();" | head -n 1)"
is_mariadb="아니오"
if [[ "$version" == *"MariaDB"* ]]; then is_mariadb="예"; fi

{
  echo "############################################################################"
  echo "  MySQL/MariaDB 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo ""
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "접속대상: ${DB_HOST}:${DB_PORT}"
  echo "DB 버전: ${version}"
  echo "MariaDB 여부: ${is_mariadb}"
  echo "SW ID: ${SW_ID}"
  echo "점검 계정: ${DB_USER}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

# MY-01 suspicious accounts
section "MY-01" "불필요/기본 계정(test/guest/anonymous) 제거" "상"
append "▶ 현재 상태"
"${MYSQL[@]}" -e "SELECT host, user, plugin FROM mysql.user WHERE user IN ('test','guest','') OR user LIKE 'test%' ORDER BY user, host;" >>"$OUTFILE" 2>&1 || true
suspect_count="$("${MYSQL_NB[@]}" -e "SELECT COUNT(*) FROM mysql.user WHERE user IN ('test','guest','') OR user LIKE 'test%';" | head -n 1)"
if [[ "${suspect_count:-0}" =~ ^[0-9]+$ && "$suspect_count" -eq 0 ]]; then
  result_line "MY-01" "양호" "의심 계정 없음"
else
  result_line "MY-01" "취약" "의심 계정 ${suspect_count:-N/A}개 발견"
fi

# Determine password/auth column
auth_col="$("${MYSQL_NB[@]}" -e "SELECT column_name FROM information_schema.columns WHERE table_schema='mysql' AND table_name='user' AND column_name IN ('authentication_string','password') ORDER BY (column_name='authentication_string') DESC LIMIT 1;" | head -n 1)"
[[ -z "${auth_col:-}" ]] && auth_col="authentication_string"

# MY-02 empty password
section "MY-02" "빈 패스워드/인증정보 계정 금지" "상"
append "▶ 현재 상태"
"${MYSQL[@]}" -e "SELECT user, host, plugin, ${auth_col} FROM mysql.user WHERE (${auth_col} IS NULL OR ${auth_col}='') AND plugin NOT IN ('auth_socket','unix_socket') ORDER BY user, host;" >>"$OUTFILE" 2>&1 || true
empty_count="$("${MYSQL_NB[@]}" -e "SELECT COUNT(*) FROM mysql.user WHERE (${auth_col} IS NULL OR ${auth_col}='') AND plugin NOT IN ('auth_socket','unix_socket');" | head -n 1)"
if [[ "${empty_count:-0}" =~ ^[0-9]+$ && "$empty_count" -eq 0 ]]; then
  result_line "MY-02" "양호" "빈 패스워드 계정 없음"
else
  result_line "MY-02" "취약" "빈 패스워드/인증정보 계정 ${empty_count:-N/A}개"
fi

# MY-03 password policy
section "MY-03" "패스워드 복잡도/만료 정책" "상"
append "▶ validate_password 변수"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'validate_password%';" >>"$OUTFILE" 2>&1 || true
append ""
append "▶ default_password_lifetime"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'default_password_lifetime';" >>"$OUTFILE" 2>&1 || true
plugins="$("${MYSQL[@]}" -e "SHOW PLUGINS;" 2>/dev/null || true)"
if echo "$plugins" | grep -qiE 'validate_password.*ACTIVE'; then
  result_line "MY-03" "주의" "validate_password 플러그인 ACTIVE 확인. 세부 정책(minlen/mixedcase/number/special) 검토 필요"
else
  # MySQL 8.0 can use component. Check component table if exists.
  comp="$("${MYSQL_NB[@]}" -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='mysql' AND table_name='component';" 2>/dev/null | head -n1 || true)"
  if [[ "${comp:-0}" =~ ^[0-9]+$ && "$comp" -ge 1 ]]; then
    comp_rows="$("${MYSQL_NB[@]}" -e "SELECT component_urn FROM mysql.component WHERE component_urn LIKE '%validate_password%';" 2>/dev/null || true)"
    if [[ -n "$comp_rows" ]]; then
      result_line "MY-03" "주의" "validate_password 컴포넌트 설치 흔적 확인. 변수/정책 점검 필요"
    else
      result_line "MY-03" "취약" "패스워드 복잡도(validate_password) 적용 흔적 확인 불가"
    fi
  else
    result_line "MY-03" "취약" "패스워드 복잡도(validate_password) 적용 흔적 확인 불가"
  fi
fi

# MY-04 root host restriction
section "MY-04" "관리자(root) 원격 접속 제한" "상"
append "▶ root 계정 host"
"${MYSQL[@]}" -e "SELECT user, host, plugin FROM mysql.user WHERE user='root' ORDER BY host;" >>"$OUTFILE" 2>&1 || true
root_remote="$("${MYSQL_NB[@]}" -e "SELECT COUNT(*) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');" | head -n1)"
if [[ "${root_remote:-0}" =~ ^[0-9]+$ && "$root_remote" -eq 0 ]]; then
  result_line "MY-04" "양호" "root 원격 접속 제한(로컬만)"
else
  result_line "MY-04" "취약" "root 원격 접속 허용(비로컬 host 존재)"
fi

# MY-05 local_infile
section "MY-05" "local_infile 비활성화" "중"
append "▶ 변수"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'local_infile';" >>"$OUTFILE" 2>&1 || true
local_infile="$("${MYSQL_NB[@]}" -e "SHOW VARIABLES LIKE 'local_infile';" | awk '{print $2}' | head -n1)"
if [[ "$local_infile" == "OFF" || "$local_infile" == "0" ]]; then
  result_line "MY-05" "양호" "local_infile=OFF"
else
  result_line "MY-05" "취약" "local_infile=${local_infile:-N/A}"
fi

# MY-06 secure_file_priv
section "MY-06" "secure_file_priv 제한" "중"
append "▶ 변수"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'secure_file_priv';" >>"$OUTFILE" 2>&1 || true
sfp="$("${MYSQL_NB[@]}" -e "SHOW VARIABLES LIKE 'secure_file_priv';" | awk '{print $2}' | head -n1)"
if [[ -z "${sfp:-}" ]]; then
  result_line "MY-06" "주의" "secure_file_priv 비활성(빈 값) - 조직 정책에 따라 제한 권고"
elif [[ "$sfp" == "NULL" ]]; then
  result_line "MY-06" "양호" "secure_file_priv=NULL (FILE IN/OUT 기능 차단)"
else
  result_line "MY-06" "주의" "secure_file_priv=${sfp} (지정 디렉토리 외 제한 여부 확인)"
fi

# MY-07 TLS enforcement
section "MY-07" "전송구간 암호화(SSL/TLS) 설정" "상"
append "▶ have_ssl / require_secure_transport"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'have_ssl'; SHOW VARIABLES LIKE 'require_secure_transport';" >>"$OUTFILE" 2>&1 || true
req_tls="$("${MYSQL_NB[@]}" -e "SHOW VARIABLES LIKE 'require_secure_transport';" | awk '{print $2}' | head -n1 || true)"
if [[ "$req_tls" == "ON" || "$req_tls" == "1" ]]; then
  result_line "MY-07" "양호" "require_secure_transport=ON"
else
  result_line "MY-07" "주의" "require_secure_transport=${req_tls:-N/A} (사내 정책에 따라 TLS 강제 권고)"
fi

# MY-08 logging
section "MY-08" "감사/로그 설정(일반로그/에러로그/slow query)" "중"
append "▶ general_log / slow_query_log / log_error"
"${MYSQL[@]}" -e "SHOW VARIABLES LIKE 'general_log'; SHOW VARIABLES LIKE 'slow_query_log'; SHOW VARIABLES LIKE 'log_error';" >>"$OUTFILE" 2>&1 || true
gen="$("${MYSQL_NB[@]}" -e "SHOW VARIABLES LIKE 'general_log';" | awk '{print $2}' | head -n1 || true)"
slow="$("${MYSQL_NB[@]}" -e "SHOW VARIABLES LIKE 'slow_query_log';" | awk '{print $2}' | head -n1 || true)"
if [[ "$slow" == "ON" || "$slow" == "1" ]]; then
  result_line "MY-08" "주의" "slow_query_log 활성. 운영 정책에 따라 보관/권한/전송(SIEM) 확인"
else
  result_line "MY-08" "주의" "slow_query_log 비활성 또는 확인 불가. 최소 에러로그/감사 정책 점검 권고"
fi

# Summary
section "요약" "점검 요약" ""
good="$(grep -c '점검 결과: 양호' "$OUTFILE" || true)"
bad="$(grep -c '점검 결과: 취약' "$OUTFILE" || true)"
warn="$(grep -c '점검 결과: 주의' "$OUTFILE" || true)"
manual="$(grep -c '점검 결과: 수동' "$OUTFILE" || true)"
append "양호: $good"
append "취약: $bad"
append "주의: $warn"
append "수동: $manual"
append ""

echo "[INFO] 완료: $OUTFILE"
