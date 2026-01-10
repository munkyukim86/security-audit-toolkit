#!/usr/bin/env bash
# =============================================================================
# mysql_audit_v8_linux.sh
# MySQL 8.x 보안 점검 스크립트 (Linux) - 단독 실행
# 기준: KISA/KCIS 2021 + Cloud Guide 2024 (DB 보안 공통 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__MySQL8__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash mysql_audit_v8_linux.sh --sw-id SW00001234 --host 127.0.0.1 --user root --port 3306
#   bash mysql_audit_v8_linux.sh --sw-id SW00001234 --defaults-file /path/my.cnf
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + Cloud Guide 2024"
NOW="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="results"
SW_ID=""

DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_USER="root"
DEFAULTS_FILE=""
SOCKET=""
NONINTERACTIVE="0"

usage() {
  cat <<'USAGE'
Usage:
  mysql_audit_v8_linux.sh --sw-id <SWID> [options]

Options:
  --sw-id           업무관리번호 (필수)
  --out-dir         결과 저장 디렉토리 (기본: ./results)
  --host            MySQL host (기본: 127.0.0.1)
  --port            MySQL port (기본: 3306)
  --user            MySQL user (기본: root)
  --socket          MySQL socket path (선택)
  --defaults-file   MySQL client defaults file (선택, [client] 섹션)
  --noninteractive  비대화 모드(비밀번호 입력 생략; defaults-file 필요) (0/1)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --host) DB_HOST="${2:-}"; shift 2;;
    --port) DB_PORT="${2:-}"; shift 2;;
    --user) DB_USER="${2:-}"; shift 2;;
    --socket) SOCKET="${2:-}"; shift 2;;
    --defaults-file) DEFAULTS_FILE="${2:-}"; shift 2;;
    --noninteractive) NONINTERACTIVE="${2:-0}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 2;;
  esac
done

if [ -z "${SW_ID}" ]; then
  echo "[ERROR] --sw-id is required"
  usage
  exit 2
fi

if ! command -v mysql >/dev/null 2>&1; then
  echo "[ERROR] mysql client not found. Please install mysql client."
  exit 2
fi

mkdir -p "${OUT_DIR}"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__MySQL8__${NOW}__result.txt"

append() { printf '%s\n' "$*" >> "${OUTFILE}"; }

section() {
  local id="$1" title="$2" severity="$3"
  append ""
  append "============================================================================"
  append "[${id}] ${title}"
  append "위험도: ${severity}"
  append "============================================================================"
}

result_line() {
  local id="$1" res="$2" details="${3:-}"
  append ""
  append "★ [${id}] 점검 결과: ${res}"
  append "----------------------------------------------------------------------------"
  [ -n "${details}" ] && append "${details}"
  append ""
  case "${res}" in
    *양호*) printf '[OK]   %s %s\n' "${id}" "${res}";;
    *취약*) printf '[VULN] %s %s\n' "${id}" "${res}";;
    *수동*) printf '[MAN]  %s %s\n' "${id}" "${res}";;
    *)      printf '[INFO] %s %s\n' "${id}" "${res}";;
  esac
}

kv() { append "- $1: ${2:-}"; }

TMP_DEFAULTS=""
cleanup() {
  [ -n "${TMP_DEFAULTS}" ] && rm -f "${TMP_DEFAULTS}" 2>/dev/null || true
}
trap cleanup EXIT

mysql_exec() {
  # Execute query and return stdout; do not leak password on process list
  local q="$1"
  local args=()
  if [ -n "${DEFAULTS_FILE}" ]; then
    args+=(--defaults-extra-file="${DEFAULTS_FILE}")
  elif [ -n "${TMP_DEFAULTS}" ]; then
    args+=(--defaults-extra-file="${TMP_DEFAULTS}")
  else
    args+=(--host="${DB_HOST}" --port="${DB_PORT}" --user="${DB_USER}")
    if [ -n "${SOCKET}" ]; then
      args+=(--socket="${SOCKET}")
    fi
  fi
  mysql "${args[@]}" --batch --raw --skip-column-names --connect-timeout=5 -e "${q}" 2>/dev/null
}

init_connection() {
  if [ -n "${DEFAULTS_FILE}" ]; then
    if [ ! -r "${DEFAULTS_FILE}" ]; then
      echo "[ERROR] defaults-file not readable: ${DEFAULTS_FILE}"
      exit 2
    fi
    return
  fi

  if [ "${NONINTERACTIVE}" = "1" ]; then
    echo "[ERROR] --noninteractive=1 requires --defaults-file or injected creds"
    exit 2
  fi

  # Prompt for password and generate temp defaults file
  printf "MySQL password for %s@%s (leave empty for none): " "${DB_USER}" "${DB_HOST}"
  stty -echo 2>/dev/null || true
  DB_PASS=""
  read -r DB_PASS || DB_PASS=""
  stty echo 2>/dev/null || true
  printf "\n"

  TMP_DEFAULTS="$(mktemp 2>/dev/null || echo /tmp/mysql_audit_defaults.$$)"
  chmod 600 "${TMP_DEFAULTS}" 2>/dev/null || true
  cat > "${TMP_DEFAULTS}" <<EOF
[client]
user=${DB_USER}
password=${DB_PASS}
host=${DB_HOST}
port=${DB_PORT}
EOF
  if [ -n "${SOCKET}" ]; then
    echo "socket=${SOCKET}" >> "${TMP_DEFAULTS}"
  fi
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  MySQL 8.x 보안 취약점 점검 결과 (Linux)
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
클라이언트: $(mysql --version 2>/dev/null || true)
연결정보: host=${DB_HOST} port=${DB_PORT} user=${DB_USER} socket=${SOCKET:-"(none)"} defaults_file=${DEFAULTS_FILE:-"(none)"}
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
}

check_connectivity() {
  section "E-00" "DB 접속 확인" "-"
  append "▶ 증적"
  local v
  v="$(mysql_exec 'SELECT VERSION();' | head -n 1 || true)"
  if [ -n "$v" ]; then
    kv "VERSION()" "$v"
    result_line "E-00" "양호 - 접속 성공"
    return 0
  fi
  result_line "E-00" "수동 점검 필요 - 접속 실패" "권고: 권한/네트워크/인증 설정 확인 후 재실행"
  return 1
}

# -----------------------------------------------------------------------------
# Legacy E-01~E-03 + 확장 점검 항목
# -----------------------------------------------------------------------------

check_E_01() {
  section "E-01" "root 계정 원격 접속 제한 및 사용 최소화" "상"
  append "▶ 증적"
  mysql_exec "SELECT user,host,account_locked,plugin FROM mysql.user WHERE user='root' ORDER BY host;" >> "${OUTFILE}" || true
  local bad
  bad="$(mysql_exec "SELECT COUNT(*) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');" | head -n 1 || echo '')"
  if [ -n "$bad" ] && [ "$bad" -eq 0 ] 2>/dev/null; then
    result_line "E-01" "양호 - root 원격 호스트 계정 미존재(추정)"
  else
    result_line "E-01" "취약 - root 원격 접속 가능 계정 존재(또는 확인 불가)" "권고: root@'%' 제거, 관리계정 분리 및 MFA/망제어 적용"
  fi
}

check_E_02() {
  section "E-02" "불필요 계정/기본 계정 제거(anonymous 등)" "상"
  append "▶ 증적"
  mysql_exec "SELECT user,host FROM mysql.user ORDER BY user,host;" | head -n 200 >> "${OUTFILE}" || true
  local anon
  anon="$(mysql_exec "SELECT COUNT(*) FROM mysql.user WHERE user='' OR user IS NULL;" | head -n 1 || echo '')"
  if [ -n "$anon" ] && [ "$anon" -eq 0 ] 2>/dev/null; then
    result_line "E-02" "양호 - anonymous 계정 미존재(추정)"
  else
    result_line "E-02" "취약 - anonymous(빈 user) 계정 존재(또는 확인 불가)" "권고: anonymous 계정 삭제"
  fi
}

check_E_03() {
  section "E-03" "패스워드 정책(복잡성/재사용 제한/만료) 적용" "상"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'validate_password%';" >> "${OUTFILE}" || true
  mysql_exec "SHOW VARIABLES WHERE Variable_name IN ('default_password_lifetime','password_history','password_reuse_interval');" >> "${OUTFILE}" || true
  local plugin
  plugin="$(mysql_exec "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name IN ('validate_password','validate_password_component') AND plugin_status='ACTIVE';" | head -n 1 || echo '')"
  local lifetime
  lifetime="$(mysql_exec "SHOW VARIABLES LIKE 'default_password_lifetime';" | awk '{print $2}' | head -n 1 || true)"
  if [ -n "$plugin" ] && [ "$plugin" -ge 1 ] 2>/dev/null; then
    result_line "E-03" "양호 - validate_password 활성(추정)"
  else
    # MySQL 8.0는 component로도 동작; 변수만 존재해도 활성일 수 있음.
    if [ -n "$lifetime" ] && [ "$lifetime" -gt 0 ] 2>/dev/null; then
      result_line "E-03" "수동 점검 필요 - validate_password 플러그인 미확인, 만료=${lifetime}일" "권고: validate_password 정책 및 password_history 적용 권장"
    else
      result_line "E-03" "수동 점검 필요 - 패스워드 정책 적용 여부 확인" "권고: validate_password + password_history/password_reuse_interval 적용"
    fi
  fi
}

check_E_04() {
  section "E-04" "계정 권한 최소화(특권 계정 점검)" "상"
  append "▶ 증적(권한이 큰 계정 Top 50)"
  mysql_exec "SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges ORDER BY is_grantable DESC, privilege_type LIMIT 200;" >> "${OUTFILE}" || true
  result_line "E-04" "수동 점검 필요 - 업무 필요 최소 권한 원칙 적용 여부 검토"
}

check_E_05() {
  section "E-05" "원격 접근 제어(bind-address, skip-networking 등)" "상"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES WHERE Variable_name IN ('bind_address','skip_networking','port','mysqlx_bind_address','mysqlx_port');" >> "${OUTFILE}" || true
  local bind
  bind="$(mysql_exec "SHOW VARIABLES LIKE 'bind_address';" | awk '{print $2}' | head -n 1 || true)"
  if [ "$bind" = "127.0.0.1" ] || [ "$bind" = "localhost" ]; then
    result_line "E-05" "양호 - bind_address=${bind}"
  else
    result_line "E-05" "수동 점검 필요 - 외부 바인딩(${bind})" "권고: 접근이 필요한 IP로만 제한 및 보안그룹/방화벽 적용"
  fi
}

check_E_06() {
  section "E-06" "계정 잠금 정책(account_locked) 활용" "중"
  append "▶ 증적"
  mysql_exec "SELECT user,host,account_locked FROM mysql.user ORDER BY account_locked DESC, user, host LIMIT 200;" >> "${OUTFILE}" || true
  result_line "E-06" "수동 점검 필요 - 미사용 계정 잠금/만료 정책 운영 여부 확인"
}

check_E_07() {
  section "E-07" "감사/접속 로그 설정(error/general/slow log)" "중"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES WHERE Variable_name IN ('log_error','general_log','general_log_file','slow_query_log','slow_query_log_file','log_output','long_query_time');" >> "${OUTFILE}" || true
  result_line "E-07" "수동 점검 필요 - 로그 수집/보관/마스킹 정책 확인"
}

check_E_08() {
  section "E-08" "TLS/SSL 사용(전송구간 암호화)" "상"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'have_ssl';" >> "${OUTFILE}" || true
  mysql_exec "SHOW VARIABLES LIKE 'require_secure_transport';" >> "${OUTFILE}" || true
  local req
  req="$(mysql_exec "SHOW VARIABLES LIKE 'require_secure_transport';" | awk '{print $2}' | head -n 1 || true)"
  if [ "$req" = "ON" ]; then
    result_line "E-08" "양호 - require_secure_transport=ON"
  else
    result_line "E-08" "수동 점검 필요 - require_secure_transport=${req}" "권고: 클라우드/원격 접속 환경은 TLS 강제 권장"
  fi
}

check_E_09() {
  section "E-09" "LOCAL INFILE 비활성화" "중"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'local_infile';" >> "${OUTFILE}" || true
  local v
  v="$(mysql_exec "SHOW VARIABLES LIKE 'local_infile';" | awk '{print $2}' | head -n 1 || true)"
  if [ "$v" = "OFF" ] || [ "$v" = "0" ]; then
    result_line "E-09" "양호 - local_infile=OFF"
  else
    result_line "E-09" "취약 - local_infile=ON" "권고: local_infile=0 (필요 시 예외 승인)"
  fi
}

check_E_10() {
  section "E-10" "secure_file_priv 설정(파일 입출력 경로 제한)" "중"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'secure_file_priv';" >> "${OUTFILE}" || true
  local v
  v="$(mysql_exec "SHOW VARIABLES LIKE 'secure_file_priv';" | awk '{$1=""; print substr($0,2)}' | head -n 1 || true)"
  if [ -z "$v" ]; then
    result_line "E-10" "취약 - secure_file_priv 미설정(빈 값)" "권고: 특정 디렉토리로 제한 또는 기능 미사용 시 NULL 설정"
  else
    result_line "E-10" "양호 - secure_file_priv=${v}"
  fi
}

check_E_11() {
  section "E-11" "불필요 DB(test) 제거" "중"
  append "▶ 증적"
  mysql_exec "SHOW DATABASES;" >> "${OUTFILE}" || true
  local cnt
  cnt="$(mysql_exec "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='test';" | head -n 1 || echo '')"
  if [ -n "$cnt" ] && [ "$cnt" -eq 0 ] 2>/dev/null; then
    result_line "E-11" "양호 - test DB 미존재(추정)"
  else
    result_line "E-11" "수동 점검 필요 - test DB 존재(또는 확인 불가)" "권고: 미사용 시 test DB 및 관련 권한 삭제"
  fi
}

check_E_12() {
  section "E-12" "강한 인증 플러그인 사용(caching_sha2_password 등)" "중"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'default_authentication_plugin';" >> "${OUTFILE}" || true
  local p
  p="$(mysql_exec "SHOW VARIABLES LIKE 'default_authentication_plugin';" | awk '{print $2}' | head -n 1 || true)"
  if [ "$p" = "caching_sha2_password" ]; then
    result_line "E-12" "양호 - default_authentication_plugin=${p}"
  else
    result_line "E-12" "수동 점검 필요 - default_authentication_plugin=${p}" "권고: legacy 플러그인(mysql_native_password) 사용 최소화"
  fi
}

check_E_13() {
  section "E-13" "SQL 보안 옵션(sql_mode, symbolic-links)" "하"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'sql_mode';" >> "${OUTFILE}" || true
  mysql_exec "SHOW VARIABLES LIKE 'symbolic-links';" >> "${OUTFILE}" || true
  result_line "E-13" "수동 점검 필요 - 업무 영향 고려하여 보안 옵션 적용 여부 검토"
}

check_E_14() {
  section "E-14" "데이터 디렉토리 권한" "중"
  append "▶ 증적"
  local datadir
  datadir="$(mysql_exec "SHOW VARIABLES LIKE 'datadir';" | awk '{$1=""; print substr($0,2)}' | head -n 1 || true)"
  kv "datadir" "$datadir"
  if [ -n "$datadir" ] && [ -d "$datadir" ]; then
    ls -ld "$datadir" 2>/dev/null >> "${OUTFILE}" || true
    result_line "E-14" "수동 점검 필요 - datadir 소유자(mysql) 및 권한(750 등) 확인"
  else
    result_line "E-14" "수동 점검 필요 - datadir 확인 불가"
  fi
}

check_E_15() {
  section "E-15" "MySQL 설정 파일 권한(my.cnf 등)" "중"
  append "▶ 증적"
  # 흔한 경로들을 확인
  for f in /etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d /etc/mysql/conf.d; do
    [ -e "$f" ] && ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
  done
  if [ -n "${DEFAULTS_FILE}" ]; then
    kv "defaults-file" "${DEFAULTS_FILE}"
    ls -l "${DEFAULTS_FILE}" 2>/dev/null >> "${OUTFILE}" || true
  fi
  result_line "E-15" "수동 점검 필요 - 설정 파일 권한(600/640) 및 변경 통제 확인"
}

check_E_16() {
  section "E-16" "로그인 시도 제한/정책(플러그인/프로시저)" "하"
  append "▶ 증적"
  mysql_exec "SHOW VARIABLES LIKE 'max_connect_errors';" >> "${OUTFILE}" || true
  result_line "E-16" "수동 점검 필요 - 방화벽/WAF/계정잠금 등과 연계한 통제 확인"
}

check_E_17() {
  section "E-17" "복제/백업 계정 권한 최소화(운영 시)" "하"
  append "▶ 증적"
  mysql_exec "SELECT user,host FROM mysql.user WHERE user IN ('repl','replication','backup') ORDER BY user,host;" >> "${OUTFILE}" || true
  result_line "E-17" "수동 점검 필요 - 운영 정책에 따라 복제/백업 계정 권한 검토"
}

check_E_18() {
  section "E-18" "민감정보 보호(암호화/마스킹/권한)" "상"
  append "▶ 증적(정보성)"
  mysql_exec "SHOW VARIABLES LIKE 'default_table_encryption';" >> "${OUTFILE}" || true
  result_line "E-18" "수동 점검 필요 - 컬럼/테이블 암호화, KMS 연동, 접근통제 점검"
}

check_E_19() {
  section "E-19" "감사로그 플러그인(Enterprise Audit 등) 적용(선택)" "하"
  append "▶ 증적"
  mysql_exec "SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_name LIKE '%audit%';" >> "${OUTFILE}" || true
  result_line "E-19" "수동 점검 필요 - 제품/라이선스/정책에 따라 감사로그 적용"
}

check_E_20() {
  section "E-20" "클라우드 운영 통제(보안그룹/Private Endpoint 등)" "상"
  append "▶ 증적(클라우드 환경에서는 플랫폼 설정이 핵심)"
  result_line "E-20" "수동 점검 필요 - DB 접근 경로(Private Link/SG/NSG), 암호화(KMS), 백업/스냅샷 권한 점검"
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
  init_connection
  banner

  printf "\n=== MySQL Audit: E-01 ~ E-20 ===\n"
  if check_connectivity; then
    check_E_01
    check_E_02
    check_E_03
    check_E_04
    check_E_05
    check_E_06
    check_E_07
    check_E_08
    check_E_09
    check_E_10
    check_E_11
    check_E_12
    check_E_13
    check_E_14
    check_E_15
    check_E_16
    check_E_17
    check_E_18
    check_E_19
    check_E_20
  else
    # 접속 실패 시에도 파일 기반 일부 항목만 기록
    check_E_15
    check_E_20
  fi

  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
