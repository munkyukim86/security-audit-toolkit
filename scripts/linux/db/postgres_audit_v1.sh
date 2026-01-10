#!/usr/bin/env bash
# =============================================================================
# postgres_audit_v1.sh
# PostgreSQL 보안 점검 스크립트 (Linux) - 단독 실행
# 기준: KISA/KCIS 2021 + Cloud Guide 2024 (DB 보안 공통 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__PostgreSQL__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash postgres_audit_v1.sh --sw-id SW00001234 --host 127.0.0.1 --port 5432 --user postgres --db postgres
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + Cloud Guide 2024"
NOW="$(date +%Y%m%d_%H%M%S)"

OUT_DIR="results"
SW_ID=""

PG_HOST="127.0.0.1"
PG_PORT="5432"
PG_USER="postgres"
PG_DB="postgres"
NONINTERACTIVE="0"

usage() {
  cat <<'USAGE'
Usage:
  postgres_audit_v1.sh --sw-id <SWID> [options]

Options:
  --sw-id           업무관리번호(필수)
  --out-dir         결과 저장 디렉토리 (기본: ./results)
  --host            PostgreSQL host (기본: 127.0.0.1)
  --port            PostgreSQL port (기본: 5432)
  --user            DB user (기본: postgres)
  --db              DB name (기본: postgres)
  --noninteractive  비대화 모드(비밀번호 입력 생략; 환경변수 PGPASSWORD 또는 PGPASSFILE 필요) (0/1)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --host) PG_HOST="${2:-}"; shift 2;;
    --port) PG_PORT="${2:-}"; shift 2;;
    --user) PG_USER="${2:-}"; shift 2;;
    --db) PG_DB="${2:-}"; shift 2;;
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

if ! command -v psql >/dev/null 2>&1; then
  echo "[ERROR] psql not found. Please install postgresql client."
  exit 2
fi

mkdir -p "${OUT_DIR}"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__PostgreSQL__${NOW}__result.txt"

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

TMP_PGPASS=""
cleanup() { [ -n "${TMP_PGPASS}" ] && rm -f "${TMP_PGPASS}" 2>/dev/null || true; }
trap cleanup EXIT

psql_exec() {
  local q="$1"
  PGPASSFILE="${TMP_PGPASS:-${PGPASSFILE:-}}" psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" -At -c "${q}" 2>/dev/null
}

init_connection() {
  if [ "${NONINTERACTIVE}" = "1" ]; then
    return
  fi
  if [ -n "${PGPASSWORD:-}" ] || [ -n "${PGPASSFILE:-}" ]; then
    return
  fi
  printf "PostgreSQL password for %s@%s (leave empty for none): " "${PG_USER}" "${PG_HOST}"
  stty -echo 2>/dev/null || true
  PG_PASS=""
  read -r PG_PASS || PG_PASS=""
  stty echo 2>/dev/null || true
  printf "\n"
  TMP_PGPASS="$(mktemp 2>/dev/null || echo /tmp/pgpass.$$)"
  chmod 600 "${TMP_PGPASS}" 2>/dev/null || true
  # host:port:db:user:password
  printf "%s:%s:%s:%s:%s\n" "${PG_HOST}" "${PG_PORT}" "*" "${PG_USER}" "${PG_PASS}" > "${TMP_PGPASS}"
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  PostgreSQL 보안 취약점 점검 결과 (Linux)
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
클라이언트: $(psql --version 2>/dev/null || true)
연결정보: host=${PG_HOST} port=${PG_PORT} user=${PG_USER} db=${PG_DB}
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
}

check_connectivity() {
  section "PG-00" "DB 접속 확인" "-"
  append "▶ 증적"
  local v
  v="$(psql_exec "SHOW server_version;" | head -n 1 || true)"
  if [ -n "$v" ]; then
    kv "server_version" "$v"
    result_line "PG-00" "양호 - 접속 성공"
    return 0
  fi
  result_line "PG-00" "수동 점검 필요 - 접속 실패" "권고: 인증/네트워크/pg_hba.conf 확인 후 재실행"
  return 1
}

check_PG_01() {
  section "PG-01" "원격 접근 제어(listen_addresses/port)" "상"
  append "▶ 증적"
  psql_exec "SHOW listen_addresses;" >> "${OUTFILE}" || true
  psql_exec "SHOW port;" >> "${OUTFILE}" || true
  result_line "PG-01" "수동 점검 필요 - 필요한 주소/IP로만 바인딩 및 방화벽/보안그룹 적용"
}

check_PG_02() {
  section "PG-02" "pg_hba.conf 인증 방식 강화(md5/scram)" "상"
  append "▶ 증적"
  psql_exec "SHOW hba_file;" >> "${OUTFILE}" || true
  local hba
  hba="$(psql_exec "SHOW hba_file;" | head -n 1 || true)"
  if [ -n "$hba" ] && [ -r "$hba" ]; then
    grep -Ev '^\s*#|^\s*$' "$hba" 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  fi
  # 자동 판정(보수적): trust 포함 여부
  if [ -n "$hba" ] && grep -Eq '^\s*host\s+.*\s+trust(\s|$)' "$hba" 2>/dev/null; then
    result_line "PG-02" "취약 - pg_hba.conf에 trust 인증 사용"
  else
    result_line "PG-02" "수동 점검 필요 - scram-sha-256/md5 등 인증방식 및 허용 IP 검토"
  fi
}

check_PG_03() {
  section "PG-03" "불필요/기본 계정 점검(슈퍼유저 최소화)" "상"
  append "▶ 증적"
  psql_exec "SELECT usename, usesuper, usecreatedb, valuntil FROM pg_user ORDER BY usesuper DESC, usename;" >> "${OUTFILE}" || true
  result_line "PG-03" "수동 점검 필요 - 슈퍼유저/CREATEDB 권한 최소화"
}

check_PG_04() {
  section "PG-04" "패스워드 정책(만료/복잡성) 적용" "중"
  append "▶ 증적"
  psql_exec "SHOW password_encryption;" >> "${OUTFILE}" || true
  psql_exec "SHOW passwordcheck;" >> "${OUTFILE}" || true
  result_line "PG-04" "수동 점검 필요 - 조직 정책에 따라 passwordcheck/LDAP/SSO 연계 여부 확인"
}

check_PG_05() {
  section "PG-05" "암호화(전송구간 SSL 강제)" "상"
  append "▶ 증적"
  psql_exec "SHOW ssl;" >> "${OUTFILE}" || true
  psql_exec "SHOW ssl_ciphers;" >> "${OUTFILE}" || true
  psql_exec "SHOW ssl_min_protocol_version;" >> "${OUTFILE}" || true
  local ssl
  ssl="$(psql_exec "SHOW ssl;" | head -n 1 || true)"
  if [ "$ssl" = "on" ]; then
    result_line "PG-05" "양호 - ssl=on(추정)"
  else
    result_line "PG-05" "수동 점검 필요 - ssl=${ssl}" "권고: 원격/클라우드 운영 시 SSL 활성 및 강한 프로토콜/암호군 적용"
  fi
}

check_PG_06() {
  section "PG-06" "로깅/감사(log_statement, log_connections 등)" "중"
  append "▶ 증적"
  psql_exec "SHOW log_connections;" >> "${OUTFILE}" || true
  psql_exec "SHOW log_disconnections;" >> "${OUTFILE}" || true
  psql_exec "SHOW log_statement;" >> "${OUTFILE}" || true
  psql_exec "SHOW log_line_prefix;" >> "${OUTFILE}" || true
  result_line "PG-06" "수동 점검 필요 - 보관/마스킹/중앙수집 정책 확인"
}

check_PG_07() {
  section "PG-07" "확장 기능/플러그인 관리(불필요 확장 제거)" "하"
  append "▶ 증적"
  psql_exec "SELECT name, default_version, installed_version FROM pg_available_extensions ORDER BY name LIMIT 200;" >> "${OUTFILE}" || true
  result_line "PG-07" "수동 점검 필요 - 사용하지 않는 확장 비활성화/제거"
}

check_PG_08() {
  section "PG-08" "권한/스키마 권한 최소화(public 권한)" "상"
  append "▶ 증적"
  psql_exec "SELECT nspname, nspowner::regrole FROM pg_namespace ORDER BY nspname;" >> "${OUTFILE}" || true
  psql_exec "SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges WHERE grantee='public' LIMIT 200;" >> "${OUTFILE}" || true
  result_line "PG-08" "수동 점검 필요 - public 권한 최소화(USAGE/CREATE 등) 검토"
}

check_PG_09() {
  section "PG-09" "설정 파일 권한(postgresql.conf/pg_hba.conf)" "중"
  append "▶ 증적"
  local conf hba
  conf="$(psql_exec "SHOW config_file;" | head -n 1 || true)"
  hba="$(psql_exec "SHOW hba_file;" | head -n 1 || true)"
  kv "config_file" "$conf"
  kv "hba_file" "$hba"
  [ -n "$conf" ] && ls -l "$conf" 2>/dev/null >> "${OUTFILE}" || true
  [ -n "$hba" ] && ls -l "$hba" 2>/dev/null >> "${OUTFILE}" || true
  result_line "PG-09" "수동 점검 필요 - 권한(600/640) 및 변경 통제 확인"
}

check_PG_10() {
  section "PG-10" "데이터 디렉토리 권한" "중"
  append "▶ 증적"
  local data
  data="$(psql_exec "SHOW data_directory;" | head -n 1 || true)"
  kv "data_directory" "$data"
  [ -n "$data" ] && ls -ld "$data" 2>/dev/null >> "${OUTFILE}" || true
  result_line "PG-10" "수동 점검 필요 - 소유자(postgres) 및 권한(700 등) 확인"
}

check_PG_11() {
  section "PG-11" "백업/복제 계정 권한(운영 시)" "하"
  append "▶ 증적"
  psql_exec "SELECT rolname, rolreplication, rolcanlogin FROM pg_roles WHERE rolreplication IS TRUE OR rolname ILIKE '%backup%' ORDER BY rolreplication DESC, rolname;" >> "${OUTFILE}" || true
  result_line "PG-11" "수동 점검 필요 - 복제/백업 계정 최소권한 적용"
}

check_PG_12() {
  section "PG-12" "위험 파라미터(archive_command, shared_preload_libraries 등)" "하"
  append "▶ 증적"
  psql_exec "SHOW shared_preload_libraries;" >> "${OUTFILE}" || true
  psql_exec "SHOW archive_command;" >> "${OUTFILE}" || true
  result_line "PG-12" "수동 점검 필요 - 외부 명령 실행 파라미터 보안 검토"
}

check_PG_13() {
  section "PG-13" "버전/패치 수준(수동 확인)" "상"
  append "▶ 증적"
  psql_exec "SHOW server_version;" >> "${OUTFILE}" || true
  result_line "PG-13" "수동 점검 필요 - 최신 보안 패치 적용 여부 확인"
}

check_PG_14() {
  section "PG-14" "클라우드 운영 통제(Private Endpoint/보안그룹 등)" "상"
  append "▶ 증적(플랫폼 설정이 핵심)"
  result_line "PG-14" "수동 점검 필요 - 접근경로, KMS 암호화, 백업/스냅샷 권한 점검"
}

check_PG_15() {
  section "PG-15" "감사 확장(pgaudit 등) 적용(선택)" "하"
  append "▶ 증적"
  psql_exec "SELECT name, installed_version FROM pg_available_extensions WHERE name='pgaudit';" >> "${OUTFILE}" || true
  result_line "PG-15" "수동 점검 필요 - 정책/라이선스에 따라 pgaudit 적용"
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

  printf "\n=== PostgreSQL Audit: PG-01 ~ PG-15 ===\n"
  if check_connectivity; then
    check_PG_01
    check_PG_02
    check_PG_03
    check_PG_04
    check_PG_05
    check_PG_06
    check_PG_07
    check_PG_08
    check_PG_09
    check_PG_10
    check_PG_11
    check_PG_12
    check_PG_13
    check_PG_14
    check_PG_15
  else
    check_PG_14
  fi
  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
