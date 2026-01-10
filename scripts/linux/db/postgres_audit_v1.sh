#!/usr/bin/env bash
# PostgreSQL security audit (Linux/Unix) - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  postgres_audit_v1.sh --sw-id SW00001234 [--host HOST] [--port PORT] [--user USER] [--db DB] [--out-dir DIR]

Notes:
  - Prompts for password (exported as PGPASSWORD for subprocess only).
  - Uses psql to discover config file locations (hba_file/config_file).
EOF
}

SW_ID=""
PGHOST="localhost"
PGPORT="5432"
PGUSER="postgres"
PGDB="postgres"
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --host) PGHOST="${2:-}"; shift 2 ;;
    --port) PGPORT="${2:-}"; shift 2 ;;
    --user) PGUSER="${2:-}"; shift 2 ;;
    --db) PGDB="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$SW_ID" ]]; then
  echo "Missing --sw-id"; usage; exit 2
fi

DATE="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname)"
GUIDE_VER="KR baseline (KCIS/KISA-style) + Cloud Guide 2024 (operator-tailored)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__PostgreSQL__${DATE}__result.txt"
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

append_cmd() {
  local label="$1"; shift
  {
    echo "▶ $label"
    echo "\$ $*"
  } >>"$OUTFILE"
  # shellcheck disable=SC2068
  "$@" >>"$OUTFILE" 2>&1 || true
  echo "" >>"$OUTFILE"
}

if ! command -v psql >/dev/null 2>&1; then
  echo "[ERROR] psql not found. Install postgresql client." >&2
  exit 1
fi

read -r -s -p "PostgreSQL 패스워드 입력(필요 시): " PGPWD
echo ""
export PGPASSWORD="$PGPWD"

PSQL=(psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -v ON_ERROR_STOP=1 -t -A)

# connectivity check
if ! "${PSQL[@]}" -c "SELECT 1;" >/dev/null 2>&1; then
  echo "[ERROR] PostgreSQL 접속 실패. 계정/비밀번호/권한/네트워크 확인 필요." >&2
  exit 1
fi

version="$("${PSQL[@]}" -c "SHOW server_version;" | head -n1)"
hba_file="$("${PSQL[@]}" -c "SHOW hba_file;" | head -n1)"
conf_file="$("${PSQL[@]}" -c "SHOW config_file;" | head -n1)"

{
  echo "############################################################################"
  echo "  PostgreSQL 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo ""
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "접속대상: ${PGHOST}:${PGPORT}"
  echo "DB: ${PGDB}"
  echo "User: ${PGUSER}"
  echo "PostgreSQL 버전: ${version}"
  echo "hba_file: ${hba_file}"
  echo "config_file: ${conf_file}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

# PG-01 auth method in pg_hba.conf
section "PG-01" "pg_hba.conf 인증 방식(trust/0.0.0.0/0 금지)" "상"
if [[ -r "$hba_file" ]]; then
  append_cmd "pg_hba.conf(주요 라인)" bash -lc "grep -vE '^\s*(#|$)' \"$hba_file\" | head -n 200"
  if grep -qE '^\s*host\s+.*\s+trust(\s|$)' "$hba_file"; then
    result_line "PG-01" "취약" "trust 인증 존재"
  elif grep -qE '^\s*host\s+.*\s+0\.0\.0\.0/0\s+(md5|scram-sha-256)(\s|$)' "$hba_file"; then
    result_line "PG-01" "주의" "0.0.0.0/0 오픈 규칙 존재(인증은 있으나 접근 범위 과대)"
  else
    result_line "PG-01" "주의" "규칙은 환경별. 외부 공개 범위/인증 방식(md5 vs scram) 종합 검토 권고"
  fi
else
  result_line "PG-01" "수동" "hba_file 읽기 불가(권한/경로)"
fi

# PG-02 password encryption
section "PG-02" "패스워드 암호화 방식(scram 권고)" "상"
pwenc="$("${PSQL[@]}" -c "SHOW password_encryption;" | head -n1)"
append_cmd "password_encryption" bash -lc "echo $pwenc"
if [[ "$pwenc" == "scram-sha-256" ]]; then
  result_line "PG-02" "양호" "password_encryption=scram-sha-256"
else
  result_line "PG-02" "주의" "password_encryption=${pwenc} (가능하면 scram-sha-256 권고)"
fi

# PG-03 SSL
section "PG-03" "전송구간 암호화(ssl)" "상"
ssl="$("${PSQL[@]}" -c "SHOW ssl;" | head -n1)"
if [[ "$ssl" == "on" ]]; then
  result_line "PG-03" "주의" "ssl=on (인증서/강제 정책/클라이언트 설정 추가 확인)"
else
  result_line "PG-03" "취약" "ssl=off (외부 통신 시 TLS 설정 필요)"
fi

# PG-04 logging
section "PG-04" "로깅(접속/종료/에러) 설정" "중"
append_cmd "주요 로그 변수" bash -lc "printf 'log_connections=%s\nlog_disconnections=%s\nlogging_collector=%s\nlog_line_prefix=%s\n' \
  \"$(${PSQL[@]} -c 'SHOW log_connections;' | head -n1)\" \
  \"$(${PSQL[@]} -c 'SHOW log_disconnections;' | head -n1)\" \
  \"$(${PSQL[@]} -c 'SHOW logging_collector;' | head -n1)\" \
  \"$(${PSQL[@]} -c 'SHOW log_line_prefix;' | head -n1)\""
lc="$("${PSQL[@]}" -c "SHOW logging_collector;" | head -n1)"
if [[ "$lc" == "on" ]]; then
  result_line "PG-04" "주의" "logging_collector=on (보관주기/권한/SIEM 전송 정책 확인)"
else
  result_line "PG-04" "주의" "logging_collector=off (systemd/journald/외부 로깅 사용 여부 확인)"
fi

# PG-05 superuser roles inventory
section "PG-05" "슈퍼유저 계정 최소화" "상"
append_cmd "슈퍼유저 목록" bash -lc "${PSQL[*]} -c \"SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolsuper IS TRUE ORDER BY rolname;\""
sup_count="$("${PSQL[@]}" -c "SELECT COUNT(*) FROM pg_roles WHERE rolsuper IS TRUE AND rolcanlogin IS TRUE;" | head -n1)"
if [[ "${sup_count:-0}" =~ ^[0-9]+$ && "$sup_count" -le 1 ]]; then
  result_line "PG-05" "주의" "슈퍼유저 로그인 계정 수=${sup_count} (조직 정책 확인)"
else
  result_line "PG-05" "주의" "슈퍼유저 로그인 계정 수=${sup_count} (최소화 권고)"
fi

# Summary
section "요약" "점검 요약" ""
good="$(grep -c '점검 결과: 양호' "$OUTFILE" || true)"
bad="$(grep -c '점검 결과: 취약' "$OUTFILE" || true)"
warn="$(grep -c '점검 결과: 주의' "$OUTFILE" || true)"
manual="$(grep -c '점검 결과: 수동' "$OUTFILE" || true)"
echo "양호: $good" >>"$OUTFILE"
echo "취약: $bad" >>"$OUTFILE"
echo "주의: $warn" >>"$OUTFILE"
echo "수동: $manual" >>"$OUTFILE"
echo "" >>"$OUTFILE"

echo "[INFO] 완료: $OUTFILE"
