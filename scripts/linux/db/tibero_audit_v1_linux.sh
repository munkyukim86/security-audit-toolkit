#!/usr/bin/env bash
# Tibero DB audit wrapper (Linux/Unix)
# - Executes bundled tbsql(SQL*Plus-like) audit script (legacy IGLOO v3.2 SQL) and stores evidence.
# Last update: 2026-01-10

set -euo pipefail
umask 077

GUIDE_VER="KISA 2021 / Cloud Guide 2024 / TLP Network 2024"
DATE="$(date +%Y%m%d_%H%M%S)"
HOST="$(hostname 2>/dev/null || echo unknown)"
OUT_DIR="$(pwd)"

SW_ID=""
OUTFILE=""

log_info() { printf '[INFO] %s\n' "$*" >&2; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }

section() {
  local id="$1" title="$2" risk="${3:-}"
  {
    printf '\n===============================================================================\n'
    printf '■ [%s] %s' "$id" "$title"
    if [[ -n "$risk" ]]; then printf ' (위험도: %s)' "$risk"; fi
    printf '\n===============================================================================\n'
  } >>"$OUTFILE"
}

result_line() {
  local id="$1" res="$2" details="${3:-}"
  local tag=""
  case "$res" in
    양호) tag="[OK]" ;;
    취약) tag="[VULN]" ;;
    수동*|점검*|확인*) tag="[MANUAL]" ;;
    *) tag="[INFO]" ;;
  esac
  {
    if [[ -n "$details" ]]; then
      printf '%s %s - %s\n' "$tag" "$id" "$details"
    else
      printf '%s %s\n' "$tag" "$id"
    fi
  } >>"$OUTFILE"
}

make_outfile() {
  mkdir -p "$OUT_DIR/results"
  OUTFILE="$OUT_DIR/results/${SW_ID}__${HOST}__${1}__${DATE}__rpt.txt"
  : >"$OUTFILE"
  {
    printf 'Security Audit Toolkit Report\n'
    printf 'Component: %s\n' "$1"
    printf 'SW_ID: %s\n' "$SW_ID"
    printf 'Host: %s\n' "$HOST"
    printf 'Generated: %s\n' "$DATE"
    printf 'Guide: %s\n' "$GUIDE_VER"
    printf '\n'
  } >>"$OUTFILE"
}


usage() {
  cat <<'EOF'
Usage:
  tibero_audit_v1_linux.sh --sw-id SW00001234 [--out-dir DIR]
                           --user USER --tns TNS_ALIAS
                           [--sql-variant tibero5|tibero5sp1|auto] [--sql-file PATH]

Notes:
  - This script uses tbsql (Tibero client). Password is prompted (not echoed).
  - sql-variant selects one of the bundled legacy SQL scripts.

Requires:
  - tbsql in PATH
EOF
}

DB_USER=""
DB_TNS=""
SQL_VARIANT="auto"
SQL_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --user) DB_USER="$2"; shift 2 ;;
    --tns) DB_TNS="$2"; shift 2 ;;
    --sql-variant) SQL_VARIANT="$2"; shift 2 ;;
    --sql-file) SQL_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$SW_ID" ]]; then
  echo "[ERROR] --sw-id is required" >&2
  usage
  exit 1
fi

make_outfile "TiberoDB"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RES_DIR="$(cd "$SCRIPT_DIR/../../resources/db/tibero" 2>/dev/null && pwd || true)"

section "TIB-00" "사전 점검(tbsql)" "상"
if ! command -v tbsql >/dev/null 2>&1; then
  result_line "TIB-00" "취약" "tbsql 미설치(Tibero client 필요). 수동으로 SQL 스크립트 실행 후 증적 첨부"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi
result_line "TIB-00" "양호" "$(tbsql -v 2>&1 | head -n 1 | tr -d '' || echo 'tbsql detected')"

# Resolve SQL file
if [[ -n "$SQL_FILE" ]]; then
  SQL_PATH="$SQL_FILE"
else
  case "$SQL_VARIANT" in
    tibero5) SQL_PATH="$(ls "$RES_DIR"/*Tibero5_*unix*.sql 2>/dev/null | head -n 1 || true)" ;;
    tibero5sp1) SQL_PATH="$(ls "$RES_DIR"/*sp_1*unix*.sql 2>/dev/null | head -n 1 || true)" ;;
    auto|*) SQL_PATH="$(ls "$RES_DIR"/*.sql 2>/dev/null | head -n 1 || true)" ;;
  esac
fi

if [[ -z "$SQL_PATH" || ! -f "$SQL_PATH" ]]; then
  result_line "TIB-00" "취약" "SQL 스크립트 파일을 찾을 수 없음(variant=$SQL_VARIANT): $SQL_PATH"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

section "TIB-01" "점검 실행(증적 수집)" "상"

if [[ -z "$DB_USER" || -z "$DB_TNS" ]]; then
  result_line "TIB-01" "수동" "필수 인자 누락: --user, --tns"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

TMP_DIR="$(mktemp -d 2>/dev/null || echo "/tmp/tibero_audit.$$")"
SQL_OUT="$TMP_DIR/tbsql_console.out"

DB_PASS=""
printf "Tibero password for %s@%s (leave empty for none): " "$DB_USER" "$DB_TNS" >&2
stty -echo 2>/dev/null || true
read -r DB_PASS || DB_PASS=""
stty echo 2>/dev/null || true
printf "
" >&2

LOGIN_SQL="$TMP_DIR/login.sql"
cat >"$LOGIN_SQL" <<EOF
connect $DB_USER/\$1@$DB_TNS
@$SQL_PATH
exit
EOF

( cd "$OUT_DIR" && tbsql -s /nolog @"$LOGIN_SQL" "$DB_PASS" ) >"$SQL_OUT" 2>&1 || true
unset DB_PASS

result_line "TIB-01" "점검완료" "tbsql 실행 완료(콘솔 출력/스풀 파일 확인)"

{
  echo "-----[tbsql console output begin]-----"
  sed -n '1,2000p' "$SQL_OUT" 2>/dev/null || true
  echo "-----[tbsql console output end]-----"
} >>"$OUTFILE"

YYMMDD="$(date +%y%m%d)"
SPOOL_CANDIDATE="$(ls -t "$OUT_DIR"/TIBERO_*_"$YYMMDD".txt 2>/dev/null | head -n 1 || true)"
if [[ -n "$SPOOL_CANDIDATE" && -f "$SPOOL_CANDIDATE" ]]; then
  DEST="$OUT_DIR/results/${SW_ID}__${HOST}__TiberoDB__${DATE}__spool.txt"
  mv -f "$SPOOL_CANDIDATE" "$DEST" 2>/dev/null || cp -f "$SPOOL_CANDIDATE" "$DEST" 2>/dev/null || true
  result_line "TIB-01" "점검완료" "Spool saved: $DEST"
else
  result_line "TIB-01" "수동" "스풀 파일 자동 탐지 실패(TIBERO_*_${YYMMDD}.txt). OUT_DIR에서 파일 확인"
fi

section "TIB-99" "후속 조치" "중"
result_line "TIB-99" "수동" "스풀 파일(상세 증적) 기반으로 계정/권한/감사/암호화 설정을 조직 기준서에 따라 판정"

rm -rf "$TMP_DIR" 2>/dev/null || true
echo "[INFO] 완료: $OUTFILE"
