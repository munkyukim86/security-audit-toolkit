#!/usr/bin/env bash
# =============================================================================
# mongodb_audit_v1.sh
# MongoDB 보안 점검 스크립트 (Linux) - 단독 실행
# 기준: KISA/KCIS 2021 + Cloud Guide 2024 (DB 보안 공통 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__MongoDB__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash mongodb_audit_v1.sh --sw-id SW00001234 --host 127.0.0.1 --port 27017
#   bash mongodb_audit_v1.sh --sw-id SW00001234 --uri "mongodb://user:pass@127.0.0.1:27017/admin?tls=true"
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + Cloud Guide 2024"
NOW="$(date +%Y%m%d_%H%M%S)"

OUT_DIR="results"
SW_ID=""

MDB_HOST="127.0.0.1"
MDB_PORT="27017"
MDB_URI=""

usage() {
  cat <<'USAGE'
Usage:
  mongodb_audit_v1.sh --sw-id <SWID> [options]

Options:
  --sw-id   업무관리번호(필수)
  --out-dir 결과 저장 디렉토리 (기본: ./results)
  --host    MongoDB host (기본: 127.0.0.1)
  --port    MongoDB port (기본: 27017)
  --uri     MongoDB URI (권장: 인증/옵션 포함) 예: mongodb://user:pass@host:27017/admin?tls=true
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --host) MDB_HOST="${2:-}"; shift 2;;
    --port) MDB_PORT="${2:-}"; shift 2;;
    --uri) MDB_URI="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 2;;
  esac
done

if [ -z "${SW_ID}" ]; then
  echo "[ERROR] --sw-id is required"
  usage
  exit 2
fi

if ! command -v mongosh >/dev/null 2>&1 && ! command -v mongo >/dev/null 2>&1; then
  echo "[ERROR] mongosh/mongo not found. Please install MongoDB shell."
  exit 2
fi

mkdir -p "${OUT_DIR}"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__MongoDB__${NOW}__result.txt"

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

mongo_shell() {
  if command -v mongosh >/dev/null 2>&1; then echo "mongosh"; else echo "mongo"; fi
}

mongo_eval() {
  local js="$1"
  local sh
  sh="$(mongo_shell)"
  if [ -n "${MDB_URI}" ]; then
    "${sh}" "${MDB_URI}" --quiet --eval "${js}" 2>/dev/null
  else
    "${sh}" --host "${MDB_HOST}" --port "${MDB_PORT}" --quiet --eval "${js}" 2>/dev/null
  fi
}

detect_config_path() {
  # Common default
  if [ -r /etc/mongod.conf ]; then
    echo "/etc/mongod.conf"
    return
  fi
  # Try from process args
  local p
  p="$(ps -eo args 2>/dev/null | grep -E '[m]ongod\b' | head -n 1 || true)"
  if echo "$p" | grep -q -- '--config'; then
    echo "$p" | sed -n 's/.*--config[= ]\([^ ]*\).*/\1/p' | head -n 1
    return
  fi
  if echo "$p" | grep -q -- ' -f '; then
    echo "$p" | sed -n 's/.* -f \([^ ]*\).*/\1/p' | head -n 1
    return
  fi
  echo ""
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  MongoDB 보안 취약점 점검 결과 (Linux)
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
클라이언트: $($(mongo_shell) --version 2>/dev/null | head -n 1 || true)
연결정보: host=${MDB_HOST} port=${MDB_PORT} uri=${MDB_URI:-"(none)"}
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
}

check_connectivity() {
  section "MB-00" "DB 접속 확인" "-"
  append "▶ 증적"
  local v
  v="$(mongo_eval 'db.runCommand({buildInfo:1}).version' | head -n 1 || true)"
  if [ -n "$v" ]; then
    kv "MongoDB version" "$v"
    result_line "MB-00" "양호 - 접속 성공(추정)"
    return 0
  fi
  result_line "MB-00" "수동 점검 필요 - 접속 실패/권한 부족" "권고: --uri로 인증/옵션 포함하여 재실행"
  return 1
}

check_MB_01() {
  section "MB-01" "네트워크 바인딩(bindIp) 제한" "상"
  append "▶ 증적"
  local conf
  conf="$(detect_config_path)"
  kv "config" "${conf:-"(unknown)"}"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*(bindIp|bindIpAll)\b' "$conf" 2>/dev/null >> "${OUTFILE}" || true
  local v
  v="$(mongo_eval "db.runCommand({getCmdLineOpts:1}).parsed.net && db.runCommand({getCmdLineOpts:1}).parsed.net.bindIp" 2>/dev/null | tail -n 1 || true)"
  [ -n "$v" ] && kv "getCmdLineOpts net.bindIp" "$v"
  # Conservative judgement: if config contains 0.0.0.0 or bindIpAll true => manual/vuln
  if [ -n "$conf" ] && grep -Eq '0\.0\.0\.0|bindIpAll\s*:\s*true|bindIpAll:\s*true' "$conf" 2>/dev/null; then
    result_line "MB-01" "취약 - bindIpAll/0.0.0.0 설정 탐지"
  else
    result_line "MB-01" "수동 점검 필요 - 운영 필요 IP로만 제한 및 방화벽/보안그룹 적용"
  fi
}

check_MB_02() {
  section "MB-02" "인증/권한관리(authorization) 활성화" "상"
  append "▶ 증적"
  local conf
  conf="$(detect_config_path)"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*authorization\s*:' "$conf" 2>/dev/null >> "${OUTFILE}" || true
  local s
  s="$(mongo_eval "db.runCommand({getParameter:1, authorization:1}).authorization" | head -n 1 || true)"
  [ -n "$s" ] && kv "getParameter authorization" "$s"
  if [ "$s" = "enabled" ]; then
    result_line "MB-02" "양호 - authorization enabled(추정)"
  else
    result_line "MB-02" "취약 또는 수동 - authorization 미확인" "권고: security.authorization: enabled"
  fi
}

check_MB_03() {
  section "MB-03" "권한 있는 계정 최소화(관리자 role 점검)" "상"
  append "▶ 증적"
  mongo_eval "db.getSiblingDB('admin').runCommand({usersInfo:1})" | head -n 200 >> "${OUTFILE}" || true
  result_line "MB-03" "수동 점검 필요 - 사용자/role 최소권한 검토"
}

check_MB_04() {
  section "MB-04" "TLS/SSL 적용(전송구간 암호화)" "상"
  append "▶ 증적"
  local conf
  conf="$(detect_config_path)"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*(tls|ssl)\s*:' "$conf" 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
  local v
  v="$(mongo_eval "db.runCommand({getCmdLineOpts:1}).parsed.net && db.runCommand({getCmdLineOpts:1}).parsed.net.tls && db.runCommand({getCmdLineOpts:1}).parsed.net.tls.mode" | tail -n 1 || true)"
  [ -n "$v" ] && kv "tls.mode" "$v"
  result_line "MB-04" "수동 점검 필요 - 원격/클라우드 운영 시 TLS 강제 권장"
}

check_MB_05() {
  section "MB-05" "감사 로그(auditLog) 적용(선택)" "하"
  append "▶ 증적"
  local conf
  conf="$(detect_config_path)"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*auditLog\s*:' "$conf" 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
  result_line "MB-05" "수동 점검 필요 - 조직 정책에 따라 감사로그 적용"
}

check_MB_06() {
  section "MB-06" "로깅 설정(systemLog)" "중"
  append "▶ 증적"
  local conf
  conf="$(detect_config_path)"
  [ -n "$conf" ] && [ -r "$conf" ] && grep -En '^\s*systemLog\s*:' "$conf" 2>/dev/null | head -n 120 >> "${OUTFILE}" || true
  result_line "MB-06" "수동 점검 필요 - 로그 보관/중앙수집/마스킹 정책 확인"
}

check_MB_07() {
  section "MB-07" "보안 관련 파라미터(스크립트 실행, 서버 사이드 JS 등)" "중"
  append "▶ 증적"
  local v
  v="$(mongo_eval "db.adminCommand({getParameter:1, javascriptEnabled:1}).javascriptEnabled" | head -n 1 || true)"
  [ -n "$v" ] && kv "javascriptEnabled" "$v"
  result_line "MB-07" "수동 점검 필요 - server-side JS 필요성/위험도 평가"
}

check_MB_08() {
  section "MB-08" "프로세스 권한/데이터 디렉토리 권한" "중"
  append "▶ 증적"
  ps -eo user,comm,args 2>/dev/null | grep -E '[m]ongod\b' | head -n 20 >> "${OUTFILE}" || true
  local conf data
  conf="$(detect_config_path)"
  data=""
  if [ -n "$conf" ] && [ -r "$conf" ]; then
    data="$(grep -E '^\s*dbPath\s*:' "$conf" 2>/dev/null | head -n 1 | awk -F: '{gsub(/[[:space:]]/,"",$2); print $2}' || true)"
  fi
  kv "dbPath(추정)" "${data:-"(unknown)"}"
  [ -n "$data" ] && [ -d "$data" ] && ls -ld "$data" 2>/dev/null >> "${OUTFILE}" || true
  result_line "MB-08" "수동 점검 필요 - dbPath 권한(700 등) 및 소유자(mongodb) 확인"
}

check_MB_09() {
  section "MB-09" "불필요 포트/인터페이스 노출" "중"
  append "▶ 증적"
  if command -v ss >/dev/null 2>&1; then
    ss -lntp 2>/dev/null | grep -E ':(27017|27018|27019)\b' >> "${OUTFILE}" || true
  fi
  result_line "MB-09" "수동 점검 필요 - 필요 포트만 노출/ACL 제한"
}

check_MB_10() {
  section "MB-10" "백업/스냅샷 권한 및 암호화(클라우드)" "상"
  append "▶ 증적(플랫폼 설정이 핵심)"
  result_line "MB-10" "수동 점검 필요 - KMS 암호화, 백업 보관/권한, 복구 테스트 확인"
}

check_MB_11() {
  section "MB-11" "버전/패치 수준(수동 확인)" "상"
  append "▶ 증적"
  mongo_eval 'db.runCommand({buildInfo:1}).version' >> "${OUTFILE}" || true
  result_line "MB-11" "수동 점검 필요 - 최신 보안 패치 적용 여부 확인"
}

check_MB_12() {
  section "MB-12" "운영 권고(옵션/권한 종합)" "하"
  append "▶ 증적"
  result_line "MB-12" "정보 - 종합 권고: 인증+TLS+접근제어+로깅+패치"
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
  printf "\n=== MongoDB Audit: MB-01 ~ MB-12 ===\n"
  if check_connectivity; then
    check_MB_01
    check_MB_02
    check_MB_03
    check_MB_04
    check_MB_05
    check_MB_06
    check_MB_07
    check_MB_08
    check_MB_09
    check_MB_10
    check_MB_11
    check_MB_12
  else
    # 접속 실패 시 파일 기반/수동 항목 일부만 기록
    check_MB_01
    check_MB_10
    check_MB_11
  fi
  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
