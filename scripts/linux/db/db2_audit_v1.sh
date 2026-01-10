#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# IBM Db2 (Linux/Unix) Audit Script
# Version : v0.2.0
# Updated : 2026-01-10
# Baseline: KISA 2021 (DBMS security baseline), Cloud Vulnerability Guide 2024
# -----------------------------------------------------------------------------
# Notes
#  - Run as Db2 instance user (e.g., db2inst1) or with its profile loaded.
#  - This script performs safe read-only commands: db2level, get dbm cfg,
#    (optional) get db cfg for a database, and (optional) db2audit status.
#
# Usage example:
#   ./db2_audit_v1.sh --sw-id SW001 --db SAMPLE --out-dir ./results
# -----------------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'
umask 077

DATE="$(date +%Y%m%d_%H%M%S)"
GUIDE_VER="KISA 2021 & Cloud 2024 & TLP Network 2024"

SW_ID=""
DB_NAME=""
OUT_DIR="$(pwd)"
HOSTNAME="$(hostname)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --db) DB_NAME="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --host) HOSTNAME="$2"; shift 2 ;;
    -h|--help)
      cat <<'HELP'
Usage: db2_audit_v1.sh --sw-id <ID> [--db <DBNAME>] [--out-dir <DIR>] [--host <HOSTNAME>]
HELP
      exit 0
      ;;
    *) shift ;;
  esac
done

if [[ -z "$SW_ID" ]]; then
  echo "[ERROR] --sw-id is required" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__DB2__${DATE}__result.txt"

section() {
  local id="$1" title="$2" severity="$3"
  {
    echo "============================================================================"
    echo "[${id}] ${title}"
    echo "위험도: ${severity}"
    echo "============================================================================"
    echo
  } >> "$OUTFILE"
}

result_line() {
  local id="$1" res="$2" details="$3"
  {
    echo "★ [${id}] 점검 결과: ${res}"
    echo "----------------------------------------------------------------------------"
    echo "$details"
    echo
  } >> "$OUTFILE"
}

log_info() {
  echo "[INFO] $1" >> "$OUTFILE"
}

{
  echo "############################################################################"
  echo "  IBM Db2 취약점 점검 결과 (Linux/Unix)"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "SW ID: ${SW_ID}"
  echo "DB: ${DB_NAME:-'(미지정)'}"
  echo "############################################################################"
  echo
} > "$OUTFILE"

if ! command -v db2 >/dev/null 2>&1; then
  result_line "DB2-00" "취약" "db2 CLI를 찾을 수 없습니다. Db2 Client/Server 설치 및 PATH 설정을 확인하세요."
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

# Collect db2level (does not require instance started)
section "DB2-01" "Db2 버전/레벨 확인" "중"
level_out="$(db2level 2>&1 || true)"
log_info "db2level:\n${level_out}"
if [[ -n "$level_out" ]]; then
  result_line "DB2-01" "양호" "Db2 설치 확인 (상세는 결과 파일 INFO 참고)"
else
  result_line "DB2-01" "취약" "db2level 실행 실패"
fi

# Check db2sysc owner (best-effort)
section "DB2-02" "Db2 프로세스 실행 계정(root 여부)" "상"
ps_out="$(ps -eo user,comm,args 2>/dev/null | grep -E 'db2sysc|db2wdog' | grep -v grep || true)"
if [[ -z "$ps_out" ]]; then
  result_line "DB2-02" "수동" "Db2 프로세스를 찾지 못했습니다. 인스턴스가 실행 중인지 확인하세요."
else
  if echo "$ps_out" | awk '{print $1}' | grep -qi '^root$'; then
    result_line "DB2-02" "취약" "Db2 프로세스가 root로 실행 중입니다. (권고: 전용 인스턴스 계정)\n${ps_out}"
  else
    result_line "DB2-02" "양호" "root로 실행되는 Db2 프로세스가 발견되지 않았습니다.\n${ps_out}"
  fi
fi

# Get DBM CFG (requires instance env; may fail)
section "DB2-03" "DBM CFG 인증 설정(AUTHENTICATION/SRVCON_AUTH)" "상"
dbm_cfg="$(db2 -x 'get dbm cfg' 2>&1 || true)"
if echo "$dbm_cfg" | grep -qiE 'SQL1024N|SQLSTATE'; then
  result_line "DB2-03" "수동" "DBM CFG 조회 실패. 인스턴스 환경(db2profile) 및 권한을 확인하세요.\n${dbm_cfg}"
else
  auth="$(echo "$dbm_cfg" | sed -n 's/.*Authentication type \(AUTHENTICATION\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
  srvcon="$(echo "$dbm_cfg" | sed -n 's/.*Client authentication \(SRVCON_AUTH\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"

  details="AUTHENTICATION=${auth:-'(미검출)'}\nSRVCON_AUTH=${srvcon:-'(미검출)'}\n\n${dbm_cfg}"

  # Conservative policy: prefer SERVER or SERVER_ENCRYPT
  bad=0
  if [[ -n "$auth" ]] && echo "$auth" | grep -qiE '^CLIENT$'; then bad=1; fi
  if [[ -n "$srvcon" ]] && echo "$srvcon" | grep -qiE '^CLIENT$'; then bad=1; fi

  if [[ $bad -eq 1 ]]; then
    result_line "DB2-03" "취약" "클라이언트 측 인증(CLIENT) 설정은 위/변조 위험이 증가할 수 있습니다. (권고: SERVER 또는 SERVER_ENCRYPT)\n${details}"
  else
    result_line "DB2-03" "양호" "인증 설정이 CLIENT로 고정되어 있지 않습니다.\n${details}"
  fi
fi

section "DB2-04" "DBM CFG 관리자 권한 그룹(SYSADM/SYSCTRL/SYSMAINT/SYSMON)" "상"
if echo "$dbm_cfg" | grep -qiE 'SQL1024N|SQLSTATE'; then
  result_line "DB2-04" "수동" "DBM CFG 미조회로 인해 수동 확인 필요"
else
  sysadm="$(echo "$dbm_cfg" | sed -n 's/.*SYSADM group name \(SYSADM_GROUP\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
  sysctrl="$(echo "$dbm_cfg" | sed -n 's/.*SYSCTRL group name \(SYSCTRL_GROUP\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
  sysmaint="$(echo "$dbm_cfg" | sed -n 's/.*SYSMAINT group name \(SYSMAINT_GROUP\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
  sysmon="$(echo "$dbm_cfg" | sed -n 's/.*SYSMON group name \(SYSMON_GROUP\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"

  details="SYSADM_GROUP=${sysadm:-'(미설정/공백)'}\nSYSCTRL_GROUP=${sysctrl:-'(미설정/공백)'}\nSYSMAINT_GROUP=${sysmaint:-'(미설정/공백)'}\nSYSMON_GROUP=${sysmon:-'(미설정/공백)'}"

  if [[ -z "$sysadm" || "$sysadm" == "NULL" ]]; then
    result_line "DB2-04" "주의" "SYSADM_GROUP 미설정(또는 NULL) 상태는 운영체제 관리자 그룹에 권한이 광범위하게 위임될 수 있습니다.\n${details}"
  else
    result_line "DB2-04" "양호" "관리자 권한 그룹이 지정되어 있습니다.\n${details}"
  fi
fi

section "DB2-05" "진단 로그 경로(DIAGPATH) 및 권한" "중"
if echo "$dbm_cfg" | grep -qiE 'SQL1024N|SQLSTATE'; then
  result_line "DB2-05" "수동" "DBM CFG 미조회로 인해 DIAGPATH 수동 확인 필요"
else
  diag="$(echo "$dbm_cfg" | sed -n 's/.*Diagnostic error capture path \(DIAGPATH\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
  if [[ -z "$diag" ]]; then
    result_line "DB2-05" "수동" "DIAGPATH 값을 찾지 못했습니다. 결과 파일의 DBM CFG 원문을 확인하세요."
  else
    perm="(경로 확인 실패)"
    if [[ -d "$diag" ]]; then
      perm="$(ls -ld "$diag" 2>/dev/null || true)"
    fi
    # Best-effort: world-writable check
    if [[ -d "$diag" ]] && (stat -c '%a' "$diag" 2>/dev/null | awk '($1 % 10) >= 2 {exit 0} {exit 1}' >/dev/null); then
      result_line "DB2-05" "취약" "진단 로그 경로가 Others 쓰기 권한을 가집니다.\nDIAGPATH=${diag}\n${perm}"
    else
      result_line "DB2-05" "양호" "진단 로그 경로 확인. (권고: 최소 권한)\nDIAGPATH=${diag}\n${perm}"
    fi
  fi
fi

section "DB2-06" "감사(Audit) 기능 활성화(db2audit)" "상"
if command -v db2audit >/dev/null 2>&1; then
  audit_status="$(db2audit status 2>&1 || true)"
  audit_desc="$(db2audit describe 2>&1 || true)"
  if echo "$audit_status" | grep -qi "Audit active"; then
    result_line "DB2-06" "양호" "db2audit 활성 상태로 확인됩니다.\n${audit_status}\n\n${audit_desc}"
  else
    result_line "DB2-06" "주의" "db2audit 비활성/미구성으로 보입니다. 정책에 따라 감사 활성화를 검토하세요.\n${audit_status}\n\n${audit_desc}"
  fi
else
  result_line "DB2-06" "수동" "db2audit 도구를 찾지 못했습니다. (Db2 감사 기능 구성 여부 수동 확인)"
fi

section "DB2-07" "DB CFG - 로그/백업 설정(선택)" "중"
if [[ -z "$DB_NAME" ]]; then
  result_line "DB2-07" "수동" "--db 미지정. 데이터베이스별 설정 점검을 생략했습니다."
else
  db_cfg="$(db2 -x "get db cfg for ${DB_NAME}" 2>&1 || true)"
  if echo "$db_cfg" | grep -qiE 'SQL1013N|SQL1024N|SQLSTATE'; then
    result_line "DB2-07" "수동" "DB CFG 조회 실패. DB명/권한/연결 상태를 확인하세요.\n${db_cfg}"
  else
    logarch="$(echo "$db_cfg" | sed -n 's/.*First log archive method \(LOGARCHMETH1\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
    recover="$(echo "$db_cfg" | sed -n 's/.*Log retain for recovery status \(LOGRETAIN\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
    details="LOGARCHMETH1=${logarch:-'(미검출)'}\nLOGRETAIN=${recover:-'(미검출)'}"

    if [[ -n "$logarch" ]] && echo "$logarch" | grep -qi '^OFF$'; then
      result_line "DB2-07" "주의" "로그 아카이빙이 OFF 입니다. (권고: 백업/복구/감사 요건에 따라 활성화)\n${details}"
    else
      result_line "DB2-07" "양호" "로그/복구 관련 설정을 확인했습니다.\n${details}"
    fi
  fi
fi

section "DB2-08" "네트워크 포트/서비스 노출(수동)" "중"
svcename="$(echo "$dbm_cfg" | sed -n 's/.*TCP/IP Service name \(SVCENAME\) = \(.*\)$/\1/p' | tail -n 1 | xargs || true)"
if [[ -n "$svcename" ]]; then
  result_line "DB2-08" "수동" "SVCENAME=${svcename}. 방화벽/보안그룹에서 인가된 대역만 허용하는지 확인하세요."
else
  result_line "DB2-08" "수동" "SVCENAME 값을 찾지 못했습니다. 네트워크 노출은 수동 확인 필요"
fi

echo "[INFO] 점검 완료. 결과 파일: $OUTFILE"
