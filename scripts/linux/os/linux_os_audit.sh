#!/usr/bin/env bash
# Linux/Unix OS security audit (standalone)
# Last update: 2026-01-10
# Intended baseline: Korean critical infra / cloud hardening checklists (operator-customizable)

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  linux_os_audit.sh --sw-id SW00001234 [--host HOSTNAME] [--out-dir DIR]

Notes:
  - Some checks require root privileges to read configs.
  - Output is a text report suited for evidence collection.
EOF
}

SW_ID=""
HOSTNAME_OVERRIDE=""
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --host) HOSTNAME_OVERRIDE="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$SW_ID" ]]; then
  echo "Missing --sw-id"; usage; exit 2
fi

HOSTNAME="${HOSTNAME_OVERRIDE:-$(hostname)}"
DATE="$(date +%Y%m%d_%H%M%S)"
GUIDE_VER="KR baseline (KCIS/KISA-style) + Cloud Guide 2024 (operator-tailored)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__LinuxOS__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section() {
  local id="$1" title="$2" severity="${3:-}"
  {
    echo ""
    echo "============================================================================"
    echo "[$id] $title"
    [[ -n "$severity" ]] && echo "위험도: $severity"
    echo "============================================================================"
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

{
  echo "############################################################################"
  echo "  Linux/Unix OS 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo ""
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

# U-01 root remote login
section "U-01" "SSH root 원격 접속 제한" "상"
SSHD_CFG="/etc/ssh/sshd_config"
if [[ -r "$SSHD_CFG" ]]; then
  append_cmd "현재 설정(관련 라인)" bash -lc "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)\b' -n $SSHD_CFG || true"
  if grep -Eq '^\s*PermitRootLogin\s+no\b' "$SSHD_CFG"; then
    result_line "U-01" "양호" "PermitRootLogin no 설정"
  else
    result_line "U-01" "취약" "PermitRootLogin no 미설정 (또는 주석/상속) - 운영 정책에 맞게 조정 필요"
  fi
else
  result_line "U-01" "수동" "sshd_config 읽기 불가(권한/미설치)."
fi

# U-02 password complexity
section "U-02" "패스워드 복잡도 정책" "상"
PWQ="/etc/security/pwquality.conf"
if [[ -r "$PWQ" ]]; then
  append_cmd "pwquality.conf" bash -lc "sed -n '1,200p' $PWQ"
  minlen="$(grep -E '^\s*minlen\s*=' "$PWQ" | tail -n1 | awk -F= '{gsub(/ /,\"\",$2); print $2}')"
  if [[ -n "${minlen:-}" && "${minlen:-0}" -ge 8 ]]; then
    result_line "U-02" "주의" "minlen=${minlen}. 추가 credit 규칙/사내 기준(영문/숫자/특수 포함) 확인 권고"
  else
    result_line "U-02" "취약" "minlen(최소 길이) 미설정 또는 8 미만"
  fi
else
  result_line "U-02" "수동" "pwquality.conf 읽기 불가. (PAM 설정: /etc/pam.d/* 확인 필요)"
fi

# U-03 account lockout
section "U-03" "계정 잠금(로그인 실패 임계값)" "상"
if [[ -r /etc/pam.d/system-auth ]]; then
  append_cmd "system-auth (faillock/tally)" bash -lc "grep -nE '(faillock|pam_tally2)\b' /etc/pam.d/system-auth || true"
elif [[ -r /etc/pam.d/common-auth ]]; then
  append_cmd "common-auth (faillock/tally)" bash -lc "grep -nE '(faillock|pam_tally2)\b' /etc/pam.d/common-auth || true"
fi

if grep -RqsE 'pam_faillock\.so.*deny=([1-5])\b' /etc/pam.d 2>/dev/null; then
  result_line "U-03" "양호" "pam_faillock deny<=5 설정 흔적 확인"
elif grep -RqsE 'pam_tally2\.so.*deny=([1-5])\b' /etc/pam.d 2>/dev/null; then
  result_line "U-03" "양호" "pam_tally2 deny<=5 설정 흔적 확인"
else
  result_line "U-03" "취약" "로그인 실패 잠금 정책(deny<=5) 확인 불가 - 배포판별 PAM 설정 점검 필요"
fi

# U-04 password max age
section "U-04" "패스워드 최대 사용기간" "상"
LOGIN_DEFS="/etc/login.defs"
if [[ -r "$LOGIN_DEFS" ]]; then
  append_cmd "login.defs (PASS_MAX_DAYS)" bash -lc "grep -nE '^\s*PASS_MAX_DAYS\b' $LOGIN_DEFS || true"
  max_days="$(grep -E '^\s*PASS_MAX_DAYS\b' "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)"
  if [[ -n "${max_days:-}" && "$max_days" =~ ^[0-9]+$ && "$max_days" -le 90 ]]; then
    result_line "U-04" "양호" "PASS_MAX_DAYS=${max_days} (<=90)"
  else
    result_line "U-04" "주의" "PASS_MAX_DAYS=${max_days:-N/A} (조직 기준에 맞게 설정 확인)"
  fi
else
  result_line "U-04" "수동" "login.defs 읽기 불가"
fi

# U-05 shadow permissions
section "U-05" "패스워드 파일 보호(/etc/shadow)" "상"
append_cmd "권한 확인" bash -lc "ls -l /etc/passwd /etc/shadow 2>/dev/null || true"
if [[ -e /etc/shadow ]]; then
  perm="$(stat -c %a /etc/shadow 2>/dev/null || echo "")"
  owner="$(stat -c %U /etc/shadow 2>/dev/null || echo "")"
  if [[ -n "$perm" && -n "$owner" && "$owner" == "root" && "$perm" -le 640 ]]; then
    result_line "U-05" "양호" "/etc/shadow owner=root, perm=${perm}"
  else
    result_line "U-05" "취약" "/etc/shadow 권한/소유자 점검 필요 (owner=${owner}, perm=${perm})"
  fi
else
  result_line "U-05" "취약" "/etc/shadow 미존재(비정상)"
fi

# U-06 uid 0
section "U-06" "root 외 UID=0 계정 금지" "상"
append_cmd "UID=0 계정" bash -lc "awk -F: '(\$3==0){print \$1\":\"\$3\":\"\$7}' /etc/passwd"
uid0_extra="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)"
if [[ -z "$uid0_extra" ]]; then
  result_line "U-06" "양호" "root 외 UID 0 없음"
else
  result_line "U-06" "취약" "root 외 UID 0 계정: ${uid0_extra}"
fi

# U-08 suid/sgid inventory
section "U-08" "SUID/SGID 파일 점검(목록화)" "상"
append_cmd "SUID/SGID 목록(상위 200)" bash -lc "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -n 200"
result_line "U-08" "수동" "SUID/SGID 목록 기반으로 불필요 바이너리 제거/권한 조정 검토"

# U-73 logging
section "U-73" "시스템 로깅 설정" "중"
if [[ -r /etc/rsyslog.conf ]]; then
  append_cmd "rsyslog.conf(주요 라인)" bash -lc "grep -vE '^\s*(#|$)' /etc/rsyslog.conf | head -n 200"
  if grep -qE '^\s*\*\.\*\s+/var/log/' /etc/rsyslog.conf; then
    result_line "U-73" "양호" "rsyslog 로그 대상 설정 확인"
  else
    result_line "U-73" "주의" "rsyslog에 /var/log 대상 설정이 명확하지 않음(배포판별 include 확인)"
  fi
elif command -v journalctl >/dev/null 2>&1; then
  append_cmd "journald 상태" bash -lc "journalctl --disk-usage; journalctl -u sshd -n 20 --no-pager"
  result_line "U-73" "주의" "systemd-journald 기반 로깅 사용. 영구 저장/전송(syslog/siem) 설정 확인 권고"
else
  result_line "U-73" "수동" "로깅 설정 확인 불가"
fi

echo "[INFO] 완료: $OUTFILE"
