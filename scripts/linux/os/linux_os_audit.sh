#!/usr/bin/env bash
# =============================================================================
# linux_os_audit.sh
# Linux/Unix OS 보안 취약점 점검 스크립트 (단독 실행)
# 기준: KISA/KCIS 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드(2021) +
#       클라우드 취약점 점검 가이드(2024) (공통 보안 하드닝 원칙 반영)
# Last update: 2026-01-10
#
# 출력: results/<SW_ID>__<HOST>__LinuxOS__<YYYYMMDD_HHMMSS>__result.txt
#
# 사용 예:
#   bash linux_os_audit.sh --sw-id SW00001234
#   bash linux_os_audit.sh --sw-id SW00001234 --out-dir /tmp/results
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + Cloud Guide 2024"
NOW="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"
OUT_DIR="results"
SW_ID=""

usage() {
  cat <<'USAGE'
Usage:
  linux_os_audit.sh --sw-id <SWID> [--out-dir <dir>] [--host <hostname>]

Options:
  --sw-id     업무관리번호 (예: SW00001234) (필수)
  --out-dir   결과 저장 디렉토리 (기본: ./results)
  --host      보고서에 기록할 호스트명 (기본: 현재 hostname)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id)   SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --host)    HOSTNAME_ACTUAL="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 2;;
  esac
done

if [ -z "${SW_ID}" ]; then
  echo "[ERROR] --sw-id is required"
  usage
  exit 2
fi

mkdir -p "${OUT_DIR}"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__LinuxOS__${NOW}__result.txt"

is_root() { [ "$(id -u 2>/dev/null || echo 9999)" -eq 0 ]; }

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
  # 콘솔 출력
  case "${res}" in
    *양호*) printf '[OK]   %s %s\n' "${id}" "${res}";;
    *취약*) printf '[VULN] %s %s\n' "${id}" "${res}";;
    *수동*) printf '[MAN]  %s %s\n' "${id}" "${res}";;
    *)      printf '[INFO] %s %s\n' "${id}" "${res}";;
  esac
}

kv() {
  local k="$1" v="${2:-}"
  append "- ${k}: ${v}"
}

file_mode_owner() {
  # prints: <mode> <owner> <group> or empty
  local f="$1"
  if [ -e "$f" ]; then
    stat -c '%a %U %G' "$f" 2>/dev/null || true
  fi
}

mode_leq() {
  # numeric compare of perms (e.g., 644 <= 644). If unknown => false
  local actual="$1" expected="$2"
  [ -n "${actual}" ] && [ "${actual}" -le "${expected}" ]
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

read_file_safe() {
  local f="$1"
  if [ -r "$f" ]; then
    sed -n '1,200p' "$f" 2>/dev/null || true
  else
    echo "(권한 부족 또는 파일 없음: $f)"
  fi
}

banner() {
  cat > "${OUTFILE}" <<EOF
############################################################################
  Linux/Unix OS 보안 취약점 점검 결과
  버전: ${SCRIPT_VER}
  기준: ${GUIDE_VER}
############################################################################
점검일시: $(date '+%Y-%m-%d %H:%M:%S')
점검대상: ${HOSTNAME_ACTUAL}
업무관리번호(SW ID): ${SW_ID}
실행계정: $(id -un 2>/dev/null || echo unknown)
OS: $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}" || uname -a)
############################################################################

EOF
  printf "Output: %s\n" "${OUTFILE}"
  printf "Running as root: %s\n" "$(is_root && echo yes || echo no)"
}

# Helper: check PAM config contains pattern across common locations
pam_contains() {
  local pattern="$1"
  local files=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
  )
  for f in "${files[@]}"; do
    if [ -r "$f" ] && grep -Eq "${pattern}" "$f"; then
      return 0
    fi
  done
  return 1
}

# Helper: get sshd effective config values if possible
sshd_effective() {
  local key="$1"
  if has_cmd sshd; then
    sshd -T 2>/dev/null | awk -v k="${key}" '$1==k{print $2}' | head -n 1
  fi
}

# =========================
# U-01 ~ U-73 Checks
# =========================

check_U_01() {
  section "U-01" "root 계정 원격 접속 제한(SSH)" "상"
  append "▶ 증적"
  if [ -f /etc/ssh/sshd_config ]; then
    kv "sshd_config(PermitRootLogin 관련)" ""
    grep -En '^\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | head -n 20 >> "${OUTFILE}" || true
  else
    append "- /etc/ssh/sshd_config 없음"
  fi
  local val
  val="$(sshd_effective permitrootlogin || true)"
  [ -n "$val" ] && kv "sshd -T permitrootlogin" "$val"
  if [ "$val" = "no" ] || grep -Eq '^\s*PermitRootLogin\s+no\b' /etc/ssh/sshd_config 2>/dev/null; then
    result_line "U-01" "양호 - PermitRootLogin no"
  else
    result_line "U-01" "취약 - root 원격 접속 차단 미확인(설정 점검 필요)" "권고: /etc/ssh/sshd_config에서 PermitRootLogin no 설정"
  fi
}

check_U_02() {
  section "U-02" "패스워드 복잡성 설정" "상"
  append "▶ 증적"
  if [ -f /etc/security/pwquality.conf ]; then
    kv "pwquality.conf(상단 200줄)" ""
    read_file_safe /etc/security/pwquality.conf >> "${OUTFILE}"
  else
    append "- /etc/security/pwquality.conf 없음(배포판/버전에 따라 PAM 모듈로만 관리될 수 있음)"
  fi
  local ok="0"
  if grep -Eq '^\s*minlen\s*=\s*(8|9|[1-9][0-9])\b' /etc/security/pwquality.conf 2>/dev/null; then
    ok="1"
  fi
  if pam_contains 'pam_pwquality\.so' || pam_contains 'pam_cracklib\.so'; then
    ok="1"
  fi
  if [ "$ok" = "1" ]; then
    result_line "U-02" "양호 - 복잡성 정책 설정 흔적 확인"
  else
    result_line "U-02" "취약 - 복잡성 정책 미확인" "권고: pam_pwquality/pwquality.conf로 최소 길이/문자조합 정책 적용"
  fi
}

check_U_03() {
  section "U-03" "계정 잠금 임계값(로그인 실패 제한)" "상"
  append "▶ 증적"
  for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
    if [ -f "$f" ]; then
      kv "PAM 파일" "$f"
      grep -En 'faillock|tally2|pam_faillock|pam_tally2' "$f" 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
    fi
  done
  if pam_contains 'pam_faillock\.so.*(deny=([1-5])\b|deny=5\b)' || pam_contains 'pam_tally2\.so.*deny=([1-5])\b'; then
    result_line "U-03" "양호 - 로그인 실패 잠금 정책(deny<=5) 확인"
  else
    result_line "U-03" "수동 점검 필요 - 배포판별 구현 상이" "권고: pam_faillock/pam_tally2로 deny=5 및 unlock_time 정책 적용"
  fi
}

check_U_04() {
  section "U-04" "패스워드 최대 사용 기간(90일 이하 권장)" "상"
  append "▶ 증적"
  if [ -f /etc/login.defs ]; then
    grep -En '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null >> "${OUTFILE}" || true
  fi
  local max_days
  max_days="$(awk '/^\s*PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null | head -n 1 || true)"
  if [ -n "$max_days" ] && [ "$max_days" -le 90 ]; then
    result_line "U-04" "양호 - PASS_MAX_DAYS ${max_days}"
  elif [ -n "$max_days" ]; then
    result_line "U-04" "취약 - PASS_MAX_DAYS ${max_days}(90 초과)" "권고: PASS_MAX_DAYS 90 이하로 설정"
  else
    result_line "U-04" "수동 점검 필요 - PASS_MAX_DAYS 미확인" "권고: /etc/login.defs 확인 및 사용자별 chage 설정 점검"
  fi
}

check_U_05() {
  section "U-05" "패스워드 파일(/etc/shadow) 보호" "상"
  append "▶ 증적"
  kv "ls -l /etc/passwd /etc/shadow" ""
  ls -l /etc/passwd /etc/shadow 2>/dev/null >> "${OUTFILE}" || true

  if ! is_root; then
    result_line "U-05" "수동 점검 필요 - root 권한 필요" "권고: root로 /etc/shadow 권한(통상 400 또는 000/640) 및 소유자 root 확인"
    return
  fi

  local st
  st="$(file_mode_owner /etc/shadow || true)"
  if [ -n "$st" ]; then
    local mode owner group
    mode="$(echo "$st" | awk '{print $1}')"
    owner="$(echo "$st" | awk '{print $2}')"
    group="$(echo "$st" | awk '{print $3}')"
    if mode_leq "$mode" 640 && [ "$owner" = "root" ]; then
      result_line "U-05" "양호 - /etc/shadow 권한 ${mode} ${owner}:${group}"
    else
      result_line "U-05" "취약 - /etc/shadow 권한/소유자 부적절(${mode} ${owner}:${group})"
    fi
  else
    result_line "U-05" "수동 점검 필요 - /etc/shadow 상태 확인 불가"
  fi
}

check_U_06() {
  section "U-06" "root 이외 UID 0 금지" "상"
  append "▶ 증적"
  awk -F: '($3==0){print $1":"$3":"$7}' /etc/passwd 2>/dev/null >> "${OUTFILE}" || true
  local others
  others="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ' || true)"
  if [ -z "$others" ]; then
    result_line "U-06" "양호 - root 외 UID 0 없음"
  else
    result_line "U-06" "취약 - root 외 UID 0 계정 존재: ${others}"
  fi
}

check_U_07() {
  section "U-07" "패스워드 최소 길이(8자 이상 권장)" "상"
  append "▶ 증적"
  if [ -f /etc/login.defs ]; then
    grep -En '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null >> "${OUTFILE}" || true
  fi
  local min_len
  min_len="$(awk '/^\s*PASS_MIN_LEN/{print $2}' /etc/login.defs 2>/dev/null | head -n 1 || true)"
  if [ -n "$min_len" ] && [ "$min_len" -ge 8 ]; then
    result_line "U-07" "양호 - PASS_MIN_LEN ${min_len}"
  elif [ -n "$min_len" ]; then
    result_line "U-07" "취약 - PASS_MIN_LEN ${min_len}(8 미만)" "권고: PASS_MIN_LEN 8 이상"
  else
    # fallback: pwquality minlen
    if grep -Eq '^\s*minlen\s*=\s*(8|9|[1-9][0-9])\b' /etc/security/pwquality.conf 2>/dev/null; then
      result_line "U-07" "양호 - pwquality minlen 설정 확인"
    else
      result_line "U-07" "수동 점검 필요 - 최소 길이 설정 미확인"
    fi
  fi
}

check_U_08() {
  section "U-08" "SUID/SGID 파일 점검" "상"
  append "▶ 증적(상위 200개)"
  # 성능/노이즈 절충: 루트(/) 전체 탐색은 시간이 매우 길 수 있음. 우선 /, /usr, /bin, /sbin 중심.
  local roots=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
  local tmp_list
  tmp_list="$(mktemp 2>/dev/null || echo /tmp/u08.$$)"
  : > "$tmp_list"
  for r in "${roots[@]}"; do
    if [ -d "$r" ]; then
      find "$r" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null >> "$tmp_list" || true
    fi
  done
  sort -u "$tmp_list" | head -n 200 >> "${OUTFILE}" || true
  local cnt
  cnt="$(sort -u "$tmp_list" | wc -l | awk '{print $1}')"
  rm -f "$tmp_list" 2>/dev/null || true
  if [ "$cnt" -eq 0 ]; then
    result_line "U-08" "양호 - 주요 경로에서 SUID/SGID 파일 없음"
  else
    result_line "U-08" "수동 점검 필요 - SUID/SGID 파일 ${cnt}개(표준 파일 제외 여부 검토)" \
      "권고: 불필요 SUID/SGID 제거 및 소유/권한 검토"
  fi
}

check_U_09() {
  section "U-09" "사용자 홈 디렉토리 권한(과도한 권한 금지)" "중"
  append "▶ 증적(로그인 가능 계정의 홈 디렉토리 권한)"
  awk -F: '($7!="/sbin/nologin" && $7!="/bin/false"){print $1":"$6":"$7}' /etc/passwd 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  # 자동 판정: 홈 디렉토리가 존재하며 others write 권한이 있는지
  local bad=0 user home
  while IFS=: read -r user home _shell; do
    [ -z "$home" ] && continue
    [ ! -d "$home" ] && continue
    local mode
    mode="$(stat -c '%a' "$home" 2>/dev/null || echo '')"
    if [ -n "$mode" ]; then
      # others write bit: mode % 10 >= 2? easier: use symbolic
      if [ -w "$home" ] && [ ! -O "$home" ]; then
        :
      fi
    fi
    # robust: check o+w via stat %A
    local sym
    sym="$(stat -c '%A' "$home" 2>/dev/null || echo '')"
    if echo "$sym" | grep -q '...w'; then
      bad=1
      kv "취약 후보" "${user} home=${home} perm=${sym}"
    fi
  done < <(awk -F: '($7!="/sbin/nologin" && $7!="/bin/false"){print $1":"$6":"$7}' /etc/passwd 2>/dev/null)
  if [ "$bad" -eq 0 ]; then
    result_line "U-09" "양호 - 홈 디렉토리 others write 미탐지"
  else
    result_line "U-09" "취약 - 홈 디렉토리 과도 권한(others write) 존재" "권고: 홈 디렉토리 권한 750~755 범위 권장(기관 정책 기준)"
  fi
}

check_U_10() {
  section "U-10" "/etc/passwd 파일 권한" "중"
  append "▶ 증적"
  ls -l /etc/passwd 2>/dev/null >> "${OUTFILE}" || true
  local st mode owner
  st="$(file_mode_owner /etc/passwd || true)"
  mode="$(echo "$st" | awk '{print $1}')"
  owner="$(echo "$st" | awk '{print $2}')"
  if [ -n "$mode" ] && mode_leq "$mode" 644 && [ "$owner" = "root" ]; then
    result_line "U-10" "양호 - /etc/passwd ${mode} owner=${owner}"
  else
    result_line "U-10" "취약 - /etc/passwd 권한/소유자 부적절(${st})"
  fi
}

check_U_11() {
  section "U-11" "/etc/shadow 파일 권한" "중"
  append "▶ 증적"
  ls -l /etc/shadow 2>/dev/null >> "${OUTFILE}" || true
  if ! is_root; then
    result_line "U-11" "수동 점검 필요 - root 권한 필요"
    return
  fi
  local st mode owner
  st="$(file_mode_owner /etc/shadow || true)"
  mode="$(echo "$st" | awk '{print $1}')"
  owner="$(echo "$st" | awk '{print $2}')"
  if [ -n "$mode" ] && mode_leq "$mode" 640 && [ "$owner" = "root" ]; then
    result_line "U-11" "양호 - /etc/shadow ${mode} owner=${owner}"
  else
    result_line "U-11" "취약 - /etc/shadow 권한/소유자 부적절(${st})"
  fi
}

check_U_12() {
  section "U-12" "/etc/hosts 파일 권한" "하"
  append "▶ 증적"
  ls -l /etc/hosts 2>/dev/null >> "${OUTFILE}" || true
  local st mode owner
  st="$(file_mode_owner /etc/hosts || true)"
  mode="$(echo "$st" | awk '{print $1}')"
  owner="$(echo "$st" | awk '{print $2}')"
  if [ -z "$mode" ]; then
    result_line "U-12" "수동 점검 필요 - /etc/hosts 확인 불가"
  elif mode_leq "$mode" 644 && [ "$owner" = "root" ]; then
    result_line "U-12" "양호"
  else
    result_line "U-12" "취약 - /etc/hosts 권한/소유자 부적절(${st})"
  fi
}

check_U_13() {
  section "U-13" "신뢰관계 파일(hosts.equiv/shosts.equiv) 사용 제한" "상"
  append "▶ 증적"
  for f in /etc/hosts.equiv /etc/shosts.equiv; do
    if [ -f "$f" ]; then
      kv "파일 존재" "$f"
      ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
      read_file_safe "$f" >> "${OUTFILE}"
    fi
  done
  if [ -f /etc/hosts.equiv ] || [ -f /etc/shosts.equiv ]; then
    result_line "U-13" "취약 - 신뢰관계 파일 존재" "권고: 사용 불필요 시 삭제 또는 내용 최소화"
  else
    result_line "U-13" "양호 - 신뢰관계 파일 미존재"
  fi
}

check_U_14() {
  section "U-14" "사용자 rhosts 파일(.rhosts/.shosts) 제거" "상"
  append "▶ 증적(상위 50개)"
  local found
  found="$(find /home /root -maxdepth 3 -type f \( -name '.rhosts' -o -name '.shosts' \) 2>/dev/null | head -n 50 || true)"
  if [ -n "$found" ]; then
    append "$found"
    result_line "U-14" "취약 - rhosts/shosts 파일 존재" "권고: 신뢰 기반 인증 제거"
  else
    result_line "U-14" "양호 - 미탐지"
  fi
}

check_U_15() {
  section "U-15" "inetd/xinetd 서비스 점검(불필요 서비스 비활성)" "상"
  append "▶ 증적"
  if has_cmd systemctl; then
    systemctl list-unit-files 2>/dev/null | grep -E '^(xinetd|inetd)\.service' | head -n 20 >> "${OUTFILE}" || true
    systemctl is-enabled xinetd 2>/dev/null >> "${OUTFILE}" || true
  fi
  if [ -d /etc/xinetd.d ]; then
    kv "/etc/xinetd.d" "존재"
    ls -l /etc/xinetd.d 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  fi
  if (has_cmd systemctl && systemctl is-active xinetd >/dev/null 2>&1) || [ -f /etc/inetd.conf ]; then
    result_line "U-15" "수동 점검 필요 - inetd/xinetd 구성 확인" "권고: 사용하지 않는 legacy 네트워크 서비스 비활성화"
  else
    result_line "U-15" "양호 - inetd/xinetd 미사용(추정)"
  fi
}

check_U_16() {
  section "U-16" "PATH 환경변수에 '.' 포함 금지" "중"
  append "▶ 증적"
  kv "현재 PATH" "${PATH}"
  if echo "${PATH}" | grep -Eq '(^|:)\.(:|$)'; then
    result_line "U-16" "취약 - PATH에 '.' 포함" "권고: /etc/profile, ~/.profile 등에서 '.' 제거"
  else
    result_line "U-16" "양호"
  fi
}

check_U_17() {
  section "U-17" "기본 umask 설정(027 또는 022 등 정책)" "중"
  append "▶ 증적"
  if [ -f /etc/profile ]; then
    kv "/etc/profile umask" ""
    grep -En '^\s*umask\s+' /etc/profile 2>/dev/null | head -n 20 >> "${OUTFILE}" || true
  fi
  local u
  u="$(umask)"
  kv "현재 umask" "$u"
  # 기관 정책별 상이: 최소 권고로 022(일반) 또는 027(강화)
  if [ "$u" = "0022" ] || [ "$u" = "022" ] || [ "$u" = "0027" ] || [ "$u" = "027" ]; then
    result_line "U-17" "양호 - umask=${u}"
  else
    result_line "U-17" "수동 점검 필요 - umask=${u}(기관 정책 확인)" "권고: 서비스 계정/시스템 정책에 맞는 umask 적용"
  fi
}

check_U_18() {
  section "U-18" "/etc/securetty 설정(콘솔 root 로그인 제한)" "중"
  append "▶ 증적"
  if [ -f /etc/securetty ]; then
    read_file_safe /etc/securetty >> "${OUTFILE}"
    result_line "U-18" "수동 점검 필요 - securetty 허용 TTY 검토" "권고: 불필요 TTY 제거"
  else
    result_line "U-18" "정보 - /etc/securetty 없음(배포판/구성에 따라 다름)"
  fi
}

check_U_19() {
  section "U-19" "TCP Wrapper(hosts.allow/hosts.deny) 설정" "하"
  append "▶ 증적"
  for f in /etc/hosts.allow /etc/hosts.deny; do
    if [ -f "$f" ]; then
      kv "파일" "$f"
      read_file_safe "$f" >> "${OUTFILE}"
    else
      kv "파일" "$f (없음)"
    fi
  done
  # 현대 배포판은 firewalld/iptables가 주류. 존재 여부만으로 자동판정 곤란.
  result_line "U-19" "수동 점검 필요 - 운영 환경(방화벽) 기준으로 판단"
}

check_U_20() {
  section "U-20" "NFS 서비스 사용 제한" "상"
  append "▶ 증적"
  if has_cmd systemctl; then
    systemctl is-active nfs-server 2>/dev/null >> "${OUTFILE}" || true
    systemctl is-enabled nfs-server 2>/dev/null >> "${OUTFILE}" || true
  fi
  if [ -f /etc/exports ]; then
    kv "/etc/exports" "존재"
    read_file_safe /etc/exports >> "${OUTFILE}"
  fi
  if (has_cmd systemctl && systemctl is-active nfs-server >/dev/null 2>&1) || [ -f /etc/exports ]; then
    result_line "U-20" "수동 점검 필요 - NFS 사용 시 export 범위/옵션 점검" "권고: 최소 공유, root_squash, 접근 IP 제한"
  else
    result_line "U-20" "양호 - NFS 미사용(추정)"
  fi
}

check_U_21() {
  section "U-21" "RPC 서비스 사용 제한" "중"
  append "▶ 증적"
  if has_cmd rpcinfo; then
    rpcinfo -p 127.0.0.1 2>/dev/null | head -n 100 >> "${OUTFILE}" || true
  else
    append "- rpcinfo 명령 없음"
  fi
  # RPC는 NFS 등 필요 서비스에 종속. 자동 판정은 곤란.
  result_line "U-21" "수동 점검 필요 - RPC 노출 서비스(특히 111/tcp) 관리 필요"
}

check_U_22() {
  section "U-22" "r-계열 서비스(rsh/rlogin/rexec) 비활성화" "상"
  append "▶ 증적"
  if has_cmd systemctl; then
    systemctl list-unit-files 2>/dev/null | grep -E 'rsh|rlogin|rexec' | head -n 50 >> "${OUTFILE}" || true
  fi
  if has_cmd ss; then
    ss -lntp 2>/dev/null | grep -E '(:513|:514|:512)\b' >> "${OUTFILE}" || true
  fi
  # 흔히 기본 비활성. 포트 리슨 시 취약으로 판단.
  if has_cmd ss && ss -lnt 2>/dev/null | grep -Eq ':(512|513|514)\b'; then
    result_line "U-22" "취약 - r-계열 포트 리슨 탐지(512/513/514)"
  else
    result_line "U-22" "양호 - 리슨 미탐지"
  fi
}

check_U_23() {
  section "U-23" "Telnet 서비스 비활성화" "상"
  append "▶ 증적"
  if has_cmd ss; then
    ss -lntp 2>/dev/null | grep -E '(:23)\b' >> "${OUTFILE}" || true
  fi
  if has_cmd systemctl; then
    systemctl list-unit-files 2>/dev/null | grep -E 'telnet\.|telnet@' | head -n 20 >> "${OUTFILE}" || true
  fi
  if has_cmd ss && ss -lnt 2>/dev/null | grep -Eq '(:23)\b'; then
    result_line "U-23" "취약 - Telnet 포트(23) 리슨"
  else
    result_line "U-23" "양호 - Telnet 리슨 미탐지"
  fi
}

check_U_24() {
  section "U-24" "FTP 서비스 사용 제한(특히 Anonymous)" "상"
  append "▶ 증적"
  if has_cmd ss; then
    ss -lntp 2>/dev/null | grep -E '(:21)\b' >> "${OUTFILE}" || true
  fi
  # vsftpd 설정 점검
  if [ -f /etc/vsftpd/vsftpd.conf ]; then
    kv "vsftpd.conf(anonymous_enable)" ""
    grep -En '^\s*anonymous_enable' /etc/vsftpd/vsftpd.conf 2>/dev/null >> "${OUTFILE}" || true
    if grep -Eq '^\s*anonymous_enable\s*=\s*YES\b' /etc/vsftpd/vsftpd.conf 2>/dev/null; then
      result_line "U-24" "취약 - Anonymous FTP 활성화"
      return
    fi
  fi
  # 리슨이면 수동
  if has_cmd ss && ss -lnt 2>/dev/null | grep -Eq '(:21)\b'; then
    result_line "U-24" "수동 점검 필요 - FTP 사용 시 계정/익명/암호화(FTPS) 정책 점검"
  else
    result_line "U-24" "양호 - FTP 리슨 미탐지(또는 Anonymous 비활성)"
  fi
}

check_U_25() {
  section "U-25" "TFTP/Talk/Finger 등 불필요 서비스 비활성화" "중"
  append "▶ 증적(대표 포트: 69/79/517/518)"
  if has_cmd ss; then
    ss -lntup 2>/dev/null | grep -E ':(69|79|517|518)\b' >> "${OUTFILE}" || true
  fi
  if has_cmd ss && ss -lntup 2>/dev/null | grep -Eq ':(69|79|517|518)\b'; then
    result_line "U-25" "취약 - 불필요 서비스 포트 리슨 탐지"
  else
    result_line "U-25" "양호 - 리슨 미탐지"
  fi
}

check_U_26() {
  section "U-26" "SNMP 설정(기본 Community 사용 금지)" "중"
  append "▶ 증적"
  if [ -f /etc/snmp/snmpd.conf ]; then
    grep -En 'community|rocommunity|rwcommunity' /etc/snmp/snmpd.conf 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
    if grep -Eq '^\s*(rocommunity|rwcommunity)\s+(public|private)\b' /etc/snmp/snmpd.conf 2>/dev/null; then
      result_line "U-26" "취약 - 기본 Community(public/private) 사용"
    else
      result_line "U-26" "수동 점검 필요 - SNMP 사용 시 Community/ACL/TLS 등 점검"
    fi
  else
    result_line "U-26" "양호 - snmpd.conf 미존재(미사용 추정)"
  fi
}

check_U_27() {
  section "U-27" "NTP/시간 동기화 설정" "중"
  append "▶ 증적"
  if has_cmd timedatectl; then
    timedatectl 2>/dev/null >> "${OUTFILE}" || true
  fi
  if has_cmd chronyc; then
    chronyc sources 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  elif has_cmd ntpq; then
    ntpq -p 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  fi
  # 자동 판정은 곤란. 동기화 상태가 yes이면 양호.
  if has_cmd timedatectl && timedatectl 2>/dev/null | grep -Eq 'System clock synchronized:\s*yes'; then
    result_line "U-27" "양호 - 시간 동기화 활성"
  else
    result_line "U-27" "수동 점검 필요 - 시간 동기화 상태 확인 권고"
  fi
}

check_U_28() {
  section "U-28" "계정/패스워드 정책(PASS_WARN_AGE 등) 설정" "하"
  append "▶ 증적"
  if [ -f /etc/login.defs ]; then
    grep -En '^\s*PASS_(WARN_AGE|MIN_DAYS|MAX_DAYS|MIN_LEN)' /etc/login.defs 2>/dev/null >> "${OUTFILE}" || true
    result_line "U-28" "수동 점검 필요 - 기관 정책에 따라 값 검토"
  else
    result_line "U-28" "수동 점검 필요 - /etc/login.defs 미존재/접근 불가"
  fi
}

check_U_29() {
  section "U-29" "불필요한 시스템 계정 쉘 제한" "중"
  append "▶ 증적(/etc/passwd shell 목록 상위 200)"
  awk -F: '{print $1":"$7}' /etc/passwd 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  local bad
  bad="$(awk -F: '($1!~/^(root)$/ && $7!~/^(\/sbin\/nologin|\/bin\/false)$/ && $1~/^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|operator|proxy|www-data|apache|nginx)$/){print $1":"$7}' /etc/passwd 2>/dev/null | head -n 50 || true)"
  if [ -n "$bad" ]; then
    append ""
    append "취약 후보(시스템 계정이 로그인 쉘 보유):"
    append "$bad"
    result_line "U-29" "수동 점검 필요 - 시스템 계정 로그인 가능 여부 검토"
  else
    result_line "U-29" "양호 - 대표 시스템 계정의 쉘 제한(추정)"
  fi
}

check_U_30() {
  section "U-30" "사용자 계정 잠금/휴면 관리(미사용 계정)" "중"
  append "▶ 증적(최근 로그인/잠금 상태는 조직 정책/AD 연동 등 영향)"
  if has_cmd lastlog; then
    lastlog 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  else
    append "- lastlog 없음"
  fi
  result_line "U-30" "수동 점검 필요 - 미사용/휴면 계정 잠금 정책 확인"
}

check_U_31() {
  section "U-31" "불필요한 계정 제거" "중"
  append "▶ 증적(UID>=1000 계정 목록)"
  awk -F: '($3>=1000 && $1!="nobody"){print $1":"$3":"$6":"$7}' /etc/passwd 2>/dev/null >> "${OUTFILE}" || true
  result_line "U-31" "수동 점검 필요 - 계정 현황과 업무 필요성 대조"
}

check_U_32() {
  section "U-32" "su 명령 제한(wheel 그룹 등)" "상"
  append "▶ 증적"
  for f in /etc/pam.d/su /etc/pam.d/su-l; do
    if [ -f "$f" ]; then
      kv "PAM" "$f"
      grep -En 'pam_wheel\.so' "$f" 2>/dev/null >> "${OUTFILE}" || true
    fi
  done
  if grep -Eq 'pam_wheel\.so' /etc/pam.d/su 2>/dev/null; then
    result_line "U-32" "양호 - pam_wheel 적용"
  else
    result_line "U-32" "수동 점검 필요 - su 제한 미확인" "권고: pam_wheel 적용 또는 sudo로 대체"
  fi
}

check_U_33() {
  section "U-33" "sudo 권한 관리(최소권한)" "상"
  append "▶ 증적(/etc/sudoers 및 /etc/sudoers.d)"
  if [ -f /etc/sudoers ]; then
    grep -En '^(%|[^#]).*ALL' /etc/sudoers 2>/dev/null | head -n 100 >> "${OUTFILE}" || true
  fi
  if [ -d /etc/sudoers.d ]; then
    ls -l /etc/sudoers.d 2>/dev/null >> "${OUTFILE}" || true
    for f in /etc/sudoers.d/*; do
      [ -f "$f" ] || continue
      kv "sudoers.d 파일" "$f"
      grep -En '^(%|[^#]).*ALL' "$f" 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
    done
  fi
  result_line "U-33" "수동 점검 필요 - 과도 권한(NOPASSWD/ALL) 여부 검토"
}

check_U_34() {
  section "U-34" "Cron 권한(관련 파일/디렉토리)" "중"
  append "▶ 증적"
  for f in /etc/crontab /etc/cron.allow /etc/cron.deny; do
    [ -e "$f" ] && ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
  done
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] && ls -ld "$d" 2>/dev/null >> "${OUTFILE}" || true
  done
  result_line "U-34" "수동 점검 필요 - cron 접근통제/권한 검토"
}

check_U_35() {
  section "U-35" "at 서비스 권한(at.allow/at.deny)" "하"
  append "▶ 증적"
  for f in /etc/at.allow /etc/at.deny; do
    [ -e "$f" ] && ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
  done
  result_line "U-35" "수동 점검 필요 - at 사용 시 접근제어 파일 검토"
}

check_U_36() {
  section "U-36" "시스템 중요 파일 권한(/etc/* 주요 설정)" "중"
  append "▶ 증적"
  for f in /etc/services /etc/inetd.conf /etc/xinetd.conf /etc/ssh/sshd_config /etc/sysctl.conf; do
    [ -e "$f" ] && ls -l "$f" 2>/dev/null >> "${OUTFILE}" || true
  done
  result_line "U-36" "수동 점검 필요 - 과도 권한 및 소유자(root) 확인"
}

check_U_37() {
  section "U-37" "World writable 파일 점검(주요 경로)" "중"
  append "▶ 증적(상위 200개)"
  local tmp
  tmp="$(mktemp 2>/dev/null || echo /tmp/u37.$$)"
  : > "$tmp"
  for r in /etc /var /usr /home; do
    [ -d "$r" ] || continue
    find "$r" -xdev -type f -perm -0002 2>/dev/null >> "$tmp" || true
  done
  sort -u "$tmp" | head -n 200 >> "${OUTFILE}" || true
  local cnt
  cnt="$(sort -u "$tmp" | wc -l | awk '{print $1}')"
  rm -f "$tmp" 2>/dev/null || true
  if [ "$cnt" -eq 0 ]; then
    result_line "U-37" "양호 - 주요 경로에서 world writable 파일 미탐지"
  else
    result_line "U-37" "수동 점검 필요 - world writable 파일 ${cnt}개(업무 필요성/위험도 검토)"
  fi
}

check_U_38() {
  section "U-38" "로그인 배너(/etc/issue, /etc/motd) 설정" "하"
  append "▶ 증적"
  for f in /etc/issue /etc/issue.net /etc/motd; do
    if [ -f "$f" ]; then
      kv "파일" "$f"
      read_file_safe "$f" >> "${OUTFILE}"
    fi
  done
  result_line "U-38" "수동 점검 필요 - 경고문구(법적 고지) 적용 여부 확인"
}

check_U_39() {
  section "U-39" "SSH 보안 설정(빈 패스워드/X11 포워딩 등)" "상"
  append "▶ 증적(sshd -T 일부)"
  if has_cmd sshd; then
    sshd -T 2>/dev/null | grep -E '^(permitemptypasswords|x11forwarding|allowtcpforwarding|clientaliveinterval|clientalivecountmax|passwordauthentication|pubkeyauthentication|ciphers|macs|kexalgorithms)\b' >> "${OUTFILE}" || true
  else
    append "- sshd 명령 없음"
  fi
  local empty
  empty="$(sshd_effective permitemptypasswords || true)"
  if [ "$empty" = "no" ] || grep -Eq '^\s*PermitEmptyPasswords\s+no\b' /etc/ssh/sshd_config 2>/dev/null; then
    result_line "U-39" "양호 - PermitEmptyPasswords no(추정)"
  else
    result_line "U-39" "수동 점검 필요 - SSH 세부 정책 검토 필요"
  fi
}

check_U_40() {
  section "U-40" "SSH 접근제어(AllowUsers/AllowGroups 등)" "중"
  append "▶ 증적"
  if [ -f /etc/ssh/sshd_config ]; then
    grep -En '^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\b' /etc/ssh/sshd_config 2>/dev/null >> "${OUTFILE}" || true
  fi
  result_line "U-40" "수동 점검 필요 - 운영 정책에 따라 접근제어 적용 여부 판단"
}

check_U_41() {
  section "U-41" "SSH 프로토콜/암호화(TLS/강한 알고리즘)" "중"
  append "▶ 증적"
  if has_cmd sshd; then
    sshd -T 2>/dev/null | grep -E '^(protocol|ciphers|macs|kexalgorithms)\b' >> "${OUTFILE}" || true
  fi
  result_line "U-41" "수동 점검 필요 - 조직 표준 암호군/정책과 비교"
}

check_U_42() {
  section "U-42" "서비스 포트 노출 현황(기본 점검)" "중"
  append "▶ 증적(listen ports)"
  if has_cmd ss; then
    ss -lntup 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
    result_line "U-42" "수동 점검 필요 - 불필요 포트/서비스 차단 여부 검토"
  elif has_cmd netstat; then
    netstat -lntup 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
    result_line "U-42" "수동 점검 필요 - 불필요 포트/서비스 차단 여부 검토"
  else
    result_line "U-42" "수동 점검 필요 - ss/netstat 도구 없음"
  fi
}

check_U_43() {
  section "U-43" "호스트 기반 방화벽(iptables/nftables/firewalld) 설정" "상"
  append "▶ 증적"
  if has_cmd firewall-cmd; then
    firewall-cmd --state 2>/dev/null >> "${OUTFILE}" || true
    firewall-cmd --list-all --zone=public 2>/dev/null >> "${OUTFILE}" || true
    if firewall-cmd --state 2>/dev/null | grep -q running; then
      result_line "U-43" "양호 - firewalld running"
    else
      result_line "U-43" "수동 점검 필요 - firewalld 상태 확인"
    fi
    return
  fi
  if has_cmd nft; then
    nft list ruleset 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
    result_line "U-43" "수동 점검 필요 - nftables 규칙 검토"
    return
  fi
  if has_cmd iptables; then
    iptables -S 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
    result_line "U-43" "수동 점검 필요 - iptables 규칙 검토"
    return
  fi
  result_line "U-43" "수동 점검 필요 - 방화벽 도구 미확인"
}

check_U_44() {
  section "U-44" "IP Spoofing 방지(sysctl rp_filter 등)" "중"
  append "▶ 증적"
  if has_cmd sysctl; then
    sysctl net.ipv4.conf.all.rp_filter 2>/dev/null >> "${OUTFILE}" || true
    sysctl net.ipv4.conf.default.rp_filter 2>/dev/null >> "${OUTFILE}" || true
  fi
  local v
  v="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo '')"
  if [ "$v" = "1" ] || [ "$v" = "2" ]; then
    result_line "U-44" "양호 - rp_filter=${v}"
  else
    result_line "U-44" "수동 점검 필요 - rp_filter 미설정/확인 불가"
  fi
}

check_U_45() {
  section "U-45" "ICMP Redirect 비활성화" "하"
  append "▶ 증적"
  if has_cmd sysctl; then
    sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null >> "${OUTFILE}" || true
    sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null >> "${OUTFILE}" || true
  fi
  local v
  v="$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo '')"
  if [ "$v" = "0" ]; then
    result_line "U-45" "양호"
  else
    result_line "U-45" "수동 점검 필요 - accept_redirects 값 검토"
  fi
}

check_U_46() {
  section "U-46" "IP Source Routing 비활성화" "하"
  append "▶ 증적"
  if has_cmd sysctl; then
    sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null >> "${OUTFILE}" || true
    sysctl net.ipv4.conf.default.accept_source_route 2>/dev/null >> "${OUTFILE}" || true
  fi
  local v
  v="$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo '')"
  if [ "$v" = "0" ]; then
    result_line "U-46" "양호"
  else
    result_line "U-46" "수동 점검 필요 - accept_source_route 값 검토"
  fi
}

check_U_47() {
  section "U-47" "불필요 커널 모듈/패킷 포워딩(ip_forward) 점검" "하"
  append "▶ 증적"
  if has_cmd sysctl; then
    sysctl net.ipv4.ip_forward 2>/dev/null >> "${OUTFILE}" || true
  fi
  local v
  v="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '')"
  if [ "$v" = "0" ]; then
    result_line "U-47" "양호 - ip_forward=0"
  else
    result_line "U-47" "수동 점검 필요 - 라우팅 필요 여부에 따라 판단(ip_forward=${v})"
  fi
}

check_U_48() {
  section "U-48" "DNS 설정 점검(불필요 노출/재귀 등)" "하"
  append "▶ 증적"
  if [ -f /etc/resolv.conf ]; then
    read_file_safe /etc/resolv.conf >> "${OUTFILE}"
  fi
  # BIND 사용 시 named.conf 점검 필요
  if [ -f /etc/named.conf ] || [ -d /etc/bind ]; then
    result_line "U-48" "수동 점검 필요 - DNS 서버 운영 시 재귀/zone transfer 제한 확인"
  else
    result_line "U-48" "정보 - DNS 서버 구성 미확인(클라이언트 설정만 확인)"
  fi
}

check_U_49() {
  section "U-49" "SMTP 서비스 릴레이 제한(운영 시)" "중"
  append "▶ 증적"
  if has_cmd ss && ss -lnt 2>/dev/null | grep -Eq '(:25)\b'; then
    ss -lntp 2>/dev/null | grep -E '(:25)\b' >> "${OUTFILE}" || true
    result_line "U-49" "수동 점검 필요 - SMTP 운영 시 open relay 금지 설정 확인"
  else
    result_line "U-49" "정보 - SMTP 리슨 미탐지"
  fi
}

check_U_50() {
  section "U-50" "웹/애플리케이션 계정 분리(서비스 계정 최소권한)" "중"
  append "▶ 증적(대표 서비스 계정 존재 여부)"
  awk -F: '($1~/^(apache|httpd|nginx|tomcat|www-data)$/){print $1":"$3":"$6":"$7}' /etc/passwd 2>/dev/null >> "${OUTFILE}" || true
  result_line "U-50" "수동 점검 필요 - 서비스 프로세스 계정/권한 분리 여부 검토"
}

check_U_51() {
  section "U-51" "웹 루트/서비스 디렉토리 권한(과도 권한 금지)" "중"
  append "▶ 증적(대표 경로 존재 시)"
  for d in /var/www /usr/share/nginx/html /srv/www /opt/tomcat /var/lib/tomcat; do
    if [ -d "$d" ]; then
      kv "디렉토리" "$d"
      ls -ld "$d" 2>/dev/null >> "${OUTFILE}" || true
    fi
  done
  result_line "U-51" "수동 점검 필요 - 운영 경로 기준으로 쓰기 권한 최소화"
}

check_U_52() {
  section "U-52" "/tmp, /var/tmp 마운트 옵션(noexec,nosuid,nodev) 점검" "중"
  append "▶ 증적(mount)"
  mount 2>/dev/null | grep -E ' on /(tmp|var/tmp) ' >> "${OUTFILE}" || true
  # 자동 판정: 옵션 포함 여부
  local m
  m="$(mount 2>/dev/null | grep -E ' on /tmp ' | head -n 1 || true)"
  if [ -n "$m" ] && echo "$m" | grep -q 'noexec' && echo "$m" | grep -q 'nosuid' && echo "$m" | grep -q 'nodev'; then
    result_line "U-52" "양호 - /tmp noexec,nosuid,nodev"
  else
    result_line "U-52" "수동 점검 필요 - /tmp 마운트 옵션 정책 검토"
  fi
}

check_U_53() {
  section "U-53" "Core dump 제한" "하"
  append "▶ 증적"
  ulimit -a 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  if [ -f /etc/security/limits.conf ]; then
    grep -En 'core' /etc/security/limits.conf 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  fi
  result_line "U-53" "수동 점검 필요 - core 파일 생성 제한 정책 확인"
}

check_U_54() {
  section "U-54" "로그인 세션 타임아웃(TMOUT) 설정" "하"
  append "▶ 증적"
  if [ -f /etc/profile ]; then
    grep -En '^\s*TMOUT=' /etc/profile 2>/dev/null >> "${OUTFILE}" || true
  fi
  if env | grep -q '^TMOUT='; then
    kv "현재 TMOUT" "$(env | grep '^TMOUT=' | head -n 1)"
  fi
  result_line "U-54" "수동 점검 필요 - TMOUT 정책(예: 600초) 적용 여부 확인"
}

check_U_55() {
  section "U-55" "권한 상승 파일/디렉토리 권한(예: /etc/sudoers)" "중"
  append "▶ 증적"
  ls -l /etc/sudoers 2>/dev/null >> "${OUTFILE}" || true
  if [ -d /etc/sudoers.d ]; then
    ls -l /etc/sudoers.d 2>/dev/null >> "${OUTFILE}" || true
  fi
  result_line "U-55" "수동 점검 필요 - sudoers 권한(0440) 및 변경 통제 확인"
}

check_U_56() {
  section "U-56" "로그 감사(auditd) 활성화" "중"
  append "▶ 증적"
  if has_cmd systemctl; then
    systemctl is-active auditd 2>/dev/null >> "${OUTFILE}" || true
    systemctl is-enabled auditd 2>/dev/null >> "${OUTFILE}" || true
  fi
  if has_cmd auditctl; then
    auditctl -s 2>/dev/null >> "${OUTFILE}" || true
  fi
  if has_cmd systemctl && systemctl is-active auditd >/dev/null 2>&1; then
    result_line "U-56" "양호 - auditd active"
  else
    result_line "U-56" "수동 점검 필요 - auditd 미확인(환경에 따라 선택)" "권고: 중요 시스템은 auditd 기반 감사 권장"
  fi
}

check_U_57() {
  section "U-57" "보안 패치 적용(커널/패키지 최신화)" "상"
  append "▶ 증적"
  uname -a 2>/dev/null >> "${OUTFILE}" || true
  if has_cmd apt; then
    apt -s upgrade 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
    result_line "U-57" "수동 점검 필요 - apt 기반 업데이트 필요 패키지 확인"
  elif has_cmd yum; then
    yum check-update 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
    result_line "U-57" "수동 점검 필요 - yum 기반 업데이트 필요 패키지 확인"
  elif has_cmd dnf; then
    dnf check-update 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
    result_line "U-57" "수동 점검 필요 - dnf 기반 업데이트 필요 패키지 확인"
  else
    result_line "U-57" "수동 점검 필요 - 패키지 관리자 확인 필요"
  fi
}

check_U_58() {
  section "U-58" "SELinux/AppArmor 적용" "중"
  append "▶ 증적"
  if has_cmd getenforce; then
    getenforce 2>/dev/null >> "${OUTFILE}" || true
    local st
    st="$(getenforce 2>/dev/null || true)"
    if [ "$st" = "Enforcing" ]; then
      result_line "U-58" "양호 - SELinux Enforcing"
    else
      result_line "U-58" "수동 점검 필요 - SELinux 상태=${st}"
    fi
    return
  fi
  if has_cmd aa-status; then
    aa-status 2>/dev/null | head -n 80 >> "${OUTFILE}" || true
    result_line "U-58" "수동 점검 필요 - AppArmor 상태 확인"
    return
  fi
  result_line "U-58" "정보 - SELinux/AppArmor 도구 미확인"
}

check_U_59() {
  section "U-59" "원격 로그 수집(syslog 원격 전송 등)" "중"
  append "▶ 증적"
  if [ -f /etc/rsyslog.conf ]; then
    grep -En '^\s*\*\.\*|@{1,2}' /etc/rsyslog.conf 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  fi
  result_line "U-59" "수동 점검 필요 - 중앙 로그 수집/보관 정책 확인"
}

check_U_60() {
  section "U-60" "로그 파일 권한/소유자(과도 권한 금지)" "중"
  append "▶ 증적(/var/log 상위 50)"
  ls -l /var/log 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  result_line "U-60" "수동 점검 필요 - 민감 로그 파일 권한 최소화"
}

check_U_61() {
  section "U-61" "로그 로테이션(logrotate) 설정" "하"
  append "▶ 증적"
  if [ -f /etc/logrotate.conf ]; then
    read_file_safe /etc/logrotate.conf >> "${OUTFILE}"
  fi
  if [ -d /etc/logrotate.d ]; then
    ls -l /etc/logrotate.d 2>/dev/null | head -n 50 >> "${OUTFILE}" || true
  fi
  result_line "U-61" "수동 점검 필요 - 로그 보관/삭제 정책 준수 여부 확인"
}

check_U_62() {
  section "U-62" "서비스 계정 비밀번호/로그인 제한" "중"
  append "▶ 증적(잠금/패스워드 상태)"
  if has_cmd passwd; then
    # passwd -S 는 일부 배포판에서만 제공
      passwd -S "root"" 2>/dev/null >> "${OUTFILE}" || true
  fi
  result_line "U-62" "수동 점검 필요 - 서비스 계정 잠금/만료 정책 검토"
}

check_U_63() {
  section "U-63" "불필요 패키지/서비스 제거(예: 컴파일러, 디버거)" "하"
  append "▶ 증적(대표 도구 존재 여부)"
  for c in gcc g++ make gdb strace; do
    if has_cmd "$c"; then kv "존재" "$c"; fi
  done
  result_line "U-63" "수동 점검 필요 - 운영서버 불필요 도구 제거 여부 판단"
}

check_U_64() {
  section "U-64" "악성코드/무결성 점검 도구(선택)" "하"
  append "▶ 증적"
  for c in aide rkhunter chkrootkit; do
    if has_cmd "$c"; then kv "존재" "$c"; fi
  done
  result_line "U-64" "수동 점검 필요 - 조직 정책에 따른 무결성/악성코드 점검 적용"
}

check_U_65() {
  section "U-65" "백업/복구 정책(선택)" "하"
  append "▶ 증적(자동화 확인은 환경 의존)"
  result_line "U-65" "수동 점검 필요 - 백업 주기/보관/복구 테스트 수행 여부 확인"
}

check_U_66() {
  section "U-66" "계정/권한 변경 이력 관리(선택)" "하"
  append "▶ 증적"
  if has_cmd last; then
    last -n 20 2>/dev/null >> "${OUTFILE}" || true
  fi
  result_line "U-66" "수동 점검 필요 - 계정/권한 변경 승인 및 이력관리 프로세스 확인"
}

check_U_67() {
  section "U-67" "서비스 실행 계정(root 실행 금지 - 주요 데몬)" "중"
  append "▶ 증적"
  ps -eo user,comm,args 2>/dev/null | grep -E '(sshd|nginx|httpd|apache2|mysqld|postgres|mongod|redis-server)' | head -n 80 >> "${OUTFILE}" || true
  result_line "U-67" "수동 점검 필요 - root로 실행 중인 서비스 최소화(필요 시 분리)"
}

check_U_68() {
  section "U-68" "권한 있는 파일(예: /etc) 무결성 보호(권한/소유자)" "중"
  append "▶ 증적"
  ls -ld /etc 2>/dev/null >> "${OUTFILE}" || true
  result_line "U-68" "수동 점검 필요 - 중요 디렉토리 권한 변경 통제"
}

check_U_69() {
  section "U-69" "로그인 시도/인증 실패 로깅" "중"
  append "▶ 증적"
  if [ -f /var/log/auth.log ]; then
    tail -n 30 /var/log/auth.log 2>/dev/null >> "${OUTFILE}" || true
  elif [ -f /var/log/secure ]; then
    tail -n 30 /var/log/secure 2>/dev/null >> "${OUTFILE}" || true
  else
    append "- auth 관련 로그 파일 미확인"
  fi
  result_line "U-69" "수동 점검 필요 - 인증 실패 이벤트 수집/모니터링 확인"
}

check_U_70() {
  section "U-70" "SSH 로그인 알림/모니터링(선택)" "하"
  append "▶ 증적(환경 의존)"
  result_line "U-70" "수동 점검 필요 - 침해 탐지/알림 체계 확인"
}

check_U_71() {
  section "U-71" "원격 관리 접근 제한(관리망/Jump Host)" "상"
  append "▶ 증적"
  if has_cmd sshd; then
    sshd -T 2>/dev/null | grep -E '^(listenaddress|port)\b' >> "${OUTFILE}" || true
  fi
  result_line "U-71" "수동 점검 필요 - 관리 접근 경로/ACL/망분리 정책 확인"
}

check_U_72() {
  section "U-72" "권한 없는 사용자에 의한 시스템 파일 수정 방지(권한/ACL)" "중"
  append "▶ 증적(대표 디렉토리 권한)"
  for d in /etc /bin /sbin /usr/bin /usr/sbin; do
    [ -d "$d" ] && ls -ld "$d" 2>/dev/null >> "${OUTFILE}" || true
  done
  result_line "U-72" "수동 점검 필요 - 중요 경로 쓰기 권한 최소화 확인"
}

check_U_73() {
  section "U-73" "정책에 따른 시스템 로깅 설정" "중"
  append "▶ 증적"
  if [ -f /etc/rsyslog.conf ]; then
    kv "rsyslog.conf(주요 규칙)" ""
    grep -Ev '^\s*#|^\s*$' /etc/rsyslog.conf 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  elif [ -f /etc/syslog.conf ]; then
    kv "syslog.conf(주요 규칙)" ""
    grep -Ev '^\s*#|^\s*$' /etc/syslog.conf 2>/dev/null | head -n 200 >> "${OUTFILE}" || true
  else
    append "- rsyslog/syslog 설정 파일 미확인"
  fi

  # 최소 자동 판정: rsyslog 설정 파일 존재 여부
  if [ -f /etc/rsyslog.conf ] || [ -f /etc/syslog.conf ]; then
    result_line "U-73" "양호 - 로깅 설정 파일 존재(세부는 정책 기반 수동 검토)"
  else
    result_line "U-73" "수동 점검 필요 - 로깅 데몬/설정 확인 필요"
  fi
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
  printf "\n=== Linux OS Audit: U-01 ~ U-73 ===\n"

  # 실행 목록(필수 73개 중, 여기서는 U-01~U-73 전부 호출)
  check_U_01
  check_U_02
  check_U_03
  check_U_04
  check_U_05
  check_U_06
  check_U_07
  check_U_08
  check_U_09
  check_U_10
  check_U_11
  check_U_12
  check_U_13
  check_U_14
  check_U_15
  check_U_16
  check_U_17
  check_U_18
  check_U_19
  check_U_20
  check_U_21
  check_U_22
  check_U_23
  check_U_24
  check_U_25
  check_U_26
  check_U_27
  check_U_28
  check_U_29
  check_U_30
  check_U_31
  check_U_32
  check_U_33
  check_U_34
  check_U_35
  check_U_36
  check_U_37
  check_U_38
  check_U_39
  check_U_40
  check_U_41
  check_U_42
  check_U_43
  check_U_44
  check_U_45
  check_U_46
  check_U_47
  check_U_48
  check_U_49
  check_U_50
  check_U_51
  check_U_52
  check_U_53
  check_U_54
  check_U_55
  check_U_56
  check_U_57
  check_U_58
  check_U_59
  check_U_60
  check_U_61
  check_U_62
  check_U_63
  check_U_64
  check_U_65
  check_U_66
  check_U_67
  check_U_68
  check_U_69
  check_U_70
  check_U_71
  check_U_72
  check_U_73

  write_summary
  append "결과 파일: ${OUTFILE}"
  printf "Done. Result: %s\n" "${OUTFILE}"
}

main "$@"
