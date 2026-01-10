#!/usr/bin/env bash
# Apache Tomcat audit (Linux/Unix) - lightweight, evidence-oriented
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
  tomcat_audit_v1.sh --sw-id SW00001234 [--catalina-base DIR] [--out-dir DIR]

Defaults:
  --catalina-base:
    - Uses $CATALINA_BASE if set
    - Else tries /opt/tomcat, /usr/local/tomcat, /var/lib/tomcat9, /var/lib/tomcat8

EOF
}

CATALINA_BASE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --catalina-base) CATALINA_BASE_ARG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$SW_ID" ]]; then
  echo "[ERROR] --sw-id is required" >&2
  usage
  exit 1
fi

make_outfile "Tomcat"

guess_catalina_base() {
  if [[ -n "$CATALINA_BASE_ARG" ]]; then
    echo "$CATALINA_BASE_ARG"; return
  fi
  if [[ -n "${CATALINA_BASE:-}" ]]; then
    echo "$CATALINA_BASE"; return
  fi
  for d in /opt/tomcat /usr/local/tomcat /var/lib/tomcat9 /var/lib/tomcat8 /var/lib/tomcat; do
    if [[ -d "$d" ]]; then echo "$d"; return; fi
  done
  echo ""
}

BASE="$(guess_catalina_base)"
CONF=""
SERVER_XML=""
WEB_XML=""

section "TC-00" "사전 점검(경로 확인)" "상"
if [[ -z "$BASE" || ! -d "$BASE" ]]; then
  result_line "TC-00" "취약" "Tomcat CATALINA_BASE를 찾지 못함(--catalina-base로 지정 필요)"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi
result_line "TC-00" "양호" "CATALINA_BASE=$BASE"

CONF="$BASE/conf"
SERVER_XML="$CONF/server.xml"
WEB_XML="$CONF/web.xml"

if [[ ! -f "$SERVER_XML" ]]; then
  result_line "TC-00" "수동" "server.xml 미존재: $SERVER_XML"
fi
if [[ ! -f "$WEB_XML" ]]; then
  result_line "TC-00" "수동" "web.xml 미존재: $WEB_XML"
fi

section "TC-01" "버전 확인" "중"
VER_CMD=""
if [[ -x "$BASE/bin/version.sh" ]]; then
  VER_CMD="$BASE/bin/version.sh"
elif command -v catalina.sh >/dev/null 2>&1; then
  VER_CMD="catalina.sh"
fi
if [[ -n "$VER_CMD" ]]; then
  {
    echo "-----[version output]-----"
    "$VER_CMD" version 2>/dev/null || true
  } >>"$OUTFILE"
  result_line "TC-01" "점검완료" "버전 출력 첨부"
else
  result_line "TC-01" "수동" "version.sh/catalina.sh 미탐지(버전 수동 확인 필요)"
fi

section "TC-02" "관리 콘솔(Manager/Host-Manager) 노출" "상"
MANAGER_DIR="$BASE/webapps/manager"
HOSTMGR_DIR="$BASE/webapps/host-manager"
if [[ -d "$MANAGER_DIR" || -d "$HOSTMGR_DIR" ]]; then
  result_line "TC-02" "취약" "webapps에 manager/host-manager 존재(미사용 시 제거 권고)"
else
  result_line "TC-02" "양호" "manager/host-manager 미탐지"
fi

# tomcat-users.xml basic check
TOMCAT_USERS="$CONF/tomcat-users.xml"
if [[ -f "$TOMCAT_USERS" ]]; then
  ADMIN_USERS="$(grep -E '<user\s' "$TOMCAT_USERS" 2>/dev/null | head -n 50 || true)"
  if echo "$ADMIN_USERS" | grep -qiE 'manager-gui|admin-gui|host-manager'; then
    result_line "TC-02" "수동" "tomcat-users.xml에 관리자 역할이 존재. 접근통제/네트워크 제한 확인 필요"
    {
      echo "-----[tomcat-users.xml (first 50 user lines)]-----"
      echo "$ADMIN_USERS"
    } >>"$OUTFILE"
  fi
else
  result_line "TC-02" "수동" "tomcat-users.xml 미존재(관리자 계정 설정 수동 확인)"
fi

section "TC-03" "Directory Listing 비활성화" "상"
if [[ -f "$WEB_XML" ]]; then
  # DefaultServlet listings parameter
  if grep -qiE '<param-name>listings</param-name>' "$WEB_XML" 2>/dev/null; then
    # Try to find the value near it
    val="$(awk 'BEGIN{IGNORECASE=1} /<param-name>listings<\/param-name>/{f=1} f && /<param-value>/{gsub(/.*<param-value>|<\/param-value>.*/,""); print; exit}' "$WEB_XML" 2>/dev/null || true)"
    if [[ "${val,,}" == "false" ]]; then
      result_line "TC-03" "양호" "listings=false"
    else
      result_line "TC-03" "취약" "listings 파라미터가 false가 아님(val=${val:-unknown}). Directory listing 노출 가능"
    fi
  else
    result_line "TC-03" "수동" "web.xml에 listings 설정 미탐지(애플리케이션별 web.xml 포함 여부 확인)"
  fi
else
  result_line "TC-03" "수동" "web.xml 미존재"
fi

section "TC-04" "AJP Connector 설정" "상"
if [[ -f "$SERVER_XML" ]]; then
  if grep -qiE 'protocol="AJP/1\.3"|protocol="org\.apache\.coyote\.ajp\.AjpNioProtocol"|AjpProtocol' "$SERVER_XML" 2>/dev/null; then
    result_line "TC-04" "수동" "AJP Connector 존재. secretRequired/secret/address/bind 설정 및 미사용 시 비활성화 권고"
    {
      echo "-----[AJP connector snippets]-----"
      grep -iE 'AJP/1\.3|Ajp' -n "$SERVER_XML" | head -n 80 || true
    } >>"$OUTFILE"
  else
    result_line "TC-04" "양호" "AJP Connector 미탐지"
  fi
else
  result_line "TC-04" "수동" "server.xml 미존재"
fi

section "TC-05" "HTTPS/TLS Connector 설정" "상"
if [[ -f "$SERVER_XML" ]]; then
  if grep -qiE 'SSLEnabled="true"|scheme="https"|secure="true"' "$SERVER_XML" 2>/dev/null; then
    result_line "TC-05" "점검완료" "HTTPS/TLS 관련 설정 스니펫 첨부"
    {
      echo "-----[TLS connector snippets]-----"
      grep -iE 'SSLEnabled="true"|scheme="https"|secure="true"|keystoreFile|sslProtocol|TLS' -n "$SERVER_XML" | head -n 120 || true
    } >>"$OUTFILE"
  else
    result_line "TC-05" "취약" "HTTPS/TLS 설정 미탐지(HTTP만 운영 가능성). 서비스 구성에 따라 수동 확인"
  fi
else
  result_line "TC-05" "수동" "server.xml 미존재"
fi

section "TC-06" "권한(퍼미션) 및 소유자" "중"
check_perm() {
  local path="$1"
  if [[ -e "$path" ]]; then
    # world-writable check
    if find "$path" -maxdepth 0 -perm -0002 >/dev/null 2>&1; then
      result_line "TC-06" "취약" "world-writable: $path"
    else
      result_line "TC-06" "점검완료" "not world-writable: $path"
    fi
    ( ls -ld "$path" 2>/dev/null || true ) >>"$OUTFILE"
  fi
}
check_perm "$CONF"
check_perm "$SERVER_XML"
check_perm "$WEB_XML"
check_perm "$BASE/webapps"

section "TC-99" "후속 조치" "중"
result_line "TC-99" "수동" "각 결과의 '취약/수동' 항목을 기준서(KISA/내규)에 맞춰 판정 및 조치계획 수립"

echo "[INFO] 완료: $OUTFILE"
