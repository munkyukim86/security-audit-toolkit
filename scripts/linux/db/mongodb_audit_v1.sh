#!/usr/bin/env bash
# MongoDB security audit (Linux/Unix) - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  mongodb_audit_v1.sh --sw-id SW00001234 [--uri URI] [--conf /etc/mongod.conf] [--out-dir DIR]

Examples:
  mongodb_audit_v1.sh --sw-id SW00001234 --conf /etc/mongod.conf
  mongodb_audit_v1.sh --sw-id SW00001234 --uri "mongodb://user@localhost:27017/admin" --conf /etc/mongod.conf
EOF
}

SW_ID=""
MONGO_URI=""
MONGO_CONF="/etc/mongod.conf"
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --uri) MONGO_URI="${2:-}"; shift 2 ;;
    --conf) MONGO_CONF="${2:-}"; shift 2 ;;
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
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__MongoDB__${DATE}__result.txt"
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

if ! command -v mongosh >/dev/null 2>&1; then
  echo "[ERROR] mongosh not found. Install MongoDB shell." >&2
  exit 1
fi

# If URI provided, allow password prompt if missing
MONGO_ARGS=(--quiet)
if [[ -n "$MONGO_URI" ]]; then
  # If URI doesn't contain password, mongosh will prompt; acceptable.
  MONGO_ARGS+=("$MONGO_URI")
fi

{
  echo "############################################################################"
  echo "  MongoDB 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo ""
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: ${HOSTNAME}"
  echo "mongosh: $(command -v mongosh)"
  echo "config: ${MONGO_CONF}"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

# MB-01 Users inventory (may require auth)
section "MB-01" "사용자/권한 목록(인증 필요 시 수동)" "상"
append_cmd "db.getUsers()" mongosh "${MONGO_ARGS[@]}" --eval "db.getUsers()"

result_line "MB-01" "수동" "출력 결과 기반으로 불필요 계정/과권한(role) 제거 여부 판단"

# MB-02 Authorization enabled (from config)
section "MB-02" "인증(authorization) 활성화" "상"
if [[ -r "$MONGO_CONF" ]]; then
  append_cmd "mongod.conf (security/bindIp)" bash -lc "grep -nE '^\s*(security:|authorization:|bindIp:|net:|#)' \"$MONGO_CONF\" | head -n 200"
  if grep -qE '^\s*authorization:\s*enabled\b' "$MONGO_CONF"; then
    result_line "MB-02" "양호" "authorization: enabled"
  else
    result_line "MB-02" "취약" "authorization 설정 확인 불가(미설정/disabled 가능)"
  fi
else
  result_line "MB-02" "수동" "mongod.conf 읽기 불가"
fi

# MB-03 Bind IP
section "MB-03" "외부 바인딩 최소화(bindIp)" "상"
if [[ -r "$MONGO_CONF" ]]; then
  bind="$(grep -nE '^\s*bindIp:\s*' "$MONGO_CONF" | head -n1 || true)"
  if echo "$bind" | grep -qE '0\.0\.0\.0|::'; then
    result_line "MB-03" "취약" "bindIp가 전체 바인딩(0.0.0.0/::)로 보임: ${bind}"
  elif [[ -n "$bind" ]]; then
    result_line "MB-03" "주의" "bindIp 설정 존재: ${bind} (관리/서비스망 범위 검토)"
  else
    result_line "MB-03" "주의" "bindIp 라인 확인 불가(기본값/별도 include 가능)"
  fi
else
  result_line "MB-03" "수동" "mongod.conf 읽기 불가"
fi

# MB-04 TLS (config)
section "MB-04" "전송구간 암호화(TLS) 설정" "상"
if [[ -r "$MONGO_CONF" ]]; then
  tls="$(grep -nE '^\s*(tls:|ssl:|mode:|certificateKeyFile:|CAFile:)' "$MONGO_CONF" | head -n 200 || true)"
  echo "▶ TLS 관련 라인" >>"$OUTFILE"
  echo "$tls" >>"$OUTFILE"
  echo "" >>"$OUTFILE"
  if echo "$tls" | grep -qE 'mode:\s*requireTLS|mode:\s*preferTLS'; then
    result_line "MB-04" "주의" "TLS 모드 설정 확인(인증서/클라이언트 강제 정책 포함 추가 확인)"
  else
    result_line "MB-04" "주의" "TLS 설정 확인 불가(환경별). 외부 통신 시 TLS 적용 권고"
  fi
else
  result_line "MB-04" "수동" "mongod.conf 읽기 불가"
fi

# MB-05 logging
section "MB-05" "로깅 설정(systemLog)" "중"
if [[ -r "$MONGO_CONF" ]]; then
  append_cmd "systemLog 관련 라인" bash -lc "grep -nE '^\s*(systemLog:|destination:|path:|logAppend:|verbosity:)' \"$MONGO_CONF\" | head -n 200"
  if grep -qE '^\s*destination:\s*file\b' "$MONGO_CONF"; then
    result_line "MB-05" "주의" "파일 로깅 설정 확인(권한/보관/SIEM 전송 정책 확인)"
  else
    result_line "MB-05" "주의" "로깅 destination 확인 불가"
  fi
else
  result_line "MB-05" "수동" "mongod.conf 읽기 불가"
fi

echo "[INFO] 완료: $OUTFILE"
