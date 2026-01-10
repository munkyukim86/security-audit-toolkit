#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# GCP Cloud Armor Audit Script
# Version : v0.2.0
# Updated : 2026-01-10
# Baseline: KISA 2021, Cloud Vulnerability Guide 2024 (InfoSec Systems),
#           TLP Network Guide 2024 (logging/monitoring principle)
# -----------------------------------------------------------------------------
# Requirements:
#  - gcloud CLI (authenticated)
#  - python3
# -----------------------------------------------------------------------------

set -euo pipefail
umask 077

GUIDE_VER="KISA 2021 / Cloud Guide 2024 / TLP Network 2024"
DATE="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$(pwd)"

SW_ID=""
PROJECT=""
POLICY=""
OUTFILE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") --sw-id <ID> --project <GCP_PROJECT> --policy <SECURITY_POLICY_NAME> [--out-dir <DIR>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) shift ;;
  esac
done

if [[ -z "${SW_ID}" || -z "${PROJECT}" || -z "${POLICY}" ]]; then
  usage
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "[ERROR] gcloud CLI not found." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found." >&2
  exit 1
fi

OUTFILE="${OUT_DIR}/${SW_ID}__GCP_CloudArmor__${DATE}__result.txt"

section() {
  local id="$1" title="$2" severity="$3"
  {
    echo "============================================================================"
    echo "[${id}] ${title}"
    echo "위험도: ${severity}"
    echo "============================================================================"
    echo ""
  } >>"$OUTFILE"
}

result_line() {
  local id="$1" res="$2" details="$3"
  {
    echo "★ [${id}] 점검 결과: ${res}"
    echo "----------------------------------------------------------------------------"
    echo -e "${details}"
    echo ""
  } >>"$OUTFILE"
}

log_info() {
  echo "[INFO] $1" >>"$OUTFILE"
}

{
  echo "############################################################################"
  echo "  GCP Cloud Armor 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: GCP (project=${PROJECT}, policy=${POLICY})"
  echo "SW ID: ${SW_ID}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

# Pull policy JSON
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

POLICY_JSON="$TMP_DIR/policy.json"
ATTACH_JSON="$TMP_DIR/attachments.json"

if ! gcloud compute security-policies describe "$POLICY" --project="$PROJECT" --format=json >"$POLICY_JSON" 2>/dev/null; then
  section "CA-01" "Cloud Armor 보안정책 존재 여부" "상"
  result_line "CA-01" "취약" "보안정책을 찾을 수 없습니다: ${POLICY} (project=${PROJECT})"
  exit 0
fi

section "CA-01" "Cloud Armor 보안정책 존재 여부" "상"
result_line "CA-01" "양호" "보안정책 존재: ${POLICY}"

# List backend-services that attach the policy
# Note: For global HTTP(S) LB, Cloud Armor attaches to backend-service.
# This is a best-effort check.
(
  gcloud compute backend-services list --project="$PROJECT" --global --format=json 2>/dev/null || echo '[]'
) >"$ATTACH_JSON"

section "CA-02" "보안정책 규칙(룰) 구성" "상"
POLICY_JSON="$POLICY_JSON" python3 <<'PY' >>"$OUTFILE"
import json, os

policy_path = os.environ["POLICY_JSON"]
with open(policy_path, "r", encoding="utf-8") as f:
    pol = json.load(f)

rules = pol.get("rules", []) or []
# Identify likely WAF-ish expressions
waf_like = 0
rate_limit = 0
preview_rules = 0
for r in rules:
    match = r.get("match", {}) or {}
    expr = (match.get("expr", {}) or {}).get("expression", "") or ""
    action = (r.get("action") or "")
    if "evaluatePreconfiguredWaf" in expr or "preconfiguredWaf" in expr or "owasp" in expr.lower():
        waf_like += 1
    if "rate_based" in action or "throttle" in action or "rate_limit" in action:
        rate_limit += 1
    if r.get("preview") is True:
        preview_rules += 1

print("★ [CA-02] 점검 결과: {}".format("양호" if rules else "취약"))
print("----------------------------------------------------------------------------")
if not rules:
    print("규칙이 없습니다. (기본 허용 상태 가능성)\n")
else:
    print(f"총 규칙 수: {len(rules)}")
    print(f"WAF(사전정의/OWASP 유사) 추정 규칙 수: {waf_like}")
    print(f"Rate limit/Throttle 추정 규칙 수: {rate_limit}")
    if preview_rules:
        print(f"Preview(탐지/검증) 규칙 수: {preview_rules} (Prevention 필요 시 조정 권고)")
    # default rule
    default = next((r for r in rules if r.get("priority") == 2147483647), None)
    if default:
        print(f"기본(default) 룰 action: {default.get('action')}")
    print("")
PY

section "CA-03" "로깅(LogConfig) 설정" "상"
POLICY_JSON="$POLICY_JSON" python3 <<'PY' >>"$OUTFILE"
import json, os

policy_path = os.environ["POLICY_JSON"]
with open(policy_path, "r", encoding="utf-8") as f:
    pol = json.load(f)

rules = pol.get("rules", []) or []
log_enabled = 0
for r in rules:
    lc = r.get("logConfig") or {}
    if lc.get("enable") is True:
        log_enabled += 1

result = "양호" if log_enabled else "취약"
print(f"★ [CA-03] 점검 결과: {result}")
print("----------------------------------------------------------------------------")
if rules:
    print(f"logConfig.enable=true 규칙 수: {log_enabled} / {len(rules)}")
    if not log_enabled:
        print("Cloud Armor 룰 로깅이 비활성화된 것으로 보입니다. (logConfig.enable 설정 권고)")
else:
    print("규칙이 없어 로깅 대상이 없습니다.")
print("")
PY

section "CA-04" "로드밸런서/백엔드 서비스에 정책 연결" "상"
POLICY_JSON="$POLICY_JSON" python3 <<'PY' >>"$OUTFILE"
import json, os

attach_path = os.environ["ATTACH_JSON"]
policy_name = os.environ["POLICY"]

with open(attach_path, "r", encoding="utf-8") as f:
    backends = json.load(f) if f.readable() else []

attached = []
for b in backends:
    sp = b.get("securityPolicy")
    if sp and sp.endswith("/securityPolicies/" + policy_name):
        attached.append(b.get("name"))

print("★ [CA-04] 점검 결과: {}".format("양호" if attached else "취약"))
print("----------------------------------------------------------------------------")
if attached:
    print("정책이 연결된 backend-services:")
    for n in attached:
        print(f" - {n}")
else:
    print("정책이 backend-services에 연결된 흔적을 찾지 못했습니다.")
    print("(HTTP(S) LB 구성 및 securityPolicy 연결 상태를 수동 확인하세요.)")
print("")
PY

log_info "Policy JSON: ${POLICY_JSON}"
log_info "Backend list JSON: ${ATTACH_JSON}"

echo "[INFO] 점검 완료. 결과 파일: $OUTFILE"
