#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# GCP Firewall Rules Audit Script
# Version : v0.2.0
# Updated : 2026-01-10
# Baseline: Cloud Vulnerability Guide 2024 (Network/Access Control),
#           KISA 2021, TLP Network Guide 2024
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
NETWORK_FILTER=""  # optional
OUTFILE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") --sw-id <ID> --project <GCP_PROJECT> [--network <VPC_NAME>] [--out-dir <DIR>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --network) NETWORK_FILTER="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) shift ;;
  esac
done

if [[ -z "${SW_ID}" || -z "${PROJECT}" ]]; then
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

OUTFILE="${OUT_DIR}/${SW_ID}__GCP_FirewallRules__${DATE}__result.txt"

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
  echo "  GCP Firewall Rules 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: GCP (project=${PROJECT})"
  echo "SW ID: ${SW_ID}"
  if [[ -n "${NETWORK_FILTER}" ]]; then
    echo "VPC: ${NETWORK_FILTER}"
  fi
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

RULES_JSON="$TMP_DIR/firewall_rules.json"

# Pull firewall rules as JSON
if ! gcloud compute firewall-rules list --project="$PROJECT" --format=json >"$RULES_JSON" 2>/dev/null; then
  section "GCP-00" "방화벽 룰 조회" "상"
  result_line "GCP-00" "취약" "firewall-rules list 실패. 권한/로그인 상태를 확인하세요."
  exit 0
fi

section "GCP-01" "인바운드 SSH/RDP 공개(0.0.0.0/0)" "상"
RULES_JSON="$RULES_JSON" NETWORK_FILTER="$NETWORK_FILTER" python3 <<'PY' >>"$OUTFILE"
import json, os, re

path = os.environ["RULES_JSON"]
net_filter = os.environ.get("NETWORK_FILTER")

with open(path, "r", encoding="utf-8") as f:
    rules = json.load(f) or []

def is_open_to_world(r):
    sr = r.get("sourceRanges") or []
    return "0.0.0.0/0" in sr

def allows_port(r, port):
    allowed = r.get("allowed") or []
    for a in allowed:
        if a.get("IPProtocol") not in ("tcp", "all"):
            continue
        ports = a.get("ports") or []
        if not ports and a.get("IPProtocol") == "all":
            return True
        for p in ports:
            if p == str(port):
                return True
            if "-" in p:
                lo, hi = p.split("-", 1)
                if lo.isdigit() and hi.isdigit() and int(lo) <= int(port) <= int(hi):
                    return True
            if p == "0-65535":
                return True
    return False

def vpc_match(r):
    if not net_filter:
        return True
    net = r.get("network") or ""
    return net.endswith("/networks/" + net_filter)

hits = []
for r in rules:
    if r.get("direction") != "INGRESS":
        continue
    if r.get("disabled") is True:
        continue
    if not vpc_match(r):
        continue
    if not is_open_to_world(r):
        continue
    if allows_port(r, 22) or allows_port(r, 3389):
        hits.append(r)

if not hits:
    print("★ [GCP-01] 점검 결과: 양호")
    print("----------------------------------------------------------------------------")
    print("0.0.0.0/0로 SSH(22) 또는 RDP(3389) 허용 룰 없음\n")
else:
    print("★ [GCP-01] 점검 결과: 취약")
    print("----------------------------------------------------------------------------")
    for r in hits:
        print(f"- {r.get('name')} (priority={r.get('priority')}, network={r.get('network')})")
        print(f"  sourceRanges={r.get('sourceRanges')}")
        print(f"  allowed={r.get('allowed')}")
    print("")
PY

section "GCP-02" "과도하게 허용된 인바운드 룰(전체포트/ALL)" "상"
RULES_JSON="$RULES_JSON" NETWORK_FILTER="$NETWORK_FILTER" python3 <<'PY' >>"$OUTFILE"
import json, os

path = os.environ["RULES_JSON"]
net_filter = os.environ.get("NETWORK_FILTER")

with open(path, "r", encoding="utf-8") as f:
    rules = json.load(f) or []

def is_open_to_world(r):
    sr = r.get("sourceRanges") or []
    return "0.0.0.0/0" in sr

def is_all_ports_or_all_proto(r):
    allowed = r.get("allowed") or []
    for a in allowed:
        proto = a.get("IPProtocol")
        ports = a.get("ports")
        if proto == "all":
            return True
        if proto == "tcp" and ports:
            if "0-65535" in ports:
                return True
    return False

def vpc_match(r):
    if not net_filter:
        return True
    net = r.get("network") or ""
    return net.endswith("/networks/" + net_filter)

hits = []
for r in rules:
    if r.get("direction") != "INGRESS":
        continue
    if r.get("disabled") is True:
        continue
    if not vpc_match(r):
        continue
    if not is_open_to_world(r):
        continue
    if is_all_ports_or_all_proto(r):
        hits.append(r)

if not hits:
    print("★ [GCP-02] 점검 결과: 양호")
    print("----------------------------------------------------------------------------")
    print("0.0.0.0/0로 전체 프로토콜/전체 포트 허용 룰 없음\n")
else:
    print("★ [GCP-02] 점검 결과: 취약")
    print("----------------------------------------------------------------------------")
    for r in hits:
        print(f"- {r.get('name')} (priority={r.get('priority')}, network={r.get('network')})")
        print(f"  sourceRanges={r.get('sourceRanges')}")
        print(f"  allowed={r.get('allowed')}")
    print("")
PY

section "GCP-03" "방화벽 룰 로깅(logConfig)" "중"
RULES_JSON="$RULES_JSON" NETWORK_FILTER="$NETWORK_FILTER" python3 <<'PY' >>"$OUTFILE"
import json, os

path = os.environ["RULES_JSON"]
net_filter = os.environ.get("NETWORK_FILTER")

with open(path, "r", encoding="utf-8") as f:
    rules = json.load(f) or []

def vpc_match(r):
    if not net_filter:
        return True
    net = r.get("network") or ""
    return net.endswith("/networks/" + net_filter)

enabled = 0
checked = 0
for r in rules:
    if r.get("direction") != "INGRESS":
        continue
    if r.get("disabled") is True:
        continue
    if not vpc_match(r):
        continue
    checked += 1
    lc = r.get("logConfig") or {}
    if lc.get("enable") is True:
        enabled += 1

res = "양호" if checked and enabled else "취약"
print(f"★ [GCP-03] 점검 결과: {res}")
print("----------------------------------------------------------------------------")
print(f"INGRESS 룰 기준 logConfig.enable=true: {enabled} / {checked}")
if checked and enabled == 0:
    print("방화벽 로깅이 전부 비활성화된 것으로 보입니다. (감사/추적을 위해 활성화 권고)")
print("")
PY

log_info "Rules JSON: ${RULES_JSON}"

echo "[INFO] 점검 완료. 결과 파일: $OUTFILE"
