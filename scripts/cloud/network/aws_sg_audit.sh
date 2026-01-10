#!/usr/bin/env bash
# AWS Security Group audit - standalone
# Last update: 2026-01-10

set -euo pipefail
umask 077

usage() { cat <<'EOF'
Usage:
  aws_sg_audit.sh --sw-id SW00001234 [--region ap-northeast-2] [--profile PROFILE] [--out-dir DIR]

Requires:
  - AWS CLI v2 configured with credentials/permissions: ec2:DescribeSecurityGroups
EOF
}

SW_ID=""
REGION=""
PROFILE=""
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2 ;;
    --region) REGION="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done
[[ -z "$SW_ID" ]] && { echo "Missing --sw-id"; usage; exit 2; }

DATE="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname)"
GUIDE_VER="Cloud Guide - AWS network exposure checks (operator-tailored)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__AWS_SG__${DATE}__result.txt"
mkdir -p "$OUT_DIR"

section(){ echo -e "\n============================================================================\n[$1] $2\n위험도: ${3:-}\n============================================================================\n" >>"$OUTFILE"; }
result_line(){ echo -e "★ [$1] 점검 결과: $2\n----------------------------------------------------------------------------\n${3:-}\n" >>"$OUTFILE"; }
append_cmd(){ local label="$1"; shift; { echo "▶ $label"; echo "\$ $*"; } >>"$OUTFILE"; "$@" >>"$OUTFILE" 2>&1 || true; echo "" >>"$OUTFILE"; }

AWS=(aws)
[[ -n "$PROFILE" ]] && AWS+=(--profile "$PROFILE")
[[ -n "$REGION" ]] && AWS+=(--region "$REGION")

{
  echo "############################################################################"
  echo "  AWS Security Group 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "실행 호스트: ${HOSTNAME}"
  echo "SW ID: ${SW_ID}"
  [[ -n "$PROFILE" ]] && echo "Profile: ${PROFILE}"
  [[ -n "$REGION" ]] && echo "Region: ${REGION}"
  echo "############################################################################"
  echo ""
} >"$OUTFILE"

if ! command -v aws >/dev/null 2>&1; then
  section "AWS-00" "사전 점검" "상"
  result_line "AWS-00" "수동" "aws CLI 미설치"
  echo "[INFO] 완료: $OUTFILE"
  exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
SG_JSON="$TMP_DIR/sg.json"

section "AWS-01" "0.0.0.0/0 또는 ::/0 공개 Inbound(민감 포트)" "상"
SENSITIVE_PORTS=(22 3389 3306 5432 27017 1433 6379 9200 5601)

query="SecurityGroups[].{GroupId:GroupId,GroupName:GroupName,IpPermissions:IpPermissions}"
append_cmd "describe-security-groups(JSON)" "${AWS[@]}" ec2 describe-security-groups --query "$query" --output json
findings="$("${AWS[@]}" ec2 describe-security-groups --query "$query" --output json 2>/dev/null || true)"
printf '%s' "$findings" >"$SG_JSON"

if command -v python3 >/dev/null 2>&1; then
  python3 - "$OUTFILE" "$SG_JSON" "${SENSITIVE_PORTS[@]}" <<'PY'
import json, sys
outfile = sys.argv[1]
json_path = sys.argv[2]
sens = set(map(int, sys.argv[3:]))
data = json.load(open(json_path, encoding="utf-8"))
bad = []
for sg in data:
    gid = sg.get("GroupId")
    gname = sg.get("GroupName")
    for perm in sg.get("IpPermissions", []) or []:
        proto = perm.get("IpProtocol")
        fp = perm.get("FromPort")
        tp = perm.get("ToPort")
        ipranges = (perm.get("IpRanges") or []) + (perm.get("Ipv6Ranges") or [])
        for r in ipranges:
            cidr = r.get("CidrIp") or r.get("CidrIpv6")
            if cidr in ("0.0.0.0/0", "::/0"):
                if fp is None or tp is None:
                    bad.append((gid, gname, proto, fp, tp, cidr, "ALL_PORTS_OR_ICMP"))
                else:
                    ports = set(range(int(fp), int(tp)+1))
                    if ports & sens or (int(fp)==0 and int(tp)==65535):
                        bad.append((gid, gname, proto, fp, tp, cidr, "SENSITIVE"))
with open(outfile, "a", encoding="utf-8") as f:
    if not bad:
        f.write("★ [AWS-01] 점검 결과: 양호\n----------------------------------------------------------------------------\n공개 Inbound(0.0.0.0/0, ::/0) 민감 포트 규칙 미탐지\n\n")
    else:
        f.write("★ [AWS-01] 점검 결과: 취약\n----------------------------------------------------------------------------\n공개 Inbound 규칙 발견:\n")
        for row in bad[:200]:
            f.write(f"- {row[0]} ({row[1]}): proto={row[2]} ports={row[3]}-{row[4]} cidr={row[5]} tag={row[6]}\n")
        if len(bad) > 200:
            f.write(f"... truncated ({len(bad)} findings)\n")
        f.write("\n")
PY
else
  result_line "AWS-01" "수동" "python3 미설치로 자동 판별 불가. JSON 출력에서 0.0.0.0/0, ::/0 규칙 수동 점검"
fi

section "AWS-02" "전체 포트(0-65535) 공개 여부" "상"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$OUTFILE" "$SG_JSON" <<'PY'
import json, sys
outfile = sys.argv[1]
json_path = sys.argv[2]
data = json.load(open(json_path, encoding="utf-8"))
bad = []
for sg in data:
    gid = sg.get("GroupId"); gname = sg.get("GroupName")
    for perm in sg.get("IpPermissions", []) or []:
        fp = perm.get("FromPort"); tp = perm.get("ToPort")
        ipranges = (perm.get("IpRanges") or []) + (perm.get("Ipv6Ranges") or [])
        for r in ipranges:
            cidr = r.get("CidrIp") or r.get("CidrIpv6")
            if cidr in ("0.0.0.0/0", "::/0") and fp == 0 and tp == 65535:
                bad.append((gid,gname,perm.get("IpProtocol"),fp,tp,cidr))
with open(outfile, "a", encoding="utf-8") as f:
    if not bad:
        f.write("★ [AWS-02] 점검 결과: 양호\n----------------------------------------------------------------------------\n전체 포트 공개 규칙 미탐지\n\n")
    else:
        f.write("★ [AWS-02] 점검 결과: 취약\n----------------------------------------------------------------------------\n전체 포트 공개 규칙 발견:\n")
        for row in bad[:200]:
            f.write(f"- {row[0]} ({row[1]}): proto={row[2]} ports={row[3]}-{row[4]} cidr={row[5]}\n")
        if len(bad) > 200:
            f.write(f"... truncated ({len(bad)} findings)\n")
        f.write("\n")
PY
else
  result_line "AWS-02" "수동" "python3 미설치로 자동 판별 불가. FromPort=0 ToPort=65535 규칙 수동 점검"
fi

echo "[INFO] 완료: $OUTFILE"
