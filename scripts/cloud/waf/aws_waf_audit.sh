#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# AWS WAF (WAFv2) Audit Script
# Version : v0.2.0
# Updated : 2026-01-10
# Baseline: KISA 2021, Cloud Vulnerability Guide 2024 (InfoSec Systems),
#           TLP Network Guide 2024 (logging/monitoring principle)
# -----------------------------------------------------------------------------
# Requirements:
#   - bash 4+
#   - AWS CLI v2 (configured credentials)
#   - python3
# Notes:
#   - This script audits AWS WAFv2 Web ACL configuration and logging.
#   - It produces evidence-oriented output; some items may remain "수동".
# -----------------------------------------------------------------------------

set -euo pipefail
umask 077

GUIDE_VER="KISA 2021 / Cloud Guide 2024 / TLP Network 2024"

usage() {
  cat <<'EOF'
Usage:
  aws_waf_audit.sh --sw-id <SWID> --region <REGION> [--profile <PROFILE>] [--scope <REGIONAL|CLOUDFRONT>] [--out-dir <DIR>]

Examples:
  ./aws_waf_audit.sh --sw-id SW00001234 --region ap-northeast-2 --profile prod
  ./aws_waf_audit.sh --sw-id SW00001234 --region us-east-1 --scope CLOUDFRONT --profile prod
EOF
}

SW_ID=""
REGION=""
PROFILE="default"
SCOPE="REGIONAL"
OUT_DIR="$(pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sw-id) SW_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$SW_ID" || -z "$REGION" ]]; then
  echo "[ERROR] --sw-id and --region are required." >&2
  usage
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "[ERROR] aws CLI not found. Install AWS CLI v2." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found." >&2
  exit 1
fi

HOSTNAME="$(hostname -s 2>/dev/null || hostname)"
DATE="$(date +%Y%m%d_%H%M%S)"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME}__AWS_WAF__${DATE}__result.txt"

section() {
  local id="$1" title="$2" severity="$3"
  {
    echo "============================================================================"
    echo "[${id}] ${title}"
    echo "위험도: ${severity}"
    echo "============================================================================"
    echo ""
  } >> "$OUTFILE"
}

result_line() {
  local id="$1" res="$2" details="$3"
  {
    echo "★ [${id}] 점검 결과: ${res}"
    echo "----------------------------------------------------------------------------"
    echo -e "${details}"
    echo ""
  } >> "$OUTFILE"
}

log_info() {
  echo "[INFO] $1" >> "$OUTFILE"
}

{
  echo "############################################################################"
  echo "  AWS WAF (WAFv2) 취약점 점검 결과"
  echo "  기준: ${GUIDE_VER}"
  echo "############################################################################"
  echo ""
  echo "점검일시: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "점검대상: AWS (${REGION})"
  echo "SW ID: ${SW_ID}"
  echo "Scope: ${SCOPE}"
  echo "Profile: ${PROFILE}"
  echo "############################################################################"
  echo ""
} > "$OUTFILE"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

LIST_JSON="$TMP_DIR/webacls.json"
GET_JSON="$TMP_DIR/webacl.json"
LOG_JSON="$TMP_DIR/logging.json"

# AWS WAFv2: list web ACLs
section "WAF-01" "WAF(Web ACL) 사용 여부" "상"
if ! aws --profile "$PROFILE" --region "$REGION" wafv2 list-web-acls --scope "$SCOPE" --output json > "$LIST_JSON" 2>"$TMP_DIR/list.err"; then
  err="$(cat "$TMP_DIR/list.err" || true)"
  result_line "WAF-01" "수동" "Web ACL 목록 조회 실패. 권한/리전/스코프를 확인하세요.\n${err}"
else
  cnt="$(OUTFILE="$OUTFILE" PROFILE="$PROFILE" REGION="$REGION" SCOPE="$SCOPE" LIST_JSON="$LIST_JSON" GET_JSON="$GET_JSON" LOG_JSON="$LOG_JSON" python3 - <<'PY'
import json,sys
j=json.load(open(sys.argv[1],'r',encoding='utf-8'))
print(len(j.get('WebACLs',[])))
PY
"$LIST_JSON")"
  log_info "WebACL count: ${cnt}"
  if [[ "$cnt" -eq 0 ]]; then
    result_line "WAF-01" "취약" "Web ACL이 없습니다. 보호 대상(CloudFront/ALB/API Gateway 등)에 WAF 적용 여부를 확인하십시오."
  else
    details="$(OUTFILE="$OUTFILE" PROFILE="$PROFILE" REGION="$REGION" SCOPE="$SCOPE" LIST_JSON="$LIST_JSON" GET_JSON="$GET_JSON" LOG_JSON="$LOG_JSON" python3 - <<'PY'
import json,sys
j=json.load(open(sys.argv[1],'r',encoding='utf-8'))
for w in j.get('WebACLs',[]):
  print(f"- {w.get('Name')} | Id={w.get('Id')} | ARN={w.get('ARN')}")
PY
"$LIST_JSON")"
    result_line "WAF-01" "양호" "Web ACL ${cnt}개 확인:\n${details}"
  fi
fi

# For each Web ACL, evaluate rules + visibility + logging
section "WAF-02" "WAF 룰(Managed Rules 포함) 적용" "상"
section "WAF-03" "WAF 로깅(감사/추적) 활성화" "상"
section "WAF-04" "WAF 가시성(메트릭/샘플링) 설정" "중"

OUTFILE="$OUTFILE" PROFILE="$PROFILE" REGION="$REGION" SCOPE="$SCOPE" LIST_JSON="$LIST_JSON" GET_JSON="$GET_JSON" LOG_JSON="$LOG_JSON" python3 - <<'PY'
import json, os, subprocess, sys

outfile = os.environ['OUTFILE']
profile = os.environ['PROFILE']
region  = os.environ['REGION']
scope   = os.environ['SCOPE']
list_json = os.environ['LIST_JSON']
get_json  = os.environ['GET_JSON']
log_json  = os.environ['LOG_JSON']

def aws_cmd(args):
    p = subprocess.run(['aws','--profile',profile,'--region',region,*args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

def append(text):
    with open(outfile,'a',encoding='utf-8') as f:
        f.write(text)

j = json.load(open(list_json,'r',encoding='utf-8'))
webacls = j.get('WebACLs',[])

if not webacls:
    append('★ [WAF-02] 점검 결과: 수동\n----------------------------------------------------------------------------\nWeb ACL이 없어 상세 룰 점검을 건너뜁니다.\n\n')
    append('★ [WAF-03] 점검 결과: 수동\n----------------------------------------------------------------------------\nWeb ACL이 없어 로깅 점검을 건너뜁니다.\n\n')
    append('★ [WAF-04] 점검 결과: 수동\n----------------------------------------------------------------------------\nWeb ACL이 없어 가시성 점검을 건너뜁니다.\n\n')
    sys.exit(0)

rule_findings = []
log_findings  = []
vis_findings  = []

for w in webacls:
    name = w.get('Name','')
    wid  = w.get('Id','')
    arn  = w.get('ARN','')

    rc, out, err = aws_cmd(['wafv2','get-web-acl','--name',name,'--id',wid,'--scope',scope,'--output','json'])
    if rc != 0:
        rule_findings.append((name,'수동',f"get-web-acl 실패: {err.strip()}"))
        log_findings.append((name,'수동',"로깅 점검 불가 (get-web-acl 실패)"))
        vis_findings.append((name,'수동',"가시성 점검 불가 (get-web-acl 실패)"))
        continue

    gj = json.loads(out)
    webacl = gj.get('WebACL',{})
    rules = webacl.get('Rules',[]) or []

    # Rule checks
    managed = 0
    blocks  = 0
    for r in rules:
        st = r.get('Statement',{})
        if 'ManagedRuleGroupStatement' in st:
            managed += 1
        # Count explicit block actions
        act = r.get('Action',{})
        if 'Block' in act:
            blocks += 1
        # For managed groups, action can be OverrideAction; treat as policy-dependent

    default_action = 'UNKNOWN'
    da = webacl.get('DefaultAction',{})
    if 'Allow' in da:
        default_action = 'ALLOW'
    elif 'Block' in da:
        default_action = 'BLOCK'

    if not rules:
        rule_findings.append((name,'취약','룰이 없습니다. (Rules=0)'))
    else:
        # Heuristic: prefer managed rule groups OR at least one block
        if managed == 0 and blocks == 0:
            rule_findings.append((name,'주의',f"룰 {len(rules)}개 존재하나 ManagedRuleGroup 없음, Block 액션 룰 없음. (기본동작={default_action})"))
        else:
            rule_findings.append((name,'양호',f"룰 {len(rules)}개 확인 (ManagedGroup={managed}, BlockRule={blocks}, 기본동작={default_action})"))

    # Visibility checks
    vc = webacl.get('VisibilityConfig',{})
    cw = bool(vc.get('CloudWatchMetricsEnabled',False))
    sr = bool(vc.get('SampledRequestsEnabled',False))
    met = vc.get('MetricName','')
    if cw and sr:
        vis_findings.append((name,'양호',f"CloudWatchMetricsEnabled=TRUE, SampledRequestsEnabled=TRUE, MetricName={met}"))
    else:
        vis_findings.append((name,'주의',f"가시성 설정 미흡: CloudWatchMetricsEnabled={cw}, SampledRequestsEnabled={sr}, MetricName={met}"))

    # Logging checks
    rc, out, err = aws_cmd(['wafv2','get-logging-configuration','--resource-arn',arn,'--output','json'])
    if rc != 0:
        # Common error: WAFNonexistentItemException / WAFLogDestinationPermissionIssueException / NoSuchLoggingConfiguration
        log_findings.append((name,'취약',f"로깅 미설정 또는 조회 실패: {err.strip()}"))
    else:
        lj = json.loads(out)
        lc = lj.get('LoggingConfiguration',{})
        dest = lc.get('LogDestinationConfigs',[]) or []
        red  = lc.get('RedactedFields',[]) or []
        if dest:
            log_findings.append((name,'양호',f"Log destinations={len(dest)}개, RedactedFields={len(red)}"))
        else:
            log_findings.append((name,'취약',"LoggingConfiguration은 있으나 LogDestinationConfigs가 비어 있습니다."))

# Summaries

def emit(check_id, findings):
    # Worst-case result prioritization
    order = {'취약':0,'주의':1,'수동':2,'양호':3}
    overall = min(findings, key=lambda x: order.get(x[1],99))[1]
    lines = []
    for name,res,msg in findings:
        lines.append(f"- {name}: {res} | {msg}")
    body = "\n".join(lines)
    append(f"★ [{check_id}] 점검 결과: {overall}\n----------------------------------------------------------------------------\n{body}\n\n")

emit('WAF-02', rule_findings)
emit('WAF-03', log_findings)
emit('WAF-04', vis_findings)
PY

# Governance / 운영 관점은 자동화로 한계가 있으므로 수동 항목 추가
section "WAF-05" "운영 정책 및 대응 체계" "중"
result_line "WAF-05" "수동" "다음 사항을 운영 정책/증적 기반으로 확인하십시오.\n- WAF 정책 변경 이력(Change Management)\n- 차단 이벤트 대응 절차(오탐/정탐 처리)\n- SIEM/로그 보관 정책 및 접근통제\n- 예외 룰(Whitelist) 승인/만료 정책"

echo "[INFO] 점검 완료. 결과 파일: $OUTFILE"
