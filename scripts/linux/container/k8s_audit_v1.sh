#!/usr/bin/env bash
# =============================================================================
# k8s_audit_v1.sh
# Kubernetes 보안 취약점 점검 스크립트 (kubectl read-only, standalone)
# 기준(참고): KISA/KCIS 2021 + KISA 클라우드 취약점 점검 가이드(2024) + Kubernetes 공식 보안 권고
# Last update: 2026-01-14
#
# 출력: <out-dir>/<SW-ID>__<HOST>__K8S__<TIMESTAMP>__result.txt (chmod 600)
#
# 사용 예:
#   bash k8s_audit_v1.sh --sw-id SW00001234
#   bash k8s_audit_v1.sh --sw-id SW00001234 --out-dir /tmp/results
#   bash k8s_audit_v1.sh --sw-id SW00001234 --context prod-cluster
#   bash k8s_audit_v1.sh --sw-id SW00001234 --allowed-registries "registry.company.com,ghcr.io"
# =============================================================================

set -u
set -o pipefail

SCRIPT_VER="1.0.0"
GUIDE_VER="KISA/KCIS 2021 + KISA Cloud Guide 2024"
NOW="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_ACTUAL="$(hostname 2>/dev/null || echo unknown)"

OUT_DIR="results"
SW_ID=""

KUBECONFIG_PATH=""
KUBE_CONTEXT=""
KUBECTL_TIMEOUT="10s"

ALLOWED_REGISTRIES=""     # comma-separated. empty => inventory-only
MAX_FINDINGS="50"
MAX_EVIDENCE_LINES="200"
NO_COLOR="0"

# Counters (summary)
CNT_CRITICAL=0
CNT_HIGH=0
CNT_MEDIUM=0
CNT_LOW=0
CNT_INFO=0
CNT_MANUAL=0

usage() {
  cat <<'USAGE'
Usage: k8s_audit_v1.sh --sw-id <SWID> [options]

Required:
  --sw-id               업무관리번호 (예: SW00001234)

Options:
  --out-dir             결과 저장 디렉토리 (기본: ./results)
  --kubeconfig          kubeconfig 경로 (기본: 환경/기본 경로 사용)
  --context             kubectl context 지정
  --allowed-registries  허용 레지스트리 목록(콤마 구분). 예: "registry.company.com,ghcr.io"
  --timeout             kubectl request-timeout (기본: 10s)
  --max-findings        항목별 출력 최대 건수 (기본: 50)
  --max-evidence-lines  증적 출력 최대 라인수 (기본: 200)
  --no-color            콘솔 컬러 비활성화
  -h|--help             도움말

Notes:
  - Read-only kubectl 명령만 사용합니다 (get/version/config/api-resources 등).
  - 클러스터 권한에 따라 일부 항목은 "수동 점검 필요"로 표시될 수 있습니다.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sw-id) SW_ID="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --kubeconfig) KUBECONFIG_PATH="${2:-}"; shift 2;;
    --context) KUBE_CONTEXT="${2:-}"; shift 2;;
    --allowed-registries) ALLOWED_REGISTRIES="${2:-}"; shift 2;;
    --timeout) KUBECTL_TIMEOUT="${2:-}"; shift 2;;
    --max-findings) MAX_FINDINGS="${2:-}"; shift 2;;
    --max-evidence-lines) MAX_EVIDENCE_LINES="${2:-}"; shift 2;;
    --no-color) NO_COLOR="1"; shift 1;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown argument: $1"; usage; exit 2;;
  esac
done

if [ -z "${SW_ID}" ]; then
  echo "[ERROR] --sw-id is required"
  usage
  exit 2
fi

# Output file (strict perms)
umask 077
mkdir -p "${OUT_DIR}"
OUTFILE="${OUT_DIR}/${SW_ID}__${HOSTNAME_ACTUAL}__K8S__${NOW}__result.txt"
: > "${OUTFILE}" || { echo "[ERROR] Cannot write to ${OUTFILE}"; exit 2; }
chmod 600 "${OUTFILE}" 2>/dev/null || true

has_cmd() { command -v "$1" >/dev/null 2>&1; }
append() { printf '%s\n' "$*" >> "${OUTFILE}"; }

# ---------- Console color (severity) ----------
is_tty() { [ -t 1 ]; }
c_reset=$'\033[0m'
c_red=$'\033[31m'
c_yellow=$'\033[33m'
c_blue=$'\033[34m'
c_green=$'\033[32m'
c_magenta=$'\033[35m'
c_cyan=$'\033[36m'
colorize() {
  local sev="$1"; shift
  local msg="$*"
  if [ "${NO_COLOR}" = "1" ] || ! is_tty; then
    printf '%s\n' "${msg}"
    return
  fi
  case "${sev}" in
    CRITICAL) printf '%s%s%s\n' "${c_red}" "${msg}" "${c_reset}";;
    HIGH)     printf '%s%s%s\n' "${c_magenta}" "${msg}" "${c_reset}";;
    MEDIUM)   printf '%s%s%s\n' "${c_yellow}" "${msg}" "${c_reset}";;
    LOW)      printf '%s%s%s\n' "${c_blue}" "${msg}" "${c_reset}";;
    INFO)     printf '%s%s%s\n' "${c_cyan}" "${msg}" "${c_reset}";;
    MANUAL)   printf '%s%s%s\n' "${c_yellow}" "${msg}" "${c_reset}";;
    PASS)     printf '%s%s%s\n' "${c_green}" "${msg}" "${c_reset}";;
    *)        printf '%s\n' "${msg}";;
  esac
}

inc_counter() {
  local sev="$1"
  case "${sev}" in
    CRITICAL) CNT_CRITICAL=$((CNT_CRITICAL+1));;
    HIGH) CNT_HIGH=$((CNT_HIGH+1));;
    MEDIUM) CNT_MEDIUM=$((CNT_MEDIUM+1));;
    LOW) CNT_LOW=$((CNT_LOW+1));;
    INFO) CNT_INFO=$((CNT_INFO+1));;
    MANUAL) CNT_MANUAL=$((CNT_MANUAL+1));;
  esac
}

section() {
  local id="$1" title="$2" severity="$3"
  append ""
  append "============================================================================"
  append "[${id}] ${title}"
  append "위험도: ${severity}"
  append "============================================================================"
}

result_line() {
  # result: 양호/취약/수동/정보
  local id="$1" severity="$2" result="$3" summary="$4"
  local details="${5:-}"

  append ""
  append "★ [${id}] 점검 결과: ${result} (Severity: ${severity})"
  append "----------------------------------------------------------------------------"
  append "${summary}"
  [ -n "${details}" ] && { append ""; append "${details}"; }
  append ""

  inc_counter "${severity}"

  case "${result}" in
    *양호*) colorize PASS "[PASS][${severity}] ${id} - ${summary}";;
    *취약*) colorize "${severity}" "[FAIL][${severity}] ${id} - ${summary}";;
    *수동*) colorize MANUAL "[MANUAL][${severity}] ${id} - ${summary}";;
    *)      colorize INFO "[INFO][${severity}] ${id} - ${summary}";;
  esac
}

# ---------- kubectl wrapper ----------
KUBECTL=(kubectl --request-timeout="${KUBECTL_TIMEOUT}")
if [ -n "${KUBECONFIG_PATH}" ]; then
  KUBECTL+=(--kubeconfig "${KUBECONFIG_PATH}")
fi
if [ -n "${KUBE_CONTEXT}" ]; then
  KUBECTL+=(--context "${KUBE_CONTEXT}")
fi

kcmd() {
  # Usage: kcmd "<desc>" <kubectl args...>
  local desc="$1"; shift
  local tmp rc
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_audit.$$.$RANDOM")"
  append "- 명령: kubectl $*"
  append "- 설명: ${desc}"
  if "${KUBECTL[@]}" "$@" >"${tmp}" 2>&1; then
    append "- 결과: 성공"
    sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
    rc=0
  else
    rc=$?
    append "- 결과: 실패 (exit=${rc})"
    sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
  fi
  append ""
  rm -f "${tmp}" 2>/dev/null || true
  return "${rc}"
}

banner() {
  append "############################################################################"
  append "# Kubernetes Security Audit Report"
  append "# Script: k8s_audit_v1.sh (ver ${SCRIPT_VER})"
  append "# Guide : ${GUIDE_VER}"
  append "# SW-ID : ${SW_ID}"
  append "# Host  : ${HOSTNAME_ACTUAL}"
  append "# Time  : ${NOW}"
  append "# Out   : ${OUTFILE}"
  append "############################################################################"
  append ""
  append "[환경 정보]"
  append "- 실행 사용자: $(id -un 2>/dev/null || echo unknown)"
  append "- kubectl: $(command -v kubectl 2>/dev/null || echo not_found)"
  append "- kubeconfig: ${KUBECONFIG_PATH:-default}"
  append "- context: ${KUBE_CONTEXT:-default}"
  append "- allowed-registries: ${ALLOWED_REGISTRIES:-not_set}"
  append ""
  kcmd "kubectl client version" version --client=true
  kcmd "current context" config current-context
}

# ---------- helpers ----------
is_system_ns() {
  case "$1" in
    kube-system|kube-public|kube-node-lease) return 0;;
    *) return 1;;
  esac
}

get_apiserver_pod() {
  # Try common label first
  local pod
  pod="$("${KUBECTL[@]}" -n kube-system get pods -l component=kube-apiserver -o name 2>/dev/null | head -n 1 | sed 's#pod/##')"
  if [ -n "${pod}" ]; then echo "${pod}"; return 0; fi
  pod="$("${KUBECTL[@]}" -n kube-system get pods --no-headers 2>/dev/null | awk '/kube-apiserver/{print $1; exit}')"
  echo "${pod}"
}

get_etcd_pod() {
  local pod
  pod="$("${KUBECTL[@]}" -n kube-system get pods -l component=etcd -o name 2>/dev/null | head -n 1 | sed 's#pod/##')"
  if [ -n "${pod}" ]; then echo "${pod}"; return 0; fi
  pod="$("${KUBECTL[@]}" -n kube-system get pods --no-headers 2>/dev/null | awk '/(^|[[:space:]])etcd[[:space:]-]/{print $1; exit}')"
  if [ -z "${pod}" ]; then
    pod="$("${KUBECTL[@]}" -n kube-system get pods --no-headers 2>/dev/null | awk '/etcd/{print $1; exit}')"
  fi
  echo "${pod}"
}

get_pod_args() {
  # print first container command+args as one line
  local ns="$1" pod="$2"
  "${KUBECTL[@]}" -n "${ns}" get pod "${pod}" -o jsonpath='{range .spec.containers[0].command[*]}{.}{" "}{end}{range .spec.containers[0].args[*]}{.}{" "}{end}' 2>/dev/null || true
}

contains_flag() {
  # contains_flag "<args>" "--flag" OR "--flag=value"
  local hay="$1" flag="$2"
  echo "${hay}" | grep -Eq "(^|[[:space:]])${flag}([=[:space:]]|$)" 2>/dev/null
}

# ---------- Checks ----------
check_K8S_00_preflight() {
  section "K8S-00" "사전 점검: kubectl 존재 여부" "HIGH"
  append "▶ 증적"
  if has_cmd kubectl; then
    result_line "K8S-00" "LOW" "양호" "kubectl 명령이 존재합니다."
  else
    result_line "K8S-00" "CRITICAL" "취약" "kubectl이 설치되어 있지 않습니다." "조치: kubectl 설치 후 재실행"
    exit 1
  fi
}

check_K8S_01_connectivity() {
  section "K8S-01" "클러스터 연결/권한 확인" "CRITICAL"
  append "▶ 증적"
  local ok="1"
  kcmd "cluster-info" cluster-info || ok="0"
  kcmd "nodes list (wide)" get nodes -o wide || ok="0"

  if [ "${ok}" = "1" ]; then
    result_line "K8S-01" "LOW" "양호" "kubectl로 클러스터 접근 및 노드 조회가 가능합니다."
  else
    result_line "K8S-01" "CRITICAL" "취약" "클러스터 연결 또는 조회 권한에 문제가 있습니다." \
      "확인: kubeconfig/context, 네트워크, RBAC 권한(get nodes/cluster-info) 점검"
  fi
}

check_K8S_10_pss() {
  section "K8S-10" "Pod Security Standards(PSS) 적용 상태(네임스페이스 라벨)" "HIGH"
  append "▶ 증적"
  local tmp missing=0 privileged=0 baseline=0 restricted=0 total=0
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_pss.$$.$RANDOM")"

  # ns, enforce, audit, warn
  if "${KUBECTL[@]}" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels["pod-security.kubernetes.io/enforce"]}{"\t"}{.metadata.labels["pod-security.kubernetes.io/audit"]}{"\t"}{.metadata.labels["pod-security.kubernetes.io/warn"]}{"\n"}{end}' \
      > "${tmp}" 2>/dev/null; then
    sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
    total="$(wc -l < "${tmp}" 2>/dev/null || echo 0)"

    while IFS=$'\t' read -r ns enforce audit warn; do
      is_system_ns "${ns}" && continue
      [ -z "${ns}" ] && continue

      if [ -z "${enforce}" ]; then
        missing=$((missing+1))
      elif [ "${enforce}" = "privileged" ]; then
        privileged=$((privileged+1))
      elif [ "${enforce}" = "baseline" ]; then
        baseline=$((baseline+1))
      elif [ "${enforce}" = "restricted" ]; then
        restricted=$((restricted+1))
      fi
    done < "${tmp}"
  else
    append "(네임스페이스 조회 실패)"
    rm -f "${tmp}" 2>/dev/null || true
    result_line "K8S-10" "HIGH" "수동 점검 필요" "네임스페이스 라벨 조회 권한/환경을 확인해야 합니다."
    return
  fi

  rm -f "${tmp}" 2>/dev/null || true

  local detail
  detail="$(cat <<EOF
- 비시스템 네임스페이스 기준 집계:
  - enforce 라벨 없음: ${missing}
  - enforce=privileged: ${privileged}
  - enforce=baseline: ${baseline}
  - enforce=restricted: ${restricted}

권고:
  - 최소 baseline 이상, 가능한 restricted 적용
  - enforce/audit/warn 모드 조합으로 단계적 강화
EOF
)"
  if [ "${privileged}" -gt 0 ]; then
    result_line "K8S-10" "CRITICAL" "취약" "일부 네임스페이스가 PSS enforce=privileged 입니다." "${detail}"
  elif [ "${missing}" -gt 0 ]; then
    result_line "K8S-10" "HIGH" "취약" "일부 네임스페이스에 PSS enforce 라벨이 없습니다." "${detail}"
  else
    result_line "K8S-10" "LOW" "양호" "비시스템 네임스페이스에 PSS enforce 라벨이 설정되어 있습니다." "${detail}"
  fi
}

check_K8S_11_psp() {
  section "K8S-11" "PodSecurityPolicy(PSP) 사용 여부(레거시)" "MEDIUM"
  append "▶ 증적"
  if "${KUBECTL[@]}" api-resources 2>/dev/null | grep -qi 'podsecuritypolic'; then
    kcmd "PodSecurityPolicy resources detected" get podsecuritypolicies || true
    result_line "K8S-11" "MEDIUM" "정보" "PSP 리소스가 감지됩니다(레거시). PSS 기반으로 전환 권고." \
      "참고: Kubernetes는 PSP 폐지 흐름이며 PSS/Pod Security Admission을 권고합니다."
  else
    result_line "K8S-11" "LOW" "양호" "PSP 리소스가 감지되지 않습니다(또는 API 비활성)."
  fi
}

check_K8S_12_workload_security_context() {
  section "K8S-12" "워크로드 보안 설정(Privileged/HostNS/HostPath/RunAsNonRoot 등)" "CRITICAL"
  append "▶ 증적"

  local tmp risky=0 risky_priv=0 risky_host=0 risky_hostpath=0 risky_root=0
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_pods.$$.$RANDOM")"

  # ns, pod, hostNetwork, hostPID, hostIPC, hostPath list, containers security bits
  if "${KUBECTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\t"}{.spec.hostIPC}{"\t"}{range .spec.volumes[*]}{.hostPath.path}{";"}{end}{"\t"}{range .spec.containers[*]}{.name}{":"}{.securityContext.privileged}{"|"}{.securityContext.allowPrivilegeEscalation}{"|"}{.securityContext.runAsNonRoot}{"|"}{.securityContext.readOnlyRootFilesystem}{"|"}{.securityContext.runAsUser}{";"}{end}{"\n"}{end}' \
      > "${tmp}" 2>/dev/null; then
    # evidence (truncated)
    sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
  else
    append "(pod 목록 조회 실패)"
    rm -f "${tmp}" 2>/dev/null || true
    result_line "K8S-12" "CRITICAL" "수동 점검 필요" "Pod 목록/보안 컨텍스트 조회에 실패했습니다(권한/환경 확인)."
    return
  fi

  local findings
  findings="$(mktemp 2>/dev/null || echo "/tmp/k8s_findings.$$.$RANDOM")"
  : > "${findings}"

  while IFS=$'\t' read -r ns pod hn hpid hipc hostpaths containers; do
    is_system_ns "${ns}" && continue

    # privileged?
    if echo "${containers}" | grep -q 'true' 2>/dev/null; then
      echo "${ns}/${pod}  privileged-container-detected  containers=${containers}" >> "${findings}"
      risky=$((risky+1)); risky_priv=$((risky_priv+1))
      continue
    fi

    # host namespaces
    if [ "${hn}" = "true" ] || [ "${hpid}" = "true" ] || [ "${hipc}" = "true" ]; then
      echo "${ns}/${pod}  host-namespace  hostNetwork=${hn},hostPID=${hpid},hostIPC=${hipc}" >> "${findings}"
      risky=$((risky+1)); risky_host=$((risky_host+1))
      continue
    fi

    # hostPath volumes
    if echo "${hostpaths}" | grep -Eq '/|[A-Za-z0-9]' 2>/dev/null; then
      # hostpaths may contain ";" even if empty; check meaningful
      if echo "${hostpaths}" | grep -Eq '/[^;]+' 2>/dev/null; then
        echo "${ns}/${pod}  hostPath-volume  hostPath=${hostpaths}" >> "${findings}"
        risky=$((risky+1)); risky_hostpath=$((risky_hostpath+1))
        continue
      fi
    fi

    # runAsUser 0 heuristics (if any container shows |...|0;)
    if echo "${containers}" | grep -Eq '\|0;' 2>/dev/null; then
      echo "${ns}/${pod}  runAsUser0-suspected  containers=${containers}" >> "${findings}"
      risky=$((risky+1)); risky_root=$((risky_root+1))
      continue
    fi
  done < "${tmp}"

  rm -f "${tmp}" 2>/dev/null || true

  append "▶ 위험 징후(상위 ${MAX_FINDINGS}개)"
  if [ -s "${findings}" ]; then
    sed -n "1,${MAX_FINDINGS}p" "${findings}" >> "${OUTFILE}"
  else
    append "(해당 없음)"
  fi
  append ""

  local detail
  detail="$(cat <<EOF
- 비시스템 네임스페이스 기준 위험 징후:
  - privileged 컨테이너 의심: ${risky_priv}
  - hostNetwork/hostPID/hostIPC 사용: ${risky_host}
  - hostPath 볼륨 사용: ${risky_hostpath}
  - runAsUser=0 의심: ${risky_root}

권고(예):
  - privileged/hostPath/hostNS 최소화, 필요 시 별도 격리 네임스페이스 운영
  - restricted PSS/정책엔진(Kyverno/Gatekeeper)로 사전 차단
EOF
)"
  if [ "${risky_priv}" -gt 0 ]; then
    result_line "K8S-12" "CRITICAL" "취약" "비시스템 워크로드에서 privileged 컨테이너가 의심됩니다." "${detail}"
  elif [ "${risky}" -gt 0 ]; then
    result_line "K8S-12" "HIGH" "취약" "비시스템 워크로드에서 고위험 설정 징후가 감지됩니다." "${detail}"
  else
    result_line "K8S-12" "LOW" "양호" "비시스템 워크로드에서 즉시 조치가 필요한 고위험 징후는 발견되지 않았습니다." "${detail}"
  fi

  rm -f "${findings}" 2>/dev/null || true
}

check_K8S_13_serviceaccount_tokens() {
  section "K8S-13" "서비스어카운트 토큰 자동 마운트(불필요 토큰 노출 최소화)" "MEDIUM"
  append "▶ 증적"
  kcmd "serviceaccounts automountServiceAccountToken" get sa -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,AUTOMOUNT:.automountServiceAccountToken --no-headers || true
  kcmd "pods automountServiceAccountToken" get pods -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,AUTOMOUNT:.spec.automountServiceAccountToken --no-headers || true

  # Heuristic: count SA with explicit false
  local tmp cnt_false cnt_total
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_sa.$$.$RANDOM")"
  if "${KUBECTL[@]}" get sa -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,AUTOMOUNT:.automountServiceAccountToken --no-headers 2>/dev/null > "${tmp}"; then
    cnt_total="$(wc -l < "${tmp}" 2>/dev/null || echo 0)"
    cnt_false="$(awk '$3=="false"{c++} END{print c+0}' "${tmp}" 2>/dev/null || echo 0)"
    rm -f "${tmp}" 2>/dev/null || true
    if [ "${cnt_false}" -gt 0 ]; then
      result_line "K8S-13" "LOW" "정보" "일부 서비스어카운트에서 automountServiceAccountToken=false 설정이 확인됩니다." \
        "- total SA: ${cnt_total}\n- explicit false: ${cnt_false}\n권고: 불필요한 워크로드는 토큰 자동 마운트 비활성화"
    else
      result_line "K8S-13" "MEDIUM" "정보" "서비스어카운트 토큰 자동 마운트 비활성화 흔적이 적습니다(기본값 true 가능)." \
        "권고: 토큰이 불필요한 워크로드는 SA 또는 Pod에 automountServiceAccountToken=false 적용"
    fi
  else
    rm -f "${tmp}" 2>/dev/null || true
    result_line "K8S-13" "MEDIUM" "수동 점검 필요" "ServiceAccount 목록 조회 권한이 부족하거나 오류가 발생했습니다."
  fi
}

check_K8S_20_rbac_cluster_admin() {
  section "K8S-20" "RBAC: cluster-admin 바인딩(과다권한) 점검" "CRITICAL"
  append "▶ 증적"

  local tmp
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_crb.$$.$RANDOM")"
  if "${KUBECTL[@]}" get clusterrolebinding -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT_KINDS:.subjects[*].kind,SUBJECTS:.subjects[*].name --no-headers \
      2>/dev/null > "${tmp}"; then

    append "- clusterrolebinding 전체(상위 ${MAX_EVIDENCE_LINES}줄)"
    sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
    append ""

    local ca
    ca="$(awk '$2=="cluster-admin"{print}' "${tmp}" 2>/dev/null | head -n "${MAX_FINDINGS}")"
    if [ -n "${ca}" ]; then
      append "▶ cluster-admin 바인딩(상위 ${MAX_FINDINGS}개)"
      printf '%s\n' "${ca}" >> "${OUTFILE}"
      append ""
      if echo "${ca}" | grep -Eq 'system:anonymous|system:unauthenticated' 2>/dev/null; then
        result_line "K8S-20" "CRITICAL" "취약" "cluster-admin이 익명/미인증 주체에 부여된 정황이 있습니다." \
          "권고: 익명 접근 차단(--anonymous-auth=false) 및 바인딩 제거/최소권한 재설계"
      else
        result_line "K8S-20" "HIGH" "취약" "cluster-admin 바인딩이 존재합니다(최소권한 원칙 위배 가능)." \
          "권고: cluster-admin은 제한된 운영 주체로 최소화하고, 필요한 범위로 Role/ClusterRole 분리"
      fi
    else
      result_line "K8S-20" "LOW" "양호" "cluster-admin 바인딩이 감지되지 않았습니다(또는 조회 권한 제한)."
    fi
  else
    result_line "K8S-20" "CRITICAL" "수동 점검 필요" "ClusterRoleBinding 조회에 실패했습니다(권한 확인 필요)."
  fi
  rm -f "${tmp}" 2>/dev/null || true
}

check_K8S_21_rbac_wildcards() {
  section "K8S-21" "RBAC: 와일드카드 권한(* verbs/resources) 점검" "HIGH"
  append "▶ 증적"

  local roles tmp findings
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_roles.$$.$RANDOM")"
  findings="$(mktemp 2>/dev/null || echo "/tmp/k8s_roles_find.$$.$RANDOM")"
  : > "${findings}"

  if ! "${KUBECTL[@]}" get clusterrole -o custom-columns=NAME:.metadata.name --no-headers 2>/dev/null > "${tmp}"; then
    result_line "K8S-21" "HIGH" "수동 점검 필요" "ClusterRole 목록 조회 실패(권한 확인 필요)."
    rm -f "${tmp}" "${findings}" 2>/dev/null || true
    return
  fi

  local count=0
  while read -r name; do
    [ -z "${name}" ] && continue
    count=$((count+1))
    # cap to avoid very large clusters
    if [ "${count}" -gt 300 ]; then
      append "(주의) ClusterRole이 많아 300개까지만 샘플 점검했습니다."
      break
    fi

    local out
    out="$("${KUBECTL[@]}" get clusterrole "${name}" -o jsonpath='{range .rules[*]}{.verbs}{"|"}{.resources}{"|"}{.nonResourceURLs}{"\n"}{end}' 2>/dev/null || true)"
    # wildcard detection: verbs [*] + resources [*] OR verbs [*] + nonResourceURLs [*]
    if echo "${out}" | awk -F'|' '($1 ~ /\[\*\]/ && $2 ~ /\[\*\]/){exit 0} ($1 ~ /\[\*\]/ && $3 ~ /\[\*\]/){exit 0} {next} END{exit 1}'; then
      echo "${name}" >> "${findings}"
    fi
  done < "${tmp}"

  append "- 점검 대상 ClusterRole 샘플 수: ${count}"
  append "- 와일드카드 의심 ClusterRole(상위 ${MAX_FINDINGS}개):"
  if [ -s "${findings}" ]; then
    sed -n "1,${MAX_FINDINGS}p" "${findings}" >> "${OUTFILE}"
    append ""
    result_line "K8S-21" "HIGH" "취약" "와일드카드 권한을 가진 ClusterRole이 존재할 가능성이 있습니다." \
      "권고: * 권한은 업무 단위로 분리/축소, 바인딩 현황까지 함께 점검"
  else
    append "(해당 없음)"
    append ""
    result_line "K8S-21" "LOW" "양호" "샘플 범위 내에서 와일드카드 ClusterRole은 확인되지 않았습니다."
  fi

  rm -f "${tmp}" "${findings}" 2>/dev/null || true
}

check_K8S_30_network_policy_coverage() {
  section "K8S-30" "NetworkPolicy 적용 범위(네임스페이스별 정책 부재 여부)" "HIGH"
  append "▶ 증적"
  kcmd "NetworkPolicy all namespaces" get networkpolicy -A || true

  local ns_tmp
  ns_tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_ns.$$.$RANDOM")"
  if ! "${KUBECTL[@]}" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null > "${ns_tmp}"; then
    result_line "K8S-30" "HIGH" "수동 점검 필요" "네임스페이스 목록 조회 실패."
    rm -f "${ns_tmp}" 2>/dev/null || true
    return
  fi

  local findings
  findings="$(mktemp 2>/dev/null || echo "/tmp/k8s_np_find.$$.$RANDOM")"
  : > "${findings}"

  while read -r ns; do
    [ -z "${ns}" ] && continue
    is_system_ns "${ns}" && continue

    local pod_cnt np_cnt
    pod_cnt="$("${KUBECTL[@]}" -n "${ns}" get pods --no-headers 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"
    np_cnt="$("${KUBECTL[@]}" -n "${ns}" get networkpolicy --no-headers 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"
    if [ "${pod_cnt}" -gt 0 ] && [ "${np_cnt}" -eq 0 ]; then
      echo "${ns}  pods=${pod_cnt}  networkpolicies=0" >> "${findings}"
    fi
  done < "${ns_tmp}"
  rm -f "${ns_tmp}" 2>/dev/null || true

  append "▶ NetworkPolicy 미적용(파드 존재) 네임스페이스(상위 ${MAX_FINDINGS}개)"
  if [ -s "${findings}" ]; then
    sed -n "1,${MAX_FINDINGS}p" "${findings}" >> "${OUTFILE}"
    append ""
    result_line "K8S-30" "HIGH" "취약" "일부 네임스페이스는 파드가 존재하지만 NetworkPolicy가 없습니다." \
      "권고: 네임스페이스별 기본 deny + 필요한 통신만 허용하는 정책 설계"
  else
    append "(해당 없음)"
    append ""
    result_line "K8S-30" "LOW" "양호" "비시스템 네임스페이스 기준, '파드 존재 + NetworkPolicy 없음' 케이스는 확인되지 않았습니다."
  fi

  rm -f "${findings}" 2>/dev/null || true
}

check_K8S_40_secrets_inventory() {
  section "K8S-40" "Secrets 관리(민감정보 노출 최소화, 유형/분포 인벤토리)" "MEDIUM"
  append "▶ 증적"
  # NOTE: data 필드는 출력하지 않음
  kcmd "Secrets list (no data)" get secrets -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type --no-headers || true

  local tmp
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_secrets.$$.$RANDOM")"
  if "${KUBECTL[@]}" get secrets -A -o jsonpath='{range .items[*]}{.type}{"\n"}{end}' 2>/dev/null > "${tmp}"; then
    append "▶ Secret 유형별 개수(상위 30개)"
    sort "${tmp}" 2>/dev/null | uniq -c 2>/dev/null | sort -nr 2>/dev/null | head -n 30 >> "${OUTFILE}"
    append ""
    result_line "K8S-40" "INFO" "정보" "Secret 인벤토리(유형/분포)를 기록했습니다." \
      "권고: Opaque Secret 최소화, 외부 Secret Store/암호화(KMS) 및 접근제어(RBAC) 강화"
  else
    result_line "K8S-40" "MEDIUM" "수동 점검 필요" "Secret 유형 집계에 실패했습니다(권한 확인)."
  fi
  rm -f "${tmp}" 2>/dev/null || true
}

check_K8S_41_encryption_at_rest() {
  section "K8S-41" "etcd 암호화(Encryption at Rest) 설정 여부(가능 범위 내 확인)" "HIGH"
  append "▶ 증적"

  local apipod args
  apipod="$(get_apiserver_pod)"
  if [ -z "${apipod}" ]; then
    result_line "K8S-41" "HIGH" "수동 점검 필요" "kube-apiserver Pod를 확인할 수 없습니다(Managed K8s일 수 있음)." \
      "권고: API server 설정에서 --encryption-provider-config 적용 여부를 확인"
    return
  fi

  args="$(get_pod_args kube-system "${apipod}")"
  append "- kube-apiserver pod: ${apipod}"
  append "- args(command+args):"
  append "${args}"
  append ""

  if contains_flag "${args}" "--encryption-provider-config"; then
    result_line "K8S-41" "LOW" "양호" "--encryption-provider-config 플래그가 확인됩니다(암호화 at rest 활성 가능성)." \
      "주의: 구성 파일 내용/대상 리소스(secrets 등)까지는 별도 확인 필요"
  else
    result_line "K8S-41" "HIGH" "취약" "--encryption-provider-config 플래그가 확인되지 않습니다(암호화 at rest 미적용 가능성)." \
      "권고: kube-apiserver에 encryption-provider-config 적용 및 KMS 연계 검토"
  fi
}

check_K8S_50_resource_quota_limits() {
  section "K8S-50" "리소스 제한(Quota/LimitRange, Pod requests/limits)" "MEDIUM"
  append "▶ 증적"
  kcmd "ResourceQuota all namespaces" get resourcequota -A || true
  kcmd "LimitRange all namespaces" get limitrange -A || true

  # Namespace coverage (simple heuristic)
  local ns_tmp findings
  ns_tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_ns.$$.$RANDOM")"
  findings="$(mktemp 2>/dev/null || echo "/tmp/k8s_rq_find.$$.$RANDOM")"
  : > "${findings}"

  if "${KUBECTL[@]}" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null > "${ns_tmp}"; then
    while read -r ns; do
      [ -z "${ns}" ] && continue
      is_system_ns "${ns}" && continue

      local pod_cnt rq_cnt lr_cnt
      pod_cnt="$("${KUBECTL[@]}" -n "${ns}" get pods --no-headers 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"
      rq_cnt="$("${KUBECTL[@]}" -n "${ns}" get resourcequota --no-headers 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"
      lr_cnt="$("${KUBECTL[@]}" -n "${ns}" get limitrange --no-headers 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"

      if [ "${pod_cnt}" -gt 0 ] && [ "${rq_cnt}" -eq 0 ] && [ "${lr_cnt}" -eq 0 ]; then
        echo "${ns}  pods=${pod_cnt}  resourcequota=0  limitrange=0" >> "${findings}"
      fi
    done < "${ns_tmp}"
  fi

  append "▶ Quota/LimitRange 미설정(파드 존재) 네임스페이스(상위 ${MAX_FINDINGS}개)"
  if [ -s "${findings}" ]; then
    sed -n "1,${MAX_FINDINGS}p" "${findings}" >> "${OUTFILE}"
    append ""
    result_line "K8S-50" "MEDIUM" "취약" "일부 네임스페이스는 파드가 존재하나 Quota/LimitRange가 없습니다." \
      "권고: 네임스페이스별 기본 Quota/LimitRange 적용 및 워크로드별 requests/limits 표준화"
  else
    append "(해당 없음)"
    append ""
    result_line "K8S-50" "LOW" "정보" "Quota/LimitRange 미설정 네임스페이스가 즉시 식별되지는 않았습니다(또는 권한/환경 제한)."
  fi

  rm -f "${ns_tmp}" "${findings}" 2>/dev/null || true
}

check_K8S_60_image_security() {
  section "K8S-60" "이미지 보안(레지스트리 출처/태그/고정(digest) 여부)" "HIGH"
  append "▶ 증적"

  local tmp
  tmp="$(mktemp 2>/dev/null || echo "/tmp/k8s_images.$$.$RANDOM")"
  if ! "${KUBECTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{";"}{end}{"\n"}{end}' \
      2>/dev/null > "${tmp}"; then
    result_line "K8S-60" "HIGH" "수동 점검 필요" "Pod 이미지 목록 조회 실패."
    rm -f "${tmp}" 2>/dev/null || true
    return
  fi

  sed -n "1,${MAX_EVIDENCE_LINES}p" "${tmp}" >> "${OUTFILE}"
  append ""

  # Build allowed list set (comma-separated)
  local allowed_set=""
  if [ -n "${ALLOWED_REGISTRIES}" ]; then
    allowed_set=",$(echo "${ALLOWED_REGISTRIES}" | tr -d ' '),"
  fi

  local findings unapproved latesttag notpinned total
  findings="$(mktemp 2>/dev/null || echo "/tmp/k8s_img_find.$$.$RANDOM")"
  : > "${findings}"
  unapproved=0; latesttag=0; notpinned=0; total=0

  # helper: get registry from image ref
  img_registry() {
    local img="$1"
    # digest pinned?
    # registry heuristic: first segment contains '.' or ':' or is 'localhost'
    local first="${img%%/*}"
    if echo "${img}" | grep -q '@sha256:' 2>/dev/null; then
      echo "${first}"
      return
    fi
    if [ "${first}" = "${img}" ]; then
      # no slash => docker hub library
      echo "docker.io"
      return
    fi
    if echo "${first}" | grep -Eq '\.|:|^localhost$' 2>/dev/null; then
      echo "${first}"
    else
      echo "docker.io"
    fi
  }

  while IFS=$'\t' read -r ns pod images; do
    [ -z "${ns}" ] && continue
    is_system_ns "${ns}" && continue
    for img in $(echo "${images}" | tr ';' ' '); do
      [ -z "${img}" ] && continue
      total=$((total+1))

      local reg
      reg="$(img_registry "${img}")"

      # unapproved registry (if allowlist set)
      if [ -n "${allowed_set}" ]; then
        if ! echo "${allowed_set}" | grep -q ",${reg}," 2>/dev/null; then
          echo "${ns}/${pod}  unapproved-registry=${reg}  image=${img}" >> "${findings}"
          unapproved=$((unapproved+1))
          continue
        fi
      fi

      # tag checks: latest or no tag (excluding digest-pinned)
      if ! echo "${img}" | grep -q '@sha256:' 2>/dev/null; then
        # find last segment after slash
        local last="${img##*/}"
        # tag is after last ':' (but may include port in registry, handled by using last segment)
        if echo "${last}" | grep -q ':' 2>/dev/null; then
          local tag="${last##*:}"
          if [ "${tag}" = "latest" ]; then
            echo "${ns}/${pod}  latest-tag  image=${img}" >> "${findings}"
            latesttag=$((latesttag+1))
            continue
          fi
        else
          echo "${ns}/${pod}  no-tag  image=${img}" >> "${findings}"
          notpinned=$((notpinned+1))
          continue
        fi
      fi
    done
  done < "${tmp}"

  append "▶ 이미지 위험 징후(상위 ${MAX_FINDINGS}개)"
  if [ -s "${findings}" ]; then
    sed -n "1,${MAX_FINDINGS}p" "${findings}" >> "${OUTFILE}"
  else
    append "(해당 없음)"
  fi
  append ""

  local detail
  detail="$(cat <<EOF
- 비시스템 네임스페이스 기준:
  - 총 이미지 참조 수: ${total}
  - (allowlist 설정 시) 미허용 레지스트리: ${unapproved}
  - latest 태그 사용: ${latesttag}
  - 태그 미지정(no-tag): ${notpinned}

권고:
  - 레지스트리 allowlist(조직 표준) 적용
  - latest/no-tag 지양, digest pinning(@sha256) 권장
  - 이미지 스캔/서명 정책은 Admission(정책엔진)과 연계
EOF
)"
  if [ "${unapproved}" -gt 0 ]; then
    result_line "K8S-60" "HIGH" "취약" "미허용 레지스트리(allowlist 기준) 이미지가 감지됩니다." "${detail}"
  elif [ "${latesttag}" -gt 0 ] || [ "${notpinned}" -gt 0 ]; then
    result_line "K8S-60" "MEDIUM" "취약" "latest 또는 태그 미지정 이미지가 감지됩니다." "${detail}"
  else
    result_line "K8S-60" "LOW" "정보" "이미지 출처/태그/고정 여부를 기록했습니다." "${detail}"
  fi

  rm -f "${tmp}" "${findings}" 2>/dev/null || true
}

check_K8S_70_admission_webhooks() {
  section "K8S-70" "Admission Webhook/정책엔진 존재 여부(Validating/Mutating)" "MEDIUM"
  append "▶ 증적"
  kcmd "ValidatingWebhookConfiguration list" get validatingwebhookconfiguration || true
  kcmd "MutatingWebhookConfiguration list" get mutatingwebhookconfiguration || true

  # Detect common policy engines (CRDs)
  append "▶ 정책엔진(예: Gatekeeper/Kyverno) 흔적(CRD) 탐지"
  kcmd "CRDs (grep gatekeeper/kyverno)" get crd || true

  local crd_out
  crd_out="$("${KUBECTL[@]}" get crd 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"

  if echo "${crd_out}" | grep -Eq 'gatekeeper|constraints\.gatekeeper|kyverno|policies\.kyverno' 2>/dev/null; then
    result_line "K8S-70" "LOW" "정보" "정책엔진(또는 관련 CRD) 흔적이 감지됩니다(정책 적용 현황 추가 점검 권고)."
  else
    result_line "K8S-70" "MEDIUM" "정보" "Admission Webhook은 존재할 수 있으나, 대표 정책엔진 흔적이 명확히 감지되지는 않습니다." \
      "권고: PSS + 정책엔진(Gatekeeper/Kyverno 등)로 이미지/권한/네트워크 정책을 사전 차단"
  fi
}

check_K8S_80_apiserver_security() {
  section "K8S-80" "API Server 보안 설정(가능 범위 내 플래그 기반 점검)" "CRITICAL"
  append "▶ 증적"

  local apipod args
  apipod="$(get_apiserver_pod)"
  if [ -z "${apipod}" ]; then
    result_line "K8S-80" "CRITICAL" "수동 점검 필요" "kube-apiserver Pod를 확인할 수 없습니다(Managed K8s일 수 있음)." \
      "권고: 관리형 서비스 콘솔/문서에서 anonymous-auth, RBAC, audit, encryption 설정을 확인"
    return
  fi

  args="$(get_pod_args kube-system "${apipod}")"
  append "- kube-apiserver pod: ${apipod}"
  append "- args(command+args):"
  append "${args}"
  append ""

  local issues=0 msg=""

  # anonymous auth
  if contains_flag "${args}" "--anonymous-auth=false"; then
    msg="${msg}- anonymous-auth: disabled\n"
  else
    issues=$((issues+1))
    msg="${msg}- anonymous-auth: NOT confirmed disabled (권고: --anonymous-auth=false)\n"
  fi

  # authorization-mode includes RBAC
  if echo "${args}" | grep -Eq -- '--authorization-mode=.*RBAC' 2>/dev/null; then
    msg="${msg}- authorization-mode: RBAC enabled\n"
  else
    issues=$((issues+1))
    msg="${msg}- authorization-mode: RBAC NOT confirmed (권고: RBAC 포함)\n"
  fi

  # profiling
  if contains_flag "${args}" "--profiling=false"; then
    msg="${msg}- profiling: disabled\n"
  else
    msg="${msg}- profiling: not confirmed disabled\n"
  fi

  # insecure-port should not be used (legacy)
  if echo "${args}" | grep -Eq -- '--insecure-port(=|[[:space:]])' 2>/dev/null; then
    issues=$((issues+1))
    msg="${msg}- insecure-port: PRESENT (취약)\n"
  else
    msg="${msg}- insecure-port: not present (good)\n"
  fi

  if [ "${issues}" -gt 0 ]; then
    result_line "K8S-80" "CRITICAL" "취약" "kube-apiserver 보안 플래그에서 리스크 징후가 확인됩니다." "${msg}"
  else
    result_line "K8S-80" "LOW" "정보" "kube-apiserver 플래그 기반 점검 결과를 기록했습니다." "${msg}"
  fi
}

check_K8S_81_audit_logging() {
  section "K8S-81" "감사 로깅(Audit Logging) 설정 여부(가능 범위 내)" "HIGH"
  append "▶ 증적"

  local apipod args
  apipod="$(get_apiserver_pod)"
  if [ -z "${apipod}" ]; then
    result_line "K8S-81" "HIGH" "수동 점검 필요" "kube-apiserver Pod를 확인할 수 없습니다(Managed K8s일 수 있음)." \
      "권고: API 서버 audit 로깅(audit-policy-file, audit-log-path) 설정을 별도 확인"
    return
  fi

  args="$(get_pod_args kube-system "${apipod}")"
  append "- kube-apiserver pod: ${apipod}"
  append "- args(command+args):"
  append "${args}"
  append ""

  local has_path=0 has_policy=0
  if contains_flag "${args}" "--audit-log-path"; then has_path=1; fi
  if contains_flag "${args}" "--audit-policy-file"; then has_policy=1; fi

  if [ "${has_path}" -eq 1 ] && [ "${has_policy}" -eq 1 ]; then
    result_line "K8S-81" "LOW" "양호" "audit-log-path 및 audit-policy-file 플래그가 확인됩니다." \
      "주의: 경로 유효성/보관/권한/전송(SIEM)까지는 별도 점검 권고"
  else
    result_line "K8S-81" "HIGH" "취약" "감사 로깅 설정이 충분히 확인되지 않습니다(audit-log-path/policy-file 미확인)." \
      "권고: API 서버 감사 로깅 활성화 및 정책/보관/회전/중앙수집 체계 점검"
  fi
}

check_K8S_90_etcd_tls() {
  section "K8S-90" "etcd 보안 설정(TLS/인증) 가능 범위 점검" "HIGH"
  append "▶ 증적"

  local etcdpod args
  etcdpod="$(get_etcd_pod)"
  if [ -z "${etcdpod}" ]; then
    result_line "K8S-90" "HIGH" "수동 점검 필요" "etcd Pod를 확인할 수 없습니다(Managed K8s일 수 있음)." \
      "권고: 관리형 서비스/컨트롤플레인 구성에서 etcd 암호화/접근제어/TLS 설정 확인"
    return
  fi

  args="$(get_pod_args kube-system "${etcdpod}")"
  append "- etcd pod: ${etcdpod}"
  append "- args(command+args):"
  append "${args}"
  append ""

  local issues=0 msg=""
  if echo "${args}" | grep -Eq -- '--cert-file=|--key-file=|--trusted-ca-file=' 2>/dev/null; then
    msg="${msg}- client TLS flags: present\n"
  else
    issues=$((issues+1))
    msg="${msg}- client TLS flags: NOT confirmed\n"
  fi
  if echo "${args}" | grep -Eq -- '--peer-cert-file=|--peer-key-file=|--peer-trusted-ca-file=' 2>/dev/null; then
    msg="${msg}- peer TLS flags: present\n"
  else
    msg="${msg}- peer TLS flags: not confirmed\n"
  fi
  if contains_flag "${args}" "--client-cert-auth=true"; then
    msg="${msg}- client-cert-auth: true\n"
  else
    msg="${msg}- client-cert-auth: not confirmed\n"
  fi

  if [ "${issues}" -gt 0 ]; then
    result_line "K8S-90" "HIGH" "취약" "etcd TLS/인증 설정이 충분히 확인되지 않습니다." "${msg}"
  else
    result_line "K8S-90" "LOW" "정보" "etcd 플래그 기반 점검 결과를 기록했습니다." "${msg}"
  fi
}

summary() {
  append "############################################################################"
  append "# Summary"
  append "############################################################################"
  append "- CRITICAL: ${CNT_CRITICAL}"
  append "- HIGH    : ${CNT_HIGH}"
  append "- MEDIUM  : ${CNT_MEDIUM}"
  append "- LOW     : ${CNT_LOW}"
  append "- INFO    : ${CNT_INFO}"
  append "- MANUAL  : ${CNT_MANUAL}"
  append ""
  append "완료 시각: $(date +%Y%m%d_%H%M%S)"
  append ""

  colorize INFO "Output: ${OUTFILE}"
  colorize INFO "Summary: CRITICAL=${CNT_CRITICAL}, HIGH=${CNT_HIGH}, MEDIUM=${CNT_MEDIUM}, LOW=${CNT_LOW}, INFO=${CNT_INFO}, MANUAL=${CNT_MANUAL}"
}

main() {
  banner
  check_K8S_00_preflight
  check_K8S_01_connectivity

  # Core security areas
  check_K8S_10_pss
  check_K8S_11_psp
  check_K8S_12_workload_security_context
  check_K8S_13_serviceaccount_tokens

  check_K8S_20_rbac_cluster_admin
  check_K8S_21_rbac_wildcards

  check_K8S_30_network_policy_coverage

  check_K8S_40_secrets_inventory
  check_K8S_41_encryption_at_rest

  check_K8S_50_resource_quota_limits
  check_K8S_60_image_security

  check_K8S_70_admission_webhooks

  check_K8S_80_apiserver_security
  check_K8S_81_audit_logging
  check_K8S_90_etcd_tls

  summary
}

main "$@"