<#
.SYNOPSIS
  Azure Application Gateway WAF / WAF Policy audit script

.DESCRIPTION
  Audits whether Azure Application Gateway has WAF enabled, is in Prevention mode,
  uses managed rules (OWASP), and has diagnostics enabled.

.VERSION
  v0.2.0 (2026-01-10)

.BASELINE
  KISA 2021 / Cloud Vulnerability Guide 2024 (InfoSec Systems) / TLP Network Guide 2024

.REQUIREMENTS
  - PowerShell 5.1+ or PowerShell 7+
  - Azure CLI (az)
  - Logged-in Azure session: az login
#>

param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$AppGwName,
  [Parameter(Mandatory=$false)][string]$OutDir = (Get-Location).Path,
  [Parameter(Mandatory=$false)][string]$WafPolicyName
)

$ErrorActionPreference = "Stop"

$GUIDE_VER = "KISA 2021 / Cloud Guide 2024 / TLP Network 2024"
$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$TargetHost = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir "${SwId}__${TargetHost}__AzureAppGwWAF__${DATE}__result.txt"

function Section {
  param([string]$Id,[string]$Title,[string]$Severity)
  "============================================================================`n[$Id] $Title`n위험도: $Severity`n============================================================================`n" | Add-Content -Encoding UTF8 $OUTFILE
}

function ResultLine {
  param([string]$Id,[string]$Result,[string]$Details)
  "★ [$Id] 점검 결과: $Result`n----------------------------------------------------------------------------`n$Details`n" | Add-Content -Encoding UTF8 $OUTFILE
}

function LogInfo {
  param([string]$Message)
  "[INFO] $Message" | Add-Content -Encoding UTF8 $OUTFILE
}

"############################################################################
  Azure Application Gateway WAF 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
점검대상: Azure (Subscription: $SubscriptionId / RG: $ResourceGroup / AppGw: $AppGwName)
SW ID: $SwId
############################################################################
" | Out-File -Encoding UTF8 -FilePath $OUTFILE

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw "Azure CLI (az) not found. Install Azure CLI first."
}

# Ensure subscription context
az account set --subscription $SubscriptionId | Out-Null

# Fetch Application Gateway
$appGwJson = az network application-gateway show -g $ResourceGroup -n $AppGwName -o json
$appGw = $appGwJson | ConvertFrom-Json

$resourceId = $appGw.id
$wafInline = $appGw.webApplicationFirewallConfiguration
$firewallPolicyId = $null
if ($appGw.firewallPolicy -and $appGw.firewallPolicy.id) {
  $firewallPolicyId = $appGw.firewallPolicy.id
}

Section "AZWAF-01" "WAF 활성화 여부" "상"
$enabled = $false
if ($wafInline -and $wafInline.enabled -eq $true) { $enabled = $true }
if ($firewallPolicyId) { $enabled = $true }

if ($enabled) {
  ResultLine "AZWAF-01" "양호" "WAF가 활성화되어 있습니다. (Inline: $($wafInline.enabled), Policy: $([bool]$firewallPolicyId))"
} else {
  ResultLine "AZWAF-01" "취약" "WAF 비활성화 또는 정책 연결 없음"
}

Section "AZWAF-02" "WAF 모드(Prevention 권장)" "상"
$mode = $null
if ($wafInline -and $wafInline.firewallMode) { $mode = $wafInline.firewallMode }

# If policy exists, mode may be defined in policy settings
if (-not $mode -and $firewallPolicyId) {
  try {
    # WAF policy name can be provided, or derived from resourceId suffix
    $policyNameToUse = $WafPolicyName
    if (-not $policyNameToUse) {
      # attempt best-effort extraction: .../applicationGatewayWebApplicationFirewallPolicies/<name>
      $policyNameToUse = ($firewallPolicyId -split "/")[-1]
    }

    $policyJson = az network application-gateway waf-policy show -g $ResourceGroup -n $policyNameToUse -o json
    $policy = $policyJson | ConvertFrom-Json
    if ($policy.policySettings -and $policy.policySettings.mode) { $mode = $policy.policySettings.mode }
  } catch {
    LogInfo "WAF Policy 조회 실패 (수동 확인 권고): $($_.Exception.Message)"
  }
}

if ($mode -eq "Prevention") {
  ResultLine "AZWAF-02" "양호" "WAF 모드: Prevention"
} elseif ($mode) {
  ResultLine "AZWAF-02" "주의" "WAF 모드: $mode (Prevention 권장)"
} else {
  ResultLine "AZWAF-02" "수동" "WAF 모드 정보를 확인할 수 없습니다. (Inline/Policy 설정 확인 필요)"
}

Section "AZWAF-03" "Managed Rules(OWASP 등) 적용 여부" "상"
$managedRuleSummary = ""
$hasManagedRules = $false

try {
  $policyNameToUse = $WafPolicyName
  if (-not $policyNameToUse -and $firewallPolicyId) {
    $policyNameToUse = ($firewallPolicyId -split "/")[-1]
  }

  if ($policyNameToUse) {
    $policyJson = az network application-gateway waf-policy show -g $ResourceGroup -n $policyNameToUse -o json
    $policy = $policyJson | ConvertFrom-Json

    if ($policy.managedRules -and $policy.managedRules.managedRuleSets) {
      $sets = $policy.managedRules.managedRuleSets
      $hasManagedRules = ($sets.Count -gt 0)
      $managedRuleSummary = ($sets | ForEach-Object { "$($_.ruleSetType) $($_.ruleSetVersion)" }) -join ", "
    }
  } elseif ($wafInline) {
    # Inline WAF config: ruleSetType/ruleSetVersion may exist
    if ($wafInline.ruleSetType -and $wafInline.ruleSetVersion) {
      $hasManagedRules = $true
      $managedRuleSummary = "$($wafInline.ruleSetType) $($wafInline.ruleSetVersion)"
    }
  }
} catch {
  LogInfo "Managed rules 정보 조회 실패: $($_.Exception.Message)"
}

if ($hasManagedRules) {
  ResultLine "AZWAF-03" "양호" "Managed rules 적용: $managedRuleSummary"
} else {
  ResultLine "AZWAF-03" "취약" "Managed rules(OWASP 등) 적용을 확인할 수 없습니다. (WAF 정책/Inline 설정 확인 필요)"
}

Section "AZWAF-04" "진단 로그/모니터링 설정" "상"
try {
  $diagJson = az monitor diagnostic-settings list --resource $resourceId -o json
  $diag = $diagJson | ConvertFrom-Json
  if ($diag.value -and $diag.value.Count -gt 0) {
    $targets = $diag.value | ForEach-Object { $_.name }
    ResultLine "AZWAF-04" "양호" ("Diagnostic settings 존재: " + ($targets -join ", "))
  } else {
    ResultLine "AZWAF-04" "취약" "Diagnostic settings 미설정 (Firewall/Access 로그 전송 미구성)"
  }
} catch {
  ResultLine "AZWAF-04" "수동" "Diagnostic settings 조회 실패. 권한/리소스ID를 확인하세요."
}

Section "AZWAF-05" "Custom Rules/예외 정책 검토" "중"
try {
  $policyNameToUse = $WafPolicyName
  if (-not $policyNameToUse -and $firewallPolicyId) {
    $policyNameToUse = ($firewallPolicyId -split "/")[-1]
  }
  if ($policyNameToUse) {
    $policyJson = az network application-gateway waf-policy show -g $ResourceGroup -n $policyNameToUse -o json
    $policy = $policyJson | ConvertFrom-Json
    $customRules = $policy.customRules
    if ($customRules -and $customRules.Count -gt 0) {
      $names = $customRules | ForEach-Object { $_.name }
      ResultLine "AZWAF-05" "주의" ("Custom rules 존재 (예외/우회 가능성 포함): " + ($names -join ", ") + " (정책 적정성 수동 검토 권고)")
    } else {
      ResultLine "AZWAF-05" "양호" "Custom rules 없음 (필요 시 정책에 따라 추가)"
    }
  } else {
    ResultLine "AZWAF-05" "수동" "WAF policy 기반 여부 확인 필요 (Inline만 사용하는 경우 별도 검토)"
  }
} catch {
  ResultLine "AZWAF-05" "수동" "Custom rules 조회 실패."
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
