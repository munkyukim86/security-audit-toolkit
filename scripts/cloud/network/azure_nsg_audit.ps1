#requires -Version 5.1
<#
.SYNOPSIS
  Azure NSG audit using Azure CLI (standalone). Requires 'az' login and permissions.

.PARAMETER SwId
  Software/System identifier used in report filename.

.PARAMETER SubscriptionId
  Optional subscription to target (az account set).

.PARAMETER OutDir
  Output directory.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$SubscriptionId = "",
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "Cloud Guide - Azure network exposure checks (operator-tailored)"
$HostName = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__Azure_NSG`__$DATE`__result.txt"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Section { param([string]$Id,[string]$Title,[string]$Severity="")
  Add-Content $OUTFILE ("`r`n============================================================================")
  Add-Content $OUTFILE ("[$Id] $Title")
  if ($Severity) { Add-Content $OUTFILE ("위험도: $Severity") }
  Add-Content $OUTFILE ("============================================================================`r`n")
}
function ResultLine { param([string]$Id,[string]$Res,[string]$Details="")
  Add-Content $OUTFILE ("★ [$Id] 점검 결과: $Res")
  Add-Content $OUTFILE ("----------------------------------------------------------------------------")
  if ($Details) { Add-Content $OUTFILE $Details }
  Add-Content $OUTFILE ""
}
function AppendCmd {
  param([string]$Label,[string]$CommandLine)
  Add-Content $OUTFILE ("▶ {0}" -f $Label)
  Add-Content $OUTFILE ("$ {0}`r`n" -f $CommandLine)
}

@"
############################################################################
  Azure NSG 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
실행 호스트: $HostName
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

Section "AZ-00" "사전 점검(Azure CLI)" "상"
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  ResultLine "AZ-00" "수동" "Azure CLI(az) 미설치"
  Write-Host "[INFO] 결과 파일: $OUTFILE"
  exit 0
}

if ($SubscriptionId) {
  AppendCmd "az account set" ("az account set --subscription {0}" -f $SubscriptionId)
  & az account set --subscription $SubscriptionId | Out-Null
}

# list NSGs
AppendCmd "az network nsg list" "az network nsg list -o json"
$nsgJson = & az network nsg list -o json 2>$null
if (-not $nsgJson) { ResultLine "AZ-00" "수동" "NSG 목록 조회 실패(로그인/권한/구독 확인)"; exit 0 }
$nsgs = $nsgJson | ConvertFrom-Json
ResultLine "AZ-00" "양호" ("NSG 개수: {0}" -f $nsgs.Count)

Section "AZ-01" "인터넷 공개 Inbound(민감 포트)" "상"
$sensitivePorts = @(22,3389,3306,5432,27017,1433,6379,9200,5601)
$findings = @()

foreach ($nsg in $nsgs) {
  $rg = $nsg.resourceGroup
  $name = $nsg.name
  AppendCmd "NSG show" ("az network nsg show -g {0} -n {1} -o json" -f $rg,$name)
  $detail = (& az network nsg show -g $rg -n $name -o json 2>$null) | ConvertFrom-Json
  foreach ($rule in $detail.securityRules) {
    if ($rule.direction -ne "Inbound" -or $rule.access -ne "Allow") { continue }
    $src = $rule.sourceAddressPrefix
    $srcs = @()
    if ($src) { $srcs += $src }
    if ($rule.sourceAddressPrefixes) { $srcs += $rule.sourceAddressPrefixes }
    $isInternet = $false
    foreach ($s in $srcs) {
      if ($s -eq "*" -or $s -match "^0\.0\.0\.0/0$" -or $s -match "^::/0$" -or $s -match "Internet") { $isInternet = $true }
    }
    if (-not $isInternet) { continue }

    $dport = $rule.destinationPortRange
    $dports = @()
    if ($dport) { $dports += $dport }
    if ($rule.destinationPortRanges) { $dports += $rule.destinationPortRanges }

    foreach ($p in $dports) {
      if ($p -eq "*" -or $p -eq "0-65535") {
        $findings += "{0}/{1}: rule={2} ports={3} source={4}" -f $rg,$name,$rule.name,$p,($srcs -join ",")
      } elseif ($p -match "^(\d+)$") {
        if ($sensitivePorts -contains [int]$Matches[1]) {
          $findings += "{0}/{1}: rule={2} ports={3} source={4}" -f $rg,$name,$rule.name,$p,($srcs -join ",")
        }
      } elseif ($p -match "^(\d+)-(\d+)$") {
        $from = [int]$Matches[1]; $to = [int]$Matches[2]
        foreach ($sp in $sensitivePorts) { if ($sp -ge $from -and $sp -le $to) { $findings += "{0}/{1}: rule={2} ports={3} source={4}" -f $rg,$name,$rule.name,$p,($srcs -join ","); break } }
      }
    }
  }
}

if ($findings.Count -eq 0) {
  ResultLine "AZ-01" "양호" "인터넷 공개 Inbound 민감 포트 미탐지"
} else {
  ResultLine "AZ-01" "취약" ("인터넷 공개 Inbound 발견:`r`n- " + ($findings -join "`r`n- "))
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
