#requires -Version 5.1
<#
.SYNOPSIS
  Hyper-V host audit (standalone). Requires Hyper-V PowerShell module on the host.

.PARAMETER SwId
  Software/System identifier used in report filename.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$HostName = $env:COMPUTERNAME,
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "KR baseline (operator-tailored) - Hyper-V hardening"
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__HyperV`__$DATE`__result.txt"
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

@"
############################################################################
  Hyper-V Host 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
점검대상: $HostName
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

Section "HV-00" "사전 점검(모듈/권한)" "중"
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
  ResultLine "HV-00" "수동" "Hyper-V PowerShell 모듈 미탑재(호스트에서만 실행 가능)"
  Write-Host "[INFO] 결과 파일: $OUTFILE"
  exit 0
}
Import-Module Hyper-V -ErrorAction Stop
ResultLine "HV-00" "양호" "Hyper-V 모듈 확인"

Section "HV-01" "가상머신 목록/상태" "중"
$vms = Get-VM -ErrorAction SilentlyContinue
Add-Content $OUTFILE ("▶ Get-VM`r`n{0}`r`n" -f ($vms | Select-Object Name, State, Generation, Version | Format-Table -AutoSize | Out-String))
ResultLine "HV-01" "수동" "VM 목록 기반으로 운영 정책(불필요 VM/테스트 VM) 정리 여부 판단"

Section "HV-02" "Gen2 VM Secure Boot 활성화" "상"
$gen2 = $vms | Where-Object { $_.Generation -eq 2 }
if (-not $gen2) {
  ResultLine "HV-02" "주의" "Gen2 VM 없음(또는 조회 실패)"
} else {
  $bad = @()
  foreach ($vm in $gen2) {
    try {
      $fw = Get-VMFirmware -VMName $vm.Name
      if (-not $fw.SecureBoot) { $bad += $vm.Name }
    } catch { $bad += $vm.Name }
  }
  if ($bad.Count -eq 0) { ResultLine "HV-02" "양호" "Gen2 VM Secure Boot 활성" }
  else { ResultLine "HV-02" "취약" ("Secure Boot 비활성/확인불가 VM: {0}" -f ($bad -join ", ")) }
}

Section "HV-03" "vSwitch 구성(불필요 외부 스위치 점검)" "중"
try {
  $sw = Get-VMSwitch
  Add-Content $OUTFILE ("▶ Get-VMSwitch`r`n{0}`r`n" -f ($sw | Select-Object Name, SwitchType, NetAdapterInterfaceDescription | Format-Table -AutoSize | Out-String))
  ResultLine "HV-03" "수동" "External vSwitch 사용 시 연결망/보안장비/분리 정책 확인"
} catch {
  ResultLine "HV-03" "수동" "vSwitch 정보 조회 실패"
}

Section "HV-04" "기본 저장 경로(권한/암호화/백업) 확인" "중"
try {
  $host = Get-VMHost
  Add-Content $OUTFILE ("▶ Get-VMHost`r`n{0}`r`n" -f ($host | Select-Object VirtualHardDiskPath, VirtualMachinePath | Format-Table -AutoSize | Out-String))
  ResultLine "HV-04" "주의" "저장 경로의 NTFS 권한/암호화/백업 정책 확인 권고"
} catch {
  ResultLine "HV-04" "수동" "호스트 설정 조회 실패"
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
