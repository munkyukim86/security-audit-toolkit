#requires -Version 5.1
<#
.SYNOPSIS
  Active Directory domain audit (standalone). Requires RSAT ActiveDirectory module.

.PARAMETER SwId
  Software/System identifier used in report filename.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "KR baseline (operator-tailored) - AD hardening"
$HostName = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__ADDomain`__$DATE`__result.txt"
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
  Active Directory Domain 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
실행 호스트: $HostName
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

Section "AD-00" "사전 점검(ActiveDirectory 모듈)" "상"
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  ResultLine "AD-00" "수동" "ActiveDirectory 모듈(보통 RSAT) 미설치. 도메인 컨트롤러/관리 서버에서 실행 필요."
  Write-Host "[INFO] 결과 파일: $OUTFILE"
  exit 0
}
Import-Module ActiveDirectory -ErrorAction Stop
ResultLine "AD-00" "양호" "ActiveDirectory 모듈 확인"

Section "AD-01" "도메인 기본 패스워드/잠금 정책" "상"
try {
  $pol = Get-ADDefaultDomainPasswordPolicy
  Add-Content $OUTFILE ("▶ Get-ADDefaultDomainPasswordPolicy`r`n{0}`r`n" -f ($pol | Format-List | Out-String))
  $ok = ($pol.MinPasswordLength -ge 8) -and ($pol.PasswordComplexityEnabled -eq $true)
  if ($ok) { ResultLine "AD-01" "주의" "기본 정책이 최소 길이/복잡도 기준 충족. 최대사용기간/Lockout 세부는 조직 기준으로 평가." }
  else { ResultLine "AD-01" "취약" "기본 정책이 최소 길이(>=8) 또는 복잡도 활성화 기준 미충족" }
} catch {
  ResultLine "AD-01" "수동" ("정책 조회 실패: {0}" -f $_.Exception.Message)
}

Section "AD-02" "Domain Admins 멤버 최소화" "상"
try {
  $da = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, objectClass, SamAccountName
  Add-Content $OUTFILE ("▶ Domain Admins members`r`n{0}`r`n" -f ($da | Format-Table -AutoSize | Out-String))
  if ($da.Count -le 5) { ResultLine "AD-02" "주의" "Domain Admins 멤버 수: $($da.Count). 업무 필요성/승인/임시권한(JIT) 적용 여부 확인 권고." }
  else { ResultLine "AD-02" "취약" "Domain Admins 멤버 수 과다: $($da.Count) (최소화 필요)" }
} catch {
  ResultLine "AD-02" "수동" ("Domain Admins 조회 실패: {0}" -f $_.Exception.Message)
}

Section "AD-03" "Protected Users 그룹 활용" "중"
try {
  $pu = Get-ADGroupMember -Identity "Protected Users" -Recursive -ErrorAction SilentlyContinue
  if ($pu) {
    Add-Content $OUTFILE ("▶ Protected Users members`r`n{0}`r`n" -f ($pu | Select-Object Name, SamAccountName, objectClass | Format-Table -AutoSize | Out-String))
    ResultLine "AD-03" "주의" "관리자/중요 계정의 Protected Users 적용 여부 및 영향도 검토 권고"
  } else {
    ResultLine "AD-03" "주의" "Protected Users 그룹 멤버 없음(중요 계정 적용 여부 검토 권고)"
  }
} catch {
  ResultLine "AD-03" "수동" "Protected Users 조회 실패"
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
