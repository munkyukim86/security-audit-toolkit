#requires -Version 5.1
<#
.SYNOPSIS
  Windows OS security audit (standalone; no common.ps1 dependency)

.PARAMETER SwId
  Software/System identifier used in report filename.

.PARAMETER HostName
  Target hostname label (default: local computer name).

.PARAMETER OutDir
  Output directory (default: current directory).
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
$GUIDE_VER = "KR baseline (KCIS/KISA-style) + Cloud Guide 2024 (operator-tailored)"
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__WinOS`__$DATE`__result.txt"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Section {
  param([string]$Id,[string]$Title,[string]$Severity="")
  Add-Content $OUTFILE ("`r`n============================================================================")
  Add-Content $OUTFILE ("[$Id] $Title")
  if ($Severity) { Add-Content $OUTFILE ("위험도: $Severity") }
  Add-Content $OUTFILE ("============================================================================`r`n")
}
function ResultLine {
  param([string]$Id,[string]$Res,[string]$Details="")
  Add-Content $OUTFILE ("★ [$Id] 점검 결과: $Res")
  Add-Content $OUTFILE ("----------------------------------------------------------------------------")
  if ($Details) { Add-Content $OUTFILE ($Details) }
  Add-Content $OUTFILE ("")
}
function LogInfo { param([string]$Message) Add-Content $OUTFILE ("[INFO] $Message") }

function Get-SecPolValue {
  param([Parameter(Mandatory=$true)][string]$Key)
  $tmp = Join-Path $env:TEMP ("secpol_{0}.cfg" -f ([Guid]::NewGuid().ToString("N")))
  try {
    & secedit /export /cfg $tmp /quiet | Out-Null
    $line = Get-Content $tmp | Where-Object { $_ -match "^\s*$Key\s*=" } | Select-Object -First 1
    if ($null -eq $line) { return $null }
    return ($line -replace "^\s*$Key\s*=\s*", "").Trim()
  } catch {
    return $null
  } finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
  }
}

function Get-NetAccounts {
  $out = & net accounts 2>$null
  return $out
}
function Parse-NetAccountsValue {
  param([string[]]$NetAccountsOutput,[string]$LabelRegex)
  $line = $NetAccountsOutput | Where-Object { $_ -match $LabelRegex } | Select-Object -First 1
  if (-not $line) { return $null }
  # split on ':' then trim
  $parts = $line -split ":"
  if ($parts.Count -lt 2) { return $null }
  return $parts[1].Trim()
}

@"
############################################################################
  Windows OS 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
점검대상: $HostName
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

# helpers to get local users by SID (built-in accounts)
function Get-LocalUserBySidEnding {
  param([int]$Rid)
  try {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
      return Get-LocalUser | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1
    }
    # fallback WMI
    $sidPrefix = (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='Administrator'" -ErrorAction SilentlyContinue | Select-Object -First 1).SID
    if ($sidPrefix) {
      $base = $sidPrefix -replace "-500$",""
      $sid = "$base-$Rid"
      return Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
    }
  } catch { }
  return $null
}

Section "W-01" "기본 Administrator 계정 이름 변경" "상"
$admin = Get-LocalUserBySidEnding -Rid 500
if ($admin -and $admin.Name -ne "Administrator") {
  ResultLine "W-01" "양호" ("기본 관리자 계정명: {0}" -f $admin.Name)
} elseif ($admin) {
  ResultLine "W-01" "취약" "기본 관리자 계정명이 'Administrator'로 유지됨"
} else {
  ResultLine "W-01" "수동" "기본 관리자 계정 확인 실패(권한/환경)"
}

Section "W-02" "Guest 계정 비활성화" "상"
$guest = Get-LocalUserBySidEnding -Rid 501
if ($guest -and ($guest.Enabled -eq $false)) {
  ResultLine "W-02" "양호" ("Guest({0}) 비활성화" -f $guest.Name)
} elseif ($guest -and ($guest.Enabled -eq $true)) {
  ResultLine "W-02" "취약" ("Guest({0}) 활성화" -f $guest.Name)
} else {
  ResultLine "W-02" "수동" "Guest 계정 확인 실패(권한/환경)"
}

Section "W-03" "불필요한 로컬 계정 점검" "상"
try {
  if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.SID.Value -notmatch "-500$" -and $_.SID.Value -notmatch "-501$" }
    if ($users.Count -eq 0) {
      ResultLine "W-03" "양호" "활성 로컬 계정(기본 제외) 없음"
    } else {
      $details = ($users | Select-Object Name, Enabled | Format-Table -AutoSize | Out-String)
      ResultLine "W-03" "주의" ("활성 로컬 계정 존재(업무 필요성 확인):`r`n{0}" -f $details)
    }
  } else {
    ResultLine "W-03" "수동" "Get-LocalUser 미지원. (구버전 OS는 net user 기반 수동 점검)"
  }
} catch {
  ResultLine "W-03" "수동" ("계정 목록 조회 실패: {0}" -f $_.Exception.Message)
}

# net accounts for policy
$na = Get-NetAccounts

Section "W-04" "계정 잠금 임계값(<=5) 설정" "상"
$lockout = Parse-NetAccountsValue -NetAccountsOutput $na -LabelRegex "잠금 임계값|Lockout threshold"
if ($lockout -match "(\d+)") {
  $val = [int]$Matches[1]
  if ($val -gt 0 -and $val -le 5) { ResultLine "W-04" "양호" "잠금 임계값: $val" }
  else { ResultLine "W-04" "취약" "잠금 임계값: $val (0 또는 5 초과)" }
} else {
  ResultLine "W-04" "수동" "net accounts에서 임계값 파싱 실패"
}

Section "W-05" "패스워드 복잡도 정책" "상"
$complexity = Get-SecPolValue -Key "PasswordComplexity"
if ($complexity -eq "1") { ResultLine "W-05" "양호" "PasswordComplexity=1" }
elseif ($complexity -eq "0") { ResultLine "W-05" "취약" "PasswordComplexity=0" }
else { ResultLine "W-05" "수동" "PasswordComplexity 값 확인 실패(권한/환경)" }

Section "W-06" "패스워드 최소 길이(>=8)" "상"
$minLen = Parse-NetAccountsValue -NetAccountsOutput $na -LabelRegex "최소 암호 길이|Minimum password length"
if ($minLen -match "(\d+)") {
  $val = [int]$Matches[1]
  if ($val -ge 8) { ResultLine "W-06" "양호" "최소 길이: $val" }
  else { ResultLine "W-06" "취약" "최소 길이: $val (8 미만)" }
} else {
  ResultLine "W-06" "수동" "net accounts에서 최소 길이 파싱 실패"
}

Section "W-07" "패스워드 최대 사용 기간(<=90일)" "상"
$maxAge = Parse-NetAccountsValue -NetAccountsOutput $na -LabelRegex "최대 암호 사용 기간|Maximum password age"
if ($maxAge -match "(\d+)") {
  $val = [int]$Matches[1]
  if ($val -le 90 -and $val -gt 0) { ResultLine "W-07" "양호" "최대 사용 기간: $val 일" }
  else { ResultLine "W-07" "주의" "최대 사용 기간: $val 일 (조직 정책 확인)" }
} else {
  ResultLine "W-07" "수동" "net accounts에서 최대 기간 파싱 실패"
}

Section "W-08" "Windows 방화벽 활성화" "상"
try {
  $profiles = & netsh advfirewall show allprofiles 2>$null
  Add-Content $OUTFILE ("▶ netsh advfirewall show allprofiles`r`n{0}`r`n" -f ($profiles -join "`r`n"))
  if ($profiles -match "State\s+ON") {
    ResultLine "W-08" "주의" "프로파일별 ON 여부를 확인(전체 ON 권고)"
  } else {
    ResultLine "W-08" "취약" "방화벽 State ON 확인 불가"
  }
} catch {
  ResultLine "W-08" "수동" ("방화벽 상태 확인 실패: {0}" -f $_.Exception.Message)
}

Section "W-09" "SMBv1 비활성화" "중"
try {
  $smb1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
  if ($smb1 -and $smb1.SMB1 -eq 0) { ResultLine "W-09" "양호" "SMB1=0" }
  elseif ($smb1) { ResultLine "W-09" "취약" ("SMB1={0}" -f $smb1.SMB1) }
  else { ResultLine "W-09" "수동" "SMB1 레지스트리 값 없음(Windows 기능 상태로 별도 확인 필요)" }
} catch {
  ResultLine "W-09" "수동" ("SMB1 확인 실패: {0}" -f $_.Exception.Message)
}

Section "W-10" "원격 데스크톱(NLA) 설정" "중"
try {
  $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue
  if ($nla -and $nla.UserAuthentication -eq 1) { ResultLine "W-10" "양호" "NLA(UserAuthentication)=1" }
  else { ResultLine "W-10" "주의" "NLA(UserAuthentication) 확인 불가 또는 미설정" }
} catch {
  ResultLine "W-10" "수동" ("RDP 설정 확인 실패: {0}" -f $_.Exception.Message)
}

Section "W-11" "감사 정책(auditpol) 활성화" "중"
try {
  $ap = & auditpol /get /category:* 2>$null
  Add-Content $OUTFILE ("▶ auditpol /get /category:*`r`n{0}`r`n" -f ($ap -join "`r`n"))
  ResultLine "W-11" "수동" "auditpol 출력 기반으로 로그 수집 범위/중요 이벤트 활성화 여부 판단"
} catch {
  ResultLine "W-11" "수동" "auditpol 실행 실패(권한/환경)"
}

Section "W-12" "기본 공유(관리 공유) 노출" "중"
try {
  $shares = Get-WmiObject Win32_Share | Select-Object Name, Path, Description
  Add-Content $OUTFILE ("▶ Win32_Share`r`n{0}`r`n" -f ($shares | Format-Table -AutoSize | Out-String))
  ResultLine "W-12" "주의" "관리 공유(C$, ADMIN$ 등)는 기본값. 외부 노출/접근제어/SMB 방화벽 정책으로 통제 권고"
} catch {
  ResultLine "W-12" "수동" "공유 조회 실패"
}

Section "요약" "점검 요약" ""
$good = (Select-String -Path $OUTFILE -Pattern "점검 결과: 양호").Count
$bad  = (Select-String -Path $OUTFILE -Pattern "점검 결과: 취약").Count
$warn = (Select-String -Path $OUTFILE -Pattern "점검 결과: 주의").Count
$manual = (Select-String -Path $OUTFILE -Pattern "점검 결과: 수동").Count
Add-Content $OUTFILE ("양호: $good`r`n취약: $bad`r`n주의: $warn`r`n수동: $manual`r`n")

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
