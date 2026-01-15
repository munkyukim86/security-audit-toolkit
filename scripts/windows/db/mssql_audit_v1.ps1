#requires -Version 5.1
<#
.SYNOPSIS
  Microsoft SQL Server security audit (standalone). Requires SqlServer module for Invoke-Sqlcmd.

.PARAMETER SwId
  Software/System identifier used in report filename.

.PARAMETER ServerInstance
  SQL Server instance (e.g., localhost, localhost\SQLEXPRESS).

.PARAMETER Database
  Database for connection context (default: master).

.PARAMETER Auth
  Auth mode: Windows or Sql.

.PARAMETER SqlUser
  SQL auth user (required if Auth=Sql).
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$ServerInstance = "localhost",
  [string]$Database = "master",
  [ValidateSet("Windows","Sql")][string]$Auth = "Windows",
  [string]$SqlUser = "",
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "KR baseline (operator-tailored) - MSSQL hardening"
$HostName = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__MSSQL`__$DATE`__result.txt"
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
  Microsoft SQL Server 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
실행 호스트: $HostName
ServerInstance: $ServerInstance
Database: $Database
Auth: $Auth
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

Section "MS-00" "사전 점검(SqlServer 모듈/Invoke-Sqlcmd)" "상"
if (-not (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue)) {
  ResultLine "MS-00" "수동" "Invoke-Sqlcmd 미존재. SqlServer 모듈 설치 필요: Install-Module SqlServer -Scope CurrentUser"
  Write-Host "[INFO] 결과 파일: $OUTFILE"
  exit 0
}
ResultLine "MS-00" "양호" "Invoke-Sqlcmd 확인"

$secPwd = $null
if ($Auth -eq "Sql") {
  if (-not $SqlUser) { throw "Auth=Sql이면 -SqlUser 필요" }
  $secPwd = Read-Host "SQL Password" -AsSecureString
}

function Run-Query {
  param([string]$Query)
  try {
    if ($Auth -eq "Windows") {
      return Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $Query -ErrorAction Stop
    } else {
      $cred = New-Object System.Management.Automation.PSCredential($SqlUser,$secPwd)
      return Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $Query -Credential $cred -ErrorAction Stop
    }
  } catch {
    Add-Content $OUTFILE ("[ERROR] Query failed: {0}`r`n{1}`r`n" -f $_.Exception.Message,$Query)
    return $null
  }
}

# MS-01 version
Section "MS-01" "SQL Server 버전" "중"
$v = Run-Query "SELECT @@VERSION AS VersionInfo;"
if ($v) {
  Add-Content $OUTFILE ("▶ @@VERSION`r`n{0}`r`n" -f ($v | Format-Table -AutoSize | Out-String))
  ResultLine "MS-01" "주의" "버전/패치 수준을 조직 기준(CU/GDR)과 비교 권고"
} else {
  ResultLine "MS-01" "수동" "버전 조회 실패"
}

# MS-02 sysadmin list
Section "MS-02" "sysadmin 역할 계정 최소화" "상"
$admins = Run-Query @"
SELECT sp.name AS login_name, sp.type_desc
FROM sys.server_principals sp
JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
JOIN sys.server_principals rp ON srm.role_principal_id = rp.principal_id
WHERE rp.name = 'sysadmin'
ORDER BY sp.name;
"@
if ($admins) {
  Add-Content $OUTFILE ("▶ sysadmin members`r`n{0}`r`n" -f ($admins | Format-Table -AutoSize | Out-String))
  if ($admins.Count -le 3) { ResultLine "MS-02" "주의" "sysadmin 계정 수=$($admins.Count). 업무 필요성/승인/JIT 적용 여부 확인." }
  else { ResultLine "MS-02" "취약" "sysadmin 계정 수 과다=$($admins.Count) (최소화 필요)" }
} else {
  ResultLine "MS-02" "수동" "sysadmin 목록 조회 실패"
}

# MS-03 password policy for SQL logins
Section "MS-03" "SQL 로그인 패스워드 정책 적용" "상"
$logins = Run-Query @"
SELECT name, type_desc, is_policy_checked, is_expiration_checked
FROM sys.sql_logins
ORDER BY name;
"@
if ($logins) {
  Add-Content $OUTFILE ("▶ sys.sql_logins`r`n{0}`r`n" -f ($logins | Format-Table -AutoSize | Out-String))
  $bad = $logins | Where-Object { $_.is_policy_checked -eq 0 -or $_.is_expiration_checked -eq 0 }
  if (-not $bad) { ResultLine "MS-03" "양호" "SQL 로그인에 정책/만료 적용" }
  else { ResultLine "MS-03" "취약" ("정책 미적용 로그인 존재: {0}" -f (($bad | Select-Object -ExpandProperty name) -join ", ")) }
} else {
  ResultLine "MS-03" "수동" "SQL 로그인 정책 조회 실패"
}

# MS-04 xp_cmdshell
Section "MS-04" "xp_cmdshell 비활성화" "상"
$xp = Run-Query "EXEC sp_configure 'xp_cmdshell';"
if ($xp) {
  Add-Content $OUTFILE ("▶ sp_configure xp_cmdshell`r`n{0}`r`n" -f ($xp | Format-Table -AutoSize | Out-String))
  $run = ($xp | Select-Object -First 1).run_value
  if ($run -eq 0) { ResultLine "MS-04" "양호" "xp_cmdshell disabled" }
  else { ResultLine "MS-04" "취약" "xp_cmdshell enabled" }
} else {
  ResultLine "MS-04" "수동" "xp_cmdshell 상태 조회 실패"
}

# MS-05 remote access
Section "MS-05" "원격 접속/네트워크 노출(수동 검토)" "중"
$net = Run-Query "SELECT local_net_address, local_tcp_port, encrypt_option, auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID;"
if ($net) {
  Add-Content $OUTFILE ("▶ dm_exec_connections(current)`r`n{0}`r`n" -f ($net | Format-Table -AutoSize | Out-String))
  ResultLine "MS-05" "주의" "listen 주소/포트, TLS 강제(Force Encryption), 방화벽 정책을 종합적으로 확인"
} else {
  ResultLine "MS-05" "수동" "네트워크 정보 조회 실패"
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
