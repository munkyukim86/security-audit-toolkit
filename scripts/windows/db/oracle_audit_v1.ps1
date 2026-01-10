<#
.SYNOPSIS
  Oracle DB audit wrapper (Windows)

.DESCRIPTION
  Executes the bundled legacy SQL*Plus audit script (IGLOO v3.2) and stores evidence files.

  - Mode OSAuth (default): uses sqlplus "/ as sysdba"
  - Mode Login: prompts for password and uses USER/PASS@TNS

.PARAMETER SwId
  점검ID (예: SW00001234)

.PARAMETER OutDir
  결과 저장 경로(기본: 현재 경로)

.PARAMETER Mode
  OSAuth | Login

.PARAMETER User
  Login 모드에서 사용할 DB 사용자

.PARAMETER Tns
  Login 모드에서 사용할 TNS 별칭/접속 문자열

.PARAMETER SqlVersion
  auto | 10g | 11g

.PARAMETER SqlFile
  번들 SQL 대신 사용자 지정 SQL 경로 사용
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$OutDir = (Get-Location).Path,
  [ValidateSet("OSAuth","Login")][string]$Mode = "OSAuth",
  [string]$User = "",
  [string]$Tns = "",
  [ValidateSet("auto","10g","11g")][string]$SqlVersion = "auto",
  [string]$SqlFile = ""
)

$ErrorActionPreference = "Stop"
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$hostName = $env:COMPUTERNAME
$resultsDir = Join-Path $OutDir "results"
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

$outFile = Join-Path $resultsDir ("{0}__{1}__OracleDB__{2}__rpt.txt" -f $SwId,$hostName,$ts)
"Security Audit Toolkit Report`nComponent: OracleDB`nSW_ID: $SwId`nHost: $hostName`nGenerated: $ts`n" | Out-File -Encoding utf8 $outFile

function Add-Section([string]$Id,[string]$Title){
  "`n===============================================================================`n■ [$Id] $Title`n===============================================================================`n" | Out-File -Append -Encoding utf8 $outFile
}
function Add-Result([string]$Id,[string]$Res,[string]$Details=""){
  $tag = switch ($Res) { "양호" {"[OK]"} "취약" {"[VULN]"} default {"[INFO]"} }
  if ($Details) { "$tag $Id - $Details" } else { "$tag $Id" } | Out-File -Append -Encoding utf8 $outFile
}

Add-Section "ORA-00" "사전 점검(sqlplus)"
$sqlplus = Get-Command "sqlplus" -ErrorAction SilentlyContinue
if (-not $sqlplus) {
  Add-Result "ORA-00" "취약" "sqlplus 미설치(Oracle Client 필요). 수동으로 SQL 스크립트 실행 후 증적 첨부"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}
Add-Result "ORA-00" "양호" $sqlplus.Source

# Resolve SQL path
$scriptRoot = $PSScriptRoot
$resDir = Resolve-Path (Join-Path $scriptRoot "..\..\resources\db\oracle") -ErrorAction SilentlyContinue
if (-not $resDir) {
  Add-Result "ORA-00" "취약" "리소스 디렉터리 미탐지: scripts\resources\db\oracle"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}
if ($SqlFile) {
  $sqlPath = $SqlFile
} else {
  $sqlPath = switch ($SqlVersion) {
    "10g" { Join-Path $resDir "IGLOO_oracle_10g_WIN_v3.2_IGCT.sql" }
    "11g" { Join-Path $resDir "IGLOO_oracle_11g_WIN_v3.2_IGCT.sql" }
    default { Join-Path $resDir "IGLOO_oracle_11g_WIN_v3.2_IGCT.sql" }
  }
}
if (-not (Test-Path $sqlPath)) {
  Add-Result "ORA-00" "취약" "SQL 스크립트 파일을 찾을 수 없음: $sqlPath"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}

Add-Section "ORA-01" "점검 실행(증적 수집)"
$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ("oracle_audit_{0}" -f [guid]::NewGuid().ToString())) 
$consoleOut = Join-Path $tmp.FullName "sqlplus_console.out"

try {
  Push-Location $OutDir
  if ($Mode -eq "OSAuth") {
    & $sqlplus.Source "-s" "/ as sysdba" "@$sqlPath" *>&1 | Out-File -Encoding utf8 $consoleOut
  } else {
    if (-not $User -or -not $Tns) { throw "Mode=Login requires -User and -Tns" }
    $sec = Read-Host ("Oracle password for {0}@{1} (leave empty for none)" -f $User,$Tns) -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $pwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null

    $loginSql = Join-Path $tmp.FullName "login.sql"
    @"
connect $User/$1@$Tns
@$sqlPath
exit
"@ | Out-File -Encoding ascii $loginSql

    & $sqlplus.Source "-s" "/nolog" "@$loginSql" $pwd *>&1 | Out-File -Encoding utf8 $consoleOut
  }
  Add-Result "ORA-01" "점검완료" "sqlplus 실행 완료(콘솔 출력/스풀 파일 확인)"
}
catch {
  Add-Result "ORA-01" "수동" $_.Exception.Message
}
finally {
  Pop-Location
}

"-----[sqlplus console output begin]-----" | Out-File -Append -Encoding utf8 $outFile
Get-Content $consoleOut -ErrorAction SilentlyContinue | Select-Object -First 2000 | Out-File -Append -Encoding utf8 $outFile
"-----[sqlplus console output end]-----" | Out-File -Append -Encoding utf8 $outFile

# Locate and normalize spool file produced by SQL (oracle_*_yymmdd.txt)
$yymmdd = Get-Date -Format "yyMMdd"
$spool = Get-ChildItem -Path $OutDir -Filter ("oracle_*_{0}.txt" -f $yymmdd) -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($spool) {
  $dest = Join-Path $resultsDir ("{0}__{1}__OracleDB__{2}__spool.txt" -f $SwId,$hostName,$ts)
  Move-Item -Force $spool.FullName $dest
  Add-Result "ORA-01" "점검완료" ("Spool saved: {0}" -f $dest)
} else {
  Add-Result "ORA-01" "수동" ("스풀 파일 자동 탐지 실패(oracle_*_{0}.txt). OutDir에서 파일 확인" -f $yymmdd)
}

Add-Section "ORA-99" "후속 조치"
Add-Result "ORA-99" "수동" "스풀 파일(상세 증적) 기반으로 계정/권한/감사/암호화 설정을 조직 기준서에 따라 판정"

Remove-Item -Recurse -Force $tmp.FullName -ErrorAction SilentlyContinue
Write-Host "[INFO] 완료: $outFile"
