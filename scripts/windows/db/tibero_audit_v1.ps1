<#
.SYNOPSIS
  Tibero DB audit wrapper (Windows)

.DESCRIPTION
  Executes the bundled legacy tbsql audit script (IGLOO v3.2) and stores evidence files.

.PARAMETER SwId
  점검ID (예: SW00001234)

.PARAMETER OutDir
  결과 저장 경로(기본: 현재 경로)

.PARAMETER User
  DB 사용자

.PARAMETER Tns
  TNS 별칭/접속 문자열

.PARAMETER SqlVariant
  auto | tibero5 | tibero5sp1

.PARAMETER SqlFile
  번들 SQL 대신 사용자 지정 SQL 경로 사용
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$OutDir = (Get-Location).Path,
  [Parameter(Mandatory=$true)][string]$User,
  [Parameter(Mandatory=$true)][string]$Tns,
  [ValidateSet("auto","tibero5","tibero5sp1")][string]$SqlVariant = "auto",
  [string]$SqlFile = ""
)

$ErrorActionPreference = "Stop"
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$hostName = $env:COMPUTERNAME
$resultsDir = Join-Path $OutDir "results"
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

$outFile = Join-Path $resultsDir ("{0}__{1}__TiberoDB__{2}__rpt.txt" -f $SwId,$hostName,$ts)
"Security Audit Toolkit Report`nComponent: TiberoDB`nSW_ID: $SwId`nHost: $hostName`nGenerated: $ts`n" | Out-File -Encoding utf8 $outFile

function Add-Section([string]$Id,[string]$Title){
  "`n===============================================================================`n■ [$Id] $Title`n===============================================================================`n" | Out-File -Append -Encoding utf8 $outFile
}
function Add-Result([string]$Id,[string]$Res,[string]$Details=""){
  $tag = switch ($Res) { "양호" {"[OK]"} "취약" {"[VULN]"} default {"[INFO]"} }
  if ($Details) { "$tag $Id - $Details" } else { "$tag $Id" } | Out-File -Append -Encoding utf8 $outFile
}

Add-Section "TIB-00" "사전 점검(tbsql)"
$tbsql = Get-Command "tbsql" -ErrorAction SilentlyContinue
if (-not $tbsql) {
  Add-Result "TIB-00" "취약" "tbsql 미설치(Tibero Client 필요). 수동으로 SQL 스크립트 실행 후 증적 첨부"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}
Add-Result "TIB-00" "양호" $tbsql.Source

# Resolve SQL path
$scriptRoot = $PSScriptRoot
$resDir = Resolve-Path (Join-Path $scriptRoot "..\..\resources\db\tibero") -ErrorAction SilentlyContinue
if (-not $resDir) {
  Add-Result "TIB-00" "취약" "리소스 디렉터리 미탐지: scripts\resources\db\tibero"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}

if ($SqlFile) {
  $sqlPath = $SqlFile
} else {
  $all = Get-ChildItem -Path $resDir -Filter "*.sql" | Sort-Object Name
  $sqlPath = switch ($SqlVariant) {
    "tibero5sp1" { ($all | Where-Object {$_.Name -match "sp_1" -and $_.Name -match "win"} | Select-Object -First 1).FullName }
    "tibero5" { ($all | Where-Object {$_.Name -match "Tibero5" -and $_.Name -notmatch "sp_1" -and $_.Name -match "win"} | Select-Object -First 1).FullName }
    default { ($all | Select-Object -First 1).FullName }
  }
}

if (-not $sqlPath -or -not (Test-Path $sqlPath)) {
  Add-Result "TIB-00" "취약" "SQL 스크립트 파일을 찾을 수 없음: $sqlPath"
  Write-Host "[INFO] 완료: $outFile"
  exit 0
}

Add-Section "TIB-01" "점검 실행(증적 수집)"
$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ("tibero_audit_{0}" -f [guid]::NewGuid().ToString()))
$consoleOut = Join-Path $tmp.FullName "tbsql_console.out"

$sec = Read-Host ("Tibero password for {0}@{1} (leave empty for none)" -f $User,$Tns) -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$pwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null

$loginSql = Join-Path $tmp.FullName "login.sql"
@"
connect $User/$1@$Tns
@$sqlPath
exit
"@ | Out-File -Encoding ascii $loginSql

try {
  Push-Location $OutDir
  & $tbsql.Source "-s" "/nolog" "@$loginSql" $pwd *>&1 | Out-File -Encoding utf8 $consoleOut
  Add-Result "TIB-01" "점검완료" "tbsql 실행 완료(콘솔 출력/스풀 파일 확인)"
}
catch {
  Add-Result "TIB-01" "수동" $_.Exception.Message
}
finally {
  Pop-Location
}

"-----[tbsql console output begin]-----" | Out-File -Append -Encoding utf8 $outFile
Get-Content $consoleOut -ErrorAction SilentlyContinue | Select-Object -First 2000 | Out-File -Append -Encoding utf8 $outFile
"-----[tbsql console output end]-----" | Out-File -Append -Encoding utf8 $outFile

# Locate and normalize spool file produced by SQL (TIBERO_*_yymmdd.txt)
$yymmdd = Get-Date -Format "yyMMdd"
$spool = Get-ChildItem -Path $OutDir -Filter ("TIBERO_*_{0}.txt" -f $yymmdd) -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($spool) {
  $dest = Join-Path $resultsDir ("{0}__{1}__TiberoDB__{2}__spool.txt" -f $SwId,$hostName,$ts)
  Move-Item -Force $spool.FullName $dest
  Add-Result "TIB-01" "점검완료" ("Spool saved: {0}" -f $dest)
} else {
  Add-Result "TIB-01" "수동" ("스풀 파일 자동 탐지 실패(TIBERO_*_{0}.txt). OutDir에서 파일 확인" -f $yymmdd)
}

Add-Section "TIB-99" "후속 조치"
Add-Result "TIB-99" "수동" "스풀 파일(상세 증적) 기반으로 계정/권한/감사/암호화 설정을 조직 기준서에 따라 판정"

Remove-Item -Recurse -Force $tmp.FullName -ErrorAction SilentlyContinue
Write-Host "[INFO] 완료: $outFile"
