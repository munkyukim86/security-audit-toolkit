#requires -Version 5.1
<#
.SYNOPSIS
  IIS security audit (standalone). Requires WebAdministration module on IIS server.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$SiteName = "Default Web Site",
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "KR baseline (operator-tailored) - IIS hardening"
$HostName = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir "$SwId`__$HostName`__IIS`__$DATE`__result.txt"
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
  IIS 취약점 점검 결과
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
실행 호스트: $HostName
Site: $SiteName
SW ID: $SwId
############################################################################
"@ | Out-File -FilePath $OUTFILE -Encoding utf8

Section "IIS-00" "사전 점검(WebAdministration 모듈)" "상"
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
  ResultLine "IIS-00" "수동" "WebAdministration 모듈 미설치. IIS 서버에서 실행 필요."
  Write-Host "[INFO] 결과 파일: $OUTFILE"
  exit 0
}
Import-Module WebAdministration -ErrorAction Stop
ResultLine "IIS-00" "양호" "WebAdministration 모듈 확인"

Section "IIS-01" "디렉터리 브라우징 비활성화" "상"
try {
  $enabled = (Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name enabled -PSPath "IIS:\Sites\$SiteName").Value
  Add-Content $OUTFILE ("▶ directoryBrowse.enabled = {0}`r`n" -f $enabled)
  if ($enabled -eq $false) { ResultLine "IIS-01" "양호" "디렉터리 브라우징 비활성화" }
  else { ResultLine "IIS-01" "취약" "디렉터리 브라우징 활성화" }
} catch {
  ResultLine "IIS-01" "수동" ("조회 실패: {0}" -f $_.Exception.Message)
}

Section "IIS-02" "상세 오류/스택노출 최소화(customErrors/httpErrors)" "중"
try {
  $httpErrors = Get-WebConfigurationProperty -Filter "system.webServer/httpErrors" -Name errorMode -PSPath "IIS:\Sites\$SiteName"
  Add-Content $OUTFILE ("▶ httpErrors.errorMode = {0}`r`n" -f $httpErrors.Value)
  ResultLine "IIS-02" "주의" "errorMode가 DetailedLocalOnly/Custom 여부 및 앱의 상세 오류 노출 여부를 종합 검토"
} catch {
  ResultLine "IIS-02" "수동" "조회 실패"
}

Section "IIS-03" "Request Filtering (Double Escaping/Max Content)" "중"
try {
  $allow = (Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name allowDoubleEscaping -PSPath "IIS:\Sites\$SiteName").Value
  $max = (Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name maxAllowedContentLength -PSPath "IIS:\Sites\$SiteName").Value
  Add-Content $OUTFILE ("▶ allowDoubleEscaping = {0}`r`n▶ maxAllowedContentLength = {1}`r`n" -f $allow,$max)
  if ($allow -eq $false) { ResultLine "IIS-03" "주의" "allowDoubleEscaping=false 확인. 업로드 제한(maxAllowedContentLength)은 앱 요구사항 대비 검토." }
  else { ResultLine "IIS-03" "취약" "allowDoubleEscaping=true (URL 우회 위험 증가)" }
} catch {
  ResultLine "IIS-03" "수동" "조회 실패"
}

Section "IIS-04" "HTTPS 바인딩/SSL 설정" "상"
try {
  $bindings = Get-WebBinding -Name $SiteName
  Add-Content $OUTFILE ("▶ Get-WebBinding`r`n{0}`r`n" -f ($bindings | Select-Object protocol,bindingInformation,sslFlags | Format-Table -AutoSize | Out-String))
  if ($bindings.protocol -contains "https") {
    ResultLine "IIS-04" "주의" "https 바인딩 존재. HSTS/최신 TLS(1.2+)/약한 Cipher 제거는 OS/IIS/레지스트리 수준에서 추가 확인."
  } else {
    ResultLine "IIS-04" "취약" "https 바인딩 없음(평문 HTTP만)"
  }
} catch {
  ResultLine "IIS-04" "수동" "바인딩 조회 실패"
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
