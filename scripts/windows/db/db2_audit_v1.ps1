<#
.SYNOPSIS
  IBM Db2 (Windows) audit script

.DESCRIPTION
  Performs a lightweight configuration audit of Db2 on Windows:
   - Authentication mode (AUTHENTICATION, SRVCON_AUTH)
   - Privileged groups (SYSADM_GROUP, SYSCTRL_GROUP, ...)
   - Audit facility (db2audit)
   - Diagnostic log path (DIAGPATH)

.VERSION
  v0.2.0 (2026-01-10)

.BASELINE
  KISA 2021 (DBMS) / Cloud Vulnerability Guide 2024

.REQUIREMENTS
  - Db2 Command Line Processor (db2) and optional db2audit
  - Run from a Db2 instance environment (db2profile) if needed
#>

param (
  [Parameter(Mandatory=$true)][string]$SwId,
  [string]$DbName = "",
  [string]$OutDir = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DATE = Get-Date -Format "yyyyMMdd_HHmmss"
$GUIDE_VER = "KISA 2021 & Cloud 2024 & TLP Network 2024"
$HostName = $env:COMPUTERNAME
$OUTFILE = Join-Path $OutDir ("{0}__{1}__DB2__{2}__result.txt" -f $SwId,$HostName,$DATE)

function Section {
  param([string]$Id,[string]$Title,[string]$Severity)
  "============================================================================`n[$Id] $Title`n위험도: $Severity`n============================================================================`n" | Add-Content -Path $OUTFILE -Encoding UTF8
}

function ResultLine {
  param([string]$Id,[string]$Result,[string]$Details)
  "★ [$Id] 점검 결과: $Result`n----------------------------------------------------------------------------`n$Details`n" | Add-Content -Path $OUTFILE -Encoding UTF8
}

function LogInfo {
  param([string]$Message)
  "[INFO] $Message" | Add-Content -Path $OUTFILE -Encoding UTF8
}

function Test-Command {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Db2 {
  param([Parameter(Mandatory=$true)][string]$Query)

  # Prefer calling db2 directly. If PATH is not set, users must start from Db2 Command Window.
  if (-not (Test-Command "db2")) {
    throw "db2 명령을 찾지 못했습니다. Db2 Command Window에서 실행하거나 PATH/db2profile을 확인하세요."
  }

  # -x: suppress headings and messages (best-effort)
  $cmd = "db2 -x \"$Query\""
  $out = & cmd.exe /c $cmd 2>&1
  return ($out | Out-String)
}

@"
############################################################################
  IBM Db2 취약점 점검 결과 (Windows)
  기준: $GUIDE_VER
############################################################################
점검일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
점검대상: $HostName
SW ID: $SwId
############################################################################

"@ | Out-File -FilePath $OUTFILE -Encoding UTF8

try {
  if (Test-Command "db2level") {
    $v = & cmd.exe /c "db2level" 2>&1 | Out-String
    LogInfo "db2level:`n$v"
  } else {
    LogInfo "db2level 명령을 찾지 못했습니다. (환경 미설정일 수 있음)"
  }
} catch {
  LogInfo "db2level 실행 중 오류: $($_.Exception.Message)"
}

Section "DB2-01" "Db2 인스턴스 프로세스 실행 계정(수동)" "중"
try {
  $procs = Get-Process -Name "db2syscs","db2sysc" -ErrorAction SilentlyContinue
  if ($null -eq $procs) {
    ResultLine "DB2-01" "수동" "Db2 프로세스를 찾지 못했습니다. 서비스 실행 여부를 확인하세요."
  } else {
    # Windows: owner retrieval is non-trivial; provide process list only.
    $details = $procs | Select-Object Id,ProcessName,Path | Format-Table -AutoSize | Out-String
    ResultLine "DB2-01" "수동" "프로세스 확인 결과입니다. (권고: 관리자/시스템 계정 최소화, 전용 서비스 계정 사용)\n$details"
  }
} catch {
  ResultLine "DB2-01" "수동" "프로세스 확인 중 오류: $($_.Exception.Message)"
}

Section "DB2-02" "인증 방식(AUTHENTICATION)" "상"
try {
  $dbm = Invoke-Db2 "get dbm cfg"
  $auth = ($dbm -split "`n" | Where-Object { $_ -match "AUTHENTICATION" } | Select-Object -First 1)
  if ($auth -match "=\s*(.+)$") {
    $val = $Matches[1].Trim()
    if ($val -match "CLIENT" -and $val -notmatch "SERVER") {
      ResultLine "DB2-02" "취약" "AUTHENTICATION=$val (권고: SERVER/SERVER_ENCRYPT 등 서버 측 인증)"
    } else {
      ResultLine "DB2-02" "양호" "AUTHENTICATION=$val"
    }
  } else {
    ResultLine "DB2-02" "수동" "AUTHENTICATION 값을 파싱하지 못했습니다. 결과 파일의 DBM CFG 원문을 확인하세요."
  }
} catch {
  ResultLine "DB2-02" "수동" "DBM CFG 조회 실패: $($_.Exception.Message)"
}

Section "DB2-03" "서버 접속 인증(SRVCON_AUTH)" "상"
try {
  $dbm = Invoke-Db2 "get dbm cfg"
  $line = ($dbm -split "`n" | Where-Object { $_ -match "SRVCON_AUTH" } | Select-Object -First 1)
  if ($line -match "=\s*(.+)$") {
    $val = $Matches[1].Trim()
    if ($val -match "CLIENT") {
      ResultLine "DB2-03" "취약" "SRVCON_AUTH=$val (권고: SERVER_ENCRYPT 등)"
    } else {
      ResultLine "DB2-03" "양호" "SRVCON_AUTH=$val"
    }
  } else {
    ResultLine "DB2-03" "수동" "SRVCON_AUTH 값을 파싱하지 못했습니다."
  }
} catch {
  ResultLine "DB2-03" "수동" "DBM CFG 조회 실패: $($_.Exception.Message)"
}

Section "DB2-04" "관리 권한 그룹(SYS*\_GROUP)" "상"
try {
  $dbm = Invoke-Db2 "get dbm cfg"
  $groups = @("SYSADM_GROUP","SYSCTRL_GROUP","SYSMAINT_GROUP","SYSMON_GROUP")
  $found = @()
  foreach ($g in $groups) {
    $l = ($dbm -split "`n" | Where-Object { $_ -match [regex]::Escape($g) } | Select-Object -First 1)
    if ($l) { $found += $l.Trim() }
  }
  if ($found.Count -eq 0) {
    ResultLine "DB2-04" "수동" "SYS* 그룹 항목을 찾지 못했습니다. DBM CFG 원문을 확인하세요."
  } else {
    $empty = $found | Where-Object { $_ -match "=\s*$" -or $_ -match "=\s*NULL\b" }
    if ($empty.Count -gt 0) {
      ResultLine "DB2-04" "주의" "일부 SYS* 그룹이 공란/NULL 입니다. (권고: 최소 권한 원칙에 따라 명시적 그룹 지정)\n$($found -join "`n")"
    } else {
      ResultLine "DB2-04" "양호" ($found -join "`n")
    }
  }
} catch {
  ResultLine "DB2-04" "수동" "DBM CFG 조회 실패: $($_.Exception.Message)"
}

Section "DB2-05" "진단 로그 경로(DIAGPATH)" "중"
try {
  $dbm = Invoke-Db2 "get dbm cfg"
  $line = ($dbm -split "`n" | Where-Object { $_ -match "DIAGPATH" } | Select-Object -First 1)
  if ($line -match "=\s*(.+)$") {
    $path = $Matches[1].Trim()
    ResultLine "DB2-05" "양호" "DIAGPATH=$path (권고: 접근권한 최소화)"
  } else {
    ResultLine "DB2-05" "수동" "DIAGPATH 값을 파싱하지 못했습니다."
  }
} catch {
  ResultLine "DB2-05" "수동" "DBM CFG 조회 실패: $($_.Exception.Message)"
}

Section "DB2-06" "감사(Audit) 기능 활성화(db2audit)" "상"
try {
  if (Test-Command "db2audit") {
    $status = & cmd.exe /c "db2audit status" 2>&1 | Out-String
    $desc   = & cmd.exe /c "db2audit describe" 2>&1 | Out-String
    if ($status -match "Audit active") {
      ResultLine "DB2-06" "양호" "db2audit 활성 상태로 확인됩니다.\n$status\n\n$desc"
    } else {
      ResultLine "DB2-06" "주의" "db2audit 비활성/미구성으로 보입니다. 정책에 따라 감사 활성화를 검토하세요.\n$status\n\n$desc"
    }
  } else {
    ResultLine "DB2-06" "수동" "db2audit 명령을 찾지 못했습니다. Db2 감사 기능 구성 여부를 수동 확인하세요."
  }
} catch {
  ResultLine "DB2-06" "수동" "db2audit 조회 실패: $($_.Exception.Message)"
}

Section "DB2-07" "DB CFG - 로그/백업 설정(선택)" "중"
if ([string]::IsNullOrWhiteSpace($DbName)) {
  ResultLine "DB2-07" "수동" "-DbName 미지정. DB별 설정 점검을 생략했습니다."
} else {
  try {
    $dbcfg = Invoke-Db2 ("get db cfg for {0}" -f $DbName)
    $logarch = ($dbcfg -split "`n" | Where-Object { $_ -match "LOGARCHMETH1" } | Select-Object -First 1)
    if ($logarch -match "=\s*(.+)$") {
      $val = $Matches[1].Trim()
      if ($val -match "^OFF$" ) {
        ResultLine "DB2-07" "주의" "LOGARCHMETH1=OFF 입니다. 백업/복구/감사 요건에 따라 활성화 검토 필요."
      } else {
        ResultLine "DB2-07" "양호" "LOGARCHMETH1=$val"
      }
    } else {
      ResultLine "DB2-07" "수동" "LOGARCHMETH1 값을 파싱하지 못했습니다."
    }
  } catch {
    ResultLine "DB2-07" "수동" "DB CFG 조회 실패: $($_.Exception.Message)"
  }
}

Section "DB2-08" "네트워크 포트/서비스 노출(수동)" "중"
try {
  $dbm = Invoke-Db2 "get dbm cfg"
  $svc = ($dbm -split "`n" | Where-Object { $_ -match "SVCENAME" } | Select-Object -First 1)
  if ($svc -match "=\s*(.+)$") {
    $val = $Matches[1].Trim()
    ResultLine "DB2-08" "수동" "SVCENAME=$val. 방화벽/보안그룹에서 인가된 대역만 허용하는지 확인하세요."
  } else {
    ResultLine "DB2-08" "수동" "SVCENAME 값을 파싱하지 못했습니다."
  }
} catch {
  ResultLine "DB2-08" "수동" "DBM CFG 조회 실패: $($_.Exception.Message)"
}

Write-Host "[INFO] 점검 완료. 결과 파일: $OUTFILE"
