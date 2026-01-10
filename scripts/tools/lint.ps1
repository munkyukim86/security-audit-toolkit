#requires -Version 5.1
<#
.SYNOPSIS
  Lint PowerShell scripts using PSScriptAnalyzer (if installed).
#>

$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root

Write-Host "[*] Lint PowerShell scripts with PSScriptAnalyzer" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
  Write-Host "[!] PSScriptAnalyzer not installed. Install with:" -ForegroundColor Yellow
  Write-Host "    Install-Module PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Yellow
  exit 0
}

Import-Module PSScriptAnalyzer -ErrorAction Stop

$files = git ls-files '*.ps1' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
if (-not $files) { Write-Host "No .ps1 files found."; exit 0 }

$results = Invoke-ScriptAnalyzer -Path $files -Recurse -Severity Warning,Error
if ($results) {
  $results | Format-Table -AutoSize
  throw "PSScriptAnalyzer findings exist. Fix before push."
} else {
  Write-Host "[*] Clean." -ForegroundColor Green
}
