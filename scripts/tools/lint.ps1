<#
Lint all PowerShell scripts in this repository.

This repository contains audit scripts that intentionally write human-readable
console output. Some PSScriptAnalyzer rules (e.g., PSAvoidUsingWriteHost) can be
excessively noisy for this use-case, so we exclude them while keeping other
warnings/errors.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
  Write-Error "PSScriptAnalyzer is not installed. Install it with: Install-Module PSScriptAnalyzer"
  exit 1
}

$exclude = @(
  'PSAvoidUsingWriteHost'
)

$scriptList = Get-ChildItem -Path "scripts" -Recurse -Include *.ps1 | Select-Object -ExpandProperty FullName

if (-not $scriptList -or $scriptList.Count -eq 0) {
  Write-Output "No PowerShell scripts found under scripts/."
  exit 0
}

Write-Output "==> Running PSScriptAnalyzer on $($scriptList.Count) file(s)..."
$results = Invoke-ScriptAnalyzer -Path $scriptList -Recurse -Severity Warning,Error -ExcludeRule $exclude

if ($results) {
  $results | Sort-Object ScriptName, Line, RuleName | Format-Table -AutoSize
  Write-Error "PSScriptAnalyzer found issues."
  exit 1
}

Write-Output "All PowerShell scripts passed lint checks."
