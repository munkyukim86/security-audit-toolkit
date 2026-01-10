# Security Audit Script Toolkit (No-Common Build)

> Defensive auditing scripts intended for authorized security assessments only.

## Goals
- Each script is **standalone** (no `common.sh` / `common.ps1` / `env.sh` dependencies).
- Produces a timestamped **evidence-friendly** text report per run.
- Supports Windows / Linux / DBMS / WAS / Network devices / Cloud baseline posture checks.
- Baseline references: **KISA 2021**, **Cloud Vulnerability Guide 2024**, **TLP Network Guide 2024**.

## Repository structure

- `scripts/`
  - `linux/` / `windows/` / `network/` / `cloud/`
  - `tools/` (lint helpers)
- `docs/`
  - `mapping_table.md` (check ID ↔ baseline mapping)
  - `execution_requirements.md` (required privileges)
  - `tools_required.md` (prereq CLI/module list)
  - `run_examples.md` (usage examples)

## Quick start

### Linux/Unix (bash)

```bash
chmod +x scripts/**/*.sh scripts/tools/*.sh
mkdir -p ./out
./scripts/linux/os/linux_os_audit.sh --sw-id SW00001234 --out-dir ./out
```

### Windows (PowerShell 5.1+)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
New-Item -ItemType Directory -Force -Path .\out | Out-Null
.\scripts\windows\os\win_os_audit.ps1 -SwId SW00001234 -OutDir .\out
```

## Cloud scripts added (WAF / Cloud Armor / Firewall)

- `scripts/cloud/waf/aws_waf_audit.sh`
- `scripts/cloud/waf/azure_waf_appgw_audit.ps1`
- `scripts/cloud/waf/gcp_cloudarmor_audit.sh`
- `scripts/cloud/network/gcp_firewall_rules_audit.sh`

> Cloud scripts assume you are already authenticated (AWS profile / `az login` / `gcloud auth login`) and have adequate read permissions.

## Db2 scripts added

- `scripts/linux/db/db2_audit_v1.sh`
- `scripts/windows/db/db2_audit_v1.ps1`

## Lint / static checks (recommended before GitHub push)

- Bash: ShellCheck + bash syntax check
- PowerShell: PSScriptAnalyzer

See: `scripts/tools/lint.sh`, `scripts/tools/lint.ps1`

## Output

All scripts write a report to `--out-dir` (default: current directory) and set strict file permissions where possible.

## Notes

- Some checks require elevated privileges (root / Administrator) and/or application-specific permissions.
- Network device audits assume SSH key-based auth (recommended).
- Results may contain sensitive details; do not commit outputs to Git.
