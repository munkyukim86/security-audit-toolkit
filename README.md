# Security Audit Script Toolkit (No-Common Build)

> Defensive auditing scripts intended for authorized security assessments only.

## Goals
- Each script is **standalone** (no `common.sh` / `common.ps1` / `env.sh` dependencies).
- Produces a timestamped **evidence-friendly** text report per run.
- Supports Windows / Linux / Network devices / Cloud basic posture checks.

## Quick start
### Linux/macOS (bash)
```bash
chmod +x scripts/**/*.sh scripts/tools/*.sh
./scripts/linux/os/linux_os_audit.sh --sw-id SW00001234 --out-dir ./out
```

### Windows (PowerShell 5.1+)
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\windows\os\win_os_audit.ps1 -SwId SW00001234 -OutDir .\out
```

## Lint / Static checks (recommended before GitHub push)
- Bash: ShellCheck + shfmt
- PowerShell: PSScriptAnalyzer

See: `scripts/tools/lint.sh`, `scripts/tools/lint.ps1`

## Output
All scripts write a report to `--out-dir` (default: current directory) and set `umask 077` where applicable.

## Notes
- Some checks require elevated privileges (root / Administrator).
- Network device audits assume SSH key-based auth (recommended).

