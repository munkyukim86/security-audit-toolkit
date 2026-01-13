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

## 추가된 커버리지(2026-01-10)

- DB: Oracle(sqlplus), Tibero(tbsql) 증적 수집 래퍼
- WAS(Linux): Tomcat 점검 스크립트(v1)



## AI-Assisted Development with OpenCode / Antigravity

This repository is configured for AI-assisted development using **OpenCode** (compatible with Antigravity IDE).

### Quick Setup

#### 1. Install OpenCode

```bash
curl -fsSL https://opencode.ai/install | bash
```

Or via npm:
```bash
npm install -g opencode
```

#### 2. Configure Model (Google Gemini)

The repository is pre-configured to use Google Gemini models (see `.opencode.json`):
- **Primary model**: `google/gemini-3-pro-preview`
- **Small model**: `google/gemini-3-flash-preview`

**Option A: Using OpenCode Zen (Recommended)**
```bash
opencode /connect
# Select "Zen" and follow authentication steps
```

**Option B: Direct Google AI Connection**
```bash
opencode /connect
# Select "Google" and enter your API key
# Get API key from: https://makersuite.google.com/app/apikey
```

**Option C: Antigravity Integration (via plugin)**

If using Antigravity IDE, install the OpenCode plugin:
```bash
npm install -g opencode-antigravity-auth@beta
```

Then configure in `~/.config/opencode/opencode.json`:
```json
{
  "plugin": ["opencode-antigravity-auth@beta"],
  "provider": {
    "google": {
      "models": {
        "antigravity-gemini-3-pro": {
          "name": "Gemini 3 Pro (Antigravity)"
        }
      }
    }
  }
}
```

#### 3. Initialize in Project

```bash
cd security-audit-toolkit
opencode /init
# This creates AGENTS.md with project rules (already included in repo)
```

### Usage Examples

#### Start OpenCode in Terminal
```bash
opencode
# Or in VS Code/Antigravity: Press Cmd+Esc (Mac) or Ctrl+Esc (Windows)
```

#### Example Commands

**Add a new audit check:**
```
Add Oracle password policy check based on KISA DB U-02
```

**Fix linting errors:**
```
Run shellcheck on scripts/linux/db/oracle_audit_v1.sh and fix all errors
```

**Create a new cloud audit script:**
```
Create AWS CloudTrail audit script following the pattern in scripts/cloud/waf/aws_waf_audit.sh
```

### Security Rules (Enforced by AI Agent)

The AI agent follows strict security rules defined in `AGENTS.md`:

❌ **PROHIBITED:**
- Accessing `.env`, `secrets/`, or credential files
- Executing destructive commands (`rm -rf`, registry/firewall changes)
- Modifying files without explicit user approval

✅ **REQUIRED:**
- Read-only database connections
- User confirmation before commits/modifications
- PR descriptions must include: reason, security impact, test results

### GitHub Integration (Optional)

OpenCode can work directly in GitHub issues/PRs:

1. Install GitHub App: [OpenCode GitHub Integration](https://github.com/apps/opencode)
2. In any issue or PR, comment:
   ```
   /opencode Fix the ShellCheck errors in this PR
   ```

### Troubleshooting

**Issue: Model not found**
```bash
opencode /models  # List available models
opencode /connect # Re-authenticate
```

**Issue: API rate limits**
- Use smaller model for simple tasks: `@small Fix this typo`
- Switch to OpenCode Zen for team quota management

**Issue: Antigravity plugin not loading**
```bash
opencode --version  # Verify installation
npm list -g opencode-antigravity-auth  # Check plugin
```

### References

- [OpenCode Documentation](https://opencode.ai/docs/)
- [OpenCode GitHub](https://github.com/opencode-ai/opencode)
- [Antigravity Plugin](https://github.com/NoeFabris/opencode-antigravity-auth)
- [Security Rules (AGENTS.md)](./AGENTS.md)
- [Configuration (.opencode.json)](./.opencode.json)
