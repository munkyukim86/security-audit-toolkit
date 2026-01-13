# AI Agent Rules for Security Audit Toolkit

## Project Context

This repository contains **security vulnerability assessment scripts** for:
- Operating Systems: Windows, Linux/Unix
- Databases: Oracle, Tibero, DB2, MySQL, PostgreSQL, MSSQL, MongoDB
- Web Application Servers: Tomcat, IIS, Apache, WebLogic, WebSphere
- Network Devices: Cisco, Juniper, Palo Alto, etc.
- Cloud Platforms: AWS, Azure, GCP

**Standards/Baselines**: KISA 2021, Cloud Vulnerability Guide 2024, TLP Network Guide 2024, KCIS

---

## CRITICAL SECURITY RULES

### 🚫 Rule 1: NEVER Access or Output Sensitive Information

**STRICTLY PROHIBITED:**
- Reading `.env`, `secrets/`, or any credential files
- Outputting API keys, passwords, certificates, private keys
- Accessing files with extensions: `.key`, `.pem`, `.crt`, `.pfx`, `.p12`
- Transmitting authentication tokens or session data
- Reading customer data or personally identifiable information (PII)

**If asked to access sensitive files:**
```
❌ CANNOT PROCEED: This file contains sensitive credentials.
Please handle credentials manually for security.
```

### 💣 Rule 2: NEVER Execute Destructive Commands

**ABSOLUTELY FORBIDDEN:**
- `rm -rf`, `del /f /s /q`, or any file deletion commands
- Registry modifications (`reg add`, `reg delete`, etc.)
- Firewall rule changes (`netsh`, `iptables`, `ufw`, etc.)
- Service/daemon modifications (`systemctl`, `sc.exe`, etc.)
- Database DROP/DELETE/TRUNCATE operations
- Cloud resource deletion (AWS/Azure/GCP CLI delete commands)

**ALWAYS require explicit user confirmation before:**
- Creating commits
- Modifying existing files
- Running any script that changes system state

### ✅ Rule 3: Pull Request (PR) Requirements

When creating PRs, **ALWAYS include**:

1. **Reason for Change**
   - What vulnerability or issue does this address?
   - Which baseline check item does this relate to?

2. **Security Impact Assessment**
   - Could this change expose credentials?
   - Does it modify audit logic that could miss vulnerabilities?
   - Impact on KISA/KCIS compliance?

3. **Test Results**
   ```
   Tested on:
   - OS: [Windows 11 / Ubuntu 22.04 / etc.]
   - Target: [Oracle 19c / Tomcat 9 / AWS WAF / etc.]
   - Lint: [ShellCheck / PSScriptAnalyzer results]
   - Evidence: [Sample output attached]
   ```

---

## Development Guidelines

### For Database Audit Scripts (Oracle, Tibero, DB2, etc.)

- Use **read-only connections** (`CONNECT` privilege only, no `DBA`)
- Query system catalogs/views (e.g., `DBA_USERS`, `V$PARAMETER`) without modifications
- Wrap SQL queries in heredocs to avoid shell injection
- Example:
  ```bash
  sqlplus -S "/ as sysdba" <<EOF
  SET PAGESIZE 0
  SELECT username, account_status FROM dba_users;
  EXIT;
  EOF
  ```

### For Web Application Server Scripts (Tomcat, etc.)

- Check configuration files **without modifying** them
- Focus on:
  - SSL/TLS settings
  - Authentication configs
  - Unnecessary services/connectors
  - Directory listing, default pages
- Parse XML/conf files safely (avoid `eval`, use proper parsers)

### For Cloud Scripts (AWS WAF, GCP Cloud Armor, etc.)

- **Read-only API calls** only (`Describe*`, `List*`, `Get*`)
- Assume credentials are already authenticated (do NOT handle credentials)
- Export required environment variables properly:
  ```bash
  export AWS_REGION="us-east-1"
  export GCP_PROJECT="my-project"
  ```

### Linting and Quality

- **Bash scripts**: Must pass `shellcheck` with no errors
- **PowerShell scripts**: Must pass `PSScriptAnalyzer` with no high-severity warnings
- Run lint checks before committing:
  ```bash
  ./scripts/tools/lint.sh
  ./scripts/tools/lint.ps1
  ```

---

## Output File Handling

- All audit reports go to `--out-dir` (default: `./out/`)
- **File naming**: `{script_name}_report_{timestamp}.txt`
- **Permissions**: Set to `600` (owner read/write only) on Unix
- **NEVER commit** output files to Git (already in `.gitignore`)

---

## AI Agent Workflow

### When asked to "add a new audit check":

1. **Identify the baseline requirement** (KISA U-01, Cloud 항목 3.1.2, etc.)
2. **Choose the correct script category**:
   - OS: `scripts/linux/os/` or `scripts/windows/os/`
   - DB: `scripts/linux/db/` or `scripts/windows/db/`
   - WAS: `scripts/linux/was/`
   - Cloud: `scripts/cloud/`
3. **Follow existing patterns** in similar scripts
4. **Add to mapping table**: `docs/mapping_table.md`
5. **Update requirements docs**: `docs/execution_requirements.md`, `docs/tools_required.md`

### When asked to "fix a script":

1. **Run lint first**:
   ```bash
   shellcheck scripts/path/to/script.sh
   # or
   Invoke-ScriptAnalyzer scripts/path/to/script.ps1
   ```
2. **Fix syntax/logic errors**
3. **Test locally** (if safe)
4. **Commit with detailed message**

---

## Example Interaction

**User**: "Add Oracle password policy check"

**Agent**:
```
1. Baseline: KISA DB U-02 (패스워드 복잡도 설정)
2. File: scripts/linux/db/oracle_audit_v1.sh
3. Query: SELECT * FROM DBA_PROFILES WHERE RESOURCE_NAME LIKE 'PASSWORD%';
4. Check: PASSWORD_LIFE_TIME <= 90, PASSWORD_REUSE_TIME >= 365
5. Update mapping_table.md: KISA_DB_U-02 → Oracle Password Policy

Ready to proceed? (yes/no)
```

---

## Questions or Clarifications

If uncertain about:
- **Baseline mapping**: Ask user to confirm KISA/KCIS item number
- **Destructive action**: ALWAYS ask explicit confirmation
- **Credential access**: Refuse and explain security policy

---

## Summary

✅ **DO**: Read-only operations, evidence collection, lint compliance
❌ **DON'T**: Access secrets, delete files, modify system state without approval
📝 **PR**: Include reason + security impact + test results
🔐 **Always**: Protect credentials, follow principle of least privilege
