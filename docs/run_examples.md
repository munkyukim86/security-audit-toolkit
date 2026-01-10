# 실행 예시

## Linux

### Linux OS

```bash
chmod +x scripts/linux/os/linux_os_audit.sh
sudo ./scripts/linux/os/linux_os_audit.sh --sw-id APP01 --out-dir ./out
```

### MySQL/MariaDB

```bash
chmod +x scripts/linux/db/mysql_audit_v8_linux.sh
./scripts/linux/db/mysql_audit_v8_linux.sh --sw-id DB01 --user audituser --host 127.0.0.1 --port 3306 --out-dir ./out
```

### PostgreSQL

```bash
chmod +x scripts/linux/db/postgres_audit_v1.sh
./scripts/linux/db/postgres_audit_v1.sh --sw-id DB02 --user audituser --host 127.0.0.1 --port 5432 --out-dir ./out
```

### Oracle (sqlplus)

```bash
chmod +x scripts/linux/db/oracle_audit_v1_linux.sh
# OS 인증(권장: DB 서버 로컬에서 oracle 계정/권한으로 실행)
./scripts/linux/db/oracle_audit_v1_linux.sh --sw-id DB03 --mode os --out-dir ./out

# 로그인 모드(TNS 사용)
./scripts/linux/db/oracle_audit_v1_linux.sh --sw-id DB03 --mode login --user audituser --tns ORCL --out-dir ./out
```

### Tibero (tbsql)

```bash
chmod +x scripts/linux/db/tibero_audit_v1_linux.sh
./scripts/linux/db/tibero_audit_v1_linux.sh --sw-id DB04 --user audituser --tns TIBERO --out-dir ./out
```

### Apache HTTPD

```bash
chmod +x scripts/linux/was/apache_httpd_audit_v1.sh
sudo ./scripts/linux/was/apache_httpd_audit_v1.sh --sw-id WAS01 --out-dir ./out
```

### Nginx

```bash
chmod +x scripts/linux/was/nginx_audit_v1.sh
sudo ./scripts/linux/was/nginx_audit_v1.sh --sw-id WAS02 --out-dir ./out
```

### Tomcat

```bash
chmod +x scripts/linux/was/tomcat_audit_v1.sh
sudo ./scripts/linux/was/tomcat_audit_v1.sh --sw-id WAS03 --catalina-base /opt/tomcat --out-dir ./out
```

### AWS Security Group

```bash
chmod +x scripts/cloud/network/aws_sg_audit.sh
./scripts/cloud/network/aws_sg_audit.sh --sw-id AWS01 --region ap-northeast-2 --profile default --out-dir ./out
```

### AWS WAFv2

```bash
chmod +x scripts/cloud/waf/aws_waf_audit.sh
./scripts/cloud/waf/aws_waf_audit.sh --sw-id AWSWAF01 --scope REGIONAL --region ap-northeast-2 --profile default --out-dir ./out
```

### GCP Cloud Armor

```bash
chmod +x scripts/cloud/waf/gcp_cloudarmor_audit.sh
./scripts/cloud/waf/gcp_cloudarmor_audit.sh --sw-id GCPCA01 --project my-project --policy my-armor-policy --out-dir ./out
```

### GCP Firewall Rules

```bash
chmod +x scripts/cloud/network/gcp_firewall_rules_audit.sh
./scripts/cloud/network/gcp_firewall_rules_audit.sh --sw-id GCPFIRE01 --project my-project --out-dir ./out
```

## Windows (PowerShell)

### Windows OS

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\os\win_os_audit.ps1 -SwId WIN01 -OutDir .\out
```

### IIS

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\was\iis_audit_v1.ps1 -SwId IIS01 -OutDir .\out
```

### MS SQL

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\db\mssql_audit_v1.ps1 -SwId MSSQL01 -OutDir .\out
```

### Oracle (sqlplus)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\db\oracle_audit_v1.ps1 -SwId ORA01 -OutDir .\out -Mode OSAuth
# 또는 Login 모드
powershell -ExecutionPolicy Bypass -File .\scripts\windows\db\oracle_audit_v1.ps1 -SwId ORA01 -OutDir .\out -Mode Login -User audituser -Tns ORCL
```

### Tibero (tbsql)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\db\tibero_audit_v1.ps1 -SwId TIB01 -OutDir .\out -User audituser -Tns TIBERO
```

### Azure NSG

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\cloud\network\azure_nsg_audit.ps1 -SwId AZ01 -OutDir .\out -SubscriptionId <SUB_ID>
```
