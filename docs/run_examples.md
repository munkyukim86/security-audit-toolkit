# 실행 예시

## Linux

### Linux OS

```bash
chmod +x scripts/linux/os/linux_os_audit.sh
sudo ./scripts/linux/os/linux_os_audit.sh --sw-id APP01 --out-dir ./results
```

### MySQL/MariaDB

```bash
chmod +x scripts/linux/db/mysql_audit_v8_linux.sh
./scripts/linux/db/mysql_audit_v8_linux.sh --sw-id DB01 --user audituser --host 127.0.0.1 --port 3306 --out-dir ./results
```

### PostgreSQL

```bash
chmod +x scripts/linux/db/postgres_audit_v1.sh
sudo -u postgres ./scripts/linux/db/postgres_audit_v1.sh --sw-id DB02 --out-dir ./results
```

### IBM Db2 (Linux)

```bash
chmod +x scripts/linux/db/db2_audit_v1.sh
# Db2 instance user로 실행(예: db2inst1)
sudo -u db2inst1 ./scripts/linux/db/db2_audit_v1.sh --sw-id DB2LIN01 --db SAMPLE --out-dir ./results
```

## Windows (PowerShell)

> PowerShell은 실행 정책/서명 정책에 따라 실행이 제한될 수 있습니다.
> 필요 시(내부 정책 준수 하에) `Set-ExecutionPolicy -Scope Process Bypass` 등으로 임시 완화 후 실행하십시오.

### Windows OS

```powershell
.\scripts\windows\os\win_os_audit.ps1 -SwId "WIN01" -OutDir ".\results"
```

### Hyper-V Host

```powershell
.\scripts\windows\os\hyperv_host_audit.ps1 -SwId "HV01" -OutDir ".\results"
```

### Azure NSG

```powershell
.\scripts\cloud\network\azure_nsg_audit.ps1 -SwId "AZ01" -SubscriptionId "<SUB>" -ResourceGroup "rg-a" -NsgName "nsg-a" -OutDir ".\results"
```

### Azure Application Gateway WAF

```powershell
.\scripts\cloud\waf\azure_waf_appgw_audit.ps1 -SwId "AZWAF01" -SubscriptionId "<SUB>" -ResourceGroup "rg-a" -AppGatewayName "agw-a" -OutDir ".\results"
```

### IBM Db2 (Windows)

```powershell
.\scripts\windows\db\db2_audit_v1.ps1 -SwId "DB2WIN01" -DbName "SAMPLE" -OutDir ".\results"
```

## AWS

```bash
chmod +x scripts/cloud/waf/aws_waf_audit.sh
./scripts/cloud/waf/aws_waf_audit.sh --sw-id AWSWAF01 --profile default --region ap-northeast-2 --scope REGIONAL --out-dir ./results
```

## GCP

### Cloud Armor

```bash
chmod +x scripts/cloud/waf/gcp_cloudarmor_audit.sh
./scripts/cloud/waf/gcp_cloudarmor_audit.sh --sw-id GCPCA01 --project my-project --policy my-armor-policy --out-dir ./results
```

### Firewall Rules

```bash
chmod +x scripts/cloud/network/gcp_firewall_rules_audit.sh
./scripts/cloud/network/gcp_firewall_rules_audit.sh --sw-id GCPFIRE01 --project my-project --out-dir ./results
```
