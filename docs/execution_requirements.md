# 스크립트 실행 권한 요구사항

본 문서는 각 스크립트의 **권한/실행 조건**을 정리합니다.

- “권장”은 자동 점검 정확도를 높이기 위한 권한이며, 환경에 따라 일부 항목은 *수동 점검*으로 대체될 수 있습니다.
- 실제 운영 환경에서는 반드시 조직의 변경관리/승인 절차를 준수하십시오.

## 공통

- 결과 파일은 기본적으로 **현재 디렉터리**에 생성됩니다(옵션 `--out-dir` 또는 `-OutDir` 제공 시 해당 경로).
- 민감 정보가 포함될 수 있으므로, 결과 파일을 Git에 커밋하지 않도록 `.gitignore`에 결과 폴더를 추가하는 것을 권장합니다.

---

## Linux 계열

| 스크립트 | 권한 | 이유/비고 |
|---|---|---|
| `scripts/linux/os/linux_os_audit.sh` | **root 권장** (또는 sudo) | `/etc/shadow`, PAM 설정, 시스템 로그 설정 파일 접근 |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | DB 계정(읽기 권한 필요) | MySQL 접속 및 권한/설정 조회 |
| `scripts/linux/db/postgres_audit_v1.sh` | OS 계정 + psql 접속 계정 | `pg_hba.conf`, `postgresql.conf` 접근 + DB 조회 |
| `scripts/linux/db/mongodb_audit_v1.sh` | **root 권장** | `mongod.conf` 접근, 로컬 설정 확인 |
| `scripts/linux/db/db2_audit_v1.sh` | **Db2 인스턴스 사용자 권장** | `db2 get dbm cfg`, `db2audit` 등 인스턴스 단위 명령 실행 |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | root 권장 | 설정 파일(`/etc/httpd/...`) 접근 |
| `scripts/linux/was/nginx_audit_v1.sh` | root 권장 | 설정 파일(`/etc/nginx/...`) 접근 |

---

## Windows 계열

| 스크립트 | 권한 | 이유/비고 |
|---|---|---|
| `scripts/windows/os/win_os_audit.ps1` | **로컬 관리자 권장** | 보안 정책(secedit/auditpol), 레지스트리/서비스 조회 |
| `scripts/windows/os/hyperv_host_audit.ps1` | **관리자 + Hyper-V 관리자 권장** | Hyper-V 모듈/호스트 설정 조회 |
| `scripts/windows/os/ad_domain_audit.ps1` | **도메인 관리자 또는 조회 권한** | AD 모듈/정책 조회 |
| `scripts/windows/db/mssql_audit_v1.ps1` | SQL 로그인(읽기 권한) | SQL Server 설정/권한 조회(Invoke-Sqlcmd) |
| `scripts/windows/was/iis_audit_v1.ps1` | 관리자 권장 | IIS 설정(WebAdministration), 레지스트리/서비스 조회 |
| `scripts/windows/db/db2_audit_v1.ps1` | Db2 인스턴스/관리 권한 권장 | `db2 get dbm cfg`, `db2audit` 실행 |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | Azure 구독 조회 권한 | App Gateway/WAF Policy/Diagnostic Settings 조회 |

---

## Network 장비

> 네트워크 장비 스크립트는 SSH 기반으로 구성되어 있으며, 장비/벤더별로 명령 출력이 상이할 수 있습니다.

| 스크립트 | 권한 | 이유/비고 |
|---|---|---|
| `scripts/network/firewall/*_audit.sh` | 장비 Read-Only 이상(권장: 보안/운영 계정) | running-config / show configuration 접근 |

---

## Cloud 계열

| 스크립트 | 권한 | 이유/비고 |
|---|---|---|
| `scripts/cloud/network/aws_sg_audit.sh` | AWS IAM Read 권한 | EC2 Security Group 조회 |
| `scripts/cloud/waf/aws_waf_audit.sh` | AWS IAM Read 권한 | WAF Web ACL/로깅 설정 조회 |
| `scripts/cloud/network/azure_nsg_audit.ps1` | Azure 구독 조회 권한 | NSG 규칙 조회 |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | Azure 구독 조회 권한 | App Gateway/WAF/진단 설정 조회 |
| `scripts/cloud/network/gcp_firewall_rules_audit.sh` | GCP 프로젝트 조회 권한 | Firewall Rules 조회 |
| `scripts/cloud/waf/gcp_cloudarmor_audit.sh` | GCP 프로젝트 조회 권한 | Cloud Armor 정책/백엔드 연결 조회 |

