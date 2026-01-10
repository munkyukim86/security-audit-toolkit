# 가이드 매핑 테이블 (점검ID ↔ 근거)

본 테이블은 리포지토리 내 스크립트에 정의된 점검ID를 기준으로, KISA 2021 / Cloud 2024 / TLP Network 2024의 **적용 범주**를 매핑한 것입니다.

> 주의: 가이드의 세부 조항(페이지/문항 번호)까지 1:1로 고정하기 어려운 항목은 "적용 범주" 수준으로 표기했으며, 현장 기준서/내규에 맞춰 조정하는 것을 권장합니다.

| 스크립트 | 점검ID | 점검 항목 | 위험도 | 적용 범주(근거) |
|---|---|---|---|---|
| `scripts/cloud/network/aws_sg_audit.sh` | `AWS-00` | 사전 점검 | 상 | Cloud 2024 (AWS) |
| `scripts/cloud/network/aws_sg_audit.sh` | `AWS-01` | 0.0.0.0/0 또는 ::/0 공개 Inbound(민감 포트) | 상 | Cloud 2024 (AWS) |
| `scripts/cloud/network/aws_sg_audit.sh` | `AWS-02` | 전체 포트(0-65535) 공개 여부 | 상 | Cloud 2024 (AWS) |
| `scripts/cloud/network/azure_nsg_audit.ps1` | `AZ-00` | 사전 점검(Azure CLI) | 상 | Cloud 2024 (Azure) |
| `scripts/cloud/network/azure_nsg_audit.ps1` | `AZ-01` | 인터넷 공개 Inbound(민감 포트) | 상 | Cloud 2024 (Azure) |
| `scripts/cloud/network/gcp_firewall_rules_audit.sh` | `GCP-00` | 방화벽 룰 조회 | 상 | Cloud 2024 (GCP) |
| `scripts/cloud/network/gcp_firewall_rules_audit.sh` | `GCP-01` | 인바운드 SSH/RDP 공개(0.0.0.0/0) | 상 | Cloud 2024 (GCP) |
| `scripts/cloud/network/gcp_firewall_rules_audit.sh` | `GCP-02` | 과도하게 허용된 인바운드 룰(전체포트/ALL) | 상 | Cloud 2024 (GCP) |
| `scripts/cloud/network/gcp_firewall_rules_audit.sh` | `GCP-03` | 방화벽 룰 로깅(logConfig) | 중 | Cloud 2024 (GCP) |
| `scripts/cloud/waf/aws_waf_audit.sh` | `WAF-01` | WAF(Web ACL) 사용 여부 | 상 | Cloud 2024 (정보보호시스템: WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/aws_waf_audit.sh` | `WAF-02` | WAF 룰(Managed Rules 포함) 적용 | 상 | Cloud 2024 (정보보호시스템: WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/aws_waf_audit.sh` | `WAF-03` | WAF 로깅(감사/추적) 활성화 | 상 | Cloud 2024 (정보보호시스템: WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/aws_waf_audit.sh` | `WAF-04` | WAF 가시성(메트릭/샘플링) 설정 | 중 | Cloud 2024 (정보보호시스템: WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/aws_waf_audit.sh` | `WAF-05` | 운영 정책 및 대응 체계 | 중 | Cloud 2024 (정보보호시스템: WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | `AZWAF-01` | WAF 활성화 여부 | 상 | Cloud 2024 (Azure WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | `AZWAF-02` | WAF 모드(Prevention 권장) | 상 | Cloud 2024 (Azure WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | `AZWAF-03` | Managed Rules(OWASP 등) 적용 여부 | 상 | Cloud 2024 (Azure WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | `AZWAF-04` | 진단 로그/모니터링 설정 | 상 | Cloud 2024 (Azure WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/azure_waf_appgw_audit.ps1` | `AZWAF-05` | Custom Rules/예외 정책 검토 | 중 | Cloud 2024 (Azure WAF) / TLP 2024(로그) |
| `scripts/cloud/waf/gcp_cloudarmor_audit.sh` | `CA-01` | Cloud Armor 보안정책 존재 여부 | 상 | Cloud 2024 (GCP Cloud Armor) / TLP 2024(로그) |
| `scripts/cloud/waf/gcp_cloudarmor_audit.sh` | `CA-02` | 보안정책 규칙(룰) 구성 | 상 | Cloud 2024 (GCP Cloud Armor) / TLP 2024(로그) |
| `scripts/cloud/waf/gcp_cloudarmor_audit.sh` | `CA-03` | 로깅(LogConfig) 설정 | 상 | Cloud 2024 (GCP Cloud Armor) / TLP 2024(로그) |
| `scripts/cloud/waf/gcp_cloudarmor_audit.sh` | `CA-04` | 로드밸런서/백엔드 서비스에 정책 연결 | 상 | Cloud 2024 (GCP Cloud Armor) / TLP 2024(로그) |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-01` | Db2 버전/레벨 확인 | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-02` | Db2 프로세스 실행 계정(root 여부) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-03` | DBM CFG 인증 설정(AUTHENTICATION/SRVCON_AUTH) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-04` | DBM CFG 관리자 권한 그룹(SYSADM/SYSCTRL/SYSMAINT/SYSMON) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-05` | 진단 로그 경로(DIAGPATH) 및 권한 | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-06` | 감사(Audit) 기능 활성화(db2audit) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-07` | DB CFG - 로그/백업 설정(선택) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/db2_audit_v1.sh` | `DB2-08` | 네트워크 포트/서비스 노출(수동) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/linux/db/mongodb_audit_v1.sh` | `MB-01` | 사용자/권한 목록(인증 필요 시 수동) | 상 | Cloud 2024 (MongoDB) |
| `scripts/linux/db/mongodb_audit_v1.sh` | `MB-02` | 인증(authorization) 활성화 | 상 | Cloud 2024 (MongoDB) |
| `scripts/linux/db/mongodb_audit_v1.sh` | `MB-03` | 외부 바인딩 최소화(bindIp) | 상 | Cloud 2024 (MongoDB) |
| `scripts/linux/db/mongodb_audit_v1.sh` | `MB-04` | 전송구간 암호화(TLS) 설정 | 상 | Cloud 2024 (MongoDB) |
| `scripts/linux/db/mongodb_audit_v1.sh` | `MB-05` | 로깅 설정(systemLog) | 중 | Cloud 2024 (MongoDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-01` | 불필요/기본 계정(test/guest/anonymous) 제거 | 상 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-02` | 빈 패스워드/인증정보 계정 금지 | 상 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-03` | 패스워드 복잡도/만료 정책 | 상 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-04` | 관리자(root) 원격 접속 제한 | 상 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-05` | local_infile 비활성화 | 중 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-06` | secure_file_priv 제한 | 중 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-07` | 전송구간 암호화(SSL/TLS) 설정 | 상 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/mysql_audit_v8_linux.sh` | `MY-08` | 감사/로그 설정(일반로그/에러로그/slow query) | 중 | Cloud 2024 (MySQL/MariaDB) |
| `scripts/linux/db/postgres_audit_v1.sh` | `PG-01` | pg_hba.conf 인증 방식(trust/0.0.0.0/0 금지) | 상 | Cloud 2024 (PostgreSQL) |
| `scripts/linux/db/postgres_audit_v1.sh` | `PG-02` | 패스워드 암호화 방식(scram 권고) | 상 | Cloud 2024 (PostgreSQL) |
| `scripts/linux/db/postgres_audit_v1.sh` | `PG-03` | 전송구간 암호화(ssl) | 상 | Cloud 2024 (PostgreSQL) |
| `scripts/linux/db/postgres_audit_v1.sh` | `PG-04` | 로깅(접속/종료/에러) 설정 | 중 | Cloud 2024 (PostgreSQL) |
| `scripts/linux/db/postgres_audit_v1.sh` | `PG-05` | 슈퍼유저 계정 최소화 | 상 | Cloud 2024 (PostgreSQL) |
| `scripts/linux/os/linux_os_audit.sh` | `U-01` | SSH root 원격 접속 제한 | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-02` | 패스워드 복잡도 정책 | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-03` | 계정 잠금(로그인 실패 임계값) | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-04` | 패스워드 최대 사용기간 | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-05` | 패스워드 파일 보호(/etc/shadow) | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-06` | root 외 UID=0 계정 금지 | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-08` | SUID/SGID 파일 점검(목록화) | 상 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/os/linux_os_audit.sh` | `U-73` | 시스템 로깅 설정 | 중 | KISA 2021 (Unix/Linux 서버) |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | `AP-00` | 사전 점검 | 상 | KISA 2021 (Apache HTTPD) |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | `AP-01` | 버전/모듈 | 중 | KISA 2021 (Apache HTTPD) |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | `AP-02` | ServerTokens/ServerSignature | 중 | KISA 2021 (Apache HTTPD) |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | `AP-03` | Directory Listing 비활성화(Options Indexes) | 상 | KISA 2021 (Apache HTTPD) |
| `scripts/linux/was/apache_httpd_audit_v1.sh` | `AP-04` | TLS 프로토콜/취약 Cipher | 상 | KISA 2021 (Apache HTTPD) |
| `scripts/linux/was/nginx_audit_v1.sh` | `NG-00` | 사전 점검 | 상 | KISA 2021 (Nginx) |
| `scripts/linux/was/nginx_audit_v1.sh` | `NG-01` | 버전/빌드 옵션 | 중 | KISA 2021 (Nginx) |
| `scripts/linux/was/nginx_audit_v1.sh` | `NG-02` | server_tokens 비활성화 | 중 | KISA 2021 (Nginx) |
| `scripts/linux/was/nginx_audit_v1.sh` | `NG-03` | TLS 프로토콜/취약 Cipher | 상 | KISA 2021 (Nginx) |
| `scripts/linux/was/nginx_audit_v1.sh` | `NG-04` | autoindex(디렉터리 리스팅) 비활성화 | 상 | KISA 2021 (Nginx) |
| `scripts/network/firewall/checkpoint_gaia_audit.sh` | `CP-01` | 버전/상태 | 중 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/checkpoint_gaia_audit.sh` | `CP-02` | SSH/관리 서비스 설정 | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/checkpoint_gaia_audit.sh` | `CP-03` | 로깅/원격 로그 | 중 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/cisco_asa_audit.sh` | `ASA-01` | 버전/하드웨어 정보 | 중 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/cisco_asa_audit.sh` | `ASA-02` | 원격관리(SSH/Telnet) 설정 | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/cisco_asa_audit.sh` | `ASA-03` | AAA/인증 정책 | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/cisco_asa_audit.sh` | `ASA-04` | 암호/키 설정(노출 주의) | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/juniper_srx_audit.sh` | `SRX-01` | 버전 | 중 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/juniper_srx_audit.sh` | `SRX-02` | 관리 서비스(SSH/NETCONF/Telnet) 설정 | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/juniper_srx_audit.sh` | `SRX-03` | 로컬 사용자/권한 클래스 | 상 | 공통(가이드 확인 필요) |
| `scripts/network/firewall/juniper_srx_audit.sh` | `SRX-04` | 로그/감사(수동) | 중 | 공통(가이드 확인 필요) |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-01` | Db2 인스턴스 프로세스 실행 계정(수동) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-02` | 인증 방식(AUTHENTICATION) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-03` | 서버 접속 인증(SRVCON_AUTH) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-04` | 관리 권한 그룹(SYS*\_GROUP) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-05` | 진단 로그 경로(DIAGPATH) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-06` | 감사(Audit) 기능 활성화(db2audit) | 상 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-07` | DB CFG - 로그/백업 설정(선택) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/db2_audit_v1.ps1` | `DB2-08` | 네트워크 포트/서비스 노출(수동) | 중 | KISA 2021 (DBMS/DB2) / Cloud 2024 |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-00` | 사전 점검(SqlServer 모듈/Invoke-Sqlcmd) | 상 | Cloud 2024 (MS-SQL) |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-01` | SQL Server 버전 | 중 | Cloud 2024 (MS-SQL) |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-02` | sysadmin 역할 계정 최소화 | 상 | Cloud 2024 (MS-SQL) |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-03` | SQL 로그인 패스워드 정책 적용 | 상 | Cloud 2024 (MS-SQL) |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-04` | xp_cmdshell 비활성화 | 상 | Cloud 2024 (MS-SQL) |
| `scripts/windows/db/mssql_audit_v1.ps1` | `MS-05` | 원격 접속/네트워크 노출(수동 검토) | 중 | Cloud 2024 (MS-SQL) |
| `scripts/windows/os/ad_domain_audit.ps1` | `AD-00` | 사전 점검(ActiveDirectory 모듈) | 상 | KISA 2021 (AD) |
| `scripts/windows/os/ad_domain_audit.ps1` | `AD-01` | 도메인 기본 패스워드/잠금 정책 | 상 | KISA 2021 (AD) |
| `scripts/windows/os/ad_domain_audit.ps1` | `AD-02` | Domain Admins 멤버 최소화 | 상 | KISA 2021 (AD) |
| `scripts/windows/os/ad_domain_audit.ps1` | `AD-03` | Protected Users 그룹 활용 | 중 | KISA 2021 (AD) |
| `scripts/windows/os/hyperv_host_audit.ps1` | `HV-00` | 사전 점검(모듈/권한) | 중 | Cloud 2024 (Hyper-V) / KISA 2021 |
| `scripts/windows/os/hyperv_host_audit.ps1` | `HV-01` | 가상머신 목록/상태 | 중 | Cloud 2024 (Hyper-V) / KISA 2021 |
| `scripts/windows/os/hyperv_host_audit.ps1` | `HV-02` | Gen2 VM Secure Boot 활성화 | 상 | Cloud 2024 (Hyper-V) / KISA 2021 |
| `scripts/windows/os/hyperv_host_audit.ps1` | `HV-03` | vSwitch 구성(불필요 외부 스위치 점검) | 중 | Cloud 2024 (Hyper-V) / KISA 2021 |
| `scripts/windows/os/hyperv_host_audit.ps1` | `HV-04` | 기본 저장 경로(권한/암호화/백업) 확인 | 중 | Cloud 2024 (Hyper-V) / KISA 2021 |
| `scripts/windows/os/win_os_audit.ps1` | `W-01` | 기본 Administrator 계정 이름 변경 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-02` | Guest 계정 비활성화 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-03` | 불필요한 로컬 계정 점검 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-04` | 계정 잠금 임계값(<=5) 설정 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-05` | 패스워드 복잡도 정책 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-06` | 패스워드 최소 길이(>=8) | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-07` | 패스워드 최대 사용 기간(<=90일) | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-08` | Windows 방화벽 활성화 | 상 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-09` | SMBv1 비활성화 | 중 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-10` | 원격 데스크톱(NLA) 설정 | 중 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-11` | 감사 정책(auditpol) 활성화 | 중 | KISA 2021 (Windows 서버) |
| `scripts/windows/os/win_os_audit.ps1` | `W-12` | 기본 공유(관리 공유) 노출 | 중 | KISA 2021 (Windows 서버) |
| `scripts/windows/was/iis_audit_v1.ps1` | `IIS-00` | 사전 점검(WebAdministration 모듈) | 상 | KISA 2021 (IIS) |
| `scripts/windows/was/iis_audit_v1.ps1` | `IIS-01` | 디렉터리 브라우징 비활성화 | 상 | KISA 2021 (IIS) |
| `scripts/windows/was/iis_audit_v1.ps1` | `IIS-02` | 상세 오류/스택노출 최소화(customErrors/httpErrors) | 중 | KISA 2021 (IIS) |
| `scripts/windows/was/iis_audit_v1.ps1` | `IIS-03` | Request Filtering (Double Escaping/Max Content) | 중 | KISA 2021 (IIS) |
| `scripts/windows/was/iis_audit_v1.ps1` | `IIS-04` | HTTPS 바인딩/SSL 설정 | 상 | KISA 2021 (IIS) |
| `scripts/linux/db/oracle_audit_v1_linux.sh` | `ORA-00` | 사전 점검(sqlplus) | 상 | KISA 2021 (DB) |
| `scripts/linux/db/oracle_audit_v1_linux.sh` | `ORA-01` | SQL*Plus 증적 수집(스풀) | 상 | KISA 2021 (DB) |
| `scripts/linux/db/tibero_audit_v1_linux.sh` | `TIB-00` | 사전 점검(tbsql) | 상 | KISA 2021 (DB) |
| `scripts/linux/db/tibero_audit_v1_linux.sh` | `TIB-01` | tbsql 증적 수집(스풀) | 상 | KISA 2021 (DB) |
| `scripts/windows/db/oracle_audit_v1.ps1` | `ORA-00` | 사전 점검(sqlplus) | 상 | KISA 2021 (DB) |
| `scripts/windows/db/oracle_audit_v1.ps1` | `ORA-01` | SQL*Plus 증적 수집(스풀) | 상 | KISA 2021 (DB) |
| `scripts/windows/db/tibero_audit_v1.ps1` | `TIB-00` | 사전 점검(tbsql) | 상 | KISA 2021 (DB) |
| `scripts/windows/db/tibero_audit_v1.ps1` | `TIB-01` | tbsql 증적 수집(스풀) | 상 | KISA 2021 (DB) |
| `scripts/linux/was/tomcat_audit_v1.sh` | `TC-00` | 사전 점검(CATALINA_BASE) | 상 | KISA 2021 (WAS) |
| `scripts/linux/was/tomcat_audit_v1.sh` | `TC-02` | 관리 콘솔(Manager/Host-Manager) 노출 | 상 | KISA 2021 (WAS) |
| `scripts/linux/was/tomcat_audit_v1.sh` | `TC-03` | Directory Listing 비활성화 | 상 | KISA 2021 (WAS) |
| `scripts/linux/was/tomcat_audit_v1.sh` | `TC-04` | AJP Connector 설정 | 상 | KISA 2021 (WAS) |
