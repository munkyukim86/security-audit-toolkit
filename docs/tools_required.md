# 필요한 도구(Prerequisites)

본 저장소의 스크립트는 “진단용(Read-Only) 조회”를 중심으로 작성되었으며, 일부는 외부 CLI/모듈이 필요합니다.

## Linux/Unix (공통)

- `bash` (권장: 4.x 이상)
- `coreutils` (`stat`, `awk`, `grep`, `sed`, `find` 등)
- `python3` (Cloud 스크립트에서 JSON 파싱에 사용)

## Windows (공통)

- PowerShell 5.1 이상(권장: PowerShell 7)
- (선택) Windows RSAT: AD 점검 스크립트에서 `ActiveDirectory` 모듈 필요

## DB/미들웨어 별

- MySQL/MariaDB: `mysql` 클라이언트
- PostgreSQL: `psql`
- MongoDB: `mongosh`
- MS SQL: `SqlServer` PowerShell module (`Invoke-Sqlcmd`)
- IBM Db2:
  - Linux: `db2` CLI, (선택) `db2audit`
  - Windows: `db2cmd`, `db2` CLI, (선택) `db2audit`

## Cloud CLI

- AWS: `aws` CLI v2 (프로필/자격증명 설정 필요)
- Azure: `az` CLI (로그인 필요)
- GCP: `gcloud` CLI (애플리케이션 기본 자격 또는 로그인 필요)

## 권한(정책) 최소 예시

- AWS: `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `wafv2:GetLoggingConfiguration`, `ec2:DescribeSecurityGroups` 등
- Azure: `Microsoft.Network/applicationGateways/read`, `.../applicationGatewayWebApplicationFirewallPolicies/read`, `Microsoft.Insights/diagnosticSettings/read` 등
- GCP: `compute.firewallPolicies.list/get`, `compute.securityPolicies.list/get`, `compute.backendServices.list`, `compute.firewalls.list` 등

