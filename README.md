# Discovery Tooling

> **IIS & Application Server → AWS EC2 Migration Discovery Tool**  
> Determines whether a Windows Server can be lifted-and-shifted to Amazon EC2, or whether re-platforming / modernisation is required.

---

## Overview

`Invoke-IISMigrationDiscovery.ps1` is a PowerShell assessment script that performs deep inspection of a Windows Server running IIS and/or other application workloads. It collects configuration, dependency, and performance data across 13 assessment areas, then produces a colour-coded HTML report and a structured JSON report — giving you a clear **migration readiness verdict** before you touch a single EC2 instance.

The tool is designed for:

- **Migration engineers** performing pre-migration discovery
- **Cloud architects** evaluating lift-and-shift vs. modernisation trade-offs
- **Operations teams** building an application inventory before an AWS migration engagement

---

## Requirements

| Requirement | Detail |
|---|---|
| Operating System | Windows Server 2016, 2019, or 2022 |
| PowerShell | 5.1 or later |
| Privileges | **Must be run as Administrator** |
| IIS Module | `WebAdministration` (auto-imported if IIS is installed) |
| Network | Optional — connectivity tests can be skipped with `-SkipNetworkScan` |

> The script does **not** require any third-party modules, AWS CLI, or internet access to run.

---

## Quick Start

Open PowerShell **as Administrator** and run:

```powershell
.\Invoke-IISMigrationDiscovery.ps1
```

Reports are written to the same directory as the script by default.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | `String` | Script directory | Directory where JSON and HTML reports are saved |
| `-SkipNetworkScan` | `Switch` | Off | Skips live connectivity tests to AWS endpoints (faster execution) |
| `-IncludeSensitive` | `Switch` | Off | Includes raw connection strings and app settings. By default, passwords and secrets are **redacted** |

---

## Usage Examples

**Basic run — output to default location:**
```powershell
.\Invoke-IISMigrationDiscovery.ps1
```

**Specify a custom output directory:**
```powershell
.\Invoke-IISMigrationDiscovery.ps1 -OutputPath "C:\MigrationReports"
```

**Skip network scan (faster, air-gapped environments):**
```powershell
.\Invoke-IISMigrationDiscovery.ps1 -SkipNetworkScan
```

**Full run including sensitive values (internal use only):**
```powershell
.\Invoke-IISMigrationDiscovery.ps1 -OutputPath "C:\MigrationReports" -IncludeSensitive
```

**Run remotely against multiple servers via PowerShell remoting:**
```powershell
$servers = @('WEB01', 'WEB02', 'APP01')
$servers | ForEach-Object {
    Invoke-Command -ComputerName $_ -FilePath .\Invoke-IISMigrationDiscovery.ps1 `
        -ArgumentList "\\fileserver\MigrationReports" -ErrorAction Continue
}
```

---

## Output Files

Each run produces two files in the output directory, named with the server hostname and timestamp:

```
MigrationDiscovery_WEB01_20250315_143022.html   ← Human-readable report
MigrationDiscovery_WEB01_20250315_143022.json   ← Structured data for automation
```

### HTML Report

The HTML report contains:

- **At-a-glance metric tiles** — total findings, pass count, warnings, blockers, RAM, CPU
- **Migration strategy verdict** — colour-coded recommendation banner
- **Blocker summary** — all items that must be resolved before migration, with remediation steps
- **Full findings table** — every check with severity, category, detail, and recommendation
- **System summary table** — OS, IIS version, site/app pool count, task count, share count

### JSON Report

The JSON report mirrors the HTML content in a structured format suitable for:

- Importing into a migration tracking spreadsheet
- Feeding into AWS Migration Hub or third-party CMDB tools
- Aggregating findings across multiple servers via a pipeline

---

## Assessment Areas

The script evaluates 13 areas and classifies each finding as one of four severities:

| Severity | Icon | Meaning |
|---|---|---|
| `BLOCK` | 🚫 | Must be resolved before migration can proceed |
| `WARN` | ⚠️ | Should be addressed; migration possible but with risk |
| `OK` | ✅ | No action required |
| `INFO` | ℹ️ | Informational — may inform architecture decisions |

---

### 1. Operating System

Validates Windows Server build number against EC2-supported versions, detects domain membership (Active Directory dependency), and identifies whether the server is physical or virtual — which determines the appropriate migration tool (AWS MGN vs. disk image import).

**Key checks:**
- Build number ≥ 14393 (Server 2016 minimum)
- Domain membership → AWS Managed AD or VPN-extended AD required
- Physical server → P2V conversion path required

---

### 2. IIS Configuration

Deep inspection of IIS version, installed role features, Application Pools, Sites, and virtual directories.

**Key checks:**
- IIS version compatibility on target EC2 AMI
- App Pools using .NET CLR v2.0 (requires .NET 3.5 Windows Feature on EC2)
- App Pools in Classic pipeline mode (legacy)
- App Pools running as domain service accounts
- App Pools with 32-bit mode enabled
- Sites with UNC path content roots (SMB dependency — **blocker**)
- Sites with HTTPS bindings (certificate export/ACM migration required)
- Sites bound to non-standard ports (Security Group configuration)
- Dangerous features: Windows Auth, Basic Auth, WebDAV, CGI, ISAPI, SMTP

---

### 3. .NET Frameworks & Runtimes

Detects all installed .NET Framework versions (1.x through 4.x) and modern .NET 5/6/7/8 runtimes via `dotnet --list-runtimes`.

**Key checks:**
- Legacy CLR v1.x / v2.x / v3.x → requires .NET 3.5 Windows Feature on EC2
- .NET Framework 4.x → Windows-only, supported on EC2 Windows AMI
- Modern .NET 6+ → cross-platform; flags containerisation and Linux EC2 as modernisation options

---

### 4. Installed Software & Components

Enumerates all installed software from the Windows registry and flags products with AWS migration implications.

**Flagged products and recommended AWS alternatives:**

| Software | Severity | AWS Alternative |
|---|---|---|
| SQL Server (local) | 🚫 BLOCK | Amazon RDS SQL Server / Aurora |
| MySQL (local) | ⚠️ WARN | Amazon RDS MySQL / Aurora MySQL |
| Oracle | ⚠️ WARN | RDS Oracle (BYOL) |
| MongoDB | ⚠️ WARN | Amazon DocumentDB |
| Redis | ℹ️ INFO | Amazon ElastiCache for Redis |
| RabbitMQ | ⚠️ WARN | Amazon MQ / Amazon SQS |
| BizTalk Server | 🚫 BLOCK | AWS Step Functions / EventBridge |
| Crystal Reports | ⚠️ WARN | Pre-install runtime on EC2 |
| SSRS | ⚠️ WARN | Amazon QuickSight |
| SharePoint | ⚠️ WARN | SharePoint Online / EC2 farm |
| Citrix | ⚠️ WARN | AWS End User Computing |
| SAP | ⚠️ WARN | SAP-certified EC2 instance types |
| AV / EDR agents | ℹ️ INFO | GuardDuty, Inspector, Security Hub |

---

### 5. Windows Services

Checks all non-disabled services for domain service accounts and flags services with AWS migration implications.

**Key checks:**
- Services running as domain accounts → must exist in AWS Managed AD or be replaced with EC2 Instance Profiles
- IIS SMTP Service → replace with Amazon SES
- SQL Server instances → migrate to RDS
- DFS Replication → migrate to Amazon FSx or S3
- SMB file sharing (LanmanServer) → migrate to Amazon FSx for Windows

---

### 6. Network & Connectivity

Audits network adapters, DNS configuration, listening ports, Windows Firewall rules, and the hosts file. Optionally performs live TCP connectivity tests to AWS service endpoints.

**Key checks:**
- Multiple NICs → VPC ENI design required
- Custom hosts file entries → migrate to Route 53 Private Hosted Zone
- On-premises DNS servers → configure Route 53 Resolver forwarding rules
- Firewall rules → translate to EC2 Security Groups

**AWS endpoint connectivity tests (unless `-SkipNetworkScan`):**

| Endpoint | Port | Purpose |
|---|---|---|
| `ec2.amazonaws.com` | 443 | EC2 API |
| `s3.amazonaws.com` | 443 | Amazon S3 |
| `ssm.amazonaws.com` | 443 | Systems Manager (SSM Agent) |
| `kms.amazonaws.com` | 443 | Key Management Service |
| `cloudwatch.amazonaws.com` | 443 | CloudWatch metrics/logs |
| `secretsmanager.amazonaws.com` | 443 | Secrets Manager |
| `169.254.169.254` | 80 | EC2 Instance Metadata (IMDS) |

---

### 7. Storage & File System

Assesses disk volumes for EBS sizing and identifies SMB shares that need to be migrated.

**Key checks:**
- Volumes >85% used → warns to provision EBS with growth headroom
- Non-NTFS/ReFS filesystems → EBS compatibility check
- Total data >1TB → recommends AWS DataSync or Snowball Edge
- SMB shares → migrate to Amazon FSx for Windows File Server
- UNC path virtual directories → migrate to EFS or local EBS

**Recommended EBS volume types:**
- General workloads: `gp3`
- High I/O (databases, logs): `io2`

---

### 8. Scheduled Tasks

Enumerates all non-Microsoft scheduled tasks that are not disabled.

**Key checks:**
- Tasks running as domain service accounts → must be available on AWS or replaced
- Total task count → flags for EventBridge Scheduler or Lambda migration evaluation

---

### 9. Certificates

Inspects the `LocalMachine\My` and `LocalMachine\WebHosting` certificate stores.

**Key checks:**
- **Expired certificates** → 🚫 BLOCK — must be renewed before migration
- Certificates expiring within 30 days → ⚠️ WARN — renew immediately
- Certificates with private keys → must be exported (PFX) and either imported to EC2 or uploaded to AWS ACM

> **Best practice:** Use AWS Certificate Manager (ACM) for SSL termination at the Application Load Balancer. ACM certificates are free and auto-renew.

---

### 10. Application Configuration Analysis

Scans `web.config`, `app.config`, and `*.exe.config` files under common web roots (`C:\inetpub`, `C:\websites`, `C:\apps`, `C:\www`).

**Key checks:**
- Remote database connection strings → update to RDS/EC2 DB endpoint after migration
- `Integrated Security=SSPI` (Windows Authentication to DB) → 🚫 BLOCK — must switch to SQL auth or IAM DB auth
- SMTP host configuration → replace with Amazon SES SMTP endpoint
- Explicit `machineKey` values → must be replicated across all EC2 instances behind an ALB for session/forms auth to work correctly; store in AWS Secrets Manager

> Connection strings are **redacted by default**. Use `-IncludeSensitive` to include raw values.

---

### 11. COM Components & Registry Dependencies

Counts COM/CLSID and 32-bit WOW64 COM registrations to gauge legacy dependency risk.

**Key checks:**
- >500 CLSID entries → significant COM surface area; all required components must be pre-installed on EC2 AMI
- >100 32-bit WOW64 COM entries → 32-bit mode must be enabled on consuming App Pools

---

### 12. Performance Baseline

Captures current CPU load and memory utilisation as a baseline for EC2 instance sizing.

**EC2 instance type recommendations:**

| Profile | Starting Instance Type |
|---|---|
| ≤4 GB RAM, ≤2 vCPUs | `t3.medium` / `t3.large` |
| ≤8 GB RAM, ≤4 vCPUs | `t3.xlarge` / `m6i.xlarge` |
| ≤16 GB RAM, ≤8 vCPUs | `m6i.2xlarge` / `m6a.2xlarge` |
| ≤32 GB RAM, ≤16 vCPUs | `m6i.4xlarge` / `r6i.2xlarge` |
| ≤64 GB RAM | `r6i.4xlarge` / `m6i.8xlarge` |
| >64 GB RAM | `r6i.8xlarge` or larger |

> Use **AWS Compute Optimizer** after 2+ weeks of production traffic on EC2 to right-size the instance based on real utilisation.

---

### 13. Migration Readiness Verdict

The script produces one of four verdicts based on total blocker and warning counts:

| Verdict | Criteria | Suggested Action |
|---|---|---|
| ✅ **Lift-and-Shift Ready** | 0 blockers, ≤3 warnings | Proceed with AWS Application Migration Service (MGN) |
| ⚠️ **Lift-and-Shift with Remediation** | 0 blockers, >3 warnings | Address WARN items before or shortly after migration |
| 🔧 **Remediate then Migrate** | 1–3 blockers | Resolve BLOCK items first; consider re-platform for affected components |
| 🏗️ **Modernisation Recommended** | 4+ blockers | Significant refactoring required; evaluate re-platform or re-architect |

---

## Common Blockers and How to Resolve Them

### SQL Server Running Locally
The database must not share an EC2 instance with the web tier in production.

**Resolution:** Migrate the database to Amazon RDS for SQL Server or Amazon Aurora (SQL Server-compatible). Update connection strings post-migration. Consider using AWS Database Migration Service (DMS) for the data move.

### Windows Authentication (Integrated Security) in Connection Strings
SQL Server Windows Authentication requires Kerberos/NTLM, which depends on a domain controller being reachable from EC2.

**Resolution options:**
1. Switch to SQL Server Authentication (username + password) and store credentials in AWS Secrets Manager
2. Configure IAM database authentication (RDS only) and use an EC2 Instance Profile

### UNC Path Content Roots or Virtual Directories
IIS sites whose content lives on a network share (`\\server\share`) will fail if the share is not accessible from EC2.

**Resolution options:**
1. Migrate content to local EBS on the EC2 instance
2. Mount an Amazon FSx for Windows File Server share (supports SMB/UNC paths)
3. Mount an Amazon EFS share (Linux/NFS only; requires IIS configuration changes)

### Domain Service Accounts
App Pools and services running as domain accounts require that account to exist and be resolvable from EC2.

**Resolution options:**
1. Deploy AWS Managed Microsoft AD and extend your on-premises domain
2. Set up site-to-site VPN or Direct Connect to reach your on-premises DC
3. Refactor to use the EC2 Instance Profile (IAM role) for AWS resource access

### BizTalk Server
BizTalk is a complex middleware platform with many dependencies.

**Resolution options:**
1. Lift BizTalk to a dedicated EC2 instance (requires SQL Server for BizTalk databases → RDS)
2. Re-architect integration workflows using AWS Step Functions, EventBridge, and Amazon MQ

### Expired SSL Certificates
Expired certificates will break HTTPS immediately after migration.

**Resolution:** Renew certificates before migration. For the long term, use AWS ACM for SSL termination at the Application Load Balancer — ACM certificates are free and renew automatically.

---

## Recommended AWS Migration Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  AWS Cloud                                                  │
│                                                             │
│  Route 53 (DNS) ──► CloudFront (optional CDN)              │
│                            │                                │
│                            ▼                                │
│          ┌─────────────────────────────┐                    │
│          │  Application Load Balancer  │  ← ACM Certificate │
│          │  (SSL Termination)          │                    │
│          └────────────┬────────────────┘                    │
│                       │                                     │
│          ┌────────────▼────────────────┐                    │
│          │  EC2 Auto Scaling Group     │                    │
│          │  Windows Server 20xx        │                    │
│          │  IIS + Application          │                    │
│          └────────────┬────────────────┘                    │
│                       │                                     │
│     ┌─────────────────┼──────────────────┐                  │
│     │                 │                  │                  │
│     ▼                 ▼                  ▼                  │
│  RDS SQL         ElastiCache        FSx for Windows         │
│  Server          (Redis/Memcached)  (SMB Shares)            │
│                                                             │
│  Secrets Manager (credentials) · SSM (patch/config)        │
│  CloudWatch (logs/metrics)     · GuardDuty (security)       │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

- **Never commit the `-IncludeSensitive` output** to source control — it may contain database passwords and API keys.
- The script is **read-only** — it makes no changes to IIS, the registry, or any configuration files.
- Reports may contain internal hostnames, IP addresses, and service account names. Handle output according to your organisation's data classification policy.
- Run the script under a **dedicated service account** with local Administrator rights when executing remotely at scale.

---

## Limitations

- The script collects a **point-in-time snapshot**. Run it during a representative workload period for accurate performance baseline data.
- Config file scanning is limited to common web root directories. If applications are installed outside `C:\inetpub`, `C:\websites`, `C:\apps`, or `C:\www`, update the `$searchRoots` array in the script.
- COM component analysis counts registry entries but does not validate whether each component is actively used. Manual review of flagged items is recommended.
- The connectivity tests use a 3-second TCP timeout. Results may vary in high-latency or proxy-dependent environments.

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 2.0 | 2025-03 | Added HTML report, 13-area framework, EC2 connectivity tests, config file analysis, certificate inspection, COM analysis |
| 1.0 | Initial | Basic IIS, OS, and service inventory |

---

## Related AWS Services

| Service | Purpose |
|---|---|
| [AWS Application Migration Service (MGN)](https://aws.amazon.com/application-migration-service/) | Automated lift-and-shift replication |
| [AWS Database Migration Service (DMS)](https://aws.amazon.com/dms/) | Migrate databases to RDS |
| [AWS DataSync](https://aws.amazon.com/datasync/) | Migrate file data to FSx / S3 / EFS |
| [AWS Migration Hub](https://aws.amazon.com/migration-hub/) | Track migration progress |
| [AWS Compute Optimizer](https://aws.amazon.com/compute-optimizer/) | Right-size EC2 instances post-migration |
| [Amazon FSx for Windows](https://aws.amazon.com/fsx/windows/) | Managed Windows file shares (SMB) |
| [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) | Store and rotate credentials |
| [AWS Managed Microsoft AD](https://aws.amazon.com/directoryservice/) | Managed Active Directory on AWS |
| [Amazon Route 53 Resolver](https://aws.amazon.com/route53/resolver/) | Hybrid DNS resolution |
| [AWS Certificate Manager](https://aws.amazon.com/certificate-manager/) | Free SSL/TLS certificates for ALB |