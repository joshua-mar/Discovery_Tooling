#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    IIS & Application Server Migration Discovery Script for AWS EC2
    Assesses lift-and-shift viability vs. modernisation requirements.

.DESCRIPTION
    Collects comprehensive system, IIS, application, dependency, and
    network configuration data to determine AWS EC2 migration readiness.
    Supports Windows Server 2016 and above.

    Output: JSON report + human-readable HTML summary.

.PARAMETER OutputPath
    Directory to write reports. Defaults to script directory.

.PARAMETER SkipNetworkScan
    Skip network connectivity and firewall checks (faster execution).

.PARAMETER IncludeSensitive
    Include connection strings and environment variables (redacted by default).

.EXAMPLE
    .\Invoke-IISMigrationDiscovery.ps1 -OutputPath "C:\MigrationReports"

.EXAMPLE
    .\Invoke-IISMigrationDiscovery.ps1 -SkipNetworkScan -IncludeSensitive

.NOTES
    Author  : AWS Migration Assessment Tool
    Version : 2.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Run as Administrator
#>

[CmdletBinding()]
param(
    [string]$OutputPath = $PSScriptRoot,
    [switch]$SkipNetworkScan,
    [switch]$IncludeSensitive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  » $Message" -ForegroundColor Yellow
}

function Write-Finding {
    param([string]$Message, [ValidateSet('OK','WARN','BLOCK','INFO')]$Severity = 'INFO')
    $colours = @{ OK = 'Green'; WARN = 'Yellow'; BLOCK = 'Red'; INFO = 'Gray' }
    $icons   = @{ OK = '[OK]  '; WARN = '[WARN]'; BLOCK = '[BLOK]'; INFO = '[INFO]' }
    Write-Host "    $($icons[$Severity]) $Message" -ForegroundColor $colours[$Severity]
}

function Get-RedactedString {
    param([string]$Value)
    if ($IncludeSensitive) { return $Value }
    # Redact passwords / secrets in connection strings
    $Value = $Value -replace '(?i)(password|pwd|secret|key)\s*=\s*[^;]+', '$1=***REDACTED***'
    return $Value
}

function Test-ModuleAvailable {
    param([string]$Name)
    return $null -ne (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
}

#endregion

#region ── Initialise ───────────────────────────────────────────────────────────

$timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$hostname    = $env:COMPUTERNAME
$reportBase  = Join-Path $OutputPath "MigrationDiscovery_${hostname}_${timestamp}"
$jsonFile    = "$reportBase.json"
$htmlFile    = "$reportBase.html"
$findings    = [System.Collections.Generic.List[hashtable]]::new()
$report      = [ordered]@{}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Detail,
        [ValidateSet('OK','WARN','BLOCK','INFO')]$Severity = 'INFO',
        [string]$Recommendation = ''
    )
    $findings.Add([ordered]@{
        Category       = $Category
        Item           = $Item
        Detail         = $Detail
        Severity       = $Severity
        Recommendation = $Recommendation
    })
    Write-Finding -Message "$Item — $Detail" -Severity $Severity
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

Write-Host @"

╔══════════════════════════════════════════════════════════════════════╗
║     IIS / Application Server  →  AWS EC2  Migration Discovery       ║
║     Server : $($hostname.PadRight(56))║
║     Date   : $($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(56))║
╚══════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  1. OPERATING SYSTEM
#══════════════════════════════════════════════════════════════════════════════

Write-Section "1. Operating System"
Write-Step "Collecting OS information…"

$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$bios= Get-CimInstance Win32_BIOS

$osData = [ordered]@{
    Caption          = $os.Caption
    Version          = $os.Version
    BuildNumber      = $os.BuildNumber
    OSArchitecture   = $os.OSArchitecture
    ServicePackMajor = $os.ServicePackMajorVersion
    InstallDate      = $os.InstallDate
    LastBootUpTime   = $os.LastBootUpTime
    SystemDrive      = $os.SystemDrive
    TotalRAM_GB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    NumberOfCPUs     = $cs.NumberOfProcessors
    LogicalCPUs      = $cs.NumberOfLogicalProcessors
    Manufacturer     = $cs.Manufacturer
    Model            = $cs.Model
    Domain           = $cs.Domain
    PartOfDomain     = $cs.PartOfDomain
    BIOSVersion      = $bios.SMBIOSBIOSVersion
    IsVirtualMachine = ($cs.Model -match 'Virtual|VMware|Hyper-V|KVM|Xen|Amazon')
}

$report.OperatingSystem = $osData

# Evaluate OS version for EC2 support
$build = [int]$os.BuildNumber
switch ($true) {
    ($build -ge 20348) { Add-Finding 'OS' 'Windows Version' "Server 2022 (Build $build) — fully supported on EC2" 'OK' }
    ($build -ge 17763) { Add-Finding 'OS' 'Windows Version' "Server 2019 (Build $build) — fully supported on EC2" 'OK' }
    ($build -ge 14393) { Add-Finding 'OS' 'Windows Version' "Server 2016 (Build $build) — supported on EC2" 'OK' }
    ($build -lt 14393) { Add-Finding 'OS' 'Windows Version' "Build $build is below Server 2016 — upgrade required before migration" 'BLOCK' 'Upgrade to Windows Server 2019 or 2022 before migrating to EC2' }
}

if ($osData.PartOfDomain) {
    Add-Finding 'OS' 'Domain Membership' "Member of domain '$($osData.Domain)' — AD dependency must be resolved on AWS (AWS Managed AD or self-hosted DC)" 'WARN' 'Deploy AWS Managed Microsoft AD or extend on-premises AD via VPN/Direct Connect'
} else {
    Add-Finding 'OS' 'Domain Membership' 'Workgroup server — no AD dependency detected' 'OK'
}

if ($osData.IsVirtualMachine) {
    Add-Finding 'OS' 'Virtualisation' "Running on $($cs.Model) — can use AWS MGN (Application Migration Service) for rehost" 'OK' 'Use AWS Application Migration Service for automated lift-and-shift'
} else {
    Add-Finding 'OS' 'Virtualisation' 'Physical server detected — P2V conversion or bare-metal import required' 'WARN' 'Use AWS VM Import/Export after creating a disk image, or use CloudEndure'
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  2. IIS CONFIGURATION
#══════════════════════════════════════════════════════════════════════════════

Write-Section "2. IIS Configuration"
Write-Step "Collecting IIS configuration…"

$iisData = [ordered]@{ Installed = $false }

$iisFeature = Get-WindowsFeature -Name 'Web-Server' -ErrorAction SilentlyContinue
if ($iisFeature -and $iisFeature.InstallState -eq 'Installed') {
    $iisData.Installed = $true

    try {
        Import-Module WebAdministration -ErrorAction Stop

        # IIS Version
        $iisReg     = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue
        $iisVersion = if ($iisReg) { "$($iisReg.MajorVersion).$($iisReg.MinorVersion)" } else { 'Unknown' }
        $iisData.Version = $iisVersion

        switch ([int]($iisVersion -split '\.')[0]) {
            {$_ -ge 10} { Add-Finding 'IIS' 'IIS Version' "IIS $iisVersion — natively available on EC2 Windows AMIs" 'OK' }
            {$_ -eq 8}  { Add-Finding 'IIS' 'IIS Version' "IIS $iisVersion — supported; consider upgrade to IIS 10 on EC2" 'WARN' }
            default      { Add-Finding 'IIS' 'IIS Version' "IIS $iisVersion — may require upgrade" 'WARN' }
        }

        # IIS Features installed
        $webFeatures = Get-WindowsFeature -Name 'Web-*' |
                       Where-Object { $_.InstallState -eq 'Installed' } |
                       Select-Object -ExpandProperty Name
        $iisData.InstalledFeatures = $webFeatures

        # Installed Feature Warnings
        $featureWarnings = @{
            'Web-Windows-Auth'   = @{ Sev='WARN'; Msg='Windows Authentication — requires AD on AWS or switch to claims/token auth' }
            'Web-Basic-Auth'     = @{ Sev='WARN'; Msg='Basic Authentication — transmits credentials; ensure HTTPS on EC2/ALB' }
            'Web-IP-Security'    = @{ Sev='INFO'; Msg='IP & Domain Restrictions — migrate rules to Security Groups / WAF on AWS' }
            'Web-DAV-Publishing' = @{ Sev='WARN'; Msg='WebDAV — assess if still required; consider S3 alternative' }
            'Web-ISAPI-Ext'      = @{ Sev='INFO'; Msg='ISAPI Extensions present — verify ISAPI modules are compatible' }
            'Web-CGI'            = @{ Sev='WARN'; Msg='CGI enabled — legacy technology; review modernisation options' }
        }
        foreach ($f in $featureWarnings.Keys) {
            if ($webFeatures -contains $f) {
                Add-Finding 'IIS' "Feature: $f" $featureWarnings[$f].Msg $featureWarnings[$f].Sev
            }
        }

        # Application Pools
        $appPools = Get-ChildItem IIS:\AppPools | ForEach-Object {
            $p = $_
            [ordered]@{
                Name            = $p.Name
                State           = $p.State
                ManagedRuntime  = $p.ManagedRuntimeVersion
                ManagedPipeline = $p.ManagedPipelineMode
                Identity        = $p.ProcessModel.userName
                IdentityType    = $p.ProcessModel.identityType
                Enable32Bit     = $p.Enable32BitAppOnWin64
                AutoStart       = $p.AutoStart
                IdleTimeout     = $p.ProcessModel.idleTimeout.TotalMinutes
                MaxProcesses    = $p.ProcessModel.maxProcesses
            }
        }
        $iisData.AppPools = $appPools

        foreach ($pool in $appPools) {
            # .NET CLR version
            if ($pool.ManagedRuntime -eq 'v2.0') {
                Add-Finding 'AppPool' "$($pool.Name)" ".NET CLR v2.0 — legacy runtime; application requires .NET 3.5 which needs Windows Feature on EC2" 'WARN' 'Enable .NET Framework 3.5 feature on EC2 instance or migrate to modern .NET'
            }
            if ($pool.ManagedRuntime -eq '') {
                Add-Finding 'AppPool' "$($pool.Name)" "No managed runtime (unmanaged/native code)" 'INFO'
            }

            # 32-bit on 64-bit OS
            if ($pool.Enable32Bit) {
                Add-Finding 'AppPool' "$($pool.Name)" "32-bit mode enabled — ensure native dependencies are 32-bit compatible on EC2" 'WARN' 'Test all native/COM dependencies in 32-bit mode on target EC2 instance'
            }

            # Custom identity
            if ($pool.IdentityType -eq 'SpecificUser') {
                Add-Finding 'AppPool' "$($pool.Name)" "Runs as service account '$($pool.Identity)' — account must exist on AWS (AD or local)" 'WARN' 'Migrate service account to AWS Managed AD or use managed identity'
            }

            # Classic pipeline
            if ($pool.ManagedPipeline -eq 'Classic') {
                Add-Finding 'AppPool' "$($pool.Name)" "Classic pipeline mode — legacy; integrated pipeline preferred" 'WARN' 'Test application in Integrated pipeline mode; migrate if possible'
            }
        }

        # Sites
        $sites = Get-ChildItem IIS:\Sites | ForEach-Object {
            $site = $_
            $bindings = $site.Bindings.Collection | ForEach-Object {
                [ordered]@{
                    Protocol    = $_.protocol
                    BindingInfo = $_.bindingInformation
                    SslFlags    = $_.sslFlags
                    CertHash    = if ($_.certificateHash) { $_.certificateHash } else { $null }
                }
            }

            # Physical path
            $physPath = $site.PhysicalPath -replace '%SystemDrive%', $env:SystemDrive

            # Applications under site
            $apps = Get-WebApplication -Site $site.Name | ForEach-Object {
                [ordered]@{
                    Path         = $_.Path
                    PhysicalPath = $_.PhysicalPath
                    AppPool      = $_.ApplicationPool
                }
            }

            # Virtual directories
            $vdirs = Get-WebVirtualDirectory -Site $site.Name | ForEach-Object {
                [ordered]@{
                    Path         = $_.Path
                    PhysicalPath = $_.PhysicalPath
                }
            }

            [ordered]@{
                Name         = $site.Name
                ID           = $site.ID
                State        = $site.State
                PhysicalPath = $physPath
                Bindings     = $bindings
                Applications = $apps
                VirtualDirs  = $vdirs
                LogPath      = $site.LogFile.Directory
            }
        }
        $iisData.Sites = $sites

        foreach ($site in $sites) {
            # Check for UNC paths (SMB shares)
            if ($site.PhysicalPath -match '^\\\\') {
                Add-Finding 'Site' "$($site.Name)" "Content on UNC path '$($site.PhysicalPath)' — file share dependency" 'BLOCK' 'Migrate content to EC2 local disk, EFS (NFS), or S3 with S3FS; eliminate UNC dependency'
            }
            foreach ($vd in $site.VirtualDirs) {
                if ($vd.PhysicalPath -match '^\\\\') {
                    Add-Finding 'Site' "$($site.Name) VDir $($vd.Path)" "Virtual directory on UNC path '$($vd.PhysicalPath)'" 'BLOCK' 'Replace UNC virtual directory with EFS mount or local storage on EC2'
                }
            }

            # HTTPS / SSL
            $httpsSites = $site.Bindings | Where-Object { $_.Protocol -eq 'https' }
            $httpOnly   = $site.Bindings | Where-Object { $_.Protocol -eq 'http' }
            if ($httpsSites) {
                Add-Finding 'Site' "$($site.Name)" "HTTPS binding found — export/re-issue SSL certificate for EC2 or use ACM with ALB" 'WARN' 'Use AWS ACM (free) certificate on an Application Load Balancer in front of EC2'
            }
            if ($httpOnly -and -not $httpsSites) {
                Add-Finding 'Site' "$($site.Name)" "HTTP-only binding — no SSL; add HTTPS via ALB + ACM on AWS" 'WARN'
            }

            # Non-standard ports
            foreach ($b in $site.Bindings) {
                if ($b.BindingInfo -match ':(\d+):') {
                    $port = [int]$Matches[1]
                    if ($port -notin @(80, 443, 8080, 8443)) {
                        Add-Finding 'Site' "$($site.Name)" "Non-standard port $port — ensure EC2 Security Group and ALB listener are configured" 'WARN' "Open port $port in Security Group; add ALB listener or use NLB for non-HTTP"
                    }
                }
            }
        }

        # Shared Configuration
        $sharedConfig = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter 'system.applicationHost/configHistory' -Name 'enabled' -ErrorAction SilentlyContinue
        $iisData.SharedConfiguration = $sharedConfig

        # Global Modules
        $globalModules = Get-WebConfiguration 'system.webServer/globalModules/*' | Select-Object -ExpandProperty Name
        $iisData.GlobalModules = $globalModules

        $nativeModuleWarnings = @('IsapiModule','CgiModule','HttpLoggingModule')
        foreach ($m in $nativeModuleWarnings) {
            if ($globalModules -contains $m) {
                Add-Finding 'IIS' "Module: $m" "$m detected — verify compatibility; may indicate legacy application patterns" 'WARN'
            }
        }

        # SMTP virtual server (IIS 6 SMTP)
        $smtpSvc = Get-Service -Name 'SMTPSVC' -ErrorAction SilentlyContinue
        if ($smtpSvc) {
            Add-Finding 'IIS' 'SMTP Service' "IIS SMTP service running — replace with Amazon SES on AWS" 'WARN' 'Configure application to use Amazon SES SMTP endpoint; remove IIS SMTP dependency'
        }

    } catch {
        Add-Finding 'IIS' 'Collection Error' "WebAdministration module error: $_" 'WARN'
    }
} else {
    $iisData.Installed = $false
    Add-Finding 'IIS' 'IIS Not Installed' 'IIS not found — this may be an application-only server' 'INFO'
}

$report.IIS = $iisData

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  3. .NET FRAMEWORKS & RUNTIMES
#══════════════════════════════════════════════════════════════════════════════

Write-Section "3. .NET Frameworks & Runtimes"
Write-Step "Detecting installed .NET versions…"

$dotNetData = [ordered]@{}

# .NET Framework versions
$fxKey   = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
$fxVersions = @()
Get-ChildItem $fxKey -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.GetValue('Version') } |
    ForEach-Object {
        $fxVersions += [ordered]@{
            Name    = $_.PSChildName
            Version = $_.GetValue('Version')
            Release = $_.GetValue('Release')
            SP      = $_.GetValue('SP')
        }
    }
$dotNetData.FrameworkVersions = $fxVersions

# .NET Core / .NET 5+ runtimes
$coreRuntimes = @()
$dotnetCmd = Get-Command 'dotnet' -ErrorAction SilentlyContinue
if ($dotnetCmd) {
    $runtimesRaw = & dotnet --list-runtimes 2>$null
    $coreRuntimes = $runtimesRaw | ForEach-Object {
        if ($_ -match '^(\S+)\s+([\d\.]+)\s+(.+)$') {
            [ordered]@{ Runtime = $Matches[1]; Version = $Matches[2]; Path = $Matches[3] }
        }
    }
    $sdksRaw = & dotnet --list-sdks 2>$null
    $dotNetData.CoreSDKs = $sdksRaw
}
$dotNetData.CoreRuntimes = $coreRuntimes

# Evaluate
$hasLegacyFx = $fxVersions | Where-Object { $_.Name -match 'v1\.|v2\.|v3\.' }
if ($hasLegacyFx) {
    Add-Finding 'DotNet' 'Legacy .NET Framework' "Versions $($hasLegacyFx.Version -join ', ') detected — require Windows; will need .NET 3.5 feature enabled on EC2" 'WARN' 'Enable .NET Framework 3.5 via Windows Features on EC2 AMI, or plan migration to .NET 6+'
}

$fx4 = $fxVersions | Where-Object { $_.Name -eq 'v4' -or $_.Name -match 'v4\.' } | Sort-Object Version | Select-Object -Last 1
if ($fx4) {
    Add-Finding 'DotNet' '.NET Framework 4.x' ".NET $($fx4.Version) — Windows-only; fully supported on EC2 Windows AMI" 'OK'
}

foreach ($rt in $coreRuntimes) {
    $major = [int]($rt.Version -split '\.')[0]
    if ($major -ge 6) {
        Add-Finding 'DotNet' ".NET Runtime $($rt.Version)" "$($rt.Runtime) $($rt.Version) — cross-platform; consider Amazon Linux EC2 or ECS/Lambda for cost savings" 'INFO' 'Modern .NET runtime opens containerisation & Linux EC2 options — evaluate for modernisation'
    }
}

$report.DotNet = $dotNetData

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  4. INSTALLED SOFTWARE & COMPONENTS
#══════════════════════════════════════════════════════════════════════════════

Write-Section "4. Installed Software & Components"
Write-Step "Enumerating installed software…"

$softwarePaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$installedSoftware = $softwarePaths | ForEach-Object {
    Get-ItemProperty $_ -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
} | Sort-Object DisplayName -Unique

$report.InstalledSoftware = $installedSoftware

# Flag items of interest
$softwareFlags = @(
    @{ Pattern = 'SQL Server';          Sev = 'BLOCK'; Msg = 'SQL Server installed locally — migrate DB to RDS/Aurora or separate EC2 instance'; Rec = 'Evaluate AWS RDS SQL Server or Aurora; decouple DB from web tier' }
    @{ Pattern = 'MySQL';               Sev = 'WARN';  Msg = 'MySQL installed locally — consider Amazon RDS MySQL'; Rec = 'Migrate to RDS MySQL or Aurora MySQL' }
    @{ Pattern = 'Oracle';              Sev = 'WARN';  Msg = 'Oracle software detected — check licensing for EC2 BYOL or use RDS Oracle'; Rec = 'Review Oracle license portability; use BYOL on EC2 or RDS Oracle' }
    @{ Pattern = 'MongoDB';             Sev = 'WARN';  Msg = 'MongoDB detected — consider Amazon DocumentDB'; Rec = 'Evaluate Amazon DocumentDB (MongoDB-compatible)' }
    @{ Pattern = 'Redis';               Sev = 'INFO';  Msg = 'Redis detected — consider Amazon ElastiCache'; Rec = 'Replace with ElastiCache for Redis for managed caching' }
    @{ Pattern = 'RabbitMQ';           Sev = 'WARN';  Msg = 'RabbitMQ detected — consider Amazon MQ or SQS/SNS'; Rec = 'Evaluate Amazon MQ (RabbitMQ-compatible) or refactor to SQS' }
    @{ Pattern = 'Crystal Reports';    Sev = 'WARN';  Msg = 'Crystal Reports — requires specific runtime; validate on target EC2 AMI'; Rec = 'Pre-install SAP Crystal Reports runtime on EC2; test report generation' }
    @{ Pattern = 'SSRS|Reporting Serv';Sev = 'WARN';  Msg = 'SQL Server Reporting Services — consider decoupling; use Power BI Embedded or QuickSight'; Rec = 'Evaluate Amazon QuickSight as managed reporting alternative' }
    @{ Pattern = 'BizTalk';            Sev = 'BLOCK'; Msg = 'BizTalk Server — complex dependency; requires full BizTalk on EC2 or migration to Logic Apps'; Rec = 'Assess AWS Step Functions / EventBridge as BizTalk alternative; or lift BizTalk to EC2' }
    @{ Pattern = 'SharePoint';         Sev = 'WARN';  Msg = 'SharePoint installed — large dependency footprint on EC2'; Rec = 'Evaluate migration to SharePoint Online (M365) or deploy on EC2 with full farm' }
    @{ Pattern = 'Citrix';             Sev = 'WARN';  Msg = 'Citrix components detected — evaluate Citrix on AWS or Amazon WorkSpaces'; Rec = 'Review Citrix Virtual Apps/Desktops on AWS or AWS End User Computing' }
    @{ Pattern = 'SAP';                Sev = 'WARN';  Msg = 'SAP software detected — use certified SAP EC2 instance types'; Rec = 'Follow AWS SAP migration guide; use SAP-certified instance types (r5, x1e)' }
    @{ Pattern = 'antivirus|McAfee|Symantec|Sophos|CrowdStrike'; Sev = 'INFO'; Msg = 'AV/EDR software detected — replace with cloud-native solution on EC2'; Rec = 'Use Amazon GuardDuty, Inspector, and Security Hub; evaluate CrowdStrike Falcon on EC2' }
)

foreach ($flag in $softwareFlags) {
    $matches = $installedSoftware | Where-Object { $_.DisplayName -match $flag.Pattern }
    foreach ($m in $matches) {
        Add-Finding 'Software' $m.DisplayName "$($flag.Msg) (v$($m.DisplayVersion))" $flag.Sev $flag.Rec
    }
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  5. WINDOWS SERVICES
#══════════════════════════════════════════════════════════════════════════════

Write-Section "5. Windows Services"
Write-Step "Collecting running services…"

$services = Get-Service | Where-Object { $_.StartType -ne 'Disabled' } | ForEach-Object {
    $svc = $_
    try {
        $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
        [ordered]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = $svc.Status.ToString()
            StartType   = $svc.StartType.ToString()
            Account     = if ($wmiSvc) { $wmiSvc.StartName } else { 'Unknown' }
            PathName    = if ($wmiSvc) { $wmiSvc.PathName } else { '' }
        }
    } catch { $null }
} | Where-Object { $_ }

$report.Services = $services

# Flag non-standard service accounts
$domainServiceAccounts = $services | Where-Object { $_.Account -match '\\' -and $_.Account -notmatch 'LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE' }
foreach ($svc in $domainServiceAccounts) {
    Add-Finding 'Services' $svc.Name "Runs as domain account '$($svc.Account)' — account must be available on AWS" 'WARN' "Create matching account in AWS Managed AD or use EC2 instance role / managed identity"
}

# Specific service checks
$serviceChecks = @{
    'MSSQLSERVER'  = @{ Sev='BLOCK'; Msg='SQL Server (Default Instance) running — migrate to RDS' }
    'MSSQL$*'      = @{ Sev='BLOCK'; Msg='SQL Server (Named Instance) running — migrate to RDS' }
    'SMTPSVC'      = @{ Sev='WARN';  Msg='IIS SMTP running — replace with Amazon SES' }
    'fax'          = @{ Sev='WARN';  Msg='Fax service running — assess need; no equivalent on AWS EC2' }
    'W3SVC'        = @{ Sev='OK';    Msg='IIS W3SVC running — will be available on EC2 Windows AMI' }
    'WAS'          = @{ Sev='OK';    Msg='Windows Process Activation Service running — available on EC2' }
    'DFSR'         = @{ Sev='WARN';  Msg='DFS Replication running — migrate to S3 or Amazon FSx' }
    'LanmanServer' = @{ Sev='WARN';  Msg='File sharing (SMB) enabled — migrate shares to Amazon FSx for Windows or EFS' }
}
foreach ($key in $serviceChecks.Keys) {
    $matched = $services | Where-Object { $_.Name -like $key }
    foreach ($svc in $matched) {
        Add-Finding 'Services' $svc.Name $serviceChecks[$key].Msg $serviceChecks[$key].Sev
    }
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  6. NETWORK & CONNECTIVITY
#══════════════════════════════════════════════════════════════════════════════

Write-Section "6. Network Configuration"
Write-Step "Collecting network information…"

$netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    $addr = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $gw   = Get-NetRoute -InterfaceIndex $_.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
    [ordered]@{
        Name       = $_.Name
        MacAddress = $_.MacAddress
        LinkSpeed  = $_.LinkSpeed
        IPAddress  = ($addr | Select-Object -ExpandProperty IPAddress) -join ', '
        PrefixLen  = ($addr | Select-Object -ExpandProperty PrefixLength) -join ', '
        Gateway    = ($gw  | Select-Object -ExpandProperty NextHop) -join ', '
    }
}

$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |
              Select-Object InterfaceAlias, ServerAddresses

$openPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, State |
             Sort-Object LocalPort -Unique

$firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } |
                 ForEach-Object {
                     $ports = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                     [ordered]@{
                         Name      = $_.DisplayName
                         Profile   = $_.Profile.ToString()
                         Action    = $_.Action.ToString()
                         Protocol  = $ports.Protocol
                         LocalPort = $ports.LocalPort
                     }
                 }

$hostFileEntries = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
                   Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }

$netData = [ordered]@{
    Adapters          = $netAdapters
    DNSServers        = $dnsServers
    ListeningPorts    = $openPorts
    FirewallRules     = $firewallRules
    HostsFileEntries  = $hostFileEntries
    MultipleNICs      = ($netAdapters.Count -gt 1)
}
$report.Network = $netData

if ($netAdapters.Count -gt 1) {
    Add-Finding 'Network' 'Multiple NICs' "$($netAdapters.Count) active adapters — EC2 supports multiple ENIs but routing must be reconfigured" 'WARN' 'Design EC2 ENI layout; use VPC subnets to segment traffic (public/private)'
}

if ($hostFileEntries) {
    Add-Finding 'Network' 'hosts File' "$($hostFileEntries.Count) custom hosts entries — must be replicated or moved to Route 53 / private hosted zone" 'WARN' 'Migrate hosts file entries to Route 53 Private Hosted Zone'
}

# Check for hardcoded IP-based DNS
$onPremDns = $dnsServers | Where-Object { $_.ServerAddresses -match '^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.' }
if ($onPremDns) {
    Add-Finding 'Network' 'On-Premises DNS' "DNS servers appear to be on-premises ($($onPremDns.ServerAddresses -join ', ')) — resolve DNS on AWS via Route 53 Resolver" 'WARN' 'Configure Route 53 Resolver with forwarding rules to on-premises DNS, or use AWS Managed AD DNS'
}

if (-not $SkipNetworkScan) {
    Write-Step "Testing external connectivity…"

    $connectivityTests = @(
        @{ Host = 'ec2.amazonaws.com';         Port = 443; Desc = 'AWS EC2 API' }
        @{ Host = 's3.amazonaws.com';          Port = 443; Desc = 'Amazon S3' }
        @{ Host = 'ssm.amazonaws.com';         Port = 443; Desc = 'AWS Systems Manager (SSM)' }
        @{ Host = 'kms.amazonaws.com';         Port = 443; Desc = 'AWS KMS' }
        @{ Host = 'cloudwatch.amazonaws.com';  Port = 443; Desc = 'CloudWatch' }
        @{ Host = 'secretsmanager.amazonaws.com'; Port = 443; Desc = 'Secrets Manager' }
        @{ Host = '169.254.169.254';           Port = 80;  Desc = 'EC2 Metadata (IMDS)' }
    )

    $connResults = foreach ($test in $connectivityTests) {
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $ar  = $tcp.BeginConnect($test.Host, $test.Port, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne(3000)
            $tcp.Close()
            [ordered]@{ Host = $test.Host; Port = $test.Port; Description = $test.Desc; Reachable = $ok }
            if ($ok) {
                Add-Finding 'Connectivity' $test.Desc "Reachable ($($test.Host):$($test.Port))" 'OK'
            } else {
                Add-Finding 'Connectivity' $test.Desc "UNREACHABLE ($($test.Host):$($test.Port)) — check proxy/firewall before migration" 'WARN' "Ensure EC2 instance can reach $($test.Host):$($test.Port) via VPC endpoints or NAT Gateway"
            }
        } catch {
            [ordered]@{ Host = $test.Host; Port = $test.Port; Description = $test.Desc; Reachable = $false }
        }
    }
    $report.ConnectivityTests = $connResults
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  7. STORAGE & FILE SYSTEM
#══════════════════════════════════════════════════════════════════════════════

Write-Section "7. Storage & File System"
Write-Step "Collecting disk and storage configuration…"

$volumes = Get-Volume | Where-Object { $_.DriveType -ne 'CD-ROM' } | ForEach-Object {
    [ordered]@{
        DriveLetter  = $_.DriveLetter
        FileSystem   = $_.FileSystem
        Size_GB      = [math]::Round($_.Size / 1GB, 2)
        FreeSpace_GB = [math]::Round($_.SizeRemaining / 1GB, 2)
        Used_Pct     = if ($_.Size -gt 0) { [math]::Round((($_.Size - $_.SizeRemaining) / $_.Size) * 100, 1) } else { 0 }
        Label        = $_.FileSystemLabel
        DriveType    = $_.DriveType.ToString()
        HealthStatus = $_.HealthStatus.ToString()
    }
}

$smbShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'ADMIN\$|C\$|IPC\$|print\$' } | ForEach-Object {
    [ordered]@{
        Name = $_.Name
        Path = $_.Path
        Description = $_.Description
    }
}

$storageData = [ordered]@{
    Volumes   = $volumes
    SMBShares = $smbShares
}
$report.Storage = $storageData

# Evaluate disk usage for EC2 EBS sizing
foreach ($vol in $volumes) {
    if ($vol.Used_Pct -gt 85) {
        Add-Finding 'Storage' "Drive $($vol.DriveLetter):" "Drive $($vol.Used_Pct)% used ($($vol.Size_GB) GB total) — size EBS volume with growth headroom" 'WARN' "Provision EBS volume at least 25% larger than current usage; use gp3 or io2 for performance"
    }
    if ($vol.FileSystem -notin @('NTFS','ReFS')) {
        Add-Finding 'Storage' "Drive $($vol.DriveLetter):" "Non-standard filesystem '$($vol.FileSystem)' — verify EBS compatibility" 'WARN'
    }
    # Total data footprint
    $totalGB = ($volumes | Measure-Object -Property Size_GB -Sum).Sum
    if ($totalGB -gt 1000) {
        Add-Finding 'Storage' 'Total Data' "$([math]::Round($totalGB,0)) GB total — use AWS DataSync or Snowball for large data transfer" 'INFO' 'For >1TB, evaluate AWS DataSync or AWS Snowball Edge for initial data migration'
    }
}

foreach ($share in $smbShares) {
    Add-Finding 'Storage' "SMB Share: $($share.Name)" "Share at '$($share.Path)' — migrate to Amazon FSx for Windows or EFS" 'WARN' 'Replace SMB shares with Amazon FSx for Windows File Server for managed file storage'
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  8. SCHEDULED TASKS
#══════════════════════════════════════════════════════════════════════════════

Write-Section "8. Scheduled Tasks"
Write-Step "Enumerating scheduled tasks…"

$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } |
         ForEach-Object {
             $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
             [ordered]@{
                 TaskName    = $_.TaskName
                 TaskPath    = $_.TaskPath
                 State       = $_.State.ToString()
                 RunAs       = $_.Principal.UserId
                 LastRun     = $info.LastRunTime
                 LastResult  = $info.LastTaskResult
                 NextRun     = $info.NextRunTime
             }
         }

$report.ScheduledTasks = $tasks

foreach ($task in $tasks) {
    if ($task.RunAs -match '\\' -and $task.RunAs -notmatch 'SYSTEM|NT AUTHORITY|NT SERVICE') {
        Add-Finding 'Tasks' $task.TaskName "Runs as '$($task.RunAs)' — domain account required on AWS" 'WARN' 'Use EC2 Instance Profile (IAM role) or AWS Systems Manager Run Command as replacement'
    }
}

if ($tasks.Count -gt 0) {
    Add-Finding 'Tasks' 'Scheduled Tasks' "$($tasks.Count) non-Microsoft tasks found — review for AWS EventBridge / Lambda replacements" 'INFO' 'Consider migrating scheduled tasks to AWS EventBridge Scheduler or Lambda for serverless execution'
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  9. CERTIFICATES
#══════════════════════════════════════════════════════════════════════════════

Write-Section "9. Certificates"
Write-Step "Inspecting certificate stores…"

$certStores  = @('LocalMachine\My', 'LocalMachine\WebHosting')
$certs = foreach ($store in $certStores) {
    try {
        $parts     = $store -split '\\'
        $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($parts[1], $parts[0])
        $certStore.Open('ReadOnly')
        foreach ($cert in $certStore.Certificates) {
            [ordered]@{
                Store       = $store
                Subject     = $cert.Subject
                Issuer      = $cert.Issuer
                Thumbprint  = $cert.Thumbprint
                NotBefore   = $cert.NotBefore
                NotAfter    = $cert.NotAfter
                HasPrivKey  = $cert.HasPrivateKey
                DaysLeft    = ([datetime]$cert.NotAfter - (Get-Date)).Days
                SAN         = ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' } | ForEach-Object { $_.Format($false) }) -join ''
            }
        }
        $certStore.Close()
    } catch { $null }
}

$report.Certificates = $certs

foreach ($cert in $certs) {
    if ($cert.DaysLeft -lt 0) {
        Add-Finding 'Certs' $cert.Subject "EXPIRED $([math]::Abs($cert.DaysLeft)) days ago — must be renewed before migration" 'BLOCK' 'Renew or replace with AWS ACM certificate'
    } elseif ($cert.DaysLeft -lt 30) {
        Add-Finding 'Certs' $cert.Subject "Expires in $($cert.DaysLeft) days — renew immediately" 'WARN' 'Renew certificate; consider using ACM for automatic renewal on ALB'
    } elseif ($cert.HasPrivKey) {
        Add-Finding 'Certs' $cert.Subject "Valid until $(Get-Date $cert.NotAfter -Format 'yyyy-MM-dd') (private key present) — must be exported and imported to EC2 or ACM" 'INFO' 'Export as PFX; import to ACM or IIS Certificate Store on EC2; prefer ACM for ALB termination'
    }
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  10. APPLICATION CONFIGURATION FILES
#══════════════════════════════════════════════════════════════════════════════

Write-Section "10. Application Configuration Analysis"
Write-Step "Scanning web.config and app.config files…"

$configFiles  = @()
$searchRoots  = @('C:\inetpub', 'C:\websites', 'C:\apps', 'C:\www')
$foundConfigs = foreach ($root in $searchRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Include 'web.config','app.config','*.exe.config' -ErrorAction SilentlyContinue |
            Select-Object -First 100
    }
}

$configSummary = foreach ($cfg in $foundConfigs) {
    try {
        [xml]$xml = Get-Content $cfg.FullName -ErrorAction SilentlyContinue
        $connStrings = $xml.configuration.connectionStrings.add | ForEach-Object {
            [ordered]@{ Name = $_.name; Value = Get-RedactedString $_.connectionString; Provider = $_.providerName }
        }
        $appSettings = $xml.configuration.appSettings.add | Select-Object -First 20 | ForEach-Object {
            [ordered]@{ Key = $_.key; Value = Get-RedactedString $_.value }
        }
        $targetFw  = $xml.configuration.'system.web'.compilation.targetFramework
        $httpRuntime = $xml.configuration.'system.web'.httpRuntime

        $configFiles += [ordered]@{
            Path          = $cfg.FullName
            ConnStrings   = $connStrings
            AppSettings   = $appSettings
            TargetFw      = $targetFw
            HttpRuntime   = $httpRuntime
        }

        # Check for on-premises DB connection strings
        foreach ($cs in $connStrings) {
            if ($cs.Value -match 'Server=(?!localhost|\(local\)|\.)\s*([^;,]+)') {
                Add-Finding 'Config' $cfg.Name "Connection string '$($cs.Name)' points to remote host — update connection string for RDS/EC2 DB endpoint" 'WARN' "Replace server name '$($Matches[1])' with RDS endpoint in app config or use AWS Secrets Manager"
            }
            if ($cs.Value -match 'Integrated Security\s*=\s*(SSPI|True|Yes)') {
                Add-Finding 'Config' $cfg.Name "Integrated Security (Windows Auth) in connection string '$($cs.Name)' — must use SQL auth or EC2 instance IAM auth on RDS" 'BLOCK' 'Switch to SQL Server Authentication or use IAM database authentication with RDS; store credentials in Secrets Manager'
            }
        }

        # Check for SMTP settings
        $smtp = $xml.configuration.'system.net'.mailSettings.smtp
        if ($smtp -and $smtp.network.host) {
            Add-Finding 'Config' $cfg.Name "SMTP host '$($smtp.network.host)' configured — replace with Amazon SES SMTP endpoint" 'WARN' "Update smtp host to 'email-smtp.<region>.amazonaws.com' and configure SES credentials"
        }

        # Machine key (replication concern)
        $machineKey = $xml.configuration.'system.web'.machineKey
        if ($machineKey -and $machineKey.validationKey -and $machineKey.validationKey -ne 'AutoGenerate') {
            Add-Finding 'Config' $cfg.Name "Explicit machineKey found — replicate to all EC2 instances for session/forms auth to work behind ALB" 'WARN' 'Ensure machineKey is identical across all EC2 instances; store in AWS Secrets Manager and inject at startup'
        }

    } catch { $null }
}

$report.ConfigFiles = $configFiles

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  11. WINDOWS REGISTRY / SYSTEM DEPENDENCIES
#══════════════════════════════════════════════════════════════════════════════

Write-Section "11. COM Components & Registry Dependencies"
Write-Step "Checking COM/ActiveX registrations…"

$comObjects = Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue |
              Where-Object { $_.GetSubKeyNames() -contains 'InprocServer32' -or $_.GetSubKeyNames() -contains 'LocalServer32' } |
              Select-Object -First 50

$comCount = (Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue).Count
$report.COMCount = $comCount

if ($comCount -gt 500) {
    Add-Finding 'COM' 'COM Objects' "$comCount COM/CLSID entries — significant COM usage; validate all required COM components exist on EC2 AMI" 'WARN' 'Document all required COM components; pre-install on EC2 AMI; consider refactoring COM to .NET'
}

# Check for 32-bit COM objects (WOW6432Node)
$wow64Com = (Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID' -ErrorAction SilentlyContinue).Count
if ($wow64Com -gt 100) {
    Add-Finding 'COM' '32-bit COM Objects' "$wow64Com 32-bit COM registrations — ensure 32-bit compatibility on 64-bit EC2 instance" 'WARN' 'Enable 32-bit mode on IIS App Pools that consume 32-bit COM components'
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  12. PERFORMANCE BASELINE
#══════════════════════════════════════════════════════════════════════════════

Write-Section "12. Performance Baseline"
Write-Step "Collecting performance counters…"

try {
    $cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $memUsed = [math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100, 1)
    $totalRam = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $usedRam  = [math]::Round(($cs.TotalPhysicalMemory - ($os.FreePhysicalMemory * 1KB)) / 1GB, 2)

    $perfData = [ordered]@{
        CPULoadPercent    = $cpuLoad
        TotalRAM_GB       = $totalRam
        UsedRAM_GB        = $usedRam
        MemoryUsedPercent = $memUsed
        LogicalCPUs       = $cs.NumberOfLogicalProcessors
    }
    $report.Performance = $perfData

    Add-Finding 'Perf' 'CPU Load' "Current: $cpuLoad% (Logical CPUs: $($cs.NumberOfLogicalProcessors))" 'INFO'
    Add-Finding 'Perf' 'Memory'   "Used: ${usedRam} GB / ${totalRam} GB ($memUsed%)" 'INFO'

    # EC2 sizing recommendation
    $recInstanceType = switch ($true) {
        ($totalRam -le 4  -and $cs.NumberOfLogicalProcessors -le 2)  { 't3.medium / t3.large' }
        ($totalRam -le 8  -and $cs.NumberOfLogicalProcessors -le 4)  { 't3.xlarge / m6i.xlarge' }
        ($totalRam -le 16 -and $cs.NumberOfLogicalProcessors -le 8)  { 'm6i.2xlarge / m6a.2xlarge' }
        ($totalRam -le 32 -and $cs.NumberOfLogicalProcessors -le 16) { 'm6i.4xlarge / r6i.2xlarge' }
        ($totalRam -le 64)  { 'r6i.4xlarge / m6i.8xlarge' }
        default             { 'r6i.8xlarge or larger — validate with AWS Compute Optimizer' }
    }

    Add-Finding 'Perf' 'EC2 Sizing' "Suggested starting instance: $recInstanceType (validate with CloudWatch after migration)" 'INFO' "Use AWS Compute Optimizer after 2+ weeks on EC2 to right-size the instance"

} catch {
    Add-Finding 'Perf' 'Performance' "Could not collect performance data: $_" 'WARN'
}

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  13. AWS MIGRATION READINESS SUMMARY
#══════════════════════════════════════════════════════════════════════════════

Write-Section "13. Migration Readiness Assessment"

$blocks = $findings | Where-Object { $_.Severity -eq 'BLOCK' }
$warns  = $findings | Where-Object { $_.Severity -eq 'WARN' }
$oks    = $findings | Where-Object { $_.Severity -eq 'OK' }

$strategy = if ($blocks.Count -eq 0 -and $warns.Count -le 3) {
    'LIFT-AND-SHIFT READY — Minimal changes required. Proceed with AWS MGN rehost.'
} elseif ($blocks.Count -eq 0) {
    'LIFT-AND-SHIFT WITH REMEDIATION — Address WARN items before or shortly after migration.'
} elseif ($blocks.Count -le 3) {
    'REMEDIATE THEN MIGRATE — Resolve BLOCK items before migrating. Consider re-platform for some components.'
} else {
    'MODERNISATION RECOMMENDED — Multiple blockers suggest significant refactoring. Evaluate re-platform or re-architect strategy.'
}

$summary = [ordered]@{
    Hostname         = $hostname
    AssessmentDate   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    OSVersion        = $os.Caption
    TotalFindings    = $findings.Count
    Blockers         = $blocks.Count
    Warnings         = $warns.Count
    PassChecks       = $oks.Count
    RecommendedStrategy = $strategy
    BlockerDetails   = $blocks | ForEach-Object { "$($_.Category) › $($_.Item): $($_.Detail)" }
}

$report.Summary = $summary

Write-Host "`n┌─────────────────────────────────────────────────────────────┐" -ForegroundColor White
Write-Host "│  MIGRATION READINESS RESULT                                  │" -ForegroundColor White
Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor White
Write-Host "│  Total Findings : $($findings.Count.ToString().PadRight(43))│" -ForegroundColor White
Write-Host "│  ✅ Pass        : $($oks.Count.ToString().PadRight(43))│" -ForegroundColor Green
Write-Host "│  ⚠️  Warnings   : $($warns.Count.ToString().PadRight(43))│" -ForegroundColor Yellow
Write-Host "│  🚫 Blockers    : $($blocks.Count.ToString().PadRight(43))│" -ForegroundColor Red
Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor White
Write-Host "│  STRATEGY: $($strategy.Substring(0, [Math]::Min(51, $strategy.Length)).PadRight(51))│" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor White

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  EXPORT: JSON REPORT
#══════════════════════════════════════════════════════════════════════════════

Write-Section "Exporting Reports"
Write-Step "Writing JSON report…"
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
Write-Host "  JSON : $jsonFile" -ForegroundColor Green

#endregion

#region ══════════════════════════════════════════════════════════════════════════
#  EXPORT: HTML REPORT
#══════════════════════════════════════════════════════════════════════════════

Write-Step "Generating HTML report…"

$sevColours = @{ BLOCK='#e74c3c'; WARN='#f39c12'; OK='#27ae60'; INFO='#7f8c8d' }
$sevBg      = @{ BLOCK='#fdecea'; WARN='#fef9e7'; OK='#eafaf1'; INFO='#f8f9fa' }

$findingsHtml = ($findings | ForEach-Object {
    $f = $_
    $col = $sevColours[$f.Severity]
    $bg  = $sevBg[$f.Severity]
    $rec = if ($f.Recommendation) { "<br><small><strong>➜</strong> $($f.Recommendation)</small>" } else { '' }
    "<tr style='background:$bg'>
        <td><span style='color:$col;font-weight:bold'>$($f.Severity)</span></td>
        <td><code>$($f.Category)</code></td>
        <td>$($f.Item)</td>
        <td>$($f.Detail)$rec</td>
    </tr>"
}) -join "`n"

$blockerList = if ($blocks.Count -gt 0) {
    "<ul>" + ($blocks | ForEach-Object { "<li><strong>$($_.Category) › $($_.Item):</strong> $($_.Detail)<br><em>$($_.Recommendation)</em></li>" }) -join "" + "</ul>"
} else { "<p style='color:#27ae60'>✅ No blockers found!</p>" }

$strategyColour = if ($blocks.Count -eq 0 -and $warns.Count -le 3) { '#27ae60' } elseif ($blocks.Count -eq 0) { '#f39c12' } else { '#e74c3c' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS EC2 Migration Discovery — $hostname</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #2c3e50; }
  header { background: linear-gradient(135deg, #1a252f 0%, #2c3e50 100%); color: #fff; padding: 32px 40px; }
  header h1 { font-size: 1.8em; margin-bottom: 6px; }
  header p  { opacity: .75; font-size: .9em; }
  .container { max-width: 1400px; margin: 0 auto; padding: 30px 20px; }
  .card { background: #fff; border-radius: 10px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
  .card h2 { font-size: 1.1em; color: #1a252f; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 16px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .metric { background: #fff; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
  .metric .val { font-size: 2.5em; font-weight: 700; }
  .metric .lbl { font-size: .8em; color: #7f8c8d; margin-top: 4px; }
  .strategy-box { border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; border-left: 6px solid $strategyColour; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
  .strategy-box h3 { color: $strategyColour; margin-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: .88em; }
  th { background: #2c3e50; color: #fff; padding: 10px 12px; text-align: left; position: sticky; top: 0; }
  td { padding: 9px 12px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
  td code { background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-size: .85em; }
  tr:hover { filter: brightness(.97); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: .75em; font-weight: 600; color: #fff; }
  .badge-BLOCK { background: #e74c3c; }
  .badge-WARN  { background: #f39c12; }
  .badge-OK    { background: #27ae60; }
  .badge-INFO  { background: #95a5a6; }
  footer { text-align: center; padding: 20px; color: #95a5a6; font-size: .8em; }
  @media (max-width: 768px) { header { padding: 20px; } }
</style>
</head>
<body>
<header>
  <h1>🚀 AWS EC2 Migration Discovery Report</h1>
  <p>Server: <strong>$hostname</strong> &nbsp;|&nbsp; OS: <strong>$($os.Caption)</strong> &nbsp;|&nbsp; Generated: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></p>
</header>

<div class="container">

  <div class="metrics">
    <div class="metric"><div class="val" style="color:#2c3e50">$($findings.Count)</div><div class="lbl">Total Findings</div></div>
    <div class="metric"><div class="val" style="color:#27ae60">$($oks.Count)</div><div class="lbl">Pass ✅</div></div>
    <div class="metric"><div class="val" style="color:#f39c12">$($warns.Count)</div><div class="lbl">Warnings ⚠️</div></div>
    <div class="metric"><div class="val" style="color:#e74c3c">$($blocks.Count)</div><div class="lbl">Blockers 🚫</div></div>
    <div class="metric"><div class="val" style="color:#3498db">$($osData.TotalRAM_GB)</div><div class="lbl">RAM (GB)</div></div>
    <div class="metric"><div class="val" style="color:#3498db">$($cs.NumberOfLogicalProcessors)</div><div class="lbl">Logical CPUs</div></div>
  </div>

  <div class="strategy-box">
    <h3>🎯 Recommended Migration Strategy</h3>
    <p style="font-size:1.05em; font-weight:600">$strategy</p>
  </div>

  <div class="card">
    <h2>🚫 Blockers — Must Resolve Before Migration</h2>
    $blockerList
  </div>

  <div class="card">
    <h2>📋 All Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Item</th><th>Detail & Recommendation</th></tr></thead>
      <tbody>$findingsHtml</tbody>
    </table>
  </div>

  <div class="card">
    <h2>🖥️ System Summary</h2>
    <table>
      <tr><td><strong>Hostname</strong></td><td>$hostname</td></tr>
      <tr><td><strong>OS</strong></td><td>$($os.Caption) (Build $($os.BuildNumber))</td></tr>
      <tr><td><strong>Architecture</strong></td><td>$($os.OSArchitecture)</td></tr>
      <tr><td><strong>RAM</strong></td><td>$($osData.TotalRAM_GB) GB</td></tr>
      <tr><td><strong>CPUs</strong></td><td>$($cs.NumberOfProcessors) physical / $($cs.NumberOfLogicalProcessors) logical</td></tr>
      <tr><td><strong>Domain</strong></td><td>$($osData.Domain) (Part of domain: $($osData.PartOfDomain))</td></tr>
      <tr><td><strong>IIS Version</strong></td><td>$($iisData.Version)</td></tr>
      <tr><td><strong>App Pools</strong></td><td>$($iisData.AppPools.Count)</td></tr>
      <tr><td><strong>IIS Sites</strong></td><td>$($iisData.Sites.Count)</td></tr>
      <tr><td><strong>Scheduled Tasks</strong></td><td>$($tasks.Count) non-Microsoft tasks</td></tr>
      <tr><td><strong>SMB Shares</strong></td><td>$($smbShares.Count)</td></tr>
    </table>
  </div>

</div>
<footer>Generated by IIS/App Migration Discovery Script v2.0 — Anthropic/AWS Assessment Tool</footer>
</body>
</html>
"@

$html | Out-File -FilePath $htmlFile -Encoding UTF8
Write-Host "  HTML : $htmlFile" -ForegroundColor Green
Write-Host "  JSON : $jsonFile" -ForegroundColor Green
Write-Host "`n  Assessment complete. Open the HTML report for the full summary.`n" -ForegroundColor Cyan

#endregion