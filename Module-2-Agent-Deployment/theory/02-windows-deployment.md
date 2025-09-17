# Windows Agent Deployment & Configuration

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Windows-specific considerations for Wazuh agent deployment
- Step-by-step installation procedures for different Windows versions
- Configuration options and security settings
- Troubleshooting common Windows deployment issues
- Integration with Windows security features

## 🪟 Windows-Specific Considerations

### Windows Architecture Overview
```
┌─────────────────────────────────────────────────────────────┐
│               WINDOWS SYSTEM ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   APPLICATIONS  │  │   SYSTEM LOGS   │  │  SECURITY   │  │
│  │                 │  │                 │  │   EVENTS    │  │
│  │ • IIS Logs      │  │ • System Events │  │ • Login     │  │
│  │ • SQL Server    │  │ • Application   │  │   Events    │  │
│  │ • Custom Apps   │  │   Events        │  │ • Policy    │  │
│  │                 │  │ • Security Logs │  │   Changes   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   FILE SYSTEM   │  │   REGISTRY      │  │  PROCESSES  │  │
│  │                 │  │                 │  │             │  │
│  │ • FIM Monitoring│  │ • Key Changes  │  │ • Process   │  │
│  │ • Directory     │  │ • Value Mods   │  │   Monitor   │  │
│  │   Changes       │  │ • Permission   │  │ • Service   │  │
│  │                 │  │   Changes       │  │   Monitor   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────┤
│              WAZUH AGENT INTEGRATION LAYER                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Windows Features for Monitoring
- **Windows Event Logs**: System, Application, Security, and custom logs
- **Registry Monitoring**: Track changes to critical registry keys
- **File Integrity Monitoring**: Monitor system and application files
- **Process and Service Monitoring**: Track running processes and services
- **Network Activity**: Monitor network connections and traffic
- **User Activity**: Track user logins, privilege changes, and access

## 📋 Pre-Deployment Requirements

### System Requirements
```bash
# Minimum Requirements:
├── Windows 7 SP1 or later (Windows 8.1, 10, 11, Server 2012+)
├── 256 MB RAM minimum, 1 GB recommended
├── 100 MB free disk space for installation
├── 500 MB additional for logs and data
├── Administrator privileges for installation
└── Network connectivity to Wazuh server
```

### Windows Versions Supported
```bash
# Supported Operating Systems:
├── Windows 7 SP1 (limited support)
├── Windows 8.1
├── Windows 10 (all editions)
├── Windows 11 (all editions)
├── Windows Server 2012 R2
├── Windows Server 2016
├── Windows Server 2019
├── Windows Server 2022
└── Windows Server Core editions
```

### Network Requirements
```bash
# Required Network Access:
├── Outbound TCP 1514 to Wazuh server
├── Outbound TCP 1515 to Wazuh server (registration)
├── DNS resolution for Wazuh server hostname
├── No proxy interference for agent communication
└── Firewall rules allowing agent traffic
```

## 🚀 Installation Methods

### Method 1: MSI Installer (Recommended)

#### Step 1: Download the MSI Package
```bash
# Download from official Wazuh repository:
# https://packages.wazuh.com/4.7/windows/wazuh-agent-4.7.1-1.msi

# Or use PowerShell to download:
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.7/windows/wazuh-agent-4.7.1-1.msi" -OutFile "C:\Temp\wazuh-agent.msi"
```

#### Step 2: Interactive Installation
```bash
# Option A: Double-click the MSI file
# 1. Run as Administrator
# 2. Follow the installation wizard
# 3. Enter Wazuh server IP/hostname
# 4. Enter agent name and group
# 5. Complete installation

# Option B: Command-line installation
msiexec /i wazuh-agent-4.7.1-1.msi /q WAZUH_MANAGER="192.168.1.100" WAZUH_AGENT_NAME="WIN-WORKSTATION-01"
```

#### Step 3: Verify Installation
```bash
# Check if service is installed and running
Get-Service -Name "WazuhSvc"

# Check agent version
& "C:\Program Files (x86)\ossec-agent\bin\agent_control.exe" -i

# View agent logs
Get-Content "C:\Program Files (x86)\ossec-agent\logs\ossec.log" -Tail 10
```

### Method 2: PowerShell Script Installation

#### Automated Deployment Script
```powershell
# PowerShell deployment script
param(
    [string]$WazuhServer = "192.168.1.100",
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$AgentGroup = "default"
)

# Download the MSI installer
$msiUrl = "https://packages.wazuh.com/4.7/windows/wazuh-agent-4.7.1-1.msi"
$msiPath = "$env:TEMP\wazuh-agent.msi"

Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath

# Install silently
$installArgs = "/i `"$msiPath`" /q WAZUH_MANAGER=`"$WazuhServer`" WAZUH_AGENT_NAME=`"$AgentName`" WAZUH_AGENT_GROUP=`"$AgentGroup`""
Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait

# Start the service
Start-Service -Name "WazuhSvc"

# Verify installation
Get-Service -Name "WazuhSvc"
```

#### Running the Script
```powershell
# Save script as Install-WazuhAgent.ps1
# Run with custom parameters:
.\Install-WazuhAgent.ps1 -WazuhServer "wazuh.company.com" -AgentGroup "workstations"

# Or use default parameters:
.\Install-WazuhAgent.ps1
```

### Method 3: Group Policy Deployment

#### For Enterprise Environments
```powershell
# Group Policy Object (GPO) Configuration:

# 1. Create a new GPO
# 2. Link to target OU containing Windows computers
# 3. Configure Computer Configuration > Policies > Software Settings
# 4. Create new package pointing to MSI file on network share
# 5. Configure installation parameters in MSI properties
# 6. Deploy and monitor installation status
```

## ⚙️ Post-Installation Configuration

### Basic Configuration File Location
```bash
# Main configuration file:
C:\Program Files (x86)\ossec-agent\ossec.conf

# Backup configuration before modifications:
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec.conf.backup"
```

### Essential Configuration Settings

#### Server Connection Configuration
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.1.100</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows-workstation</config-profile>
    <notify_time>60</notify_time>
    <time-reconnect>300</time_reconnect>
    <auto_restart>yes</auto_restart>
  </client>
</ossec_config>
```

#### Windows Event Log Monitoring
```xml
<!-- Windows Event Logs -->
<localfile>
  <location>Security</location>
  <log_format>eventlog</log_format>
  <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4985 and EventID != 5453]</query>
</localfile>

<localfile>
  <location>System</location>
  <log_format>eventlog</log_format>
</localfile>

<localfile>
  <location>Application</location>
  <log_format>eventlog</log_format>
</localfile>
```

#### File Integrity Monitoring
```xml
<!-- File Integrity Monitoring -->
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files (x86)</directories>

  <!-- Windows Registry monitoring -->
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE</registry>
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM</registry>

  <!-- Scan settings -->
  <scan_on_start>yes</scan_on_start>
  <frequency>3600</frequency> <!-- 1 hour -->
</syscheck>
```

### Advanced Configuration Options

#### Custom Log Monitoring
```xml
<!-- IIS Logs -->
<localfile>
  <location>C:\inetpub\logs\LogFiles\W3SVC1\*.log</location>
  <log_format>iis</log_format>
</localfile>

<!-- SQL Server Logs -->
<localfile>
  <location>C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*</location>
  <log_format>syslog</log_format>
</localfile>

<!-- Custom Application Logs -->
<localfile>
  <location>C:\Logs\MyApplication\*.log</location>
  <log_format>syslog</log_format>
</localfile>
```

#### Process and Service Monitoring
```xml
<!-- Process monitoring -->
<localfile>
  <location>C:\Program Files (x86)\ossec-agent\active-response\active-responses.log</location>
  <log_format>syslog</log_format>
</localfile>

<!-- Service monitoring script output -->
<localfile>
  <location>C:\Scripts\service-monitor.log</location>
  <log_format>syslog</log_format>
</localfile>
```

## 🔧 Windows-Specific Security Configuration

### Windows Defender Integration
```powershell
# Add Wazuh agent to Windows Defender exclusions
Add-MpPreference -ExclusionPath "C:\Program Files (x86)\ossec-agent"
Add-MpPreference -ExclusionProcess "ossec-agent.exe"
Add-MpPreference -ExclusionProcess "wazuh-agent.exe"
```

### User Account Control (UAC) Settings
```powershell
# Configure UAC for agent operation
# Note: Agent runs as SYSTEM account, so UAC typically doesn't interfere
# But ensure proper privileges for file monitoring
```

### Windows Firewall Configuration
```powershell
# Allow outbound connections to Wazuh server
New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Outbound -RemoteAddress "192.168.1.100" -Protocol TCP -RemotePort 1514 -Action Allow

# Allow outbound for agent registration
New-NetFirewallRule -DisplayName "Wazuh Registration" -Direction Outbound -RemoteAddress "192.168.1.100" -Protocol TCP -RemotePort 1515 -Action Allow
```

## 🚨 Troubleshooting Windows Deployments

### Common Issues and Solutions

#### Issue 1: Agent Won't Start
```powershell
# Check service status
Get-Service -Name "WazuhSvc"

# Check event logs for errors
Get-EventLog -LogName "Application" -Source "Wazuh" -Newest 10

# Check agent logs
Get-Content "C:\Program Files (x86)\ossec-agent\logs\ossec.log" -Tail 20

# Try manual start
Start-Service -Name "WazuhSvc" -Verbose
```

#### Issue 2: Connection Problems
```powershell
# Test network connectivity
Test-NetConnection -ComputerName "192.168.1.100" -Port 1514

# Test DNS resolution
Resolve-DnsName "wazuh-server.company.com"

# Check proxy settings (if applicable)
netsh winhttp show proxy
```

#### Issue 3: Configuration Errors
```powershell
# Validate XML configuration
& "C:\Program Files (x86)\ossec-agent\bin\ossec-logtest.exe"

# Check configuration syntax
[xml]$config = Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"
$config.ossec_config.client.server.address
```

#### Issue 4: Performance Issues
```powershell
# Check agent resource usage
Get-Process -Name "*ossec*"

# Monitor CPU and memory usage
Get-Counter -Counter "\Process(ossec-agent)\% Processor Time"
Get-Counter -Counter "\Process(ossec-agent)\Working Set"
```

#### Issue 5: Windows Event Log Issues
```powershell
# Check Windows Event Log service
Get-Service -Name "eventlog"

# Test event log access
Get-WinEvent -LogName "Security" -MaxEvents 1

# Check event log permissions
icacls "C:\Windows\System32\winevt\Logs\Security.evtx"
```

### Advanced Troubleshooting Scripts

#### Agent Health Check Script
```powershell
# Comprehensive agent health check
$agentPath = "C:\Program Files (x86)\ossec-agent"

# Check service status
$service = Get-Service -Name "WazuhSvc"
Write-Host "Service Status: $($service.Status)"

# Check configuration
$configPath = "$agentPath\ossec.conf"
if (Test-Path $configPath) {
    Write-Host "Configuration file exists"
    # Validate XML
    try {
        [xml]$config = Get-Content $configPath
        Write-Host "Configuration is valid XML"
    } catch {
        Write-Host "Configuration has XML errors: $($_.Exception.Message)"
    }
}

# Check logs
$logPath = "$agentPath\logs\ossec.log"
if (Test-Path $logPath) {
    $lastLines = Get-Content $logPath -Tail 5
    Write-Host "Last 5 log entries:"
    $lastLines | ForEach-Object { Write-Host "  $_" }
}

# Test connectivity
$serverIP = "192.168.1.100"
$connection = Test-NetConnection -ComputerName $serverIP -Port 1514
Write-Host "Server connectivity: $($connection.TcpTestSucceeded)"
```

## 📊 Windows-Specific Monitoring Capabilities

### Windows Event Log Analysis
```xml
<!-- Advanced Windows Event Log monitoring -->
<localfile>
  <location>Security</location>
  <log_format>eventlog</log_format>
  <query>Event/System[EventID=4624 or EventID=4625 or EventID=4634]</query>
</localfile>
```

### Registry Change Detection
```xml
<!-- Critical registry monitoring -->
<registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</registry>
<registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</registry>
<registry check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</registry>
```

### Windows Service Monitoring
```xml
<!-- Monitor critical Windows services -->
<localfile>
  <location>C:\Scripts\windows-service-monitor.log</location>
  <log_format>syslog</log_format>
</localfile>
```

## 🎯 Best Practices for Windows Deployments

### 1. Security Considerations
- **Run as SYSTEM**: Agent operates with highest privileges for comprehensive monitoring
- **Secure Configuration**: Protect configuration files from unauthorized access
- **Network Security**: Use encrypted communication channels
- **Update Management**: Keep agents updated with latest security patches

### 2. Performance Optimization
- **Selective Monitoring**: Monitor only necessary files and registry keys
- **Schedule Scans**: Run intensive scans during off-peak hours
- **Resource Limits**: Configure appropriate memory and CPU limits
- **Log Rotation**: Implement log rotation to prevent disk space issues

### 3. Management and Maintenance
- **Centralized Configuration**: Use agent groups for consistent settings
- **Automated Updates**: Implement automated agent update mechanisms
- **Monitoring Dashboards**: Set up alerts for agent health and performance
- **Documentation**: Maintain detailed deployment and configuration records

### 4. Compliance and Audit
- **Change Tracking**: Monitor configuration changes and unauthorized modifications
- **Access Logging**: Track administrative access and configuration changes
- **Compliance Reports**: Generate reports for regulatory compliance
- **Audit Trails**: Maintain complete audit logs of agent activities

## 📚 Self-Assessment Questions

1. What are the minimum system requirements for Wazuh agent on Windows?
2. How do you configure Windows Event Log monitoring in Wazuh?
3. What are the different methods for deploying Wazuh agent on Windows?
4. How can you troubleshoot connectivity issues between Windows agent and Wazuh server?
5. What Windows-specific security configurations are important for Wazuh deployment?

## 🔗 Next Steps

Now that you understand Windows deployment, let's explore Linux agent deployment procedures.

**[← Previous: Agent Types](./01-agent-types.md)** | **[Next: Linux Deployment →](./03-linux-deployment.md)**