# File Integrity Monitoring (FIM) with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- How file integrity monitoring works in Wazuh
- Configuring FIM policies for different environments
- FIM alerting and response mechanisms
- Performance optimization for FIM scanning
- Integration with compliance requirements
- Troubleshooting common FIM issues

## 📋 What is File Integrity Monitoring?

### Definition and Purpose
**File Integrity Monitoring (FIM)** is a security process that detects and alerts on unauthorized changes to critical system files, directories, and configurations.

### Why FIM Matters
```
┌─────────────────────────────────────────────────────────────┐
│               FILE INTEGRITY MONITORING VALUE               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ DETECT      │  │ PREVENT     │  │ COMPLIANCE  │          │
│  │ CHANGES     │  │ BREACHES    │  │ AUDITING    │          │
│  │             │  │             │  │             │          │
│  │ • Unauthorized│  │ • Malware    │  │ • PCI-DSS    │          │
│  │   modifications││   persistence│  │ • HIPAA      │          │
│  │ • Configuration│  │ • Data       │  │ • ISO 27001  │          │
│  │   tampering   │  │   exfiltration│ │ • GDPR       │          │
│  │ • System      │  │ • Rootkit    │  │ • SOX        │          │
│  │   compromise  │  │   installation│ │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ FORENSICS   │  │ CHANGE      │  │ BASELINE    │          │
│  │ ANALYSIS    │  │ MANAGEMENT  │  │ VALIDATION  │          │
│  │             │  │             │  │             │          │
│  │ • Attack     │  │ • Authorized  │  │ • System     │          │
│  │   timeline   │  │   changes   │  │   integrity  │          │
│  │ • Compromise │  │ • Version    │  │ • Drift       │          │
│  │   indicators │  │   control   │  │   detection   │          │
│  │ • Evidence   │  │ • Audit      │  │ • Anomalies   │          │
│  │   collection │  │   trails    │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ How FIM Works in Wazuh

### FIM Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                WAZUH FIM ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  BASELINE   │───▶│   MONITOR   │───▶│   DETECT    │      │
│  │ COLLECTION  │    │   CHANGES   │    │   ALERTS    │      │
│  │             │    │             │    │             │      │
│  │ • File      │    │ • Real-time  │    │ • Config    │      │
│  │   hashing   │    │ • Scheduled  │    │   changes   │      │
│  │ • Metadata  │    │ • Whitelist  │    │ • Unauthorized│      │
│  │ • Registry  │    │ • Performance│    │   access    │      │
│  │             │    │ • Who/What  │    │ • File       │      │
│  │             │    │ • When      │    │   deletions  │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   STORAGE   │    │   ANALYSIS  │    │   RESPONSE  │      │
│  │             │    │             │    │             │      │
│  │ • Local DB  │    │ • Correlation│    │ • Alerts    │      │
│  │ • Central   │    │ • Rules     │    │ • Automated  │      │
│  │ • Retention │    │ • Thresholds │    │   actions   │      │
│  │             │    │ • Baselines │    │ • Integration│      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### FIM Process Flow

#### 1. Baseline Creation
```bash
# Initial baseline collection
/var/ossec/bin/wazuh-control start
# Agent collects file information
# Calculates hashes and metadata
# Stores baseline in local database
```

#### 2. Continuous Monitoring
```bash
# Real-time monitoring
# Scheduled scans (default: every 6 hours)
# Registry monitoring (Windows)
# Directory watching
# Permission changes
```

#### 3. Change Detection
```bash
# File modification detection
# New file creation alerts
# File deletion tracking
# Permission changes
# Ownership modifications
```

#### 4. Alert Generation
```bash
# Immediate alerts for critical files
# Scheduled summary reports
# Integration with SIEM rules
# Custom alerting based on file types
```

## ⚙️ FIM Configuration

### Basic FIM Setup

#### Windows Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <!-- Directories to monitor -->
  <directories check_all="yes" realtime="yes">C:\Windows</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files (x86)</directories>

  <!-- Windows Registry monitoring -->
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE</registry>
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM</registry>

  <!-- Scan settings -->
  <scan_on_start>yes</scan_on_start>
  <frequency>3600</frequency> <!-- 1 hour -->
  <auto_ignore>no</auto_ignore>

  <!-- Alert settings -->
  <alert_new_files>yes</alert_new_files>
  <ignore>C:\Windows\Temp</ignore>
  <ignore>C:\Users\*\AppData\Local\Temp</ignore>
</syscheck>
```

#### Linux Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <!-- Critical system directories -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/bin</directories>
  <directories check_all="yes" realtime="yes">/sbin</directories>
  <directories check_all="yes" realtime="yes">/usr/bin</directories>
  <directories check_all="yes" realtime="yes">/usr/sbin</directories>

  <!-- Application directories -->
  <directories check_all="yes" realtime="yes">/var/www</directories>
  <directories check_all="yes" realtime="yes">/home</directories>
  <directories check_all="yes">/var/log</directories>

  <!-- Scan settings -->
  <scan_on_start>yes</scan_on_start>
  <frequency>1800</frequency> <!-- 30 minutes -->
  <auto_ignore>no</auto_ignore>

  <!-- Alert settings -->
  <alert_new_files>yes</alert_new_files>
  <ignore>/var/log</ignore>
  <ignore>/tmp</ignore>
  <ignore>/var/tmp</ignore>
</syscheck>
```

### Advanced FIM Configuration

#### Custom File Monitoring
```xml
<!-- Monitor specific file types -->
<syscheck>
  <directories check_all="yes" realtime="yes">/etc/ssh</directories>
  <directories check_all="yes" realtime="yes">/etc/apache2</directories>
  <directories check_all="yes">*.conf</directories>
  <directories check_all="yes">*.key</directories>
  <directories check_all="yes">*.pem</directories>

  <!-- Monitor specific files -->
  <directories check_all="yes" realtime="yes">/etc/passwd</directories>
  <directories check_all="yes" realtime="yes">/etc/shadow</directories>
  <directories check_all="yes" realtime="yes">/etc/sudoers</directories>
</syscheck>
```

#### Performance Optimization
```xml
<!-- Optimized for large environments -->
<syscheck>
  <!-- Reduce scan frequency for large directories -->
  <directories check_all="yes">/var/log</directories>
  <frequency>86400</frequency> <!-- Daily for logs -->

  <!-- Real-time for critical files only -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/bin</directories>

  <!-- Limit file size monitoring -->
  <max_size>100MB</max_size>

  <!-- Use diff for large files -->
  <diff_size_limit>50MB</diff_size_limit>
</syscheck>
```

#### Windows Registry Advanced Monitoring
```xml
<!-- Comprehensive registry monitoring -->
<syscheck>
  <!-- System registry keys -->
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</registry>
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</registry>
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</registry>

  <!-- User registry (all users) -->
  <registry check_all="yes">HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</registry>

  <!-- Security-sensitive keys -->
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SECURITY</registry>
  <registry check_all="yes">HKEY_LOCAL_MACHINE\SAM</registry>
</syscheck>
```

## 🔍 FIM Alert Analysis

### Understanding FIM Events

#### File Change Events
```json
{
  "timestamp": "2024-01-15T10:30:00.000+0000",
  "rule": {
    "id": "550",
    "description": "Integrity checksum changed"
  },
  "syscheck": {
    "path": "/etc/passwd",
    "size_before": "1024",
    "size_after": "1024",
    "perm_before": "0644",
    "perm_after": "0644",
    "uid_before": "0",
    "uid_after": "0",
    "gid_before": "0",
    "gid_after": "0",
    "md5_before": "d41d8cd98f00b204e9800998ecf8427e",
    "md5_after": "f5c7d4f4c8b8c8b8c8b8c8b8c8b8c8b",
    "sha1_before": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha1_after": "3f786850e387550fdab836ed7e6dc881de23001b",
    "event": "modified"
  }
}
```

#### Registry Change Events
```json
{
  "timestamp": "2024-01-15T10:30:00.000+0000",
  "rule": {
    "id": "550",
    "description": "Registry integrity checksum changed"
  },
  "syscheck": {
    "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "type": "registry",
    "event": "modified",
    "registry": {
      "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "value": "NewMalware",
      "type": "REG_SZ",
      "size": "24"
    }
  }
}
```

### FIM Rule Examples

#### Critical File Monitoring
```xml
<!-- Alert on critical system file changes -->
<rule id="100001" level="12">
  <if_group>syscheck</if_group>
  <field name="syscheck.path">/etc/passwd|/etc/shadow|/etc/sudoers</field>
  <description>FIM: Critical system file modified</description>
  <group>fim,critical_file,syscheck</group>
</rule>
```

#### New File Creation Alerts
```xml
<!-- Alert on suspicious file creation -->
<rule id="100002" level="8">
  <if_group>syscheck</if_group>
  <field name="syscheck.event">added</field>
  <field name="syscheck.path">\.exe$|\.dll$|\.bat$|\.cmd$</field>
  <description>FIM: Suspicious executable file created</description>
  <group>fim,new_file,suspicious</group>
</rule>
```

#### Registry Persistence Detection
```xml
<!-- Alert on registry persistence -->
<rule id="100003" level="10">
  <if_group>syscheck</if_group>
  <field name="syscheck.path">HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
  <field name="syscheck.event">modified</field>
  <description>FIM: Registry Run key modified - possible persistence</description>
  <group>fim,registry,persistence</group>
</rule>
```

## 📊 FIM Performance Optimization

### Scan Scheduling Optimization
```xml
<!-- Optimized scan schedules -->
<syscheck>
  <!-- Frequent scans for critical files -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <frequency>300</frequency> <!-- 5 minutes -->

  <!-- Less frequent for large directories -->
  <directories check_all="yes">/var/log</directories>
  <frequency>3600</frequency> <!-- 1 hour -->

  <!-- Daily scans for user directories -->
  <directories check_all="yes">/home</directories>
  <frequency>86400</frequency> <!-- 24 hours -->
</syscheck>
```

### Resource Management
```xml
<!-- Resource optimization -->
<syscheck>
  <!-- Limit file sizes to monitor -->
  <max_eps>100</max_eps> <!-- Events per second limit -->

  <!-- Database optimization -->
  <database>wdb</database>
  <db_clean>yes</db_clean>

  <!-- Memory usage control -->
  <memory_limit>256</memory_limit> <!-- MB -->
</syscheck>
```

### Exclusions and Filtering
```xml
<!-- Smart exclusions -->
<syscheck>
  <!-- Exclude temporary files -->
  <ignore type="sregex">/tmp/.*</ignore>
  <ignore type="sregex">/var/tmp/.*</ignore>
  <ignore>/var/log</ignore>

  <!-- Exclude specific file types -->
  <ignore type="sregex">.*\.log$</ignore>
  <ignore type="sregex">.*\.tmp$</ignore>

  <!-- Exclude specific processes -->
  <ignore type="sregex">/proc/.*</ignore>
  <ignore type="sregex">/sys/.*</ignore>
</syscheck>
```

## 🔧 FIM Integration with Compliance

### PCI-DSS Compliance
```xml
<!-- PCI-DSS FIM requirements -->
<syscheck>
  <!-- Monitor cardholder data environment -->
  <directories check_all="yes" realtime="yes">/var/lib/mysql</directories>
  <directories check_all="yes" realtime="yes">/etc/mysql</directories>

  <!-- Audit logs -->
  <directories check_all="yes">/var/log/mysql</directories>

  <!-- System configuration -->
  <directories check_all="yes" realtime="yes">/etc/apache2</directories>
  <directories check_all="yes" realtime="yes">/etc/ssh</directories>
</syscheck>
```

### HIPAA Compliance
```xml
<!-- HIPAA FIM monitoring -->
<syscheck>
  <!-- Protected Health Information -->
  <directories check_all="yes" realtime="yes">/var/medical_records</directories>
  <directories check_all="yes" realtime="yes">/etc/healthcare_app</directories>

  <!-- Audit logs -->
  <directories check_all="yes">/var/log/healthcare</directories>

  <!-- System configuration -->
  <directories check_all="yes" realtime="yes">/etc</directories>
</syscheck>
```

## 🚨 FIM Incident Response

### Automated Response Actions
```xml
<!-- Active response for FIM events -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100001,100002,100003</rules_id>
  <timeout>300</timeout>
</active-response>
```

### Investigation Workflow
```bash
# FIM investigation steps
1. Review FIM alert details
2. Check file change timeline
3. Identify user/process responsible
4. Verify change legitimacy
5. Restore from backup if malicious
6. Update FIM rules if needed
7. Document incident
8. Report to security team
```

## 📊 FIM Reporting and Analytics

### FIM Dashboard Configuration
```json
{
  "title": "FIM Overview Dashboard",
  "visState": {
    "title": "File Integrity Monitoring",
    "type": "table",
    "params": {
      "perPage": 10,
      "showPartialRows": false,
      "showMeticsAtAllLevels": false,
      "sort": {
        "columnIndex": 0,
        "direction": "desc"
      }
    }
  }
}
```

### Key FIM Metrics
```bash
# Monitor FIM effectiveness
FIM_EVENTS_TOTAL=$(curl -s -u admin:admin -k "https://localhost:55000/events?q=rule.groups:fim" | jq '.data.totalItems')
FIM_ALERTS_CRITICAL=$(curl -s -u admin:admin -k "https://localhost:55000/events?q=rule.level:>10 AND rule.groups:fim" | jq '.data.totalItems')
FIM_BASELINE_SIZE=$(du -sh /var/ossec/queue/syscheck/ | cut -f1)

echo "FIM Events: $FIM_EVENTS_TOTAL"
echo "Critical Alerts: $FIM_ALERTS_CRITICAL"
echo "Database Size: $FIM_BASELINE_SIZE"
```

## 🔧 Troubleshooting FIM Issues

### Common Problems and Solutions

#### Issue 1: High CPU Usage
```bash
# Check FIM process usage
ps aux | grep wazuh-syscheck

# Reduce scan frequency
<frequency>3600</frequency> <!-- Increase to 1 hour -->

# Exclude large directories
<ignore>/var/log</ignore>
<ignore>/tmp</ignore>
```

#### Issue 2: Database Corruption
```bash
# Stop agent
sudo systemctl stop wazuh-agent

# Clear FIM database
rm -f /var/ossec/queue/syscheck/*

# Restart agent (will rebuild baseline)
sudo systemctl start wazuh-agent
```

#### Issue 3: False Positives
```bash
# Add exclusions for legitimate changes
<ignore type="sregex">/var/log/.*\.log$</ignore>
<ignore>/tmp/*</ignore>

# Use nodiff for frequently changing files
<nodiff>/var/log/syslog</nodiff>
```

#### Issue 4: Missing Events
```bash
# Check agent connectivity
/var/ossec/bin/agent_control -i

# Verify configuration
cat /var/ossec/etc/ossec.conf | grep -A 10 "<syscheck>"

# Check agent logs
tail -f /var/ossec/logs/ossec.log
```

## 🎯 Best Practices for FIM Deployment

### 1. Planning and Design
- **Assess Requirements**: Identify critical files and systems to monitor
- **Performance Impact**: Evaluate resource requirements for your environment
- **Change Management**: Plan for handling authorized file changes
- **Alert Tuning**: Configure appropriate alert levels and responses

### 2. Implementation Strategy
- **Phased Deployment**: Start with critical systems and expand gradually
- **Baseline Creation**: Ensure clean baseline before enabling monitoring
- **Testing**: Thoroughly test FIM configuration in staging environment
- **Documentation**: Document all monitored files and alerting rules

### 3. Operations and Maintenance
- **Regular Review**: Review FIM alerts and adjust rules as needed
- **Performance Monitoring**: Monitor FIM impact on system resources
- **Database Maintenance**: Regular cleanup and optimization of FIM database
- **Rule Updates**: Keep FIM rules current with threat landscape

### 4. Integration and Automation
- **SIEM Integration**: Forward FIM alerts to central SIEM system
- **Automated Response**: Configure automated responses for critical changes
- **Ticketing Integration**: Create tickets for FIM incidents
- **Reporting**: Generate regular FIM compliance and security reports

## 📚 Self-Assessment Questions

1. What is file integrity monitoring and why is it important?
2. How does Wazuh implement FIM differently on Windows vs Linux?
3. What are the key components of a FIM configuration in Wazuh?
4. How can you optimize FIM performance for large environments?
5. What are the best practices for handling FIM alerts and investigations?

## 🔗 Next Steps

Now that you understand file integrity monitoring, let's explore vulnerability detection capabilities in Wazuh.

**[← Previous: MITRE ATT&CK Framework](./02-mitre-attck-framework.md)** | **[Next: Vulnerability Detection](./04-vulnerability-detection.md)**