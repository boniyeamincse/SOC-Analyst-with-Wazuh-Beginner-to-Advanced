# MITRE ATT&CK Framework in Threat Hunting

## 🎯 Learning Objectives

By the end of this section, you will understand:
- The structure and components of the MITRE ATT&CK framework
- How to apply ATT&CK for threat detection and hunting
- Mapping Wazuh capabilities to ATT&CK techniques
- Creating ATT&CK-based detection rules
- Using ATT&CK for threat intelligence and analysis

## 📋 Introduction to MITRE ATT&CK

### Framework Overview
**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

```
┌─────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK FRAMEWORK                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   TACTICS   │  │ TECHNIQUES  │  │ PROCEDURES  │          │
│  │             │  │             │  │             │          │
│  │ • Recon     │  │ • Methods   │  │ • Commands  │          │
│  │ • Initial   │  │ • Tools     │  │ • Scripts   │          │
│  │   Access    │  │ • Behaviors │  │ • Malware   │          │
│  │ • Execution │  │ • Indicators│  │ • TTPs      │          │
│  │ • Persistence│  │             │  │             │          │
│  │ • Privilege  │  │             │  │             │          │
│  │   Escalation │  │             │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   MATRIX    │  │   NAVIGATOR │  │   SUB-     │          │
│  │             │  │             │  │   TECHNIQUES│          │          │
│  │ • Enterprise│  │ • Visual    │  │ • Mobile    │          │
│  │ • Mobile    │  │   Mapping   │  │ • ICS       │          │
│  │ • ICS       │  │ • Layer     │  │ • Cloud     │          │
│  │             │  │   Analysis  │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### Why ATT&CK Matters for SOC

#### 1. Standardized Language
- **Common terminology** for describing threat behaviors
- **Consistent communication** across security teams
- **Unified understanding** of adversary actions

#### 2. Proactive Defense
- **Predictive capabilities** based on known adversary patterns
- **Gap analysis** to identify missing detections
- **Threat modeling** for attack chain prevention

#### 3. Intelligence Integration
- **Threat intelligence mapping** to specific techniques
- **Indicator enrichment** with context and behavior
- **Prioritization** based on adversary capabilities

## 🏗️ ATT&CK Framework Structure

### Core Components

#### 1. Tactics (Why)
Tactics represent the **technical objectives** that adversaries achieve through their actions.

**Enterprise Tactics:**
- **Reconnaissance** - Gathering information about targets
- **Resource Development** - Establishing resources for operations
- **Initial Access** - Gaining entry to systems
- **Execution** - Running malicious code
- **Persistence** - Maintaining access
- **Privilege Escalation** - Gaining higher permissions
- **Defense Evasion** - Avoiding detection
- **Credential Access** - Stealing account credentials
- **Discovery** - Exploring environment
- **Lateral Movement** - Moving through network
- **Collection** - Gathering data of interest
- **Command and Control** - Communicating with compromised systems
- **Exfiltration** - Stealing data
- **Impact** - Manipulating, interrupting, or destroying systems

#### 2. Techniques (How)
Techniques are the **methods** adversaries use to achieve tactical objectives.

**Examples by Tactic:**

**Initial Access:**
- T1078 - Valid Accounts (using legitimate credentials)
- T1133 - External Remote Services (VPN, RDP, Citrix)
- T1566 - Phishing (email, spear-phishing, etc.)
- T1190 - Exploit Public-Facing Application
- T1134 - Access Token Manipulation

**Execution:**
- T1059 - Command and Scripting Interpreter (PowerShell, Python, etc.)
- T1204 - User Execution (malicious attachments, links)
- T1053 - Scheduled Task/Job
- T1106 - Native API

**Persistence:**
- T1098 - Account Manipulation
- T1547 - Boot or Logon Autostart Execution
- T1053 - Scheduled Task/Job
- T1543 - Create or Modify System Process

#### 3. Sub-techniques (Specific Methods)
Sub-techniques provide **more granular detail** about how techniques are implemented.

**Example: T1059 Command and Scripting Interpreter**
- T1059.001 - PowerShell
- T1059.002 - AppleScript
- T1059.003 - Windows Command Shell
- T1059.004 - Unix Shell
- T1059.005 - Visual Basic
- T1059.006 - Python
- T1059.007 - JavaScript

### ATT&CK Matrix Structure

#### Enterprise Matrix
```
┌─────────────────────────────────────────────────────────────────────┐
│                           ENTERPRISE MATRIX                          │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────┤
│ Reconnaissance │ Weaponization │ Delivery    │ Exploitation│ Installation │
├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
│ Discovery   │ Persistence  │ Privilege    │ Execution    │ Defense     │
│             │              │ Escalation   │              │ Evasion     │
├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
│ Lateral     │ Collection   │ Exfiltration │ Command &    │ Impact      │
│ Movement    │              │              │ Control      │             │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
```

## 🔍 Applying ATT&CK in Threat Hunting

### Hunt Hypothesis Development

#### 1. Tactic-Based Hypotheses
```bash
# Examples of hunt hypotheses based on ATT&CK tactics:

# Persistence Hunting
"Hypotheses: Adversaries have established persistence mechanisms on our systems"
- Look for: Scheduled tasks, startup folders, registry keys
- ATT&CK: T1053, T1547, T1543

# Lateral Movement
"Hypothesis: Attackers are moving laterally through our network"
- Look for: Unusual login patterns, network connections
- ATT&CK: T1021, T1078, T1091

# Credential Access
"Hypothesis: Adversaries are attempting to steal credentials"
- Look for: LSASS access, password dumping, Kerberos attacks
- ATT&CK: T1003, T1555, T1110
```

#### 2. Technique-Focused Hunting
```bash
# Specific technique hunting:

# PowerShell Empire Detection
"Hypothesis: Attackers are using PowerShell Empire for command execution"
- Look for: Base64 encoded commands, Empire-specific patterns
- ATT&CK: T1059.001, T1027, T1055

# Living-off-the-Land
"Hypothesis: Attackers are using legitimate tools maliciously"
- Look for: Unusual use of net.exe, wmic.exe, powershell.exe
- ATT&CK: T1218, T1059, T1106
```

### Intelligence-Led Hunting

#### Threat Actor Profiling
```bash
# APT29 (Cozy Bear) Profile:
"Tactics: Initial Access (T1078), Execution (T1059), Persistence (T1547)"
"Techniques: Valid Accounts, PowerShell, Registry Run Keys"
"Hunting Focus: Look for these patterns in combination"

# APT41 Profile:
"Tactics: Initial Access (T1190), Execution (T1059), Lateral Movement (T1021)"
"Techniques: Exploit Public Apps, PowerShell, Remote Services"
"Hunting Focus: Web server exploitation followed by PowerShell usage"
```

#### IOC to ATT&CK Mapping
```bash
# Map indicators to techniques:

# File Hash → Technique
"Hash: 5d2c7b8b9d1e4f3a6c8e2b7d9f4a1c5 → T1059.001 (PowerShell)"

# Domain → Technique
"Domain: malicious.c2.server → T1071 (Application Layer Protocol)"

# Registry Key → Technique
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run → T1547.001 (Registry Run Keys)"

# Process → Technique
"powershell.exe -enc <base64> → T1059.001 + T1027 (PowerShell + Obfuscated Files)"
```

## 🛠️ Wazuh and ATT&CK Integration

### Mapping Wazuh Rules to ATT&CK

#### 1. Rule Tagging with ATT&CK
```xml
<!-- Wazuh rule with ATT&CK mapping -->
<rule id="100500" level="12">
  <if_sid>5710</if_sid>
  <match>^Failed password</match>
  <description>ATT&CK T1110: Brute Force Attack</description>
  <group>attack,brute_force,att&ck_t1110</group>
  <mitre>
    <id>T1110</id>
    <tactic>Credential Access</tactic>
    <technique>Brute Force</technique>
  </mitre>
</rule>
```

#### 2. ATT&CK-Based Detection Rules
```xml
<!-- PowerShell Empire detection -->
<rule id="100501" level="15">
  <decoded_as>windows-eventlog</decoded_as>
  <field name="win.system.eventID">^4688$</field>
  <match>powershell.*-enc.*[A-Za-z0-9+/=]{100,}</match>
  <description>ATT&CK T1059.001: PowerShell with Base64 Encoding</description>
  <group>attack,powershell,att&ck_t1059_001</group>
</rule>

<!-- Registry persistence -->
<rule id="100502" level="10">
  <if_group>syscheck</if_group>
  <match>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</match>
  <description>ATT&CK T1547.001: Registry Run Keys</description>
  <group>persistence,registry,att&ck_t1547_001</group>
</rule>
```

### ATT&CK Navigator Integration

#### Custom ATT&CK Layer Creation
```json
{
  "name": "Wazuh SOC Coverage",
  "version": "4.4",
  "domain": "enterprise-attack",
  "description": "Wazuh detection coverage mapped to ATT&CK",
  "techniques": [
    {
      "techniqueID": "T1110",
      "score": 100,
      "comment": "Brute force detection via SSH/PowerShell logs",
      "enabled": true,
      "metadata": [
        {
          "name": "Detection Rule",
          "value": "Rule ID: 100500"
        }
      ]
    },
    {
      "techniqueID": "T1059.001",
      "score": 90,
      "comment": "PowerShell execution monitoring",
      "enabled": true
    }
  ]
}
```

## 📊 ATT&CK-Based Threat Hunting Workflow

### 1. Intelligence Gathering
```bash
# Collect threat intelligence
curl -s "https://api.mitre.org/techniques" | jq '.[] | select(.id == "T1059")'

# Map to Wazuh capabilities
# T1059: Command and Scripting Interpreter
# Wazuh detection: Log monitoring, process monitoring, command execution tracking
```

### 2. Hypothesis Development
```bash
# Create hunting hypotheses based on ATT&CK
echo "Hypothesis: APT group X is using T1059.001 (PowerShell) for execution"
echo "Look for: Base64 encoded commands, unusual PowerShell usage"
echo "Timeframe: Last 30 days"
echo "Scope: Windows servers and workstations"
```

### 3. Data Collection
```bash
# Query Wazuh for relevant data
curl -u admin:admin -k -X GET "https://localhost:55000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "rule.groups:powershell AND agent.id:*",
    "size": 1000,
    "sort": "timestamp:desc"
  }'
```

### 4. Analysis and Detection
```bash
# Analyze collected data for ATT&CK patterns
# Look for technique combinations
# Identify anomalous behavior
# Correlate with other indicators
```

### 5. Response and Reporting
```bash
# Generate ATT&CK-based reports
# Update detection rules
# Share intelligence with team
# Improve future hunting efforts
```

## 🎯 Practical ATT&CK Applications

### Building ATT&CK Detection Coverage

#### 1. Coverage Assessment
```bash
# Assess current ATT&CK coverage
curl -s "https://api.mitre.org/techniques" | jq 'length'

# Check Wazuh rule coverage
grep -r "att&ck" /var/ossec/rules/ | wc -l

# Identify gaps
# Compare against threat actor profiles
# Prioritize based on risk
```

#### 2. Gap Analysis and Prioritization
```bash
# Identify missing detections
echo "Missing ATT&CK Coverage:"
echo "- T1027: Obfuscated Files or Information"
echo "- T1070: Indicator Removal on Host"
echo "- T1497: Virtualization/Sandbox Evasion"

# Prioritize based on:
# 1. High-impact techniques
# 2. Common adversary usage
# 3. Current threat intelligence
# 4. Available data sources
```

#### 3. Detection Development
```xml
<!-- New rule for missing technique -->
<rule id="100503" level="12">
  <decoded_as>windows-eventlog</decoded_as>
  <field name="win.system.eventID">^4104$</field>
  <match>ScriptBlock.*-f.*format</match>
  <description>ATT&CK T1027: PowerShell Script Obfuscation</description>
  <group>attack,powershell,obfuscation,att&ck_t1027</group>
</rule>
```

### Threat Actor Hunting Playbooks

#### 1. APT Group TTP Mapping
```bash
# Create hunting playbook for specific threat actor
echo "Threat Actor: APT29 (Cozy Bear)"
echo "Primary Tactics: Initial Access, Execution, Persistence"
echo "Key Techniques: T1078, T1059, T1547"
echo "Hunting Queries:"
echo "1. Unusual privileged account usage"
echo "2. PowerShell execution patterns"
echo "3. Registry persistence mechanisms"
```

#### 2. Automated ATT&CK Rule Generation
```bash
#!/bin/bash
# Generate Wazuh rules from ATT&CK data

ATTACK_TECHNIQUE="T1059.001"
RULE_ID="100504"

cat << EOF > /var/ossec/rules/attck_$RULE_ID.xml
<rule id="$RULE_ID" level="10">
  <decoded_as>windows-eventlog</decoded_as>
  <field name="win.system.eventID">^4688$</field>
  <match>powershell</match>
  <description>ATT&CK $ATTACK_TECHNIQUE: PowerShell Execution</description>
  <group>execution,powershell,att&ck_$ATTACK_TECHNIQUE</group>
</rule>
EOF
```

## 📊 Measuring ATT&CK Coverage Effectiveness

### Coverage Metrics
```bash
# Calculate ATT&CK coverage
TOTAL_TECHNIQUES=$(curl -s "https://api.mitre.org/techniques" | jq 'length')
DETECTED_TECHNIQUES=$(grep -r "att&ck" /var/ossec/rules/ | wc -l)
COVERAGE_PERCENTAGE=$((DETECTED_TECHNIQUES * 100 / TOTAL_TECHNIQUES))

echo "ATT&CK Coverage: $COVERAGE_PERCENTAGE%"
```

### Effectiveness Metrics
```bash
# Track detection effectiveness
echo "Detection Effectiveness Metrics:"
echo "1. True Positive Rate"
echo "2. False Positive Rate"
echo "3. Time to Detection"
echo "4. Coverage by Tactic"
echo "5. Threat Actor Coverage"
```

### Continuous Improvement
```bash
# Regular coverage assessment
# 1. Review new ATT&CK updates
# 2. Analyze detection gaps
# 3. Update rules based on new intelligence
# 4. Test new detections
# 5. Measure improvement over time
```

## 🎯 Best Practices for ATT&CK Implementation

### 1. Start Small and Scale
- Begin with high-impact techniques
- Gradually expand coverage
- Focus on your environment and threats
- Build upon existing detections

### 2. Integrate with Threat Intelligence
- Map intelligence to ATT&CK techniques
- Use ATT&CK for threat actor profiling
- Enrich alerts with ATT&CK context
- Share findings with intelligence teams

### 3. Maintain Updated Knowledge
- Stay current with ATT&CK updates
- Follow threat actor technique evolution
- Update rules as new techniques emerge
- Participate in ATT&CK community

### 4. Measure and Improve
- Track coverage metrics regularly
- Assess detection effectiveness
- Identify and address gaps
- Continuously refine approach

## 📚 Self-Assessment Questions

1. What are the main components of the MITRE ATT&CK framework?
2. How can ATT&CK be used to develop threat hunting hypotheses?
3. What are the differences between tactics and techniques in ATT&CK?
4. How can Wazuh rules be mapped to ATT&CK techniques?
5. What are the best practices for implementing ATT&CK in a SOC environment?

## 🔗 Next Steps

Now that you understand the MITRE ATT&CK framework, let's explore file integrity monitoring (FIM) as a key security monitoring capability.

**[← Previous: Threat Hunting Fundamentals](./01-threat-hunting-fundamentals.md)** | **[Next: File Integrity Monitoring](./03-file-integrity-monitoring.md)**