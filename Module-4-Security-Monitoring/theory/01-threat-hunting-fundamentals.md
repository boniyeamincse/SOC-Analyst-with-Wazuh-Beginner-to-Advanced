# Threat Hunting Fundamentals with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- What threat hunting is and why it's essential for modern security
- Systematic approaches to threat hunting operations
- How to integrate threat hunting with Wazuh capabilities
- Different threat hunting methodologies and frameworks
- Tools and techniques for effective threat discovery
- Measuring the effectiveness of threat hunting programs

## 📋 What is Threat Hunting?

### Definition and Core Concept

**Threat Hunting** is the proactive, systematic process of searching for hidden threats, malicious activities, and security weaknesses within an organization's IT environment that may have evaded automated detection systems.

Unlike traditional security monitoring that waits for alerts, threat hunting assumes that:
- Attackers may already be present in the network
- Automated systems may miss sophisticated attacks
- Manual investigation is necessary to uncover hidden threats

### The Threat Hunting Mindset

```
Traditional Security: "Wait for alerts and respond"
Threat Hunting: "Assume breach and actively search"
```

### Historical Evolution

1. **Early Days**: Reactive incident response only
2. **2000s**: Introduction of SIEM and automated detection
3. **2010s**: Recognition that automated systems aren't enough
4. **Present**: Proactive threat hunting as a core security discipline
5. **Future**: AI-assisted and automated threat hunting

## 🏹 Threat Hunting vs Traditional Security

### Traditional Security Approach
```bash
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ATTACK        │───▶│   DETECTION     │───▶│   RESPONSE      │
│   (Unknown)     │    │   (Automated)   │    │   (Reactive)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Threat Hunting Approach
```bash
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HYPOTHESIS    │───▶│   INVESTIGATION │───▶│   DISCOVERY     │
│   (Proactive)   │    │   (Manual)      │    │   (Continuous)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Differences

| Aspect | Traditional Security | Threat Hunting |
|--------|---------------------|----------------|
| **Approach** | Reactive | Proactive |
| **Detection** | Signature-based | Behavioral + Intelligence |
| **Scope** | Known threats | Unknown threats |
| **Timing** | After attack | Before/during attack |
| **Tools** | SIEM, IDS/IPS | Advanced analytics, manual investigation |
| **Skills** | Technical operations | Investigative analysis |

## 🔍 Threat Hunting Methodologies

### 1. Hypothesis-Driven Hunting

#### Process Overview
1. **Formulate Hypothesis**: Based on threat intelligence, recent attacks, or system knowledge
2. **Define Scope**: Determine systems, timeframes, and data sources to investigate
3. **Collect Data**: Gather relevant logs, events, and system information
4. **Analyze Data**: Look for indicators supporting or refuting the hypothesis
5. **Document Findings**: Record results and update threat intelligence
6. **Refine Hypothesis**: Adjust based on findings and continue investigation

#### Example Hypotheses
- "Attackers are using living-off-the-land techniques in our environment"
- "Credential theft may be occurring through Pass-the-Hash attacks"
- "Malware persistence mechanisms exist in startup folders"
- "Data exfiltration is happening through DNS tunneling"

### 2. Intelligence-Driven Hunting

#### Leveraging Threat Intelligence
```bash
External Intelligence Sources:
├── MITRE ATT&CK framework
├── Vendor threat reports
├── Security community sharing
├── Dark web monitoring
├── Government alerts
└── Industry-specific intelligence
```

#### Intelligence-to-Hunting Translation
1. **Ingest Intelligence**: Collect and process threat intelligence
2. **Map to Environment**: Translate generic indicators to specific environment
3. **Create Detection Logic**: Develop rules and queries for identified threats
4. **Hunt Systematically**: Search for indicators across the environment
5. **Validate Findings**: Confirm if detected activity is malicious
6. **Update Intelligence**: Feed findings back into intelligence cycle

### 3. Analytics-Driven Hunting

#### Data Analytics Approaches
- **Statistical Analysis**: Identify anomalies through statistical modeling
- **Machine Learning**: Use ML algorithms to detect unusual patterns
- **Behavioral Analysis**: Monitor for deviations from normal behavior
- **Correlation Analysis**: Find relationships between disparate events

#### Analytics Hunting Process
1. **Establish Baselines**: Define normal behavior patterns
2. **Monitor Deviations**: Track anomalies from established baselines
3. **Investigate Anomalies**: Determine if deviations are malicious
4. **Refine Models**: Update analytics based on investigation results
5. **Automate Detection**: Implement automated alerting for identified patterns

### 4. Situational Awareness Hunting

#### Current Environment Assessment
- **Asset Discovery**: Identify all systems and their configurations
- **Vulnerability Assessment**: Map known weaknesses
- **Traffic Analysis**: Understand normal network communication patterns
- **User Behavior**: Establish normal user activity baselines

#### Situational Hunting Techniques
- **Log Analysis**: Deep dive into system and security logs
- **Network Traffic Inspection**: Analyze network communications
- **Endpoint Investigation**: Examine individual system states
- **Configuration Review**: Check system and application configurations

## 🛠️ Wazuh Threat Hunting Capabilities

### Leveraging Wazuh for Threat Hunting

#### 1. Advanced Query Capabilities
```bash
# Wazuh query examples for threat hunting
# Search for suspicious login patterns
agent.id=001 AND rule.id=5710 AND srcip!=192.168.0.0/16

# Hunt for privilege escalation attempts
agent.id=* AND rule.group=privilege_escalation

# Look for unusual process executions
agent.id=* AND rule.id=100001 AND process.name!=/normal_processes/
```

#### 2. Custom Rule Development
```xml
<!-- Custom threat hunting rule -->
<rule id="100500" level="12">
  <if_sid>5710</if_sid>
  <field name="srcip">!192.168.0.0/16</field>
  <match>Failed password</match>
  <frequency>5</frequency>
  <timeframe>300</timeframe>
  <description>Potential brute force attack from external IP</description>
  <group>threat_hunting,brute_force,external_attack</group>
</rule>
```

#### 3. File Integrity Monitoring for Hunting
```bash
# Monitor critical system files for changes
<directories check_all="yes" realtime="yes">/etc/passwd</directories>
<directories check_all="yes" realtime="yes">/etc/shadow</directories>
<directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
```

#### 4. Log Analysis for Threat Patterns
```bash
# Search for suspicious command executions
grep "powershell.*-enc" /var/ossec/logs/alerts/alerts.log

# Look for unusual network connections
grep "ESTABLISHED" /var/log/syslog | grep -v "normal_services"

# Hunt for privilege escalation indicators
grep "sudo.*root" /var/log/auth.log | grep -v "legitimate_users"
```

### Wazuh Hunting Dashboard Setup

#### Custom Dashboard Configuration
```json
{
  "title": "Threat Hunting Dashboard",
  "visState": {
    "title": "Threat Hunting Overview",
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

## 📊 Threat Hunting Frameworks and Models

### The Intelligence Cycle in Threat Hunting

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   PLANNING  │───▶│   COLLECTION│───▶│   ANALYSIS  │
│             │    │             │    │             │
│ • Hypothesis │    │ • Evidence  │    │ • Patterns  │
│ • Resources  │    │ • Logs      │    │ • IOCs      │
│ • Tools      │    │ • Network   │    │ • TTPs      │
└─────────────┘    └─────────────┘    └─────────────┘
      ▲                     ▲                     │
      │                     │                     ▼
      └─────────────────────┼───────────────▶┌─────────────┐
                            │               │ DISSEMINATION│
                            │               │             │
                            │               │ • Reports   │
                            │               │ • Alerts    │
                            │               │ • Actions   │
                            └───────────────┘─────────────┘
```

### Structured Hunting Models

#### 1. The Pyramid of Pain
```
┌─────────────────────────────────────────────────────────────┐
│                    PYRAMID OF PAIN                          │
├─────────────────────────────────────────────────────────────┤
│   TRIVIAL                EASY               MODERATE        │
├─────────────────────────────────────────────────────────────┤
│  Hash Values ──────────▶ IP Addresses ────▶ Domain Names ──▶│
│  (Easiest to change)    │  (Easy to change) │  (Harder)     │
├─────────────────────────────────────────────────────────────┤
│                        Network/Host Artifacts ─────────────▶│
│                        (Hardest to change)                 │
├─────────────────────────────────────────────────────────────┤
│   LOW IMPACT            MEDIUM IMPACT      HIGH IMPACT     │
└─────────────────────────────────────────────────────────────┘
```

#### 2. The Hunting Loop
```
┌─────────────────────────────────────────────────────────────┐
│                      THE HUNTING LOOP                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │ UNCOVER     │───▶│  ANALYZE   │───▶│  RESPOND   │      │
│  │ THREATS     │    │ FINDINGS   │    │            │      │
│  │             │    │            │    │            │      │
│  │ • Search    │    │ • Context  │    │ • Contain   │      │
│  │ • Discover  │    │ • Impact   │    │ • Remediate │      │
│  │ • Investigate│    │ • Scope   │    │ • Report    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│         ▲                     ▲                     │        │
│         └─────────────────────┼─────────────────────┘        │
│                               │                              │
│                ┌─────────────┐                               │
│                │   LEARN    │                               │
│                │ & IMPROVE  │                               │
│                │            │                               │
│                │ • Insights │                               │
│                │ • Rules    │                               │
│                │ • Process  │                               │
│                └─────────────┘                               │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Threat Hunting Tools and Techniques

### Data Collection Tools
- **Log Aggregators**: Collect logs from multiple sources
- **Network Packet Captures**: Analyze network traffic
- **Endpoint Detection**: Monitor system activities
- **Memory Analysis**: Examine running processes
- **File System Analysis**: Check file modifications

### Analysis Techniques
- **Timeline Analysis**: Reconstruct attack sequences
- **Pattern Recognition**: Identify malicious behavior patterns
- **Anomaly Detection**: Find deviations from normal behavior
- **Correlation Analysis**: Connect related events
- **Root Cause Analysis**: Determine attack origins

### Hunting Playbook Examples

#### 1. Credential Theft Hunting
```bash
# Hypothesis: Attackers are stealing credentials
# Investigation steps:
1. Check for unusual login patterns
2. Look for Pass-the-Hash indicators
3. Examine authentication logs for anomalies
4. Monitor for suspicious account usage
5. Check for lateral movement signs
```

#### 2. Malware Persistence Hunting
```bash
# Hypothesis: Malware has achieved persistence
# Investigation steps:
1. Check startup folders and registry keys
2. Examine scheduled tasks and cron jobs
3. Look for unusual service installations
4. Monitor for fileless malware indicators
5. Check for rootkit presence
```

#### 3. Data Exfiltration Hunting
```bash
# Hypothesis: Sensitive data is being exfiltrated
# Investigation steps:
1. Monitor unusual outbound traffic
2. Check for DNS tunneling attempts
3. Look for encrypted channel usage
4. Examine file access patterns
5. Monitor for large data transfers
```

## 📈 Measuring Threat Hunting Effectiveness

### Key Performance Indicators (KPIs)

#### Operational Metrics
- **Dwell Time Reduction**: Time between compromise and detection
- **Threat Detection Rate**: Percentage of threats found through hunting
- **False Positive Rate**: Accuracy of hunting findings
- **Investigation Time**: Average time to complete hunt analysis

#### Quality Metrics
- **Threat Intelligence Quality**: Usefulness of hunting intelligence
- **Process Maturity**: Effectiveness of hunting methodologies
- **Team Skills**: Hunter expertise and training levels
- **Tool Effectiveness**: Performance of hunting tools and platforms

### Success Measurement Framework
```bash
┌─────────────────────────────────────────────────────────────┐
│               THREAT HUNTING SUCCESS METRICS                │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  DETECTION  │  │  PREVENTION │  │  RESPONSE   │          │
│  │             │  │             │  │             │          │
│  │ • Threats   │  │ • Attacks   │  │ • Time      │          │
│  │   Found     │  │   Stopped   │  │ • Efficiency│          │
│  │ • Accuracy  │  │ • Coverage  │  │ • Cost      │          │
│  │ • Speed     │  │             │  │   Savings   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  LEARNING   │  │  MATURITY  │  │  IMPACT     │          │
│  │             │  │             │  │             │          │
│  │ • Intelligence│  │ • Process  │  │ • Business │          │
│  │ • Skills     │  │ • Tools    │  │   Value    │          │
│  │ • Techniques │  │ • Team     │  │ • ROI      │          │
│  │             │  │             │  │            │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 Best Practices for Threat Hunting

### 1. Structured Methodology
- Use systematic approaches to ensure comprehensive coverage
- Document all hunting activities and findings
- Maintain hunting playbooks for common scenarios
- Regularly update methodologies based on lessons learned

### 2. Intelligence Integration
- Incorporate threat intelligence into hunting activities
- Use external intelligence to inform hunting hypotheses
- Share hunting findings with intelligence teams
- Build institutional knowledge from hunting results

### 3. Tool and Technology Optimization
- Select appropriate tools for different hunting scenarios
- Customize tools to fit specific environment needs
- Regularly evaluate and update hunting toolsets
- Integrate tools for comprehensive visibility

### 4. Team Development
- Train hunters in both technical and analytical skills
- Encourage knowledge sharing among team members
- Develop specialized roles within hunting teams
- Maintain work-life balance to prevent burnout

### 5. Process Improvement
- Regularly review and refine hunting processes
- Implement feedback loops for continuous improvement
- Measure and track hunting program effectiveness
- Adapt to changing threat landscapes and technologies

## 📚 Self-Assessment Questions

1. What is the fundamental difference between traditional security monitoring and threat hunting?
2. Describe the key phases of hypothesis-driven threat hunting.
3. How can Wazuh be used as a threat hunting platform?
4. What is the Pyramid of Pain and how does it apply to threat hunting?
5. How would you measure the effectiveness of a threat hunting program?

## 🔗 Next Steps

Now that you understand threat hunting fundamentals, let's explore the MITRE ATT&CK framework and how to apply it in threat hunting operations.

**[← Back to Module Overview](../README.md)** | **[Next: MITRE ATT&CK Framework →](./02-mitre-attck-framework.md)**