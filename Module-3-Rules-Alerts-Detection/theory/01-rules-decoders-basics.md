# Wazuh Rules & Decoders: Detection Engine Fundamentals

## 🎯 Learning Objectives

By the end of this section, you will understand:
- How Wazuh's detection engine processes security events
- The relationship between decoders and rules
- Rule syntax and structure components
- Decoder functionality and log parsing
- Alert generation and management processes

## 📋 Wazuh Detection Engine Overview

### Core Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                 WAZUH DETECTION ENGINE                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   LOG       │────▶   DECODER   │────▶   RULE      │      │
│  │  COLLECTION │    │   ENGINE    │    │   ENGINE    │      │
│  │             │    │             │    │             │      │
│  │ • Raw logs  │    │ • Parse &   │    │ • Analyze & │      │
│  │ • Events    │    │   normalize │    │   correlate │      │
│  │ • Metrics   │    │ • Extract   │    │ • Generate  │      │
│  │             │    │   fields    │    │   alerts    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   ALERT     │    │   STORAGE   │    │   ACTION    │      │
│  │ GENERATION  │    │   & INDEX   │    │   ENGINE    │      │
│  │             │    │             │    │             │      │
│  │ • Severity  │    │ • Elastic-  │    │ • Email     │      │
│  │ • Priority  │    │   search    │    │ • Scripts   │      │
│  │ • Context   │    │ • Dash-     │    │ • Integration│      │
│  │             │    │   boards    │    │             │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Processing Flow
1. **Log Collection**: Agents gather raw log data from various sources
2. **Decoder Processing**: Raw logs are parsed and normalized into structured data
3. **Rule Evaluation**: Structured data is analyzed against detection rules
4. **Alert Generation**: Matching rules generate alerts with appropriate severity
5. **Action Execution**: Automated responses are triggered based on alert conditions

## 🔧 Understanding Decoders

### What are Decoders?
Decoders are XML configuration files that parse and normalize log data from different sources. They extract structured information from raw log entries, making them suitable for rule analysis.

### Decoder Structure
```xml
<decoder name="example_decoder">
  <program_name>application_name</program_name>
  <prematch>^Specific pattern to match</prematch>
  <regex>^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (.+)$</regex>
  <order>date,time,level,message</order>
  <fts>name,date,time,message</fts>
</decoder>
```

### Key Decoder Elements

#### 1. Program Name
```xml
<program_name>sshd</program_name>
```
- **Purpose**: Identifies the application or service generating the log
- **Usage**: Matches logs from specific programs
- **Example**: `sshd`, `apache`, `windows-eventlog`

#### 2. Prematch Pattern
```xml
<prematch>^Dec \d{2} \d{2}:\d{2}:\d{2}</prematch>
```
- **Purpose**: Initial pattern to identify log format
- **Usage**: Quick filtering before detailed parsing
- **Performance**: Improves processing efficiency

#### 3. Regular Expression
```xml
<regex>^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (.+)$</regex>
```
- **Purpose**: Extract specific data fields from logs
- **Groups**: Parentheses capture different data elements
- **Complexity**: Can handle complex log formats

#### 4. Field Order
```xml
<order>date,time,severity,source,message</order>
```
- **Purpose**: Maps captured groups to field names
- **Usage**: Creates structured data for rules
- **Standardization**: Ensures consistent field naming

#### 5. Full Text Search
```xml
<fts>srcip,hostname,message</fts>
```
- **Purpose**: Specifies fields for full-text search indexing
- **Usage**: Enables fast searching in dashboards
- **Performance**: Optimizes search operations

### Decoder Types

#### 1. Parent Decoders
```xml
<decoder name="windows-eventlog">
  <program_name>Windows Eventlog</program_name>
  <prematch>^Windows Eventlog:</prematch>
</decoder>
```
- **Purpose**: Base decoder for a log source type
- **Inheritance**: Child decoders can extend parent functionality
- **Organization**: Groups related log formats

#### 2. Child Decoders
```xml
<decoder name="windows-security">
  <parent>windows-eventlog</parent>
  <program_name>^Security$</program_name>
  <regex>^(\d{4} \w{3} \d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\S+): (.+)$</regex>
  <order>date,time,action,user,message</order>
</decoder>
```
- **Purpose**: Specialized parsing for specific log subtypes
- **Inheritance**: Extends parent decoder capabilities
- **Modularity**: Allows fine-grained parsing control

### Built-in Decoders

#### System Decoders
```xml
<!-- SSH Authentication Events -->
<decoder name="sshd">
  <program_name>sshd</program_name>
  <regex>^(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\S+) sshd\[(\d+)\]: (.+)$</regex>
  <order>date,hostname,pid,message</order>
</decoder>

<!-- Apache Access Logs -->
<decoder name="apache-accesslog">
  <program_name>apache</program_name>
  <regex>^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.+)\] "(\w+) (.+) HTTP/\d\.\d" (\d+) (\d+|-)</regex>
  <order>srcip,date,method,url,protocol,status,size</order>
</decoder>
```

#### Security Decoders
```xml
<!-- Windows Security Events -->
<decoder name="windows-security">
  <parent>windows-eventlog</parent>
  <program_name>^Security$</program_name>
  <regex>^(\d{4} \w{3} \d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\d+) (\S+) (\S+)</regex>
  <order>date,time,action,eventid,user,source</order>
</decoder>

<!-- Firewall Logs -->
<decoder name="iptables">
  <program_name>kernel</program_name>
  <prematch>IN=</prematch>
  <regex>IN=(\w+) OUT=(\w+)? MAC=([\w:]+) SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .* PROTO=(\w+)</regex>
  <order>in,out,mac,srcip,dstip,proto</order>
</decoder>
```

## 📋 Understanding Rules

### What are Rules?
Rules are XML configuration files that define detection logic for security events. They analyze decoded log data to identify suspicious activities, policy violations, and security threats.

### Rule Structure
```xml
<rule id="100001" level="5">
  <decoded_as>sshd</decoded_as>
  <description>SSH authentication failed</description>
  <match>^Failed password|^Invalid user</match>
  <group>authentication_failed,ssh</group>
</rule>
```

### Key Rule Elements

#### 1. Rule ID
```xml
<rule id="100001" level="5">
```
- **Purpose**: Unique identifier for the rule
- **Range**: 1-999 (system), 100000+ (custom)
- **Management**: Facilitates rule organization and updates

#### 2. Alert Level
```xml
level="5"
```
- **Purpose**: Indicates severity of the detected event
- **Range**: 0-15 (0 = no alert, 15 = critical)
- **Usage**: Determines alert priority and response actions

#### 3. Decoded As
```xml
<decoded_as>sshd</decoded_as>
```
- **Purpose**: Specifies which decoder output to analyze
- **Usage**: Links rules to specific log sources
- **Filtering**: Only processes matching decoded events

#### 4. Match Patterns
```xml
<match>^Failed password|^Invalid user</match>
```
- **Purpose**: Pattern to match in decoded log data
- **Usage**: Identifies specific security events
- **Options**: `match`, `regex`, `srcip`, `dstip`, etc.

#### 5. Description
```xml
<description>SSH authentication failed</description>
```
- **Purpose**: Human-readable explanation of the rule
- **Usage**: Provides context for alerts and investigations
- **Best Practice**: Clear, specific descriptions

#### 6. Groups
```xml
<group>authentication_failed,ssh</group>
```
- **Purpose**: Categorizes rules for organization and filtering
- **Usage**: Groups related rules together
- **Reporting**: Enables group-based alert analysis

### Rule Matching Logic

#### Basic Rule Example
```xml
<rule id="5710" level="5">
  <decoded_as>sshd</decoded_as>
  <description>SSH authentication failed</description>
  <match>^Failed password</match>
  <group>authentication_failed,ssh</group>
</rule>
```
This rule will:
1. Only process logs decoded by the `sshd` decoder
2. Look for lines starting with "Failed password"
3. Generate level 5 alert if matched
4. Categorize under authentication and SSH groups

#### Complex Rule with Multiple Conditions
```xml
<rule id="100100" level="10">
  <decoded_as>sshd</decoded_as>
  <description>Multiple SSH authentication failures</description>
  <match>^Failed password</match>
  <srcip>!192.168.1.0/24</srcip>
  <within>300</within>
  <frequency>5</frequency>
  <group>authentication_failed,ssh,brute_force</group>
</rule>
```
This rule detects brute force attacks by:
1. Matching SSH failed password attempts
2. Excluding internal IP addresses
3. Looking for 5 failures within 300 seconds
4. Generating high-priority alerts

### Rule Categories and Levels

#### Alert Level Guidelines
```bash
Level 0-3: Informational events
├── 0: Debug/trace information
├── 1: Successful operations
├── 2: System status changes
└── 3: Policy compliance events

Level 4-7: Low to medium security events
├── 4: Basic security events
├── 5: Failed authentication
├── 6: Privilege changes
└── 7: System errors

Level 8-11: High security events
├── 8: Security policy violations
├── 9: Configuration changes
├── 10: Active attacks
└── 11: Critical security breaches

Level 12-15: Critical system events
├── 12: System compromise indicators
├── 13: Data exfiltration attempts
├── 14: Advanced persistent threats
└── 15: Critical system failure
```

### Rule Dependencies and Relationships

#### Parent-Child Rules
```xml
<!-- Parent rule -->
<rule id="100200" level="0">
  <decoded_as>apache-accesslog</decoded_as>
  <description>Apache access log entry</description>
  <group>web,access</group>
</rule>

<!-- Child rule -->
<rule id="100201" level="8">
  <if_sid>100200</if_sid>
  <match>union select</match>
  <description>SQL injection attempt in web logs</description>
  <group>web,attack,sql_injection</group>
</rule>
```
- **Parent Rule**: Base rule that matches general conditions
- **Child Rule**: Inherits from parent and adds specific conditions
- **Inheritance**: Child rules only evaluate if parent matches

### Advanced Rule Features

#### Frequency Analysis
```xml
<rule id="100300" level="8">
  <decoded_as>sshd</decoded_as>
  <match>^Failed password</match>
  <frequency>10</frequency>
  <timeframe>600</timeframe>
  <description>High frequency SSH brute force attack</description>
  <group>authentication_failed,ssh,brute_force</group>
</rule>
```
Detects patterns over time:
- `frequency`: Number of matching events
- `timeframe`: Time window in seconds
- `within`: Alternative to timeframe

#### IP-based Rules
```xml
<rule id="100400" level="10">
  <decoded_as>apache-accesslog</decoded_as>
  <srcip>192.168.1.100</srcip>
  <match>admin</match>
  <description>Suspicious access from known bad IP</description>
  <group>web,attack,suspicious_ip</group>
</rule>
```
- `srcip`: Source IP address matching
- `dstip`: Destination IP address matching
- Supports CIDR notation and IP ranges

#### Time-based Rules
```xml
<rule id="100500" level="3">
  <decoded_as>windows-security</decoded_as>
  <time>6 am - 6 pm</time>
  <match>logon</match>
  <description>User login during business hours</description>
  <group>authentication,success,normal_hours</group>
</rule>
```
- `time`: Time range specifications
- `weekday`: Day of week restrictions
- Useful for anomaly detection

## 🔄 Rule Processing Flow

### Step-by-Step Processing
1. **Log Reception**: Raw log data arrives from agents
2. **Decoder Application**: Appropriate decoder parses the log
3. **Rule Matching**: Rules are evaluated against decoded data
4. **Condition Checking**: Each rule condition is verified
5. **Alert Generation**: Matching rules create alerts
6. **Action Execution**: Automated responses are triggered

### Rule Evaluation Order
```bash
1. System rules (IDs 1-999) - Always evaluated first
2. Custom rules (IDs 100000+) - Evaluated in ID order
3. Parent rules before child rules
4. Higher specificity rules before general rules
5. Rules with more conditions evaluated after simpler rules
```

### Rule Optimization Techniques

#### 1. Use Specific Match Patterns
```xml
<!-- Good: Specific pattern -->
<match>^Failed password for invalid user</match>

<!-- Avoid: Overly broad pattern -->
<match>Failed</match>
```

#### 2. Leverage Decoder Pre-filtering
```xml
<!-- Good: Use decoded_as to pre-filter -->
<decoded_as>sshd</decoded_as>
<match>Failed password</match>

<!-- Avoid: Manual program name matching -->
<match>sshd.*Failed password</match>
```

#### 3. Use Appropriate Alert Levels
```xml
<!-- Good: Appropriate severity -->
<rule id="100600" level="5">
  <description>Failed authentication attempt</description>

<!-- Avoid: Over-alerting -->
<rule id="100601" level="12">
  <description>Routine failed login</description>
```

## 🛠️ Rule Testing and Validation

### Using ossec-logtest
```bash
# Test a log entry against rules
sudo /var/ossec/bin/ossec-logtest

# Interactive testing
# Type: Mar 15 12:34:56 ubuntu sshd[1234]: Failed password for root from 192.168.1.100
# Exit with Ctrl+C
```

### Rule Validation Checklist
```bash
□ Rule ID is unique and follows numbering convention
□ Alert level is appropriate for the threat severity
□ Match patterns are specific enough to avoid false positives
□ Description is clear and informative
□ Groups are relevant and properly categorized
□ Decoder reference is correct
□ Rule dependencies are properly configured
□ Performance impact has been considered
□ Testing has been performed with sample logs
□ Documentation has been updated
```

## 📊 Rule Performance Monitoring

### Performance Metrics
- **Rule Evaluation Time**: How long rules take to process
- **False Positive Rate**: Percentage of incorrect alerts
- **Alert Volume**: Number of alerts generated per time period
- **Processing Throughput**: Logs processed per second

### Optimization Strategies
1. **Rule Ordering**: Place frequently matching rules first
2. **Pattern Efficiency**: Use efficient regular expressions
3. **Conditional Logic**: Use `if_sid` to reduce unnecessary evaluations
4. **Frequency Controls**: Implement appropriate frequency limits
5. **Regular Maintenance**: Remove or modify underperforming rules

## 🎯 Best Practices

### Rule Development Guidelines
1. **Start Simple**: Begin with basic rules and gradually add complexity
2. **Test Thoroughly**: Validate rules against real log data
3. **Document Everything**: Maintain detailed rule documentation
4. **Use Version Control**: Track rule changes and versions
5. **Monitor Performance**: Regularly assess rule effectiveness
6. **Avoid Over-alerting**: Balance detection with alert fatigue
7. **Stay Updated**: Keep rules current with threat landscape
8. **Collaborate**: Share effective rules with the community

### Rule Organization Best Practices
```xml
<!-- Use consistent naming conventions -->
<rule id="100700" level="8">
  <description>ATTACK: Suspicious PowerShell execution</description>
  <group>attack,powershell,execution</group>
</rule>

<!-- Group related rules logically -->
<group>authentication,success</group>
<group>authentication,failure</group>
<group>network,firewall</group>
<group>file,integrity</group>
```

## 📚 Self-Assessment Questions

1. What is the relationship between decoders and rules in Wazuh?
2. How does the alert level system work in Wazuh rules?
3. What are the key components of a decoder configuration?
4. How do parent-child rule relationships work?
5. What are the best practices for optimizing rule performance?

## 🔗 Next Steps

Now that you understand the fundamentals of rules and decoders, let's explore how to create custom rules for specific security scenarios.

**[← Back to Module Overview](../README.md)** | **[Next: Custom Rules Creation →](./02-custom-rules-creation.md)**