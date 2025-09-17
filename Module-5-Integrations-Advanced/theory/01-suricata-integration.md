# Suricata IDS Integration with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Suricata IDS architecture and capabilities
- Integration methods with Wazuh SIEM
- Configuration of network threat detection rules
- Log parsing and normalization for network events
- Performance optimization for high-volume networks
- Troubleshooting common integration issues

## 📋 What is Suricata?

### Overview and History
**Suricata** is a high-performance, open-source Network IDS, IPS and Network Security Monitoring (NSM) engine that:

- **Inspects network traffic** in real-time using powerful rules
- **Detects threats** based on signatures and behavioral analysis
- **Provides comprehensive logging** of network events
- **Supports advanced features** like file extraction and protocol analysis

### Key Features
```
┌─────────────────────────────────────────────────────────────┐
│                    SURICATA CAPABILITIES                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   NETWORK   │  │   THREAT    │  │   PROTOCOL  │          │
│  │ MONITORING  │  │ DETECTION  │  │   ANALYSIS  │          │
│  │             │  │             │  │             │          │
│  │ • Real-time │  │ • Signature │  │ • HTTP/2    │          │
│  │   traffic   │  │   matching  │  │   parsing   │          │
│  │   analysis  │  │ • Anomaly   │  │ • TLS       │          │
│  │ • Packet    │  │   detection │  │   inspection│          │
│  │   inspection│  │ • Custom    │  │ • DNS       │          │
│  │             │  │   rules     │  │   analysis  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   LOGGING   │  │   FILE      │  │   PERFORMANCE│          │
│  │   & ALERTS  │  │   EXTRACTION│  │   FEATURES  │          │
│  │             │  │             │  │             │          │
│  │ • JSON      │  │ • Malware   │  │ • Multi-core│          │
│  │   output    │  │   extraction│  │   processing│          │
│  │ • EVE       │  │ • File      │  │ • GPU       │          │
│  │   format    │  │   hashing   │  │   acceleration│          │
│  │ • Custom    │  │ • Stream    │  │ • Zero-copy │          │
│  │   alerts    │  │   reassembly│  │   networking│          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ Suricata Architecture

### Core Components

#### 1. Packet Acquisition
Suricata captures network traffic through various methods:
- **PCAP**: Standard packet capture interface
- **AF_PACKET**: Linux high-performance packet capture
- **PF_RING**: Commercial high-performance capture
- **Netmap**: BSD-based high-performance networking

#### 2. Stream Engine
Handles TCP stream reassembly and state management:
- **TCP Reassembly**: Reconstructs TCP streams from packets
- **State Tracking**: Maintains connection state information
- **Flow Management**: Tracks network flows and sessions

#### 3. Detection Engine
Core threat detection capabilities:
- **Signature Matching**: Fast pattern matching against rules
- **Protocol Parsers**: Deep inspection of application protocols
- **Anomaly Detection**: Behavioral analysis for unknown threats

#### 4. Output Modules
Various logging and alerting mechanisms:
- **EVE JSON**: Structured JSON output format
- **Fast Log**: Simple text-based alerts
- **Syslog**: Integration with logging systems
- **Database**: Direct database output

### Processing Pipeline
```
Network Traffic → Packet Acquisition → Stream Reassembly → Protocol Parsing → Detection Engine → Output Modules
```

## 🔧 Integration with Wazuh

### Integration Architecture

#### Direct Integration Method
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  SURICATA   │───▶│   SYSLOG    │───▶│   WAZUH     │
│             │    │             │    │             │
│ • Network   │    │ • Alert     │    │ • Log       │
│   Traffic   │    │   Forwarding│    │   Analysis  │
│ • Threat    │    │ • JSON      │    │ • Rule      │
│   Detection │    │   Format    │    │   Engine    │
│ • Alert     │    │ • Reliable  │    │ • Dashboard │
│   Generation│    │   Transport │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

#### Agent-Based Integration Method
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  SURICATA   │───▶│   LOG FILE  │───▶│  WAZUH      │───▶│   WAZUH     │
│             │    │             │    │  AGENT      │    │   SERVER    │
│ • JSON Logs │    │ • File      │    │ • Log       │    │ • Analysis   │
│ • EVE       │    │   Monitor   │    │   Collector │    │ • Rules     │
│   Format    │    │ • Rotation  │    │ • Parser    │    │ • Dashboard │
│             │    │   Handling  │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### Integration Benefits
- **Enhanced Detection**: Network-level threat identification
- **Comprehensive Coverage**: Host + Network security monitoring
- **Correlated Analysis**: Link network events with host activities
- **Unified Dashboard**: Single pane of glass for all security events
- **Automated Response**: Coordinated response across network and host

## 📋 Installation and Configuration

### Installing Suricata

#### Ubuntu/Debian Installation
```bash
# Add Suricata repository
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update

# Install Suricata
sudo apt install suricata

# Verify installation
suricata --version
```

#### CentOS/RHEL Installation
```bash
# Add repository
sudo yum install epel-release
sudo yum install suricata

# Or using dnf
sudo dnf install suricata
```

#### Manual Compilation
```bash
# Install dependencies
sudo apt install build-essential libpcre3-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev

# Download and compile
wget https://www.openinfosecfoundation.org/download/suricata-6.0.10.tar.gz
tar -xzf suricata-6.0.10.tar.gz
cd suricata-6.0.10
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
```

### Basic Configuration

#### Network Interface Setup
```yaml
# /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

#### Output Configuration for Wazuh Integration
```yaml
# EVE JSON output for Wazuh
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
```

#### Syslog Output for Direct Integration
```yaml
# Syslog output configuration
outputs:
  - syslog:
      enabled: yes
      facility: local5
      level: info
      format: "[%i] %t - (%t:%s) %m"
```

## 🔍 Rule Management

### Suricata Rule Format
```bash
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; nocase; content:"FROM"; nocase; distance:0; content:"WHERE"; nocase; distance:0; classtype:web-application-attack; sid:1234567; rev:1;)
```

#### Rule Components
- **Action**: alert, drop, reject, pass
- **Protocol**: tcp, udp, icmp, http, dns, tls
- **Source/Destination**: IP addresses, ports, variables
- **Rule Options**: Detection patterns and metadata
- **Rule ID**: Unique identifier (sid)
- **Revision**: Rule version number

### Managing Rules

#### Rule Categories
```bash
# Emerging Threats rules
emerging-attack_response.rules
emerging-malware.rules
emerging-web_server.rules
emerging-exploit.rules

# Custom rules
local.rules
```

#### Rule Updates
```bash
# Download latest rules
suricata-update

# Update with specific rule sources
suricata-update --enable-source et/open
suricata-update --enable-source oisf/trafficid

# List available sources
suricata-update list-sources
```

## 🔗 Wazuh Integration Setup

### Method 1: File Monitoring Integration

#### Configure Wazuh Agent to Monitor Suricata Logs
```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

#### Create Suricata Decoder
```xml
<!-- /var/ossec/etc/decoders/local_decoder.xml -->
<decoder name="suricata-eve">
  <program_name>^suricata</program_name>
  <prematch>^{</prematch>
</decoder>

<decoder name="suricata-alert">
  <parent>suricata-eve</parent>
  <regex type="pcre2">{"event_type":"alert"</regex>
  <order>event_type</order>
</decoder>
```

#### Create Suricata Rules
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="suricata">
  <rule id="100001" level="10">
    <decoded_as>suricata-alert</decoded_as>
    <field name="alert.category">Malware</field>
    <description>Suricata detected malware activity</description>
    <group>suricata,malware</group>
  </rule>

  <rule id="100002" level="8">
    <decoded_as>suricata-alert</decoded_as>
    <field name="alert.category">Attempted Information Leak</field>
    <description>Suricata detected data exfiltration attempt</description>
    <group>suricata,data_leak</group>
  </rule>
</group>
```

### Method 2: Syslog Integration

#### Configure Suricata for Syslog Output
```yaml
# /etc/suricata/suricata.yaml
outputs:
  - syslog:
      enabled: yes
      facility: local5
      level: info
      identity: "suricata"
      format: "[%i] %t - %m"
```

#### Configure rsyslog for Suricata
```bash
# /etc/rsyslog.d/suricata.conf
local5.*    @127.0.0.1:514
local5.*    /var/log/suricata/alerts.log
```

#### Wazuh Syslog Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/suricata/alerts.log</location>
</localfile>
```

## 📊 Advanced Configuration

### Performance Tuning

#### Multi-Threading Configuration
```yaml
# /etc/suricata/suricata.yaml
max-pending-packets: 1024
runmode: workers
detect-engine:
  - profile: medium
  - custom-values:
      toclient-groups: 3
      toserver-groups: 25
```

#### Memory Optimization
```yaml
# Memory settings
stream:
  memcap: 64mb
  checksum-validation: yes

host:
  hash-size: 4096
  prealloc: 1000
```

#### Detection Engine Optimization
```yaml
detect-engine:
  profile: high
  sgh-mpm-context: full
  inspection-recursion-limit: 3000
```

### Custom Rule Development

#### Basic Rule Structure
```bash
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Outbound HTTP Connection"; flow:established,to_server; content:"GET"; http_method; classtype:policy-violation; sid:1000001; rev:1;)
```

#### Advanced Rule Features
```bash
# Content matching with modifiers
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection Detected"; flow:established,to_server; content:"SELECT"; nocase; content:"UNION"; nocase; distance:0; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000002; rev:1;)

# File magic detection
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Executable File Download"; flow:established,to_client; filemagic:"executable"; filestore; sid:1000003; rev:1;)
```

## 🚨 Monitoring and Alerting

### Dashboard Integration

#### Kibana Visualization for Suricata Events
```json
{
  "title": "Suricata Alerts",
  "visState": {
    "title": "Suricata Alert Trends",
    "type": "line",
    "params": {
      "type": "line",
      "grid": {
        "categoryLines": false
      },
      "categoryAxes": [
        {
          "id": "CategoryAxis-1",
          "type": "category",
          "position": "bottom"
        }
      ],
      "seriesParams": [
        {
          "show": "true",
          "type": "line",
          "mode": "normal",
          "data": {
            "label": "Alert Count",
            "id": "1"
          }
        }
      ]
    }
  }
}
```

### Alert Correlation with Wazuh

#### Correlated Detection Rules
```xml
<!-- Correlate Suricata network alerts with Wazuh host alerts -->
<rule id="100100" level="12">
  <if_sid>100001</if_sid>  <!-- Suricata malware alert -->
  <if_fts>srcip,dstip</if_fts>
  <description>Suricata malware alert correlated with suspicious host activity</description>
  <group>correlation,suricata,host_analysis</group>
</rule>
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: High CPU Usage
```bash
# Check Suricata performance
suricata --list-runmodes
suricata --build-info

# Optimize configuration
detect-engine:
  profile: low  # or medium, high based on hardware
```

#### Issue 2: Dropped Packets
```bash
# Monitor packet drops
tail -f /var/log/suricata/stats.log

# Check interface settings
ethtool -k eth0

# Adjust buffer sizes
af-packet:
  - interface: eth0
    ring-size: 2048
    use-mmap: yes
```

#### Issue 3: Log Parsing Issues
```bash
# Validate JSON output
python3 -m json.tool /var/log/suricata/eve.json | head -10

# Check Wazuh agent logs
tail -f /var/ossec/logs/ossec.log

# Test decoder
/var/ossec/bin/ossec-logtest -f /var/log/suricata/eve.json
```

#### Issue 4: Rule Loading Problems
```bash
# Test rule syntax
suricata -T -c /etc/suricata/suricata.yaml

# Check for duplicate SIDs
grep "sid:" /etc/suricata/rules/*.rules | sort | uniq -d
```

### Performance Monitoring
```bash
# Suricata stats
suricata --list-app-layer-protocols
suricata --list-keywords

# System monitoring
sar -n DEV 1 5  # Network interface statistics
iostat -x 1 5   # I/O statistics
```

## 📊 Integration Testing and Validation

### Testing Checklist
```bash
□ Suricata service is running and capturing traffic
□ Rules are loading without errors
□ EVE JSON output is being generated
□ Wazuh agent is collecting Suricata logs
□ Custom decoders are parsing events correctly
□ Rules are triggering on test traffic
□ Alerts are appearing in Wazuh dashboard
□ Performance metrics are within acceptable ranges
□ Log rotation is working properly
□ Backup and recovery procedures are tested
```

### Validation Commands
```bash
# Test Suricata rule matching
curl -X GET "localhost:9200/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "rule.description": "Suricata*"
    }
  }
}'

# Check Wazuh alert statistics
/var/ossec/bin/agent_control -i | grep "suricata"
```

## 🎯 Best Practices

### 1. Deployment Considerations
- **Resource Planning**: Ensure adequate CPU and memory for network load
- **Network Architecture**: Position Suricata for optimal traffic visibility
- **Rule Tuning**: Start with essential rules and expand gradually
- **Maintenance Windows**: Schedule updates during low-traffic periods

### 2. Security Configuration
- **Network Segmentation**: Isolate Suricata from critical network segments
- **Access Control**: Limit administrative access to Suricata systems
- **Log Security**: Protect Suricata logs from unauthorized access
- **Update Management**: Keep Suricata and rules updated regularly

### 3. Integration Optimization
- **Data Format Selection**: Choose appropriate output format for integration
- **Buffering Strategy**: Implement appropriate log buffering for high-volume environments
- **Error Handling**: Configure robust error handling and recovery mechanisms
- **Monitoring Integration**: Monitor both Suricata and integration components

### 4. Performance and Scalability
- **Load Balancing**: Distribute traffic across multiple Suricata instances
- **Rule Optimization**: Regularly review and optimize rule sets
- **Hardware Scaling**: Plan for hardware upgrades as network traffic grows
- **Cloud Integration**: Consider cloud-based scaling options for large deployments

## 📚 Self-Assessment Questions

1. What are the main differences between Snort and Suricata?
2. How does Suricata integrate with Wazuh for comprehensive threat detection?
3. What are the key components of a Suricata rule?
4. How can you optimize Suricata performance for high-volume networks?
5. What are the different methods for integrating Suricata logs with Wazuh?

## 🔗 Next Steps

Now that you understand Suricata integration, let's explore Zeek network analysis framework integration for even deeper network visibility.

**[← Back to Module Overview](../README.md)** | **[Next: Zeek Integration →](./02-zeek-integration.md)**