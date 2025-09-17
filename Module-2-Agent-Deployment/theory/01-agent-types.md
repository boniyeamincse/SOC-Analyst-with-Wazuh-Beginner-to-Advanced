# Understanding Wazuh Agents: Types and Concepts

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Different types of Wazuh agents and their use cases
- How agents collect and transmit data to the Wazuh server
- Agent architecture and communication protocols
- Deployment strategies and management approaches

## 📋 What is a Wazuh Agent?

### Definition and Purpose
A **Wazuh agent** is a lightweight software program installed on endpoints, servers, and devices to:

- **Collect Security Data**: Gather logs, system events, and security information
- **Monitor System Health**: Track file changes, process activity, and system metrics
- **Detect Threats**: Identify suspicious behavior and security incidents
- **Report to Central Server**: Send collected data to Wazuh manager for analysis

### Core Functions
```
┌─────────────────────────────────────────────────────────────┐
│                    WAZUH AGENT FUNCTIONS                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   LOG       │  │   SYSTEM    │  │   SECURITY  │          │
│  │ COLLECTION  │  │ MONITORING  │  │   ANALYSIS  │          │
│  │             │  │             │  │             │          │
│  │ • Application│  │ • File      │  │ • Rootkit   │          │
│  │   Logs      │  │   Integrity  │  │   Detection │          │
│  │ • System    │  │ • Process    │  │ • Malware   │          │
│  │   Events    │  │   Activity   │  │   Scanning  │          │
│  │ • Security  │  │ • Network    │  │ • Policy    │          │
│  │   Events    │  │   Traffic    │  │   Assessment│          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│           COMMUNICATION & MANAGEMENT LAYER                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  ENCRYPTED  │  │   CONFIG    │  │   STATUS    │          │
│  │COMMUNICATION│  │ MANAGEMENT  │  │  REPORTING  │          │
│  │             │  │             │  │             │          │
│  │ • AES 256   │  │ • Remote    │  │ • Heartbeat │          │
│  │   Encryption│  │   Updates   │  │ • Connection │          │
│  │ • Secure    │  │ • Policy    │  │   Status    │          │
│  │   Channel   │  │   Sync      │  │ • Performance│          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Agent Types and Classifications

### 1. Active Agents

#### Characteristics
- **Real-time Communication**: Maintains persistent connection with Wazuh server
- **Immediate Data Transmission**: Sends data as it's collected
- **Continuous Monitoring**: Always-on monitoring and reporting
- **Two-way Communication**: Receives commands and configuration updates

#### Use Cases
```bash
# Perfect for:
├── Critical servers requiring immediate alerting
├── Production systems needing constant monitoring
├── Environments with reliable network connectivity
├── Systems requiring real-time response capabilities
└── High-security environments
```

#### Configuration Example
```xml
<client>
  <server>
    <address>192.168.1.100</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>production</config-profile>
  <notify_time>60</notify_time>
  <time-reconnect>300</time_reconnect>
</client>
```

### 2. Passive Agents

#### Characteristics
- **Scheduled Communication**: Connects to server on predefined schedule
- **Batch Data Transmission**: Sends accumulated data in batches
- **Lower Network Overhead**: Reduces continuous network traffic
- **Suitable for Intermittent Connectivity**: Works with unstable networks

#### Use Cases
```bash
# Ideal for:
├── Remote or branch office systems
├── Mobile devices and laptops
├── Systems with limited network bandwidth
├── Environments with intermittent connectivity
└── Cost-sensitive network configurations
```

#### Configuration Example
```xml
<client>
  <server>
    <address>wazuh-server.company.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>remote-office</config-profile>
  <notify_time>3600</notify_time>  <!-- 1 hour intervals -->
  <time-reconnect>3600</time_reconnect>
</client>
```

### 3. Agentless Monitoring

#### Characteristics
- **No Agent Installation**: Direct data collection from sources
- **Protocol-Based Collection**: Uses SSH, WMI, APIs, and syslog
- **Lightweight on Targets**: No software installation required
- **Flexible Data Sources**: Supports various network devices and systems

#### Supported Methods
```bash
# Data Collection Methods:
├── SSH for Linux/Unix systems
├── WMI for Windows systems
├── SNMP for network devices
├── Syslog for network appliances
├── API integration for cloud services
└── Database direct connections
```

#### Use Cases
```bash
# Best for:
├── Network devices (routers, switches, firewalls)
├── Legacy systems without agent support
├── Cloud instances with API access
├── Temporary monitoring needs
├── Systems where agent installation is not allowed
└── Large-scale network device monitoring
```

## 🏗️ Agent Architecture Deep Dive

### Agent Components

#### 1. Control Module
```bash
# Responsibilities:
├── Manages agent configuration
├── Handles communication with server
├── Processes remote commands
├── Maintains agent status
└── Coordinates other modules
```

#### 2. Log Collector Module
```bash
# Functions:
├── Monitors log files and directories
├── Collects system event logs
├── Parses log formats and extracts data
├── Applies log filtering rules
└── Buffers data for transmission
```

#### 3. System Checker Module (Syscheck)
```bash
# Capabilities:
├── File integrity monitoring (FIM)
├── Registry monitoring (Windows)
├── Directory monitoring
├── Permission checking
├── Hash calculation and comparison
└── Real-time file change detection
```

#### 4. Rootcheck Module
```bash
# Security Analysis:
├── Rootkit detection
├── System policy checking
├── Hidden process detection
├── Unusual file permission analysis
├── Known malware signature scanning
└── System anomaly detection
```

#### 5. Active Response Module
```bash
# Automated Actions:
├── Executes predefined response commands
├── Blocks suspicious IP addresses
├── Isolates compromised systems
├── Sends alert notifications
├── Integrates with external tools
└── Custom script execution
```

### 6. Configuration Assessment Module (SCA)
```bash
# Compliance Checking:
├── CIS benchmark validation
├── System hardening verification
├── Security policy enforcement
├── Configuration drift detection
├── Automated remediation suggestions
└── Compliance reporting
```

## 🔐 Communication and Security

### Secure Communication Channels

#### Encryption and Authentication
```bash
# Security Features:
├── AES-256 encryption for data in transit
├── Agent registration and authentication
├── Certificate-based communication (optional)
├── Message integrity verification
├── Secure key exchange
└── Man-in-the-middle protection
```

#### Communication Flow
```
1. Agent Registration
   Agent → Server: Registration request with unique ID
   Server → Agent: Authentication confirmation

2. Data Transmission
   Agent → Server: Encrypted data packets
   Server → Agent: Acknowledgment and commands

3. Heartbeat Mechanism
   Agent → Server: Regular status updates
   Server → Agent: Configuration updates and commands

4. Error Handling
   Agent → Server: Error reports and retry logic
   Server → Agent: Diagnostic information and recovery instructions
```

### Network Requirements

#### Port Configuration
```bash
# Required Ports:
├── TCP 1514: Main communication port
├── TCP 1515: Agent enrollment and configuration
├── UDP 514:  Syslog input (optional)
├── TCP 9200: Elasticsearch API (for queries)
└── TCP 55000: Wazuh API (for management)
```

#### Firewall Considerations
```bash
# Allow outbound from agents:
sudo ufw allow out to WAZUH_SERVER_IP port 1514 proto tcp
sudo ufw allow out to WAZUH_SERVER_IP port 1515 proto tcp

# Allow inbound on Wazuh server:
sudo ufw allow from AGENT_NETWORKS to any port 1514 proto tcp
sudo ufw allow from AGENT_NETWORKS to any port 1515 proto tcp
```

## 📊 Agent Performance and Scalability

### Resource Requirements

#### System Resources
```bash
# Typical Resource Usage:
├── CPU: 1-5% average, peaks at 10-15%
├── Memory: 50-200 MB per agent
├── Disk: 100-500 MB for logs and buffers
├── Network: 10-100 KB/minute average
└── Bandwidth depends on log volume and frequency
```

#### Performance Optimization
```bash
# Optimization Strategies:
├── Adjust monitoring frequency for less critical systems
├── Use log filtering to reduce data volume
├── Implement data compression for transmission
├── Configure appropriate buffer sizes
├── Schedule resource-intensive scans during off-hours
└── Use passive agents for bandwidth-constrained environments
```

### Scalability Considerations

#### Large Deployments
```bash
# Scaling Strategies:
├── Distributed Wazuh cluster for load balancing
├── Agent groups for targeted configuration
├── Hierarchical agent management
├── Automated deployment and configuration
├── Centralized logging and monitoring
└── Performance monitoring and alerting
```

#### Cluster Architecture
```
┌─────────────────┐    ┌─────────────────┐
│   Wazuh Server  │    │   Wazuh Server  │
│   (Master)      │◄──►│   (Worker)      │
│                 │    │                 │
│ • Agent Mgmt    │    │ • Data Analysis │
│ • Configuration │    │ • Rule Engine   │
│ • API Service   │    │ • Aggregation   │
└─────────────────┘    └─────────────────┘
         ▲                       ▲
         │                       │
    ┌────┴───────────────────────┴────┐
    │         Load Balancer           │
    └─────────────────────────────────┘
         ▲                       ▲
         │                       │
    ┌────┴─────┐            ┌────┴─────┐
    │  Agents  │            │  Agents  │
    │ (Group A)│            │ (Group B)│
    └──────────┘            └──────────┘
```

## 🎯 Agent Deployment Strategies

### 1. Manual Deployment
```bash
# Step-by-step approach:
├── Download agent package for target OS
├── Install agent software
├── Configure server connection
├── Register agent with server
├── Test connectivity and data collection
└── Verify monitoring functionality
```

### 2. Automated Deployment
```bash
# Using scripts and tools:
├── Create deployment scripts
├── Use configuration management tools (Ansible, Puppet)
├── Implement automated registration
├── Configure centralized management
├── Set up monitoring and alerting
└── Establish update mechanisms
```

### 3. Hybrid Approach
```bash
# Combination strategy:
├── Manual deployment for critical systems
├── Automated deployment for standard systems
├── Agentless monitoring for network devices
├── Centralized configuration management
├── Regular audit and compliance checks
└── Continuous improvement processes
```

## 🛠️ Agent Management Best Practices

### 1. Version Control and Updates
- **Regular Updates**: Keep agents updated with latest versions
- **Testing**: Test updates in staging environment first
- **Rollback Plan**: Have rollback procedures for failed updates
- **Change Management**: Document all agent configuration changes

### 2. Monitoring and Maintenance
- **Performance Monitoring**: Track agent resource usage and performance
- **Connectivity Checks**: Monitor agent-server communication status
- **Log Analysis**: Review agent logs for errors and issues
- **Health Checks**: Regular verification of agent functionality

### 3. Security Considerations
- **Secure Configuration**: Use strong authentication and encryption
- **Access Control**: Limit agent management access to authorized personnel
- **Network Security**: Protect agent-server communications
- **Data Protection**: Ensure sensitive data is properly secured

### 4. Troubleshooting Methodology
```bash
# Systematic Approach:
├── Check agent status and logs
├── Verify network connectivity
├── Test server communication
├── Validate configuration files
├── Review firewall and security settings
├── Check system resources and performance
└── Consult documentation and community resources
```

## 📚 Self-Assessment Questions

1. What are the main differences between active and passive agents?
2. When would you choose agentless monitoring over agent-based monitoring?
3. How does Wazuh ensure secure communication between agents and server?
4. What are the key components of a Wazuh agent's architecture?
5. How can you optimize agent performance for large-scale deployments?

## 🔗 Next Steps

Now that you understand agent types and concepts, let's move on to practical deployment on Windows systems.

**[← Back to Module Overview](../README.md)** | **[Next: Windows Deployment →](./02-windows-deployment.md)**