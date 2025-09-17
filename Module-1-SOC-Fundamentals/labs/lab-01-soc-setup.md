# Lab 01: SOC Setup Fundamentals

## 🎯 Lab Objectives

By the end of this lab, you will be able to:
- Understand the key steps for installing a Security Operations Center (SOC)
- Plan SOC infrastructure and tool deployment
- Set up basic SOC processes and team structure

## 📋 Prerequisites

- Basic understanding of SOC concepts
- Access to virtualization software (VirtualBox/VMware) or cloud platform
- Linux/Windows system administration knowledge
- Network configuration basics

## 🛠️ Lab Setup

### Infrastructure Requirements
- **Servers:** At least 2-3 virtual machines for SOC components
- **Network:** Isolated lab network for security testing
- **Storage:** Sufficient disk space for logs and data (100GB+)
- **RAM:** Minimum 8GB per VM, 16GB recommended

### Recommended Virtual Machines
1. **SOC Manager Server** (Ubuntu 22.04 LTS)
2. **Log Collector Server** (Ubuntu 22.04 LTS)
3. **Endpoint Agents** (Windows 10/11 or Ubuntu)
4. **Optional:** Database server for advanced setups

## 📝 Step-by-Step SOC Installation

### Step 1: Planning & Requirements Gathering

#### Define SOC Objectives
```bash
# Document your SOC goals
- 24/7 monitoring of critical systems
- Threat detection and incident response
- Compliance with industry standards
- Cost-effective security operations
```

#### Identify Scope
- Systems to monitor: servers, endpoints, network devices
- Log sources: applications, firewalls, IDS/IPS, endpoints
- Compliance requirements: PCI-DSS, HIPAA, GDPR
- Team size and skill sets

### Step 2: Infrastructure Setup

#### Server Provisioning
```bash
# Example: Create Ubuntu server VM
# Configure network settings
sudo nano /etc/netplan/50-cloud-init.yaml
# Add static IP configuration

# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y openssh-server vim curl wget
```

#### Security Hardening
```bash
# Configure firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Disable root login
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### Step 3: Tool Deployment

#### SIEM Platform Setup (Wazuh)
```bash
# Install Wazuh Manager (covered in next lab)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

#### Additional Tools Installation
```bash
# Install Suricata IDS
sudo apt install -y suricata

# Install ELK Stack (basic)
sudo apt install -y openjdk-11-jdk
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install -y elasticsearch kibana
```

### Step 4: Integration & Configuration

#### Configure Log Collection
```xml
<!-- Example: Wazuh ossec.conf configuration -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
</ossec_config>
```

#### Set Up Alerting
- Configure email notifications
- Set up dashboard access
- Define alert escalation procedures

### Step 5: Team Setup & Training

#### Define Roles
- **SOC Analyst Level 1:** Monitoring and triage
- **SOC Analyst Level 2:** Investigation and response
- **SOC Manager:** Oversight and strategy

#### Create Documentation
- Standard operating procedures
- Incident response playbooks
- Escalation matrix

## 🔍 Testing & Validation

### Validate SOC Functionality
```bash
# Check service status
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana

# Test log collection
tail -f /var/ossec/logs/ossec.log

# Verify agent connection
/var/ossec/bin/agent_control -l
```

### Conduct Test Incidents
1. Simulate failed login attempts
2. Generate test alerts
3. Practice incident response procedures

## 📊 Expected Outcomes

After completing this lab, you should have:
- A basic SOC infrastructure running
- Understanding of SOC deployment challenges
- Foundation for advanced SOC configurations
- Knowledge of SOC operations best practices

## 🚨 Troubleshooting

### Common Issues
- **Service won't start:** Check system resources and logs
- **Agent connection fails:** Verify network connectivity and firewall rules
- **Logs not collecting:** Check file permissions and log formats

### Getting Help
- Review official documentation
- Check community forums
- Consult with experienced SOC professionals

## 📚 Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS SOC Resources](https://www.sans.org/cyber-security-skills-roadmap/soc/)

## 🔗 Next Steps

Now that you have a basic SOC setup, let's configure Wazuh single-node deployment.

**[← Back: Wazuh vs Competitors →](../theory/06-wazuh-vs-competitors.md)** | **[Next: Wazuh Single-Node Setup →](./lab-02-wazuh-single-node.md)**