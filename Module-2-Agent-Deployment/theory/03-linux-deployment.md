# Linux Agent Deployment & Configuration

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Linux-specific considerations for Wazuh agent deployment
- Installation procedures for different Linux distributions
- System service management and security configurations
- Linux log collection and monitoring best practices
- Troubleshooting common Linux deployment issues

## 🐧 Linux System Architecture

### Linux Monitoring Overview
```
┌─────────────────────────────────────────────────────────────┐
│                 LINUX SYSTEM MONITORING                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   SYSTEM LOGS   │  │   APPLICATION   │  │  SECURITY   │  │
│  │                 │  │     LOGS        │  │   EVENTS    │  │
│  │ • /var/log/*    │  │ • Apache/Nginx  │  │ • Audit      │  │
│  │ • Journalctl    │  │ • MySQL/Postgre│  │   Logs       │  │
│  │ • Syslog        │  │ • Custom Apps   │  │ • SELinux    │  │
│  │                 │  │                 │  │   Events     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   FILE SYSTEM   │  │   PROCESS       │  │  NETWORK    │  │
│  │                 │  │   MONITORING    │  │             │  │
│  │ • FIM           │  │ • Process Tree  │  │ • Netfilter  │  │
│  │ • Permissions   │  │ • Service       │  │ • Connections│  │
│  │ • Changes       │  │   Monitoring    │  │ • Traffic    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────┤
│              WAZUH AGENT INTEGRATION LAYER                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Linux Features for Security Monitoring
- **Syslog Integration**: Comprehensive system logging
- **Audit Logs**: Detailed security event tracking
- **File Integrity Monitoring**: Critical system file monitoring
- **Process Monitoring**: Track running processes and services
- **Network Monitoring**: Connection tracking and analysis
- **Package Management**: Software installation and update monitoring

## 📋 Distribution Support Matrix

### Supported Linux Distributions
```bash
# Debian-based:
├── Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS
├── Debian 9 (Stretch), 10 (Buster), 11 (Bullseye)
├── Linux Mint (Ubuntu-based versions)
└── Pop!_OS (Ubuntu-based)

# Red Hat-based:
├── CentOS 7, 8, 9
├── RHEL 7, 8, 9
├── Fedora 30+
├── Rocky Linux 8, 9
├── AlmaLinux 8, 9
└── Oracle Linux 7, 8, 9

# SUSE-based:
├── SUSE Linux Enterprise Server (SLES) 12, 15
├── openSUSE Leap 15+
└── SUSE Linux Enterprise Desktop

# Other distributions:
├── Amazon Linux 2
├── Oracle Linux
└── Arch Linux (community supported)
```

### System Requirements
```bash
# Minimum Requirements:
├── Linux kernel 2.6.32 or later
├── 256 MB RAM (1 GB recommended)
├── 100 MB free disk space for installation
├── 500 MB additional for logs and data
├── Root or sudo privileges for installation
└── Network connectivity to Wazuh server
```

## 🚀 Installation Methods

### Method 1: Package Manager Installation (Recommended)

#### Ubuntu/Debian Installation
```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.7/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Update package lists
sudo apt update

# Install Wazuh agent
sudo apt install -y wazuh-agent

# Verify installation
sudo dpkg -l | grep wazuh
```

#### CentOS/RHEL/Rocky Linux Installation
```bash
# Add Wazuh repository
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.7/yum/
protect=1
EOF

# Install Wazuh agent
sudo yum install -y wazuh-agent

# Verify installation
sudo rpm -qi wazuh-agent
```

### Method 2: Automated Installation Script

#### Universal Installation Script
```bash
# Download and run the installation script
curl -s https://packages.wazuh.com/4.7/wazuh-install.sh | sudo bash -s -- -a agent

# For custom server configuration
curl -s https://packages.wazuh.com/4.7/wazuh-install.sh | sudo bash -s -- -a agent -s WAZUH_SERVER_IP
```

#### Custom Installation Parameters
```bash
# Advanced installation options
WAZUH_MANAGER_IP="192.168.1.100"
AGENT_NAME="linux-server-01"
AGENT_GROUP="production"

# Install with custom parameters
curl -s https://packages.wazuh.com/4.7/wazuh-install.sh | sudo bash -s -- \
  -a agent \
  -m "$WAZUH_MANAGER_IP" \
  -n "$AGENT_NAME" \
  -g "$AGENT_GROUP"
```

### Method 3: Manual Compilation (Advanced)

#### From Source Installation
```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential openssl libssl-dev zlib1g-dev

# Download source code
wget https://github.com/wazuh/wazuh/archive/v4.7.1.tar.gz
tar -xzf v4.7.1.tar.gz
cd wazuh-4.7.1

# Compile and install
sudo ./install.sh

# Note: Manual compilation is complex and typically not recommended
# Use only for custom requirements or unsupported distributions
```

## ⚙️ Post-Installation Configuration

### Agent Registration and Connection

#### Method 1: Using Agent Management Script
```bash
# Stop the agent if running
sudo systemctl stop wazuh-agent

# Register agent with server
sudo /var/ossec/bin/agent-auth -m 192.168.1.100 -A linux-server-01

# Or using hostname
sudo /var/ossec/bin/agent-auth -m wazuh-server.company.com -A $(hostname)

# Start the agent
sudo systemctl start wazuh-agent

# Check connection status
sudo /var/ossec/bin/agent_control -i
```

#### Method 2: Configuration File Method
```bash
# Edit the agent configuration
sudo nano /var/ossec/etc/ossec.conf

# Update server IP
<client>
  <server>
    <address>192.168.1.100</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>

# Restart agent
sudo systemctl restart wazuh-agent
```

### Essential Configuration Settings

#### Basic Client Configuration
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.1.100</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux-server</config-profile>
    <notify_time>60</notify_time>
    <time-reconnect>300</time_reconnect>
    <auto_restart>yes</auto_restart>
  </client>
</ossec_config>
```

#### Linux Log Monitoring Configuration
```xml
<!-- System logs -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>

<!-- Journald integration (for systemd systems) -->
<localfile>
  <log_format>journald</log_format>
  <location>system</location>
</localfile>
```

#### File Integrity Monitoring
```xml
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

  <!-- Configuration files -->
  <directories check_all="yes">/etc/ssh</directories>
  <directories check_all="yes">/etc/apache2</directories>
  <directories check_all="yes">/etc/nginx</directories>

  <!-- Scan settings -->
  <scan_on_start>yes</scan_on_start>
  <frequency>3600</frequency>
  <auto_ignore>no</auto_ignore>
</syscheck>
```

### Advanced Linux-Specific Configurations

#### Audit Log Monitoring
```xml
<!-- Linux Audit logs -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

#### Application-Specific Monitoring
```xml
<!-- Apache/Nginx logs -->
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>

<!-- MySQL logs -->
<localfile>
  <log_format>mysql_log</log_format>
  <location>/var/log/mysql/error.log</location>
</localfile>

<!-- PostgreSQL logs -->
<localfile>
  <log_format>postgresql_log</log_format>
  <location>/var/log/postgresql/postgresql-*.log</location>
</localfile>
```

#### Process and Service Monitoring
```xml
<!-- Monitor critical processes -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/process-monitor.log</location>
</localfile>

<!-- Service monitoring -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/service-monitor.log</location>
</localfile>
```

## 🔧 Linux Security Configuration

### SELinux/AppArmor Integration
```bash
# For SELinux systems (CentOS/RHEL)
sudo setsebool -P wazuh_agent 1
sudo semanage permissive -a wazuh_agent_t

# For AppArmor systems (Ubuntu)
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.wazuh-agent
```

### Firewall Configuration

#### UFW (Ubuntu/Debian)
```bash
# Allow outbound connections to Wazuh server
sudo ufw allow out to 192.168.1.100 port 1514 proto tcp
sudo ufw allow out to 192.168.1.100 port 1515 proto tcp
```

#### Firewalld (CentOS/RHEL)
```bash
# Add permanent rules
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="192.168.1.100" port port="1514" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="192.168.1.100" port port="1515" protocol="tcp" accept'

# Reload firewall
sudo firewall-cmd --reload
```

#### iptables (Legacy systems)
```bash
# Allow outbound to Wazuh server
sudo iptables -A OUTPUT -d 192.168.1.100 -p tcp --dport 1514 -j ACCEPT
sudo iptables -A OUTPUT -d 192.168.1.100 -p tcp --dport 1515 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## 🚨 Troubleshooting Linux Deployments

### Common Issues and Solutions

#### Issue 1: Agent Won't Start
```bash
# Check service status
sudo systemctl status wazuh-agent

# Check for errors in logs
sudo tail -f /var/ossec/logs/ossec.log

# Check system logs
sudo journalctl -u wazuh-agent -n 20

# Try manual start
sudo /var/ossec/bin/wazuh-control start
```

#### Issue 2: Connection Problems
```bash
# Test network connectivity
telnet 192.168.1.100 1514

# Check DNS resolution
nslookup wazuh-server.company.com

# Test with curl
curl -v telnet://192.168.1.100:1514

# Check agent configuration
sudo cat /var/ossec/etc/ossec.conf | grep -A 5 "<server>"
```

#### Issue 3: Permission Issues
```bash
# Check file permissions
ls -la /var/ossec/

# Fix permissions if needed
sudo chown -R wazuh:wazuh /var/ossec/
sudo chmod -R 750 /var/ossec/

# Check user permissions
id wazuh
```

#### Issue 4: SELinux/AppArmor Issues
```bash
# Check SELinux status
sestatus

# Check for denials
sudo ausearch -m avc -ts recent | grep wazuh

# For AppArmor
sudo apparmor_status | grep wazuh
```

#### Issue 5: Log Collection Issues
```bash
# Check if log files exist
ls -la /var/log/syslog
ls -la /var/log/auth.log

# Test log rotation
logrotate -f /etc/logrotate.d/rsyslog

# Check syslog configuration
sudo cat /etc/rsyslog.conf
```

### Advanced Troubleshooting

#### Agent Debug Mode
```bash
# Stop agent
sudo systemctl stop wazuh-agent

# Start in debug mode
sudo /var/ossec/bin/wazuh-control start -d

# Monitor debug output
sudo tail -f /var/ossec/logs/ossec.log
```

#### Network Analysis
```bash
# Capture network traffic
sudo tcpdump -i eth0 host 192.168.1.100 and port 1514

# Test connection with timeout
timeout 10 nc -zv 192.168.1.100 1514
```

#### Performance Monitoring
```bash
# Monitor agent resource usage
ps aux | grep wazuh

# Check memory usage
pmap $(pgrep wazuh-agent) | tail -1

# Monitor network connections
ss -tunp | grep wazuh
```

## 📊 Linux-Specific Monitoring Capabilities

### Systemd Journal Integration
```xml
<!-- Systemd journal monitoring -->
<localfile>
  <log_format>journald</log_format>
  <location>system</location>
</localfile>

<localfile>
  <log_format>journald</log_format>
  <location>audit</location>
</localfile>
```

### Linux Audit Framework
```xml
<!-- Linux audit logs -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

### Package Management Monitoring
```bash
# Monitor package changes (add to cron)
#!/bin/bash
PREVIOUS_PACKAGES="/var/ossec/packages.previous"
CURRENT_PACKAGES="/var/ossec/packages.current"

dpkg --get-selections > "$CURRENT_PACKAGES"
if [ -f "$PREVIOUS_PACKAGES" ]; then
    diff "$PREVIOUS_PACKAGES" "$CURRENT_PACKAGES" >> /var/log/package-changes.log
fi
mv "$CURRENT_PACKAGES" "$PREVIOUS_PACKAGES"
```

## 🎯 Best Practices for Linux Deployments

### 1. Security Hardening
- **Minimal Privileges**: Run agent with necessary permissions only
- **Secure Configuration**: Protect configuration files
- **Network Security**: Use encrypted communication
- **Regular Updates**: Keep system and agent updated

### 2. Performance Optimization
- **Selective Monitoring**: Monitor critical files and logs only
- **Efficient Scanning**: Schedule intensive scans appropriately
- **Resource Limits**: Configure memory and CPU limits
- **Log Rotation**: Implement proper log rotation policies

### 3. Management and Monitoring
- **Centralized Configuration**: Use agent groups
- **Automated Updates**: Implement update mechanisms
- **Health Monitoring**: Monitor agent performance
- **Documentation**: Maintain deployment records

### 4. Compliance and Audit
- **Change Tracking**: Monitor configuration changes
- **Access Logging**: Track administrative actions
- **Compliance Reports**: Generate audit reports
- **Security Baselines**: Maintain security baselines

## 📚 Self-Assessment Questions

1. What are the system requirements for Wazuh agent on Linux?
2. How do you configure syslog monitoring in Wazuh for Linux?
3. What are the different methods for installing Wazuh agent on Linux?
4. How can you troubleshoot connectivity issues on Linux agents?
5. What Linux-specific security configurations are important for Wazuh?

## 🔗 Next Steps

Now that you understand Linux deployment, let's explore macOS agent deployment procedures.

**[← Previous: Windows Deployment](./02-windows-deployment.md)** | **[Next: macOS Deployment →](./04-macos-deployment.md)**