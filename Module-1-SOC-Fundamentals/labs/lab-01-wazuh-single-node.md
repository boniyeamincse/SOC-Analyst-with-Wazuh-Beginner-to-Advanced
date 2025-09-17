# Lab 1: Single-Node Wazuh Installation

## 🎯 Lab Overview

**Duration**: 2-3 hours
**Difficulty**: Beginner
**Prerequisites**: Basic Linux knowledge, sudo access

This lab will guide you through installing a complete Wazuh environment on a single server. You'll learn the fundamental installation process and basic configuration.

## 📋 Learning Objectives

By the end of this lab, you will be able to:
- Install Wazuh server components on Linux
- Configure basic Wazuh settings
- Access the Wazuh dashboard
- Deploy and connect a Wazuh agent
- Generate and view basic security alerts

## 🛠️ Lab Environment Requirements

### Hardware Requirements
- **RAM**: Minimum 4GB, Recommended 8GB+
- **CPU**: 2+ cores
- **Storage**: 20GB+ free space
- **Network**: Internet access

### Software Requirements
- **OS**: Ubuntu 20.04 LTS / 22.04 LTS (or CentOS 7/8/RHEL 7/8)
- **Package Manager**: apt (Ubuntu) or yum/dnf (CentOS/RHEL)
- **Tools**: curl, wget, vim/nano (text editor)

### Virtual Environment Setup
For this lab, you can use:
- **VirtualBox/VMware**: Create a new VM with Ubuntu 22.04
- **AWS EC2**: t3.medium instance with Ubuntu 22.04
- **Local Machine**: If you have Linux installed
- **Docker**: For containerized deployment (advanced)

## 📝 Pre-Lab Preparation

### Step 1: System Update
```bash
# Update package lists
sudo apt update

# Upgrade installed packages (optional but recommended)
sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl wget vim net-tools
```

### Step 2: Configure Firewall
```bash
# Allow SSH (if not already allowed)
sudo ufw allow ssh

# Allow Wazuh required ports
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw allow 55000/tcp

# Enable firewall
sudo ufw --force enable

# Check firewall status
sudo ufw status
```

### Step 3: Configure Hostname (Optional)
```bash
# Set a meaningful hostname
sudo hostnamectl set-hostname wazuh-server

# Update /etc/hosts file
echo "127.0.0.1 wazuh-server" | sudo tee -a /etc/hosts
```

## 🚀 Installation Steps

### Method 1: Quick Start Script (Recommended for Beginners)

#### Step 1: Download and Run Installation Script
```bash
# Download the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Make the script executable
chmod +x wazuh-install.sh

# Run the installation (single-node deployment)
sudo bash wazuh-install.sh -a
```

#### Step 2: Installation Output
The script will install:
- Wazuh Manager (Server)
- Wazuh API
- Elasticsearch
- Filebeat
- Kibana with Wazuh plugin

**Expected Output:**
```
Starting Wazuh installation...
Installing Wazuh manager...
Installing Elasticsearch...
Installing Filebeat...
Installing Kibana...
Wazuh installation finished.
```

#### Step 3: Verify Installation
```bash
# Check Wazuh manager status
sudo systemctl status wazuh-manager

# Check Elasticsearch status
sudo systemctl status elasticsearch

# Check Kibana status
sudo systemctl status kibana
```

### Method 2: Manual Installation (Advanced)

If you prefer manual installation or need more control:

#### Install Wazuh Manager
```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.7/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Update package lists
sudo apt update

# Install Wazuh manager
sudo apt install -y wazuh-manager

# Start Wazuh manager
sudo systemctl start wazuh-manager
sudo systemctl enable wazuh-manager
```

#### Install Elasticsearch
```bash
# Install Java (required for Elasticsearch)
sudo apt install -y openjdk-11-jdk

# Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Update and install Elasticsearch
sudo apt update
sudo apt install -y elasticsearch=7.17.9

# Configure Elasticsearch
sudo sed -i 's/-Xms1g/-Xms512m/g' /etc/elasticsearch/jvm.options
sudo sed -i 's/-Xmx1g/-Xmx512m/g' /etc/elasticsearch/jvm.options

# Start Elasticsearch
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
```

#### Install Kibana
```bash
# Install Kibana
sudo apt install -y kibana=7.17.9

# Install Wazuh Kibana plugin
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-4.7.1_7.17.9.zip

# Start Kibana
sudo systemctl start kibana
sudo systemctl enable kibana
```

## ⚙️ Post-Installation Configuration

### Step 1: Access the Dashboard

#### Get Server IP Address
```bash
# Get your server's IP address
ip addr show | grep "inet " | grep -v 127.0.0.1

# Alternative method
curl ifconfig.me
```

#### Access Kibana Dashboard
1. Open your web browser
2. Navigate to: `http://YOUR_SERVER_IP:5601`
3. Default credentials:
   - **Username**: admin
   - **Password**: admin

**Note**: Change the default password after first login!

### Step 2: Basic Wazuh Configuration

#### Check Wazuh Manager Configuration
```bash
# View main configuration file
sudo cat /var/ossec/etc/ossec.conf | head -50

# Check Wazuh processes
sudo /var/ossec/bin/wazuh-control status
```

#### Generate Agent Registration Password
```bash
# Generate a random password for agent registration
openssl rand -base64 32 > /tmp/agent_password.txt
cat /tmp/agent_password.txt
```

## 📱 Deploying Wazuh Agent

### Method 1: Install Agent on Same Server (for testing)

```bash
# Install Wazuh agent
sudo apt install -y wazuh-agent

# Configure agent to connect to local manager
sudo sed -i 's/MANAGER_IP/wazuh-server/g' /var/ossec/etc/ossec.conf

# Start the agent
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent

# Check agent status
sudo /var/ossec/bin/wazuh-control status
```

### Method 2: Install Agent on Remote System

#### On the remote system (Linux):
```bash
# Download agent installation script
curl -s https://packages.wazuh.com/4.7/wazuh-install.sh | sudo bash -s -- -a agent

# Or manual installation
sudo apt install -y wazuh-agent
sudo sed -i 's/MANAGER_IP/YOUR_WAZUH_SERVER_IP/g' /var/ossec/etc/ossec.conf
sudo systemctl start wazuh-agent
```

#### On the remote system (Windows):
```bash
# Download Windows agent MSI
# https://packages.wazuh.com/4.7/windows/wazuh-agent-4.7.1-1.msi

# Install MSI with manager IP parameter
# msiexec /i wazuh-agent-4.7.1-1.msi /q MANAGER_IP=YOUR_WAZUH_SERVER_IP
```

## 🔍 Testing and Validation

### Step 1: Check Agent Connection
```bash
# On Wazuh server, check connected agents
sudo /var/ossec/bin/agent_control -l

# Expected output:
# Wazuh agent_control. List of available agents:
# ID: 001, Name: wazuh-server, IP: 127.0.0.1, Active
```

### Step 2: Generate Test Alerts

#### Create a test log entry
```bash
# Create a test log file
sudo mkdir -p /var/log/test
echo "$(date) - Test security event: Unauthorized access attempt" | sudo tee -a /var/log/test/security.log

# Add the log file to Wazuh monitoring
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/test/security.log</location>
</localfile>
EOF

# Restart Wazuh manager
sudo systemctl restart wazuh-manager
```

### Step 3: View Alerts in Dashboard

1. **Access Kibana**: `http://YOUR_SERVER_IP:5601`
2. **Navigate to Wazuh**: Click "Wazuh" in the left sidebar
3. **View Security Events**: Go to "Security Events" tab
4. **Check Agents**: Go to "Agents" tab to see connected agents

## 🔧 Troubleshooting Common Issues

### Issue 1: Services Not Starting
```bash
# Check service status
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana

# Check logs for errors
sudo journalctl -u wazuh-manager -n 20
sudo journalctl -u elasticsearch -n 20
sudo journalctl -u kibana -n 20
```

### Issue 2: Cannot Access Dashboard
```bash
# Check if Kibana is listening on correct port
sudo netstat -tlnp | grep :5601

# Check firewall rules
sudo ufw status

# Verify Elasticsearch is running
curl -X GET "localhost:9200"
```

### Issue 3: Agent Connection Issues
```bash
# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Test connectivity
telnet YOUR_SERVER_IP 1514

# Check agent configuration
sudo cat /var/ossec/etc/ossec.conf | grep -A 5 "<client>"
```

### Issue 4: Memory Issues
```bash
# Check memory usage
free -h

# Check Java heap size for Elasticsearch
sudo cat /etc/elasticsearch/jvm.options | grep -E "Xms|Xmx"

# Adjust if necessary (for low-memory systems)
sudo sed -i 's/-Xms1g/-Xms256m/g' /etc/elasticsearch/jvm.options
sudo sed -i 's/-Xmx1g/-Xmx256m/g' /etc/elasticsearch/jvm.options
sudo systemctl restart elasticsearch
```

## 📊 Lab Validation Checklist

- [ ] Wazuh manager service is running
- [ ] Elasticsearch service is running
- [ ] Kibana service is running
- [ ] Can access Kibana dashboard at port 5601
- [ ] At least one agent is connected (local agent)
- [ ] Can view security events in dashboard
- [ ] Firewall rules are configured correctly
- [ ] Basic test alerts are being generated

## 🎓 Best Practices Learned

### Installation Best Practices
1. **Use Official Repositories**: Always use official Wazuh repositories
2. **Secure Default Credentials**: Change default passwords immediately
3. **Configure Firewall**: Set up proper firewall rules
4. **Monitor Resources**: Keep an eye on system resources
5. **Regular Backups**: Backup configurations and data

### Configuration Best Practices
1. **Use Meaningful Names**: Give servers and agents descriptive names
2. **Document Changes**: Keep track of configuration modifications
3. **Test Configurations**: Validate changes before applying to production
4. **Version Control**: Use version control for configuration files
5. **Regular Updates**: Keep Wazuh and dependencies updated

### Security Best Practices
1. **Principle of Least Privilege**: Run services with minimal required permissions
2. **Network Segmentation**: Isolate Wazuh components when possible
3. **Encryption**: Use TLS for all communications
4. **Access Control**: Implement proper authentication and authorization
5. **Monitoring**: Monitor your monitoring system

## 📚 Additional Resources

- [Official Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Wazuh Troubleshooting Guide](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Wazuh Community Forums](https://wazuh.com/community/)
- [GitHub Issues](https://github.com/wazuh/wazuh/issues)

## 🎯 Next Steps

Congratulations! You've successfully installed Wazuh. In the next lab, you'll learn to:
- Configure advanced Wazuh rules
- Set up custom alerts
- Deploy agents across multiple systems
- Create custom dashboards

## 📝 Lab Report

**Document your installation:**
1. **Server Details**: IP address, OS version, resources
2. **Installation Method**: Quick script or manual
3. **Issues Encountered**: Any problems and solutions
4. **Configuration Changes**: Custom settings applied
5. **Validation Results**: Screenshots of dashboard and alerts

---

*Remember: The best way to learn is by doing. Don't be afraid to experiment and break things - that's how you learn!*