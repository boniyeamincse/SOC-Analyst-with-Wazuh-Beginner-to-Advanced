# Lab 03: Basic Wazuh Configuration

## 🎯 Lab Objectives

By the end of this lab, you will be able to:
- Configure basic Wazuh security monitoring rules
- Set up log collection from various sources
- Customize alert levels and notifications
- Implement basic security policies

## 📋 Prerequisites

- Completed Lab 02 (Wazuh single-node installation)
- Wazuh dashboard access
- Basic understanding of Wazuh architecture
- sudo access on Wazuh server

## 🛠️ Lab Setup

### Environment Requirements
- Wazuh server running with dashboard accessible
- At least one connected agent
- Internet access for updates and documentation

### Backup Configuration
```bash
# Always backup before making changes
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup
```

## 📝 Configuration Tasks

### Task 1: Configure Log Collection

#### Add Custom Log Sources
```xml
<!-- Edit /var/ossec/etc/ossec.conf -->
<ossec_config>
  <!-- Add custom log monitoring -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/application.json</location>
  </localfile>
</ossec_config>
```

#### Configure Windows Event Logs (if applicable)
```xml
<!-- For Windows agents -->
<localfile>
  <location>Security</location>
  <log_format>eventlog</log_format>
</localfile>
```

### Task 2: Security Policy Configuration

#### Enable File Integrity Monitoring
```xml
<!-- Enable FIM for critical directories -->
<syscheck>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/var/ossec</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
</syscheck>
```

#### Configure Rootkit Detection
```xml
<!-- Enable rootkit detection -->
<rootcheck>
  <disabled>no</disabled>
  <check_files>yes</check_files>
  <check_trojans>yes</check_trojans>
  <check_dev>yes</check_dev>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
</rootcheck>
```

### Task 3: Alert Configuration

#### Customize Alert Levels
```xml
<!-- Modify alert levels in rules -->
<group name="syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <description>SSH authentication failed.</description>
  </rule>
</group>
```

#### Email Notifications Setup
```xml
<!-- Configure email alerts -->
<global>
  <email_notification>yes</email_notification>
  <email_to>admin@example.com</email_to>
</global>

<smtp_server>smtp.example.com</smtp_server>
<email_from>wazuh@example.com</email_from>
```

### Task 4: Agent Configuration

#### Update Agent Settings
```bash
# On agent system
sudo /var/ossec/bin/agent_config -m <manager_ip>

# Enable specific modules
sudo sed -i 's/<wodle name="syscollector">/<wodle name="syscollector">\n  <disabled>no<\/disabled>/g' /var/ossec/etc/ossec.conf
```

#### Configure Agent Labels
```xml
<!-- Add labels for better organization -->
<labels>
  <label key="environment">production</label>
  <label key="department">IT</label>
</labels>
```

## 🔍 Testing Configuration

### Validate Configuration
```bash
# Check configuration syntax
sudo /var/ossec/bin/ossec-analysisd -t

# Test rules
sudo /var/ossec/bin/ossec-logtest

# Check agent connectivity
sudo /var/ossec/bin/agent_control -l
```

### Generate Test Events
```bash
# Create test log entries
logger -p auth.info "Test authentication event"
echo "Test web access" >> /var/log/apache2/access.log

# Force syscheck scan
sudo /var/ossec/bin/wazuh-control syscheck

# Trigger rootkit check
sudo /var/ossec/bin/wazuh-control rootcheck
```

### Monitor Alerts
- Access Wazuh dashboard
- Navigate to Security Events
- Verify alerts are appearing
- Check agent status and last keepalive

## 📊 Validation Checklist

- [ ] Configuration file syntax is valid
- [ ] Wazuh services restart successfully
- [ ] Agents connect and report status
- [ ] Custom logs are being collected
- [ ] FIM alerts are generated on file changes
- [ ] Email notifications are working (if configured)
- [ ] Dashboard shows new security events

## 🚨 Troubleshooting

### Common Configuration Issues

#### Services Won't Start
```bash
# Check logs for errors
sudo tail -f /var/ossec/logs/ossec.log
sudo journalctl -u wazuh-manager -f

# Validate configuration
sudo /var/ossec/bin/ossec-analysisd -t
```

#### Agents Not Connecting
```bash
# Check connectivity
telnet <manager_ip> 1514

# Verify agent configuration
sudo cat /var/ossec/etc/ossec.conf | grep -A 5 "<client>"

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log
```

#### Alerts Not Appearing
```bash
# Test rule matching
sudo /var/ossec/bin/ossec-logtest < /path/to/test/log

# Verify log collection
sudo ls -la /var/ossec/logs/archives/

# Check dashboard connectivity
curl -X GET "localhost:9200/_cluster/health"
```

## 📚 Best Practices

### Configuration Management
1. **Version Control**: Keep configuration files in git
2. **Documentation**: Comment all custom rules and settings
3. **Testing**: Test configurations in staging before production
4. **Backup**: Regular backups of working configurations

### Security Considerations
1. **Principle of Least Privilege**: Limit agent permissions
2. **Network Security**: Use TLS for agent communications
3. **Regular Updates**: Keep rules and decoders updated
4. **Monitoring**: Monitor your monitoring system

## 🎓 Key Learnings

- Configuration flexibility of Wazuh
- Importance of proper log collection
- Alert tuning and customization
- Basic security policy implementation

## 📚 Additional Resources

- [Wazuh Configuration Manual](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)
- [Wazuh Rules Reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/index.html)
- [Community Rules Repository](https://github.com/wazuh/wazuh-ruleset)

## 🔗 Next Steps

Ready for advanced troubleshooting techniques.

**[← Back: Wazuh Single-Node Setup →](./lab-02-wazuh-single-node.md)** | **[Next: Troubleshooting →](./lab-04-troubleshooting.md)**