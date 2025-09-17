# Lab 04: Troubleshooting Wazuh Deployments

## 🎯 Lab Objectives

By the end of this lab, you will be able to:
- Diagnose common Wazuh installation and configuration issues
- Use troubleshooting tools effectively
- Implement solutions for typical problems
- Develop systematic debugging approaches

## 📋 Prerequisites

- Completed previous labs (installation and basic configuration)
- Access to Wazuh server and agents
- Understanding of Wazuh architecture and components

## 🛠️ Troubleshooting Methodology

### Systematic Approach
1. **Gather Information**: Collect logs, configuration, and status
2. **Identify Symptoms**: Determine what's working vs. not working
3. **Isolate Issues**: Narrow down potential causes
4. **Test Solutions**: Apply fixes incrementally
5. **Verify Resolution**: Confirm the issue is resolved
6. **Document Findings**: Record solutions for future reference

## 🔧 Common Issues and Solutions

### Issue 1: Wazuh Services Not Starting

#### Symptoms
- Services fail to start after installation
- Systemctl shows failed status
- Dashboard inaccessible

#### Diagnosis
```bash
# Check service status
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana

# Review systemd logs
sudo journalctl -u wazuh-manager -n 50
sudo journalctl -u elasticsearch -n 50

# Check Wazuh logs
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/log/elasticsearch/elasticsearch.log
```

#### Common Causes & Solutions

**Port Conflicts:**
```bash
# Check if ports are in use
sudo netstat -tlnp | grep :1514
sudo netstat -tlnp | grep :9200

# Find process using port
sudo lsof -i :1514
```

**Permission Issues:**
```bash
# Check file permissions
ls -la /var/ossec/
ls -la /var/lib/elasticsearch/

# Fix permissions if needed
sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch/
sudo chown -R wazuh:wazuh /var/ossec/
```

**Memory Issues:**
```bash
# Check memory usage
free -h
df -h

# Adjust JVM settings for low memory
sudo sed -i 's/-Xms1g/-Xms256m/g' /etc/elasticsearch/jvm.options
sudo sed -i 's/-Xmx1g/-Xmx256m/g' /etc/elasticsearch/jvm.options
```

### Issue 2: Agent Connection Problems

#### Symptoms
- Agents show "Never connected" or "Disconnected"
- No agent data in dashboard
- Agent status shows errors

#### Diagnosis
```bash
# Check agent status on manager
sudo /var/ossec/bin/agent_control -l

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Test connectivity from agent
telnet <manager_ip> 1514
ping <manager_ip>
```

#### Solutions

**Firewall Configuration:**
```bash
# Ubuntu/Debian
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw reload

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=1515/tcp
sudo firewall-cmd --reload
```

**Agent Configuration:**
```xml
<!-- Verify /var/ossec/etc/ossec.conf -->
<client>
  <server>
    <address>MANAGER_IP</address>
    <port>1514</port>
  </server>
</client>
```

**Registration Issues:**
```bash
# Manual agent registration
sudo /var/ossec/bin/agent-auth -m <manager_ip> -p 1515

# Or use password authentication
sudo /var/ossec/bin/agent-auth -m <manager_ip> -P <password>
```

### Issue 3: No Alerts or Events

#### Symptoms
- Dashboard shows no security events
- Agents connected but no data
- Log files exist but not processed

#### Diagnosis
```bash
# Check log collection
sudo /var/ossec/bin/wazuh-logtest

# Verify log sources
sudo cat /var/ossec/etc/ossec.conf | grep -A 5 "<localfile>"

# Check decoder status
sudo /var/ossec/bin/wazuh-control status
```

#### Solutions

**Log Format Issues:**
```xml
<!-- Correct log format configuration -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/var/log/application.log</location>
</localfile>
```

**Rule Configuration:**
```bash
# Test rules with sample log
echo "Sample log entry" | sudo /var/ossec/bin/ossec-logtest

# Check custom rules syntax
sudo /var/ossec/bin/ossec-analysisd -t
```

### Issue 4: Dashboard Access Problems

#### Symptoms
- Cannot access Kibana on port 5601
- Authentication failures
- Blank or error pages

#### Diagnosis
```bash
# Check Kibana status
sudo systemctl status kibana

# Verify Elasticsearch connectivity
curl -X GET "localhost:9200/_cluster/health"

# Check Kibana logs
sudo tail -f /var/log/kibana/kibana.log
```

#### Solutions

**Service Dependencies:**
```bash
# Ensure Elasticsearch starts first
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Then start Kibana
sudo systemctl restart kibana
```

**Index Patterns:**
- Access Kibana → Management → Index Patterns
- Create pattern for Wazuh indices: `wazuh-*`

### Issue 5: Performance Problems

#### Symptoms
- High CPU/memory usage
- Slow dashboard response
- Delayed alerts

#### Diagnosis
```bash
# Monitor system resources
top
htop
iostat -x 1

# Check Wazuh process usage
ps aux | grep wazuh

# Review Elasticsearch performance
curl -X GET "localhost:9200/_cat/nodes?v"
```

#### Solutions

**Resource Optimization:**
```xml
<!-- Adjust Wazuh manager settings -->
<ossec_config>
  <global>
    <max_agents>100</max_agents>
  </global>
  <rule_test>
    <enabled>no</enabled>
  </rule_test>
</ossec_config>
```

**Log Rotation:**
```bash
# Configure log rotation
sudo cat > /etc/logrotate.d/wazuh << EOF
/var/ossec/logs/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
EOF
```

## 🛠️ Advanced Troubleshooting Tools

### Wazuh Log Test
```bash
# Test rule matching
sudo /var/ossec/bin/ossec-logtest

# Input: Sample log line
# Output: Matching rules and alert levels
```

### Cluster Status (if applicable)
```bash
# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# View node information
curl -X GET "localhost:9200/_cat/nodes?v"
```

### Debug Mode
```bash
# Enable debug logging
sudo sed -i 's/log_level=info/log_level=debug/' /var/ossec/etc/internal_options.conf

# Restart services
sudo systemctl restart wazuh-manager

# Monitor debug logs
sudo tail -f /var/ossec/logs/ossec.log
```

## 📊 Validation Checklist

- [ ] All Wazuh services are running
- [ ] Agents are connected and reporting
- [ ] Security events appear in dashboard
- [ ] No critical errors in logs
- [ ] System performance is acceptable
- [ ] Backup configurations are working

## 🎓 Best Practices

### Preventive Measures
1. **Regular Monitoring**: Monitor system resources and logs continuously
2. **Configuration Backups**: Always backup before changes
3. **Testing**: Test changes in development environment first
4. **Documentation**: Keep detailed records of configurations and changes

### Debugging Techniques
1. **Divide and Conquer**: Isolate components to identify issues
2. **Change One Thing**: Modify only one setting at a time
3. **Use Official Docs**: Reference official documentation for solutions
4. **Community Support**: Utilize forums and community resources

## 📚 Additional Resources

- [Wazuh Troubleshooting Guide](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Elasticsearch Troubleshooting](https://www.elastic.co/guide/en/elasticsearch/reference/current/troubleshooting.html)
- [Kibana Troubleshooting](https://www.elastic.co/guide/en/kibana/current/troubleshooting.html)

## 🔗 Next Steps

With troubleshooting skills mastered, explore advanced topics in the next modules.

**[← Back: Basic Configuration →](./lab-03-basic-configuration.md)** | **[Next: Key Terms →](../resources/key-terms.md)**