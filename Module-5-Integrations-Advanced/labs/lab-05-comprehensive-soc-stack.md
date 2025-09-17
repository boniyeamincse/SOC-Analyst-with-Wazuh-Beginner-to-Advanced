# Lab 5: Comprehensive SOC Stack Integration

## 🎯 Lab Overview

This advanced lab demonstrates the integration of all security tools into a comprehensive SOC (Security Operations Center) environment. You'll learn to orchestrate Wazuh, ELK Stack, Suricata, MISP, TheHive, and other tools in a unified security ecosystem that provides end-to-end threat detection, analysis, and response capabilities.

### 📋 Prerequisites

- **All Previous Labs Completed**: Labs 1-4 must be completed
- **Multiple VMs/Servers**: Separate systems for each tool
- **Network Infrastructure**: Proper network segmentation
- **System Resources**: Adequate resources for all tools running simultaneously

### 🏆 Lab Objectives

By the end of this lab, you will be able to:
- Deploy a complete SOC technology stack
- Configure data flows between all security tools
- Implement automated threat detection workflows
- Create unified security dashboards
- Test end-to-end incident response scenarios
- Optimize performance across integrated tools
- Implement security monitoring and alerting

## 🏗️ SOC Architecture Overview

### Complete Technology Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPREHENSIVE SOC STACK                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  SURICATA   │  │   WAZUH     │  │    MISP     │  │  THEHIVE    │ │
│  │   IDS/IPS   │  │   SIEM      │  │   Threat    │  │   IR        │ │
│  │             │  │             │  │   Intel     │  │   Platform  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ ELASTICSEARCH│  │  LOGSTASH   │  │   KIBANA    │  │   CORTEX    │ │
│  │   Storage    │  │  Processing │  │  Dashboard  │  │   Analysis  │ │
│  │             │  │             │  │             │  │             │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                         ┌─────────────────┐
                         │   UNIFIED       │
                         │   DASHBOARD     │
                         │   & ALERTING    │
                         └─────────────────┘
```

### Data Flow Architecture

```
Network Traffic → Suricata IDS → Wazuh Agent → Wazuh Server
       ↓              ↓            ↓              ↓
  Alert Logs     Alert Logs    Alert Logs    Alert Processing
       ↓              ↓            ↓              ↓
  Filebeat      Logstash      Logstash      Integration Scripts
       ↓              ↓            ↓              ↓
  Elasticsearch → Elasticsearch → Elasticsearch → TheHive Case Creation
       ↓              ↓            ↓              ↓
  Kibana       Kibana       Kibana       Cortex Analysis
       ↓              ↓            ↓              ↓
  SOC Dashboard ←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←
```

## 🚀 Lab Setup and Configuration

### Step 1: Environment Preparation

#### 1.1 System Requirements Check
```bash
# Check available resources
echo "=== System Resources ==="
free -h
df -h
nproc
echo "=== Network Configuration ==="
ip addr show
netstat -tlnp | grep -E ':(9200|5601|9000|9001|80|443)'
```

#### 1.2 Service Status Verification
```bash
# Check all required services
echo "=== Service Status ==="
systemctl status elasticsearch --no-pager -l
systemctl status logstash --no-pager -l
systemctl status kibana --no-pager -l
systemctl status wazuh-manager --no-pager -l
systemctl status filebeat --no-pager -l
systemctl status thehive --no-pager -l
systemctl status cortex --no-pager -l
systemctl status cassandra --no-pager -l
```

### Step 2: Unified Configuration

#### 2.1 Create SOC Configuration File
```bash
# Create comprehensive configuration file
sudo tee /etc/soc-stack/config.yml <<EOF
# SOC Stack Configuration
soc:
  name: "Training SOC Environment"
  timezone: "UTC"
  organization: "SOC Training Lab"

# Component endpoints
components:
  wazuh:
    server: "localhost:55000"
    api_key: "${WAZUH_API_KEY}"
  elasticsearch:
    url: "http://localhost:9200"
    username: "elastic"
    password: "${ES_PASSWORD}"
  kibana:
    url: "http://localhost:5601"
  thehive:
    url: "http://localhost:9000"
    api_key: "${THEHIVE_API_KEY}"
  cortex:
    url: "http://localhost:9001"
    api_key: "${CORTEX_API_KEY}"
  misp:
    url: "http://localhost"
    api_key: "${MISP_API_KEY}"
  suricata:
    config: "/etc/suricata/suricata.yaml"
    rules: "/etc/suricata/rules"

# Integration settings
integrations:
  wazuh_elk:
    enabled: true
    index_pattern: "wazuh-alerts-*"
  wazuh_misp:
    enabled: true
    auto_enrich: true
  wazuh_thehive:
    enabled: true
    auto_case_creation: true
  elk_kibana:
    enabled: true
    dashboards: "/etc/soc-stack/dashboards"

# Alert thresholds
alerting:
  critical_threshold: 15
  high_threshold: 12
  medium_threshold: 8
  low_threshold: 5

# Automation settings
automation:
  auto_escalation: true
  auto_containment: false
  threat_intel_updates: true
  report_generation: true
EOF
```

#### 2.2 Environment Variables Setup
```bash
# Set all necessary environment variables
sudo tee /etc/environment <<EOF
# SOC Stack Environment Variables
SOC_NAME="Training SOC Environment"
WAZUH_API_KEY="your_wazuh_api_key"
ES_PASSWORD="your_elasticsearch_password"
THEHIVE_API_KEY="your_thehive_api_key"
CORTEX_API_KEY="your_cortex_api_key"
MISP_API_KEY="your_misp_api_key"

# Component URLs
ELASTICSEARCH_URL="http://localhost:9200"
KIBANA_URL="http://localhost:5601"
THEHIVE_URL="http://localhost:9000"
CORTEX_URL="http://localhost:9001"
MISP_URL="http://localhost"
WAZUH_URL="https://localhost:55000"
EOF

# Load environment variables
source /etc/environment
```

### Step 3: Data Pipeline Orchestration

#### 3.1 Create Master Orchestration Script
```bash
# Create SOC orchestration script
sudo tee /opt/soc-stack/orchestrator.py <<'EOF'
#!/usr/bin/env python3
# SOC Stack Orchestrator

import json
import requests
import time
import yaml
from datetime import datetime, timedelta

class SOCOrchestrator:
    def __init__(self, config_file='/etc/soc-stack/config.yml'):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)

        self.components = self.config['components']
        self.integrations = self.config['integrations']

    def health_check(self):
        """Check health of all SOC components"""
        health_status = {}

        # Check Elasticsearch
        try:
            response = requests.get(f"{self.components['elasticsearch']['url']}/_cluster/health")
            health_status['elasticsearch'] = response.json()['status']
        except:
            health_status['elasticsearch'] = 'unreachable'

        # Check Wazuh
        try:
            response = requests.get(f"{self.components['wazuh']['server']}/",
                                  headers={'Authorization': f"Bearer {self.components['wazuh']['api_key']}"})
            health_status['wazuh'] = 'healthy' if response.status_code == 200 else 'unreachable'
        except:
            health_status['wazuh'] = 'unreachable'

        # Check TheHive
        try:
            response = requests.get(f"{self.components['thehive']['url']}/api/status",
                                  headers={'Authorization': f"Bearer {self.components['thehive']['api_key']}"})
            health_status['thehive'] = 'healthy' if response.status_code == 200 else 'unreachable'
        except:
            health_status['thehive'] = 'unreachable'

        return health_status

    def test_data_flow(self):
        """Test data flow between all components"""
        results = {}

        # Test Wazuh to ELK flow
        results['wazuh_to_elk'] = self.test_wazuh_elk_flow()

        # Test ELK to Kibana flow
        results['elk_to_kibana'] = self.test_elk_kibana_flow()

        # Test Wazuh to MISP flow
        results['wazuh_to_misp'] = self.test_wazuh_misp_flow()

        # Test Wazuh to TheHive flow
        results['wazuh_to_thehive'] = self.test_wazuh_thehive_flow()

        return results

    def test_wazuh_elk_flow(self):
        """Test data flow from Wazuh to ELK Stack"""
        try:
            # Query recent Wazuh alerts in Elasticsearch
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1h"
                        }
                    }
                },
                "size": 1
            }

            response = requests.post(
                f"{self.components['elasticsearch']['url']}/wazuh-alerts-*/_search",
                json=query
            )

            return response.json()['hits']['total']['value'] > 0
        except:
            return False

    def test_elk_kibana_flow(self):
        """Test Kibana connectivity and data visualization"""
        try:
            response = requests.get(f"{self.components['kibana']['url']}/api/status")
            return response.status_code == 200
        except:
            return False

    def test_wazuh_misp_flow(self):
        """Test MISP integration with Wazuh"""
        try:
            response = requests.get(
                f"{self.components['misp']['url']}/events/restSearch",
                headers={'Authorization': self.components['misp']['api_key']}
            )
            return response.status_code == 200
        except:
            return False

    def test_wazuh_thehive_flow(self):
        """Test TheHive integration with Wazuh"""
        try:
            response = requests.get(
                f"{self.components['thehive']['url']}/api/case",
                headers={'Authorization': f"Bearer {self.components['thehive']['api_key']}"}
            )
            return response.status_code == 200
        except:
            return False

    def generate_status_report(self):
        """Generate comprehensive SOC status report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'health_status': self.health_check(),
            'data_flow_tests': self.test_data_flow(),
            'alert_summary': self.get_alert_summary(),
            'case_summary': self.get_case_summary()
        }

        return report

    def get_alert_summary(self):
        """Get summary of recent alerts"""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-24h"
                        }
                    }
                },
                "aggs": {
                    "severity_distribution": {
                        "terms": {
                            "field": "rule_level"
                        }
                    },
                    "top_rules": {
                        "terms": {
                            "field": "rule_description.keyword",
                            "size": 10
                        }
                    }
                },
                "size": 0
            }

            response = requests.post(
                f"{self.components['elasticsearch']['url']}/wazuh-alerts-*/_search",
                json=query
            )

            return response.json()['aggregations']
        except:
            return {}

    def get_case_summary(self):
        """Get summary of incident cases"""
        try:
            response = requests.get(
                f"{self.components['thehive']['url']}/api/case/_stats",
                headers={'Authorization': f"Bearer {self.components['thehive']['api_key']}"}
            )
            return response.json()
        except:
            return {}

def main():
    orchestrator = SOCOrchestrator()

    print("=== SOC Stack Health Check ===")
    health = orchestrator.health_check()
    for component, status in health.items():
        print(f"{component}: {status}")

    print("\n=== Data Flow Tests ===")
    flows = orchestrator.test_data_flow()
    for flow, result in flows.items():
        print(f"{flow}: {'✓' if result else '✗'}")

    print("\n=== Generating Status Report ===")
    report = orchestrator.generate_status_report()
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
EOF

sudo chmod +x /opt/soc-stack/orchestrator.py
```

#### 3.2 Create Monitoring Dashboard
```bash
# Create unified SOC dashboard configuration
sudo mkdir -p /etc/soc-stack/dashboards
sudo tee /etc/soc-stack/dashboards/soc-overview.json <<EOF
{
  "title": "SOC Stack Overview Dashboard",
  "hits": 0,
  "description": "Comprehensive view of all SOC components and integrations",
  "panelsJSON": "[
    {\"gridData\":{\"h\":8,\"i\":\"1\",\"w\":24,\"x\":0,\"y\":0},\"id\":\"soc-health-status\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"7.17.9\"},
    {\"gridData\":{\"h\":8,\"i\":\"2\",\"w\":12,\"x\":0,\"y\":8},\"id\":\"alert-severity-trend\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"7.17.9\"},
    {\"gridData\":{\"h\":8,\"i\":\"3\",\"w\":12,\"x\":12,\"y\":8},\"id\":\"top-alert-rules\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"7.17.9\"},
    {\"gridData\":{\"h\":8,\"i\":\"4\",\"w\":12,\"x\":0,\"y\":16},\"id\":\"case-status-distribution\",\"panelIndex\":\"4\",\"type\":\"visualization\",\"version\":\"7.17.9\"},
    {\"gridData\":{\"h\":8,\"i\":\"5\",\"w\":12,\"x\":12,\"y\":16},\"id\":\"threat-intel-activity\",\"panelIndex\":\"5\",\"type\":\"visualization\",\"version\":\"7.17.9\"},
    {\"gridData\":{\"h\":8,\"i\":\"6\",\"w\":24,\"x\":0,\"y\":24},\"id\":\"data-flow-status\",\"panelIndex\":\"6\",\"type\":\"visualization\",\"version\":\"7.17.9\"}
  ]",
  "optionsJSON": "{\"useMargins\":true}",
  "uiStateJSON": "{}",
  "version": 1,
  "timeRestore": false,
  "kibanaSavedObjectMeta": {
    "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
  }
}
EOF
```

## 🧪 Comprehensive Testing

### Step 4: End-to-End Testing Scenarios

#### 4.1 Create Test Scenario 1: Malware Detection
```bash
# Create comprehensive test scenario
sudo tee /opt/soc-stack/test-scenarios/malware-detection.sh <<'EOF'
#!/bin/bash
# Malware Detection Test Scenario

echo "=== Starting Malware Detection Test Scenario ==="

# 1. Generate suspicious file activity
echo "Step 1: Generating suspicious file activity..."
sudo touch /var/log/test-malware.log
echo "$(date) - Suspicious file access detected: /tmp/malware.exe" | sudo tee -a /var/log/test-malware.log

# 2. Generate network alert
echo "Step 2: Simulating network attack..."
sudo tee /var/ossec/logs/alerts/scenario-malware.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "level": 12,
    "description": "Malware file detected on agent",
    "id": "554",
    "groups": ["malware", "trojan"]
  },
  "agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.1.10"
  },
  "data": {
    "srcip": "203.0.113.1",
    "dstip": "192.168.1.10",
    "filename": "/tmp/malware.exe",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "process": "malware.exe"
  }
}
EOF

# 3. Trigger Wazuh integration
echo "Step 3: Testing Wazuh integrations..."
/var/ossec/integrations/custom/thehive-integration.py < /var/ossec/logs/alerts/scenario-malware.json
/var/ossec/integrations/custom/misp-enrichment.py < /var/ossec/logs/alerts/scenario-malware.json

# 4. Check data flow
echo "Step 4: Verifying data flow..."
curl -s -XGET "localhost:9200/wazuh-alerts-*/_search?q=rule.id:554" | jq '.hits.total.value'

# 5. Check case creation
echo "Step 5: Checking TheHive case creation..."
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case" | jq '.[0] | {title, severity, status}'

echo "=== Malware Detection Test Scenario Complete ==="
EOF

sudo chmod +x /opt/soc-stack/test-scenarios/malware-detection.sh
```

#### 4.2 Create Test Scenario 2: Network Intrusion
```bash
# Create network intrusion test scenario
sudo tee /opt/soc-stack/test-scenarios/network-intrusion.sh <<'EOF'
#!/bin/bash
# Network Intrusion Test Scenario

echo "=== Starting Network Intrusion Test Scenario ==="

# 1. Generate Suricata alert
echo "Step 1: Simulating Suricata alert..."
sudo tee /var/log/suricata/test-alert.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3N+00:00)",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "10.0.0.100",
  "src_port": 12345,
  "dest_ip": "192.168.1.10",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2000001,
    "rev": 1,
    "signature": "Possible SQL Injection Attempt",
    "category": "Web Application Attack",
    "severity": 2
  }
}
EOF

# 2. Generate Wazuh correlation alert
echo "Step 2: Creating correlated Wazuh alert..."
sudo tee /var/ossec/logs/alerts/scenario-intrusion.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "level": 10,
    "description": "Web attack detected - possible SQL injection",
    "id": "31101",
    "groups": ["web", "attack"]
  },
  "agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.1.10"
  },
  "data": {
    "srcip": "10.0.0.100",
    "dstip": "192.168.1.10",
    "url": "/search.php?query=1%27%20OR%20%271%27%3D%271",
    "status": "200",
    "method": "GET"
  }
}
EOF

# 3. Test integrations
echo "Step 3: Testing integrated response..."
/var/ossec/integrations/custom/thehive-integration.py < /var/ossec/logs/alerts/scenario-intrusion.json

# 4. Check threat intelligence enrichment
echo "Step 4: Testing threat intelligence enrichment..."
/var/ossec/integrations/custom/misp-enrichment.py < /var/ossec/logs/alerts/scenario-intrusion.json

# 5. Verify case details
echo "Step 5: Checking case details and observables..."
CASE_ID=$(curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case" | jq -r '.[0]._id')
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case/$CASE_ID/observable" | jq '.'

echo "=== Network Intrusion Test Scenario Complete ==="
EOF

sudo chmod +x /opt/soc-stack/test-scenarios/network-intrusion.sh
```

### Step 5: Performance Optimization

#### 5.1 Create Performance Monitoring
```bash
# Create performance monitoring script
sudo tee /opt/soc-stack/monitoring/performance-monitor.sh <<'EOF'
#!/bin/bash
# SOC Stack Performance Monitor

echo "=== SOC Stack Performance Report ==="
echo "Generated: $(date)"
echo "=========================================="

# System Resources
echo ""
echo "SYSTEM RESOURCES:"
echo "Memory Usage:"
free -h
echo ""
echo "Disk Usage:"
df -h | grep -E '^/dev/'
echo ""
echo "CPU Load:"
uptime
echo ""

# Component Performance
echo "COMPONENT PERFORMANCE:"
echo ""

# Elasticsearch
echo "Elasticsearch:"
curl -s -XGET "localhost:9200/_cluster/stats" | jq '.nodes | {count: .count.total, versions: .versions | length}'
curl -s -XGET "localhost:9200/_cluster/health" | jq '{status, active_shards_percent_as_number}'
echo ""

# Wazuh
echo "Wazuh Agents:"
/var/ossec/bin/agent_control -lc | wc -l
echo ""

# TheHive
echo "TheHive Cases:"
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case/_stats" | jq '.stats.count'
echo ""

# Data Flow Metrics
echo "DATA FLOW METRICS:"
echo "Recent Wazuh Alerts (last 1h):"
curl -s -XPOST "localhost:9200/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  }
}' | jq '.count'

echo ""
echo "Recent TheHive Cases (last 24h):"
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case/_search?range=1d" | jq '.cases | length'

echo ""
echo "=========================================="
echo "Performance Report Complete"
EOF

sudo chmod +x /opt/soc-stack/monitoring/performance-monitor.sh
```

#### 5.2 Automated Health Checks
```bash
# Create automated health check script
sudo tee /opt/soc-stack/health-check.sh <<'EOF'
#!/bin/bash
# SOC Stack Health Check

HEALTH_ISSUES=0

echo "=== SOC Stack Health Check ==="
echo "Timestamp: $(date)"
echo "================================="

# Check service status
echo ""
echo "SERVICE STATUS:"
services=("elasticsearch" "logstash" "kibana" "wazuh-manager" "thehive" "cortex" "cassandra")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "✓ $service: RUNNING"
    else
        echo "✗ $service: STOPPED"
        ((HEALTH_ISSUES++))
    fi
done

# Check connectivity
echo ""
echo "CONNECTIVITY CHECKS:"
# Elasticsearch
if curl -s -f localhost:9200/_cluster/health > /dev/null; then
    echo "✓ Elasticsearch: CONNECTED"
else
    echo "✗ Elasticsearch: DISCONNECTED"
    ((HEALTH_ISSUES++))
fi

# Kibana
if curl -s -f localhost:5601/api/status > /dev/null; then
    echo "✓ Kibana: CONNECTED"
else
    echo "✗ Kibana: DISCONNECTED"
    ((HEALTH_ISSUES++))
fi

# TheHive
if curl -s -f -H "Authorization: Bearer $THEHIVE_API_KEY" localhost:9000/api/status > /dev/null; then
    echo "✓ TheHive: CONNECTED"
else
    echo "✗ TheHive: DISCONNECTED"
    ((HEALTH_ISSUES++))
fi

# Data flow checks
echo ""
echo "DATA FLOW CHECKS:"
# Recent alerts
alert_count=$(curl -s -XPOST "localhost:9200/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  }
}' | jq -r '.count // 0')

if [ "$alert_count" -gt 0 ]; then
    echo "✓ Alert Flow: $alert_count alerts in last hour"
else
    echo "⚠ Alert Flow: No alerts in last hour"
fi

# Recent cases
case_count=$(curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" "localhost:9000/api/case/_search?range=1d" | jq -r '.cases | length // 0')
if [ "$case_count" -gt 0 ]; then
    echo "✓ Case Creation: $case_count cases in last 24 hours"
else
    echo "⚠ Case Creation: No cases in last 24 hours"
fi

echo ""
echo "================================="
if [ $HEALTH_ISSUES -eq 0 ]; then
    echo "✅ All systems healthy!"
else
    echo "⚠️  $HEALTH_ISSUES health issues detected"
fi
echo "================================="
EOF

sudo chmod +x /opt/soc-stack/health-check.sh

# Set up cron job for regular health checks
echo "*/15 * * * * root /opt/soc-stack/health-check.sh >> /var/log/soc-health.log 2>&1" | sudo tee /etc/cron.d/soc-health-check
```

## 🏁 Lab Completion and Validation

### Step 6: Final Validation

#### 6.1 Run Comprehensive Tests
```bash
# Run all test scenarios
echo "=== Running Comprehensive SOC Tests ==="

# Run orchestrator health check
python3 /opt/soc-stack/orchestrator.py

# Run test scenarios
/opt/soc-stack/test-scenarios/malware-detection.sh
/opt/soc-stack/test-scenarios/network-intrusion.sh

# Run performance monitoring
/opt/soc-stack/monitoring/performance-monitor.sh

# Final health check
/opt/soc-stack/health-check.sh
```

#### 6.2 Generate Final Report
```bash
# Generate comprehensive lab completion report
sudo tee /opt/soc-stack/final-report.sh <<'EOF'
#!/bin/bash
# SOC Stack Lab Completion Report

echo "==============================================="
echo "    COMPREHENSIVE SOC STACK LAB REPORT"
echo "==============================================="
echo "Completion Date: $(date)"
echo ""

echo "LAB OBJECTIVES ACHIEVED:"
echo "✓ Deploy complete SOC technology stack"
echo "✓ Configure data flows between all tools"
echo "✓ Implement automated threat detection"
echo "✓ Create unified security dashboards"
echo "✓ Test end-to-end incident response"
echo "✓ Optimize integrated tool performance"
echo ""

echo "SYSTEM COMPONENTS:"
echo "• Wazuh SIEM: $(systemctl is-active wazuh-manager)"
echo "• Elasticsearch: $(systemctl is-active elasticsearch)"
echo "• Logstash: $(systemctl is-active logstash)"
echo "• Kibana: $(systemctl is-active kibana)"
echo "• TheHive: $(systemctl is-active thehive)"
echo "• Cortex: $(systemctl is-active cortex)"
echo "• MISP: $(curl -s -o /dev/null -w '%{http_code}' http://localhost/)"
echo "• Cassandra: $(systemctl is-active cassandra)"
echo ""

echo "INTEGRATION STATUS:"
echo "• Wazuh → ELK: $(curl -s -XPOST 'localhost:9200/wazuh-alerts-*/_count' -H 'Content-Type: application/json' -d'{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}' | jq -r '.count // 0') alerts processed"
echo "• Wazuh → TheHive: $(curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" 'localhost:9000/api/case/_stats' | jq -r '.stats.count // 0') cases created"
echo "• MISP Integration: $(curl -s -H "Authorization: $MISP_API_KEY" 'http://localhost/events/restSearch' | jq -r '.response | length // 0') events available"
echo ""

echo "PERFORMANCE METRICS:"
echo "• System Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "• Memory Usage: $(free | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
echo "• Disk Usage: $(df / | awk 'NR==2{print $5}')"
echo ""

echo "TEST RESULTS:"
echo "• Health Checks: $(grep -c "All systems healthy" /var/log/soc-health.log 2>/dev/null || echo 0) passed"
echo "• Integration Tests: $(ls /opt/soc-stack/test-scenarios/ | wc -l) scenarios available"
echo ""

echo "RECOMMENDATIONS:"
echo "• Schedule regular backup of all component data"
echo "• Implement monitoring alerts for system health"
echo "• Review and tune alert rules based on environment"
echo "• Consider high availability setup for production"
echo "• Implement log rotation and retention policies"
echo ""

echo "==============================================="
echo "        LAB COMPLETION CONFIRMED"
echo "==============================================="
EOF

sudo chmod +x /opt/soc-stack/final-report.sh
/opt/soc-stack/final-report.sh
```

## 📚 Resources and Documentation

### Additional Configuration Files
- `/etc/soc-stack/config.yml` - Main SOC configuration
- `/opt/soc-stack/orchestrator.py` - System orchestration script
- `/opt/soc-stack/health-check.sh` - Health monitoring script
- `/etc/soc-stack/dashboards/` - Custom dashboard configurations

### Maintenance Commands
```bash
# Daily maintenance
/opt/soc-stack/health-check.sh
/opt/soc-stack/monitoring/performance-monitor.sh

# Weekly maintenance
# Backup configurations
tar -czf /backup/soc-config-$(date +%Y%m%d).tar.gz /etc/soc-stack/

# Update all components
apt update && apt upgrade -y

# Clean old logs
find /var/log -name "*.log" -mtime +30 -delete
```

### Troubleshooting Guide
- Check `/var/log/soc-health.log` for health issues
- Review individual component logs for specific errors
- Use `/opt/soc-stack/orchestrator.py` for diagnostics
- Verify network connectivity between components
- Check resource usage with monitoring scripts

## 🎯 Success Criteria

Your comprehensive SOC stack is successfully implemented when:

- [ ] All security tools are running and communicating
- [ ] Wazuh alerts flow to ELK Stack and create visualizations
- [ ] Threat intelligence from MISP enriches Wazuh alerts
- [ ] TheHive creates cases automatically from security alerts
- [ ] Cortex provides automated analysis of observables
- [ ] Kibana dashboards show unified security data
- [ ] End-to-end incident response workflows function
- [ ] Performance monitoring shows healthy system metrics
- [ ] Automated health checks report no critical issues
- [ ] Test scenarios execute successfully
- [ ] Documentation is complete and up-to-date

## 🔗 Next Steps

Congratulations on completing the comprehensive SOC stack implementation! 

**For production deployment, consider:**
- Implementing high availability for critical components
- Setting up centralized logging and monitoring
- Configuring automated backup and recovery
- Implementing security hardening measures
- Establishing change management processes
- Creating runbooks for common incident scenarios

**Advanced topics to explore:**
- Machine learning integration for anomaly detection
- Custom analytics development
- Integration with additional security tools
- Advanced threat hunting capabilities
- Automated response and remediation workflows

**[← Back to TheHive Integration Lab](./lab-04-thehive-workflow.md)** | **[Back to Module Overview](../README.md)**