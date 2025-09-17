# Lab 4: TheHive Incident Response Integration

## 🎯 Lab Overview

This hands-on lab will guide you through setting up TheHive incident response platform and integrating it with Wazuh for automated case creation, task management, and coordinated incident response. You'll learn to create cases from Wazuh alerts, implement response workflows, and configure Cortex for automated analysis.

### 📋 Prerequisites

- **Wazuh Environment**: Working Wazuh server with agents and alerts
- **System Requirements**: Ubuntu/Debian server with:
  - 6GB RAM minimum (8GB recommended)
  - 2 CPU cores minimum
  - 20GB free disk space
- **Basic Knowledge**: Wazuh alerts, incident response concepts, case management

### 🏆 Lab Objectives

By the end of this lab, you will be able to:
- Install and configure TheHive and Cortex platforms
- Create automated case generation from Wazuh alerts
- Implement task workflows and assignments
- Configure Cortex analyzers for automated threat analysis
- Set up escalation rules and response automation
- Build incident response dashboards
- Test end-to-end incident response workflows

## 🚀 Lab Setup

### Step 1: Install TheHive and Cortex

#### 1.1 Install Dependencies
```bash
sudo apt update
sudo apt install -y openjdk-11-jdk-headless curl wget gnupg2 \
    software-properties-common ca-certificates python3 python3-pip
```

#### 1.2 Install Cassandra
```bash
# Install Cassandra
sudo apt install -y cassandra

# Start Cassandra
sudo systemctl enable cassandra
sudo systemctl start cassandra

# Verify Cassandra
nodetool status
```

#### 1.3 Install Elasticsearch
```bash
# Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

sudo apt update
sudo apt install -y elasticsearch

# Configure Elasticsearch
sudo tee /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: thehive-cluster
node.name: thehive-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
EOF

sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

#### 1.4 Install TheHive
```bash
# Download and install TheHive
wget https://github.com/TheHive-Project/TheHive/releases/download/4.1.0/thehive_4.1.0-1_amd64.deb
sudo dpkg -i thehive_4.1.0-1_amd64.deb
sudo apt install -f

# Configure TheHive
sudo tee /etc/thehive/application.conf <<EOF
play.http.secret.key = "$(openssl rand -base64 32)"

db.janusgraph {
  storage.backend = cql
  storage.hostname = "127.0.0.1"
  storage.cql.keyspace = thehive
}

search {
  index = local
  uri = "http://127.0.0.1:9200"
}

cortex {
  servers = [
    {
      name = "local"
      url = "http://127.0.0.1:9001"
      auth {
        type = "bearer"
        key = "cortex_api_key"
      }
    }
  ]
}
EOF

sudo systemctl enable thehive
sudo systemctl start thehive
```

#### 1.5 Install Cortex
```bash
# Download and install Cortex
wget https://github.com/TheHive-Project/Cortex/releases/download/3.1.0/cortex_3.1.0-1_amd64.deb
sudo dpkg -i cortex_3.1.0-1_amd64.deb
sudo apt install -f

# Configure Cortex
sudo tee /etc/cortex/application.conf <<EOF
play.http.secret.key = "$(openssl rand -base64 32)"

search {
  index = local
  uri = "http://127.0.0.1:9200"
}
EOF

sudo systemctl enable cortex
sudo systemctl start cortex
```

### Step 2: Configure TheHive Integration

#### 2.1 Create Wazuh Integration Script
```bash
sudo tee /var/ossec/integrations/custom/thehive-integration.py <<'EOF'
#!/usr/bin/env python3
# TheHive Integration for Wazuh

import json
import sys
import os
import requests
from datetime import datetime

class TheHiveIntegration:
    def __init__(self):
        self.thehive_url = os.getenv('THEHIVE_URL', 'http://localhost:9000')
        self.thehive_api_key = os.getenv('THEHIVE_API_KEY')
        self.headers = {
            'Authorization': f'Bearer {self.thehive_api_key}',
            'Content-Type': 'application/json'
        }

    def process_alert(self, alert):
        """Process Wazuh alert and create TheHive case"""
        try:
            # Create case
            case_data = self.create_case_data(alert)
            case_response = requests.post(
                f'{self.thehive_url}/api/case',
                headers=self.headers,
                json=case_data
            )

            if case_response.status_code == 201:
                case_id = case_response.json()['_id']
                print(f"Case created: {case_id}")

                # Add observables
                self.add_observables(case_id, alert)

                # Create tasks
                self.create_tasks(case_id, alert)

                return {"success": True, "case_id": case_id}
            else:
                return {"success": False, "error": f"HTTP {case_response.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_case_data(self, alert):
        """Create case data from Wazuh alert"""
        rule = alert.get('rule', {})
        data = alert.get('data', {})
        agent = alert.get('agent', {})

        case = {
            "title": f"Wazuh Alert: {rule.get('description', 'Unknown')}",
            "description": f"""# Wazuh Security Alert

**Rule ID:** {rule.get('id', 'N/A')}
**Level:** {rule.get('level', 'N/A')}
**Agent:** {agent.get('name', 'N/A')} ({agent.get('ip', 'N/A')})

## Alert Details
- **Timestamp:** {alert.get('timestamp', 'N/A')}
- **Source IP:** {data.get('srcip', 'N/A')}
- **Destination IP:** {data.get('dstip', 'N/A')}
- **Filename:** {data.get('filename', 'N/A')}

## Raw Alert Data
```json
{json.dumps(alert, indent=2)}
```
            """,
            "severity": min(rule.get('level', 5) // 2 + 1, 4),
            "startDate": int(datetime.now().timestamp() * 1000),
            "tags": [
                "wazuh",
                f"rule-{rule.get('id', 'unknown')}",
                f"level-{rule.get('level', 'unknown')}",
                f"agent-{agent.get('name', 'unknown')}"
            ],
            "customFields": {
                "wazuhRuleId": {"string": rule.get('id', 'N/A')},
                "wazuhAgent": {"string": agent.get('name', 'N/A')},
                "sourceIP": {"string": data.get('srcip', '')},
                "destinationIP": {"string": data.get('dstip', '')}
            }
        }

        return case

    def add_observables(self, case_id, alert):
        """Add observables to the case"""
        data = alert.get('data', {})
        observables = []

        # Add IP addresses
        for ip_field in ['srcip', 'dstip']:
            if data.get(ip_field):
                observables.append({
                    "dataType": "ip",
                    "data": data[ip_field],
                    "message": f"Wazuh detected IP: {data[ip_field]}",
                    "tags": ["wazuh", ip_field]
                })

        # Add filename
        if data.get('filename'):
            observables.append({
                "dataType": "filename",
                "data": data['filename'],
                "message": f"Suspicious file: {data['filename']}",
                "tags": ["wazuh", "file"]
            })

        # Add hashes
        for hash_field in ['md5', 'sha1', 'sha256']:
            if data.get(hash_field):
                observables.append({
                    "dataType": "hash",
                    "data": data[hash_field],
                    "message": f"File hash ({hash_field}): {data[hash_field]}",
                    "tags": ["wazuh", "hash"]
                })

        # Submit observables
        for obs in observables:
            requests.post(
                f'{self.thehive_url}/api/case/{case_id}/observable',
                headers=self.headers,
                json=obs
            )

    def create_tasks(self, case_id, alert):
        """Create response tasks for the case"""
        rule_level = alert.get('rule', {}).get('level', 5)

        tasks = [
            {
                "title": "Triage Alert",
                "description": "Review alert details and assess impact",
                "status": "Waiting",
                "order": 1
            },
            {
                "title": "Gather Evidence",
                "description": "Collect additional context and evidence",
                "status": "Waiting",
                "order": 2
            },
            {
                "title": "Analyze Impact",
                "description": "Determine scope and impact of the incident",
                "status": "Waiting",
                "order": 3
            }
        ]

        # Add escalation task for high-severity alerts
        if rule_level >= 12:
            tasks.append({
                "title": "Escalate to Senior Team",
                "description": "High severity alert requires senior review",
                "status": "Waiting",
                "order": 4
            })

        # Submit tasks
        for task in tasks:
            requests.post(
                f'{self.thehive_url}/api/case/{case_id}/task',
                headers=self.headers,
                json=task
            )

def main():
    integration = TheHiveIntegration()

    # Read Wazuh alert from stdin
    alert_json = sys.stdin.read()
    try:
        alert = json.loads(alert_json)
        result = integration.process_alert(alert)
        print(json.dumps(result))
    except json.JSONDecodeError as e:
        error_result = {
            'success': False,
            'error': f'Invalid JSON: {str(e)}'
        }
        print(json.dumps(error_result))

if __name__ == "__main__":
    main()
EOF

sudo chmod +x /var/ossec/integrations/custom/thehive-integration.py
```

#### 2.2 Configure Wazuh Integration
```bash
# Add TheHive integration to Wazuh
sudo tee -a /var/ossec/etc/ossec.conf <<EOF
<integration>
  <name>custom/thehive-integration</name>
  <hook_url>http://localhost:8080/thehive</hook_url>
  <level>8</level>
  <rule_id>100500</rule_id>
  <alert_format>json</alert_format>
</integration>
EOF

# Set environment variables
sudo tee /etc/environment <<EOF
THEHIVE_URL=http://localhost:9000
THEHIVE_API_KEY=your_thehive_api_key_here
EOF
```

### Step 3: Configure Cortex Analyzers

#### 3.1 Install Cortex Analyzers
```bash
# Install analyzers
cd /opt/cortex
sudo -u cortex ./bin/cortex analyzers install

# List available analyzers
curl -H "Authorization: Bearer cortex_api_key" \
  http://localhost:9001/api/analyzer | jq '.[] | .name'
```

#### 3.2 Create Custom Analyzer
```bash
# Create custom Wazuh analyzer
sudo mkdir -p /opt/cortex/analyzers/custom
sudo tee /opt/cortex/analyzers/custom/wazuh_analyzer.py <<'EOF'
from cortexutils.analyzer import Analyzer

class WazuhAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        return {"type": "Wazuh Analysis", "result": "Analysis completed"}

    def run(self):
        try:
            data = self.get_param('data', None)
            data_type = self.get_param('dataType', 'wazuh-alert')

            if data_type == 'wazuh-alert':
                result = self.analyze_wazuh_alert(data)
            else:
                result = {"error": f"Unsupported data type: {data_type}"}

            self.report(result)

        except Exception as e:
            self.error(f"Analysis failed: {str(e)}")

    def analyze_wazuh_alert(self, alert_data):
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        event_data = alert_data.get('data', {})

        analysis = {
            "rule_analysis": {
                "id": rule.get('id'),
                "level": rule.get('level'),
                "description": rule.get('description'),
                "severity_assessment": self.assess_severity(rule.get('level', 0))
            },
            "agent_analysis": {
                "name": agent.get('name'),
                "ip": agent.get('ip'),
                "status": "active"
            },
            "ioc_analysis": {
                "source_ip": event_data.get('srcip'),
                "destination_ip": event_data.get('dstip'),
                "filename": event_data.get('filename'),
                "file_hash": event_data.get('md5') or event_data.get('sha1') or event_data.get('sha256')
            },
            "recommendations": self.generate_recommendations(rule.get('level', 0))
        }

        return analysis

    def assess_severity(self, level):
        if level >= 15:
            return "Critical - Immediate response required"
        elif level >= 12:
            return "High - Rapid response needed"
        elif level >= 8:
            return "Medium - Investigation required"
        elif level >= 5:
            return "Low - Monitor and log"
        else:
            return "Informational"

    def generate_recommendations(self, level):
        if level >= 12:
            return [
                "Isolate affected system",
                "Collect full memory dump",
                "Review recent system changes",
                "Check for lateral movement"
            ]
        elif level >= 8:
            return [
                "Review system logs",
                "Check for similar events",
                "Validate user activity",
                "Update security controls"
            ]
        else:
            return [
                "Document the event",
                "Monitor for patterns",
                "Review security policies"
            ]

if __name__ == '__main__':
    WazuhAnalyzer().run()
EOF
```

### Step 4: Test Integration

#### 4.1 Create Test Alert
```bash
# Generate test alert
sudo tee /var/ossec/logs/alerts/test-alert.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "level": 10,
    "description": "Test alert for TheHive integration",
    "id": "100001"
  },
  "agent": {
    "id": "001",
    "name": "test-agent",
    "ip": "10.0.0.1"
  },
  "data": {
    "srcip": "192.168.1.100",
    "dstip": "10.0.0.2",
    "filename": "suspicious.exe"
  }
}
EOF
```

#### 4.2 Test Integration Script
```bash
# Test the integration script
cat /var/ossec/logs/alerts/test-alert.json | python3 /var/ossec/integrations/custom/thehive-integration.py
```

#### 4.3 Verify Case Creation
```bash
# Check TheHive for created cases
curl -H "Authorization: Bearer $THEHIVE_API_KEY" \
  http://localhost:9000/api/case | jq '.'
```

### Step 5: Advanced Workflows

#### 5.1 Create Escalation Rules
```bash
# Create escalation workflow script
sudo tee /var/ossec/integrations/custom/escalation-manager.py <<'EOF'
#!/usr/bin/env python3
# Case Escalation Manager

import json
import requests
import time

THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "your_api_key"

def check_escalation_rules():
    """Check for cases requiring escalation"""
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Get open cases
    response = requests.get(f"{THEHIVE_URL}/api/case", headers=headers)

    if response.status_code == 200:
        cases = response.json()

        for case in cases:
            if needs_escalation(case):
                escalate_case(case['_id'])

def needs_escalation(case):
    """Determine if case needs escalation"""
    severity = case.get('severity', 1)
    age_hours = (time.time() * 1000 - case.get('startDate', 0)) / (1000 * 60 * 60)

    # Escalate if high severity and older than 2 hours
    return severity >= 3 and age_hours > 2

def escalate_case(case_id):
    """Escalate case to senior team"""
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Add escalation task
    task_data = {
        "title": "URGENT: Senior Team Review Required",
        "description": "Case has exceeded SLA and requires immediate attention",
        "status": "Waiting",
        "flag": True
    }

    requests.post(
        f"{THEHIVE_URL}/api/case/{case_id}/task",
        headers=headers,
        json=task_data
    )

if __name__ == "__main__":
    while True:
        check_escalation_rules()
        time.sleep(300)  # Check every 5 minutes
EOF

sudo chmod +x /var/ossec/integrations/custom/escalation-manager.py
```

#### 5.2 Set Up Automated Analysis
```bash
# Create automated analyzer trigger
sudo tee /var/ossec/integrations/custom/auto-analyzer.py <<'EOF'
#!/usr/bin/env python3
# Automated Cortex Analyzer

import json
import requests
import time

CORTEX_URL = "http://localhost:9001"
CORTEX_API_KEY = "cortex_api_key"

THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "thehive_api_key"

def analyze_new_observables():
    """Automatically analyze new observables with Cortex"""
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Get recent cases
    response = requests.get(f"{THEHIVE_URL}/api/case", headers=headers)

    if response.status_code == 200:
        cases = response.json()

        for case in cases:
            analyze_case_observables(case['_id'])

def analyze_case_observables(case_id):
    """Analyze observables for a specific case"""
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Get case observables
    response = requests.get(f"{THEHIVE_URL}/api/case/{case_id}/observable", headers=headers)

    if response.status_code == 200:
        observables = response.json()

        for obs in observables:
            if not obs.get('reports'):  # If not already analyzed
                run_cortex_analysis(case_id, obs)

def run_cortex_analysis(case_id, observable):
    """Run Cortex analysis on observable"""
    cortex_headers = {
        'Authorization': f'Bearer {CORTEX_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Trigger analysis
    analysis_data = {
        "analyzerId": "wazuh_analyzer",
        "objectId": observable['_id'],
        "objectType": "case_artifact"
    }

    requests.post(
        f"{CORTEX_URL}/api/analyzer/run",
        headers=cortex_headers,
        json=analysis_data
    )

if __name__ == "__main__":
    while True:
        analyze_new_observables()
        time.sleep(600)  # Run every 10 minutes
EOF

sudo chmod +x /var/ossec/integrations/custom/auto-analyzer.py
```

## 🧪 Testing and Validation

### Step 6: Comprehensive Testing

#### 6.1 Test Case Creation
```bash
# Generate test alerts of different severities
for level in 5 8 12 15; do
  sudo tee /var/ossec/logs/alerts/test-level-$level.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "level": $level,
    "description": "Test alert level $level",
    "id": "10${level}001"
  },
  "agent": {
    "id": "001",
    "name": "test-agent",
    "ip": "10.0.0.1"
  },
  "data": {
    "srcip": "192.168.1.$level",
    "dstip": "10.0.0.2"
  }
}
EOF
done
```

#### 6.2 Test Cortex Integration
```bash
# Test Cortex analyzer
curl -X POST \
  -H "Authorization: Bearer cortex_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "analyzerId": "wazuh_analyzer",
    "data": "{\"rule\":{\"level\":12,\"description\":\"Test\"},\"agent\":{\"name\":\"test\"}}",
    "dataType": "wazuh-alert"
  }' \
  http://localhost:9001/api/analyzer/run
```

#### 6.3 Verify Dashboard Integration
```bash
# Check TheHive dashboard
curl -H "Authorization: Bearer $THEHIVE_API_KEY" \
  http://localhost:9000/api/case/_stats | jq '.'
```

## 🏁 Lab Completion Checklist

- [ ] TheHive and Cortex platforms installed and configured
- [ ] Wazuh integration script created and configured
- [ ] Test cases generated from Wazuh alerts
- [ ] Observables extracted and added to cases
- [ ] Tasks created and assigned based on alert severity
- [ ] Cortex analyzers configured for automated analysis
- [ ] Escalation workflows implemented
- [ ] End-to-end integration tested
- [ ] Automation scripts configured and running
- [ ] Incident response dashboards functional
- [ ] Documentation of workflows completed

## 🎯 Next Steps

With your TheHive integration complete, proceed to the final lab to combine all integrations into a comprehensive SOC environment.

**[← Back to Incident Response Theory](./05-incident-response-integration.md)** | **[Next: Comprehensive SOC Stack Lab →](./lab-05-comprehensive-soc-stack.md)**