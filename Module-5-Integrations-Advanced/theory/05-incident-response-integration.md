# Incident Response Integration with TheHive

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Incident response frameworks and processes
- TheHive platform architecture and capabilities
- Case management and workflow automation
- Integration methods between Wazuh and TheHive
- Automated incident creation from Wazuh alerts
- Cortex integration for automated analysis
- Escalation workflows and response coordination
- Performance monitoring and optimization

## 📋 What is Incident Response?

### Overview and Framework
**Incident Response** is an organized approach to addressing and managing security breaches or cyber attacks:
- **Preparation**: Establishing incident response capabilities and plans
- **Identification**: Detecting and assessing potential security incidents
- **Containment**: Limiting the scope and impact of incidents
- **Eradication**: Removing the cause and effects of incidents
- **Recovery**: Restoring systems to normal operation
- **Lessons Learned**: Analyzing incidents and improving response capabilities

### Incident Response Frameworks
```
┌─────────────────────────────────────────────────────────────┐
│             INCIDENT RESPONSE FRAMEWORKS                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   NIST      │  │   SANS     │  │   VERIS     │          │
│  │   SP 800-61 │  │   PROCESS  │  │   FRAMEWORK│          │
│  │             │  │            │  │            │          │
│  │ • Preparation│  │ • Preparation│  │ • Vocabulary│          │
│  │ • Detection │  │ • Identification│  │ • Enumeration│        │
│  │ • Analysis  │  │ • Containment │  │ • Analysis  │          │
│  │ • Containment│  │ • Eradication│  │ • Attribution│          │
│  │ • Eradication│  │ • Recovery   │  │ • Impact    │          │
│  │ • Recovery  │  │ • Lessons    │  │ • Incident  │          │
│  │ • Lessons   │  │   Learned    │  │   Types    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   CASE      │  │   WORKFLOW  │  │   AUTOMATION│          │
│  │ MANAGEMENT  │  │   ORCHESTRATION│  │   INTEGRATION│       │
│  │             │  │             │  │             │          │
│  │ • Ticket    │  │ • Task      │  │ • API       │          │
│  │   creation  │  │   assignment │  │   triggers │          │
│  │ • Evidence  │  │ • Escalation │  │ • Response  │          │
│  │   collection│  │ • SLA       │  │   actions   │          │
│  │ • Timeline  │  │   tracking   │  │ • Integration│         │
│  │ • Reporting │  │ • Reporting  │  │   with tools│         │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ TheHive Platform Architecture

### Core Components

#### 1. TheHive Server
Central incident response platform:
- **Case Management**: Structured incident tracking and documentation
- **Task Management**: Assignable tasks and checklists for response activities
- **Observable Management**: Evidence collection and analysis
- **Timeline Tracking**: Chronological incident timeline with all activities

#### 2. Cortex
Automated analysis and response engine:
- **Analyzer Modules**: Automated analysis of observables
- **Responder Modules**: Automated response actions
- **Integration Framework**: Extensible analysis and response capabilities
- **API Interface**: RESTful API for integration with other tools

#### 3. TheHive Web Interface
User interface for incident management:
- **Dashboard**: Overview of active cases and system status
- **Case Details**: Comprehensive case information and management
- **Search and Filtering**: Advanced search capabilities
- **Reporting**: Case statistics and reporting tools

### Integration Architecture
```
Wazuh Alerts → TheHive API → Case Creation → Task Assignment → Cortex Analysis → Response Actions
     ↓              ↓           ↓           ↓           ↓           ↓
Detection    Integration  Management  Workflow   Automation   Execution
```

## 🔧 Integration with Wazuh

### Integration Methods

#### Direct API Integration
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  THEHIVE    │───▶│   CORTEX    │───▶│  RESPONSE   │
│   ALERTS    │    │   API       │    │   ANALYSIS  │    │   ACTIONS   │
│ • JSON      │    │ • Case      │    │ • Observable │    │ • Blocking  │
│   format    │    │   creation  │    │   analysis  │    │ • Isolation │
│ • Rule      │    │ • Task      │    │ • Threat    │    │ • Remediation│
│   triggers  │    │   assignment│    │   intelligence│   │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

#### Webhook Integration
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│   WEBHOOK   │───▶│  THEHIVE    │
│   SERVER    │    │   SERVICE   │    │   PLATFORM  │
│ • Alert     │    │ • HTTP      │    │ • Case      │
│   generation│    │   POST      │    │   creation  │
│ • JSON      │    │ • Processing│    │ • Observable│
│   payload   │    │ • Filtering │    │   extraction│
└─────────────┘    └─────────────┘    └─────────────┘
```

### Integration Benefits
- **Structured Response**: Organized incident management and tracking
- **Automated Workflows**: Reduced manual effort through automation
- **Evidence Collection**: Systematic evidence gathering and analysis
- **Team Collaboration**: Coordinated response across multiple team members
- **Audit Trail**: Complete documentation of all response activities
- **Performance Metrics**: Incident response statistics and reporting

## 📋 TheHive Installation and Configuration

### Installing TheHive

#### Ubuntu/Debian Installation
```bash
# Install Java
sudo apt update
sudo apt install openjdk-11-jre-headless

# Install Cassandra
sudo apt install cassandra

# Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch

# Install TheHive
wget https://github.com/TheHive-Project/TheHive/releases/download/4.1.0/thehive_4.1.0-1_amd64.deb
sudo dpkg -i thehive_4.1.0-1_amd64.deb
sudo apt install -f

# Install Cortex
wget https://github.com/TheHive-Project/Cortex/releases/download/3.1.0/cortex_3.1.0-1_amd64.deb
sudo dpkg -i cortex_3.1.0-1_amd64.deb
sudo apt install -f
```

#### Docker Installation (Recommended for Labs)
```yaml
# docker-compose.yml
version: '3.8'
services:
  thehive:
    image: thehiveproject/thehive:4.1.0
    ports:
      - "9000:9000"
    environment:
      - TH_CORTEX_ORGANISATION=your_org
      - TH_CORTEX_URL=http://cortex:9001
      - TH_SECRET_KEY=your_secret_key
    depends_on:
      - cassandra
      - elasticsearch

  cortex:
    image: thehiveproject/cortex:3.1.0
    ports:
      - "9001:9001"
    environment:
      - CORTEX_SECRET_KEY=cortex_secret_key
    depends_on:
      - elasticsearch

  cassandra:
    image: cassandra:3.11
    ports:
      - "9042:9042"

  elasticsearch:
    image: elasticsearch:7.17.9
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
      - "9300:9300"
```

### Basic Configuration

#### TheHive Configuration
```yaml
# /etc/thehive/application.conf
play.http.secret.key = "your_secret_key_here"
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
```

#### Cortex Configuration
```yaml
# /etc/cortex/application.conf
play.http.secret.key = "cortex_secret_key"

search {
  index = local
  uri = "http://127.0.0.1:9200"
}

auth {
  type = "local"
  user = "admin"
  password = "admin_password"
}
```

## 🔍 Wazuh TheHive Integration Setup

### Method 1: Direct API Integration

#### Python Integration Script
```python
#!/usr/bin/env python3
# /var/ossec/integrations/custom-thehive.py

import json
import sys
import os
import requests
from datetime import datetime

def main():
    # Read Wazuh alert from stdin
    alert = json.loads(sys.stdin.read())

    # TheHive configuration
    thehive_url = os.getenv('THEHIVE_URL', 'http://localhost:9000')
    thehive_api_key = os.getenv('THEHIVE_API_KEY', 'your_api_key')

    headers = {
        'Authorization': f'Bearer {thehive_api_key}',
        'Content-Type': 'application/json'
    }

    try:
        # Create case from alert
        case_data = create_case_from_alert(alert)

        # Send to TheHive
        response = requests.post(
            f'{thehive_url}/api/case',
            headers=headers,
            json=case_data
        )

        if response.status_code == 201:
            case_id = response.json()['_id']
            print(f"Case created in TheHive: {case_id}")

            # Add observables
            add_observables(case_id, alert, headers, thehive_url)

            # Create tasks
            create_tasks(case_id, alert, headers, thehive_url)

        else:
            print(f"Error creating case: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Integration error: {str(e)}")

def create_case_from_alert(alert):
    rule = alert.get('rule', {})
    data = alert.get('data', {})

    case = {
        "title": f"Wazuh Alert: {rule.get('description', 'Unknown')}",
        "description": f"""
# Wazuh Security Alert

**Rule ID:** {rule.get('id', 'N/A')}
**Level:** {rule.get('level', 'N/A')}
**Description:** {rule.get('description', 'N/A')}

## Alert Details
- **Timestamp:** {alert.get('timestamp', 'N/A')}
- **Agent:** {alert.get('agent', {}).get('name', 'N/A')} ({alert.get('agent', {}).get('ip', 'N/A')})

## Event Data
{json.dumps(data, indent=2)}
        """,
        "severity": min(rule.get('level', 5) // 2 + 1, 4),  # Convert to 1-4 scale
        "startDate": datetime.now().timestamp() * 1000,
        "tags": [
            "wazuh",
            f"rule-{rule.get('id', 'unknown')}",
            f"level-{rule.get('level', 'unknown')}"
        ],
        "customFields": {
            "wazuhRuleId": {"string": rule.get('id', 'N/A')},
            "wazuhAgent": {"string": alert.get('agent', {}).get('name', 'N/A')}
        }
    }

    return case

def add_observables(case_id, alert, headers, thehive_url):
    data = alert.get('data', {})
    observables = []

    # Add IP addresses
    for ip_field in ['srcip', 'dstip', 'clientip']:
        if data.get(ip_field):
            observables.append({
                "dataType": "ip",
                "data": data[ip_field],
                "message": f"Wazuh detected IP: {data[ip_field]}"
            })

    # Add file information
    if data.get('filename'):
        observables.append({
            "dataType": "filename",
            "data": data['filename'],
            "message": f"Suspicious file: {data['filename']}"
        })

    # Add hashes
    for hash_field in ['md5', 'sha1', 'sha256']:
        if data.get(hash_field):
            observables.append({
                "dataType": "hash",
                "data": data[hash_field],
                "message": f"File hash ({hash_field}): {data[hash_field]}"
            })

    # Submit observables
    for obs in observables:
        requests.post(
            f'{thehive_url}/api/case/{case_id}/observable',
            headers=headers,
            json=obs
        )

def create_tasks(case_id, alert, headers, thehive_url):
    rule_level = alert.get('rule', {}).get('level', 5)

    tasks = []

    # Basic triage task
    tasks.append({
        "title": "Initial Triage",
        "description": "Review alert details and assess severity",
        "status": "Waiting",
        "order": 1
    })

    # Investigation task
    tasks.append({
        "title": "Investigate Alert",
        "description": "Gather additional context and evidence",
        "status": "Waiting",
        "order": 2
    })

    # High severity additional tasks
    if rule_level >= 12:
        tasks.append({
            "title": "Escalate to Senior Team",
            "description": "High severity alert requires senior review",
            "status": "Waiting",
            "order": 3
        })

    # Submit tasks
    for task in tasks:
        requests.post(
            f'{thehive_url}/api/case/{case_id}/task',
            headers=headers,
            json=task
        )

if __name__ == "__main__":
    main()
```

### Method 2: Webhook Integration

#### Wazuh Integration Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<integration>
  <name>custom-thehive</name>
  <hook_url>http://localhost:8080/thehive-webhook</hook_url>
  <level>8</level>
  <rule_id>100400</rule_id>
  <alert_format>json</alert_format>
</integration>
```

#### Webhook Service (Node.js example)
```javascript
// webhook-server.js
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

const THEHIVE_URL = process.env.THEHIVE_URL || 'http://localhost:9000';
const THEHIVE_API_KEY = process.env.THEHIVE_API_KEY;

// Middleware to verify Wazuh webhook
app.use((req, res, next) => {
  // Add authentication if needed
  next();
});

// Webhook endpoint
app.post('/thehive-webhook', async (req, res) => {
  try {
    const alert = req.body;

    // Create case in TheHive
    const caseData = {
      title: `Wazuh Alert: ${alert.rule?.description || 'Unknown'}`,
      description: `Security alert from Wazuh\n\n${JSON.stringify(alert, null, 2)}`,
      severity: Math.min(Math.floor((alert.rule?.level || 5) / 3) + 1, 4),
      startDate: Date.now(),
      tags: ['wazuh', `level-${alert.rule?.level || 'unknown'}`]
    };

    const response = await axios.post(`${THEHIVE_URL}/api/case`, caseData, {
      headers: {
        'Authorization': `Bearer ${THEHIVE_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    console.log(`Case created: ${response.data._id}`);
    res.status(200).json({ success: true, caseId: response.data._id });

  } catch (error) {
    console.error('Webhook error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(8080, () => {
  console.log('TheHive webhook server listening on port 8080');
});
```

## 🔧 Cortex Integration for Automated Analysis

### Cortex Analyzer Configuration

#### Install Analyzers
```bash
# Install Cortex analyzers
cd /opt/cortex
sudo -u cortex ./bin/cortex analyzers install

# List available analyzers
curl -H "Authorization: Bearer cortex_api_key" \
  http://localhost:9001/api/analyzer
```

#### Custom Analyzer for Wazuh Data
```python
# /opt/cortex/analyzers/wazuh_analyzer.py
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
        # Extract key information
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        event_data = alert_data.get('data', {})

        analysis = {
            "rule_id": rule.get('id'),
            "rule_level": rule.get('level'),
            "rule_description": rule.get('description'),
            "agent_name": agent.get('name'),
            "agent_ip": agent.get('ip'),
            "source_ip": event_data.get('srcip'),
            "destination_ip": event_data.get('dstip'),
            "filename": event_data.get('filename'),
            "severity_assessment": self.assess_severity(rule.get('level', 0))
        }

        return analysis

    def assess_severity(self, level):
        if level >= 15:
            return "Critical"
        elif level >= 12:
            return "High"
        elif level >= 8:
            return "Medium"
        elif level >= 5:
            return "Low"
        else:
            return "Informational"

if __name__ == '__main__':
    WazuhAnalyzer().run()
```

## 🚨 Advanced Workflows and Automation

### Escalation Rules

#### Automatic Case Escalation
```javascript
// Escalation workflow script
const axios = require('axios');

async function checkEscalationRules(caseId) {
  const caseData = await getCaseDetails(caseId);

  // Check for critical indicators
  const criticalIndicators = [
    caseData.severity >= 4,
    caseData.tags.includes('critical'),
    caseData.observables.some(obs => obs.dataType === 'ip' && isMaliciousIP(obs.data))
  ];

  if (criticalIndicators.some(indicator => indicator)) {
    await escalateCase(caseId, 'Critical threat detected');
  }
}

async function getCaseDetails(caseId) {
  // Implementation to fetch case details from TheHive
}

async function escalateCase(caseId, reason) {
  // Implementation to escalate case
  console.log(`Escalating case ${caseId}: ${reason}`);
}
```

### Response Action Integration

#### Automated Response Actions
```python
# Automated response script
import subprocess
import json

def execute_response_action(action_type, parameters):
    actions = {
        'block_ip': block_ip_address,
        'isolate_host': isolate_host,
        'quarantine_file': quarantine_file,
        'send_notification': send_notification
    }

    if action_type in actions:
        return actions[action_type](parameters)
    else:
        return {"error": f"Unknown action type: {action_type}"}

def block_ip_address(params):
    ip = params.get('ip')
    if ip:
        # Add to firewall
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        return {"status": "success", "message": f"IP {ip} blocked"}
    return {"status": "error", "message": "No IP provided"}

def isolate_host(params):
    hostname = params.get('hostname')
    if hostname:
        # Disable network access
        subprocess.run(['nmcli', 'device', 'disconnect', hostname])
        return {"status": "success", "message": f"Host {hostname} isolated"}
    return {"status": "error", "message": "No hostname provided"}

def quarantine_file(params):
    filepath = params.get('filepath')
    if filepath:
        # Move file to quarantine
        subprocess.run(['mv', filepath, f'/quarantine/{filepath.replace("/", "_")}'])
        return {"status": "success", "message": f"File {filepath} quarantined"}
    return {"status": "error", "message": "No filepath provided"}

def send_notification(params):
    message = params.get('message', 'Security alert')
    # Send email or Slack notification
    return {"status": "success", "message": "Notification sent"}
```

## 📊 Monitoring and Alerting

### TheHive Dashboard Integration

#### Kibana Visualization for TheHive Cases
```json
{
  "title": "TheHive Case Management",
  "hits": 0,
  "description": "",
  "panelsJSON": "[{\"gridData\":{\"h\":15,\"i\":\"1\",\"w\":24,\"x\":0,\"y\":0},\"id\":\"case-status-distribution\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"2\",\"w\":12,\"x\":0,\"y\":15},\"id\":\"case-resolution-time\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"3\",\"w\":12,\"x\":12,\"y\":15},\"id\":\"wazuh-integration-stats\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"7.17.9\"}]",
  "optionsJSON": "{\"useMargins\":true}",
  "uiStateJSON": "{}",
  "version": 1,
  "timeRestore": false,
  "kibanaSavedObjectMeta": {
    "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
  }
}
```

### Integration Health Monitoring
```bash
# Monitor TheHive API
curl -H "Authorization: Bearer your_api_key" \
  http://localhost:9000/api/status

# Check Cortex analyzers
curl -H "Authorization: Bearer cortex_api_key" \
  http://localhost:9001/api/analyzer

# Monitor case creation rate
curl -H "Authorization: Bearer your_api_key" \
  "http://localhost:9000/api/case/_search?range=7d" | jq '.cases | length'

# Check integration logs
tail -f /var/log/thehive/application.log
tail -f /var/log/cortex/application.log
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### TheHive API Connection Issues
```bash
# Test API connectivity
curl -H "Authorization: Bearer your_api_key" \
  http://localhost:9000/api/case

# Check TheHive configuration
cat /etc/thehive/application.conf | grep -E "(secret|db|search)"

# Validate API key
curl -H "Authorization: Bearer invalid_key" \
  http://localhost:9000/api/case
# Should return 401 Unauthorized
```

#### Cortex Analyzer Problems
```bash
# List installed analyzers
curl -H "Authorization: Bearer cortex_api_key" \
  http://localhost:9001/api/analyzer | jq '.'

# Test analyzer execution
curl -X POST \
  -H "Authorization: Bearer cortex_api_key" \
  -H "Content-Type: application/json" \
  -d '{"analyzerId": "wazuh_analyzer", "data": "test_data", "dataType": "wazuh-alert"}' \
  http://localhost:9001/api/analyzer/run
```

#### Integration Script Issues
```bash
# Test Python integration script
echo '{"rule": {"id": "1001", "level": 10, "description": "Test alert"}}' | \
  python3 /var/ossec/integrations/custom-thehive.py

# Check for Python dependencies
pip3 list | grep requests

# Validate JSON parsing
python3 -c "
import json
with open('/var/ossec/logs/alerts/alerts.json', 'r') as f:
    for line in f:
        try:
            json.loads(line.strip())
            print('Valid JSON')
        except:
            print('Invalid JSON:', line.strip())
            break
"
```

### Performance Optimization
```bash
# Monitor system resources
htop
iostat -x 1 5
free -h

# Elasticsearch performance
curl -X GET "localhost:9200/_cluster/stats?pretty"

# Cassandra performance
nodetool status
nodetool tpstats
```

## 📊 Integration Testing and Validation

### Testing Checklist
```bash
□ TheHive server is running and accessible via web interface
□ Cortex is installed and configured with analyzers
□ API keys are configured and have appropriate permissions
□ Integration scripts are executable and in correct location
□ Wazuh can trigger integration scripts on alerts
□ Cases are created automatically from Wazuh alerts
□ Observables are extracted and added to cases
□ Tasks are created and assigned based on alert severity
□ Cortex analyzers process observables correctly
□ Response actions execute when triggered
□ Escalation rules work for high-severity alerts
□ Reporting and metrics are available
□ Backup and recovery procedures are tested
```

### Validation Commands
```bash
# Check recent cases from Wazuh
curl -H "Authorization: Bearer your_api_key" \
  "http://localhost:9000/api/case/_search?title=Wazuh" | jq '.'

# Test Cortex analyzer
curl -X POST \
  -H "Authorization: Bearer cortex_api_key" \
  -H "Content-Type: application/json" \
  -d '{"analyzerId": "test_analyzer", "data": "192.168.1.100", "dataType": "ip"}' \
  http://localhost:9001/api/analyzer/run

# Check integration logs
tail -f /var/ossec/logs/integrations.log

# Validate case structure
curl -H "Authorization: Bearer your_api_key" \
  http://localhost:9000/api/case/CASE_ID | jq '.'
```

## 🎯 Best Practices

### 1. Case Management
- **Structured Templates**: Use standardized case templates for different alert types
- **Evidence Collection**: Systematically collect and document all evidence
- **Timeline Maintenance**: Keep detailed chronological records of all activities
- **Collaboration**: Ensure proper team communication and task assignment

### 2. Automation Strategy
- **Workflow Definition**: Clearly define escalation and response workflows
- **Action Prioritization**: Focus automation on high-frequency, low-complexity tasks
- **Testing**: Thoroughly test automated actions before production deployment
- **Monitoring**: Monitor automated actions for effectiveness and accuracy

### 3. Integration Design
- **API-First**: Design integrations using APIs for reliability and flexibility
- **Error Handling**: Implement robust error handling and retry mechanisms
- **Rate Limiting**: Respect API rate limits and implement appropriate throttling
- **Security**: Secure all integration channels with proper authentication

### 4. Performance and Scalability
- **Resource Planning**: Ensure adequate resources for expected case load
- **Database Optimization**: Regularly maintain and optimize TheHive database
- **Caching**: Implement caching for frequently accessed data
- **Horizontal Scaling**: Plan for multiple TheHive instances as needed

## 📚 Self-Assessment Questions

1. What are the main phases of the incident response process according to NIST SP 800-61?
2. How does TheHive facilitate structured incident response and case management?
3. What are the different methods for integrating Wazuh alerts with TheHive?
4. How can Cortex be used to automate analysis of security observables?
5. What are the key considerations for designing automated response workflows?
6. How do you troubleshoot common integration issues between Wazuh and TheHive?

## 🔗 Next Steps

Now that you understand incident response integration, let's explore creating comprehensive SOC lab environments that combine all these integrations for hands-on practice.

**[← Back to Threat Intelligence Integration](./04-threat-intelligence-integration.md)** | **[Next: ELK Stack Lab →](../labs/lab-02-elk-stack-setup.md)**