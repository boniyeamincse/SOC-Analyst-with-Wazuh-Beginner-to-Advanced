# Integration Architectures

## Overview

This document provides comprehensive integration architecture patterns for connecting Wazuh with various security tools and platforms, including best practices, design considerations, and implementation guidelines.

## Core Integration Patterns

### 1. Direct API Integration
```
┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  TARGET     │
│   SERVER    │    │   SYSTEM    │
│ • REST API  │    │ • API       │
│ • Webhooks  │    │   Endpoint  │
│ • JSON      │    │ • Processing│
└─────────────┘    └─────────────┘
```

**Characteristics:**
- Direct communication between systems
- Real-time data exchange
- Low latency
- Requires API authentication
- Best for immediate actions

**Implementation Example:**
```python
import requests

def send_to_target_system(alert_data):
    headers = {'Authorization': 'Bearer token'}
    response = requests.post('https://target-system/api/alerts',
                           json=alert_data, headers=headers)
    return response.status_code == 201
```

### 2. Message Queue Integration
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  MESSAGE    │───▶│  TARGET     │
│   SERVER    │    │   QUEUE     │    │   SYSTEM    │
│ • Publisher │    │ • Buffer    │    │ • Consumer  │
│ • Async     │    │ • Reliable  │    │ • Processing│
└─────────────┘    └─────────────┘    └─────────────┘
```

**Characteristics:**
- Asynchronous communication
- High reliability
- Load balancing
- Message persistence
- Decoupling of systems

### 3. Log File Integration
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  LOG FILE   │───▶│  LOG       │
│   SERVER    │    │             │    │  SHIPPER   │
│ • File      │    │ • JSON      │    │ • Parser   │
│   output    │    │   format    │    │ • Forwarder│
└─────────────┘    └─────────────┘    └─────────────┘
```

**Characteristics:**
- File-based data exchange
- High volume processing
- Batch processing
- Simple implementation
- Good for historical data

## ELK Stack Integration Architecture

### Data Flow Pattern
```
Wazuh Agents → Wazuh Server → Filebeat → Logstash → Elasticsearch → Kibana
     ↓             ↓            ↓          ↓            ↓          ↓
  Raw Events   Alert Rules   Collection  Processing   Indexing   Visualization
```

### Configuration Template
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/ossec/logs/alerts/alerts.json
  fields:
    type: wazuh-alerts

output.logstash:
  hosts: ["localhost:5044"]
```

## Threat Intelligence Integration

### MISP Integration Pattern
```
Wazuh Alert → Enrichment Script → MISP API → IOC Database
     ↓              ↓               ↓          ↓
   Trigger     Extract IOCs     Search DB   Retrieve Context
```

### VirusTotal Integration Pattern
```
File Hash/URL → VT API → Analysis Report → Wazuh Alert Enrichment
     ↓           ↓        ↓              ↓
  Extract     Query    Parse Results   Add Context
```

### STIX/TAXII Integration
```
Threat Feed → TAXII Server → STIX Parser → Indicator Database
     ↓           ↓             ↓             ↓
   Subscribe   Poll Data    Parse STIX    Store IOCs
```

## Incident Response Integration

### TheHive Case Management
```
Wazuh Alert → Case Creation → Task Assignment → Observable Analysis
     ↓            ↓              ↓              ↓
   Trigger     Auto Case     Assign Tasks    Cortex Analysis
```

### Cortex Analysis Workflow
```
Observable → Analyzer Selection → Analysis Execution → Result Processing
     ↓              ↓                ↓               ↓
   Identify    Choose Tool      Run Analysis     Store Results
```

## Network Security Integration

### Suricata Integration Pattern
```
Network Traffic → Suricata IDS → Alert Logs → Wazuh Parser → Correlation
     ↓               ↓             ↓            ↓           ↓
   Capture       Detect      Generate     Parse       Create
   packets     signatures     alerts       events     incidents
```

### Zeek Integration Pattern
```
Network → Zeek Sensors → Log Files → Filebeat → Logstash → Elasticsearch
   ↓          ↓            ↓          ↓          ↓          ↓
Monitor   Analyze     Generate   Collect    Process    Index
traffic   protocols    logs      logs       data      data
```

## Automation and Orchestration

### Workflow Automation Pattern
```
Trigger Event → Condition Check → Action Execution → Result Verification
     ↓               ↓               ↓               ↓
   Alert/IOC    Evaluate     Execute       Check
   Detection    Rules        Response     Success
```

### Multi-Tool Orchestration
```
Primary Tool → Orchestrator → Secondary Tools → Result Aggregation
     ↓             ↓               ↓               ↓
  Generate      Route        Execute        Combine
  event        to tools      actions       results
```

## Security Considerations

### Authentication Patterns
```yaml
# API Key Authentication
auth:
  type: api_key
  header: X-API-Key
  value: your_secure_api_key

# OAuth2 Authentication
auth:
  type: oauth2
  token_url: https://auth.example.com/token
  client_id: your_client_id
  client_secret: your_client_secret
```

### Encryption in Transit
```yaml
# TLS Configuration
tls:
  enabled: true
  ca_file: /path/to/ca.crt
  cert_file: /path/to/client.crt
  key_file: /path/to/client.key
  verify_mode: full
```

### Data Sanitization
```python
def sanitize_alert_data(alert):
    # Remove sensitive information
    sensitive_fields = ['password', 'api_key', 'token']
    for field in sensitive_fields:
        if field in alert:
            alert[field] = '[REDACTED]'
    return alert
```

## Monitoring and Logging

### Integration Health Monitoring
```bash
# Health check script
#!/bin/bash
check_service() {
    if curl -f -s "$1" > /dev/null; then
        echo "✓ $2 is healthy"
    else
        echo "✗ $2 is unhealthy"
    fi
}

check_service "http://localhost:9200/_cluster/health" "Elasticsearch"
check_service "http://localhost:9000/api/status" "TheHive"
```

### Performance Monitoring
```python
import time
import psutil

def monitor_performance():
    metrics = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_connections': len(psutil.net_connections())
    }
    return metrics
```

## Scalability Patterns

### Horizontal Scaling
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   LOAD      │───▶│  LOAD       │───▶│   TARGET    │
│  BALANCER   │    │ BALANCER    │    │   SYSTEMS   │
│             │    │ (Nginx)     │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                     │
                                     ▼
                         ┌─────────────────────┐
                         │   SHARED STORAGE    │
                         │   (Database/Queue)  │
                         └─────────────────────┘
```

### Data Partitioning
```sql
-- Database partitioning example
CREATE TABLE wazuh_alerts (
    id SERIAL,
    agent_id VARCHAR(100),
    timestamp TIMESTAMP,
    alert_data JSONB
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions
CREATE TABLE wazuh_alerts_2024_01 PARTITION OF wazuh_alerts
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

## Best Practices

### 1. Error Handling
```python
def robust_integration():
    try:
        # Main integration logic
        result = perform_integration()
        return result
    except ConnectionError:
        # Retry with exponential backoff
        time.sleep(2 ** retry_count)
        retry_count += 1
    except AuthenticationError:
        # Refresh authentication token
        refresh_token()
    except Exception as e:
        # Log error and alert administrators
        log_error(e)
        send_admin_alert(e)
```

### 2. Data Validation
```python
def validate_alert_data(alert):
    required_fields = ['timestamp', 'rule', 'agent']
    for field in required_fields:
        if field not in alert:
            raise ValueError(f"Missing required field: {field}")

    if not isinstance(alert.get('rule', {}).get('level'), int):
        raise ValueError("Rule level must be integer")

    return True
```

### 3. Rate Limiting
```python
from collections import defaultdict
import time

class RateLimiter:
    def __init__(self, max_calls, time_window):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = defaultdict(list)

    def is_allowed(self, key):
        now = time.time()
        self.calls[key] = [t for t in self.calls[key] if now - t < self.time_window]

        if len(self.calls[key]) < self.max_calls:
            self.calls[key].append(now)
            return True
        return False
```

## Troubleshooting Common Issues

### Connection Problems
```bash
# Test connectivity
telnet target_host target_port

# Check firewall rules
iptables -L -n | grep target_port

# Verify service status
systemctl status target_service
```

### Data Format Issues
```bash
# Validate JSON format
python3 -c "import json; json.load(open('alert.json'))"

# Check encoding
file -bi alert.json

# Test parsing
python3 -c "import json; print(json.dumps(json.load(open('alert.json')), indent=2))"
```

### Performance Issues
```bash
# Monitor system resources
top -b -n1 | head -20

# Check network throughput
iftop -i eth0

# Monitor application logs
tail -f /var/log/application.log | grep -i error
```

This document provides the foundation for implementing robust, scalable, and secure integrations between Wazuh and various security tools and platforms.