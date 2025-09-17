# API Reference Guide

## Overview

This document provides comprehensive API reference information for integrating with Wazuh and related security tools. It includes endpoint specifications, authentication methods, request/response formats, and code examples.

## Wazuh API Reference

### Authentication
```bash
# Generate JWT token
TOKEN=$(curl -u wazuh:wazuh -k -X POST "https://localhost:55000/security/user/authenticate" | jq -r '.data.token')

# Use token in requests
curl -H "Authorization: Bearer $TOKEN" "https://localhost:55000/"
```

### Core Endpoints

#### Get Agents Status
```bash
GET /agents/summary/status
Authorization: Bearer <token>

Response:
{
  "data": {
    "connection": {
      "active": 5,
      "disconnected": 0,
      "never_connected": 2,
      "pending": 0,
      "total": 7
    }
  }
}
```

#### Get Alerts
```bash
GET /events?limit=10&sort=-timestamp
Authorization: Bearer <token>

Parameters:
- limit: Number of alerts to retrieve (default: 500, max: 100000)
- offset: Pagination offset
- sort: Sort field (timestamp, rule.level, etc.)
- search: Search query
```

#### Get Agent Information
```bash
GET /agents/{agent_id}
Authorization: Bearer <token>

Response:
{
  "data": {
    "id": "001",
    "name": "agent-001",
    "ip": "192.168.1.100",
    "status": "active",
    "dateAdd": "2023-01-01T00:00:00Z",
    "version": "4.4.0"
  }
}
```

## ELK Stack API Reference

### Elasticsearch APIs

#### Cluster Health
```bash
GET /_cluster/health

Response:
{
  "cluster_name": "wazuh-elk-cluster",
  "status": "green",
  "number_of_nodes": 1,
  "active_shards": 10
}
```

#### Search Wazuh Alerts
```bash
POST /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-1h"
            }
          }
        },
        {
          "term": {
            "rule.level": 12
          }
        }
      ]
    }
  },
  "size": 100,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}
```

#### Index Template Management
```bash
# Create template
PUT /_index_template/wazuh-alerts-template
{
  "index_patterns": ["wazuh-alerts-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "rule.level": { "type": "integer" }
    }
  }
}

# Get template
GET /_index_template/wazuh-alerts-template
```

### Kibana APIs

#### Saved Objects
```bash
# Get all dashboards
GET /api/saved_objects/_find?type=dashboard

# Create visualization
POST /api/saved_objects/visualization
{
  "attributes": {
    "title": "Wazuh Alert Trends",
    "visState": "...",
    "uiStateJSON": "{}",
    "description": "",
    "version": 1,
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{}"
    }
  }
}
```

## TheHive API Reference

### Authentication
```bash
# Get API key from TheHive UI (Administration > Users > API Key)

# Use in requests
curl -H "Authorization: Bearer your_api_key" \
  "http://localhost:9000/api/case"
```

### Case Management

#### Create Case
```bash
POST /api/case
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "title": "Security Incident",
  "description": "Description of the incident",
  "severity": 3,
  "startDate": 1640995200000,
  "tags": ["wazuh", "malware"],
  "customFields": {
    "source": {
      "string": "Wazuh SIEM"
    }
  }
}
```

#### Get Cases
```bash
GET /api/case?range=all&sort=-startDate
Authorization: Bearer <api_key>

Parameters:
- range: Time range (all, 1d, 7d, 30d)
- sort: Sort field with direction
- query: Search query
```

#### Add Observable
```bash
POST /api/case/{case_id}/observable
Authorization: Bearer <api_key>

{
  "dataType": "ip",
  "data": "192.168.1.100",
  "message": "Suspicious IP address",
  "tags": ["wazuh", "network"]
}
```

#### Create Task
```bash
POST /api/case/{case_id}/task
Authorization: Bearer <api_key>

{
  "title": "Investigate Alert",
  "description": "Detailed investigation steps",
  "status": "Waiting",
  "order": 1,
  "group": "default"
}
```

## MISP API Reference

### Authentication
```bash
# Get API key from MISP UI (My Profile > Auth Keys)

# Use in requests
curl -H "Authorization: your_api_key" \
  "http://localhost/events/restSearch"
```

### Event Management

#### Search Events
```bash
POST /events/restSearch
Authorization: <api_key>

{
  "value": "192.168.1.100",
  "type": "ip-src",
  "limit": 10,
  "page": 1
}
```

#### Create Event
```bash
POST /events/add
Authorization: <api_key>

{
  "Event": {
    "info": "Malware Campaign Detection",
    "threat_level_id": "2",
    "analysis": "1",
    "distribution": "1",
    "Attribute": [
      {
        "type": "ip-src",
        "category": "Network activity",
        "value": "192.168.1.100",
        "comment": "C2 Server"
      }
    ]
  }
}
```

#### Add Attribute
```bash
POST /attributes/add/{event_id}
Authorization: <api_key>

{
  "type": "domain",
  "category": "Network activity",
  "value": "malicious.example.com",
  "comment": "Malware domain"
}
```

## Cortex API Reference

### Authentication
```bash
# Get API key from Cortex UI

# Use in requests
curl -H "Authorization: Bearer cortex_api_key" \
  "http://localhost:9001/api/analyzer"
```

### Analyzer Management

#### List Analyzers
```bash
GET /api/analyzer
Authorization: Bearer <api_key>

Response:
[
  {
    "name": "VirusTotal_GetReport",
    "version": "1.0",
    "description": "Get file reputation from VirusTotal",
    "dataTypeList": ["file"]
  }
]
```

#### Run Analysis
```bash
POST /api/analyzer/run
Authorization: Bearer <api_key>

{
  "analyzerId": "VirusTotal_GetReport",
  "objectId": "observable_id",
  "objectType": "case_artifact",
  "dataType": "file"
}
```

#### Get Analysis Results
```bash
GET /api/job/{job_id}
Authorization: Bearer <api_key>

Response:
{
  "id": "job_id",
  "analyzerId": "VirusTotal_GetReport",
  "status": "Success",
  "report": {
    "summary": {
      "taxonomies": [
        {
          "level": "info",
          "namespace": "VT",
          "predicate": "detection",
          "value": "2/70"
        }
      ]
    }
  }
}
```

## VirusTotal API Reference

### Authentication
```bash
# Get API key from VirusTotal
# Use in requests
curl -H "x-apikey: your_api_key" \
  "https://www.virustotal.com/api/v3/files/{hash}"
```

### File Analysis

#### Get File Report
```bash
GET /api/v3/files/{hash}
x-apikey: <api_key>

Response:
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "harmless": 50,
        "malicious": 20,
        "suspicious": 2,
        "undetected": 28
      },
      "names": ["malware.exe"],
      "size": 102400
    }
  }
}
```

#### Upload File
```bash
POST /api/v3/files
x-apikey: <api_key>
Content-Type: multipart/form-data

# File upload with form data
```

#### URL Analysis
```bash
POST /api/v3/urls
x-apikey: <api_key>

{
  "url": "http://suspicious.example.com"
}

# Get analysis results
GET /api/v3/analyses/{analysis_id}
```

## Integration Code Examples

### Python Integration Classes

#### Wazuh API Client
```python
import requests
import json

class WazuhAPI:
    def __init__(self, url, username, password):
        self.url = url
        self.session = requests.Session()
        self.token = None
        self.authenticate(username, password)

    def authenticate(self, username, password):
        auth_url = f"{self.url}/security/user/authenticate"
        response = self.session.post(auth_url, auth=(username, password), verify=False)
        self.token = response.json()['data']['token']
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})

    def get_agents(self):
        response = self.session.get(f"{self.url}/agents")
        return response.json()

    def get_alerts(self, limit=100):
        response = self.session.get(f"{self.url}/events?limit={limit}")
        return response.json()
```

#### TheHive API Client
```python
import requests

class TheHiveAPI:
    def __init__(self, url, api_key):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })

    def create_case(self, case_data):
        response = self.session.post(f"{self.url}/api/case", json=case_data)
        return response.json()

    def add_observable(self, case_id, observable_data):
        response = self.session.post(
            f"{self.url}/api/case/{case_id}/observable",
            json=observable_data
        )
        return response.json()
```

### JavaScript/Node.js Examples

#### Express Webhook Handler
```javascript
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

app.post('/wazuh-webhook', async (req, res) => {
  try {
    const alert = req.body;

    // Process alert
    console.log('Received Wazuh alert:', alert.rule.description);

    // Forward to TheHive
    const caseData = {
      title: `Wazuh Alert: ${alert.rule.description}`,
      description: `Alert from agent ${alert.agent.name}`,
      severity: Math.min(Math.floor(alert.rule.level / 3) + 1, 4),
      startDate: Date.now()
    };

    const response = await axios.post('http://localhost:9000/api/case', caseData, {
      headers: {
        'Authorization': `Bearer ${process.env.THEHIVE_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    res.status(200).json({ success: true, caseId: response.data._id });
  } catch (error) {
    console.error('Webhook error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Webhook server listening on port 3000');
});
```

## Error Handling

### Common HTTP Status Codes
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### Retry Logic
```python
import time
import requests
from requests.exceptions import RequestException

def api_call_with_retry(url, max_retries=3, backoff_factor=2):
    for attempt in range(max_retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(backoff_factor ** attempt)
```

## Rate Limiting

### Rate Limit Headers
```bash
# Check rate limit status
curl -I "https://api.example.com/endpoint"
# Response headers:
# X-RateLimit-Limit: 1000
# X-RateLimit-Remaining: 999
# X-RateLimit-Reset: 1640995200
```

### Rate Limiting Implementation
```python
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, requests_per_minute=60):
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)

    def is_allowed(self, client_id):
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > minute_ago
        ]

        if len(self.requests[client_id]) < self.requests_per_minute:
            self.requests[client_id].append(now)
            return True
        return False
```

This API reference guide provides the essential information needed to integrate with Wazuh and related security tools effectively.