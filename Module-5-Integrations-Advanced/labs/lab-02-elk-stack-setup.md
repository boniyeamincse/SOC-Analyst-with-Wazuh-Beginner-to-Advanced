# Lab 2: ELK Stack Setup and Wazuh Integration

## 🎯 Lab Overview

This hands-on lab will guide you through setting up the ELK Stack (Elasticsearch, Logstash, Kibana) and integrating it with Wazuh for advanced security data visualization and analysis. You'll learn to configure data pipelines, create security dashboards, and implement real-time monitoring.

### 📋 Prerequisites

- **Wazuh Environment**: Working Wazuh server with at least one agent
- **System Requirements**: Ubuntu/Debian server with:
  - 8GB RAM minimum (16GB recommended)
  - 4 CPU cores minimum
  - 50GB free disk space
- **Network Access**: Internet access for package downloads
- **Basic Knowledge**: Linux administration, Wazuh fundamentals

### 🏆 Lab Objectives

By the end of this lab, you will be able to:
- Install and configure the complete ELK Stack
- Set up Logstash pipelines for Wazuh data processing
- Configure Filebeat for secure log shipping
- Create security-focused Kibana visualizations
- Implement automated alerting and reporting
- Optimize ELK Stack performance for security monitoring

### 📊 Lab Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   WAZUH SERVER  │───▶│    FILEBEAT     │───▶│   LOGSTASH      │
│   (Alerts)      │    │   (Collector)   │    │  (Processor)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │ ELASTICSEARCH   │
                    │  (Storage)      │
                    └─────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     KIBANA      │
                    │ (Visualization) │
                    └─────────────────┘
```

## 🚀 Lab Setup

### Step 1: Prepare Your Environment

#### 1.1 Update System and Install Dependencies
```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates

# Install Java (required for Elasticsearch and Logstash)
sudo apt install -y openjdk-11-jdk

# Verify Java installation
java -version
```

#### 1.2 Configure Firewall
```bash
# Allow necessary ports
sudo ufw allow 22/tcp
sudo ufw allow 9200/tcp    # Elasticsearch
sudo ufw allow 5601/tcp    # Kibana
sudo ufw allow 5044/tcp    # Logstash/Filebeat
sudo ufw --force enable

# Verify firewall status
sudo ufw status
```

### Step 2: Install Elasticsearch

#### 2.1 Add Elasticsearch Repository
```bash
# Import Elasticsearch GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

# Add Elasticsearch repository
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Update package lists
sudo apt update
```

#### 2.2 Install and Configure Elasticsearch
```bash
# Install Elasticsearch
sudo apt install -y elasticsearch

# Configure Elasticsearch memory settings
sudo tee /etc/elasticsearch/jvm.options.d/memory.options <<EOF
-Xms2g
-Xmx2g
EOF

# Configure Elasticsearch
sudo tee /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: wazuh-elk-cluster
node.name: elk-node-01
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF

# Enable and start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verify Elasticsearch is running
curl -X GET "localhost:9200/"
```

#### 2.3 Test Elasticsearch Installation
```bash
# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check node information
curl -X GET "localhost:9200/_nodes?pretty"

# Check Elasticsearch logs
sudo tail -f /var/log/elasticsearch/elasticsearch.log
```

### Step 3: Install and Configure Logstash

#### 3.1 Install Logstash
```bash
# Install Logstash
sudo apt install -y logstash

# Enable Logstash service
sudo systemctl enable logstash
```

#### 3.2 Create Wazuh Logstash Pipeline
```bash
# Create Logstash configuration directory for Wazuh
sudo mkdir -p /etc/logstash/conf.d/wazuh

# Create main Wazuh pipeline configuration
sudo tee /etc/logstash/conf.d/wazuh/wazuh-pipeline.conf <<EOF
input {
  beats {
    port => 5044
    ssl => false
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
    ssl_verify_mode => "force_peer"
  }

  # Optional: Direct TCP input for testing
  tcp {
    port => 5140
    codec => json_lines
    type => "wazuh-direct"
    tags => ["wazuh", "direct"]
  }
}

filter {
  if [type] == "wazuh-alerts" or "wazuh" in [tags] {
    # Parse Wazuh JSON alerts
    json {
      source => "message"
      remove_field => ["message"]
    }

    # Handle timestamp
    date {
      match => ["timestamp", "ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"]
      target => "@timestamp"
      timezone => "UTC"
    }

    # Extract agent information
    mutate {
      add_field => {
        "agent_name" => "%{[agent][name]}"
        "agent_ip" => "%{[agent][ip]}"
        "agent_id" => "%{[agent][id]}"
      }
    }

    # Extract rule information
    mutate {
      add_field => {
        "rule_id" => "%{[rule][id]}"
        "rule_level" => "%{[rule][level]}"
        "rule_description" => "%{[rule][description]}"
        "rule_groups" => "%{[rule][groups]}"
      }
    }

    # Add GeoIP information for source IPs
    if [data][srcip] {
      geoip {
        source => "[data][srcip]"
        target => "source_geo"
        database => "/etc/logstash/geoip/GeoLite2-City.mmdb"
      }
    }

    # Add GeoIP information for destination IPs
    if [data][dstip] {
      geoip {
        source => "[data][dstip]"
        target => "destination_geo"
        database => "/etc/logstash/geoip/GeoLite2-City.mmdb"
      }
    }

    # Classify alerts by severity
    if [rule_level] >= 15 {
      mutate { add_tag => ["critical"] }
    } else if [rule_level] >= 12 {
      mutate { add_tag => ["high"] }
    } else if [rule_level] >= 8 {
      mutate { add_tag => ["medium"] }
    } else if [rule_level] >= 5 {
      mutate { add_tag => ["low"] }
    } else {
      mutate { add_tag => ["informational"] }
    }

    # Clean up unnecessary fields
    mutate {
      remove_field => ["beat", "prospector", "input", "offset", "host"]
    }
  }
}

output {
  if [type] == "wazuh-alerts" or "wazuh" in [tags] {
    elasticsearch {
      hosts => ["127.0.0.1:9200"]
      index => "wazuh-alerts-%{+YYYY.MM.dd}"
      document_type => "_doc"
      template_name => "wazuh-alerts"
      template => "/etc/logstash/templates/wazuh-alerts-template.json"
      template_overwrite => true
    }

    # Also output to stdout for debugging
    stdout {
      codec => rubydebug
    }
  }

  # Fallback output for non-Wazuh logs
  else {
    elasticsearch {
      hosts => ["127.0.0.1:9200"]
      index => "logstash-%{+YYYY.MM.dd}"
    }
  }
}
EOF
```

#### 3.3 Create Elasticsearch Template
```bash
# Create template directory
sudo mkdir -p /etc/logstash/templates

# Create Wazuh alerts template
sudo tee /etc/logstash/templates/wazuh-alerts-template.json <<EOF
{
  "index_patterns": ["wazuh-alerts-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "30s"
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "timestamp": {
        "type": "date",
        "format": "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'||yyyy-MM-dd'T'HH:mm:ss'Z'||ISO8601"
      },
      "rule": {
        "properties": {
          "id": {
            "type": "keyword"
          },
          "level": {
            "type": "integer"
          },
          "description": {
            "type": "text",
            "analyzer": "english"
          },
          "groups": {
            "type": "keyword"
          }
        }
      },
      "agent": {
        "properties": {
          "id": {
            "type": "keyword"
          },
          "name": {
            "type": "keyword"
          },
          "ip": {
            "type": "ip"
          }
        }
      },
      "data": {
        "properties": {
          "srcip": {
            "type": "ip"
          },
          "dstip": {
            "type": "ip"
          },
          "srcport": {
            "type": "integer"
          },
          "dstport": {
            "type": "integer"
          },
          "filename": {
            "type": "keyword"
          },
          "md5": {
            "type": "keyword"
          },
          "sha1": {
            "type": "keyword"
          },
          "sha256": {
            "type": "keyword"
          }
        }
      },
      "source_geo": {
        "properties": {
          "country_name": { "type": "keyword" },
          "city_name": { "type": "keyword" },
          "location": { "type": "geo_point" }
        }
      },
      "destination_geo": {
        "properties": {
          "country_name": { "type": "keyword" },
          "city_name": { "type": "keyword" },
          "location": { "type": "geo_point" }
        }
      },
      "agent_name": { "type": "keyword" },
      "agent_ip": { "type": "ip" },
      "agent_id": { "type": "keyword" },
      "rule_id": { "type": "keyword" },
      "rule_level": { "type": "integer" },
      "rule_description": { "type": "text", "analyzer": "english" },
      "rule_groups": { "type": "keyword" },
      "tags": { "type": "keyword" }
    }
  }
}
EOF
```

#### 3.4 Start Logstash
```bash
# Start Logstash service
sudo systemctl start logstash

# Check Logstash status
sudo systemctl status logstash

# Monitor Logstash logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

### Step 4: Install and Configure Filebeat

#### 4.1 Install Filebeat
```bash
# Install Filebeat
sudo apt install -y filebeat

# Enable Filebeat service
sudo systemctl enable filebeat
```

#### 4.2 Configure Filebeat for Wazuh
```bash
# Backup original configuration
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup

# Configure Filebeat
sudo tee /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
    - /var/ossec/logs/alerts/alerts.log
  fields:
    type: wazuh-alerts
  json.keys_under_root: true
  json.add_error_key: true
  exclude_lines: ['^{']

- type: log
  enabled: true
  paths:
    - /var/ossec/logs/archives/archives.json
  fields:
    type: wazuh-archives
  json.keys_under_root: true
  json.add_error_key: true

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_cloud_metadata: ~
- add_docker_metadata: ~

output.logstash:
  hosts: ["127.0.0.1:5044"]
  loadbalance: true
  worker: 1

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

monitoring.enabled: true
EOF
```

#### 4.3 Start Filebeat
```bash
# Start Filebeat service
sudo systemctl start filebeat

# Check Filebeat status
sudo systemctl status filebeat

# Monitor Filebeat logs
sudo tail -f /var/log/filebeat/filebeat
```

### Step 5: Install and Configure Kibana

#### 5.1 Install Kibana
```bash
# Install Kibana
sudo apt install -y kibana

# Enable Kibana service
sudo systemctl enable kibana
```

#### 5.2 Configure Kibana
```bash
# Configure Kibana
sudo tee /etc/kibana/kibana.yml <<EOF
server.port: 5601
server.host: "127.0.0.1"
server.name: "wazuh-kibana"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
kibana.index: ".kibana"
i18n.locale: "en"
EOF

# Start Kibana service
sudo systemctl start kibana

# Check Kibana status
sudo systemctl status kibana
```

#### 5.3 Access Kibana Web Interface
```bash
# Open Kibana in your browser
echo "Access Kibana at: http://localhost:5601"

# Or if accessing remotely:
echo "Access Kibana at: http://YOUR_SERVER_IP:5601"
```

## 🔧 Integration Configuration

### Step 6: Configure Wazuh for ELK Integration

#### 6.1 Enable JSON Output in Wazuh
```bash
# On Wazuh server, enable JSON output
sudo tee -a /var/ossec/etc/ossec.conf <<EOF
<global>
  <jsonout_output>yes</jsonout_output>
</global>

<alerts>
  <log_alert_level>3</log_alert_level>
  <email_alert_level>12</email_alert_level>
</alerts>

<logging>
  <log_format>json</log_format>
</logging>
EOF

# Restart Wazuh manager
sudo systemctl restart wazuh-manager
```

#### 6.2 Verify Wazuh JSON Logs
```bash
# Check that Wazuh is generating JSON alerts
tail -f /var/ossec/logs/alerts/alerts.json

# Verify JSON format
python3 -c "
import json
with open('/var/ossec/logs/alerts/alerts.json', 'r') as f:
    for line in f:
        try:
            data = json.loads(line.strip())
            print('Valid JSON alert:', data['rule']['description'])
            break
        except json.JSONDecodeError:
            print('Invalid JSON:', line.strip())
            break
"
```

## 📊 Creating Security Dashboards

### Step 7: Kibana Index Patterns and Visualizations

#### 7.1 Create Index Pattern
```bash
# Open Kibana web interface and navigate to Management > Stack Management > Index Patterns

# Create index pattern for Wazuh alerts:
# Index pattern: wazuh-alerts-*
# Time field: @timestamp

# Alternatively, use Kibana Dev Tools:
curl -X POST "localhost:5601/api/saved_objects/index-pattern/wazuh-alerts" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d'
{
  "attributes": {
    "title": "wazuh-alerts-*",
    "timeFieldName": "@timestamp"
  }
}'
```

#### 7.2 Create Security Visualizations

##### Alert Trend Visualization
```json
{
  "title": "Wazuh Alert Trends",
  "type": "line",
  "params": {
    "type": "line",
    "grid": {
      "categoryLines": false
    },
    "categoryAxes": [
      {
        "id": "CategoryAxis-1",
        "type": "category",
        "position": "bottom",
        "show": true,
        "style": {},
        "scale": {
          "type": "linear"
        },
        "labels": {
          "show": true,
          "truncate": 100
        },
        "title": {}
      }
    ],
    "valueAxes": [
      {
        "id": "ValueAxis-1",
        "name": "LeftAxis-1",
        "type": "value",
        "position": "left",
        "show": true,
        "style": {},
        "scale": {
          "type": "linear",
          "mode": "normal"
        },
        "labels": {
          "show": true,
          "rotate": 0,
          "filter": false,
          "truncate": 100
        },
        "title": {
          "text": "Alert Count"
        }
      }
    ],
    "seriesParams": [
      {
        "show": true,
        "type": "line",
        "mode": "normal",
        "data": {
          "label": "Alert Count",
          "id": "1"
        },
        "valueAxis": "ValueAxis-1",
        "drawLinesBetweenPoints": true,
        "lineWidth": 2,
        "showCircles": true
      }
    ],
    "addTooltip": true,
    "addLegend": true,
    "legendPosition": "right",
    "times": [],
    "addTimeMarker": false,
    "defaultYExtents": false,
    "setYExtents": false,
    "yAxis": {}
  },
  "aggs": [
    {
      "id": "1",
      "enabled": true,
      "type": "count",
      "schema": "metric",
      "params": {}
    },
    {
      "id": "2",
      "enabled": true,
      "type": "date_histogram",
      "schema": "segment",
      "params": {
        "field": "@timestamp",
        "interval": "h",
        "customInterval": "2h",
        "min_doc_count": 1,
        "extended_bounds": {}
      }
    }
  ]
}
```

##### Top Alert Rules Visualization
```json
{
  "title": "Top Wazuh Alert Rules",
  "type": "pie",
  "params": {
    "type": "pie",
    "addTooltip": true,
    "addLegend": true,
    "legendPosition": "right",
    "isDonut": false
  },
  "aggs": [
    {
      "id": "1",
      "enabled": true,
      "type": "count",
      "schema": "metric",
      "params": {}
    },
    {
      "id": "2",
      "enabled": true,
      "type": "terms",
      "schema": "segment",
      "params": {
        "field": "rule_description.keyword",
        "size": 10,
        "order": "desc",
        "orderBy": "1"
      }
    }
  ]
}
```

##### Agent Status Visualization
```json
{
  "title": "Wazuh Agent Status",
  "type": "table",
  "params": {
    "perPage": 10,
    "showPartialRows": false,
    "showMetricsAtAllLevels": false,
    "sort": {
      "columnIndex": null,
      "direction": null
    },
    "showTotal": false,
    "totalFunc": "sum"
  },
  "aggs": [
    {
      "id": "1",
      "enabled": true,
      "type": "count",
      "schema": "metric",
      "params": {}
    },
    {
      "id": "2",
      "enabled": true,
      "type": "terms",
      "schema": "segment",
      "params": {
        "field": "agent_name.keyword",
        "size": 20,
        "order": "desc",
        "orderBy": "1"
      }
    }
  ]
}
```

#### 7.3 Create Security Dashboard
```json
{
  "title": "Wazuh Security Overview",
  "hits": 0,
  "description": "Comprehensive Wazuh security monitoring dashboard",
  "panelsJSON": "[{\"gridData\":{\"h\":15,\"i\":\"1\",\"w\":24,\"x\":0,\"y\":0},\"id\":\"wazuh-alert-trends\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"2\",\"w\":12,\"x\":0,\"y\":15},\"id\":\"top-alert-rules\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"3\",\"w\":12,\"x\":12,\"y\":15},\"id\":\"agent-status\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"4\",\"w\":12,\"x\":0,\"y\":30},\"id\":\"severity-distribution\",\"panelIndex\":\"4\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"5\",\"w\":12,\"x\":12,\"y\":30},\"id\":\"geo-map\",\"panelIndex\":\"5\",\"type\":\"visualization\",\"version\":\"7.17.9\"}]",
  "optionsJSON": "{\"useMargins\":true}",
  "uiStateJSON": "{}",
  "version": 1,
  "timeRestore": false,
  "kibanaSavedObjectMeta": {
    "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
  }
}
```

## 🚨 Alerting and Monitoring

### Step 8: Configure Kibana Alerts

#### 8.1 Create Index Threshold Alert
```json
{
  "name": "High Severity Wazuh Alerts",
  "alertTypeId": ".index-threshold",
  "params": {
    "index": ["wazuh-alerts-*"],
    "timeField": "@timestamp",
    "aggType": "count",
    "aggField": "rule_level",
    "groupBy": "top",
    "termSize": 10,
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "thresholdComparator": ">",
    "threshold": [12]
  },
  "consumer": "alerts",
  "schedule": {
    "interval": "1m"
  },
  "actions": [
    {
      "actionTypeId": ".email",
      "params": {
        "to": ["soc@yourcompany.com"],
        "subject": "High Severity Security Alert Detected",
        "body": "Multiple high-severity alerts detected in Wazuh monitoring system"
      }
    }
  ]
}
```

#### 8.2 Create Watcher Alert (Advanced)
```json
PUT _watcher/watch/wazuh_critical_alerts
{
  "trigger": {
    "schedule": {
      "interval": "5m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["wazuh-alerts-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-5m"
                    }
                  }
                },
                {
                  "terms": {
                    "rule_level": [13, 14, 15]
                  }
                }
              ]
            }
          },
          "size": 0,
          "aggs": {
            "alert_count": {
              "value_count": {
                "field": "rule_id"
              }
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gt": 5
      }
    }
  },
  "actions": {
    "email_admin": {
      "email": {
        "to": ["admin@yourcompany.com"],
        "subject": "Critical Wazuh Alerts Detected",
        "body": "More than 5 critical alerts detected in the last 5 minutes"
      }
    }
  }
}
```

## 🔍 Testing and Validation

### Step 9: Test the Integration

#### 9.1 Generate Test Alerts
```bash
# On Wazuh agent, generate test alerts
sudo touch /var/log/auth.log
echo "Test alert generation" | sudo tee -a /var/log/auth.log

# Or use Wazuh test rule
sudo /var/ossec/bin/ossec-control restart

# Check Wazuh alerts
tail -f /var/ossec/logs/alerts/alerts.json
```

#### 9.2 Verify Data Flow
```bash
# Check Filebeat is reading logs
sudo filebeat test config

# Test Filebeat to Logstash connection
telnet localhost 5044

# Check Logstash processing
curl -XGET 'localhost:9600/_node/stats?pretty'

# Verify Elasticsearch indexing
curl -XGET 'localhost:9200/_cat/indices/wazuh-alerts-*?v'

# Check Kibana discovery
curl -XGET 'localhost:9200/wazuh-alerts-*/_search?size=5&pretty'
```

#### 9.3 Validate Dashboard Data
```bash
# Query recent alerts in Elasticsearch
curl -XGET 'localhost:9200/wazuh-alerts-*/_search' \
  -H 'Content-Type: application/json' \
  -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  },
  "size": 10,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}'
```

## 📈 Performance Optimization

### Step 10: Optimize ELK Stack Performance

#### 10.1 Elasticsearch Tuning
```bash
# Update Elasticsearch configuration for better performance
sudo tee -a /etc/elasticsearch/elasticsearch.yml <<EOF
# Performance settings
indices.memory.index_buffer_size: 10%
indices.queries.cache.size: 10%
search.max_open_scroll_context: 5000

# Circuit breaker settings
indices.breaker.total.limit: 70%
indices.breaker.fielddata.limit: 40%
EOF

# Restart Elasticsearch
sudo systemctl restart elasticsearch
```

#### 10.2 Logstash Optimization
```bash
# Configure Logstash pipeline workers
sudo tee -a /etc/logstash/logstash.yml <<EOF
pipeline.workers: 4
pipeline.batch.size: 125
pipeline.batch.delay: 5
EOF

# Restart Logstash
sudo systemctl restart logstash
```

#### 10.3 Monitoring Performance
```bash
# Monitor Elasticsearch performance
curl -XGET 'localhost:9200/_nodes/stats?pretty'

# Monitor Logstash performance
curl -XGET 'localhost:9600/_node/stats?pretty'

# Monitor system resources
htop
df -h
free -h
```

## 🧪 Lab Exercises

### Exercise 1: Custom Security Dashboard
**Objective**: Create a specialized dashboard for monitoring authentication failures

**Steps**:
1. Create visualizations for failed login attempts
2. Add geographic mapping for suspicious login locations
3. Configure alerts for brute force attack patterns
4. Add agent-specific filtering

### Exercise 2: Logstash Pipeline Enhancement
**Objective**: Enhance Logstash pipeline with custom parsing and enrichment

**Steps**:
1. Add custom grok patterns for specific log formats
2. Implement DNS lookup enrichment for IP addresses
3. Add threat intelligence enrichment
4. Create conditional routing based on alert severity

### Exercise 3: Alert Correlation
**Objective**: Implement multi-source alert correlation

**Steps**:
1. Configure correlation rules in Elasticsearch
2. Create Kibana visualizations for correlated events
3. Set up automated responses for correlated alerts
4. Test correlation with simulated attacks

## 🏁 Lab Completion Checklist

- [ ] ELK Stack components installed and running
- [ ] Filebeat configured and shipping Wazuh logs
- [ ] Logstash pipeline processing data correctly
- [ ] Elasticsearch indexing Wazuh alerts
- [ ] Kibana index patterns configured
- [ ] Security visualizations created
- [ ] Dashboard displaying Wazuh data
- [ ] Alerting configured and tested
- [ ] Performance optimized
- [ ] Integration tested with sample alerts
- [ ] Documentation updated with configuration details

## 🔧 Troubleshooting

### Common Issues and Solutions

**Filebeat not shipping logs**:
```bash
# Check Filebeat status
sudo systemctl status filebeat

# Test configuration
sudo filebeat test config
sudo filebeat test output

# Check permissions
ls -la /var/ossec/logs/alerts/
```

**Logstash pipeline errors**:
```bash
# Check pipeline configuration
sudo -u logstash /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

# View detailed logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

**Elasticsearch indexing issues**:
```bash
# Check cluster health
curl -XGET 'localhost:9200/_cluster/health?pretty'

# Check index status
curl -XGET 'localhost:9200/_cat/indices?v'
```

**Kibana connection problems**:
```bash
# Check Kibana logs
sudo tail -f /var/log/kibana/kibana.log

# Verify Elasticsearch connection
curl -XGET 'localhost:5601/api/status'
```

## 📚 Additional Resources

- [ELK Stack Documentation](https://www.elastic.co/guide/index.html)
- [Wazuh ELK Integration Guide](https://documentation.wazuh.com/current/integrations/elastic.html)
- [Filebeat Configuration Reference](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-reference-yml.html)
- [Logstash Pipeline Patterns](https://www.elastic.co/guide/en/logstash/current/pipeline.html)

## 🎯 Next Steps

With your ELK Stack integration complete, proceed to the next lab to integrate MISP for threat intelligence sharing with Wazuh.

**[← Back to ELK Stack Theory](../theory/03-elk-stack-integration.md)** | **[Next: MISP Integration Lab →](./lab-03-misp-integration.md)**