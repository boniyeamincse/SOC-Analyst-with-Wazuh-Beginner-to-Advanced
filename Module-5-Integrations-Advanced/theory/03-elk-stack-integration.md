# ELK Stack Integration with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- ELK Stack architecture and components (Elasticsearch, Logstash, Kibana)
- Data pipeline concepts for security log aggregation
- Integration methods between Wazuh and ELK Stack
- Configuration of Logstash pipelines for Wazuh data
- Creating security dashboards in Kibana
- Performance optimization for high-volume log processing
- Troubleshooting common ELK integration issues

## 📋 What is the ELK Stack?

### Overview and History
**ELK Stack** is a powerful open-source log analytics platform that provides:
- **Elasticsearch**: Distributed search and analytics engine
- **Logstash**: Data processing pipeline for ingesting, transforming, and shipping logs
- **Kibana**: Visualization and exploration tool for log data
- **Beats**: Lightweight data shippers (including Filebeat for log collection)

### Key Features
```
┌─────────────────────────────────────────────────────────────┐
│                    ELK STACK CAPABILITIES                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   DATA      │  │   SEARCH    │  │   VISUAL    │          │
│  │ COLLECTION  │  │   & ANALYTICS│  │   DASHBOARDS│          │
│  │             │  │             │  │             │          │
│  │ • Multiple   │  │ • Full-text │  │ • Real-time │          │
│  │   sources   │  │   search    │  │   charts    │          │
│  │ • Real-time │  │ • Aggregations│  │ • Maps     │          │
│  │   ingestion │  │ • Analytics │  │ • Timelines │          │
│  │ • Filtering │  │ • Machine   │  │ • Alerts    │          │
│  │ • Enrichment│  │   Learning  │  │ • Reports   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   SCALING   │  │   SECURITY  │  │   INTEGRATION│          │
│  │   & RELIABILITY│  │   FEATURES │  │   ECOSYSTEM │          │
│  │             │  │             │  │             │          │
│  │ • Horizontal │  │ • User auth │  │ • REST API  │          │
│  │   scaling   │  │ • Encryption│  │ • Plugins   │          │
│  │ • High      │  │ • Audit     │  │ • Custom    │          │
│  │   availability│  │   logging │  │   pipelines │          │
│  │ • Fault     │  │ • RBAC      │  │ • Webhooks  │          │
│  │   tolerance │  │ • SSL/TLS   │  │ • Alerting  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ ELK Stack Architecture

### Core Components

#### 1. Elasticsearch
Distributed search and analytics engine:
- **Document Store**: JSON document storage with schema flexibility
- **Search Engine**: Full-text search with advanced query capabilities
- **Analytics Engine**: Aggregations and real-time analytics
- **Distributed Architecture**: Horizontal scaling across multiple nodes

#### 2. Logstash
Data processing pipeline:
- **Input Plugins**: Data ingestion from various sources (files, TCP, HTTP, etc.)
- **Filter Plugins**: Data transformation and enrichment
- **Output Plugins**: Data shipping to destinations (Elasticsearch, files, etc.)
- **Pipeline Configuration**: Declarative configuration for data flow

#### 3. Kibana
Visualization and management interface:
- **Dashboards**: Customizable data visualizations
- **Discover**: Interactive data exploration
- **Management**: Index patterns, saved objects, and security settings
- **Canvas**: Custom visualizations and presentations

### Data Pipeline Architecture
```
Wazuh Agents → Filebeat → Logstash → Elasticsearch → Kibana
     ↓              ↓           ↓           ↓           ↓
  Log Events    Collection   Processing   Storage   Visualization
```

## 🔧 Integration with Wazuh

### Integration Architecture

#### Filebeat Integration Method
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  FILEBEAT   │───▶│  LOGSTASH   │───▶│ ELASTICSEARCH│
│   SERVER    │    │             │    │             │    │             │
│ • Alert logs │    │ • Log       │    │ • Data      │    │ • Indexed   │
│ • Archive   │    │   collection│    │   processing│    │   data      │
│   logs      │    │ • Filtering │    │ • Enrichment│    │ • Search    │
│ • JSON      │    │ • SSL       │    │ • GeoIP     │    │ • Analytics │
│   format    │    │   transport │    │ • Parsing   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                        │
                                                        ▼
                                                 ┌─────────────┐
                                                 │   KIBANA    │
                                                 │             │
                                                 │ • Dashboards│
                                                 │ • Visualizations│
                                                 │ • Alerts     │
                                                 └─────────────┘
```

#### Direct Logstash Integration Method
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   WAZUH     │───▶│  LOGSTASH   │───▶│ ELASTICSEARCH│
│   SERVER    │    │   (Input    │    │             │
│ • TCP/UDP   │    │   Plugin)   │    │ • Direct    │
│   output    │    │ • JSON      │    │   indexing │
│ • Syslog    │    │   parsing   │    │ • No       │
│   format    │    │ • Filtering │    │   Filebeat │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Integration Benefits
- **Enhanced Analytics**: Advanced search and correlation capabilities
- **Rich Visualizations**: Comprehensive dashboards for security monitoring
- **Scalable Storage**: Distributed storage for large volumes of security data
- **Real-time Processing**: Live data ingestion and analysis
- **Historical Analysis**: Long-term retention and trend analysis
- **Alert Integration**: Automated alerting based on complex conditions

## 📋 Installation and Configuration

### Installing ELK Stack

#### Single-Node Installation (Development)
```bash
# Install Java (required for Elasticsearch and Logstash)
sudo apt update
sudo apt install openjdk-11-jdk

# Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch

# Install Logstash
sudo apt install logstash

# Install Kibana
sudo apt install kibana

# Install Filebeat
sudo apt install filebeat

# Start services
sudo systemctl enable elasticsearch
sudo systemctl enable logstash
sudo systemctl enable kibana
sudo systemctl enable filebeat
```

#### Docker Installation (Recommended for Labs)
```yaml
# docker-compose.yml
version: '3.8'
services:
  elasticsearch:
    image: elasticsearch:7.17.9
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
      - "9300:9300"

  logstash:
    image: logstash:7.17.9
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch

  kibana:
    image: kibana:7.17.9
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
```

### Basic Configuration

#### Elasticsearch Configuration
```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: wazuh-elk-cluster
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node

# Security settings (basic)
xpack.security.enabled: false  # Disable for development
```

#### Logstash Pipeline Configuration
```ruby
# /etc/logstash/conf.d/wazuh-pipeline.conf
input {
  beats {
    port => 5044
    ssl => false
  }
}

filter {
  if [type] == "wazuh-alerts" {
    json {
      source => "message"
    }

    date {
      match => ["timestamp", "ISO8601"]
      target => "@timestamp"
    }

    geoip {
      source => "data.srcip"
      target => "geoip"
    }
  }
}

output {
  if [type] == "wazuh-alerts" {
    elasticsearch {
      hosts => ["127.0.0.1:9200"]
      index => "wazuh-alerts-%{+YYYY.MM.dd}"
      document_type => "_doc"
    }
  }
}
```

#### Filebeat Configuration for Wazuh
```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
  fields:
    type: wazuh-alerts
  json.keys_under_root: true
  json.add_error_key: true

output.logstash:
  hosts: ["127.0.0.1:5044"]
```

## 🔍 Wazuh Integration Setup

### Method 1: Filebeat Integration

#### Configure Wazuh for JSON Output
```xml
<!-- /var/ossec/etc/ossec.conf -->
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
```

#### Filebeat Configuration
```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
    - /var/ossec/logs/archives/archives.json
  fields:
    type: wazuh-alerts
  json.keys_under_root: true
  json.add_error_key: true

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_cloud_metadata: ~
- add_docker_metadata: ~
- add_kubernetes_metadata: ~

output.logstash:
  hosts: ["127.0.0.1:5044"]
```

### Method 2: Direct Logstash TCP Input

#### Wazuh TCP Output Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>
```

#### Logstash TCP Input Configuration
```ruby
# /etc/logstash/conf.d/wazuh-tcp.conf
input {
  tcp {
    port => 514
    codec => json_lines
    type => "wazuh-alerts"
  }
}

filter {
  json {
    source => "message"
  }

  date {
    match => ["timestamp", "ISO8601"]
    target => "@timestamp"
  }
}

output {
  elasticsearch {
    hosts => ["127.0.0.1:9200"]
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
  }
}
```

## 📊 Kibana Dashboard Creation

### Index Pattern Configuration
```json
// Kibana Dev Tools
PUT /_index_template/wazuh-alerts-template
{
  "index_patterns": ["wazuh-alerts-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
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
            "type": "text"
          }
        }
      },
      "agent": {
        "properties": {
          "name": {
            "type": "keyword"
          },
          "ip": {
            "type": "ip"
          }
        }
      }
    }
  }
}
```

### Security Dashboard Example
```json
{
  "title": "Wazuh Security Overview",
  "hits": 0,
  "description": "",
  "panelsJSON": "[{\"gridData\":{\"h\":15,\"i\":\"1\",\"w\":24,\"x\":0,\"y\":0},\"id\":\"wazuh-alerts-trend\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"2\",\"w\":12,\"x\":0,\"y\":15},\"id\":\"top-alert-rules\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"3\",\"w\":12,\"x\":12,\"y\":15},\"id\":\"agent-status\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"7.17.9\"}]",
  "optionsJSON": "{\"useMargins\":true}",
  "uiStateJSON": "{}",
  "version": 1,
  "timeRestore": false,
  "kibanaSavedObjectMeta": {
    "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
  }
}
```

## 📈 Advanced Configuration

### Logstash Pipeline Optimization

#### Multiple Pipeline Configuration
```ruby
# /etc/logstash/pipelines.yml
- pipeline.id: wazuh-alerts
  path.config: "/etc/logstash/conf.d/wazuh-alerts.conf"
- pipeline.id: wazuh-archives
  path.config: "/etc/logstash/conf.d/wazuh-archives.conf"
- pipeline.id: system-logs
  path.config: "/etc/logstash/conf.d/system.conf"
```

#### Advanced Filtering Pipeline
```ruby
# /etc/logstash/conf.d/wazuh-advanced.conf
filter {
  if [type] == "wazuh-alerts" {
    # Parse nested JSON
    json {
      source => "message"
    }

    # Extract rule information
    mutate {
      add_field => {
        "rule_category" => "%{[rule][groups]}"
        "rule_level" => "%{[rule][level]}"
      }
    }

    # Add GeoIP information
    geoip {
      source => "[data][srcip]"
      target => "source_geo"
    }

    # DNS lookup for destination
    dns {
      reverse => "[data][dstip]"
      action => "replace"
      nameserver => ["8.8.8.8", "8.8.4.4"]
    }

    # Add threat intelligence enrichment
    http {
      url => "http://localhost:9090/api/v1/indicators/%{[data][srcip]}"
      method => "get"
      target_body => "threat_intel"
    }
  }
}
```

### Elasticsearch Performance Tuning
```yaml
# /etc/elasticsearch/elasticsearch.yml
# Memory settings
bootstrap.memory_lock: true

# Indexing performance
index.refresh_interval: 30s
index.merge.scheduler.max_thread_count: 1

# Search performance
search.max_open_scroll_context: 5000

# Circuit breaker settings
indices.breaker.total.limit: 70%
```

## 🚨 Monitoring and Alerting

### Kibana Alert Configuration
```json
{
  "name": "High Severity Wazuh Alerts",
  "alertTypeId": ".index-threshold",
  "params": {
    "index": ["wazuh-alerts-*"],
    "timeField": "@timestamp",
    "aggType": "count",
    "aggField": "rule.level",
    "groupBy": "top",
    "termSize": 10,
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "thresholdComparator": ">",
    "threshold": [12]
  },
  "schedule": {
    "interval": "1m"
  },
  "actions": [
    {
      "actionTypeId": ".email",
      "params": {
        "to": ["soc@company.com"],
        "subject": "High Severity Security Alert",
        "body": "Multiple high-severity alerts detected in Wazuh"
      }
    }
  ]
}
```

### Integration Health Monitoring
```bash
# Monitor Elasticsearch cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check Logstash pipeline status
curl -X GET "localhost:9600/_node/stats/pipelines?pretty"

# Monitor Filebeat status
curl -X GET "localhost:5066/stats?pretty"

# Elasticsearch index statistics
curl -X GET "localhost:9200/_cat/indices/wazuh-*?v"
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Elasticsearch JVM Memory Errors
```bash
# Check memory usage
curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"

# Adjust JVM settings
# /etc/elasticsearch/jvm.options
-Xms2g
-Xmx2g

# Restart Elasticsearch
sudo systemctl restart elasticsearch
```

#### Issue 2: Logstash Pipeline Errors
```bash
# Check pipeline configuration
sudo -u logstash /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

# View Logstash logs
tail -f /var/log/logstash/logstash-plain.log

# Test pipeline with sample data
echo '{"message": "test alert", "timestamp": "2023-01-01T00:00:00Z"}' | \
  nc localhost 5044
```

#### Issue 3: Kibana Index Pattern Issues
```bash
# Refresh index pattern
curl -X POST "localhost:5601/api/saved_objects/index-pattern/wazuh-alerts-*/_refresh"

# Rebuild index pattern
DELETE /_index_template/wazuh-alerts-template
PUT /_index_template/wazuh-alerts-template
{
  "index_patterns": ["wazuh-alerts-*"],
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "rule": { "type": "object" },
      "agent": { "type": "object" }
    }
  }
}
```

#### Issue 4: Filebeat Connection Issues
```bash
# Test Logstash connectivity
telnet localhost 5044

# Check Filebeat logs
tail -f /var/log/filebeat/filebeat

# Validate configuration
sudo filebeat test config
sudo filebeat test output
```

### Performance Monitoring
```bash
# Elasticsearch performance metrics
curl -X GET "localhost:9200/_nodes/stats?pretty"

# Logstash performance
curl -X GET "localhost:9600/_node/stats?pretty"

# System resource monitoring
iostat -x 1 5
free -h
df -h
```

## 📊 Integration Testing and Validation

### Testing Checklist
```bash
□ ELK Stack services are running and accessible
□ Filebeat is collecting Wazuh logs successfully
□ Logstash pipeline is processing data without errors
□ Elasticsearch is indexing documents correctly
□ Kibana can discover and visualize Wazuh data
□ Index patterns are configured properly
□ Dashboards are displaying data accurately
□ Alerts are triggering on test conditions
□ Data retention policies are working
□ Backup and recovery procedures are tested
```

### Validation Queries
```bash
# Check recent Wazuh alerts in Elasticsearch
curl -X GET "localhost:9200/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  },
  "size": 10
}'

# Verify data ingestion rate
curl -X GET "localhost:9200/_cat/indices/wazuh-alerts-*?v&s=index"

# Test Kibana connectivity
curl -X GET "localhost:5601/api/status"
```

## 🎯 Best Practices

### 1. Architecture Planning
- **Resource Sizing**: Plan for adequate CPU, memory, and storage based on log volume
- **Network Design**: Position ELK components for optimal data flow
- **Security Zones**: Implement proper network segmentation and access controls
- **Scalability**: Design for horizontal scaling from the beginning

### 2. Data Management
- **Index Management**: Implement proper index lifecycle management
- **Data Retention**: Configure appropriate retention policies for security data
- **Backup Strategy**: Regular backups of Elasticsearch data and configurations
- **Data Quality**: Implement data validation and cleansing pipelines

### 3. Performance Optimization
- **Elasticsearch Tuning**: Optimize JVM settings, thread pools, and cache sizes
- **Logstash Pipelines**: Use multiple pipelines for different data types
- **Indexing Strategy**: Implement proper shard and replica configuration
- **Query Optimization**: Use appropriate index patterns and field mappings

### 4. Security Considerations
- **Access Control**: Implement proper authentication and authorization
- **Encryption**: Enable TLS/SSL for all communications
- **Audit Logging**: Enable comprehensive audit logging
- **Network Security**: Implement firewalls and network segmentation

### 5. Monitoring and Maintenance
- **Health Monitoring**: Implement comprehensive monitoring of all components
- **Alert Configuration**: Set up alerts for system and performance issues
- **Regular Updates**: Keep ELK Stack components updated with latest versions
- **Capacity Planning**: Monitor resource usage and plan for scaling

## 📚 Self-Assessment Questions

1. What are the main components of the ELK Stack and their primary functions?
2. How does Filebeat integrate with Wazuh to forward security logs to Elasticsearch?
3. What are the different methods for configuring Logstash pipelines for Wazuh data?
4. How can you create effective security dashboards in Kibana for Wazuh alerts?
5. What are the key performance considerations when deploying ELK Stack for security monitoring?
6. How do you troubleshoot common integration issues between Wazuh and ELK Stack?

## 🔗 Next Steps

Now that you understand ELK Stack integration, let's explore threat intelligence integration with platforms like MISP and VirusTotal for enhanced security context.

**[← Back to Module Overview](../README.md)** | **[Next: Threat Intelligence Integration →](./04-threat-intelligence-integration.md)**