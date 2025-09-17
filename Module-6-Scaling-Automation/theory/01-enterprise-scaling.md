# Enterprise SOC Scaling with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Enterprise SOC architecture design principles
- Multi-node Wazuh cluster deployment strategies
- Load balancing and performance optimization
- Enterprise integration challenges and solutions
- Scaling considerations for large organizations
- Resource planning and capacity management

## 📋 Enterprise SOC Architecture

### Scaling Challenges

#### Traditional SOC Limitations
```
┌─────────────────────────────────────────────────────────────┐
│                TRADITIONAL SOC LIMITATIONS                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ SINGLE      │  │ LIMITED     │  │ MANUAL      │          │
│  │ POINT OF    │  │ SCALABILITY │  │ MANAGEMENT  │          │
│  │ FAILURE     │  │             │  │             │          │
│  │             │  │ • Fixed      │  │ • Labor      │          │
│  │ • Downtime  │  │   capacity  │  │   intensive  │          │
│  │ • Data loss │  │ • Performance│  │ • Error prone│          │
│  │ • Recovery  │  │   bottlenecks│  │ • Slow       │          │
│  │   complex   │  │ • Resource   │  │   response   │          │
│  │             │  │   waste      │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ COMPLIANCE  │  │ INTEGRATION │  │ COST        │          │
│  │ ISSUES      │  │ CHALLENGES  │  │ OVERRUNS    │          │
│  │             │  │             │  │             │          │
│  │ • Audit      │  │ • Legacy     │  │ • Hardware   │          │
│  │   failures  │  │   systems    │  │   expensive  │          │
│  │ • Reporting  │  │ • API        │  │ • Maintenance│          │
│  │   delays    │  │   complexity │  │   costs      │          │
│  │ • Regulatory │  │ • Custom     │  │ • Training    │          │
│  │   penalties │  │   interfaces │  │   costs      │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

#### Enterprise Requirements
- **High Availability**: 99.9%+ uptime requirements
- **Scalability**: Handle thousands of endpoints and massive data volumes
- **Performance**: Sub-second response times for critical alerts
- **Compliance**: Meet strict regulatory requirements
- **Integration**: Connect with existing enterprise systems
- **Automation**: Reduce manual intervention and human error

## 🏗️ Multi-Node Wazuh Architecture

### Distributed Architecture Components

#### Wazuh Manager Cluster
```
┌─────────────────┐    ┌─────────────────┐
│   MASTER NODE   │    │   WORKER NODE   │
│                 │    │                 │
│ • API Service   │    │ • Log Analysis  │
│ • Configuration │    │ • Rule Engine   │
│ • Agent Mgmt    │    │ • Alert Gen     │
│ • Cluster Coord │    │ • Data Process  │
└─────────────────┘    └─────────────────┘
      │                        │
      └──────────┬─────────────┘
                 │
        ┌─────────────────┐
        │   LOAD BALANCER │
        │                 │
        │ • Agent Traffic │
        │ • API Requests  │
        │ • Health Checks │
        └─────────────────┘
```

#### Indexer Cluster (Elasticsearch/OpenSearch)
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MASTER NODE   │    │   DATA NODE     │    │   DATA NODE     │
│                 │    │                 │    │                 │
│ • Cluster Mgmt  │    │ • Data Storage  │    │ • Data Storage  │
│ • Index Mgmt    │    │ • Search        │    │ • Search        │
│ • Metadata      │    │ • Analytics     │    │ • Analytics     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Dashboard Cluster
```
┌─────────────────┐    ┌─────────────────┐
│   KIBANA/       │    │   KIBANA/       │
│   OPENSEARCH    │    │   OPENSEARCH    │
│   DASHBOARDS    │    │   DASHBOARDS    │
│                 │    │                 │
│ • Visualization │    │ • Visualization │
│ • Dashboards    │    │ • Dashboards    │
│ • User Mgmt     │    │ • User Mgmt     │
└─────────────────┘    └─────────────────┘
```

### Cluster Communication Architecture

#### Internal Communication
```yaml
# Cluster configuration
cluster:
  name: wazuh-cluster
  node.name: wazuh-manager-01
  path.data: /var/ossec/data
  path.logs: /var/ossec/logs
  network.host: 0.0.0.0
  discovery.seed_hosts: ["wazuh-manager-01:9300", "wazuh-manager-02:9300"]
  cluster.initial_master_nodes: ["wazuh-manager-01"]
```

#### Load Balancing Strategy
```nginx
# Nginx load balancer configuration
upstream wazuh_managers {
    server wazuh-manager-01:55000;
    server wazuh-manager-02:55000;
    server wazuh-manager-03:55000;
}

server {
    listen 80;
    location / {
        proxy_pass http://wazuh_managers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 Capacity Planning

### Resource Requirements Assessment

#### Agent Count Planning
```bash
# Calculate based on agent types and activity levels
LOW_ACTIVITY_AGENTS=1000     # 1 event/minute = 1.44K events/day
MEDIUM_ACTIVITY_AGENTS=500   # 5 events/minute = 7.2K events/day
HIGH_ACTIVITY_AGENTS=100     # 20 events/minute = 28.8K events/day

TOTAL_DAILY_EVENTS=$((LOW_ACTIVITY_AGENTS * 1440 + MEDIUM_ACTIVITY_AGENTS * 7200 + HIGH_ACTIVITY_AGENTS * 28800))
echo "Total daily events: $TOTAL_DAILY_EVENTS"
```

#### Hardware Sizing Guidelines
```bash
# Wazuh Manager Node Requirements
MANAGER_CPU_CORES=8          # Minimum for production
MANAGER_MEMORY_GB=16         # Minimum for production
MANAGER_STORAGE_GB=100       # Base + logs retention

# Indexer Node Requirements
INDEXER_CPU_CORES=16         # For high-volume environments
INDEXER_MEMORY_GB=64         # For optimal performance
INDEXER_STORAGE_TB=2         # Based on retention requirements

# Dashboard Node Requirements
DASHBOARD_CPU_CORES=4        # For user load
DASHBOARD_MEMORY_GB=8        # For dashboard rendering
DASHBOARD_STORAGE_GB=50      # For configurations
```

### Performance Benchmarking

#### EPS (Events Per Second) Calculations
```bash
# Performance metrics calculation
EVENTS_PER_SECOND=1000       # Target EPS
PEAK_MULTIPLIER=3           # Peak load multiplier
HOURS_PER_DAY=24            # Daily operation

DAILY_EVENTS=$((EVENTS_PER_SECOND * 3600 * HOURS_PER_DAY * PEAK_MULTIPLIER))
echo "Daily events capacity: $DAILY_EVENTS"
```

#### Storage Planning
```bash
# Storage calculation
AVG_EVENT_SIZE_KB=2         # Average event size
RETENTION_DAYS=90           # Data retention period
COMPRESSION_RATIO=0.3       # Compression savings

RAW_STORAGE_TB=$(echo "scale=2; $DAILY_EVENTS * $AVG_EVENT_SIZE_KB * $RETENTION_DAYS / 1024 / 1024 / 1024" | bc)
ACTUAL_STORAGE_TB=$(echo "scale=2; $RAW_STORAGE_TB * (1 - $COMPRESSION_RATIO)" | bc)
echo "Required storage: $ACTUAL_STORAGE_TB TB"
```

## 🚀 Multi-Node Cluster Deployment

### Cluster Prerequisites

#### System Requirements
```bash
# All cluster nodes must have:
├── Consistent OS versions (Ubuntu 22.04 LTS recommended)
├── NTP synchronization
├── DNS resolution configured
├── Firewall rules for cluster communication
├── SSH key-based authentication
└── sudo privileges for installation
```

#### Network Requirements
```bash
# Required ports between cluster nodes:
├── TCP 1516: Wazuh cluster communication
├── TCP 9200: Elasticsearch REST API
├── TCP 9300: Elasticsearch node communication
├── TCP 5601: Kibana web interface
└── TCP 55000: Wazuh API
```

### Step-by-Step Cluster Deployment

#### Step 1: Base Installation
```bash
# Install Wazuh on all manager nodes
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

#### Step 2: Configure First Master Node
```bash
# Stop Wazuh service
sudo systemctl stop wazuh-manager

# Configure as master
sudo sed -i 's/<node_type>master</<node_type>master</g' /var/ossec/etc/ossec.conf
sudo sed -i 's/<node_name>node01</<node_name>wazuh-manager-01</g' /var/ossec/etc/ossec.conf

# Configure cluster settings
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF
<cluster>
  <name>wazuh-cluster</name>
  <node_name>wazuh-manager-01</node_name>
  <node_type>master</node_type>
  <key>your_cluster_key_here</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
</cluster>
EOF
```

#### Step 3: Configure Worker Nodes
```bash
# Stop Wazuh service
sudo systemctl stop wazuh-manager

# Configure as worker
sudo sed -i 's/<node_type>master</<node_type>worker</g' /var/ossec/etc/ossec.conf
sudo sed -i 's/<node_name>node01</<node_name>wazuh-worker-01</g' /var/ossec/etc/ossec.conf

# Configure cluster settings
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF
<cluster>
  <name>wazuh-cluster</name>
  <node_name>wazuh-worker-01</node_name>
  <node_type>worker</node_type>
  <key>your_cluster_key_here</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>wazuh-manager-01</node>
  </nodes>
</cluster>
EOF
```

#### Step 4: Start Cluster Services
```bash
# Start services in order: master first, then workers
# On master node:
sudo systemctl start wazuh-manager

# On worker nodes:
sudo systemctl start wazuh-manager

# Verify cluster status
sudo /var/ossec/bin/cluster_control -l
```

### Indexer Cluster Configuration

#### Elasticsearch Cluster Setup
```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: wazuh-elasticsearch
node.name: elasticsearch-01
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200

# Discovery settings
discovery.seed_hosts: ["elasticsearch-01:9300", "elasticsearch-02:9300"]
cluster.initial_master_nodes: ["elasticsearch-01"]

# Security settings
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
```

#### Filebeat Configuration for Cluster
```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/ossec/logs/alerts/alerts.json
  json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch-01:9200", "elasticsearch-02:9200"]
  protocol: "https"
  username: "elastic"
  password: "your_password"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/ca.crt"]
```

## ⚖️ Load Balancing and High Availability

### Load Balancer Configuration

#### HAProxy Setup
```bash
# /etc/haproxy/haproxy.cfg
frontend wazuh_api
    bind *:55000
    mode tcp
    default_backend wazuh_managers

backend wazuh_managers
    mode tcp
    balance roundrobin
    server manager01 wazuh-manager-01:55000 check
    server manager02 wazuh-manager-02:55000 check
    server manager03 wazuh-manager-03:55000 check
```

#### Nginx Load Balancer
```nginx
# /etc/nginx/nginx.conf
upstream wazuh_cluster {
    server wazuh-manager-01:55000;
    server wazuh-manager-02:55000;
    server wazuh-manager-03:55000;
}

server {
    listen 55000;
    location / {
        proxy_pass http://wazuh_cluster;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Failover Configuration

#### Automatic Failover Script
```bash
#!/bin/bash
# Cluster health monitoring and failover script

CLUSTER_STATUS=$(curl -s -k -u admin:admin https://localhost:55000/cluster/status)
MASTER_NODE=$(echo $CLUSTER_STATUS | jq -r '.data.running_nodes[] | select(.type=="master") | .name')

if [ -z "$MASTER_NODE" ]; then
    echo "No master node found, initiating failover"
    # Promote worker to master
    /var/ossec/bin/cluster_control -p wazuh-worker-01
    systemctl restart wazuh-manager
fi
```

## 📊 Monitoring and Maintenance

### Cluster Health Monitoring

#### Health Check Script
```bash
#!/bin/bash
# Comprehensive cluster health monitoring

echo "=== WAZUH CLUSTER HEALTH CHECK ==="
echo "Date: $(date)"
echo

# Check Wazuh cluster
echo "Wazuh Cluster Status:"
/var/ossec/bin/cluster_control -l
echo

# Check Elasticsearch cluster
echo "Elasticsearch Cluster Health:"
curl -s -X GET "localhost:9200/_cluster/health?pretty"
echo

# Check Kibana
echo "Kibana Status:"
curl -s -I http://localhost:5601 | head -1
echo

# Performance metrics
echo "System Resources:"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
echo "Memory Usage: $(free | grep Mem | awk '{printf "%.2f%", $3/$2 * 100.0}')"
echo "Disk Usage: $(df / | tail -1 | awk '{print $5}')"
```

#### Automated Monitoring Setup
```bash
# Add to crontab for regular monitoring
*/5 * * * * /usr/local/bin/cluster-health-check.sh >> /var/log/cluster-monitoring.log 2>&1

# Alert configuration
*/10 * * * * /usr/local/bin/cluster-alert-check.sh
```

### Backup and Recovery

#### Cluster Backup Strategy
```bash
#!/bin/bash
# Cluster backup script

BACKUP_DIR="/backup/wazuh-cluster"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/$TIMESTAMP

# Backup Wazuh configurations
cp -r /var/ossec/etc $BACKUP_DIR/$TIMESTAMP/wazuh-config
cp -r /var/ossec/rules $BACKUP_DIR/$TIMESTAMP/wazuh-rules

# Backup Elasticsearch data
curl -X PUT "localhost:9200/_snapshot/cluster_backup/$TIMESTAMP?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": "wazuh-alerts-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'
```

#### Recovery Procedures
```bash
#!/bin/bash
# Cluster recovery script

BACKUP_TIMESTAMP="20231201_120000"
BACKUP_DIR="/backup/wazuh-cluster/$BACKUP_TIMESTAMP"

# Stop services
systemctl stop wazuh-manager elasticsearch kibana

# Restore configurations
cp -r $BACKUP_DIR/wazuh-config/* /var/ossec/etc/
cp -r $BACKUP_DIR/wazuh-rules/* /var/ossec/rules/

# Restore data
curl -X POST "localhost:9200/_snapshot/cluster_backup/$BACKUP_TIMESTAMP/_restore" \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": "wazuh-alerts-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'

# Start services
systemctl start elasticsearch
systemctl start wazuh-manager
systemctl start kibana
```

## 🔧 Performance Optimization

### Wazuh Manager Optimization

#### Configuration Tuning
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <memory_size>1024</memory_size>
    <white_list>127.0.0.1</white_list>
  </global>

  <logging>
    <log_format>json</log_format>
  </logging>
</ossec_config>
```

#### Rule Optimization
```bash
# Analyze rule performance
/var/ossec/bin/ossec-logtest -f /var/ossec/rules/local_rules.xml

# Optimize frequently triggered rules
# Move high-frequency rules to top of rule file
# Use more specific match patterns
# Implement rule filtering for noisy sources
```

### Indexer Performance Tuning

#### Elasticsearch Configuration
```yaml
# /etc/elasticsearch/elasticsearch.yml
indices.query.bool.max_clause_count: 1024
indices.memory.index_buffer_size: 10%
indices.memory.min_index_buffer_size: 96mb

# Circuit breaker settings
indices.breaker.total.limit: 70%
indices.breaker.fielddata.limit: 40%
```

#### Index Management
```bash
# Automated index management
curl -X PUT "localhost:9200/_ilm/policy/wazuh-alerts-policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "min_age": "0ms",
          "actions": {
            "rollover": {
              "max_size": "50gb",
              "max_age": "30d"
            }
          }
        },
        "warm": {
          "min_age": "30d",
          "actions": {
            "allocate": {
              "number_of_replicas": 1
            }
          }
        },
        "cold": {
          "min_age": "60d",
          "actions": {
            "allocate": {
              "number_of_replicas": 0
            }
          }
        }
      }
    }
  }'
```

## 📈 Scaling Strategies

### Horizontal Scaling

#### Adding Manager Nodes
```bash
# Add new worker node to cluster
sudo sed -i 's/<node_type>master</<node_type>worker</g' /var/ossec/etc/ossec.conf
sudo sed -i 's/<node_name>node01</<node_name>wazuh-worker-new</g' /var/ossec/etc/ossec.conf

# Update cluster configuration
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF
<cluster>
  <nodes>
    <node>wazuh-manager-01</node>
    <node>wazuh-manager-02</node>
    <node>wazuh-worker-new</node>
  </nodes>
</cluster>
EOF

sudo systemctl restart wazuh-manager
```

#### Adding Indexer Nodes
```yaml
# Update elasticsearch.yml on new node
cluster.name: wazuh-elasticsearch
node.name: elasticsearch-new
discovery.seed_hosts: ["elasticsearch-01:9300", "elasticsearch-02:9300", "elasticsearch-new:9300"]
```

### Vertical Scaling

#### Resource Optimization
```bash
# Memory tuning
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf

# File descriptor limits
echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf
```

#### Storage Optimization
```bash
# SSD optimization
echo 'deadline' | sudo tee /sys/block/sda/queue/scheduler

# RAID configuration for performance
# Use RAID 10 for optimal read/write performance
# Implement hot spare drives for redundancy
```

## 🎯 Enterprise Integration

### Existing Infrastructure Integration

#### SIEM Integration
```bash
# Export Wazuh alerts to existing SIEM
curl -X POST "https://existing-siem.company.com/api/alerts" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Wazuh",
    "alerts": '$(cat /var/ossec/logs/alerts/alerts.json)'
  }'
```

#### Ticketing System Integration
```bash
# Create tickets from Wazuh alerts
ALERT_DATA=$(cat /var/ossec/logs/alerts/alerts.json | jq '.[0]')
curl -X POST "https://ticketing.company.com/api/tickets" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"title\": \"Wazuh Alert: $(echo $ALERT_DATA | jq -r '.rule.description')\",
    \"description\": $(echo $ALERT_DATA | jq '.'),
    \"priority\": \"high\",
    \"assignee\": \"soc_team\"
  }"
```

### Compliance and Audit Integration

#### Audit Logging Enhancement
```xml
<!-- Enhanced audit logging -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/alerts/alerts.json</location>
</localfile>
```

#### Compliance Reporting Automation
```bash
#!/bin/bash
# Automated compliance report generation

REPORT_DATE=$(date +%Y%m%d)
REPORT_DIR="/var/ossec/compliance-reports"

# Generate PCI-DSS compliance report
curl -X GET "https://localhost:55000/security/pci-dss" \
  -H "Authorization: Bearer $WAZUH_API_TOKEN" \
  -o "$REPORT_DIR/pci-dss-$REPORT_DATE.json"

# Generate HIPAA compliance report
curl -X GET "https://localhost:55000/security/hipaa" \
  -H "Authorization: Bearer $WAZUH_API_TOKEN" \
  -o "$REPORT_DIR/hipaa-$REPORT_DATE.json"
```

## 📊 Self-Assessment Questions

1. What are the main components of a multi-node Wazuh cluster?
2. How does load balancing work in a Wazuh cluster environment?
3. What are the key considerations for capacity planning in enterprise SOC?
4. How do you configure high availability in a Wazuh cluster?
5. What are the best practices for monitoring cluster health and performance?

## 🔗 Next Steps

Now that you understand enterprise scaling, let's explore high availability configurations to ensure your SOC remains operational during failures.

**[← Back to Module Overview](../README.md)** | **[Next: High Availability →](./02-high-availability.md)**