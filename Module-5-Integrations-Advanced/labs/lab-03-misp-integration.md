# Lab 3: MISP Integration with Wazuh

## 🎯 Lab Overview

This hands-on lab will guide you through setting up the Malware Information Sharing Platform (MISP) and integrating it with Wazuh for automated threat intelligence sharing and enrichment. You'll learn to create threat intelligence events, configure sharing communities, and implement real-time intelligence feeds.

### 📋 Prerequisites

- **Wazuh Environment**: Working Wazuh server with agents configured
- **System Requirements**: Ubuntu/Debian server with:
  - 4GB RAM minimum (8GB recommended)
  - 2 CPU cores minimum
  - 20GB free disk space
  - Internet access for package installation
- **Basic Knowledge**: Linux administration, Wazuh rules/decoders, JSON data formats

### 🏆 Lab Objectives

By the end of this lab, you will be able to:
- Install and configure MISP platform
- Create and manage threat intelligence events
- Configure sharing communities and synchronization
- Implement automated threat intelligence feeds
- Integrate MISP with Wazuh for alert enrichment
- Create custom intelligence processing scripts
- Set up automated malware analysis workflows
- Build threat intelligence dashboards

### 📊 Lab Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   THREAT        │───▶│      MISP       │───▶│   INTELLIGENCE  │
│   SOURCES       │    │   PLATFORM      │    │   ENRICHMENT    │
│ • Feeds         │    │ • Events        │    │ • Context       │
│ • Sharing       │    │ • Attributes    │    │ • Correlation   │
│ • Manual        │    │ • Sharing       │    │ • Scoring       │
└─────────────────┘    └─────────────┬───┘    └─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────┐
                    │     WAZUH       │
                    │   INTEGRATION   │
                    │ • Alert         │
                    │   enrichment    │
                    │ • IOC matching  │
                    │ • Response      │
                    └─────────────────┘
```

## 🚀 Lab Setup

### Step 1: Prepare Your Environment

#### 1.1 Install Required Dependencies
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install basic dependencies
sudo apt install -y curl wget gnupg2 software-properties-common ca-certificates \
    python3-dev python3-pip redis-server mariadb-server mariadb-client \
    git unzip zip apache2 libapache2-mod-php php php-cli php-json php-mysql \
    php-xml php-mbstring php-zip php-curl php-gd php-intl
```

#### 1.2 Configure MySQL Database
```bash
# Secure MySQL installation
sudo mysql_secure_installation

# Create MISP database and user
sudo mysql -u root -p << EOF
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'misp_password_strong';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
EOF
```

#### 1.3 Configure PHP
```bash
# Update PHP configuration for MISP
sudo tee /etc/php/7.4/apache2/php.ini <<EOF
memory_limit = 512M
upload_max_filesize = 50M
post_max_size = 50M
max_execution_time = 300
date.timezone = UTC
EOF

# Restart Apache
sudo systemctl restart apache2
```

### Step 2: Install MISP Core

#### 2.1 Download and Install MISP
```bash
# Clone MISP repository
cd /var/www
sudo git clone https://github.com/MISP/MISP.git
sudo chown -R www-data:www-data MISP
cd MISP

# Install PHP dependencies
sudo -u www-data composer install --no-dev

# Set permissions
sudo chmod -R 750 /var/www/MISP
sudo chmod -R g+ws /var/www/MISP/app/tmp
sudo chmod -R g+ws /var/www/MISP/app/files
sudo chmod -R g+ws /var/www/MISP/app/Config
```

#### 2.2 Configure MISP Database
```bash
# Copy database configuration
sudo -u www-data cp /var/www/MISP/app/Config/database.default.php /var/www/MISP/app/Config/database.php

# Edit database configuration
sudo -u www-data tee /var/www/MISP/app/Config/database.php <<EOF
class DATABASE_CONFIG {
    public \$default = array(
        'datasource' => 'Database/Mysql',
        'persistent' => false,
        'host' => 'localhost',
        'port' => '',
        'login' => 'misp',
        'password' => 'misp_password_strong',
        'database' => 'misp',
        'encoding' => 'utf8',
    );
}
EOF
```

#### 2.3 Configure MISP Application
```bash
# Copy main configuration
sudo -u www-data cp /var/www/MISP/app/Config/config.default.php /var/www/MISP/app/Config/config.php

# Generate random salts
MISP_SALT=\$(openssl rand -base64 32)
MISP_CIPHERSEED=\$(openssl rand -base64 32)

# Configure MISP settings
sudo -u www-data tee /var/www/MISP/app/Config/config.php <<EOF
<?php
\$config = array(
    'debug' => 0,
    'Security' => array(
        'salt' => '$MISP_SALT',
        'cipherSeed' => '$MISP_CIPHERSEED',
    ),
    'MISP' => array(
        'organisation' => array(
            'name' => 'SOC Training Lab',
        ),
        'host_org_id' => 1,
        'email' => 'admin@soctlab.local',
        'disable_emailing' => true,
        'live' => true,
        'baseurl' => 'https://localhost',
    ),
);
EOF
```

#### 2.4 Initialize MISP Database
```bash
# Run database setup
sudo -u www-data /var/www/MISP/app/Console/cake user init

# Set admin password
sudo -u www-data /var/www/MISP/app/Console/cake admin setSetting "MISP.email" "admin@soctlab.local"
sudo -u www-data /var/www/MISP/app/Console/cake admin setSetting "MISP.disable_emailing" true

# Set site admin
sudo -u www-data /var/www/MISP/app/Console/cake admin setSetting "MISP.host_org_id" 1
```

### Step 3: Configure Apache Web Server

#### 3.1 Create Apache Virtual Host
```bash
# Create Apache configuration for MISP
sudo tee /etc/apache2/sites-available/misp.conf <<EOF
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/MISP/app/webroot

    <Directory /var/www/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Require all granted
    </Directory>

    LogLevel warn
    ErrorLog /var/log/apache2/misp_error.log
    CustomLog /var/log/apache2/misp_access.log combined

    ServerSignature Off
</VirtualHost>
EOF
```

#### 3.2 Enable Site and Restart Apache
```bash
# Enable MISP site
sudo a2ensite misp.conf
sudo a2dissite 000-default.conf

# Enable required Apache modules
sudo a2enmod rewrite
sudo a2enmod headers

# Restart Apache
sudo systemctl restart apache2
```

### Step 4: Install MISP Modules

#### 4.1 Install PyMISP and Dependencies
```bash
# Install Python dependencies for MISP modules
pip3 install pymisp requests

# Install MISP modules
cd /var/www/MISP
sudo -u www-data git clone https://github.com/MISP/misp-modules.git
cd misp-modules

# Install module dependencies
sudo -u www-data pip3 install -r REQUIREMENTS
sudo -u www-data pip3 install -r REQUIREMENTS.txt
```

#### 4.2 Configure MISP Modules
```bash
# Create modules configuration
sudo -u www-data tee /var/www/MISP/misp-modules/misp_modules.cfg <<EOF
[misp_modules]
plugin_folder = /var/www/MISP/misp-modules/modules
socket_timeout = 10
cache_timeout = 10
max_cache_age = 30
redis_host = localhost
redis_port = 6379
redis_database = 10
redis_password =
EOF

# Start MISP modules service
sudo -u www-data nohup python3 /var/www/MISP/misp-modules/misp-modules.py &
```

### Step 5: Access MISP Web Interface

#### 5.1 First Login Setup
```bash
# Open MISP in browser
echo "Access MISP at: http://localhost"

# Default credentials:
# Username: admin@admin.test
# Password: admin

# Change default password after first login
```

#### 5.2 Initial Configuration
```bash
# In MISP web interface, go to Administration > Server Settings

# Configure essential settings:
# - MISP.live: true
# - MISP.baseurl: http://localhost
# - MISP.org: SOC Training Lab
# - MISP.email: admin@soctlab.local

# Enable background jobs
# - SimpleBackgroundJobs.enabled: true
# - SimpleBackgroundJobs.redis_host: localhost
```

## 🔧 Wazuh MISP Integration

### Step 6: Install Wazuh Integration Scripts

#### 6.1 Create Integration Directory
```bash
# Create directory for custom integrations
sudo mkdir -p /var/ossec/integrations/custom
sudo chmod 755 /var/ossec/integrations/custom
```

#### 6.2 Create MISP Integration Script
```bash
# Create MISP enrichment script
sudo tee /var/ossec/integrations/custom/misp-enrichment.py <<'EOF'
#!/usr/bin/env python3
# MISP Threat Intelligence Integration for Wazuh

import json
import sys
import os
import requests
from datetime import datetime, timedelta

class MISPEnrichment:
    def __init__(self):
        self.misp_url = os.getenv('MISP_URL', 'http://localhost')
        self.misp_key = os.getenv('MISP_API_KEY', 'your_api_key_here')
        self.headers = {
            'Authorization': self.misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def enrich_alert(self, alert):
        """Enrich Wazuh alert with MISP threat intelligence"""
        enriched_alert = alert.copy()
        enriched_alert['misp'] = {}

        # Extract IOCs from alert
        iocs = self.extract_iocs(alert)

        if not iocs:
            enriched_alert['misp']['status'] = 'no_iocs_found'
            return enriched_alert

        # Search MISP for each IOC
        misp_matches = []
        for ioc_type, ioc_value in iocs.items():
            matches = self.search_misp(ioc_type, ioc_value)
            if matches:
                misp_matches.extend(matches)

        if misp_matches:
            enriched_alert['misp']['status'] = 'threats_found'
            enriched_alert['misp']['matches'] = misp_matches
            enriched_alert['misp']['threat_level'] = self.calculate_threat_level(misp_matches)
        else:
            enriched_alert['misp']['status'] = 'no_threats_found'

        return enriched_alert

    def extract_iocs(self, alert):
        """Extract indicators of compromise from Wazuh alert"""
        iocs = {}
        data = alert.get('data', {})

        # Extract IP addresses
        if data.get('srcip'):
            iocs['ip-src'] = data['srcip']
        if data.get('dstip'):
            iocs['ip-dst'] = data['dstip']

        # Extract domains and URLs
        if data.get('hostname'):
            iocs['domain'] = data['hostname']
        if data.get('url'):
            iocs['url'] = data['url']

        # Extract file hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            if data.get(hash_type):
                iocs['filename|' + hash_type] = data[hash_type]

        return iocs

    def search_misp(self, ioc_type, ioc_value):
        """Search MISP for specific IOC"""
        try:
            search_url = f"{self.misp_url}/attributes/restSearch"
            payload = {
                "value": ioc_value,
                "type": ioc_type,
                "limit": 10
            }

            response = requests.post(search_url, headers=self.headers, json=payload, verify=False)
            if response.status_code == 200:
                results = response.json()
                return results.get('response', {}).get('Attribute', [])
            else:
                print(f"MISP search failed: {response.status_code}")
                return []
        except Exception as e:
            print(f"MISP search error: {str(e)}")
            return []

    def calculate_threat_level(self, matches):
        """Calculate overall threat level from MISP matches"""
        if not matches:
            return 'low'

        # Get highest threat level from matching events
        threat_levels = []
        for match in matches:
            event = match.get('Event', {})
            threat_level = event.get('threat_level_id', 4)  # Default to low
            threat_levels.append(threat_level)

        max_threat = min(threat_levels)  # Lower number = higher threat in MISP

        if max_threat == 1:
            return 'critical'
        elif max_threat == 2:
            return 'high'
        elif max_threat == 3:
            return 'medium'
        else:
            return 'low'

def main():
    enrichment = MISPEnrichment()

    # Read Wazuh alert from stdin
    alert_json = sys.stdin.read()
    try:
        alert = json.loads(alert_json)
        enriched_alert = enrichment.enrich_alert(alert)
        print(json.dumps(enriched_alert))
    except json.JSONDecodeError as e:
        error_alert = {
            'error': 'Invalid JSON input',
            'message': str(e),
            'original_input': alert_json[:500]  # Limit output
        }
        print(json.dumps(error_alert))

if __name__ == "__main__":
    main()
EOF

# Make script executable
sudo chmod +x /var/ossec/integrations/custom/misp-enrichment.py
```

#### 6.3 Configure Wazuh Integration
```bash
# Add MISP integration to Wazuh configuration
sudo tee -a /var/ossec/etc/ossec.conf <<EOF
<integration>
  <name>custom/misp-enrichment</name>
  <hook_url>http://localhost:8080/misp-webhook</hook_url>
  <level>8</level>
  <rule_id>100400</rule_id>
  <alert_format>json</alert_format>
</integration>
EOF

# Set environment variables for MISP integration
sudo tee /etc/environment <<EOF
MISP_URL=http://localhost
MISP_API_KEY=your_misp_api_key_here
EOF
```

### Step 7: Create Sample Threat Intelligence

#### 7.1 Create Sample Event in MISP
```bash
# Using MISP API to create a sample event
curl -k -X POST "$MISP_URL/events/add" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "Event": {
      "info": "Sample Malware Campaign",
      "threat_level_id": "2",
      "analysis": "2",
      "distribution": "1",
      "Attribute": [
        {
          "type": "ip-src",
          "category": "Network activity",
          "value": "192.168.1.100",
          "comment": "C2 Server IP"
        },
        {
          "type": "domain",
          "category": "Network activity",
          "value": "malicious.example.com",
          "comment": "Malware C2 Domain"
        },
        {
          "type": "md5",
          "category": "Payload delivery",
          "value": "d41d8cd98f00b204e9800998ecf8427e",
          "comment": "Malware sample hash"
        }
      ]
    }
  }'
```

#### 7.2 Create Custom MISP Rules
```bash
# Create custom Wazuh rules for MISP-enriched alerts
sudo tee /var/ossec/etc/rules/local_rules.xml <<EOF
<group name="misp">
  <rule id="100400" level="10">
    <decoded_as>misp-enrichment</decoded_as>
    <field name="misp.status">threats_found</field>
    <description>MISP threat intelligence enrichment found matching indicators</description>
    <group>misp,threat_intelligence</group>
  </rule>

  <rule id="100401" level="12">
    <if_sid>100400</if_sid>
    <field name="misp.threat_level">critical</field>
    <description>Critical threat level indicator detected by MISP</description>
    <group>misp,critical_threat</group>
  </rule>

  <rule id="100402" level="10">
    <if_sid>100400</if_sid>
    <field name="misp.threat_level">high</field>
    <description>High threat level indicator detected by MISP</description>
    <group>misp,high_threat</group>
  </rule>
</group>
EOF
```

## 📊 Creating Threat Intelligence Dashboard

### Step 8: Kibana Visualizations for MISP Data

#### 8.1 Create Index Pattern
```bash
# Create index pattern for MISP-enriched alerts
curl -X POST "localhost:5601/api/saved_objects/index-pattern/wazuh-misp-enriched" \
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

#### 8.2 Create Threat Intelligence Visualizations

##### MISP Enrichment Status Pie Chart
```json
{
  "title": "MISP Enrichment Status",
  "type": "pie",
  "params": {
    "type": "pie",
    "addTooltip": true,
    "addLegend": true,
    "legendPosition": "right",
    "isDonut": true
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
        "field": "misp.status.keyword",
        "size": 5,
        "order": "desc",
        "orderBy": "1"
      }
    }
  ]
}
```

##### Threat Level Distribution
```json
{
  "title": "MISP Threat Level Distribution",
  "type": "horizontal_bar",
  "params": {
    "type": "histogram",
    "grid": {
      "categoryLines": false
    },
    "categoryAxes": [
      {
        "id": "CategoryAxis-1",
        "type": "category",
        "position": "left",
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
        "position": "bottom",
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
        "show": "true",
        "type": "histogram",
        "mode": "stacked",
        "data": {
          "label": "Alert Count",
          "id": "1"
        },
        "valueAxis": "ValueAxis-1",
        "drawLinesBetweenPoints": true,
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
      "type": "terms",
      "schema": "segment",
      "params": {
        "field": "misp.threat_level.keyword",
        "size": 4,
        "order": "desc",
        "orderBy": "1"
      }
    }
  ]
}
```

## 🧪 Testing the Integration

### Step 9: Test MISP-Wazuh Integration

#### 9.1 Generate Test Alerts
```bash
# Create a test alert that matches MISP indicators
sudo tee /var/ossec/logs/alerts/test-alert.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "level": 8,
    "description": "Test alert for MISP integration",
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
    "hostname": "malicious.example.com"
  }
}
EOF
```

#### 9.2 Test Integration Script
```bash
# Test the MISP enrichment script manually
cat /var/ossec/logs/alerts/test-alert.json | python3 /var/ossec/integrations/custom/misp-enrichment.py

# Check for enriched output with MISP data
```

#### 9.3 Trigger Wazuh Integration
```bash
# Restart Wazuh to load new configuration
sudo systemctl restart wazuh-manager

# Monitor Wazuh logs for integration activity
sudo tail -f /var/ossec/logs/ossec.log | grep -i misp

# Check integration logs
sudo tail -f /var/ossec/logs/integrations.log
```

#### 9.4 Verify Elasticsearch Data
```bash
# Query Elasticsearch for MISP-enriched alerts
curl -X GET "localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d'
{
  "query": {
    "exists": {
      "field": "misp"
    }
  },
  "size": 5
}'

# Check for MISP enrichment data in results
```

## 🔧 Advanced Configuration

### Step 10: Automated Threat Intelligence Workflows

#### 10.1 Create Automated Feed Processor
```bash
# Create script to automatically process MISP feeds
sudo tee /var/ossec/integrations/custom/misp-feed-processor.py <<'EOF'
#!/usr/bin/env python3
# Automated MISP Feed Processor for Wazuh

import json
import os
import time
import requests
from datetime import datetime, timedelta

class MISPFeedProcessor:
    def __init__(self):
        self.misp_url = os.getenv('MISP_URL', 'http://localhost')
        self.misp_key = os.getenv('MISP_API_KEY')
        self.wazuh_cdb_dir = '/var/ossec/etc/lists'
        self.processed_events_file = '/var/ossec/etc/misp_processed_events.json'

    def process_feeds(self):
        """Process recent MISP events and update Wazuh CDB lists"""
        try:
            # Get recent events (last 24 hours)
            events = self.get_recent_events()

            if not events:
                print("No recent events found")
                return

            # Extract IOCs
            iocs = self.extract_iocs_from_events(events)

            # Update Wazuh CDB lists
            self.update_cdb_lists(iocs)

            # Update processed events tracking
            self.update_processed_events(events)

            print(f"Processed {len(events)} events, extracted {len(iocs)} IOCs")

        except Exception as e:
            print(f"Feed processing error: {str(e)}")

    def get_recent_events(self):
        """Get recent events from MISP"""
        yesterday = datetime.now() - timedelta(days=1)
        date_filter = yesterday.strftime('%Y-%m-%d')

        try:
            url = f"{self.misp_url}/events/restSearch"
            payload = {
                "date": date_filter,
                "limit": 100
            }
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            response = requests.post(url, headers=headers, json=payload, verify=False)

            if response.status_code == 200:
                return response.json().get('response', [])
            else:
                print(f"Failed to get events: {response.status_code}")
                return []

        except Exception as e:
            print(f"Error getting events: {str(e)}")
            return []

    def extract_iocs_from_events(self, events):
        """Extract IOCs from MISP events"""
        iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'urls': set(),
            'file_hashes': set()
        }

        for event_wrapper in events:
            event = event_wrapper.get('Event', {})
            attributes = event.get('Attribute', [])

            for attr in attributes:
                attr_type = attr.get('type')
                attr_value = attr.get('value')

                if attr_type in ['ip-src', 'ip-dst']:
                    iocs['ip_addresses'].add(attr_value)
                elif attr_type == 'domain':
                    iocs['domains'].add(attr_value)
                elif attr_type == 'url':
                    iocs['urls'].add(attr_value)
                elif attr_type in ['md5', 'sha1', 'sha256']:
                    iocs['file_hashes'].add(attr_value)

        return iocs

    def update_cdb_lists(self, iocs):
        """Update Wazuh CDB lists with new IOCs"""
        # Create CDB directory if it doesn't exist
        os.makedirs(self.wazuh_cdb_dir, exist_ok=True)

        # Update IP addresses list
        if iocs['ip_addresses']:
            with open(f"{self.wazuh_cdb_dir}/misp_ip_addresses", 'w') as f:
                for ip in sorted(iocs['ip_addresses']):
                    f.write(f"{ip}\n")

        # Update domains list
        if iocs['domains']:
            with open(f"{self.wazuh_cdb_dir}/misp_domains", 'w') as f:
                for domain in sorted(iocs['domains']):
                    f.write(f"{domain}\n")

        # Update URLs list
        if iocs['urls']:
            with open(f"{self.wazuh_cdb_dir}/misp_urls", 'w') as f:
                for url in sorted(iocs['urls']):
                    f.write(f"{url}\n")

        # Update file hashes list
        if iocs['file_hashes']:
            with open(f"{self.wazuh_cdb_dir}/misp_file_hashes", 'w') as f:
                for hash_value in sorted(iocs['file_hashes']):
                    f.write(f"{hash_value}\n")

        print("Updated CDB lists with MISP IOCs")

    def update_processed_events(self, events):
        """Track processed events to avoid duplicates"""
        processed_ids = set()

        # Load existing processed events
        if os.path.exists(self.processed_events_file):
            with open(self.processed_events_file, 'r') as f:
                try:
                    processed_ids = set(json.load(f))
                except:
                    processed_ids = set()

        # Add new event IDs
        for event_wrapper in events:
            event = event_wrapper.get('Event', {})
            event_id = event.get('id')
            if event_id:
                processed_ids.add(str(event_id))

        # Save updated list
        with open(self.processed_events_file, 'w') as f:
            json.dump(list(processed_ids), f)

def main():
    processor = MISPFeedProcessor()

    # Run once immediately
    processor.process_feeds()

    # Then run every hour
    while True:
        time.sleep(3600)  # 1 hour
        processor.process_feeds()

if __name__ == "__main__":
    main()
EOF

# Make script executable
sudo chmod +x /var/ossec/integrations/custom/misp-feed-processor.py
```

#### 10.2 Set Up Cron Job for Automated Processing
```bash
# Add cron job for automated feed processing
sudo tee /etc/cron.d/misp-feeds <<EOF
# Run MISP feed processor every hour
0 * * * * root /var/ossec/integrations/custom/misp-feed-processor.py
EOF
```

#### 10.3 Update Wazuh Rules for MISP IOCs
```bash
# Create rules that reference MISP CDB lists
sudo tee /var/ossec/etc/rules/misp_ioc_rules.xml <<EOF
<group name="misp-iocs">
  <rule id="100500" level="12">
    <list field="srcip">etc/lists/misp_ip_addresses</list>
    <description>MISP: Source IP matches known threat indicator</description>
    <group>misp,ioc,network</group>
  </rule>

  <rule id="100501" level="12">
    <list field="dstip">etc/lists/misp_ip_addresses</list>
    <description>MISP: Destination IP matches known threat indicator</description>
    <group>misp,ioc,network</group>
  </rule>

  <rule id="100502" level="10">
    <list field="hostname">etc/lists/misp_domains</list>
    <description>MISP: Domain matches known threat indicator</description>
    <group>misp,ioc,network</group>
  </rule>

  <rule id="100503" level="12">
    <list field="md5">etc/lists/misp_file_hashes</list>
    <description>MISP: File hash matches known malware</description>
    <group>misp,ioc,malware</group>
  </rule>
</group>
EOF

# Include the new rules in ossec.conf
sudo sed -i '/<\/rules>/i <include>misp_ioc_rules.xml</include>' /var/ossec/etc/ossec.conf
```

## 🏁 Lab Completion Checklist

- [ ] MISP platform installed and configured
- [ ] Sample threat intelligence events created
- [ ] MISP Python integration script implemented
- [ ] Wazuh configuration updated for MISP integration
- [ ] Custom Wazuh rules for MISP-enriched alerts created
- [ ] Kibana visualizations for threat intelligence data built
- [ ] Integration tested with sample alerts
- [ ] Automated feed processor configured
- [ ] Cron job for automated processing set up
- [ ] MISP IOC CDB lists integrated with Wazuh rules
- [ ] Threat intelligence dashboard functional
- [ ] Documentation of integration process completed

## 🔧 Troubleshooting

### Common Issues and Solutions

**MISP API Connection Issues**:
```bash
# Test API connectivity
curl -k -H "Authorization: $MISP_API_KEY" $MISP_URL/events/index | jq .

# Check MISP logs
sudo tail -f /var/www/MISP/app/logs/error.log
```

**Integration Script Errors**:
```bash
# Test script manually
export MISP_URL=http://localhost
export MISP_API_KEY=your_api_key
echo '{"data": {"srcip": "192.168.1.100"}}' | python3 /var/ossec/integrations/custom/misp-enrichment.py
```

**CDB List Issues**:
```bash
# Check CDB list format
head -10 /var/ossec/etc/lists/misp_ip_addresses

# Test list compilation
/var/ossec/bin/ossec-makelists

# Check for compilation errors
tail -f /var/ossec/logs/ossec.log | grep -i list
```

## 📚 Additional Resources

- [MISP Documentation](https://www.misp-project.org/documentation/)
- [PyMISP Library](https://github.com/MISP/PyMISP)
- [MISP Threat Intelligence Fundamentals](https://www.misp-project.org/features.html)
- [Wazuh Integration Examples](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-external-software.html)

## 🎯 Next Steps

With your MISP integration complete, proceed to the next lab to integrate TheHive for comprehensive incident response and case management.

**[← Back to Threat Intelligence Theory](./04-threat-intelligence-integration.md)** | **[Next: TheHive Integration Lab →](./lab-04-thehive-workflow.md)**