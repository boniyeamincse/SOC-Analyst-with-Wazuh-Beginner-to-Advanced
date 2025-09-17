# Threat Intelligence Integration with Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Threat intelligence concepts and frameworks (STIX, TAXII)
- MISP platform architecture and capabilities
- VirusTotal integration for file and URL analysis
- Integration methods between Wazuh and threat intelligence platforms
- Configuration of automated threat intelligence feeds
- Threat data enrichment and correlation
- API-based integration patterns
- Security considerations for threat intelligence sharing

## 📋 What is Threat Intelligence?

### Overview and Importance
**Threat Intelligence** is evidence-based knowledge about threats and threat actors that helps organizations:
- **Understand Attack Patterns**: Know how attackers operate and what techniques they use
- **Enhance Detection**: Improve security controls with current threat data
- **Prioritize Defenses**: Focus resources on the most relevant threats
- **Contextualize Incidents**: Provide background information for security events
- **Proactive Defense**: Anticipate and prevent attacks before they occur

### Threat Intelligence Frameworks
```
┌─────────────────────────────────────────────────────────────┐
│                THREAT INTELLIGENCE FRAMEWORKS              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   STRATEGIC │  │   OPERATIONAL│  │   TACTICAL  │          │
│  │ INTELLIGENCE│  │ INTELLIGENCE│  │ INTELLIGENCE│          │
│  │             │  │             │  │             │          │
│  │ • Long-term │  │ • Attack     │  │ • Indicators│          │
│  │   trends    │  │   campaigns │  │   of Compromise│         │
│  │ • Threat    │  │ • Attacker   │  │ • Signatures │          │
│  │   actor     │  │   methods   │  │ • IOCs      │          │
│  │   profiles  │  │ • Tools &    │  │ • Attack    │          │
│  │ • Geopolitical│  │   malware  │  │   patterns │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   STIX      │  │   TAXII     │  │   MAEC      │          │
│  │   FORMAT    │  │   PROTOCOL  │  │   FORMAT    │          │
│  │             │  │             │  │             │          │
│  │ • Structured│  │ • Transport │  │ • Malware   │          │
│  │   threat    │  │   protocol  │  │   analysis  │          │
│  │   data      │  │ • Sharing   │  │ • Behavior  │          │
│  │ • JSON/XML  │  │   standard  │  │   patterns  │          │
│  │ • Interop   │  │ • REST API  │  │ • Attribution│          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ MISP Platform Architecture

### Core Components

#### 1. MISP Server
Central threat intelligence sharing platform:
- **Event Management**: Structured threat intelligence events
- **Attribute Storage**: Indicators of compromise (IOCs) and contextual data
- **Sharing Groups**: Controlled sharing between organizations
- **API Interface**: RESTful API for integration and automation

#### 2. MISP Modules
Extensible analysis and enrichment modules:
- **Import Modules**: Data ingestion from various sources
- **Export Modules**: Data export to different formats
- **Analysis Modules**: Automated analysis and correlation
- **Enrichment Modules**: Additional context and threat data

#### 3. MISP Clients
Various tools for interacting with MISP:
- **MISP Web Interface**: Web-based management console
- **MISP Python Library**: Programmatic access to MISP
- **MISP STIX Converter**: Format conversion utilities

### Integration Architecture
```
External Feeds → MISP Server → Enrichment → Sharing → Wazuh Integration
     ↓              ↓           ↓           ↓           ↓
  Threat Data    Storage   Analysis   Distribution  Correlation
```

## 🔧 Integration with Wazuh

### Integration Methods

#### MISP Integration Architecture
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   EXTERNAL  │───▶│   MISP      │───▶│  ENRICHMENT │───▶│   WAZUH     │
│   FEEDS     │    │   SERVER    │    │   MODULES   │    │   SERVER    │
│ • Threat    │    │ • Event     │    │ • Context   │    │ • Rules     │
│   actors    │    │   storage   │    │   analysis  │    │ • IOCs      │
│ • IOCs      │    │ • Sharing   │    │ • Correlation│    │ • Alerts    │
│ • Campaigns │    │   groups    │    │ • Scoring   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

#### VirusTotal Integration Architecture
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  WAZUH      │───▶│ VIRUSTOTAL  │───▶│  ENRICHMENT │
│  ALERTS     │    │   API       │    │   PROCESS   │
│ • File      │    │ • File      │    │ • Reputation│
│   hashes    │    │   analysis  │    │ • Behavior  │
│ • URLs      │    │ • URL       │    │ • Context   │
│ • IPs       │    │   scanning  │    │ • Scoring   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Integration Benefits
- **Enhanced Detection**: Proactive identification of known threats
- **Context Enrichment**: Additional information for security alerts
- **Threat Correlation**: Linking alerts to known campaigns and actors
- **Automated Response**: Intelligence-driven automated actions
- **Community Intelligence**: Access to shared threat data

## 📋 MISP Installation and Configuration

### Installing MISP

#### Ubuntu/Debian Installation
```bash
# Install dependencies
sudo apt update
sudo apt install curl gcc git gnupg-agent make python3-dev python3-pip redis-server unzip zip

# Install MySQL
sudo apt install mysql-server
sudo mysql_secure_installation

# Clone MISP repository
cd /var/www
sudo git clone https://github.com/MISP/MISP.git
sudo chown -R www-data:www-data MISP
cd MISP

# Install CakePHP
sudo apt install composer
composer install --no-dev

# Configure database
sudo mysql -u root -p
CREATE DATABASE misp;
GRANT ALL ON misp.* TO misp@localhost IDENTIFIED BY 'misp_password';
FLUSH PRIVILEGES;
EXIT;

# Configure MISP
sudo cp app/Config/database.default.php app/Config/database.php
sudo cp app/Config/config.default.php app/Config/config.php
sudo cp app/Config/email.php app/Config/email.default.php
```

#### Docker Installation (Recommended for Labs)
```yaml
# docker-compose.yml
version: '3.8'
services:
  misp:
    image: harvarditsecurity/misp:latest
    ports:
      - "80:80"
      - "443:443"
    environment:
      - MYSQL_HOST=db
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
      - MYSQL_DATABASE=misp
      - MISP_FQDN=localhost
    depends_on:
      - db
    volumes:
      - misp-data:/var/www/MISP/app/tmp
      - misp-logs:/var/www/MISP/app/logs

  db:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
      - MYSQL_DATABASE=misp
    volumes:
      - db-data:/var/lib/mysql

volumes:
  misp-data:
  misp-logs:
  db-data:
```

### Basic MISP Configuration

#### Database Configuration
```php
// app/Config/database.php
class DATABASE_CONFIG {
    public $default = array(
        'datasource' => 'Database/Mysql',
        'persistent' => false,
        'host' => 'localhost',
        'port' => '',
        'login' => 'misp',
        'password' => 'misp_password',
        'database' => 'misp',
        'encoding' => 'utf8',
    );
}
```

#### Security Configuration
```php
// app/Config/config.php
$config = array(
    'Security' => array(
        'salt' => 'your_random_salt_here',
        'cipherSeed' => 'your_random_cipher_seed',
    ),
    'MISP' => array(
        'organisation' => array(
            'name' => 'Your Organization',
        ),
        'host_org_id' => 1,
        'email' => 'admin@yourorg.com',
        'disable_emailing' => false,
    ),
);
```

## 🔍 Wazuh MISP Integration Setup

### Method 1: MISP Module Integration

#### Install MISP Python Library
```bash
# Install required packages
pip3 install pymisp

# Create MISP configuration
cat > ~/.misprc << EOF
[https://localhost]
certify = False
key_file =
cert_file =
ca_file =
EOF
```

#### Wazuh Rules for MISP Enrichment
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<rule id="100100" level="10">
  <decoded_as>misp</decoded_as>
  <description>MISP threat intelligence enrichment</description>
  <group>misp,intelligence</group>
</rule>

<rule id="100101" level="12">
  <if_sid>100100</if_sid>
  <field name="misp.threat_level">high</field>
  <description>High threat level indicator from MISP</description>
  <group>misp,high_threat</group>
</rule>
```

#### Custom Wazuh Integration Script
```python
#!/usr/bin/env python3
# /var/ossec/integrations/custom-misp.py

import json
import sys
import os
from pymisp import PyMISP

def main():
    # Read Wazuh alert from stdin
    alert = json.loads(sys.stdin.read())

    # Extract relevant data
    srcip = alert.get('data', {}).get('srcip')
    dstip = alert.get('data', {}).get('dstip')
    filename = alert.get('data', {}).get('filename')

    # MISP connection
    misp_url = os.getenv('MISP_URL', 'https://localhost')
    misp_key = os.getenv('MISP_KEY', 'your_api_key')

    try:
        misp = PyMISP(misp_url, misp_key, False)

        # Search for indicators
        if srcip:
            results = misp.search('attributes', value=srcip)
            if results:
                alert['misp'] = {'matches': results, 'threat_level': 'medium'}

        # Output enriched alert
        print(json.dumps(alert))

    except Exception as e:
        print(json.dumps({'error': str(e)}))

if __name__ == "__main__":
    main()
```

### Method 2: API-Based Integration

#### REST API Integration
```python
# MISP API integration script
import requests
import json

def enrich_with_misp(indicator, indicator_type):
    misp_url = "https://your-misp-instance.com"
    api_key = "your_api_key"
    headers = {
        'Authorization': api_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Search for indicator
    search_url = f"{misp_url}/attributes/restSearch"
    payload = {
        "value": indicator,
        "type": indicator_type
    }

    response = requests.post(search_url, headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()
    return None

# Usage example
indicator_data = enrich_with_misp("192.168.1.100", "ip-src")
if indicator_data:
    print("Threat intelligence found:", indicator_data)
```

## 📊 VirusTotal Integration with Wazuh

### VirusTotal API Setup

#### API Key Configuration
```bash
# Set VirusTotal API key
export VT_API_KEY="your_virustotal_api_key"

# Store in configuration file
cat > /etc/wazuh/virustotal.conf << EOF
api_key = your_virustotal_api_key
EOF
```

#### Wazuh VirusTotal Integration Script
```python
#!/usr/bin/env python3
# /var/ossec/integrations/custom-virustotal.py

import json
import sys
import os
import requests

def main():
    alert = json.loads(sys.stdin.read())

    # Extract file hashes or URLs
    file_hash = alert.get('data', {}).get('md5') or alert.get('data', {}).get('sha1') or alert.get('data', {}).get('sha256')
    url = alert.get('data', {}).get('url')

    vt_api_key = os.getenv('VT_API_KEY')
    if not vt_api_key:
        print(json.dumps({'error': 'VirusTotal API key not configured'}))
        return

    headers = {
        'x-apikey': vt_api_key
    }

    try:
        if file_hash:
            # File hash analysis
            vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(vt_url, headers=headers)

            if response.status_code == 200:
                vt_data = response.json()
                malicious = vt_data['data']['attributes']['last_analysis_stats']['malicious']

                alert['virustotal'] = {
                    'file_hash': file_hash,
                    'malicious': malicious,
                    'total_scans': vt_data['data']['attributes']['last_analysis_stats']['total']
                }

        elif url:
            # URL analysis
            vt_url = "https://www.virustotal.com/api/v3/urls"
            payload = {'url': url}
            response = requests.post(vt_url, headers=headers, data=payload)

            if response.status_code == 200:
                vt_data = response.json()
                analysis_id = vt_data['data']['id']

                # Get analysis results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)

                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    alert['virustotal'] = {
                        'url': url,
                        'malicious': analysis_data['data']['attributes']['stats']['malicious'],
                        'total_scans': analysis_data['data']['attributes']['stats']['total']
                    }

        print(json.dumps(alert))

    except Exception as e:
        print(json.dumps({'error': str(e)}))

if __name__ == "__main__":
    main()
```

### Integration Configuration

#### Wazuh Integration Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<integration>
  <name>custom-virustotal</name>
  <hook_url>https://localhost:8080/virustotal</hook_url>
  <level>10</level>
  <rule_id>100200</rule_id>
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>custom-misp</name>
  <hook_url>https://localhost:8080/misp</hook_url>
  <level>8</level>
  <rule_id>100300</rule_id>
  <alert_format>json</alert_format>
</integration>
```

## 🔧 Advanced Configuration

### Automated Feed Processing

#### MISP Feed Synchronization
```python
# Automated MISP feed processor
import time
from pymisp import PyMISP

def sync_misp_feeds():
    misp = PyMISP('https://localhost', 'your_api_key', False)

    # Get all events
    events = misp.search('events', limit=1000)

    # Process indicators
    for event in events['response']:
        attributes = event['Event']['Attribute']

        for attr in attributes:
            indicator_type = attr['type']
            value = attr['value']

            # Add to Wazuh CDB list or rules
            add_to_wazuh_blacklist(indicator_type, value)

def add_to_wazuh_blacklist(indicator_type, value):
    # Implementation to add indicators to Wazuh
    # Could write to CDB files or create dynamic rules
    pass

# Run synchronization
while True:
    sync_misp_feeds()
    time.sleep(3600)  # Sync every hour
```

#### VirusTotal Automated Analysis
```python
# Automated VirusTotal analysis for suspicious files
import os
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SuspiciousFileHandler(FileSystemEventHandler):
    def __init__(self, vt_api_key):
        self.vt_api_key = vt_api_key
        self.headers = {'x-apikey': vt_api_key}

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            file_hash = self.calculate_hash(file_path)

            if self.is_suspicious(file_hash):
                self.analyze_with_virustotal(file_path, file_hash)

    def calculate_hash(self, file_path):
        import hashlib
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def is_suspicious(self, file_hash):
        # Check against known good/bad lists
        # This is a simplified example
        return True

    def analyze_with_virustotal(self, file_path, file_hash):
        # Upload file to VirusTotal
        upload_url = "https://www.virustotal.com/api/v3/files"
        files = {'file': open(file_path, 'rb')}
        response = requests.post(upload_url, headers=self.headers, files=files)

        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            print(f"File {file_path} uploaded for analysis: {analysis_id}")

if __name__ == "__main__":
    vt_api_key = os.getenv('VT_API_KEY')
    event_handler = SuspiciousFileHandler(vt_api_key)
    observer = Observer()
    observer.schedule(event_handler, path='/var/ossec/logs', recursive=True)
    observer.start()
```

## 🚨 Monitoring and Alerting

### Threat Intelligence Dashboard Integration

#### Kibana Visualization for Threat Intelligence
```json
{
  "title": "Threat Intelligence Overview",
  "hits": 0,
  "description": "",
  "panelsJSON": "[{\"gridData\":{\"h\":15,\"i\":\"1\",\"w\":24,\"x\":0,\"y\":0},\"id\":\"misp-indicators\",\"panelIndex\":\"1\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"2\",\"w\":12,\"x\":0,\"y\":15},\"id\":\"virustotal-analysis\",\"panelIndex\":\"2\",\"type\":\"visualization\",\"version\":\"7.17.9\"},{\"gridData\":{\"h\":15,\"i\":\"3\",\"w\":12,\"x\":12,\"y\":15},\"id\":\"threat-correlation\",\"panelIndex\":\"3\",\"type\":\"visualization\",\"version\":\"7.17.9\"}]",
  "optionsJSON": "{\"useMargins\":true}",
  "uiStateJSON": "{}",
  "version": 1,
  "timeRestore": false,
  "kibanaSavedObjectMeta": {
    "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"
  }
}
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### MISP Connection Issues
```bash
# Test MISP API connectivity
curl -H "Authorization: your_api_key" -H "Accept: application/json" https://localhost/events/restSearch

# Check MISP logs
tail -f /var/www/MISP/app/logs/error.log

# Validate API key
python3 -c "
from pymisp import PyMISP
misp = PyMISP('https://localhost', 'your_api_key', False)
print(misp.get_version())
"
```

#### VirusTotal API Issues
```bash
# Test API key
curl -H "x-apikey: your_api_key" https://www.virustotal.com/api/v3/users/current

# Check rate limits
curl -H "x-apikey: your_api_key" https://www.virustotal.com/api/v3/users/current | jq .data.quota

# Validate file hash format
python3 -c "
import hashlib
with open('file.exe', 'rb') as f:
    print(hashlib.sha256(f.read()).hexdigest())
"
```

#### Integration Script Issues
```bash
# Test Python script manually
echo '{"data": {"srcip": "192.168.1.100"}}' | python3 /var/ossec/integrations/custom-misp.py

# Check Python dependencies
pip3 list | grep pymisp

# Validate JSON output
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

### Performance Monitoring
```bash
# Monitor MISP performance
curl -H "Authorization: your_api_key" https://localhost/servers/getVersion

# Check MISP database performance
mysql -u misp -p -e "SHOW PROCESSLIST;"

# Monitor API usage
tail -f /var/log/apache2/access.log | grep "/api/"
```

## 📊 Integration Testing and Validation

### Testing Checklist
```bash
□ MISP server is running and accessible via web interface
□ API key is configured and has appropriate permissions
□ VirusTotal API key is valid and has quota available
□ Integration scripts are executable and in correct location
□ Wazuh can trigger integration scripts on alerts
□ Enriched alerts appear in Wazuh dashboard with threat intelligence
□ Kibana visualizations display threat intelligence data
□ Automated feed synchronization is working
□ Alert correlation with threat intelligence is functioning
□ False positive rates are within acceptable limits
□ Performance impact on Wazuh is monitored and acceptable
```

### Validation Commands
```bash
# Test MISP integration
curl -X POST "https://localhost/events/restSearch" \
  -H "Authorization: your_api_key" \
  -H "Accept: application/json" \
  -d '{"value": "192.168.1.100"}'

# Test VirusTotal integration
curl -H "x-apikey: your_api_key" \
  "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f"

# Check Wazuh integration logs
tail -f /var/ossec/logs/integrations.log

# Validate enriched alerts
grep "misp\|virustotal" /var/ossec/logs/alerts/alerts.json | head -5
```

## 🎯 Best Practices

### 1. Data Quality Management
- **Source Validation**: Verify the credibility and accuracy of threat intelligence sources
- **Data Freshness**: Ensure indicators are current and relevant
- **False Positive Management**: Implement scoring and confidence levels
- **Data Normalization**: Standardize indicator formats across sources

### 2. Security and Privacy
- **API Security**: Use secure channels and proper authentication
- **Data Sanitization**: Remove sensitive information before sharing
- **Access Control**: Implement role-based access to threat intelligence
- **Compliance**: Ensure compliance with data protection regulations

### 3. Integration Optimization
- **Rate Limiting**: Implement appropriate API rate limiting
- **Caching**: Cache frequently accessed indicators
- **Batch Processing**: Process indicators in batches for efficiency
- **Error Handling**: Robust error handling and retry mechanisms

### 4. Operational Considerations
- **Monitoring**: Comprehensive monitoring of integration health
- **Alert Tuning**: Fine-tune alerts to reduce noise
- **Documentation**: Maintain detailed integration documentation
- **Training**: Ensure SOC team understands threat intelligence context

## 📚 Self-Assessment Questions

1. What are the main differences between strategic, operational, and tactical threat intelligence?
2. How does MISP facilitate threat intelligence sharing between organizations?
3. What are the key integration methods for connecting Wazuh with threat intelligence platforms?
4. How can VirusTotal be used to enrich Wazuh alerts with file reputation data?
5. What are the security considerations when integrating external threat intelligence feeds?
6. How do you troubleshoot common issues with threat intelligence integrations?

## 🔗 Next Steps

Now that you understand threat intelligence integration, let's explore incident response integration with TheHive for comprehensive case management and workflow automation.

**[← Back to ELK Integration](./03-elk-stack-integration.md)** | **[Next: Incident Response Integration →](./05-incident-response-integration.md)**