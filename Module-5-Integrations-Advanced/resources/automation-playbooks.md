# Automation Playbooks

## Overview

This document contains automation playbooks for common SOC integration scenarios. These playbooks provide step-by-step procedures for automating security operations, incident response, and threat intelligence workflows.

## Incident Response Playbooks

### Playbook 1: Malware Detection Response

#### Overview
Automated response to malware detection alerts from Wazuh agents.

#### Trigger
- Wazuh alert with rule ID 554 (malware detected)
- High severity (level ≥ 12)

#### Automation Steps
```yaml
name: malware_detection_response
description: Automated response to malware detection
trigger:
  - wazuh_rule_id: 554
  - severity: high

steps:
  1. isolate_host:
      description: Isolate affected host from network
      action: network_isolation
      parameters:
        host_ip: "{{ alert.data.srcip }}"
        duration: 3600  # 1 hour
      rollback: network_restore

  2. collect_evidence:
      description: Collect system evidence
      action: evidence_collection
      parameters:
        host_ip: "{{ alert.data.srcip }}"
        evidence_types:
          - memory_dump
          - file_hashes
          - network_connections
          - running_processes
      storage: "/evidence/{{ alert.timestamp }}"

  3. analyze_with_cortex:
      description: Submit suspicious files to Cortex for analysis
      action: cortex_analysis
      parameters:
        file_hash: "{{ alert.data.md5 }}"
        analyzers:
          - VirusTotal_GetReport
          - HybridAnalysis_GetReport
          - JoeSandbox_GetReport
      timeout: 300

  4. create_thehive_case:
      description: Create incident case in TheHive
      action: thehive_case_creation
      parameters:
        title: "Malware Detected: {{ alert.data.filename }}"
        severity: "{{ alert.rule.level }}"
        observables:
          - type: file
            value: "{{ alert.data.filename }}"
            tags: ["malware"]
          - type: ip
            value: "{{ alert.data.srcip }}"
            tags: ["source"]
        tasks:
          - title: "Initial Triage"
            status: "InProgress"
          - title: "Malware Analysis"
            status: "Waiting"

  5. notify_soc_team:
      description: Alert SOC team via multiple channels
      action: multi_channel_notification
      parameters:
        channels:
          - slack: "#security-incidents"
          - email: "soc-team@company.com"
          - sms: "+1234567890"
        message: |
          🚨 MALWARE DETECTED 🚨

          Agent: {{ alert.agent.name }}
          File: {{ alert.data.filename }}
          Hash: {{ alert.data.md5 }}
          Severity: {{ alert.rule.level }}

          Case created: {{ thehive_case_id }}
        priority: high

  6. update_wazuh_rules:
      description: Update dynamic rules if needed
      action: adaptive_rules
      condition: "{{ cortex_analysis.malicious_count > 10 }}"
      parameters:
        rule_update:
          - block_hash: "{{ alert.data.md5 }}"
          - quarantine_path: "{{ alert.data.filename }}"
```

### Playbook 2: Network Intrusion Response

#### Overview
Automated response to network-based intrusion detection.

#### Trigger
- Suricata alert with high severity
- Wazuh correlation with network rules

#### Automation Steps
```yaml
name: network_intrusion_response
description: Automated response to network intrusions
trigger:
  - suricata_alert: high_severity
  - wazuh_rule_group: "web|network"

steps:
  1. block_ip_address:
      description: Block malicious IP address
      action: firewall_block
      parameters:
        ip_address: "{{ alert.data.srcip }}"
        direction: both
        duration: 7200  # 2 hours
      rollback: firewall_unblock

  2. collect_packet_capture:
      description: Capture network traffic for analysis
      action: packet_capture
      parameters:
        interface: "{{ alert.agent.network_interface }}"
        duration: 300
        filter: "host {{ alert.data.srcip }}"
        storage: "/pcaps/{{ alert.timestamp }}.pcap"

  3. enrich_with_misp:
      description: Check threat intelligence for IOCs
      action: misp_enrichment
      parameters:
        indicators:
          - type: ip
            value: "{{ alert.data.srcip }}"
          - type: url
            value: "{{ alert.data.url }}"
        enrich_fields:
          - threat_level
          - tags
          - related_events

  4. update_threat_feeds:
      description: Update local threat intelligence feeds
      action: feed_update
      parameters:
        feeds:
          - name: malicious_ips
            source: misp
            update_interval: 3600
          - name: suspicious_urls
            source: virustotal
            update_interval: 1800

  5. generate_report:
      description: Generate automated incident report
      action: report_generation
      parameters:
        template: network_intrusion_report
        data:
          alert_details: "{{ alert }}"
          packet_analysis: "{{ packet_capture.results }}"
          threat_intel: "{{ misp_enrichment.results }}"
          recommended_actions: "{{ analysis.recommendations }}"
        format: pdf
        recipients:
          - email: "network-team@company.com"
          - slack: "#network-security"

  6. monitor_for_reoccurrence:
      description: Set up monitoring for similar attacks
      action: behavioral_monitoring
      parameters:
        watch_ip: "{{ alert.data.srcip }}"
        watch_patterns: "{{ alert.data.attack_pattern }}"
        duration: 86400  # 24 hours
        alert_threshold: 3
```

## Threat Intelligence Playbooks

### Playbook 3: Threat Intelligence Enrichment

#### Overview
Automated enrichment of security alerts with threat intelligence data.

#### Trigger
- Any security alert from Wazuh agents
- Scheduled execution (daily)

#### Automation Steps
```yaml
name: threat_intelligence_enrichment
description: Enrich alerts with threat intelligence
trigger:
  - any_wazuh_alert
  - schedule: "0 */4 * * *"  # Every 4 hours

steps:
  1. extract_indicators:
      description: Extract IOCs from recent alerts
      action: ioc_extraction
      parameters:
        time_range: "4h"
        indicator_types:
          - ip_addresses
          - domains
          - urls
          - file_hashes
          - email_addresses
      deduplication: true

  2. query_misp:
      description: Query MISP for threat intelligence
      action: misp_bulk_search
      parameters:
        indicators: "{{ extracted_indicators }}"
        search_types:
          - attributes
          - events
          - sightings
        max_results: 100
      error_handling: continue

  3. query_virustotal:
      description: Query VirusTotal for file intelligence
      action: vt_bulk_search
      parameters:
        file_hashes: "{{ extracted_indicators.file_hashes }}"
        rate_limit: 4  # requests per minute
      retry_on_error: true

  4. correlate_intelligence:
      description: Correlate threat intelligence with alerts
      action: intelligence_correlation
      parameters:
        alerts: "{{ recent_alerts }}"
        misp_data: "{{ misp_results }}"
        vt_data: "{{ vt_results }}"
        correlation_rules:
          - ip_match: exact
          - domain_match: substring
          - hash_match: exact
        confidence_threshold: 0.8

  5. update_alerts:
      description: Update alerts with intelligence data
      action: alert_enrichment
      parameters:
        correlated_alerts: "{{ correlation_results }}"
        enrichment_fields:
          - threat_level
          - confidence_score
          - related_campaigns
          - recommended_actions
        update_index: "wazuh-alerts-enriched"

  6. generate_intelligence_report:
      description: Generate threat intelligence summary
      action: intelligence_report
      parameters:
        time_period: "24h"
        top_indicators: 10
        new_threats: true
        format: html
        distribution:
          - email: "threat-intel@company.com"
          - dashboard: "threat-intelligence-summary"
```

### Playbook 4: Indicator of Compromise (IOC) Management

#### Overview
Automated management and distribution of IOCs across the SOC environment.

#### Trigger
- New IOCs from threat feeds
- Manual IOC addition
- Scheduled updates

#### Automation Steps
```yaml
name: ioc_management
description: Manage and distribute IOCs across SOC tools
trigger:
  - new_iocs_from_feed
  - manual_ioc_addition
  - schedule: "0 */2 * * *"  # Every 2 hours

steps:
  1. collect_iocs:
      description: Collect IOCs from various sources
      action: ioc_collection
      parameters:
        sources:
          - misp_events: true
          - virustotal_retro: true
          - custom_feeds: ["/feeds/custom-iocs.json"]
          - manual_entries: true
        filters:
          - confidence: "> 0.7"
          - age: "< 30d"
          - duplicates: remove

  2. validate_iocs:
      description: Validate IOC format and quality
      action: ioc_validation
      parameters:
        validation_rules:
          - ip_format: valid_ipv4_ipv6
          - domain_format: valid_fqdn
          - hash_format: valid_md5_sha1_sha256
          - url_format: valid_url
        quality_checks:
          - reputation_score: "> 0.5"
          - source_credibility: trusted_only
          - timeliness: not_stale

  3. enrich_iocs:
      description: Enrich IOCs with additional context
      action: ioc_enrichment
      parameters:
        enrichment_sources:
          - whois: domain_owner
          - geoip: location_data
          - reputation: threat_scores
          - malware_family: classification
        cache_results: true
        cache_ttl: 86400

  4. distribute_iocs:
      description: Distribute validated IOCs to SOC tools
      action: ioc_distribution
      parameters:
        destinations:
          - wazuh_cdb:
              format: text
              path: "/var/ossec/etc/lists/"
              reload_command: "/var/ossec/bin/ossec-control reload"
          - suricata_rules:
              format: suricata_rule
              path: "/etc/suricata/rules/custom-iocs.rules"
              reload_command: "suricatasc -c reload-rules"
          - elk_watchlist:
              format: json
              index: "threat-watchlist"
              update_command: "curl -XPOST localhost:9200/_refresh"
          - thehive_observables:
              format: thehive_observable
              create_cases: false
              tags: ["automated", "threat-intel"]

  5. monitor_ioc_effectiveness:
      description: Monitor IOC performance and effectiveness
      action: ioc_monitoring
      parameters:
        metrics:
          - hit_rate: alerts_per_ioc
          - false_positives: percentage
          - coverage: threat_types
          - timeliness: detection_delay
        reporting:
          - dashboard: "ioc-performance"
          - alerts: "ioc_performance_drop"
          - threshold: 0.1  # 10% drop triggers alert

  6. cleanup_expired_iocs:
      description: Remove expired or ineffective IOCs
      action: ioc_cleanup
      parameters:
        expiration_rules:
          - age: "> 90d"  # Remove after 90 days
          - hit_rate: "< 0.001"  # Remove if hit rate too low
          - false_positive_rate: "> 0.1"  # Remove if too many FPs
        cleanup_actions:
          - remove_from_cdb: true
          - archive_to_history: true
          - notify_analysts: true
```

## Compliance and Reporting Playbooks

### Playbook 5: Security Compliance Monitoring

#### Overview
Automated monitoring and reporting for security compliance requirements.

#### Trigger
- Scheduled execution (daily/weekly)
- Compliance deadline approaching
- Configuration changes

#### Automation Steps
```yaml
name: compliance_monitoring
description: Monitor security compliance across environment
trigger:
  - schedule: "0 2 * * *"  # Daily at 2 AM
  - compliance_deadline: approaching

steps:
  1. collect_compliance_data:
      description: Collect compliance-related data
      action: compliance_data_collection
      parameters:
        frameworks:
          - pci_dss: true
          - hipaa: true
          - gdpr: true
          - cis_benchmarks: true
        data_sources:
          - wazuh_agent_configs: true
          - system_logs: true
          - security_events: true
          - configuration_files: true

  2. assess_compliance:
      description: Assess compliance against requirements
      action: compliance_assessment
      parameters:
        assessment_rules:
          - log_retention: "> 365d"
          - access_controls: enabled
          - encryption: required_fields
          - monitoring: comprehensive
        scoring_method: weighted
        criticality_levels: [critical, high, medium, low]

  3. generate_compliance_report:
      description: Generate detailed compliance report
      action: compliance_report
      parameters:
        report_format: pdf
        include_sections:
          - executive_summary
          - detailed_findings
          - remediation_plan
          - evidence_artifacts
        distribution:
          - email: "compliance@company.com"
          - portal: "compliance-dashboard"
          - archive: "compliance-reports/{{ date }}"

  4. create_remediation_tasks:
      description: Create tasks for compliance issues
      action: remediation_task_creation
      parameters:
        thehive_integration: true
        task_assignment:
          - critical: "security-lead"
          - high: "system-admin"
          - medium: "it-support"
          - low: "junior-admin"
        due_dates:
          - critical: "7d"
          - high: "30d"
          - medium: "90d"
          - low: "180d"

  5. update_compliance_dashboard:
      description: Update compliance monitoring dashboard
      action: dashboard_update
      parameters:
        dashboard: "compliance-overview"
        metrics:
          - overall_score: percentage
          - framework_scores: breakdown
          - trend_analysis: 90d
          - risk_assessment: current
        alerts:
          - compliance_drop: "> 5%"
          - deadline_approach: "< 30d"

  6. archive_evidence:
      description: Archive compliance evidence
      action: evidence_archival
      parameters:
        retention_period: "7y"
        storage_location: "/compliance/evidence/{{ year }}"
        encryption: true
        integrity_check: sha256
```

## Maintenance and Operational Playbooks

### Playbook 6: SOC Environment Maintenance

#### Overview
Automated maintenance tasks for SOC environment health and performance.

#### Trigger
- Scheduled execution
- System alerts
- Manual initiation

#### Automation Steps
```yaml
name: soc_maintenance
description: Perform routine SOC environment maintenance
trigger:
  - schedule: "0 1 * * 0"  # Weekly Sunday 1 AM
  - system_alert: maintenance_required
  - manual: operator_request

steps:
  1. backup_soc_data:
      description: Backup all SOC component data
      action: comprehensive_backup
      parameters:
        components:
          - elasticsearch_indices: "wazuh-*"
          - thehive_database: all_cases
          - misp_database: all_events
          - wazuh_configuration: all
        storage:
          - primary: "/backup/soc/{{ date }}"
          - secondary: "s3://soc-backups/{{ date }}"
        retention: "30d"
        encryption: true

  2. optimize_databases:
      description: Optimize database performance
      action: database_optimization
      parameters:
        elasticsearch:
          - force_merge: true
          - delete_old_indices: "> 90d"
          - update_mappings: latest
        cassandra:
          - repair: true
          - cleanup: true
          - compaction: size_tiered
        mysql:
          - analyze_tables: true
          - optimize_tables: true

  3. update_signatures:
      description: Update all security signatures and rules
      action: signature_update
      parameters:
        components:
          - wazuh_rules: latest
          - suricata_rules: et-open
          - misp_galaxies: latest
          - cortex_analyzers: latest
        rollback_on_failure: true
        validation_tests: comprehensive

  4. performance_tuning:
      description: Tune system performance
      action: performance_optimization
      parameters:
        elasticsearch:
          - heap_size: optimal
          - thread_pools: balanced
          - cache_sizes: auto
        system:
          - memory_management: optimize
          - disk_io: tune
          - network_stack: optimize

  5. security_hardening:
      description: Apply security hardening measures
      action: security_hardening
      parameters:
        updates:
          - system_packages: latest
          - security_patches: all
          - configuration_hardening: cis_benchmarks
        scans:
          - vulnerability_scan: true
          - compliance_check: true
          - configuration_audit: true

  6. generate_maintenance_report:
      description: Generate maintenance completion report
      action: maintenance_report
      parameters:
        report_content:
          - backup_status
          - optimization_results
          - update_status
          - performance_metrics
          - security_scan_results
        distribution:
          - email: "soc-admin@company.com"
          - dashboard: "maintenance-reports"
          - archive: "/reports/maintenance/{{ date }}"
```

## Implementation Notes

### Playbook Execution Engine
```python
class PlaybookEngine:
    def __init__(self, playbook_config):
        self.playbook = playbook_config
        self.context = {}

    def execute(self, trigger_data):
        """Execute playbook with given trigger data"""
        self.context['trigger'] = trigger_data

        for step in self.playbook['steps']:
            try:
                result = self.execute_step(step)
                self.context[step['name']] = result

                if result.get('failed'):
                    self.handle_failure(step, result)
                    break
            except Exception as e:
                self.handle_error(step, e)
                break

    def execute_step(self, step):
        """Execute individual playbook step"""
        action = step['action']
        parameters = self.interpolate_parameters(step.get('parameters', {}))

        # Execute action (could be local function, API call, etc.)
        return self.execute_action(action, parameters)

    def interpolate_parameters(self, parameters):
        """Interpolate context variables in parameters"""
        import re

        def replace_var(match):
            var_path = match.group(1)
            return self.get_context_value(var_path)

        for key, value in parameters.items():
            if isinstance(value, str):
                parameters[key] = re.sub(r'\{\{\s*([^}]+)\s*\}\}', replace_var, value)

        return parameters
```

### Error Handling and Rollback
```python
def execute_with_rollback(step_config):
    """Execute step with rollback capability"""
    try:
        # Execute main action
        result = execute_step(step_config)

        # Store rollback information
        if 'rollback' in step_config:
            store_rollback_info(step_config['rollback'], result)

        return result

    except Exception as e:
        # Execute rollback if available
        if 'rollback' in step_config:
            execute_rollback(step_config['rollback'])

        raise e
```

### Monitoring and Alerting
```python
def monitor_playbook_execution(playbook_id, status):
    """Monitor playbook execution and alert on issues"""
    if status == 'failed':
        alert_soc_team(
            subject=f"Playbook {playbook_id} Failed",
            message=f"Playbook execution failed at step {status['failed_step']}",
            priority='high'
        )

    # Update monitoring dashboard
    update_dashboard_metric(
        'playbook_execution',
        {'playbook_id': playbook_id, 'status': status['overall_status']}
    )
```

These automation playbooks provide a foundation for implementing sophisticated SOC automation workflows that can significantly enhance operational efficiency and response capabilities.