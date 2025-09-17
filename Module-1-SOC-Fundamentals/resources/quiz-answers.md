# Quiz Answers

This document contains answers to the self-assessment questions found throughout Module 1.

## SOC Basics (01-soc-basics.md)

### 1. What are the three core components of a SOC?
**Answer:** The three core components are:
- **People**: Skilled security analysts and specialists
- **Processes**: Standardized incident response procedures and workflows
- **Technology**: Security tools and monitoring systems (SIEM, IDS/IPS, EDR, etc.)

### 2. Explain the difference between Tier 1 and Tier 3 SOC analysts.
**Answer:**
- **Tier 1 (Entry Level)**: Focus on monitoring alerts, initial triage, basic response, and escalating issues. They handle high-volume routine tasks.
- **Tier 3 (Expert Level)**: Conduct advanced threat research, develop threat intelligence, design security architectures, and mentor junior analysts. They handle complex investigations and strategic security decisions.

### 3. What is the CIA triad and why is it important?
**Answer:** The CIA triad consists of:
- **Confidentiality**: Protecting sensitive information from unauthorized access
- **Integrity**: Ensuring data accuracy and trustworthiness
- **Availability**: Maintaining access to systems and data when needed

It's important because it provides a fundamental framework for understanding and implementing information security across all SOC operations.

### 4. Describe two major challenges faced by SOC teams.
**Answer:** Two major challenges are:
- **Alert Fatigue**: Overwhelming number of alerts leading to missed important events
- **Skills Shortage**: Difficulty finding and retaining qualified cybersecurity professionals with the expertise needed for SOC operations

### 5. How can organizations measure SOC effectiveness?
**Answer:** SOC effectiveness can be measured through:
- **Operational Metrics**: Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), False Positive Rate
- **Effectiveness Metrics**: Incident Volume, Severity Distribution, Escalation Rate, Resolution Rate
- **Business Impact Metrics**: Financial Loss from incidents, Compliance Score, System Availability, User Satisfaction

## OS Selection (05-os-selection.md)

### 1. What are the recommended Linux distributions for Wazuh Server?
**Answer:** The recommended Linux distributions are:
- Ubuntu LTS (20.04, 22.04)
- Debian (10, 11)
- CentOS / Rocky Linux / AlmaLinux (8, 9)
- RHEL (8, 9)

### 2. Can Wazuh agents run on Windows systems?
**Answer:** Yes, Wazuh agents can run on Windows systems including:
- Windows 10 and 11
- Windows Server 2016, 2019, and 2022

### 3. Why is Linux preferred for Wazuh Server?
**Answer:** Linux is preferred for Wazuh Server because of:
- **Stability**: More reliable for 24/7 server operations
- **Compatibility**: Better integration with Elastic Stack components
- **Performance**: Generally provides better performance for server workloads
- **Security**: Strong security features and regular updates
- **Support**: LTS versions provide long-term support without frequent upgrades

## Wazuh vs Competitors (06-wazuh-vs-competitors.md)

### 1. What are the main cost advantages of Wazuh over Splunk?
**Answer:** Wazuh's main cost advantages are:
- **Free and Open Source**: No licensing fees for the core platform
- **No Usage-Based Pricing**: Unlike Splunk's expensive data ingestion costs
- **Lower Infrastructure Costs**: Can run on commodity hardware
- **Community Support**: Free community resources and forums

### 2. Which SIEM is best for large enterprises with advanced analytics needs?
**Answer:** For large enterprises with advanced analytics needs, **Splunk** is generally the best choice because:
- Highly scalable for massive data volumes
- Advanced analytics and machine learning capabilities
- Strong enterprise support and ecosystem
- Proven track record with Fortune 500 companies

### 3. How does Wazuh compare to Elastic SIEM in terms of features?
**Answer:** Feature comparison:
- **Similar Features**: Both offer log collection, visualization, and detection rules
- **Wazuh Advantages**: Built-in FIM, IDS, vulnerability detection, compliance reporting
- **Elastic Advantages**: More flexible visualization, larger community, broader integrations
- **Cost**: Wazuh is free; Elastic has paid enterprise tiers
- **Use Case**: Wazuh better for security-focused deployments; Elastic better for general log analytics

## Lab Assessments

### Lab 1: SOC Setup
**Key Points to Verify:**
- Infrastructure planning includes all necessary components
- Security hardening steps are properly implemented
- Team roles and responsibilities are clearly defined
- Monitoring tools are correctly configured

### Lab 2: Wazuh Single-Node Installation
**Installation Checklist:**
- All services (Wazuh, Elasticsearch, Kibana) are running
- Dashboard is accessible on port 5601
- At least one agent is connected
- Basic security events are being generated

### Lab 3: Basic Configuration
**Configuration Verification:**
- Custom log sources are properly configured
- File integrity monitoring is enabled
- Alert rules are customized
- Email notifications are set up (if configured)

### Lab 4: Troubleshooting
**Common Issues Resolved:**
- Service startup problems due to permissions or resources
- Agent connectivity issues from firewall or configuration
- Missing alerts due to log format or rule problems
- Dashboard access issues from service dependencies

## 🔗 Next Steps

**[← Back: Further Reading →](./further-reading.md)**

---

**Note:** These answers provide comprehensive explanations. In a real assessment, focus on demonstrating understanding of key concepts rather than memorizing exact wording.