# Key Terms & Glossary

## 🔤 Module 1: SOC & Wazuh Fundamentals

This glossary contains important terms and concepts covered in Module 1. Understanding these terms is crucial for your SOC analyst journey.

## 📋 SOC Fundamentals

### Security Operations Center (SOC)
A centralized facility that monitors, detects, prevents, and responds to cybersecurity incidents 24/7. Combines people, processes, and technology.

### Security Operations (SecOps)
The processes and services that ensure an organization's information systems are protected from cyber threats, including monitoring, detection, analysis, and response.

### Security Information and Event Management (SIEM)
A comprehensive security solution that combines Security Information Management (SIM) and Security Event Management (SEM) to provide real-time analysis and alerting.

### Intrusion Detection System (IDS)
A security tool that monitors network traffic and system activities for malicious activities or policy violations.

### Intrusion Prevention System (IPS)
An active security tool that not only detects intrusions but also takes action to prevent them.

### Endpoint Detection and Response (EDR)
A security solution that monitors endpoint devices (computers, servers, mobile devices) for suspicious activities and responds to threats.

### Extended Detection and Response (XDR)
An integrated security platform that collects and correlates data across multiple security layers (endpoint, network, email, cloud, etc.).

## 🔍 Security Concepts

### CIA Triad
The three fundamental security principles:
- **Confidentiality**: Protecting sensitive information from unauthorized access
- **Integrity**: Ensuring data accuracy and trustworthiness
- **Availability**: Maintaining access to systems and data when needed

### Defense in Depth
A security strategy that uses multiple layers of defense to protect assets. If one layer fails, others provide protection.

### Threat Intelligence
The collection, analysis, and sharing of information about current or potential cyber threats to help organizations proactively identify and mitigate risks.

### Incident Response
The process of identifying, containing, eradicating, and recovering from security incidents.

### Vulnerability Assessment
The systematic identification, classification, and prioritization of security weaknesses in systems, applications, and networks.

### Risk Assessment
The process of identifying, analyzing, and prioritizing risks to determine appropriate mitigation strategies.

## 🏗️ Wazuh Architecture

### Wazuh Manager (Server)
The core component of Wazuh that receives data from agents, performs analysis, applies rules, and generates alerts.

### Wazuh Agent
A lightweight software installed on endpoints that collects security data and sends it to the Wazuh manager.

### Indexer
A component (Elasticsearch or OpenSearch) that stores and indexes security data for fast searching and analysis.

### Dashboard
A web interface (Kibana or OpenSearch Dashboards) that provides visualizations and monitoring capabilities.

### File Integrity Monitoring (FIM)
A security process that monitors changes to critical system files and directories to detect unauthorized modifications.

### Security Configuration Assessment (SCA)
Automated checks against security benchmarks and best practices to ensure systems are properly configured.

### Rootkit Detection
The process of identifying hidden malware that attempts to conceal its presence on a system.

### Log Collector
A component that gathers log data from various sources including files, Windows event logs, and network devices.

## 🔧 Deployment Types

### Single-Node Deployment
A Wazuh installation where all components (manager, indexer, dashboard) run on a single server. Suitable for small environments and testing.

### Distributed Deployment
A Wazuh installation where components are deployed on separate servers for better performance and scalability.

### Cluster Deployment
A highly available deployment with multiple instances of each component working together to provide redundancy and load balancing.

### Agentless Monitoring
A monitoring approach that collects data from endpoints without installing agent software, using protocols like SSH, WMI, or APIs.

## 📊 Monitoring & Alerting

### Rules Engine
A component that applies predefined rules to security events to identify suspicious activities and generate alerts.

### Decoders
Components that parse and normalize log data from different sources into a standard format for analysis.

### Correlation Rules
Rules that connect multiple security events to identify complex attack patterns that individual events might miss.

### Alert Levels
Severity classifications for security alerts, typically ranging from 1 (lowest) to 15 (highest) in Wazuh.

### False Positive
An alert that incorrectly identifies benign activity as malicious.

### False Negative
A failure to detect actual malicious activity.

## ☁️ Cloud & Container Security

### Cloud Security Posture Management (CSPM)
Tools and processes that continuously monitor cloud infrastructure for misconfigurations and compliance violations.

### Container Security
Security practices and tools designed to protect containerized applications and orchestration platforms like Docker and Kubernetes.

### Infrastructure as Code (IaC) Security
Security assessment of infrastructure configuration files to identify security issues before deployment.

## 📋 Compliance & Standards

### PCI-DSS (Payment Card Industry Data Security Standard)
A security standard for organizations that handle credit card information.

### HIPAA (Health Insurance Portability and Accountability Act)
A US law that protects patient health information and sets standards for healthcare organizations.

### GDPR (General Data Protection Regulation)
A European Union regulation that governs data protection and privacy.

### ISO 27001
An international standard for information security management systems.

### CIS Benchmarks
Security configuration guidelines developed by the Center for Internet Security for various technologies.

## 🛠️ Operational Concepts

### Alert Fatigue
The state of being overwhelmed by too many security alerts, leading to important alerts being missed.

### Mean Time to Detect (MTTD)
The average time it takes to identify a security incident.

### Mean Time to Respond (MTTR)
The average time it takes to respond to and resolve a security incident.

### Threat Hunting
The proactive process of searching for hidden threats or malicious activities in an organization's network and systems.

### Security Orchestration, Automation, and Response (SOAR)
A technology stack that enables organizations to collect security data and automate incident response processes.

## 📚 Study Tips for These Terms

1. **Create Flashcards**: Make digital or physical flashcards for each term
2. **Group Related Terms**: Study terms by category (e.g., all SOC-related terms together)
3. **Use Mnemonics**: Create memory aids for complex concepts
4. **Apply in Context**: Use terms in sentences or explain them to others
5. **Regular Review**: Review terms weekly to maintain retention
6. **Practical Application**: Try to use tools that demonstrate these concepts

## 🔗 Related Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls/)

## 📝 Quiz Yourself

Test your knowledge by covering the definitions and trying to recall or explain each term. Focus on understanding how these concepts relate to each other and real-world applications.

## 🔗 Next Steps

**[← Back: Troubleshooting →](../labs/lab-04-troubleshooting.md)** | **[Next: Further Reading →](./further-reading.md)**

---

*Mastering these terms will give you a solid foundation for advanced SOC concepts and practical implementation.*