# Module 2: Agent Deployment & Data Collection

## 🎯 Module Overview

Welcome to Module 2! Building on your SOC fundamentals, this module focuses on the practical deployment of Wazuh agents across different platforms and environments. You'll learn how to collect diverse data sources and build comprehensive monitoring coverage for your security operations.

### 📋 Learning Objectives

By the end of this module, you will be able to:
- Understand different types of Wazuh agents and their use cases
- Deploy Wazuh agents on Windows, Linux, and macOS systems
- Configure agents for various data collection scenarios
- Monitor cloud infrastructure and services
- Collect logs from network devices, web servers, and databases
- Implement comprehensive endpoint monitoring
- Troubleshoot agent deployment and connectivity issues

### ⏱️ Estimated Time

- **Theory**: 6-8 hours
- **Labs**: 12-16 hours
- **Total**: 18-24 hours

### 📚 Module Structure

```
📁 Module-2-Agent-Deployment/
├── 📄 README.md (This file)
├── 📁 theory/
│   ├── 📄 01-agent-types.md
│   ├── 📄 02-windows-deployment.md
│   ├── 📄 03-linux-deployment.md
│   ├── 📄 04-macos-deployment.md
│   ├── 📄 05-cloud-integration.md
│   └── 📄 06-advanced-collection.md
├── 📁 labs/
│   ├── 📄 lab-01-multi-agent-deployment.md
│   ├── 📄 lab-02-cloud-monitoring.md
│   ├── 📄 lab-03-network-device-monitoring.md
│   ├── 📄 lab-04-web-server-monitoring.md
│   └── 📄 lab-05-database-monitoring.md
└── 📁 resources/
    ├── 📄 deployment-checklist.md
    ├── 📄 troubleshooting-guide.md
    └── 📄 agent-configuration-examples.md
```

### 🛠️ Prerequisites

Before starting this module, ensure you have:
- Completed Module 1 (SOC & Wazuh Fundamentals)
- A working Wazuh server installation (from Module 1)
- Access to test systems (physical/virtual) for agent deployment
- Basic understanding of different operating systems
- Network access between agents and Wazuh server
- Administrative privileges on target systems

### 📖 Lesson Plan

#### Week 1: Agent Deployment Fundamentals
1. **Day 1-2**: Agent types and basic deployment concepts
2. **Day 3-4**: Windows and Linux agent deployment
3. **Day 5-7**: macOS deployment and troubleshooting

#### Week 2: Advanced Data Collection
1. **Day 1-3**: Cloud integration and monitoring
2. **Day 4-5**: Network device and web server monitoring
3. **Day 6-7**: Database monitoring and advanced configurations

### 🎯 Success Criteria

You can move to the next module when you:
- ✅ Successfully deploy agents on at least 3 different platforms
- ✅ Configure agents to collect logs from various sources
- ✅ Monitor cloud infrastructure and services
- ✅ Collect and analyze logs from network devices
- ✅ Implement comprehensive endpoint monitoring
- ✅ Troubleshoot common agent deployment issues

### 📝 Key Concepts

- **Active vs Passive Agents**: Real-time vs scheduled data collection
- **Agentless Monitoring**: Direct data collection without agents
- **Multi-platform Support**: Consistent monitoring across environments
- **Cloud Integration**: Monitoring cloud-native services
- **Syslog Integration**: Network device log collection
- **Endpoint Detection**: Comprehensive host monitoring

### 🔧 Tools & Technologies

- **Wazuh Agents**: Multi-platform monitoring agents
- **Cloud Platforms**: AWS, Azure, GCP integration
- **Network Devices**: Routers, switches, firewalls
- **Web Servers**: Apache, Nginx, IIS monitoring
- **Databases**: MySQL, PostgreSQL, MSSQL monitoring
- **Endpoint Systems**: Windows, Linux, macOS hosts

### 📊 Progress Tracking

- [ ] Study agent types and deployment strategies
- [ ] Deploy agents on Windows systems
- [ ] Deploy agents on Linux systems
- [ ] Deploy agents on macOS systems
- [ ] Configure cloud integrations
- [ ] Monitor network devices
- [ ] Monitor web servers
- [ ] Monitor databases
- [ ] Complete all hands-on labs
- [ ] Pass self-assessment quiz

### 🚨 Common Challenges

**Challenge**: Agent connectivity issues
**Solution**: Check firewall rules, network configuration, and authentication

**Challenge**: Platform-specific deployment problems
**Solution**: Follow platform-specific guides and check prerequisites

**Challenge**: Large-scale agent management
**Solution**: Use automation tools and centralized configuration

### 🎓 Best Practices for Agent Deployment

1. **Plan Your Deployment**: Design your monitoring architecture
2. **Test in Stages**: Start with pilot deployments
3. **Use Automation**: Script deployments for consistency
4. **Monitor Performance**: Track agent resource usage
5. **Regular Updates**: Keep agents updated with latest versions
6. **Security First**: Secure agent communications and configurations
7. **Documentation**: Document your deployment procedures

### 📞 Support Resources

- **Module Resources**: Check the `/resources/` folder
- **Official Documentation**: [Wazuh Agent Deployment Guide](https://documentation.wazuh.com/)
- **Community Forums**: Wazuh community discussions
- **GitHub Issues**: Report bugs and get help

---

## 🚀 Getting Started

1. **Review Prerequisites**: Ensure you have the required systems and access
2. **Start with Theory**: Read about agent types and deployment strategies
3. **Practice Deployment**: Begin with simple agent installations
4. **Scale Gradually**: Add more complex monitoring scenarios
5. **Troubleshoot Issues**: Use the troubleshooting guide for problems

### 🧪 Testing Environment

For best learning experience, set up:
- **Multiple VMs**: Different operating systems for agent testing
- **Cloud Instances**: For cloud integration testing
- **Network Lab**: For device monitoring (optional)
- **Web/Database Servers**: For application monitoring

### 📈 Skill Progression

This module builds these essential SOC skills:
- **System Administration**: Multi-platform deployment
- **Network Configuration**: Secure agent communications
- **Log Management**: Diverse data source integration
- **Troubleshooting**: Agent deployment and connectivity issues
- **Automation**: Deployment scripting and management

---

## 🔗 Module Dependencies

**Required**: Module 1 (SOC & Wazuh Fundamentals)
**Recommended**: Basic Linux/Windows administration knowledge

## 📚 Additional Learning Resources

- **Wazuh Agent Documentation**: Comprehensive deployment guides
- **Cloud Provider Documentation**: AWS, Azure, GCP monitoring guides
- **Network Device Manuals**: Vendor-specific configuration guides
- **Security Best Practices**: Industry standards and guidelines

---

*Remember: Effective SOC operations depend on comprehensive data collection. Master agent deployment to build a strong monitoring foundation!*

---

**[← Back to Main Tutorial](../README.md)** | **[Next: Agent Types →](./theory/01-agent-types.md)**