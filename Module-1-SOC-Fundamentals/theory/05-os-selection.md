# OS Selection for Wazuh

## 🎯 Learning Objectives

By the end of this section, you will understand:
- Recommended operating systems for Wazuh deployment
- Factors to consider when selecting an OS
- Differences between server and agent OS requirements

## 📋 OS Selection for Wazuh

### Recommended OS for Wazuh Server (Manager)
- Linux-based OS is preferred for Wazuh server due to stability and compatibility
- Popular choices:
  - Ubuntu LTS (20.04, 22.04)
  - Debian (10, 11)
  - CentOS / Rocky Linux / AlmaLinux (8, 9)
  - RHEL (8, 9)

### Recommended OS for Wazuh Agents
- Wazuh agents can run on multiple OS types:
  - Linux (Ubuntu, Debian, CentOS, RHEL)
  - Windows (Windows 10, 11, Windows Server 2016/2019/2022)
  - macOS
  - Cloud platforms (AWS EC2, Azure VM, GCP Compute Engine)

### Factors to Consider for OS Selection
- **Stability**: LTS (Long-Term Support) versions are preferred
- **Security**: Regular patch updates and security support
- **Compatibility**: Wazuh integrates well with Elastic Stack on Linux
- **Performance**: Linux generally provides better performance for Wazuh Manager and indexing services
- **Support**: Choose an OS that your team can manage and maintain

### Not Recommended
- Older, unsupported OS versions
- Non-Linux OS for large-scale Wazuh Server deployment due to potential compatibility and performance issues

## 💡 Summary
- Wazuh Server: Prefer Linux LTS distributions for production
- Wazuh Agent: Flexible, supports Linux, Windows, macOS, and cloud environments

## 📚 Self-Assessment Questions
1. What are the recommended Linux distributions for Wazuh Server?
2. Can Wazuh agents run on Windows systems?
3. Why is Linux preferred for Wazuh Server?

## 🔗 Next Steps
Now that you understand OS selection for Wazuh, let's compare Wazuh with other SIEM tools.

**[← Back: Wazuh Architecture →](./04-wazuh-architecture.md)** | **[Next: Wazuh vs Competitors →](./06-wazuh-vs-competitors.md)**