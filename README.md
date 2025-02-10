# Detection-Lab
## Objective
The Detection-Lab project was designed to establish a controlled and realistic environment for simulating, detecting, and responding to cyberattacks. The lab deployed six virtual machines, each serving a critical role in network defense and attack simulation:
- Firewall (PfSense) – Protecting and monitoring network traffic.
- Splunk Server (SIEM) – Collecting, ingesting, and analyzing security logs.
- Active Directory (AD) Server – Managing user authentication and access controls.
- IPS/IDS (Zeek & Suricata Server) – Detecting and alerting on intrusion attempts.
- Attacker Server (Kali Linux & Atomic Red Team) – Simulating real-world cyberattacks.
- Windows Workstation – Acting as a target machine for security event logging.

Logs from these machines were ingested into Splunk (SIEM) for log correlation, behavioral analysis, and detection of malicious activities.
Additionally, automated incident response workflows were implemented to demonstrate how security teams can proactively detect, investigate, and respond to cyber threats.This hands-on project provided practical exposure to security operations, network defense strategies, and threat detection techniques.

### Skills Learned
- SIEM Log Analysis & Correlation – Ingesting and analyzing logs within Splunk to detect security incidents..
- Intrusion Detection & Prevention (IDS/IPS) – Configuring and managing Zeek and Suricata to identify malicious network activity.
- Firewall Configuration & Network Security – Implementing PfSense firewall rules for traffic monitoring and protection..
- Threat Hunting & Incident Response – Investigating attack indicators, correlating logs, and responding to threats.
- Active Directory Security & Management – Understanding authentication processes, user access controls, and security monitoring in Windows AD.
- Attack Simulation & Penetration Testing – Using Kali Linux and Atomic Red Team to simulate real-world attack techniques.
- Endpoint Security Monitoring – Logging attacker activities from a Windows workstation for analysis.
- Security Automation & Playbook Development – Creating automated workflows for incident response in Splunk SOAR.
- MITRE ATT&CK Framework – Mapping detected attack behaviors to known adversarial TTPs.
- Network Traffic Analysis – Capturing and analyzing traffic with Wireshark to detect anomalies.
- Threat Intelligence Integration – Enriching security alerts with external threat feeds (e.g., AbuseIPDB, VirusTotal).
- Scripting & Automation – Using Python and PowerShell to automate log parsing and security tasks.

### Tools Used
- Splunk (SIEM) – For centralized log collection, analysis, and correlation of security events.
- PfSense (Firewall) – To filter, route, and monitor network traffic for security enforcement.
- Zeek & Suricata (IDS/IPS) – To detect network-based threats and generate alerts.
- Active Directory (Windows Server) – For managing users, authentication, and security policies.
- Kali Linux – Used as an attacker machine for penetration testing and threat simulation.
- Atomic Red Team – For executing controlled adversary emulation and attack simulations.
- Windows Workstation – A target endpoint for collecting logs and monitoring system behavior.
- Wireshark – To analyze network traffic and detect anomalies.
- Threat Intelligence Feeds – Including VirusTotal, AbuseIPDB, and other sources for enrichment.
- Python & PowerShell – For scripting security automation and log analysis.
- Virtualized Lab Environment – Built using VMware or VirtualBox to create isolated test environments.
- MITRE ATT&CK Framework – To classify and map attack techniques based on real-world adversary behaviors.
- Sysmon (by Olaf Harton) – For system monitoring and generating detailed logs of system activities (e.g., process creation, network connections).
- Splunk Inputs Creation – Configured inputs in Splunk to index logs from Sysmon, Zeek, Suricata, and other sources, ensuring accurate log ingestion and analysis.

## Steps
*Ref 1: Network Diagram*
