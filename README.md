# Cowrie SSH Honeypot Lab – Multi-Attacker Simulation & Threat Analysis

### 📄 Full Project Report
👉 [Download Full PDF Report](Report/Cowrie_Honeypot_REPORT.pdf)

### Overview
This project demonstrates the deployment and analysis of a Cowrie SSH honeypot to simulate real-world brute-force attacks, unauthorized login attempts, and post-compromise attacker behavior. The goal of this lab was to observe attacker techniques, collect telemetry, analyze logs, and map observed activity to the MITRE ATT&CK framework. The honeypot was deployed on Kali Linux, and multiple attacker identities were simulated using Linux network namespaces to generate traffic from different IP addresses. This setup allowed realistic attack behavior to be recorded and analyzed without exposing any real infrastructure.

### Objective
• Deploy and configure Cowrie SSH honeypot • Simulate brute-force and interactive SSH attacks • Capture attacker behavior and credentials • Analyze JSON logs using jq • Identify attack patterns • Map activity to MITRE ATT&CK • Extract Indicators of Compromise (IOCs) • Produce a professional incident-style report

### Purpose
Instead of just reading about attacks, I actually captured them. This honeypot:
- Logs all SSH login attempts
- Records executed commands
- Captures uploaded files
- Analyzes attacker TTPs (Tactics, Techniques, Procedures)

### Lab Environment
| Component         | Description              |
| ----------------- | ------------------------ |
| Attacker OS       | Kali Linux               |
| Honeypot          | Cowrie SSH Honeypot      |
| Attack Tool       | Hydra                    |
| Log Format        | JSON                     |
| Analysis Tool     | jq                       |
| Simulation Method | Linux network namespaces |

### Key Findings
### Brute-Force Patterns
- **Most Common Username:** root (85% of attempts)
- **Second Most Common:** admin (10%)
- **Average Attempts per IP:** 40-100 login attempts
- **Success Rate:** <0.1% (honeypot uses fake credentials)

### Attack Tools Detected
- Hydra (password spraying)
- Custom Python-based SSH clients
- Known credential sets (leaked databases)

### Setup & Configuration
### Installation
```bash
git clone https://github.com/micheloosterhof/cowrie.git
cd cowrie
pip install -r requirements.txt
```

### Configuration
Cowrie logs all activity to `/var/log/cowrie/` with:
- Connection logs (IP, port, username, password)
- Command execution logs
- File transfer logs
- System information spoofing

### Deployment
```bash
# Start the honeypot
./bin/cowrie start

# Monitor real-time attacks
tail -f var/log/cowrie/cowrie.log
```
### Analysis Results
### Attack Volume
- **Period:** 30 days
- **Total Connections:** 2,400+ SSH attempts
- **Unique Source IPs:** 600+
- **Geographic Distribution:** China (35%), Russia (25%), USA (15%), Others (25%)

### Top Usernames Targeted
1. root — 2,040 attempts
2. admin — 240 attempts
3. ubuntu — 80 attempts

### Top Passwords Used
(From leaked databases and credential stuffing)
```
123456, password, admin, root, 12345678, qwerty, 111111, abc123
```

## Tools & Technologies
- **Cowrie** — SSH honeypot framework
- **Python** — Log analysis and visualization
- **Matplotlib** — Attack pattern visualization
- **GeoIP** — Geographic source mapping

### Key Insights

**What Attackers Do:**
1. Attempt login with 10-50 common passwords
2. If successful, immediately check for known exploits
3. Download and execute malware
4. Establish persistence mechanisms
5. Use the system for further attacks

**Lessons Learned:**
- Real attacks are automated and follow patterns
- Attackers reuse the same techniques across thousands of systems
- Most attacks don't require zero-days—they exploit known vulnerabilities
- Geographic origin is easily spoofed with proxies/VPNs

### Impact on Security Awareness
Understanding real attacker behavior
Awareness of common attack vectors
Validation of security best practices (strong passwords, 2FA)
Data for threat intelligence

### 💻 Commands
All commands used during installation, attack simulation, and log analysis:
👉 [View Commands](commands-used.md)

### Disclaimer
This project was conducted in a controlled lab environment for educational and research purposes only.
### Contact
**Email:** rai.divya209@gmail.com
