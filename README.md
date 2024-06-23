# Network Intrusion Detection System (NIDS) using Suricata 

This project implements a Network Intrusion Detection System (NIDS) using Suricata, an open-source Intrusion Detection and Prevention System (IDPS) engine. Suricata is utilized to monitor network traffic and detect suspicious activities based on custom-defined rules.
#### (used Ubuntu)
## Features
<ul>
    <li>Rule-Based Detection: Utilizes Suricata's rule-based detection engine to identify various network-based attacks and anomalies.</li>
   <li> Customizable Rules: Allows customization of intrusion detection rules tailored to specific network environments and security requirements.</li>
    <li>Event Logging: Logs detected events to facilitate post-analysis and investigation of security incidents.</li>
    <li>Real-Time Monitoring: Provides real-time monitoring of network traffic for potential security threats.</li>
    <li>Testing Methodologies: Includes testing methodologies to validate the effectiveness of custom rules and analyze live network traffic.</li>
    </ul>
    
## Installation
  1. **Clone the repository**:

```bash
     git clone https://github.com/salma-h-wagdy/CodeAlpha_Network_Intrusion_Detection_System
     cd CodeAlpha_Network_Intrusion_Detection_System
```

  2. **Install Suricata**:

    Follow the installation instructions provided in the Suricata documentation to install and configure Suricata on your Ubuntu system.

  3. **Configure Suricata**:
  
    Edit the Suricata configuration file (suricata.yaml) located in /etc/suricata/ to customize settings such as interface configuration, logging options, and rule files.
    
  4. **Customize Rules**:

    Create or modify the Suricata rules file (custom.rules) to define custom intrusion detection rules tailored to your network environment and security policies.

### Custom Rules

```markdown
# Rule 1: Detect HTTP GET request from internal network to external network
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Detected"; flow:established,to_server; content:"GET"; http_method; sid:1; rev:1;)

# Rule 2: Detect Telnet connection attempt
alert tcp any any -> $HOME_NET 23 (msg:"Telnet Connection Attempt Detected"; sid:2; rev:1;)

# Rule 3: Detect ICMP Echo Request
alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; itype:8; sid:3; rev:1;)

# Rule 4: Detect ICMP Echo Reply
alert icmp any any -> any any (msg:"ICMP Echo Reply Detected"; itype:0; sid:4; rev:1;)

# Rule 5: Detect SSH connection attempt
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection Attempt Detected"; sid:5; rev:1;)

# Rule 6: Detect FTP connection attempt
alert tcp any any -> $HOME_NET 21 (msg:"FTP Connection Attempt Detected"; sid:6; rev:1;)
```

## Usage


- **Start Suricata**:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -S custom.rules -i <interface>
```
Replace <interface> with the name of the network interface you want Suricata to monitor (e.g., eth0, wlo1).

- **Monitor Logs**:

View Suricata logs in real-time to observe detected events:
```bash
tail -f /var/log/suricata/fast.log
```
## Testing


1. **Generate Test Traffic**:

   Use tools like `curl`, `telnet`, `ping`, or other network utilities to simulate network activities that match your defined rules.

2. **Verify Detection**:

   Monitor the Suricata logs (`fast.log`, `eve.json`) to ensure that alerts are generated for the simulated attacks and network anomalies.


## Resources
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Suricata Rule Management](https://suricata.readthedocs.io/en/suricata-6.0.2/rule-management/rule-management.html)
- [Google's Detection and Response Course](https://cloud.google.com/blog/topics/inside-google-cloud/introducing-detection-and-response-course)

## Acknowledgements
- Thanks to [Suricata](https://suricata-ids.org/) developers and contributors for providing an excellent open-source IDPS solution.
- Special thanks to [CodeAlpha](https://github.com/ahmedelgendy3/CodeAlpha_Network_Intrusion_Detection_System) for the initial inspiration and repository structure.

