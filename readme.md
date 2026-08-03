# 🛡️ CyberShield

CyberShield is a real-time network threat detection and prevention system built using **Zeek** and **Python**.

It monitors Zeek network logs, detects suspicious network activity, generates threat alerts, and can automatically block malicious IP addresses.

## 🚨 Threat Detection

CyberShield detects:

- DDoS Attacks
- Port Scanning
- Beaconing / C2 Activity
- Data Exfiltration
- Weak TLS
- Failed Connection Spikes
- Connection Floods
- IP Spoofing Heuristics


## ⚙️ How It Works

```text
Network Traffic
      ↓
     Zeek
      ↓
  Zeek Logs
      ↓
   Watchdog
      ↓
Python Detection Engine
      ↓
Threat Detected
      ↓
Alert + Prevention
      ↓
MongoDB Atlas
      ↓
Dashboard