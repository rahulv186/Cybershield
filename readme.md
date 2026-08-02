# 🛡️ Vigil

Vigil is a real-time network threat detection and prevention system built using **Zeek** and **Python**.

It monitors Zeek network logs, detects suspicious network activity, generates threat alerts, and can automatically block malicious IP addresses.

## 🚨 Threat Detection

Vigil detects:

- DDoS Attacks
- Port Scanning
- Beaconing / C2 Activity
- Data Exfiltration
- Weak TLS
- Failed Connection Spikes
- Connection Floods
- IP Spoofing Heuristics

## 🏗️ Tech Stack

- **Network Monitoring:** Zeek
- **Detection Engine:** Python
- **Log Monitoring:** Watchdog
- **Backend:** Node.js + Express
- **Database:** MongoDB Atlas
- **Frontend:** React

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