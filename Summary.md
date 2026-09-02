# 🛡️ CyberShield Project Summary

## 📝 Overview
**CyberShield** is a real-time network threat detection and prevention system. It monitors network traffic captured by **Zeek**, analyzes the resulting logs using a custom **Python-based detection engine**, and provides a live security dashboard for visualization and management. The system can automatically block malicious IP addresses based on detected threat patterns.

## 🏗️ Architecture & Data Flow
The system operates in a pipeline:
1. **Traffic Capture**: Zeek captures network packets and writes them to tab-separated log files (`conn.log`, `ssl.log`).
2. **Real-time Monitoring**: A Python `watcher` tails these log files, handling rotation and truncation.
3. **Parsing & Detection**: The `parser` normalizes log lines, and the `detectors` module applies configurable thresholds to identify 8 types of threats.
4. **Prevention**: When critical threats are detected, the `prevention` module triggers an IP block (either via system firewall or simulation mode).
5. **Persistence**: Alerts and blocked IPs are sent via a REST API to a **MongoDB Atlas** database.
6. **Visualization**: A **React** dashboard polls the API to display live metrics, threat logs, and blocked-IP lists.

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Packet Capture** | Zeek | Network traffic analysis and log generation |
| **Detection Engine** | Python 3 | Log tailing, threat detection, and prevention logic |
| **Backend API** | Node.js, Express | RESTful API for data management |
| **Database** | MongoDB Atlas | Persistent storage for threats and blocked IPs |
| **Frontend** | React 19, Vite 5 | Live security SOC dashboard |
| **Icons/UI** | lucide-react | Dashboard iconography |

## 🚀 Installation Guide

### 1. Backend Setup
```bash
cd Backend
npm install
```
- Create `.env` with `PORT=5050` and `MONGO_URI=<your_mongodb_uri>`.
- Start: `npm run dev`

### 2. Detection Engine Setup
```bash
cd Engine
pip install requests
```
- Configure settings in `config.py` (e.g., `SIMULATION_MODE`).
- Start: `python3 main.py`

### 3. Frontend Setup
```bash
cd frontend
npm install
```
- Create `.env` with `VITE_API_BASE_URL=http://localhost:5050`.
- Start: `npm run dev`

### 4. (Optional) Live Traffic Capture
```bash
cd Log
python3 start_zeek.py
```

## 🚨 Detected Threats
The system detects the following threats:
- **DDoS Attack** (Critical)
- **Port Scan** (Critical)
- **Beaconing / C2 Activity** (Medium)
- **Data Exfiltration** (High)
- **Weak TLS Negotiation** (Medium)
- **Failed Connection Spike** (Medium)
- **Connection Flood** (High)
- **IP Spoofing** (Medium)
