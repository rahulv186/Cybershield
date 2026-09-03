# 🛡️ CyberShield

**CyberShield** is a real-time network threat detection and prevention system built with **Zeek**, **Python**, **Node.js/Express**, and **React**.

It monitors network traffic through Zeek, watches the generated logs in real time, detects suspicious activity with a Python detection engine, automatically blocks malicious IP addresses, and displays everything on a live security dashboard.

---

## 📋 Table of Contents

- [Features](#-features)
- [Threat Detection](#-threat-detection)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Setup](#-setup)
  - [1. Backend (Node.js / Express)](#1-backend-nodejs--express)
  - [2. Detection Engine (Python)](#2-detection-engine-python)
  - [3. Frontend (React + Vite)](#3-frontend-react--vite)
  - [4. Packet Capture (Zeek)](#4-packet-capture-zeek-optional-for-live-detection)
- [Running the Full System](#-running-the-full-system)
- [Testing the Detection Engine](#-testing-the-detection-engine)
- [API Endpoints](#-api-endpoints)
- [Configuration](#-configuration)

---

## ✨ Features

- **Real-time log monitoring** – tails Zeek `conn.log` and `ssl.log`, handles log rotation/truncation automatically
- **8 threat detection modules** with configurable thresholds
- **Automatic prevention** – blocks malicious IPs via firewall (or simulated blocking in simulation mode)
- **Live SOC-style dashboard** – metrics, charts, threat logs, blocked-IP list and analytics
- **MongoDB persistence** – threats and blocked IPs stored via MongoDB Atlas
- **Report export** – download a JSON security report from the dashboard
- **Dark mode** support

---

## 🚨 Threat Detection

| # | Threat | Severity | Source |
|---|--------|----------|--------|
| 1 | DDoS Attack | CRITICAL | conn.log |
| 2 | Port Scan | CRITICAL | conn.log |
| 3 | Beaconing / C2 Activity | MEDIUM | conn.log |
| 4 | Data Exfiltration (static & anomaly) | HIGH | conn.log |
| 5 | Weak TLS Negotiation | MEDIUM | ssl.log |
| 6 | Failed Connection Spike | MEDIUM | conn.log |
| 7 | Connection Flood | HIGH | conn.log |
| 8 | IP Spoofing (heuristic) | MEDIUM | conn.log |

Detection thresholds (window sizes, connection counts, byte limits, etc.) are fully configurable in [`Engine/config.py`](Engine/config.py).

---

## 🏗️ Architecture

**Data flow:** Zeek captures traffic → writes tab-separated log files → the Python `watcher` tails those files → `parser` normalises each line → `detectors` raise alerts → alerts are uploaded to the Express API → stored in MongoDB Atlas → the React dashboard polls and renders them.

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet capture | [Zeek](https://zeek.org/) (formerly Bro) |
| Detection engine | Python 3 (threading, `requests`) |
| Backend API | Node.js, Express, Mongoose |
| Database | MongoDB Atlas |
| Frontend | React 19, Vite 5, lucide-react |
| Linting | oxlint |

---

## ✅ Prerequisites

- **Node.js** v18+ (for Vite 5 / React 19)
- **Python** 3.9+
- **MongoDB** account (Atlas cluster or local instance)
- **Zeek** (optional – only for live packet capture; you can feed log files manually)

---

## 🛠🛠 Setup

### 1. Backend (Node.js / Express)

```bash
cd Backend
npm install
```

Create a `.env` file in the `Backend/` directory (copy of `Backend/.env.example`):

```env
PORT=5050
MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/ThreatShield
```

Run the server:

```bash
npm start        # production
npm run dev      # development with nodemon auto-reload
```

The API will be available at `http://localhost:5050`.

### 2. Detection Engine (Python)

```bash
cd Engine
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install requests
```

By default the engine runs with `SIMULATION_MODE = True` (in `Engine/config.py`), so no real firewall changes are made – safe for testing.

Start it with:

```bash
python3 main.py
```

The engine creates the `Log/conn.log` and `Log/ssl.log` files if they don't exist and tails them in real time.

> **Note:** The engine expects the backend at `http://localhost:5050` (hard-coded in `Engine/utils.py` and `Engine/prevention.py`). Make sure the backend is running first.

### 3. Frontend (React + Vite)

```bash
cd frontend
npm install
```

Create a `.env` file in the `frontend/` directory:

```env
VITE_API_BASE_URL=http://localhost:5050
```

Start the dev server:

```bash
npm run dev
```

Open `http://localhost:5173` in your browser.

Build for production:

```bash
npm run build
```

Lint:

```bash
npm run lint
```

### 4. Packet Capture (Zeek) (optional, for live detection)

Install Zeek (see [official docs](https://docs.zeek.org/)) then capture traffic:

```bash
cd Log
python3 start_zeek.py   # runs: sudo zeek -i en0 -C
```

This writes real traffic logs into the `Log/` folder, which the Python engine picks up automatically. Alternatively, tail an existing Zeek output or use the test driver (below).

---

## 🚀 Running the Full System

1. **Backend**

```bash
cd Backend
npm run dev
```

2. **Detection engine**

```bash
cd Engine
python3 main.py
```

3. **Frontend**

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173`, and start feeding traffic to Zeek (or run the test driver). Threats appear on the dashboard within seconds.

---

## 🧪 Testing the Detection Engine

The engine ships with a test driver that injects synthetic Zeek log lines for **all 8 threats plus log-rotation**:

```bash
cd Engine
python3 test_driver.py
```

> Ensure the backend is running first so alerts are persisted and visible in the dashboard.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats` | Fetch all threats (newest first) |
| GET | `/api/threats/:id` | Fetch a single threat |
| POST | `/api/threats` | Create a new threat record |
| DELETE | `/api/threats/:id` | Delete a threat |
| DELETE | `/api/threats` | Delete all threats |
| GET | `/api/threats/filter?severity=&attack_type=&source_ip=&protocol=&startDate=&endDate=` | Filter threats |
| GET | `/api/blocked` | Fetch blocked IPs |
| POST | `/api/blocked` | Block an IP |
| DELETE | `/api/blocked/:ip` | Unblock an IP |
| DELETE | `/api/blocked` | Clear all blocked IPs |
| GET | `/api/stats` | Dashboard stats (counts + top attack types/source IPs) |

All responses follow the standard shape: `{ success, message, data }`.

---

## ⚙️ Configuration

### Engine (`Engine/config.py`)

- `DEBUG` – verbose console output
- `SIMULATION_MODE` – `True` logs blocks instead of touching the firewall (recommended for testing)
- `DDOS_THRESHOLD` / `DDOS_WINDOW` – DDoS connection count and window (seconds)
- `PORTSCAN_THRESHOLD` – unique destination ports before flagging
- `BEACON_MIN_EVENTS` / `BEACON_TOLERANCE` – beacon interval consistency
- `UPLOAD_STATIC_THRESHOLD`, `UPLOAD_HISTORICAL_MULTIPLIER` – data exfiltration limits
- `FAILED_CONN_THRESHOLD` / `FAILED_CONN_WINDOW` – failed-connection spike
- `FLOOD_THRESHOLD` / `FLOOD_WINDOW` / `FLOOD_DURATION_THRESHOLD` – connection flood

### Backend

- `PORT` – Express server port
- `MONGO_URI` – MongoDB Atlas connection string

### Frontend

- `VITE_API_BASE_URL` – backend API base URL

---
