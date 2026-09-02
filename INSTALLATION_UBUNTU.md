# Ubuntu Installation Guide for CyberShield

This guide provides step-by-step instructions for cloning and deploying the CyberShield project on an Ubuntu system.

## 🛠 Necessary Changes & Considerations for Ubuntu

Because CyberShield interacts with system-level networking, there are a few Ubuntu-specific requirements:

1.  **Firewall Tool**: The `Engine` uses `iptables` for "Real Mode" prevention. You must ensure `iptables` is installed.
2.  **Administrative Privileges**: Since `iptables` modifies the system kernel's network tables, the Python Engine **must** be executed with `sudo` to function in Real Mode.
3.  **Log Directory**: The `Engine` expects logs at `../Log/conn.log` and `../Log/ssl.log`. This `Log` folder must exist in the project root.
4.  **Database**: A running MongoDB instance is required for the Backend.

---

## 🚀 Installation Steps

### Step 1: System Prerequisites
Open your terminal and install the required system packages:

```bash
# Update package list
sudo apt update

# Install Git, Node.js, NPM, Python, and iptables
sudo apt install -y git nodejs npm python3 python3-pip python3-venv iptables
```

### Step 2: Clone the Project
```bash
git clone <your-repo-url>
cd CyberShield
```

### Step 3: Backend Setup
```bash
cd Backend
npm install

# Create a .env file for your MongoDB connection
# Example:
echo "MONGODB_URI=mongodb://localhost:27017/cybershield" > .env

# Start the backend
npm start 
```

### Step 4: Frontend Setup
Open a new terminal tab:
```bash
cd frontend
npm install
npm start
```

### Step 5: Engine Setup
Open a new terminal tab:
```bash
cd Engine

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install requests
```

### Step 6: Log Environment Setup
Create the `Log` folder in the project root to ensure the engine can find the log files:
```bash
# Navigate back to project root
cd ..
mkdir Log
# Create dummy log files for initial testing
touch Log/conn.log Log/ssl.log
```

### Step 7: Running the Engine
Navigate back to the Engine directory: `cd Engine`

#### A. Simulation Mode (Safe)
Use this for testing detection logic without affecting network traffic.
```bash
source venv/bin/activate
python3 main.py
```

#### B. Real Mode (Active Defense)
Use this to actually block IPs. **Requires root privileges.**
```bash
# Use sudo with the full path to the venv python to maintain dependencies
sudo ./venv/bin/python3 main.py
```

---

## 📋 Summary Checklist

| Component | Requirement | Ubuntu Action |
| :--- | :--- | :--- |
| **OS** | Ubuntu 20.04+ | `sudo apt update` |
| **Firewall** | `iptables` | `sudo apt install iptables` |
| **Runtime** | Node.js & Python 3 | `npm install` & `pip install` |
| **Database** | MongoDB | `sudo apt install mongodb` |
| **Permissions** | Root access for Engine | `sudo python3 main.py` |
| **FileSystem** | `/Log` directory | `mkdir Log` |
