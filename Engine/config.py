# config.py
# Central configuration for the Python Detection Engine

# General Engine Settings
DEBUG = False
SIMULATION_MODE = False
ALERT_COOLDOWN = 60.0       # Seconds before the same detector/key can alert again
STATE_MAX_EVENTS = 256      # Maximum records retained per rolling-state key

# Log file paths monitored by the watchdog
CONN_LOG_PATH = "../Log/conn.log"
SSL_LOG_PATH = "../Log/ssl.log"

# Threat 1: DDoS Detection Settings
DDOS_THRESHOLD = 100        # Number of connections from a single IP
DDOS_WINDOW = 1.0           # Time window in seconds

# Threat 2: Port Scan Detection Settings
PORTSCAN_THRESHOLD = 10    # Number of unique destination ports scanned by a single IP
PORTSCAN_WINDOW = 60.0
HORIZONTAL_SCAN_THRESHOLD = 10  # Unique destinations contacted on one port
HORIZONTAL_SCAN_WINDOW = 60.0

# Threat 3: Beacon Detection Settings
BEACON_MIN_EVENTS = 5      # Minimum number of intervals to calculate consistency (requires 6 timestamps)
BEACON_TOLERANCE = 1.0     # Allowed deviation in seconds from the average interval
BEACON_WINDOW = 3600.0
BEACON_MAX_EVENTS = 32

# Threat 4: Data Exfiltration Settings
UPLOAD_HISTORICAL_MULTIPLIER = 5.0  # Alert if current upload is > 5x historical average
UPLOAD_STATIC_THRESHOLD = 10485760    # Static threshold: 10 MB in bytes (10 * 1024 * 1024)
EXFIL_MIN_HISTORY = 5
EXFIL_HISTORY_MAX = 50

# Threat 6: Suspicious Failed Connections Settings
FAILED_CONN_THRESHOLD = 5   # Number of failed connections from a single IP
FAILED_CONN_WINDOW = 10.0    # Time window in seconds
FAILED_CONN_STATES = {"S0", "REJ", "RSTO", "RSTOS0"}

# Threat 7: Connection Flood Settings
FLOOD_THRESHOLD = 30         # Number of connections
FLOOD_WINDOW = 5.0           # Time window in seconds
FLOOD_DURATION_THRESHOLD = 0.2 # Connections lasting less than this (in seconds) are considered short-lived

# Repeated network activity detectors
SSH_ATTEMPT_THRESHOLD = 8
SSH_WINDOW = 60.0
BURST_THRESHOLD = 12
BURST_WINDOW = 10.0
BURST_SHORT_DURATION = 0.2
SERVICE_ABUSE_THRESHOLD = 5
SERVICE_MISMATCH_THRESHOLD = 3
SERVICE_ABUSE_WINDOW = 60.0
SENSITIVE_SERVICE_PORTS = {22, 23, 139, 445, 3389, 5900}
SERVICE_PORTS = {
    "ssh": {22},
    "ftp": {21},
    "http": {80, 8080, 8000},
    "https": {443, 8443},
    "dns": {53},
    "smtp": {25, 465, 587},
    "imap": {143, 993},
    "pop3": {110, 995},
}

# Protected IPs that should never be blocked (e.g., internal services, trusted sources)
PROTECTED_IPS = {
    "192.168.137.218",
    "10.10.10.2 ",
    "172.17.0.1 "
}
