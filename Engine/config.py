# config.py
# Central configuration for the Python Detection Engine

# General Engine Settings
DEBUG = True
SIMULATION_MODE = True

# Log file paths monitored by the watchdog
CONN_LOG_PATH = "../Log/conn.log"
SSL_LOG_PATH = "../Log/ssl.log"

# Threat 1: DDoS Detection Settings
DDOS_THRESHOLD = 20        # Number of connections from a single IP
DDOS_WINDOW = 5.0          # Time window in seconds

# Threat 2: Port Scan Detection Settings
PORTSCAN_THRESHOLD = 10    # Number of unique destination ports scanned by a single IP

# Threat 3: Beacon Detection Settings
BEACON_MIN_EVENTS = 5      # Minimum number of intervals to calculate consistency (requires 6 timestamps)
BEACON_TOLERANCE = 2.0     # Allowed deviation in seconds from the average interval

# Threat 4: Data Exfiltration Settings
UPLOAD_HISTORICAL_MULTIPLIER = 5.0  # Alert if current upload is > 5x historical average
UPLOAD_STATIC_THRESHOLD = 10485760    # Static threshold: 10 MB in bytes (10 * 1024 * 1024)

# Threat 6: Suspicious Failed Connections Settings
FAILED_CONN_THRESHOLD = 15   # Number of failed connections from a single IP
FAILED_CONN_WINDOW = 10.0    # Time window in seconds

# Threat 7: Connection Flood Settings
FLOOD_THRESHOLD = 30         # Number of connections
FLOOD_WINDOW = 5.0           # Time window in seconds
FLOOD_DURATION_THRESHOLD = 0.2 # Connections lasting less than this (in seconds) are considered short-lived
