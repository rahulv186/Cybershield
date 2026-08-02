import time
import os
import threading
import config

# Set config settings for testing
config.DEBUG = True
config.SIMULATION_MODE = True
config.CONN_LOG_PATH = "conn.log"
config.SSL_LOG_PATH = "ssl.log"

import main
import utils

def write_line(filepath, line):
    """Appends a single line to a file."""
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

def setup_log_files():
    """Initializes clean log files for the test run."""
    for path in [config.CONN_LOG_PATH, config.SSL_LOG_PATH]:
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("#separator \\x09\n") # Written to demonstrate comments are ignored
            f.write("#types\ttime\tstring\taddr\tport\taddr\tport\n")
            f.flush()

def run_tests():
    print("\n" + "="*80)
    print("🧪 STARTING PYTHON DETECTION ENGINE TEST SUITE")
    print("="*80)
    
    # 1. DDoS Detection Test (Threshold: 20 connections in 5 seconds)
    print("\n--> Testing Threat 1: DDoS Detection...")
    now = time.time()
    for i in range(25):
        # 25 connections in 1 second from 192.168.1.50
        line = f"{now + i*0.01}\tUID_D_{i}\t192.168.1.50\t49152\t10.0.0.5\t443\ttcp\tssl\t0.1\t100\t100\tSF\t-\t-\t0\tShAdDaFf"
        write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 2. Port Scan Detection Test (Threshold: 10 unique ports scanned)
    print("\n--> Testing Threat 2: Port Scan Detection...")
    now = time.time()
    for port in range(80, 95):
        # Scans 15 unique ports from 192.168.1.51
        line = f"{now}\tUID_P_{port}\t192.168.1.51\t49152\t10.0.0.5\t{port}\ttcp\t-\t0.1\t50\t50\tSF\t-\t-\t0\tShAdDaF"
        write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 3. Beacon Detection Test (Threshold: 5 intervals within tolerance of ±2s)
    print("\n--> Testing Threat 3: Beacon Detection...")
    now = time.time()
    # Write 6 connections from 192.168.1.52 to 10.0.0.10, spaced exactly 5 seconds apart
    for i in range(6):
        line = f"{now + i*5.0}\tUID_B_{i}\t192.168.1.52\t49152\t10.0.0.10\t443\ttcp\tssl\t0.5\t120\t120\tSF\t-\t-\t0\tShAdDaFf"
        write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 4. Data Exfiltration Test (Threshold: > 5x avg upload or static 10MB)
    print("\n--> Testing Threat 4: Data Exfiltration...")
    now = time.time()
    # Scenario A: Static threshold (20MB upload)
    print("   Subtest A: Static threshold (> 10MB)")
    large_upload = 20 * 1024 * 1024 # 20MB
    line = f"{now}\tUID_E_STATIC\t192.168.1.53\t49152\t203.0.113.5\t443\ttcp\t-\t12.0\t{large_upload}\t500\tSF\t-\t-\t0\tShAdDaFf"
    write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # Scenario B: Historical Anomaly (5 small connections, then one large anomaly)
    print("   Subtest B: Historical Anomaly (> 5x avg)")
    # Establish history of 5 connections with avg upload of ~1000 bytes
    for i in range(5):
        line = f"{now + i}\tUID_E_HIST_{i}\t192.168.1.54\t49152\t203.0.113.6\t443\ttcp\t-\t1.0\t1000\t500\tSF\t-\t-\t0\tShAdDaFf"
        write_line(config.CONN_LOG_PATH, line)
    # The anomaly (10,000 bytes, which is 10x average)
    line = f"{now + 6}\tUID_E_HIST_ANOMALY\t192.168.1.54\t49152\t203.0.113.6\t443\ttcp\t-\t1.0\t10000\t500\tSF\t-\t-\t0\tShAdDaFf"
    write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 5. Weak TLS Detection Test (ssl.log analysis)
    print("\n--> Testing Threat 5: Weak TLS Detection...")
    now = time.time()
    # Weak version: SSLv3
    line_ver = f"{now}\tUID_S_VER\t192.168.1.55\t49152\t10.0.0.6\t443\tSSLv3\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\t-\tlegacy-portal.internal\t-"
    write_line(config.SSL_LOG_PATH, line_ver)
    time.sleep(0.2)
    # Weak cipher: RC4
    line_ciph = f"{now + 1}\tUID_S_CIPH\t192.168.1.55\t49153\t10.0.0.6\t443\tTLSv12\tTLS_RSA_WITH_RC4_128_SHA\t-\tbanking-api.internal\t-"
    write_line(config.SSL_LOG_PATH, line_ciph)
    time.sleep(0.5)

    # 6. Suspicious Failed Connections Test (Threshold: 15 failed connections in 10s)
    print("\n--> Testing Threat 6: Suspicious Failed Connections...")
    now = time.time()
    for i in range(18):
        # 18 failed connections (conn_state = REJ) from 192.168.1.56
        line = f"{now + i*0.01}\tUID_F_{i}\t192.168.1.56\t49152\t10.0.0.7\t80\ttcp\t-\t0.0\t0\t0\tREJ\t-\t-\t0\tS"
        write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 7. Connection Flood Test (Threshold: 30 connections of < 0.2s duration in 5s)
    print("\n--> Testing Threat 7: Connection Flood...")
    now = time.time()
    for i in range(35):
        # 35 connections of 0.05s duration from 192.168.1.57
        line = f"{now + i*0.01}\tUID_FL_{i}\t192.168.1.57\t49152\t10.0.0.8\t80\ttcp\t-\t0.05\t40\t40\tSF\t-\t-\t0\tShAdDaFf"
        write_line(config.CONN_LOG_PATH, line)
    time.sleep(0.5)

    # 8. IP Spoofing (Heuristic) Test
    print("\n--> Testing Threat 8: IP Spoofing (Heuristics)...")
    now = time.time()
    # Case A: Broadcast source address
    line_a = f"{now}\tUID_SP_A\t192.168.1.255\t49152\t10.0.0.9\t80\ttcp\t-\t0.1\t100\t100\tSF\t-\t-\t0\t-"
    write_line(config.CONN_LOG_PATH, line_a)
    time.sleep(0.2)
    # Case B: 0.0.0.0 source address
    line_b = f"{now}\tUID_SP_B\t0.0.0.0\t49152\t10.0.0.9\t80\ttcp\t-\t0.1\t100\t100\tSF\t-\t-\t0\t-"
    write_line(config.CONN_LOG_PATH, line_b)
    time.sleep(0.2)
    # Case C: Loopback appearing externally
    line_c = f"{now}\tUID_SP_C\t127.0.0.1\t49152\t192.168.1.10\t80\ttcp\t-\t0.1\t100\t100\tSF\t-\t-\t0\t-"
    write_line(config.CONN_LOG_PATH, line_c)
    time.sleep(0.2)
    # Case D: Multicast as source
    line_d = f"{now}\tUID_SP_D\t224.0.0.100\t49152\t10.0.0.9\t80\ttcp\t-\t0.1\t100\t100\tSF\t-\t-\t0\t-"
    write_line(config.CONN_LOG_PATH, line_d)
    time.sleep(0.5)

    # 9. Log Rotation Demonstration
    print("\n--> Testing Log Rotation...")
    # Rotate log by rewriting setup_log_files()
    setup_log_files()
    utils.debug_log("Truncated and set up logs again. Injecting a DDoS event post-rotation...")

    # Write a new DDoS event post-rotation to verify the watcher detects the truncation/inode shift
    now = time.time()
    for i in range(25):
        line = f"{now + i*0.01}\tUID_ROT_{i}\t192.168.1.99\t49152\t10.0.0.5\t443\ttcp\tssl\t0.1\t100\t100\tSF\t-\t-\t0\tShAdDaFf"
        write_line(config.CONN_LOG_PATH, line)
        
    time.sleep(1.0)
    print("\n" + "="*80)
    print("🏁 TEST SUITE COMPLETED")
    print("="*80)

if __name__ == "__main__":
    setup_log_files()
    
    # Start detection platform main daemon threads in background
    t_conn = threading.Thread(target=main.monitor_conn, name="TestConnMonitor", daemon=True)
    t_ssl = threading.Thread(target=main.monitor_ssl, name="TestSSLMonitor", daemon=True)
    
    t_conn.start()
    t_ssl.start()
    
    # Allow background monitoring threads to bind to files
    time.sleep(0.5)
    
    # Run the test injection
    run_tests()
    
    # Clean up test files after completion
    # for path in [config.CONN_LOG_PATH, config.SSL_LOG_PATH]:
    #     if os.path.exists(path):
    #         os.remove(path)
