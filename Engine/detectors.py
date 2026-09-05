# detectors.py
# REDESIGNED Python Detection Engine
# Procedural state and detector functions for all 8 threats

import time
import datetime
from collections import defaultdict
import config
import utils

# ==============================================================================
# STATE STORAGE (Procedural memory)
# ==============================================================================

# Threat 1 (DDoS): src_ip -> list of floats (timestamps)
ddos_state = defaultdict(list)

# Threat 2 (Port Scan): src_ip -> list of tuples (dst_port, timestamp)
port_scan_state = defaultdict(list)

# Threat 3 (Beaconing): (src_ip, dst_ip) -> list of floats (timestamps)
beacon_state = defaultdict(list)

# Threat 4 (Data Exfiltration): src_ip -> list of ints (bytes sent)
exfil_state = defaultdict(list)

# Threat 6 (Suspicious Failed Connections): src_ip -> list of floats (timestamps)
failed_conn_state = defaultdict(list)

# Threat 7 (Connection Flood): src_ip -> list of floats (timestamps)
flood_state = defaultdict(list)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def format_epoch(epoch_time):
    """Converts epoch float timestamp to readable format."""
    try:
        return datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(epoch_time)

def is_private_ip(ip):
    """Heuristic check to see if an IP is within private ranges (RFC 1918)."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        p1, p2 = int(parts[0]), int(parts[1])
        if p1 == 10:
            return True
        if p1 == 172 and (16 <= p2 <= 31):
            return True
        if p1 == 192 and p2 == 168:
            return True
        return False
    except ValueError:
        return False

# ==============================================================================
# DETECTORS
# ==============================================================================

def detect_ddos(record):
    """
    THREAT 1: DDoS Detection
    Detects a single source IP initiating a high number of connections in a short time.
    """
    src_ip = record.get("src_ip")
    ts = record.get("timestamp")
    if not src_ip or not ts:
        return None

    # Append current timestamp
    ddos_state[src_ip].append(ts)

    # Remove timestamps older than the configured window
    cutoff = ts - config.DDOS_WINDOW
    ddos_state[src_ip] = [t for t in ddos_state[src_ip] if t >= cutoff]
    current_count = len(ddos_state[src_ip])

    utils.debug_log(f"[DDoS Check] IP {src_ip} has {current_count} connections in last {config.DDOS_WINDOW}s (Threshold: {config.DDOS_THRESHOLD})")

    if current_count > config.DDOS_THRESHOLD:
        # Clear state after detection to prevent alert flooding
        ddos_state[src_ip] = []
        # ddos_score = min(100, 70 + ((current_count - 20)/20) * 30)
        return {
            "attack_type": "DDoS Attack",
            "severity": "CRITICAL",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": record.get("dst_ip", "Multiple"),
            "protocol":"TCP/HTTPS",
            "description": f"IP {src_ip} initiated {current_count} connections in {config.DDOS_WINDOW} seconds, exceeding threshold.",
            "evidence": f"Connections: {current_count} (Threshold: {config.DDOS_THRESHOLD} in {config.DDOS_WINDOW}s)",
            "recommendation": "Temporarily block IP using firewall rule."
        }
    return None


def detect_port_scan(record):
    """
    THREAT 2: Port Scan Detection
    Detects one host scanning many different destination ports.
    """
    src_ip = record.get("src_ip")
    dst_port = record.get("dst_port")
    ts = record.get("timestamp")
    if not src_ip or dst_port is None or not ts:
        return None

    # Keep port scan history within a rolling 60-second window to prevent stale accumulation
    port_scan_state[src_ip].append((dst_port, ts))
    cutoff = ts - 60.0
    port_scan_state[src_ip] = [item for item in port_scan_state[src_ip] if item[1] >= cutoff]

    # Calculate unique ports
    unique_ports = {item[0] for item in port_scan_state[src_ip]}
    unique_count = len(unique_ports)

    utils.debug_log(f"[Port Scan Check] IP {src_ip} scanned {unique_count} unique ports in last 60s (Threshold: {config.PORTSCAN_THRESHOLD})")

    if unique_count > config.PORTSCAN_THRESHOLD:
        scanned_list = sorted(list(unique_ports))
        # Clear state after alert to avoid alert storms
        port_scan_state[src_ip] = []
        port_score = min(100, 70+ ((unique_count-config.PORTSCAN_THRESHOLD)/config.PORTSCAN_THRESHOLD )* 100)
        return {
            "attack_type": "Port Scan",
            "severity": "CRITICAL",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": record.get("dst_ip", "Multiple"),
            "protocol":"TCP",
            "description": f"IP {src_ip} scanned {unique_count} unique ports in 60s.",
            "evidence": f"Scanned Port Count: {unique_count} (Threshold: {config.PORTSCAN_THRESHOLD}). Scanned Ports: {scanned_list}",
            "recommendation": "Block source IP and investigate port scanning behavior."
        }
    return None


def detect_beacon(record):
    """
    THREAT 3: Beacon Detection
    Detects malware periodically contacting the same server (constant communication intervals).
    """
    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    ts = record.get("timestamp")
    if not src_ip or not dst_ip or not ts:
        return None

    key = (src_ip, dst_ip)
    beacon_state[key].append(ts)

    # Keep at most last 10 connections for memory optimization
    if len(beacon_state[key]) > 10:
        beacon_state[key] = beacon_state[key][-10:]

    timestamps = beacon_state[key]
    utils.debug_log(f"[Beacon Check] {src_ip} -> {dst_ip} has {len(timestamps)} timestamps in state.")

    # We need at least (BEACON_MIN_EVENTS + 1) timestamps to get BEACON_MIN_EVENTS intervals
    min_timestamps = config.BEACON_MIN_EVENTS + 1
    if len(timestamps) >= min_timestamps:
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])

        # Calculate average interval
        avg_interval = sum(intervals) / len(intervals)

        # Check if all intervals are within tolerance
        beaconing = True
        for interval in intervals:
            if abs(interval - avg_interval) > config.BEACON_TOLERANCE:
                beaconing = False
                break

        utils.debug_log(f"[Beacon Check] Intervals: {[round(x, 2) for x in intervals]}, Avg: {round(avg_interval, 2)}s, Beaconing: {beaconing}")
        beacon_score = min(100, (70 + (len(intervals)-config.BEACON_MIN_EVENTS)/config.BEACON_MIN_EVENTS) * 30)
        if beaconing:
            # Clear state to avoid double alerts on subsequent packets
            beacon_state[key] = []
            return {
                "attack_type": "Beacon Detection",
                "severity": "MEDIUM",
                "detectedAt": format_epoch(ts),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol":"HTTPS(TLS)",
                "description": f"Periodic beaconing pattern detected from {src_ip} to {dst_ip}.",
                "evidence": f"Avg Interval: {round(avg_interval, 2)}s across {len(intervals)} intervals. Tolerance: ±{config.BEACON_TOLERANCE}s",
                "recommendation": "Inspect process running on source IP for Command & Control (C2) agents."
            }
    return None


def detect_data_exfiltration(record):
    """
    THREAT 4: Data Exfiltration
    Detects unusually large outbound transfers based on static size or deviation from history.
    """
    src_ip = record.get("src_ip")
    orig_bytes = record.get("orig_bytes", 0)
    ts = record.get("timestamp")
    if not src_ip or not ts:
        return None

    # Static Threshold Check (High Alert)
    if orig_bytes > config.UPLOAD_STATIC_THRESHOLD:
        utils.debug_log(f"[Exfil Check] IP {src_ip} exceeded static threshold: {orig_bytes} bytes (Static: {config.UPLOAD_STATIC_THRESHOLD})")
        # Save to history
        exfil_state[src_ip].append(orig_bytes)
        return {
            "attack_type": "Data Exfiltration (Static)",
            "severity": "HIGH",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": record.get("dst_ip", "Unknown"),
            "protocol":"HTTPS(TLS)",
            "description": f"IP {src_ip} uploaded a massive payload exceeding the static threshold.",
            "evidence": f"Uploaded: {orig_bytes} bytes (Static Threshold: {config.UPLOAD_STATIC_THRESHOLD} bytes)",
            "recommendation": "Isolate the host immediately. Check files transferred."
        }

    # Historical Anomaly Check
    history = exfil_state[src_ip]
    alert_triggered = None

    # We require a history of at least 5 connections to build an average
    if len(history) >= 5:
        avg_bytes = sum(history) / len(history)
        threshold = avg_bytes * config.UPLOAD_HISTORICAL_MULTIPLIER

        utils.debug_log(f"[Exfil Check] IP {src_ip} uploaded {orig_bytes} bytes (Hist Avg: {round(avg_bytes, 1)} bytes, Multiplier Threshold: {round(threshold, 1)})")

        # Check anomaly
        if avg_bytes > 0 and orig_bytes > threshold:
            ratio = round(orig_bytes / avg_bytes, 2)
            alert_triggered = {
                "attack_type": "Data Exfiltration (Anomaly)",
                "severity": "HIGH",
                "detectedAt": format_epoch(ts),
                "source_ip": src_ip,
                "destination_ip": record.get("dst_ip", "Unknown"),
                "protocol":"HTTPS(TLS)",
                "description": f"IP {src_ip} uploaded {orig_bytes} bytes, which is {ratio}x its historical average.",
                "evidence": f"Uploaded: {orig_bytes} bytes, Avg: {round(avg_bytes, 1)} bytes, Ratio: {ratio}x (Threshold: {config.UPLOAD_HISTORICAL_MULTIPLIER}x)",
                "recommendation": "Inspect connection payload and destination IP reputation."
            }

    # Update history (keep last 50 entries to save memory)
    history.append(orig_bytes)
    if len(history) > 50:
        exfil_state[src_ip] = history[-50:]

    return alert_triggered


def detect_weak_tls(record):
    """
    THREAT 5: Weak TLS Detection (analyzes ssl.log parsed dictionaries)
    Detects outdated protocol versions (SSLv3, TLS1.0, TLS1.1) and weak/unsecure cipher suites.
    """
    version = record.get("version", "").strip().upper()
    cipher = record.get("cipher", "").strip().upper()
    server_name = record.get("server_name", "Unknown")
    ts = record.get("timestamp")

    if not ts:
        return None

    # Weak TLS versions
    weak_versions = ["SSLV3", "TLSV10", "TLSV11"]

    # Weak cipher substring keywords
    weak_cipher_keywords = [
        "NULL", "RC4", "3DES", "anon", "DES", "MD5", "EXPORT"
    ]

    is_weak_version = any(wv in version for wv in weak_versions)
    is_weak_cipher = any(wc in cipher for wc in weak_cipher_keywords) if cipher else False

    utils.debug_log(f"[Weak TLS Check] Version: '{version}' (Weak? {is_weak_version}), Cipher: '{cipher}' (Weak? {is_weak_cipher})")

    if is_weak_version or is_weak_cipher:
        reason_list = []
        if is_weak_version:
            reason_list.append(f"Outdated Protocol ({version})")
        if is_weak_cipher:
            reason_list.append(f"Insecure Cipher ({cipher})")

        evidence = " & ".join(reason_list)
        return {
            "attack_type": "Weak TLS Negotiation",
            "severity": "MEDIUM",
            "detectedAt": format_epoch(ts),
            "source_ip": record.get("src_ip", "Unknown"),
            "destination_ip": record.get("dst_ip", "Unknown"),
            "protocol":"HTTPS(TLS)",
            "description": f"Negotiated connection to server '{server_name}' using insecure SSL/TLS parameters.",
            "evidence": f"Evidence: {evidence}",
            "recommendation": "Configure client/server to require TLS 1.2+ and disable weak cipher suites."
        }
    return None


def detect_failed_connections(record):
    """
    THREAT 6: Suspicious Failed Connections
    Detects one IP creating many failed connections (S0, REJ, RSTO, RSTOS0).
    """
    src_ip = record.get("src_ip")
    conn_state = record.get("conn_state")
    ts = record.get("timestamp")
    if not src_ip or not conn_state or not ts:
        return None

    # Failed states specified by requirement
    failed_states = {"S0", "REJ", "RSTO", "RSTOS0"}
    if conn_state not in failed_states:
        return None

    failed_conn_state[src_ip].append(ts)

    # Clean up older than window
    cutoff = ts - config.FAILED_CONN_WINDOW
    failed_conn_state[src_ip] = [t for t in failed_conn_state[src_ip] if t >= cutoff]
    failed_count = len(failed_conn_state[src_ip])

    utils.debug_log(f"[Failed Conn Check] IP {src_ip} has {failed_count} failed connections in last {config.FAILED_CONN_WINDOW}s (Threshold: {config.FAILED_CONN_THRESHOLD})")

    if failed_count > config.FAILED_CONN_THRESHOLD:
        failed_conn_state[src_ip] = []  # Clear to avoid storm
        return {
            "attack_type": "Failed Connection Spike",
            "severity": "MEDIUM",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": record.get("dst_ip", "Multiple"),
            "protocol":"TCP",
            "description": f"IP {src_ip} generated {failed_count} failed connections in {config.FAILED_CONN_WINDOW} seconds.",
            "evidence": f"Failed Connection Count: {failed_count} (Threshold: {config.FAILED_CONN_THRESHOLD})",
            "recommendation": "Investigate source IP for network scanning or brute force activity."
        }
    return None


def detect_connection_flood(record):
    """
    THREAT 7: Connection Flood
    Detects high volume of extremely short-lived connections.
    """
    src_ip = record.get("src_ip")
    duration = record.get("duration", 0.0)
    ts = record.get("timestamp")
    if not src_ip or not ts:
        return None

    # Check if connection is short-lived
    if duration >= config.FLOOD_DURATION_THRESHOLD:
        return None

    flood_state[src_ip].append(ts)

    # Clean up older than window
    cutoff = ts - config.FLOOD_WINDOW
    flood_state[src_ip] = [t for t in flood_state[src_ip] if t >= cutoff]
    flood_count = len(flood_state[src_ip])

    utils.debug_log(f"[Conn Flood Check] IP {src_ip} has {flood_count} rapid short connections in last {config.FLOOD_WINDOW}s (Threshold: {config.FLOOD_THRESHOLD})")

    if flood_count > config.FLOOD_THRESHOLD:
        flood_state[src_ip] = []  # Clear state
        return {
            "attack_type": "Connection Flood",
            "severity": "HIGH",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": record.get("dst_ip", "Multiple"),
            "protocol":"TCP",
            "description": f"IP {src_ip} initiated {flood_count} connection floods of duration < {config.FLOOD_DURATION_THRESHOLD}s in {config.FLOOD_WINDOW} seconds.",
            "evidence": f"Short-lived Connections: {flood_count} (Threshold: {config.FLOOD_THRESHOLD})",
            "recommendation": "Block source IP and investigate for application layer DoS attacks."
        }
    return None

import ipaddress

def detect_ip_spoofing(record):
    """
    IP Spoofing Detection (Heuristic)

    NOTE:
    Zeek conn.log cannot reliably detect IP spoofing because it does not
    contain ARP, MAC addresses, TTL, routing or interface information.

    Therefore this detector only flags obvious invalid or suspicious
    source addresses.
    """

    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    ts = record.get("timestamp")

    if not src_ip or not dst_ip or not ts:
        return None

    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)

    except ValueError:

        return {
            "attack_type": "IP Spoofing (Heuristic)",
            "severity": "LOW",
            "detectedAt": format_epoch(ts),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol":"UDP",
            "description": "Malformed IP address detected.",
            "evidence": f"Source IP '{src_ip}' is not a valid IPv4 or IPv6 address.",
            "recommendation": "Inspect packet capture for malformed traffic."
        }

    # =====================================================
    # IPv4 Checks
    # =====================================================

    if isinstance(src, ipaddress.IPv4Address):

        # 0.0.0.0
        if src == ipaddress.IPv4Address("0.0.0.0"):

            reason = "Source IP is 0.0.0.0"

        # 255.255.255.255
        elif src == ipaddress.IPv4Address("255.255.255.255"):

            reason = "Broadcast address used as source"

        # Multicast used as source
        elif src.is_multicast:

            reason = "Multicast address used as source"

        # Loopback communicating externally
        elif src.is_loopback and not dst.is_loopback:

            reason = "Loopback address communicating externally"

        else:
            return None

    # =====================================================
    # IPv6 Checks
    # =====================================================

    else:

        # Ignore completely normal IPv6 traffic
        if (
            src.is_link_local or
            src.is_loopback or
            src.is_multicast or
            src.is_private
        ):
            return None

        # Unspecified ::
        if src == ipaddress.IPv6Address("::"):

            reason = "IPv6 unspecified address used as source"

        else:
            # Most IPv6 addresses are perfectly valid.
            # Do not generate false positives.
            return None

    # =====================================================
    # Alert
    # =====================================================

    return {
        "attack_type": "IP Spoofing (Heuristic)",
        "severity": "MEDIUM",
        "detectedAt": format_epoch(ts),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol":"UDP",
        "description": reason,
        "evidence": (
            "Zeek conn.log provides only Layer-3 metadata. "
            "Detection is heuristic and cannot confirm spoofing without "
            "ARP/MAC/interface information."
        ),
        "recommendation": (
            "Verify ARP tables, DHCP logs, switch CAM tables, "
            "or firewall/router logs to confirm spoofing."
        )
    }