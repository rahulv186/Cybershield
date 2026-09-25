"""Network detectors for the Zeek-backed CyberShield engine.

The parser deliberately exposes only fields present in Zeek conn.log and
ssl.log. These detectors therefore report network evidence, not application
events that Zeek has not observed (for example, SSH password failures).
"""

import datetime
import ipaddress
from collections import defaultdict, deque

import config


# State is bounded by deque limits and rolling windows. Cooldowns prevent a
# continuing event from creating an alert for every Zeek record.
ddos_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
port_scan_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
horizontal_scan_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
beacon_state = defaultdict(lambda: deque(maxlen=config.BEACON_MAX_EVENTS))
exfil_state = defaultdict(lambda: deque(maxlen=config.EXFIL_HISTORY_MAX))
failed_conn_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
flood_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
ssh_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
burst_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
service_abuse_state = defaultdict(lambda: deque(maxlen=config.STATE_MAX_EVENTS))
alert_cooldowns = {}


def format_epoch(epoch_time):
    try:
        return datetime.datetime.fromtimestamp(float(epoch_time)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(epoch_time)


def _timestamp(record):
    try:
        value = float(record.get("timestamp"))
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _prune(events, timestamp, window):
    cutoff = timestamp - max(float(window), 0.0)
    while events:
        first = events[0]
        first_timestamp = first[0] if isinstance(first, tuple) else first
        if first_timestamp >= cutoff:
            break
        events.popleft()


def _cooldown_ready(name, key, timestamp):
    cooldown_key = (name, key)
    last_alert = alert_cooldowns.get(cooldown_key)
    if last_alert is not None and timestamp - last_alert < config.ALERT_COOLDOWN:
        return False
    alert_cooldowns[cooldown_key] = timestamp
    return True


def _alert(attack_type, severity, timestamp, source_ip, destination_ip,
           protocol, description, evidence, recommendation):
    return {
        "attack_type": attack_type,
        "severity": severity,
        "detectedAt": format_epoch(timestamp),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol or "Unknown",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _count_score(count, threshold, weight=35):
    if threshold <= 0:
        return 100
    return min(100, int(65 + max(0, count - threshold) * weight / threshold))


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def detect_ddos(record):
    """Detect a high source connection rate in a rolling window."""
    src, ts = record.get("src_ip"), _timestamp(record)
    if not src or ts is None:
        return None
    events = ddos_state[src]
    events.append((ts, record.get("dst_ip", "")))
    _prune(events, ts, config.DDOS_WINDOW)
    count = len(events)
    if count < config.DDOS_THRESHOLD or not _cooldown_ready("ddos", src, ts):
        return None
    destinations = len({item[1] for item in events if item[1]})
    return _alert(
        "DDoS Attack", "CRITICAL", ts, src, record.get("dst_ip", "Multiple"),
        record.get("protocol", "TCP"),
        f"High connection rate from {src} detected in a rolling window.",
        f"Connections: {count}; unique destinations: {destinations}; threshold: "
        f"{config.DDOS_THRESHOLD} in {config.DDOS_WINDOW}s; score: "
        f"{_count_score(count, config.DDOS_THRESHOLD)} / 100",
        "Rate-limit or temporarily block the source after validating it is not trusted traffic.",
    )


def _detect_vertical_scan(record, attack_type):
    src, dst, port, ts = (record.get("src_ip"), record.get("dst_ip"),
                           record.get("dst_port"), _timestamp(record))
    if not src or not dst or port in (None, "") or ts is None:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    events = port_scan_state[src]
    events.append((ts, dst, port))
    _prune(events, ts, config.PORTSCAN_WINDOW)
    ports = {item[2] for item in events if item[1] == dst}
    if (len(ports) < config.PORTSCAN_THRESHOLD or
            not _cooldown_ready("vertical_scan", (src, dst), ts)):
        return None
    return _alert(
        attack_type, "HIGH", ts, src, dst, record.get("protocol", "TCP"),
        f"{src} contacted {len(ports)} different ports on {dst} in a rolling window.",
        f"Unique destination ports: {len(ports)}; threshold: {config.PORTSCAN_THRESHOLD} "
        f"in {config.PORTSCAN_WINDOW}s; ports: {sorted(ports)}; score: "
        f"{_count_score(len(ports), config.PORTSCAN_THRESHOLD)} / 100",
        "Investigate the source and restrict access to only required services.",
    )


def detect_port_scan(record):
    """Backward-compatible vertical scan detector."""
    return _detect_vertical_scan(record, "Port Scan")


def detect_vertical_port_scan(record):
    return _detect_vertical_scan(record, "Vertical Port Scan")


def detect_horizontal_port_scan(record):
    """Detect one source contacting the same port on many destinations."""
    src, dst, port, ts = (record.get("src_ip"), record.get("dst_ip"),
                           record.get("dst_port"), _timestamp(record))
    if not src or not dst or port in (None, "") or ts is None:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    events = horizontal_scan_state[(src, port)]
    events.append((ts, dst))
    _prune(events, ts, config.HORIZONTAL_SCAN_WINDOW)
    destinations = {item[1] for item in events}
    if (len(destinations) < config.HORIZONTAL_SCAN_THRESHOLD or
            not _cooldown_ready("horizontal_scan", (src, port), ts)):
        return None
    return _alert(
        "Horizontal Port Scan", "HIGH", ts, src, "Multiple",
        record.get("protocol", "TCP"),
        f"{src} contacted port {port} on {len(destinations)} destinations.",
        f"Unique destinations: {len(destinations)}; port: {port}; threshold: "
        f"{config.HORIZONTAL_SCAN_THRESHOLD} in {config.HORIZONTAL_SCAN_WINDOW}s; "
        f"score: {_count_score(len(destinations), config.HORIZONTAL_SCAN_THRESHOLD)} / 100",
        "Investigate the source and restrict east-west access to approved hosts.",
    )


def detect_beacon(record):
    """Detect regular repeated connections to one destination as a C2 heuristic."""
    src, dst, ts = record.get("src_ip"), record.get("dst_ip"), _timestamp(record)
    if not src or not dst or ts is None:
        return None
    key = (src, dst, record.get("dst_port", 0))
    events = beacon_state[key]
    events.append(ts)
    while events and ts - events[0] > config.BEACON_WINDOW:
        events.popleft()
    if len(events) < config.BEACON_MIN_EVENTS + 1:
        return None
    intervals = [events[i] - events[i - 1] for i in range(1, len(events))]
    if any(interval <= 0 for interval in intervals):
        return None
    average = sum(intervals) / len(intervals)
    jitter = max(abs(interval - average) for interval in intervals)
    if jitter > config.BEACON_TOLERANCE or not _cooldown_ready("beacon", key, ts):
        return None
    return _alert(
        "Beacon Detection", "MEDIUM", ts, src, dst, record.get("protocol", "TCP"),
        f"Regular repeated connections from {src} to {dst} resemble beaconing.",
        f"Intervals: {[round(value, 2) for value in intervals]}; average: {average:.2f}s; "
        f"jitter: {jitter:.2f}s; tolerance: {config.BEACON_TOLERANCE}s; score: "
        f"{min(100, 70 + len(intervals) * 5)} / 100",
        "Inspect the source process, destination reputation, and DNS history for C2 indicators.",
    )


def detect_data_exfiltration(record):
    """Detect large uploads and source-level upload anomalies."""
    src, dst, ts = (record.get("src_ip"), record.get("dst_ip", "Unknown"),
                    _timestamp(record))
    if not src or ts is None:
        return None
    try:
        uploaded = max(0, int(record.get("orig_bytes", 0)))
    except (TypeError, ValueError):
        return None
    history = exfil_state[src]
    average = sum(history) / len(history) if history else 0
    ratio = uploaded / average if average else 0
    is_static = uploaded >= config.UPLOAD_STATIC_THRESHOLD
    is_anomaly = (len(history) >= config.EXFIL_MIN_HISTORY and average > 0 and
                  ratio >= config.UPLOAD_HISTORICAL_MULTIPLIER)
    history.append(uploaded)
    if not (is_static or is_anomaly) or not _cooldown_ready("exfil", (src, dst), ts):
        return None
    reason = "static upload threshold" if is_static else "historical upload anomaly"
    return _alert(
        "Data Exfiltration", "HIGH", ts, src, dst, record.get("protocol", "TCP"),
        f"Outbound upload from {src} exceeded the {reason} evidence threshold.",
        f"Uploaded: {uploaded} bytes; historical average: {average:.1f} bytes; "
        f"ratio: {ratio:.2f}x; static threshold: {config.UPLOAD_STATIC_THRESHOLD}; "
        f"multiplier: {config.UPLOAD_HISTORICAL_MULTIPLIER}x",
        "Review the destination and transferred data, then isolate the host if the transfer is unauthorized.",
    )


def detect_weak_tls(record):
    """Detect old TLS versions or weak cipher names present in Zeek ssl.log."""
    version = str(record.get("version", "")).strip().upper()
    cipher = str(record.get("cipher", "")).strip().upper()
    ts = _timestamp(record)
    if ts is None:
        return None
    weak_versions = {"SSLV3", "TLSV10", "TLSV11", "TLS1.0", "TLS1.1"}
    weak_cipher_keywords = ("NULL", "RC4", "3DES", "DES-", "_DES", "MD5", "EXPORT", "ANON")
    weak_version = version in weak_versions or any(item in version for item in ("SSLV3", "TLSV10", "TLSV11"))
    weak_cipher = bool(cipher) and any(keyword in cipher for keyword in weak_cipher_keywords)
    key = (record.get("src_ip"), record.get("dst_ip"), version, cipher)
    if not (weak_version or weak_cipher) or not _cooldown_ready("weak_tls", key, ts):
        return None
    reasons = []
    if weak_version:
        reasons.append(f"protocol={version}")
    if weak_cipher:
        reasons.append(f"cipher={cipher}")
    return _alert(
        "Weak TLS Negotiation", "MEDIUM", ts, record.get("src_ip", "Unknown"),
        record.get("dst_ip", "Unknown"), "TLS",
        "TLS negotiation used a protocol or cipher marked weak by policy.",
        "; ".join(reasons),
        "Require TLS 1.2 or newer and disable legacy cipher suites where possible.",
    )


def _is_failed(record):
    return str(record.get("conn_state", "")).upper() in config.FAILED_CONN_STATES


def detect_failed_connections(record):
    """Detect a source-level spike in Zeek failed connection states."""
    src, ts = record.get("src_ip"), _timestamp(record)
    if not src or ts is None or not _is_failed(record):
        return None
    events = failed_conn_state[src]
    events.append((ts, record.get("dst_ip", ""), record.get("dst_port", 0)))
    _prune(events, ts, config.FAILED_CONN_WINDOW)
    count = len(events)
    if count < config.FAILED_CONN_THRESHOLD or not _cooldown_ready("failed", src, ts):
        return None
    return _alert(
        "Failed Connection Spike", "MEDIUM", ts, src, "Multiple", record.get("protocol", "TCP"),
        f"{src} generated a spike of failed network connections.",
        f"Failed connections: {count}; states: {sorted(config.FAILED_CONN_STATES)}; "
        f"threshold: {config.FAILED_CONN_THRESHOLD} in {config.FAILED_CONN_WINDOW}s; "
        f"score: {_count_score(count, config.FAILED_CONN_THRESHOLD)} / 100",
        "Investigate for scanning or repeated service access and apply rate limiting as appropriate.",
    )


def detect_connection_flood(record):
    """Detect a high rate of short-lived connections."""
    src, ts = record.get("src_ip"), _timestamp(record)
    if not src or ts is None:
        return None
    try:
        duration = float(record.get("duration", 0.0))
    except (TypeError, ValueError):
        return None
    if duration >= config.FLOOD_DURATION_THRESHOLD:
        return None
    events = flood_state[src]
    events.append((ts, record.get("dst_ip", ""), _is_failed(record)))
    _prune(events, ts, config.FLOOD_WINDOW)
    count = len(events)
    failed = sum(1 for item in events if item[2])
    if count < config.FLOOD_THRESHOLD or not _cooldown_ready("flood", src, ts):
        return None
    return _alert(
        "Connection Flood", "HIGH", ts, src, "Multiple", record.get("protocol", "TCP"),
        f"{src} created many short-lived connections in a rolling window.",
        f"Short-lived connections: {count}; failed states: {failed}; duration threshold: "
        f"{config.FLOOD_DURATION_THRESHOLD}s; threshold: {config.FLOOD_THRESHOLD} "
        f"in {config.FLOOD_WINDOW}s; score: {_count_score(count, config.FLOOD_THRESHOLD)} / 100",
        "Rate-limit the source and investigate whether the traffic targets a service under stress.",
    )


def detect_ssh_bruteforce(record):
    """Detect repeated SSH attempts; never asserts password failure."""
    src, dst, ts = record.get("src_ip"), record.get("dst_ip"), _timestamp(record)
    try:
        is_ssh = int(record.get("dst_port")) == 22 or str(record.get("service", "")).lower() == "ssh"
    except (TypeError, ValueError):
        is_ssh = str(record.get("service", "")).lower() == "ssh"
    if not src or not dst or ts is None or not is_ssh:
        return None
    events = ssh_state[(src, dst)]
    events.append((ts, _is_failed(record)))
    _prune(events, ts, config.SSH_WINDOW)
    attempts = len(events)
    failed = sum(1 for item in events if item[1])
    if attempts < config.SSH_ATTEMPT_THRESHOLD or not _cooldown_ready("ssh", (src, dst), ts):
        return None
    return _alert(
        "SSH Brute Force / Repeated Attempts", "HIGH", ts, src, dst, "TCP",
        f"Repeated SSH connection attempts from {src} to {dst} were observed.",
        f"SSH attempts: {attempts}; attempts with Zeek failed states: {failed}; "
        f"threshold: {config.SSH_ATTEMPT_THRESHOLD} in {config.SSH_WINDOW}s. "
        "This is network evidence and does not prove password failures.",
        "Verify account activity on the SSH host and apply SSH rate limits or source restrictions.",
    )


def detect_connection_burst(record):
    """Detect repeated suspicious connections to one endpoint and port."""
    src, dst, ts = record.get("src_ip"), record.get("dst_ip"), _timestamp(record)
    if not src or not dst or ts is None:
        return None
    try:
        duration = float(record.get("duration", 0.0) or 0.0)
    except (TypeError, ValueError):
        return None
    suspicious = _is_failed(record) or duration < config.BURST_SHORT_DURATION
    if not suspicious:
        return None
    key = (src, dst, record.get("dst_port", 0))
    events = burst_state[key]
    events.append(ts)
    _prune(events, ts, config.BURST_WINDOW)
    count = len(events)
    if count < config.BURST_THRESHOLD or not _cooldown_ready("burst", key, ts):
        return None
    return _alert(
        "Suspicious Connection Burst", "MEDIUM", ts, src, dst, record.get("protocol", "TCP"),
        f"Repeated short-lived or failed connections from {src} to {dst} were observed.",
        f"Suspicious connections: {count}; threshold: {config.BURST_THRESHOLD} in "
        f"{config.BURST_WINDOW}s; destination port: {record.get('dst_port')}; score: "
        f"{_count_score(count, config.BURST_THRESHOLD)} / 100",
        "Review the target service and source process; rate-limit if the pattern is unauthorized.",
    )


def detect_service_port_abuse(record):
    """Detect repeated failed sensitive-port access or service/port mismatch."""
    src, dst, ts = record.get("src_ip"), record.get("dst_ip"), _timestamp(record)
    if not src or not dst or ts is None:
        return None
    try:
        port = int(record.get("dst_port"))
    except (TypeError, ValueError):
        return None
    service = str(record.get("service", "")).lower()
    expected = config.SERVICE_PORTS.get(service)
    mismatch = bool(service and expected and port not in expected)
    sensitive = port in config.SENSITIVE_SERVICE_PORTS
    key = (src, dst, port)
    if not (mismatch or (sensitive and _is_failed(record))):
        return None
    events = service_abuse_state[key]
    events.append((ts, mismatch, _is_failed(record)))
    _prune(events, ts, config.SERVICE_ABUSE_WINDOW)
    mismatches = sum(1 for item in events if item[1])
    failed = sum(1 for item in events if item[2])
    enough = (mismatches >= config.SERVICE_MISMATCH_THRESHOLD if mismatch
              else failed >= config.SERVICE_ABUSE_THRESHOLD)
    if not enough or not _cooldown_ready("service_abuse", key, ts):
        return None
    detail = (f"service={service}, observed_port={port}, expected_ports={expected}"
              if mismatch else f"failed attempts={failed}, sensitive_port={port}")
    return _alert(
        "Service/Port Abuse", "MEDIUM", ts, src, dst, record.get("protocol", "TCP"),
        f"Repeated suspicious access to a service port was observed from {src}.",
        f"{detail}; threshold window: {config.SERVICE_ABUSE_WINDOW}s; score: "
        f"{_count_score(max(mismatches, failed), config.SERVICE_ABUSE_THRESHOLD)} / 100",
        "Confirm the service is expected on that port and restrict or rate-limit unauthorized access.",
    )


def detect_ip_spoofing(record):
    """Flag only obvious invalid source addresses; this is explicitly heuristic."""
    src, dst, ts = record.get("src_ip"), record.get("dst_ip"), _timestamp(record)
    if not src or not dst or ts is None:
        return None
    try:
        source = ipaddress.ip_address(src)
        destination = ipaddress.ip_address(dst)
    except ValueError:
        reason = f"Source IP '{src}' is not a valid IP address."
    else:
        reason = None
        if source.version == 4:
            if source.is_unspecified:
                reason = "Unspecified IPv4 address used as source (0.0.0.0)."
            elif source == ipaddress.IPv4Address("255.255.255.255") or source.is_multicast:
                reason = "Broadcast or multicast IPv4 address used as source."
            elif source.is_loopback and not destination.is_loopback:
                reason = "Loopback IPv4 address communicating with a non-loopback destination."
        elif source.is_unspecified:
            reason = "Unspecified IPv6 address used as source (::)."
    if reason is None or not _cooldown_ready("spoof", src, ts):
        return None
    return _alert(
        "IP Spoofing (Heuristic)", "MEDIUM", ts, src, dst, record.get("protocol", "Unknown"),
        reason,
        "Zeek conn.log lacks ARP/MAC/TTL/interface data, so this is a heuristic and cannot confirm spoofing.",
        "Validate with ARP/DHCP, switch CAM, routing, or packet-capture evidence before blocking.",
    )
