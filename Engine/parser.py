# parser.py
# Parses Zeek conn.log and ssl.log entries into standard Python dictionaries

import utils

# Module-level state to track the active headers dynamically from the log stream.
# This ensures that even if Zeek shifts the fields around, we parse them correctly.
_conn_headers = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history"
]

_ssl_headers = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "version", "cipher", "curve", "server_name", "resumed"
]

def parse_conn(line):
    """
    Parses a single line from conn.log.
    Returns a dict with normalized fields, or None if it's a comment/header line.
    """
    global _conn_headers
    line = line.strip()
    if not line:
        return None
    
    # Handle headers
    if line.startswith("#"):
        if line.startswith("#fields"):
            # Update the headers dynamically
            parts = line.split()
            # The first element is '#fields', the rest are the field names
            _conn_headers = parts[1:]
            utils.debug_log(f"Parsed conn.log headers: {_conn_headers}")
        return None

    # Split fields (Zeek logs are tab-separated, but we fallback to space-split)
    parts = line.split('\t')
    if len(parts) == 1:
        parts = line.split()
        
    if len(parts) < min(len(_conn_headers), 5):
        # Line doesn't look like a valid data line
        return None

    # Zip headers and parts into a dictionary
    record = {}
    for i, field in enumerate(_conn_headers):
        if i < len(parts):
            val = parts[i]
            # Replace Zeek '-' placeholder with empty string or standard default
            record[field] = "" if val == "-" else val
        else:
            record[field] = ""

    # Map to the target format
    parsed = {
        "timestamp": float(record.get("ts")) if record.get("ts") else 0.0,
        "src_ip": record.get("id.orig_h", ""),
        "dst_ip": record.get("id.resp_h", ""),
        "src_port": int(record.get("id.orig_p")) if record.get("id.orig_p") else 0,
        "dst_port": int(record.get("id.resp_p")) if record.get("id.resp_p") else 0,
        "protocol": record.get("proto", ""),
        "service": record.get("service", ""),
        "duration": float(record.get("duration")) if record.get("duration") else 0.0,
        "orig_bytes": int(record.get("orig_bytes")) if record.get("orig_bytes") else 0,
        "resp_bytes": int(record.get("resp_bytes")) if record.get("resp_bytes") else 0,
        "conn_state": record.get("conn_state", ""),
        "history": record.get("history", "")
    }
    return parsed

def parse_ssl(line):
    """
    Parses a single line from ssl.log.
    Returns a dict with normalized fields, or None if it's a comment/header line.
    """
    global _ssl_headers
    line = line.strip()
    if not line:
        return None
        
    # Handle headers
    if line.startswith("#"):
        if line.startswith("#fields"):
            parts = line.split()
            _ssl_headers = parts[1:]
            utils.debug_log(f"Parsed ssl.log headers: {_ssl_headers}")
        return None

    # Split fields
    parts = line.split('\t')
    if len(parts) == 1:
        parts = line.split()
        
    if len(parts) < min(len(_ssl_headers), 5):
        return None

    # Zip headers and parts
    record = {}
    for i, field in enumerate(_ssl_headers):
        if i < len(parts):
            val = parts[i]
            record[field] = "" if val == "-" else val
        else:
            record[field] = ""

    # Map to the target format
    parsed = {
        "timestamp": float(record.get("ts")) if record.get("ts") else 0.0,
        "src_ip": record.get("id.orig_h", ""),
        "dst_ip": record.get("id.resp_h", ""),
        "src_port": int(record.get("id.orig_p")) if record.get("id.orig_p") else 0,
        "dst_port": int(record.get("id.resp_p")) if record.get("id.resp_p") else 0,
        "version": record.get("version", ""),
        "cipher": record.get("cipher", ""),
        "server_name": record.get("server_name", "")
    }
    return parsed
