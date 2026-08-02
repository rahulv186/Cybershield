# utils.py
# Helper utilities for debugging and formatting console outputs

import time
import config
import requests

BACKEND_URL = "http://localhost:5050"

def debug_log(message):
    """
    Prints a debug message to console if DEBUG is enabled in config.py.
    """
    if config.DEBUG:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[\033[94mDEBUG\033[0m] [{timestamp}] {message}")

def upload_threat(threat):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/threats",
                json=threat,
            timeout=5
        )

        response.raise_for_status()

        print("✅ Threat uploaded successfully.")
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to upload threat: {e}")
        return None


def format_alert(alert):
    """
    Prints a beautiful, highly-visible console alert for a detected threat.
    
    Expected alert structure:
    {
        "attack_type": str,
        "severity": str,
        "timestamp": str or float,
        "source_ip": str,
        "destination_ip": str,
        "description": str,
        "evidence": str,
        "recommendation": str
    }
    """
    severity = alert.get("severity", "INFO").upper()

    # print(alert)

    upload_threat(alert)
    
    # ANSI color codes for prettier outputs
    if severity == "HIGH":
        color_code = "\033[91m"  # Light Red
    elif severity == "MEDIUM":
        color_code = "\033[93m"  # Light Yellow
    else:
        color_code = "\033[92m"  # Light Green
    reset_code = "\033[0m"



    
    print("\n" + "=" * 50)
    print(f"🚨 {color_code}THREAT DETECTED{reset_code}")
    print("-" * 50)
    print(f"%-15s: {color_code}%s{reset_code}" % ("Attack Type", alert.get("attack_type")))
    print(f"%-15s: {color_code}%s{reset_code}" % ("Severity", severity))
    print(f"%-15s: %s" % ("Time", alert.get("timestamp")))
    print(f"%-15s: %s" % ("Source", alert.get("source_ip")))
    print(f"%-15s: %s" % ("Destination", alert.get("destination_ip")))
    print(f"%-15s: %s" % ("Protocol", alert.get("protocol")))
    print(f"%-15s: %s" % ("Description", alert.get("description")))
    print(f"%-15s: %s" % ("Evidence", alert.get("evidence")))
    print(f"%-15s: \033[96m%s\033[0m" % ("Recommendation", alert.get("recommendation")))
    print("=" * 50 + "\n")
