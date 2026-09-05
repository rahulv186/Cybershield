# main.py
# Main driver script that coordinates the watcher, parser, detectors, and prevention

import threading
import time
import os

import config
import watcher
import parser
import detectors
import prevention
import utils


def monitor_conn():
    """
    Tails and processes new entries in the conn.log file.
    """

    utils.debug_log(
        f"Starting conn.log monitor thread on: {config.CONN_LOG_PATH}"
    )

    for line in watcher.tail_file(config.CONN_LOG_PATH):

        try:
            # Parse Zeek conn.log line
            record = parser.parse_conn(line)

            if not record:
                continue

            if config.DEBUG:
                utils.debug_log(
                    f"Processed conn.log record: {record}"
                )

            # Store all generated alerts
            alerts = []

            # 1. DDoS Detection
            alert = detectors.detect_ddos(record)
            if alert:
                alerts.append(alert)

            # 2. Port Scan Detection
            alert = detectors.detect_port_scan(record)
            if alert:
                alerts.append(alert)

            # 3. Beacon Detection
            alert = detectors.detect_beacon(record)
            if alert:
                alerts.append(alert)

            # 4. Data Exfiltration Detection
            alert = detectors.detect_data_exfiltration(record)
            if alert:
                alerts.append(alert)

            # 6. Suspicious Failed Connections
            alert = detectors.detect_failed_connections(record)
            if alert:
                alerts.append(alert)

            # 7. Connection Flood
            alert = detectors.detect_connection_flood(record)
            if alert:
                alerts.append(alert)

            # 8. IP Spoofing Heuristic
            alert = detectors.detect_ip_spoofing(record)
            if alert:
                alerts.append(alert)

            # --------------------------------------------------
            # Process generated alerts
            # --------------------------------------------------

            for a in alerts:

                try:
                    utils.format_alert(a)

                    print(
                        f"[DEBUG] Attack type: "
                        f"{repr(a.get('attack_type'))}"
                    )

                    print(
                        f"[DEBUG] Source IP: "
                        f"{a.get('source_ip')}"
                    )

                    # Threats that should trigger prevention
                    if a.get("attack_type") in [
                        "DDoS Attack",
                        "Port Scan",
                        "Connection Flood",
                        "IP Spoofing (Heuristic Check)",
                    ]:

                        print("[DEBUG] Calling block_ip()")

                        reason = {
                            "attack_type": a.get("attack_type"),
                            "timestamp": a.get("detectedAt"),
                            "protocol": a.get("protocol"),
                            "description": a.get("description"),
                            "evidence": a.get("evidence"),
                        }

                        prevention.block_ip(
                            a.get("source_ip"),
                            reason
                        )

                        print("[DEBUG] block_ip() returned")

                    else:
                        print(
                            "[DEBUG] Alert does not require "
                            "automatic blocking"
                        )

                except Exception as e:

                    utils.debug_log(
                        f"Error processing alert: {e}"
                    )

        except Exception as e:

            utils.debug_log(
                f"Error in conn.log monitor: {e}"
            )


def monitor_ssl():
    """
    Tails and processes new entries in the ssl.log file.
    """

    utils.debug_log(
        f"Starting ssl.log monitor thread on: {config.SSL_LOG_PATH}"
    )

    for line in watcher.tail_file(config.SSL_LOG_PATH):

        try:
            # Parse Zeek SSL log line
            record = parser.parse_ssl(line)

            if not record:
                continue

            if config.DEBUG:
                utils.debug_log(
                    f"Processed ssl.log record: {record}"
                )

            # 5. Weak TLS Detection
            alert = detectors.detect_weak_tls(record)

            if alert:

                utils.format_alert(alert)

                # Weak TLS is logged but does not automatically
                # block the source IP.
                #
                # Reason:
                # Weak TLS negotiation is generally a security
                # weakness rather than an active attack.

        except Exception as e:

            utils.debug_log(
                f"Error in ssl.log monitor: {e}"
            )


def main():

    print("=" * 60)
    print("🚀 REDESIGNED PYTHON DETECTION ENGINE STARTED")

    print(
        f"Simulation Mode : "
        f"{config.SIMULATION_MODE}"
    )

    print(
        f"Debug Mode      : "
        f"{config.DEBUG}"
    )

    print("=" * 60)

    # --------------------------------------------------
    # Initialize log files if they don't exist
    # --------------------------------------------------

    for path in [
        config.CONN_LOG_PATH,
        config.SSL_LOG_PATH
    ]:

        if not os.path.exists(path):

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as f:

                # Write a minimal Zeek-style header
                f.write(
                    f"#separator \\x09\n"
                    f"#path "
                    f"{os.path.basename(path).split('.')[0]}\n"
                )

            utils.debug_log(
                f"Initialized empty log file: {path}"
            )

    # --------------------------------------------------
    # Start monitor threads
    # --------------------------------------------------

    t_conn = threading.Thread(
        target=monitor_conn,
        name="ConnMonitor",
        daemon=True
    )

    t_ssl = threading.Thread(
        target=monitor_ssl,
        name="SSLMonitor",
        daemon=True
    )

    t_conn.start()
    t_ssl.start()

    # --------------------------------------------------
    # Keep main thread alive
    # --------------------------------------------------

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\nStopping Python Detection Engine. Goodbye!"
        )


if __name__ == "__main__":
    main()