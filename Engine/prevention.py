# prevention.py
# Implements network level prevention actions for threats

import sys
import subprocess
import config
import utils

# Track blocked IPs globally to prevent duplicate actions
blocked_ips = set()
import requests

BACKEND_URL = "http://localhost:5050"


def upload_blocked_ip(ip, reason):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/blocked",
            json={
                "blockedIP": ip,
                "reason": reason
            },
            timeout=5
        )

        response.raise_for_status()

        print("✅ Blocked IP uploaded successfully.")
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to upload blocked IP: {e}")
        return None

def upload_unblocked_ip(ip):
    try:
        response = requests.delete(
            f"{BACKEND_URL}/api/blocked",
            json={
                "blockedIP": ip
            },
            timeout=5
        )

        response.raise_for_status()

        print(f"✅ Unblocked IP {ip} successfully.")
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to unblock IP {ip}: {e}")
        return None


def block_ip(ip, reason):
    """
    Blocks an IP address using system firewall commands or simulation.
    """
    print(f"block_ip() called with IP: {ip}")
    if not ip:
        return

    if ip in config.PROTECTED_IPS:
        utils.debug_log(f"IP {ip} is protected and cannot be blocked. Skipping.")
        return
    
    if ip in blocked_ips:
        utils.debug_log(f"IP {ip} is already blocked. Skipping.")
        return

    if config.SIMULATION_MODE:
        simulate_block(ip)
        blocked_ips.add(ip)
        upload_blocked_ip(ip, reason)
        return
    else:
        utils.debug_log(f"Attempting to block IP {ip} in Real Firewall Mode...")
        if sys.platform == "darwin":
            # macOS: blackhole routing rule is the simplest direct block command
            cmd = ["sudo", "route", "add", "-host", ip, "127.0.0.1", "-blackhole"]
            try:
                # We won't block main process execution if user rejects/cannot run sudo
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                utils.debug_log(f"Successfully blackholed traffic from {ip}")
                blocked_ips.add(ip)
                upload_blocked_ip(ip, reason)
            except Exception as e:
                utils.debug_log(f"Failed to add route block for {ip}: {e}. Ensure script is run as root/sudo.")
        elif sys.platform.startswith("linux"):
            # Linux: iptables
            cmd = ["sudo", "-n", "/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            try:
                subprocess.run(cmd, check=True)
                utils.debug_log(f"Successfully added iptables DROP rule for {ip}")
                blocked_ips.add(ip)
                upload_blocked_ip(ip, reason)
            except Exception as e:
                utils.debug_log(f"Failed to run iptables block for {ip}: {e}. Ensure script is run as root/sudo.")
        else:
            utils.debug_log(f"Real Firewall Mode blocking not implemented for OS: {sys.platform}")

def unblock_ip(ip):
    """
    Unblocks an IP address by removing firewall rules.
    """
    if not ip:
        return
    if ip not in blocked_ips:
        utils.debug_log(f"IP {ip} is not currently blocked. Skipping unblock.")
        return

    if config.SIMULATION_MODE:
        print(f"[SIMULATION] Unblocking IP: {ip}")
        blocked_ips.discard(ip)
    else:
        utils.debug_log(f"Attempting to unblock IP {ip} in Real Firewall Mode...")
        if sys.platform == "darwin":
            cmd = ["sudo", "route", "delete", "-host", ip, "127.0.0.1", "-blackhole"]
            try:
                subprocess.run(cmd, check=True)
                utils.debug_log(f"Successfully deleted blackhole route for {ip}")
                blocked_ips.discard(ip)
            except Exception as e:
                utils.debug_log(f"Failed to delete route block for {ip}: {e}")
        elif sys.platform.startswith("linux"):
            cmd = [
        "sudo", "-n",
        "/usr/sbin/iptables",
        "-D", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ]
            try:
                subprocess.run(cmd, check=True)
                utils.debug_log(f"Successfully deleted iptables rule for {ip}")
                blocked_ips.discard(ip)
            except Exception as e:
                utils.debug_log(f"Failed to delete iptables rule for {ip}: {e}")
        else:
            utils.debug_log(f"Real Firewall Mode unblocking not implemented for OS: {sys.platform}")

def simulate_block(ip):
    """
    Prints a simulated block message.
    """
    print(f"[SIMULATION] Blocking IP: {ip}")

def log_only(ip):
    """
    Logs the alert without taking blocking action.
    """
    print(f"[LOG ONLY] Alert triggered for IP: {ip} - No blocking action taken.")
