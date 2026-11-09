"""
PS5 Power Control — Wake-on-LAN and power state detection.

Wake-on-LAN works when PS5 is in Rest Mode with "Stay Connected to the Internet" enabled.
"""
import socket
import struct
import subprocess
import platform
import time
import logging

log = logging.getLogger("ps5remote.power")


def send_wol(mac_address, broadcast="255.255.255.255", port=9):
    mac = mac_address.replace(":", "").replace("-", "")
    if len(mac) != 12:
        log.error(f"Invalid MAC: {mac_address}")
        return False
    mac_bytes = bytes.fromhex(mac)
    magic = b'\xFF' * 6 + mac_bytes * 16

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic, (broadcast, port))
        sock.close()
        log.info(f"WOL packet sent to {mac_address}")
        return True
    except Exception as e:
        log.error(f"WOL failed: {e}")
        return False


def is_ps5_reachable(ip, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 9295))
        sock.close()
        if result == 0:
            return True
        result = subprocess.run(
            ["ping", "-c", "1", "-t", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return result.returncode == 0
    except Exception:
        return False


def is_probe_port_open(ip, port=9026, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def is_chiaki_port_open(ip, timeout=3):
    for port in [9295, 9296, 9297]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


def get_ps5_state(ip, probe_port=9026):
    if not is_ps5_reachable(ip):
        return "off"
    if is_chiaki_port_open(ip):
        if is_probe_port_open(ip, probe_port):
            return "game_running"
        return "awake"
    return "rest_mode"


def wake_ps5(ip, mac, max_wait=60):
    state = get_ps5_state(ip)
    if state in ("awake", "game_running"):
        log.info(f"PS5 already awake (state={state})")
        return True

    log.info("Sending Wake-on-LAN...")
    for _ in range(3):
        send_wol(mac)
        time.sleep(1)

    start = time.time()
    while time.time() - start < max_wait:
        if is_ps5_reachable(ip):
            log.info("PS5 is responding to ping")
            time.sleep(5)
            if is_chiaki_port_open(ip):
                log.info("PS5 fully awake")
                return True
        time.sleep(3)

    log.warning("PS5 did not wake within timeout")
    return False
