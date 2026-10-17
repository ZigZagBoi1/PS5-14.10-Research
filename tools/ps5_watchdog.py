#!/usr/bin/env python3
"""PS5 reboot watchdog — detects kernel panics during fuzzing campaigns.

Usage:
    PYTHONIOENCODING=utf-8 python tools/ps5_watchdog.py [--ps5-ip 10.0.0.96] [--port 9026]
        [--interval 5] [--duration 0] [--log results/watchdog_log.txt] [--ping]

Polls the PS5's Lua loader port every --interval seconds and classifies the
console state:

    ALIVE        TCP connect to ip:port succeeds (loader accepting).
    LOADER_DOWN  Ping succeeds but the port refuses/times out (loader dead or
                 game not running; process kill, recoverable by relaunch).
    REBOOTING    Ping fails too — the console is rebooting. This is the panic
                 signal: a kernel bug was hit.
    UNKNOWN      No ping configured and the port is unreachable; can't
                 distinguish reboot from loader-down.

State changes are printed and appended to the log with timestamps, e.g.:
    2026-10-16 21:00:05 STATE ALIVE->REBOOTING (host unreachable)

A REBOOTING event is the strongest possible fuzzing signal: the packet sent
immediately before it is the prime replay candidate. Log the last-sent probe
from the campaign terminal alongside the watchdog timestamps.
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

STATE_ALIVE = "ALIVE"
STATE_LOADER_DOWN = "LOADER_DOWN"
STATE_REBOOTING = "REBOOTING"
STATE_UNKNOWN = "UNKNOWN"

# Windows ping: -n count, -w timeout in milliseconds. Linux would need
# -c/-W, but this project runs on a Windows host.
PING_ARGS = ["ping", "-n", "1", "-w", "1000", "{ip}"]


def tcp_alive(ip, port, timeout=3.0):
    """True if a TCP connection to ip:port completes, False otherwise."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ping_ok(ip):
    """True if the host answers ICMP echo (Windows 'ping -n 1 -w 1000')."""
    try:
        result = subprocess.run(
            [a.format(ip=ip) for a in PING_ARGS],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def classify(ip, port, use_ping):
    """Classify console state. Returns (state, detail)."""
    port_open = tcp_alive(ip, port)
    if port_open:
        return STATE_ALIVE, "port %d accepts" % port

    if not use_ping:
        return STATE_UNKNOWN, "no ping option, port %d refused/timeout" % port

    if ping_ok(ip):
        return STATE_LOADER_DOWN, "host reachable, port %d refused/timeout" % port
    return STATE_REBOOTING, "host unreachable"


def log_line(log_path, line):
    """Append one line to the log file, creating the directory if needed."""
    directory = os.path.dirname(log_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def emit(log_path, message):
    """Print a message and append it to the log with a timestamp."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "%s %s" % (stamp, message)
    print(line, flush=True)
    log_line(log_path, line)


def main():
    parser = argparse.ArgumentParser(description="PS5 reboot watchdog (kernel panic detector)")
    parser.add_argument("--ps5-ip", default="10.0.0.96", help="PS5 IP (default: 10.0.0.96)")
    parser.add_argument("--port", type=int, default=9026, help="Lua loader port (default: 9026)")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between checks (default: 5)")
    parser.add_argument("--duration", type=float, default=0, help="Run for N seconds, 0 = infinite (default: 0)")
    parser.add_argument("--log", default=os.path.join("results", "watchdog_log.txt"),
                        help="Log file path (default: results/watchdog_log.txt)")
    parser.add_argument("--ping", action="store_true",
                        help="Enable ICMP ping fallback to distinguish reboot from loader-down")
    args = parser.parse_args()

    emit(args.log, "WATCHDOG START ip=%s port=%d interval=%ss duration=%s ping=%s log=%s"
         % (args.ps5_ip, args.port, args.interval, "inf" if args.duration <= 0 else args.duration,
            args.ping, args.log))

    state = None
    start = time.time()
    exit_code = 0
    try:
        while True:
            new_state, detail = classify(args.ps5_ip, args.port, args.ping)
            if new_state != state:
                emit(args.log, "STATE %s->%s (%s)"
                     % (state if state else "START", new_state, detail))
                state = new_state
            if args.duration > 0 and (time.time() - start) >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        emit(args.log, "WATCHDOG STOP (Ctrl+C after %.0fs)" % (time.time() - start))
    except Exception as exc:  # unexpected — still log it
        emit(args.log, "WATCHDOG ERROR %r" % (exc,))
        exit_code = 1
    else:
        emit(args.log, "WATCHDOG DONE (%.0fs)" % (time.time() - start))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
