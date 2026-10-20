#!/usr/bin/env python3
"""
PS5 Remote Control — Main entry point.

Usage:
  python run.py setup     — Interactive first-time setup
  python run.py loop      — Start the 24/7 autonomous loop
  python run.py api       — Start the REST API server
  python run.py both      — Start both the loop and API server
  python run.py status    — Check PS5 and Chiaki status
  python run.py wake      — Wake PS5 from rest mode
  python run.py screenshot — Take a single screenshot
"""
import sys
import os
import logging
import threading

sys.path.insert(0, os.path.dirname(__file__))

from config import load_config, interactive_setup


def cmd_setup():
    interactive_setup()


def cmd_status():
    from power.wake import get_ps5_state
    from capture.chiaki_manager import is_chiaki_running

    config = load_config()
    ps5 = get_ps5_state(config["ps5_ip"], config["probe_port"])
    chiaki = is_chiaki_running()
    print(f"PS5 ({config['ps5_ip']}): {ps5}")
    print(f"Chiaki: {'running' if chiaki else 'not running'}")
    print(f"Probe port {config['probe_port']}: {'open' if ps5 == 'game_running' else 'closed'}")


def cmd_wake():
    from power.wake import wake_ps5
    config = load_config()
    ok = wake_ps5(config["ps5_ip"], config["ps5_mac"])
    print("Wake:" + (" success" if ok else " failed"))


def cmd_screenshot():
    from capture.hdmi import take_screenshot
    path = os.path.join(os.path.dirname(__file__), "screenshots", "manual.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if take_screenshot(path):
        print(f"Screenshot saved: {path}")
    else:
        print("Screenshot failed — is Chiaki running?")


def cmd_loop():
    from loop.autonomous import main
    main()


def cmd_api():
    from api.server import start_server
    start_server()


def cmd_both():
    from loop.autonomous import AutonomousLoop
    from api.server import start_server

    config = load_config()
    loop = AutonomousLoop(config)

    loop_thread = threading.Thread(target=loop.run, daemon=True)
    loop_thread.start()

    print("Autonomous loop started in background")
    print("Starting API server...")
    start_server(config)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(os.path.dirname(__file__), "ps5_remote.log")),
        ]
    )

    commands = {
        "setup": cmd_setup,
        "loop": cmd_loop,
        "api": cmd_api,
        "both": cmd_both,
        "status": cmd_status,
        "wake": cmd_wake,
        "screenshot": cmd_screenshot,
    }

    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print(__doc__)
        sys.exit(0)

    commands[sys.argv[1]]()


if __name__ == "__main__":
    main()
