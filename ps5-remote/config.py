"""
PS5 Remote Control — Configuration
"""
import os
import json
import platform

DEFAULT_CONFIG = {
    "ps5_ip": "10.0.0.50",
    "ps5_mac": "00:00:00:00:00:00",
    "capture_device": "auto",
    "screenshot_interval": 2.0,
    "api_port": 8888,
    "api_host": "0.0.0.0",
    "game_title_id": "",
    "crash_timeout": 30,
    "freeze_timeout": 15,
    "probe_port": 9026,
    "dns_server": "10.0.0.80",
    "dualsense_usb": True,
    "screenshot_dir": "screenshots",
    "log_file": "ps5_remote.log",
}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    cfg["platform"] = platform.system().lower()
    return cfg


def save_config(cfg):
    out = {k: v for k, v in cfg.items() if k != "platform"}
    with open(CONFIG_PATH, "w") as f:
        json.dump(out, f, indent=2)


def interactive_setup():
    cfg = load_config()
    print("=== PS5 Remote Control Setup ===\n")
    cfg["ps5_ip"] = input(f"PS5 IP address [{cfg['ps5_ip']}]: ").strip() or cfg["ps5_ip"]
    cfg["ps5_mac"] = input(f"PS5 MAC address [{cfg['ps5_mac']}]: ").strip() or cfg["ps5_mac"]
    cfg["probe_port"] = int(input(f"Probe port [{cfg['probe_port']}]: ").strip() or cfg["probe_port"])
    cfg["api_port"] = int(input(f"API port [{cfg['api_port']}]: ").strip() or cfg["api_port"])
    save_config(cfg)
    print(f"\nConfig saved to {CONFIG_PATH}")
    return cfg
