"""Chiaki-ng control for PS5 UI recovery.

Wraps the existing chiaki_keys.py / chiaki_bridge.py infrastructure
to perform automated PS5 UI recovery sequences:
  - Dismiss crash dialog
  - Navigate to User Guide
  - Refresh current page
  - Close and reopen browser

CANNOT recover: kernel panic, hard freeze (no display output).
"""

import subprocess
import time
import os
from pathlib import Path


CHIAKI_KEYS = Path(__file__).parent.parent / "browser_runner" / "chiaki_keys.py"
CHIAKI_BRIDGE = Path(__file__).parent.parent / "browser_runner" / "chiaki_bridge.py"

# Key constants matching chiaki_keys.py / PostMessage protocol
KEY_CROSS = "cross"       # X button (confirm/select)
KEY_CIRCLE = "circle"     # O button (back)
KEY_TRIANGLE = "triangle"
KEY_SQUARE = "square"
KEY_UP = "up"
KEY_DOWN = "down"
KEY_LEFT = "left"
KEY_RIGHT = "right"
KEY_OPTIONS = "options"
KEY_PS = "ps"             # PS button (home)
KEY_L1 = "l1"
KEY_R1 = "r1"


def _run_key(key, hold_ms=100):
    """Send a single key press to the PS5 via Chiaki."""
    if CHIAKI_KEYS.exists():
        try:
            subprocess.run(
                ["python", str(CHIAKI_KEYS), key, str(hold_ms)],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            pass

    if CHIAKI_BRIDGE.exists():
        try:
            subprocess.run(
                ["python", str(CHIAKI_BRIDGE), "key", key],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            pass

    return False


def _run_sequence(keys, delay=0.5):
    """Send a sequence of key presses with delays between them."""
    results = []
    for key in keys:
        if isinstance(key, tuple):
            key_name, hold_ms = key
            ok = _run_key(key_name, hold_ms)
        else:
            ok = _run_key(key)
        results.append(ok)
        time.sleep(delay)
    return all(results)


def press_ps_button():
    """Press the PS button to return to home screen."""
    return _run_key(KEY_PS)


def dismiss_crash_dialog():
    """Dismiss a WebProcess crash dialog (press X to confirm)."""
    return _run_sequence([KEY_CROSS, KEY_CROSS], delay=1.0)


def navigate_to_userguide():
    """From home screen, navigate to Settings > User Guide.

    This is an approximate sequence — the exact path depends on
    which tile is focused when we start.
    """
    steps = [
        KEY_PS,          # Go to home
    ]
    _run_sequence(steps, delay=1.0)
    time.sleep(2.0)

    # Navigate to Settings (gear icon, typically far right on home bar)
    for _ in range(8):
        _run_key(KEY_RIGHT)
        time.sleep(0.3)
    _run_key(KEY_CROSS)
    time.sleep(2.0)

    # Scroll down to User Guide (near bottom of Settings)
    for _ in range(12):
        _run_key(KEY_DOWN)
        time.sleep(0.3)
    _run_key(KEY_CROSS)
    time.sleep(3.0)

    return True


def refresh_browser_page():
    """Refresh the current browser page using Options > Refresh."""
    _run_key(KEY_OPTIONS)
    time.sleep(1.0)
    # "Refresh" is typically the first or second item
    _run_key(KEY_CROSS)
    time.sleep(2.0)
    return True


def close_browser():
    """Close the browser app using PS button > Options > Close."""
    _run_key(KEY_PS)
    time.sleep(1.5)
    _run_key(KEY_OPTIONS)
    time.sleep(1.0)
    # "Close Application" in the quick menu
    _run_key(KEY_CROSS)
    time.sleep(2.0)
    return True


def reopen_userguide():
    """Full recovery: close browser, navigate back to user guide."""
    close_browser()
    time.sleep(3.0)
    navigate_to_userguide()
    return True


def check_chiaki_running():
    """Check if Chiaki-ng is running on this machine."""
    try:
        r = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq chiaki-ng.exe"],
            capture_output=True, text=True, timeout=5
        )
        return "chiaki-ng.exe" in r.stdout
    except Exception:
        return False


def attempt_recovery(failure_type):
    """Attempt recovery based on the failure type.

    Returns (recovered, action_taken).
    """
    if not check_chiaki_running():
        return False, "Chiaki not running"

    if failure_type == "JS_EXCEPTION":
        refresh_browser_page()
        return True, "Refreshed page"

    elif failure_type == "WEBPROCESS_CRASH":
        dismiss_crash_dialog()
        time.sleep(2.0)
        refresh_browser_page()
        return True, "Dismissed crash + refreshed"

    elif failure_type == "APP_FREEZE":
        reopen_userguide()
        return True, "Closed and reopened browser"

    elif failure_type == "CONSOLE_PANIC":
        return False, "Console panic — cannot recover via Chiaki"

    elif failure_type == "REMOTE_PLAY_DISCONNECT":
        return False, "Remote play disconnected — manual reconnection needed"

    return False, f"Unknown failure type: {failure_type}"


def health_check():
    """Return Chiaki health status."""
    running = check_chiaki_running()
    keys_exist = CHIAKI_KEYS.exists()
    bridge_exist = CHIAKI_BRIDGE.exists()

    return {
        "chiaki_running": running,
        "chiaki_keys": keys_exist,
        "chiaki_bridge": bridge_exist,
        "ready": running and (keys_exist or bridge_exist),
    }
