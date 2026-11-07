"""
PS5 Automated Recovery Tool
Detects game crashes and loader failures, automatically recovers.

States:
  READY    - Loader accepting connections and responding
  HUNG     - TCP connects but loader not responding
  CRASH    - "Game or App Error" dialog visible
  TITLE    - Game title screen (after dismissing crash)
  LOADING  - Black/loading screen (transitioning)
  UNKNOWN  - Can't determine state

Recovery:
  CRASH  -> Enter (dismiss dialog) -> wait 20s -> TITLE
  TITLE  -> Enter (relaunch)       -> wait 15s -> READY
  HUNG   -> user must restart game manually (not automated yet)
"""

import sys
import os
import time
import socket
import struct
import ctypes
from ctypes import wintypes
from PIL import Image, ImageGrab, ImageStat
import numpy as np

PS5_IP = "10.0.0.96"
PS5_PORT = 9026

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
SCREENSHOTS_DIR = os.path.join(PROJECT_DIR, "screenshots")

# Reference crops: (x1, y1, x2, y2) relative to Chiaki content area
# These regions distinguish the three states
# Crash dialog: "Game or App Error" text in upper-left quadrant
# Title screen: colorful anime art
# Loader: dark with white text center-right


def find_chiaki_window():
    FindWindowW = ctypes.windll.user32.FindWindowW
    GetWindowRect = ctypes.windll.user32.GetWindowRect
    IsWindowVisible = ctypes.windll.user32.IsWindowVisible
    EnumWindows = ctypes.windll.user32.EnumWindows
    GetWindowTextW = ctypes.windll.user32.GetWindowTextW
    GetWindowTextLengthW = ctypes.windll.user32.GetWindowTextLengthW

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    EnumWindows.restype = wintypes.BOOL
    GetWindowTextLengthW.argtypes = [wintypes.HWND]
    GetWindowTextLengthW.restype = ctypes.c_int
    GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    GetWindowTextW.restype = ctypes.c_int
    IsWindowVisible.argtypes = [wintypes.HWND]
    IsWindowVisible.restype = wintypes.BOOL

    result = [None]

    def callback(hwnd, lparam):
        length = GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
            if "chiaki" in title.lower() and IsWindowVisible(hwnd):
                result[0] = hwnd
                return False
        return True

    EnumWindows(WNDENUMPROC(callback), 0)
    return result[0]


def capture_chiaki():
    hwnd = find_chiaki_window()
    if hwnd is None:
        return None

    rect = wintypes.RECT()
    GetWindowRect = ctypes.windll.user32.GetWindowRect
    GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    GetWindowRect.restype = wintypes.BOOL
    GetWindowRect(hwnd, ctypes.byref(rect))

    bbox = (rect.left, rect.top, rect.right, rect.bottom)
    if bbox[2] - bbox[0] < 100 or bbox[3] - bbox[1] < 100:
        return None

    img = ImageGrab.grab(bbox)
    return img


def send_enter_via_vgamepad():
    try:
        import vgamepad as vg
        pad = vg.VX360Gamepad()
        time.sleep(0.1)
        pad.press_button(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
        pad.update()
        time.sleep(0.15)
        pad.release_button(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
        pad.update()
        time.sleep(0.1)
        del pad
        return True
    except Exception as e:
        print(f"  vgamepad failed: {e}")
        return False


def send_enter_via_keyboard():
    try:
        from pynput.keyboard import Key, Controller
        kb = Controller()

        hwnd = find_chiaki_window()
        if hwnd:
            SetForegroundWindow = ctypes.windll.user32.SetForegroundWindow
            SetForegroundWindow.argtypes = [wintypes.HWND]
            SetForegroundWindow.restype = wintypes.BOOL
            SetForegroundWindow(hwnd)
            time.sleep(0.3)

        kb.press(Key.enter)
        time.sleep(0.1)
        kb.release(Key.enter)
        return True
    except Exception as e:
        print(f"  keyboard failed: {e}")
        return False


def send_cross():
    if not send_enter_via_vgamepad():
        return send_enter_via_keyboard()
    return True


def check_tcp(timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((PS5_IP, PS5_PORT))

        probe = b'print("ALIVE")\n'
        header = struct.pack("<Q", len(probe))
        s.sendall(header + probe)

        s.settimeout(5.0)
        data = b""
        try:
            while len(data) < 64:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if b"ALIVE" in data:
                    break
        except socket.timeout:
            pass

        s.close()

        if b"ALIVE" in data:
            return "READY"
        elif len(data) > 0:
            return "READY"
        else:
            return "HUNG"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "DOWN"


def classify_screenshot(img):
    if img is None:
        return "UNKNOWN"

    w, h = img.size

    # Skip title bar area (~30px), analyze content
    content = img.crop((0, 30, w, h))
    cw, ch = content.size

    arr = np.array(content, dtype=np.float32)

    # Overall brightness
    mean_brightness = arr.mean()

    # Color variance (high = colorful like title screen)
    color_std = arr.std()

    # Check center region for text patterns
    cx1, cy1 = int(cw * 0.3), int(ch * 0.3)
    cx2, cy2 = int(cw * 0.7), int(ch * 0.7)
    center = arr[cy1:cy2, cx1:cx2]
    center_brightness = center.mean()

    # Check upper portion for the crash dialog gradient
    upper = arr[0:int(ch * 0.35), :]
    upper_brightness = upper.mean()

    # Check for "OK" button region at bottom center
    bx1 = int(cw * 0.3)
    bx2 = int(cw * 0.7)
    by1 = int(ch * 0.8)
    by2 = int(ch * 0.95)
    bottom = arr[by1:by2, bx1:bx2]
    bottom_brightness = bottom.mean()

    # Check how much white text is in center (loader screen has white text on dark)
    white_pixels = np.sum(center > 200) / center.size

    # Crash dialog: gradient upper area (bright 40-80), dark lower, "OK" button visible
    # Upper area has the gradient (brighter than pure black)
    if upper_brightness > 30 and upper_brightness < 100 and center_brightness > 20:
        if bottom_brightness > 15:
            return "CRASH"

    # Title screen: very colorful, high brightness, high variance
    if mean_brightness > 60 and color_std > 50:
        return "TITLE"

    # Loader ready: mostly dark, some white text in center-right
    if mean_brightness < 30 and white_pixels > 0.001:
        return "LOADER"

    # Mostly black = loading/transitioning
    if mean_brightness < 10:
        return "LOADING"

    return "UNKNOWN"


def classify_with_reference(img):
    """Compare against saved reference screenshots using histogram similarity."""
    if img is None:
        return "UNKNOWN", 0.0

    refs = {
        "CRASH": os.path.join(SCREENSHOTS_DIR, "restart_01.png"),
        "TITLE": os.path.join(SCREENSHOTS_DIR, "restart_78.png"),
        "LOADER": os.path.join(SCREENSHOTS_DIR, "restart_80.png"),
    }

    # Resize input to standard size for comparison
    img_small = img.resize((200, 200))
    img_hist = img_small.histogram()

    best_state = "UNKNOWN"
    best_score = float('inf')

    for state, path in refs.items():
        if not os.path.exists(path):
            continue
        ref = Image.open(path).resize((200, 200))
        ref_hist = ref.histogram()

        # Chi-squared histogram distance
        dist = sum((a - b) ** 2 / (a + b + 1e-10) for a, b in zip(img_hist, ref_hist))

        if dist < best_score:
            best_score = dist
            best_state = state

    confidence = max(0, 1.0 - best_score / 500000)
    return best_state, confidence


def detect_state():
    tcp_state = check_tcp()

    if tcp_state == "READY":
        return "READY", 1.0

    img = capture_chiaki()
    if img is None:
        return tcp_state, 0.5

    visual_state, confidence = classify_with_reference(img)

    if tcp_state == "HUNG":
        return "HUNG", confidence

    # TCP is DOWN, use visual
    return visual_state, confidence


def recover(state, verbose=True):
    if state == "READY":
        if verbose:
            print("  Loader is ready, nothing to do")
        return True

    if state == "CRASH":
        if verbose:
            print("  Crash detected -> sending Enter to dismiss...")
        send_cross()
        if verbose:
            print("  Waiting 20s for title screen...")
        time.sleep(20)

        if verbose:
            print("  Sending Enter to relaunch...")
        send_cross()
        if verbose:
            print("  Waiting 15s for loader...")
        time.sleep(15)

        new_state = check_tcp()
        if new_state == "READY":
            if verbose:
                print("  Recovery SUCCESSFUL - loader is ready!")
            return True
        else:
            if verbose:
                print(f"  Recovery incomplete, TCP state: {new_state}")
            return False

    if state == "TITLE":
        if verbose:
            print("  Title screen -> sending Enter to relaunch...")
        send_cross()
        if verbose:
            print("  Waiting 15s for loader...")
        time.sleep(15)

        new_state = check_tcp()
        if new_state == "READY":
            if verbose:
                print("  Recovery SUCCESSFUL!")
            return True
        else:
            if verbose:
                print(f"  Recovery incomplete, TCP state: {new_state}")
            return False

    if state == "LOADING":
        if verbose:
            print("  Loading/transitioning, waiting 10s...")
        time.sleep(10)
        return False

    if state == "HUNG":
        if verbose:
            print("  Loader is hung (TCP connects, no response)")
            print("  Manual restart required (not yet automated)")
        return False

    if verbose:
        print(f"  Unknown state: {state}")
    return False


def monitor_loop(interval=10, max_recoveries=5):
    print(f"PS5 Recovery Monitor - checking every {interval}s")
    print(f"Target: {PS5_IP}:{PS5_PORT}")
    print("")

    recovery_count = 0

    while True:
        state, conf = detect_state()
        ts = time.strftime("%H:%M:%S")

        if state == "READY":
            print(f"[{ts}] READY (conf={conf:.2f})")
        else:
            print(f"[{ts}] {state} (conf={conf:.2f})")

            if state in ("CRASH", "TITLE", "LOADING"):
                recovery_count += 1
                if recovery_count > max_recoveries:
                    print(f"  Hit max recoveries ({max_recoveries}), stopping")
                    break

                print(f"  Attempting recovery #{recovery_count}...")
                success = recover(state)
                if success:
                    print(f"  Recovered! Resuming monitoring.")
                    recovery_count = 0
            elif state == "HUNG":
                print(f"  Hung loader - manual intervention needed")

        time.sleep(interval)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PS5 Recovery Tool")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("check", help="Check current PS5 state")
    sub.add_parser("recover", help="Attempt one recovery")

    mon = sub.add_parser("monitor", help="Continuous monitoring loop")
    mon.add_argument("--interval", type=int, default=10)
    mon.add_argument("--max-recoveries", type=int, default=5)

    sub.add_parser("screenshot", help="Save current Chiaki screenshot")
    sub.add_parser("calibrate", help="Show detection values for reference screenshots")

    args = parser.parse_args()

    if args.cmd == "check" or args.cmd is None:
        print("Checking PS5 state...")
        state, conf = detect_state()
        print(f"State: {state} (confidence: {conf:.2f})")

        tcp = check_tcp()
        print(f"TCP: {tcp}")

        img = capture_chiaki()
        if img:
            vis, vc = classify_with_reference(img)
            print(f"Visual: {vis} (confidence: {vc:.2f})")
        else:
            print("Visual: no Chiaki window found")

    elif args.cmd == "recover":
        state, conf = detect_state()
        print(f"Current state: {state} (conf={conf:.2f})")
        recover(state)

    elif args.cmd == "monitor":
        monitor_loop(args.interval, args.max_recoveries)

    elif args.cmd == "screenshot":
        img = capture_chiaki()
        if img:
            path = os.path.join(SCREENSHOTS_DIR, f"capture_{int(time.time())}.png")
            img.save(path)
            print(f"Saved to {path}")
        else:
            print("No Chiaki window found")

    elif args.cmd == "calibrate":
        print("Calibrating against reference screenshots...")
        for name, fname in [("CRASH", "restart_01.png"), ("TITLE", "restart_78.png"), ("LOADER", "restart_80.png")]:
            path = os.path.join(SCREENSHOTS_DIR, fname)
            if os.path.exists(path):
                img = Image.open(path)
                state, conf = classify_with_reference(img)
                arr = np.array(img, dtype=np.float32)
                print(f"  {name} ({fname}):")
                print(f"    brightness={arr.mean():.1f} std={arr.std():.1f}")
                print(f"    classified as: {state} (conf={conf:.2f})")
            else:
                print(f"  {name}: {fname} not found")


if __name__ == "__main__":
    main()
