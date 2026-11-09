"""
Screen Capture — Background window capture of the Chiaki Remote Play window.

Uses screencapture -l <windowID> on Mac for zero-focus background capture.
Only takes screenshots on demand, no continuous streaming.
"""
import subprocess
import platform
import time
import os
import glob
import logging

log = logging.getLogger("ps5remote.capture")

_cached_window_id = None


def get_chiaki_window_id():
    global _cached_window_id
    system = platform.system().lower()

    if system == "darwin":
        result = subprocess.run(["swift", "-e", '''
import Cocoa
let options = CGWindowListOption(arrayLiteral: .excludeDesktopElements, .optionOnScreenOnly)
if let list = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] {
    for w in list {
        let name = w[kCGWindowOwnerName as String] as? String ?? ""
        if name.lowercased().contains("chiaki") {
            let wid = w[kCGWindowNumber as String] as? Int ?? 0
            if wid > 0 { print(wid); break }
        }
    }
}
'''], capture_output=True, text=True, timeout=10)
        wid = result.stdout.strip()
        if wid.isdigit():
            _cached_window_id = wid
            return wid

    elif system == "windows":
        try:
            import pygetwindow as gw
            wins = [w for w in gw.getAllWindows() if "chiaki" in w.title.lower()]
            if wins:
                _cached_window_id = str(wins[0]._hWnd)
                return _cached_window_id
        except ImportError:
            pass

    return _cached_window_id


def take_screenshot(output_path, device="auto", timeout=8):
    system = platform.system().lower()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if system == "darwin":
        wid = get_chiaki_window_id()
        if wid:
            cmd = ["screencapture", "-l", wid, "-x", output_path]
            try:
                subprocess.run(cmd, capture_output=True, timeout=timeout)
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    return True
            except Exception as e:
                log.error(f"screencapture failed: {e}")

        capture_script = f'do shell script "screencapture -x {output_path}"'
        try:
            subprocess.run(["osascript", "-e", capture_script], timeout=timeout)
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True
        except Exception:
            pass

    elif system == "windows":
        try:
            import pyautogui
            import pygetwindow as gw
            wins = [w for w in gw.getAllWindows() if "chiaki" in w.title.lower()]
            if wins:
                win = wins[0]
                img = pyautogui.screenshot(region=(win.left, win.top, win.width, win.height))
                img.save(output_path)
                return True
            img = pyautogui.screenshot()
            img.save(output_path)
            return True
        except ImportError:
            log.error("Install pyautogui + pygetwindow: pip install pyautogui pygetwindow")

    log.error("Screenshot failed")
    return False


def take_screenshot_with_retry(output_path, device="auto", retries=3):
    for i in range(retries):
        if take_screenshot(output_path, device):
            return True
        time.sleep(0.5)
    return False


def get_latest_screenshot(screenshot_dir):
    files = glob.glob(os.path.join(screenshot_dir, "*.jpg")) + glob.glob(os.path.join(screenshot_dir, "*.png"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)
