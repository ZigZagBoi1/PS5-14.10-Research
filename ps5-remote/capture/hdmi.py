"""
Screen Capture — Captures the Chiaki (Remote Play) window.

No capture card needed. Takes screenshots of the Chiaki window
using platform-native methods (screencapture on Mac, PIL on Windows).
"""
import subprocess
import platform
import time
import os
import glob
import logging

log = logging.getLogger("ps5remote.capture")


def find_chiaki_window():
    system = platform.system().lower()
    if system == "darwin":
        script = '''
        tell application "System Events"
            set wList to {}
            repeat with p in (every process whose visible is true)
                if name of p contains "Chiaki" or name of p contains "chiaki" then
                    set end of wList to name of p
                end if
            end repeat
            return wList
        end tell
        '''
        result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()
        if output and output != "":
            return output.split(",")[0].strip()
    elif system == "windows":
        try:
            import pygetwindow as gw
            wins = [w for w in gw.getAllWindows() if "chiaki" in w.title.lower()]
            if wins:
                return wins[0].title
        except ImportError:
            result = subprocess.run(
                ["powershell", "-c",
                 "Get-Process | Where-Object {$_.MainWindowTitle -like '*Chiaki*' -or $_.ProcessName -like '*chiaki*'} | Select-Object -First 1 MainWindowTitle | Format-List"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "MainWindowTitle" in line:
                    title = line.split(":", 1)[-1].strip()
                    if title:
                        return title
    return None


def screenshot_chiaki(output_path, timeout=5):
    system = platform.system().lower()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if system == "darwin":
        window_name = find_chiaki_window()
        if window_name:
            script = f'''
            tell application "System Events"
                set chiakiProc to first process whose name contains "Chiaki"
                set chiakiWin to first window of chiakiProc
                set {{x, y, w, h}} to {{position of chiakiWin, size of chiakiWin}}
                set {{px, py}} to position of chiakiWin
                set {{sw, sh}} to size of chiakiWin
            end tell
            return (px as text) & "," & (py as text) & "," & (sw as text) & "," & (sh as text)
            '''
            result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
            coords = result.stdout.strip()
            if coords and "," in coords:
                parts = coords.split(",")
                if len(parts) == 4:
                    x, y, w, h = [int(p.strip()) for p in parts]
                    cmd = ["screencapture", "-R", f"{x},{y},{w},{h}", "-x", output_path]
                    subprocess.run(cmd, timeout=timeout)
                    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                        return True

        cmd = ["screencapture", "-x", output_path]
        subprocess.run(cmd, timeout=timeout)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            log.info(f"Full-screen screenshot (Chiaki window not found specifically): {output_path}")
            return True

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
            log.error("Install pyautogui and pygetwindow: pip install pyautogui pygetwindow")
            cmd = ["powershell", "-c", f"""
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object {{
                $bmp = New-Object System.Drawing.Bitmap($_.Bounds.Width, $_.Bounds.Height)
                $g = [System.Drawing.Graphics]::FromImage($bmp)
                $g.CopyFromScreen($_.Bounds.Location, [System.Drawing.Point]::Empty, $_.Bounds.Size)
                $bmp.Save('{output_path}')
                $g.Dispose()
                $bmp.Dispose()
            }}
            """]
            subprocess.run(cmd, timeout=timeout)
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True

    log.error("Screenshot failed")
    return False


def take_screenshot(output_path, device="auto", timeout=5):
    return screenshot_chiaki(output_path, timeout)


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


def start_continuous_capture(screenshot_dir, device="auto", interval=2.0, stop_event=None):
    os.makedirs(screenshot_dir, exist_ok=True)
    frame = 0
    while stop_event is None or not stop_event.is_set():
        ext = "png" if platform.system().lower() == "darwin" else "jpg"
        path = os.path.join(screenshot_dir, f"frame_{frame:06d}.{ext}")
        take_screenshot(path, device)
        frame += 1
        if frame > 100:
            old_ext = ext
            old = os.path.join(screenshot_dir, f"frame_{frame - 101:06d}.{old_ext}")
            if os.path.exists(old):
                os.remove(old)
        if stop_event:
            stop_event.wait(interval)
        else:
            time.sleep(interval)
