"""Send keyboard inputs to Chiaki window to control PS5.
Chiaki maps keyboard keys to controller buttons.
Default mappings: Enter=Cross, Backspace=Circle, Escape=PS button
"""
import ctypes
import time

u32 = ctypes.windll.user32

# Find chiaki window
WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
results = []; buf = ctypes.create_unicode_buffer(256)
def cb(h, _):
    u32.GetWindowTextW(h, buf, 256)
    if 'chiaki' in buf.value.lower() and u32.IsWindowVisible(h): results.append(h)
    return True
u32.EnumWindows(WNDENUMPROC(cb), 0)

if not results:
    print("No Chiaki window found")
    exit(1)

hwnd = results[0]
print(f"Chiaki hwnd={hwnd}")

# Bring to foreground
u32.SetForegroundWindow(hwnd)
time.sleep(0.5)

WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
VK_RETURN = 0x0D    # Enter = Cross (X)
VK_BACK = 0x08      # Backspace = Circle (O)
VK_ESCAPE = 0x1B    # Escape = PS button
VK_UP = 0x26
VK_DOWN = 0x28
VK_LEFT = 0x25
VK_RIGHT = 0x27
VK_F2 = 0x71        # F2 = Options

def send_key(vk, hold=0.15, wait=0.4):
    u32.PostMessageW(hwnd, WM_KEYDOWN, vk, 0)
    time.sleep(hold)
    u32.PostMessageW(hwnd, WM_KEYUP, vk, 0)
    time.sleep(wait)

# Phase 1: Dismiss crash dialogs
print("1: Dismiss dialogs (Enter + Backspace spam)")
for _ in range(5):
    send_key(VK_RETURN, 0.1, 0.3)
for _ in range(3):
    send_key(VK_BACK, 0.1, 0.3)
time.sleep(1)

# Phase 2: PS button (Escape) to go home
print("2: PS button (hold Escape)")
u32.PostMessageW(hwnd, WM_KEYDOWN, VK_ESCAPE, 0)
time.sleep(1.5)
u32.PostMessageW(hwnd, WM_KEYUP, VK_ESCAPE, 0)
time.sleep(3)

# Phase 3: Dismiss control center
print("3: Dismiss (Backspace)")
send_key(VK_BACK, 0.1, 0.5)
time.sleep(1)

# Phase 4: Options on game tile (F2)
print("4: Options menu")
send_key(VK_F2, 0.15, 2)

# Phase 5: Navigate to Close Game
print("5: Down to Close Game")
for _ in range(6):
    send_key(VK_DOWN, 0.1, 0.3)

# Phase 6: Select
print("6: Select Close Game")
send_key(VK_RETURN, 0.15, 2)

# Phase 7: Confirm
print("7: Confirm")
send_key(VK_RETURN, 0.15, 5)

# Phase 8: Relaunch
print("8: Relaunch")
for _ in range(5):
    send_key(VK_RETURN, 0.1, 1)

print("9: Wait 50s")
time.sleep(50)
print("Done")
