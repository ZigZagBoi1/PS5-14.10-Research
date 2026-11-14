"""
chiaki_keys.py — Send keyboard inputs to chiaki-ng WITHOUT stealing focus.

Uses PostMessage WM_KEYDOWN/WM_KEYUP to the Qt window directly.
This lets the PS5 be controlled while the user plays other games.

Usage:
    python tools/chiaki_keys.py reload_browser
    python tools/chiaki_keys.py refresh
    python tools/chiaki_keys.py press <key>
    python tools/chiaki_keys.py seq "backspace esc up enter"
    python tools/chiaki_keys.py test           # quick test: sends Enter
"""

import ctypes
import ctypes.wintypes as wt
import time
import sys

u32 = ctypes.windll.user32

# Windows messages
WM_KEYDOWN    = 0x0100
WM_KEYUP      = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP   = 0x0105
WM_ACTIVATE   = 0x0006
WM_SETFOCUS   = 0x0007
WA_ACTIVE     = 1
MAPVK_VK_TO_VSC = 0

# Type declarations for 64-bit safety
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
u32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
u32.EnumWindows.restype = wt.BOOL
u32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetWindowTextW.restype = ctypes.c_int
u32.IsWindowVisible.argtypes = [wt.HWND]
u32.IsWindowVisible.restype = wt.BOOL
u32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u32.PostMessageW.restype = wt.BOOL
u32.MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
u32.MapVirtualKeyW.restype = wt.UINT

# Virtual key codes — chiaki-ng default mappings
VK = {
    'enter': 0x0D, 'return': 0x0D,        # Cross (X)
    'backspace': 0x08, 'back': 0x08,      # Circle (O)
    'escape': 0x1B, 'esc': 0x1B,          # PS button
    'up': 0x26, 'down': 0x28,
    'left': 0x25, 'right': 0x27,
    'c': 0x43,                             # Triangle
    'o': 0x4F,                             # Options
    'f': 0x46,                             # Share
    't': 0x54,                             # Touchpad
    'tab': 0x09,
    'space': 0x20,
    '\\': 0xDC,                            # Square
    '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34,
    '5': 0x35, '6': 0x36,
    '[': 0xDB, ']': 0xDD,
    '-': 0xBD, '=': 0xBB,
    'insert': 0x2D, 'delete': 0x2E,
    'pageup': 0x21, 'pagedown': 0x22,
}

def find_chiaki():
    """Find chiaki-ng main window handle without stealing focus."""
    wins = []
    buf = ctypes.create_unicode_buffer(256)
    def cb(h, _):
        u32.GetWindowTextW(h, buf, 256)
        if 'chiaki' in buf.value.lower() and u32.IsWindowVisible(h):
            wins.append(h)
        return True
    u32.EnumWindows(WNDENUMPROC(cb), 0)
    if not wins:
        return None
    return wins[0]

def _make_lparam(vk, down):
    scan = u32.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC)
    if down:
        return (1) | (scan << 16)
    else:
        return (1) | (scan << 16) | (0xC0000000)

def send_key(hwnd, key_name, hold=0.08):
    """Send one key press via PostMessage (no focus steal)."""
    key_name = key_name.lower().strip()
    vk = VK.get(key_name)
    if vk is None:
        if len(key_name) == 1:
            vk = ord(key_name.upper())
        else:
            print(f"Unknown key: {key_name}")
            return False
    u32.PostMessageW(hwnd, WM_KEYDOWN, vk, _make_lparam(vk, True))
    time.sleep(hold)
    u32.PostMessageW(hwnd, WM_KEYUP, vk, _make_lparam(vk, False))
    return True

def send_seq(hwnd, keys, delay=0.5):
    """Send a sequence of named keys."""
    if isinstance(keys, str):
        keys = keys.split()
    for k in keys:
        send_key(hwnd, k)
        time.sleep(delay)

def activate_chiaki_input(hwnd):
    """Attach to chiaki's input thread so PostMessage keys are processed,
    without actually bringing chiaki to foreground."""
    u32.PostMessageW(hwnd, WM_ACTIVATE, WA_ACTIVE, 0)
    u32.PostMessageW(hwnd, WM_SETFOCUS, 0, 0)
    # Also attach threads so key state is shared
    k32 = ctypes.windll.kernel32
    our_tid = k32.GetCurrentThreadId()
    chi_tid = u32.GetWindowThreadProcessId(hwnd, None)
    if our_tid != chi_tid:
        u32.AttachThreadInput(our_tid, chi_tid, True)

def reload_browser(hwnd=None):
    """Exit crashed browser and reopen User Guide — no focus steal."""
    if hwnd is None:
        hwnd = find_chiaki()
    if not hwnd:
        print("ERROR: chiaki not found"); return False

    activate_chiaki_input(hwnd)
    time.sleep(0.2)

    print("[1/5] Exiting browser (backspace spam)...")
    for _ in range(8):
        send_key(hwnd, 'backspace')
        time.sleep(0.2)

    time.sleep(1)
    print("[2/5] PS button → home...")
    send_key(hwnd, 'escape')
    time.sleep(3)
    send_key(hwnd, 'backspace')
    time.sleep(2)

    print("[3/5] Navigate to Settings...")
    send_seq(hwnd, 'up up right right right', 0.6)
    send_key(hwnd, 'enter')
    time.sleep(3)

    print("[4/5] Guide & Tips → User's Guide...")
    for _ in range(10):
        send_key(hwnd, 'up')
        time.sleep(0.3)
    send_key(hwnd, 'enter')
    time.sleep(3)

    print("[5/5] Opening User's Guide...")
    send_key(hwnd, 'right')
    time.sleep(0.8)
    send_key(hwnd, 'enter')
    time.sleep(5)

    print("Done — browser loading.")
    return True

def refresh_page(hwnd=None):
    """Press Triangle (C) to reload."""
    if hwnd is None:
        hwnd = find_chiaki()
    if not hwnd:
        print("ERROR: chiaki not found"); return False
    activate_chiaki_input(hwnd)
    time.sleep(0.1)
    send_key(hwnd, 'c')
    print("Refresh sent.")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("chiaki_keys.py — control PS5 via chiaki without stealing focus")
        print()
        print("Commands:")
        print("  reload_browser  — exit browser crash, reopen User Guide")
        print("  refresh         — Triangle to reload current page")
        print("  press <key>     — single key (enter, backspace, esc, up, etc.)")
        print('  seq "k1 k2 k3"  — sequence of keys')
        print("  test            — send Enter to verify PostMessage works")
        sys.exit(0)

    hwnd = find_chiaki()
    if not hwnd:
        print("ERROR: chiaki-ng not found")
        sys.exit(1)
    print(f"Chiaki hwnd={hwnd}")

    cmd = sys.argv[1].lower()
    if cmd == 'reload_browser':
        reload_browser(hwnd)
    elif cmd == 'refresh':
        refresh_page(hwnd)
    elif cmd == 'press' and len(sys.argv) >= 3:
        activate_chiaki_input(hwnd)
        time.sleep(0.1)
        send_key(hwnd, sys.argv[2])
        print(f"Sent: {sys.argv[2]}")
    elif cmd == 'seq' and len(sys.argv) >= 3:
        activate_chiaki_input(hwnd)
        time.sleep(0.1)
        send_seq(hwnd, sys.argv[2])
        print(f"Sent: {sys.argv[2]}")
    elif cmd == 'test':
        activate_chiaki_input(hwnd)
        time.sleep(0.1)
        send_key(hwnd, 'enter')
        print("Test: sent Enter (Cross). Check PS5 reacted.")
    else:
        print(f"Unknown: {cmd}")
