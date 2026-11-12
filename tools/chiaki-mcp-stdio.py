#!/usr/bin/env python3
"""Minimal MCP stdio server for chiaki-ng PS5 remote control.

Provides tools to send keypresses to the chiaki-ng window via PostMessage
(no focus steal). Designed for PS5 browser probe automation.

Limitations:
- Requires chiaki-ng to be running with an active Remote Play session
- Cannot recover a completely unresponsive/powered-off console
- Cannot detect whether Remote Play is connected (only window existence)
- PostMessage delivers to the window message queue; if chiaki-ng is hung
  or the Remote Play stream is frozen, keys queue but have no effect
- The PS5 browser may show "not enough free system memory" dialogs that
  block input until Enter is pressed — use refresh_page which handles this
"""
import json, sys, os, time, ctypes, ctypes.wintypes

if sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
user32 = ctypes.windll.user32

KEY_MAP = {
    "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
    "enter": 0x0D, "escape": 0x1B, "space": 0x20,
    "1": 0x31, "2": 0x32, "3": 0x33, "4": 0x34,
    "tab": 0x09, "backspace": 0x08,
}

WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)


def find_chiaki_hwnd():
    import subprocess as sp
    try:
        r = sp.run(["tasklist", "/FI", "IMAGENAME eq chiaki.exe",
                     "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=5)
        pid = None
        for line in r.stdout.strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and "chiaki" in parts[0].lower():
                pid = int(parts[1])
                break
        if not pid:
            return None
    except Exception:
        return None

    result = [None]
    def callback(hwnd, _):
        wpid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid and user32.IsWindowVisible(hwnd):
            result[0] = hwnd
            return False
        return True
    user32.EnumWindows(WNDENUMPROC(callback), 0)
    return result[0]


def _post_key(hwnd, vk):
    r1 = user32.PostMessageW(hwnd, WM_KEYDOWN, vk, 0)
    time.sleep(0.05)
    r2 = user32.PostMessageW(hwnd, WM_KEYUP, vk, 0)
    return bool(r1 and r2)


def _resolve_vk(key_name):
    vk = KEY_MAP.get(key_name.lower())
    if vk is None and len(key_name) == 1 and key_name.isalnum():
        vk = ord(key_name.upper())
    return vk


def send_key(key_name):
    hwnd = find_chiaki_hwnd()
    if not hwnd:
        return {"ok": False, "error": "chiaki window not found"}
    vk = _resolve_vk(key_name)
    if vk is None:
        return {"ok": False, "error": f"unknown key: {key_name}"}
    ok = _post_key(hwnd, vk)
    return {"ok": ok, "key": key_name, "vk": hex(vk), "hwnd": hex(hwnd)}


def refresh_page():
    """Send Enter (dismiss dialog) + wait + key '2' (User Guide refresh).

    The PS5 browser sometimes shows "not enough free system memory"
    dialogs that block all input. Sending Enter first dismisses these.
    Key '2' navigates to the User Guide page which auto-redirects to
    the current probe via index.html meta-refresh.
    """
    hwnd = find_chiaki_hwnd()
    if not hwnd:
        return {"ok": False, "error": "chiaki window not found"}
    _post_key(hwnd, 0x0D)  # Enter
    time.sleep(0.5)
    _post_key(hwnd, 0x32)  # '2'
    return {"ok": True, "sequence": "enter+wait+2", "hwnd": hex(hwnd)}


def send_sequence(keys, delay_ms=200):
    """Send a sequence of keys with configurable delay between them."""
    hwnd = find_chiaki_hwnd()
    if not hwnd:
        return {"ok": False, "error": "chiaki window not found"}
    results = []
    for key_name in keys:
        vk = _resolve_vk(key_name)
        if vk is None:
            results.append({"key": key_name, "ok": False, "error": "unknown"})
            continue
        ok = _post_key(hwnd, vk)
        results.append({"key": key_name, "ok": ok})
        time.sleep(delay_ms / 1000.0)
    return {"ok": all(r["ok"] for r in results), "keys": results,
            "hwnd": hex(hwnd)}


# --- MCP stdio protocol ---

def write_msg(msg):
    data = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(data)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + data)
    sys.stdout.buffer.flush()


def read_msg():
    buf = sys.stdin.buffer
    headers = {}
    while True:
        line = buf.readline()
        if not line:
            return None
        line = line.decode("ascii").strip()
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", 0))
    if length == 0:
        return None
    body = buf.read(length)
    return json.loads(body.decode("utf-8"))


TOOLS = [
    {
        "name": "send_key",
        "description": "Send a single keypress to chiaki-ng (PS5 Remote Play). Does not steal focus.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Key: up/down/left/right/enter/escape/space/1/2/3/4/tab/backspace or single char"
                }
            },
            "required": ["key"]
        }
    },
    {
        "name": "refresh_page",
        "description": "Refresh the PS5 browser page. Sends Enter (dismiss any memory dialog) then key '2' (navigate to User Guide which redirects to current probe). Use this instead of bare send_key('2').",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "send_sequence",
        "description": "Send a sequence of keys to chiaki-ng with delay between each.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of key names to send in order"
                },
                "delay_ms": {
                    "type": "integer",
                    "description": "Delay between keys in milliseconds (default 200)",
                    "default": 200
                }
            },
            "required": ["keys"]
        }
    }
]


def main():
    while True:
        msg = read_msg()
        if msg is None:
            break
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            write_msg({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "chiaki-ng", "version": "1.1.0"}
            }})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            write_msg({"jsonrpc": "2.0", "id": mid, "result": {
                "tools": TOOLS}})
        elif method == "tools/call":
            name = msg["params"]["name"]
            args = msg["params"].get("arguments", {})
            if name == "send_key":
                r = send_key(args.get("key", "2"))
            elif name == "refresh_page":
                r = refresh_page()
            elif name == "send_sequence":
                r = send_sequence(
                    args.get("keys", []),
                    args.get("delay_ms", 200))
            else:
                write_msg({"jsonrpc": "2.0", "id": mid, "error": {
                    "code": -32601, "message": f"unknown tool: {name}"}})
                continue
            write_msg({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": json.dumps(r)}]}})
        elif method == "ping":
            write_msg({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif mid is not None:
            write_msg({"jsonrpc": "2.0", "id": mid, "result": {}})


if __name__ == "__main__":
    main()
