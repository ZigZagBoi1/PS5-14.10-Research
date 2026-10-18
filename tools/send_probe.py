#!/usr/bin/env python3
"""Send a Lua recon probe to the PS5 Lua loader.

Usage:
    python send_probe.py <probe_file.lua> [--ip 10.0.0.96] [--port 9026] [--save]

The probe output is printed to stdout. With --save, it's also written under
results/ as <probe_name>_<timestamp>.txt. For a probe inside this checkout's
probes/ directory, the probe's subdirectories are mirrored:
probes/phase_x/foo.lua -> results/phase_x/foo_<timestamp>.txt. Probes at the
root of probes/ and probes outside the checkout are saved flat in results/.
The results/ directory is relative to the caller's working directory.
"""

import socket
import struct
import sys
import argparse
from datetime import datetime
from pathlib import Path

def send_lua(ip, port, lua_file, save=False):
    with open(lua_file, "r", encoding="utf-8") as f:
        payload = f.read()

    print(f"[*] Connecting to {ip}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    try:
        sock.connect((ip, port))
        print(f"[*] Connected, sending {len(payload)} bytes...")

        # Protocol: 8-byte LE uint64 length prefix, then raw Lua source
        encoded = payload.encode("utf-8")
        sock.sendall(struct.pack("<Q", len(encoded)) + encoded)

        print(f"[*] Waiting for response...")
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Print as we receive
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except socket.timeout:
                print("\n[*] Timeout waiting for more data")
                break

        print(f"\n[*] Received {len(response)} bytes total")

        if save and response:
            # Mirror the probe's path below the checkout's probes/ into results/,
            # creating missing directories. External and root-level probes fall
            # back to the results/ root.
            out_dir = Path("results")
            probes_root = Path(__file__).resolve().parent.parent / "probes"
            try:
                rel_dir = Path(lua_file).resolve().relative_to(probes_root).parent
            except ValueError:
                rel_dir = Path(".")
            if rel_dir != Path("."):
                out_dir = out_dir / rel_dir
            out_dir.mkdir(parents=True, exist_ok=True)
            probe_name = Path(lua_file).stem
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = out_dir / f"{probe_name}_{ts}.txt"
            with open(out_path, "wb") as f:
                f.write(response)
            print(f"[*] Saved to {out_path}")

    except ConnectionRefusedError:
        print(f"[!] Connection refused — is the game running with the Lua loader?")
    except socket.timeout:
        print(f"[!] Connection timed out")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send Lua probe to PS5")
    parser.add_argument("probe", help="Lua probe file to send")
    parser.add_argument("--ip", default="10.0.0.96", help="PS5 IP (default: 10.0.0.96)")
    parser.add_argument("--port", type=int, default=9026, help="Lua loader port (default: 9026)")
    parser.add_argument("--save", action="store_true",
                        help="Save output under results/, mirroring the probe's probes/ subdirectories")
    args = parser.parse_args()

    send_lua(args.ip, args.port, args.probe, args.save)
