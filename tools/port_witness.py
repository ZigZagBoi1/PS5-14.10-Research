#!/usr/bin/env python3
"""Distinguish a dead loader from a live-but-stuck one.

The loader protocol is an 8-byte little-endian length followed by Lua source, so a bare
byte on the socket is not a request and a healthy idle loader would never answer. This
sends a real one-line script and looks for its token. A killed process stops listening
(connect refused); a process whose main thread is blocked in a signal handler still has
the listening socket open, so the connection is queued but never served.
"""
import argparse, socket, struct, sys

SRC = b'print("WITNESS-OK")\n'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.121")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--wait", type=float, default=3.0)
    a = ap.parse_args()
    s = socket.socket()
    s.settimeout(a.wait)
    try:
        s.connect((a.ip, a.port))
    except ConnectionRefusedError:
        print("LOADER-DEAD connect refused")
        return 1
    except OSError as exc:
        print("LOADER-INCONCLUSIVE connect error: %s" % exc)
        return 2
    try:
        s.sendall(struct.pack("<Q", len(SRC)) + SRC)
        data = s.recv(4096)
    except socket.timeout:
        print("LOADER-STUCK accepted, no reply")
        return 3
    except OSError as exc:
        print("LOADER-STUCK accepted, send/recv error: %s" % exc)
        return 3
    finally:
        s.close()
    if b"WITNESS-OK" in data:
        print("LOADER-RESPONSIVE pid line: %s" % data.decode("latin-1").strip().splitlines()[0][:80])
        return 0
    print("LOADER-ODD %d bytes: %r" % (len(data), data[:80]))
    return 4

if __name__ == "__main__":
    sys.exit(main())
