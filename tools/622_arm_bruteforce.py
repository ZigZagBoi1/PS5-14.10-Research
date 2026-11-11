#!/usr/bin/env python3
"""Walk the 622 `0x201`-`0x271` command arm, one command per connection.

Entering that arm kills the game on its first two commands (probes 1074a arm 1, 1078a), so a
contiguous sweep cannot reach the rest of it. This driver runs a single command per process by
rewriting the `CMD_SELECT` line of `probes/phase17_new_vectors/1079a_622_arm_sample.lua`, records
whether the process survived (a `=== DONE` marker) and what the status dword said, and stops at the
first death so the console can be relaunched before resuming.

    python tools/622_arm_bruteforce.py --ip 192.168.1.121
    python tools/622_arm_bruteforce.py --ip 192.168.1.121 --order 0x210,0x220
    python tools/622_arm_bruteforce.py --show

Progress lives in `.local/622_arm_state.json`; delete it to start over.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEMPLATE = os.path.join(ROOT, "probes", "phase17_new_vectors", "1079a_622_arm_sample.lua")
SCRATCH = os.path.join(ROOT, ".local", "622_arm_cmd.lua")
STATE = os.path.join(ROOT, ".local", "622_arm_state.json")

# Descending by 0x10: the arm head (0x201, 0x202) is already known lethal, so the tail is sampled
# first and a uniform result costs the fewest restarts.
DEFAULT_ORDER = [hex(c) for c in range(0x271, 0x200, -0x10)]


def load_state():
    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    return {"done": {}}


def save_state(state):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)


def render(cmd):
    with open(TEMPLATE, encoding="utf-8") as f:
        src = f.read()
    patched, n = re.subn(r"local CMD = 0x[0-9A-Fa-f]+ -- CMD_SELECT",
                         "local CMD = %s -- CMD_SELECT" % cmd, src)
    if n != 1:
        raise SystemExit("template lost its CMD_SELECT line")
    os.makedirs(os.path.dirname(SCRATCH), exist_ok=True)
    with open(SCRATCH, "w", encoding="utf-8", newline="\n") as f:
        f.write(patched)
    return SCRATCH


def loader_alive(ip):
    """A dead loader would look exactly like a lethal command, so never start without it."""
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "port_witness.py"), "--ip", ip],
            capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return "LOADER-RESPONSIVE" in (proc.stdout or "")


def wait_for_loader(ip, limit, interval=5):
    """Poll until the loader answers again, so a relaunch resumes the walk by itself."""
    waited = 0
    while waited < limit:
        time.sleep(interval)
        waited += interval
        if loader_alive(ip):
            print("  loader is back after %ds" % waited, flush=True)
            return True
    return False


def run_one(ip, cmd, timeout):
    path = render(cmd)
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "send_probe.py"),
         "--ip", ip, "--save", path],
        capture_output=True, text=True, timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    if "=== 1079a DONE ===" in out:
        rv = re.search(r"\[B\] risky 0x([0-9A-F]+) handle=0 out=a5a5a5a5", out)
        line = re.search(r"rv=(-?\d+) out=0x([0-9A-F]{8})  \(survived\)", out)
        return {
            "result": "survived",
            "rv": int(line.group(1)) if line else None,
            "out": line.group(2) if line else None,
        }
    return {"result": "died"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.121")
    ap.add_argument("--order", default="")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--wait", type=int, default=0,
                    help="seconds to wait for a relaunch after a death, then continue")
    args = ap.parse_args()

    state = load_state()
    if args.show:
        for cmd in sorted(state["done"]):
            print("%s  %s" % (cmd, state["done"][cmd]))
        print("%d of 113 sampled" % len(state["done"]))
        return

    order = [c.strip() for c in args.order.split(",") if c.strip()] or DEFAULT_ORDER
    pending = [c for c in order if c not in state["done"]]
    if not pending:
        print("nothing pending in this order; --show to see what ran")
        return

    if not loader_alive(args.ip):
        print("loader is not responsive - relaunch it and run again")
        return

    for cmd in pending:
        print("trying %s ..." % cmd, flush=True)
        try:
            res = run_one(args.ip, cmd, args.timeout)
        except subprocess.TimeoutExpired:
            res = {"result": "timeout"}
        state["done"][cmd] = res
        save_state(state)
        print("  %s" % res, flush=True)
        if res["result"] != "survived":
            print("died at %s" % cmd, flush=True)
            if not args.wait or not wait_for_loader(args.ip, args.wait):
                print("stopped at %s - relaunch the loader, then run again to continue" % cmd)
                return
    print("order complete; %d sampled" % len(state["done"]))


if __name__ == "__main__":
    main()
