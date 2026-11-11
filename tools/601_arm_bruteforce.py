#!/usr/bin/env python3
"""Walk 601's command space one command per connection, looking for the mdbg log drain.

`docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 describes a 601 command that memcpy's the kernel log
list into a 0x4000 bounce buffer and uiomove's it to the caller. Its dispatch table sits above
0x1400000, outside every dump, so the command number is only knowable behaviourally - and the space
is hostile: `0x03`/`0x04` take a raw `struct proc*` (panic) and `0x08` blocks the loader forever
(measured by 1170a). A contiguous sweep therefore loses everything after the first bad command.

This driver rewrites the `CMD_SELECT` line of `probes/phase17_new_vectors/1171a_mdbg_one_cmd.lua`,
runs exactly one command in its own process, and records `rv`, how many bytes changed, and whether
the returned bytes contain `mDBG`. Progress lives in `.local/601_cmd_state.json`, so a relaunch
resumes by itself.

    python tools/601_arm_bruteforce.py --ip 192.168.1.121 --wait 3600
    python tools/601_arm_bruteforce.py --show
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
TEMPLATE = os.path.join(ROOT, "probes", "phase17_new_vectors", "1171a_mdbg_one_cmd.lua")
SCRATCH = os.path.join(ROOT, ".local", "601_cmd.lua")
STATE = os.path.join(ROOT, ".local", "601_cmd_state.json")

# Descending: the tail is unknown and cheap, and the low commands hold the two known-lethal ones
# (0x03/0x04) and the known blocker (0x08), so they come last.
DEFAULT_ORDER = [hex(c) for c in range(0x2F, 0x08, -1)]


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
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "port_witness.py"), "--ip", ip],
            capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return "LOADER-RESPONSIVE" in (proc.stdout or "")


def wait_for_loader(ip, limit, interval=5):
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
    if "=== 1171a DONE ===" not in out:
        return {"result": "died", "tail": out.strip().splitlines()[-2:]}
    m = re.search(r"\[R\] cmd=0x([0-9A-F]+) rv=(-?\d+) changed=(\d+) first=(-?\d+) text_hit=(\w+)", out)
    if not m:
        return {"result": "unparsed", "tail": out.strip().splitlines()[-4:]}
    return {"result": "survived", "rv": int(m.group(2)), "changed": int(m.group(3)),
            "first": int(m.group(4)), "text_hit": m.group(5) == "true"}


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
        for cmd in sorted(state["done"], key=lambda s: int(s, 16)):
            print("%s  %s" % (cmd, state["done"][cmd]))
        print("%d of %d sampled" % (len(state["done"]), len(DEFAULT_ORDER)))
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
        if res.get("text_hit"):
            print("  *** mDBG text returned by %s - stop and read the capture ***" % cmd, flush=True)
            return
        if res["result"] != "survived":
            print("lost the loader at %s" % cmd, flush=True)
            if not args.wait or not wait_for_loader(args.ip, args.wait):
                print("stopped at %s - relaunch the loader, then run again to continue" % cmd)
                return
    print("order complete; %d sampled" % len(state["done"]))


if __name__ == "__main__":
    main()
