#!/usr/bin/env python3
"""Sweep a syscall-number range with one connection per number.

Why this exists
---------------
A probe that walks a range inside a single connection cannot get past the first
number that terminates the process: everything after it is never executed, and
the capture ends with no result line.

The loader process survives across connections and is only replaced when the game
is relaunched: identical pid and module addresses across consecutive connections
(159a/160a pid 133, 162a/163a/164a pid 143, 167a/168a pid 158), new values after
a relaunch. A lethal number therefore takes the process down for every connection
that follows, which is why this driver aborts on the first connect failure.

That is what happened to `probes/phase14_final_push/54c_aio_full_attack.lua`.
Its survival matrix lists 661-670, and the saved capture
(`results/54c_aio_full_attack_20261018_090527.txt`) contains the header and
`[BEFORE] sys 661` and nothing else. Probe 54f's section G stops at the same
number. Neither run executed 662-670, so neither run can support a conclusion
about them.

This driver sends one minimal probe per number, in its own connection, so a
lethal number costs exactly one data point instead of hiding the rest of the
range.

Usage::

    python tools/syscall_isolation_sweep.py --ps5-ip 10.0.0.96 --range 661-670
    python tools/syscall_isolation_sweep.py --ps5-ip 10.0.0.96 --numbers 661,662
    python tools/syscall_isolation_sweep.py --range 661-670 --dry-run

Every number is called with six zero `uint64` arguments, matching the argument
shape used by the 54c matrix. Output is classified per number; see
`classify()`.

Offline test: `python -m unittest tools.test_syscall_isolation_sweep`
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

DEFAULT_IP = "10.0.0.96"
DEFAULT_PORT = 9026
DEFAULT_TIMEOUT = 15.0
DEFAULT_DELAY = 1.0

SENTINEL = "=== SWEEP SENTINEL {num} ==="
RESULT = "SWEEP RESULT {num} "
DONE = "=== SWEEP DONE {num} ==="

# Classification values.
RETURNED = "RETURNED"          # the call returned a value
RAISED = "RAISED"              # pcall caught a Lua error
KILLED_IN_CALL = "KILLED_IN_CALL"   # sentinel printed, no result: process died
NO_OUTPUT = "NO_OUTPUT"        # connected and sent, nothing came back
CONNECT_FAILED = "CONNECT_FAILED"   # could not open the connection


PROBE_TEMPLATE = """print("{sentinel}")
local function make_syscall(num)
    local t = {{}}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local probe_ok, probe_ret = pcall(function()
    return make_syscall({num})(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
-- Report through a number-safe helper rather than %d: some handlers hand back
-- userdata, which tostring() prints but tonumber() rejects.
local function describe(v)
    local as_str = tostring(v)
    local as_num
    if type(v) == "table" and v.tonumber then
        as_num = v:tonumber()
    else
        as_num = tonumber(v)
    end
    if as_num ~= nil then
        return string.format("%s (num=%s)", as_str, tostring(as_num))
    end
    return string.format("%s (type=%s)", as_str, type(v))
end
if probe_ok then
    print(string.format("SWEEP RESULT {num} ok=1 ret=%s", describe(probe_ret)))
else
    print(string.format("SWEEP RESULT {num} ok=0 err=%s", tostring(probe_ret)))
end
print("{done}")
"""


def build_probe(num):
    """Return the Lua source for one number."""
    return PROBE_TEMPLATE.format(
        sentinel=SENTINEL.format(num=num),
        done=DONE.format(num=num),
        num=num,
    )


def parse_range(spec):
    """Parse ``661-670`` or ``661,662`` into a list of ints."""
    numbers = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo, 0), int(hi, 0)
            if hi < lo:
                raise ValueError("descending range: %s" % part)
            numbers.extend(range(lo, hi + 1))
        else:
            numbers.append(int(part, 0))
    if not numbers:
        raise ValueError("empty syscall range")
    return numbers


def classify(output, num):
    """Note: KILLED_IN_CALL means the slot is absent, not that the handler is hostile.

    make_syscall(4095) also terminates the process, and 4095 cannot have a handler, so a
    kill is evidence of a missing sysent entry. A ``-1`` return proves the opposite: the
    handler exists and rejected these arguments. See docs/SYSCALL_ABSENT_VS_LETHAL.md.
    """
    """Classify one run's response.

    ``output`` is the decoded response, which may be empty or truncated at the
    point the process died. The sentinel is printed before the call, so its
    presence separates "died inside the call" from "never got that far".
    """
    if output is None:
        return CONNECT_FAILED, None
    text = output
    result_prefix = RESULT.format(num=num)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(result_prefix):
            body = line[len(result_prefix):]
            if body.startswith("ok=1"):
                return RETURNED, body[4:].strip()
            if body.startswith("ok=0"):
                return RAISED, body[4:].strip()
    if SENTINEL.format(num=num) in text:
        return KILLED_IN_CALL, None
    return NO_OUTPUT, None


def tcp_transport(ip, port, lua_source, timeout=DEFAULT_TIMEOUT):
    """Send one probe over the loader protocol; return decoded output or None."""
    encoded = lua_source.encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    chunks = []
    try:
        sock.connect((ip, port))
        sock.sendall(struct.pack("<Q", len(encoded)) + encoded)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    except (ConnectionRefusedError, ConnectionResetError,
            ConnectionAbortedError, BrokenPipeError):
        return None
    except OSError:
        return None
    finally:
        sock.close()
    return b"".join(chunks).decode("utf-8", errors="replace")


def sweep(numbers, transport, delay=DEFAULT_DELAY, sleep=time.sleep,
          repeat=1, log=None, wait=None, wedge_guard=True):
    """Run one connection per number and return per-number records.

    ``wait`` is an optional callable that blocks until the loader is back and
    returns True. A number that kills the process is retried once the loader
    returns, so one relaunch resumes the same range instead of ending the run.
    Without ``wait`` the sweep aborts on the first missing loader, which is the
    behaviour every earlier capture was taken with.

    ``wedge_guard`` retries a number that answered nothing and ends the run if it
    answers nothing twice: a call that parks the Lua thread in the kernel leaves
    the loader accepting connections while every later probe times out, which
    would otherwise burn the whole remaining range in timeouts.
    """
    log = log or (lambda _msg: None)
    records = []
    for num in numbers:
        attempts = []
        waited = False
        wedge_checked = False
        while True:
            for attempt in range(repeat):
                if attempts or num != numbers[0]:
                    sleep(delay)
                output = transport(build_probe(num))
                status, detail = classify(output, num)
                attempts.append({
                    "status": status,
                    "detail": detail,
                    "response": output,
                })
                log("sys %d: %s%s" % (num, status, (" " + detail) if detail else ""))
                if status == CONNECT_FAILED:
                    break
            if attempts[-1]["status"] != CONNECT_FAILED:
                if (wedge_guard and not wedge_checked
                        and attempts[-1]["status"] == NO_OUTPUT):
                    wedge_checked = True
                    log("sys %d answered nothing; checking whether the loader is "
                        "parked" % num)
                    sleep(delay)
                    output = transport(build_probe(num))
                    status, detail = classify(output, num)
                    attempts.append({"status": status, "detail": detail,
                                     "response": output})
                    log("sys %d retry: %s%s" % (num, status,
                                                (" " + detail) if detail else ""))
                    if status == NO_OUTPUT:
                        records.append({"num": num, "attempts": attempts,
                                        "status": NO_OUTPUT, "aborted": True})
                        return records
                break
            if wait is None or waited:
                # The loader is gone; further numbers would all report the
                # same thing, which is not information about the syscalls.
                records.append({"num": num, "attempts": attempts,
                                "status": CONNECT_FAILED, "aborted": True})
                return records
            log("sys %d left the loader down; waiting for it to come back" % num)
            if not wait():
                records.append({"num": num, "attempts": attempts,
                                "status": CONNECT_FAILED, "aborted": True})
                return records
            waited = True
        final = attempts[-1]["status"]
        records.append({"num": num, "attempts": attempts, "status": final,
                        "aborted": False})
    return records


def format_report(records):
    """Render the sweep result as a fixed-width table."""
    lines = []
    lines.append("%-8s %-16s %s" % ("syscall", "status", "detail"))
    lines.append("-" * 60)
    for rec in records:
        detail = rec["attempts"][-1]["detail"] or ""
        lines.append("%-8d %-16s %s" % (rec["num"], rec["status"], detail))
    lines.append("")
    counts = {}
    for rec in records:
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    summary = ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))
    lines.append("SUMMARY: %d numbers, %s" % (len(records), summary))
    survivors = [r["num"] for r in records if r["status"] == RETURNED]
    if survivors:
        lines.append("Returned values from: %s" % ", ".join(str(n) for n in survivors))
    lethal = [r["num"] for r in records if r["status"] == KILLED_IN_CALL]
    if lethal:
        lines.append("Process terminated inside: %s" % ", ".join(str(n) for n in lethal))
    return "\n".join(lines)


def save_report(report, records, numbers, stamp=None):
    """Write the table and a JSON record under results/phase15_native_sysent/."""
    out_dir = Path("results") / "phase15_native_sysent"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = out_dir / ("syscall_isolation_sweep_%s.txt" % stamp)
    json_path = out_dir / ("syscall_isolation_sweep_%s.json" % stamp)
    txt_path.write_text(report + "\n", encoding="utf-8")
    payload = {
        "numbers": numbers,
        "started_at": stamp,
        "records": [
            {
                "num": rec["num"],
                "status": rec["status"],
                "aborted": rec["aborted"],
                "attempts": [
                    {"status": a["status"], "detail": a["detail"]}
                    for a in rec["attempts"]
                ],
            }
            for rec in records
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return txt_path, json_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ps5-ip", default=DEFAULT_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--range", dest="numbers_spec", default="661-670")
    group.add_argument("--numbers", dest="numbers_spec")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help="seconds between connections (loader respawn)")
    parser.add_argument("--repeat", type=int, default=1,
                        help="connections per number, to test reproducibility")
    parser.add_argument("--wait-for-loader", type=float, default=0.0,
                        metavar="SECONDS",
                        help="on a dead loader, poll until it comes back (relaunch "
                             "the game) and resume from that number; 0 disables")
    parser.add_argument("--resume", action="store_true",
                        help="skip every number that already has a record in "
                             "results/**/syscall_isolation_sweep_*.json, so an "
                             "interrupted range can be picked up where it stopped")
    parser.add_argument("--no-wedge-guard", dest="wedge_guard",
                        action="store_false",
                        help="keep sweeping after a number answers nothing twice")
    parser.add_argument("--skip", default="",
                        help="comma-separated numbers to leave out of the range; use "
                             "it for slots that are known to take the kernel with them "
                             "(430 thr_create panics on a zeroed context)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the generated probe and exit")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args(argv)

    try:
        numbers = parse_range(args.numbers_spec)
    except ValueError as exc:
        parser.error(str(exc))

    if args.skip:
        skipped = set()
        for part in args.skip.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                skipped.update(parse_range(part))
            except ValueError as exc:
                parser.error(str(exc))
        numbers = [n for n in numbers if n not in skipped]
        if not numbers:
            parser.error("--skip removed every number")

    if args.resume:
        from gen_presence_map import load_measurements
        # A CONNECT_FAILED record says nothing about the number, so keep it.
        covered = {num for num, (_started, status, _ret)
                   in load_measurements().items()
                   if status != CONNECT_FAILED}
        before = len(numbers)
        numbers = [n for n in numbers if n not in covered]
        print("[*] --resume left out %d already measured numbers"
              % (before - len(numbers)), flush=True)
        if not numbers:
            print("[*] nothing left to sweep in this range")
            return 0

    if args.dry_run:
        print(build_probe(numbers[0]))
        print("-- %d numbers: %s" % (len(numbers), numbers))
        return 0

    def transport(source):
        return tcp_transport(args.ps5_ip, args.port, source, args.timeout)

    waiter = None
    if args.wait_for_loader > 0:
        from send_probe import wait_for_loader
        waiter = lambda: wait_for_loader(
            args.ps5_ip, args.port, timeout=args.wait_for_loader,
            log=lambda msg: print(msg, flush=True))

    records = sweep(numbers, transport, delay=args.delay, repeat=args.repeat,
                    log=lambda msg: print("[*] " + msg, flush=True),
                    wait=waiter, wedge_guard=args.wedge_guard)
    report = format_report(records)
    print(report)
    if args.save:
        txt_path, json_path = save_report(report, records, numbers)
        print("[*] wrote %s and %s" % (txt_path, json_path))
    if any(r["aborted"] for r in records):
        print("[!] sweep aborted: the loader stopped accepting connections",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
