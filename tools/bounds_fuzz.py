"""Fuzz the buffer-size arguments of the present Sony handlers.

Every earlier test of 574-660 handed the handler one 0x400 page and a size it
either ignored or rejected, so the only thing measured was its return value.
This driver varies the declared size instead, and the probe watches for dwords
changed outside the region the handler was told it owns. A handler that copies
more than it was given shows up as an overflow, which a return value cannot
show, and a handler that writes while the size says zero is the same finding
from the other direction.

One connection per (number, layout, size) triple: a handler that faults takes
the whole loader with it, and the sweep driver has already shown that the game
brings a fresh loader up about ten seconds later.

A size above 0x10000 tells the kernel to copy far more than the probe allocated.
If the handler trusts the size, the copy crosses into unmapped memory and the
console panics; that needs a physical power cycle, not a relaunch. The default
size list therefore stays small, and going bigger is an explicit flag.
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from tools.syscall_isolation_sweep import (
        CONNECT_FAILED,
        KILLED_IN_CALL,
        NO_OUTPUT,
        RETURNED,
        parse_range,
        tcp_transport,
    )
    from tools.send_probe import wait_for_loader
except ModuleNotFoundError:  # run directly as `python tools/bounds_fuzz.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.syscall_isolation_sweep import (
    CONNECT_FAILED,
    KILLED_IN_CALL,
    NO_OUTPUT,
    RETURNED,
        parse_range,
        tcp_transport,
    )
    from tools.send_probe import wait_for_loader

BEGIN = "BFUZZ BEGIN {num} {layout} {size}"
BEFORE = "BFUZZ BEFORE {num} {layout} {size}"
RESULT = "BFUZZ RESULT {num} {layout} {size} "
SCAN = "BFUZZ SCAN {num} {layout} {size} "
DONE = "BFUZZ DONE {num} {layout} {size}"

DEFAULT_SIZES = [0, 1, 0x100, 0x1000]
DEFAULT_LAYOUTS = ["a1_size_buf", "a1_buf_size", "size_a1_buf"]

# The probe allocates TOTAL bytes and hands the handler BUF_OFF inside it, so a
# write past the declared size lands in memory the probe still owns and can see.
TOTAL = 0x6000
BUF_OFF = 0x2000
CANARY = 0xA5A5A5A5

PROBE_TEMPLATE = """print("{begin}")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {{}}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    pcall(function() memory.write_dword(addr, val) end)
end
local TOTAL = {total}
local BUF_OFF = {buf_off}
local BASE = memory.alloc(TOTAL)
local BUF = BASE + BUF_OFF
local CANARY = {canary}
local i
for i = 0, TOTAL - 4, 4 do
    safe_wd(BASE + i, CANARY)
end
print("{before}")
local ok, ret = pcall(function()
    return make_syscall({num})({call})
end)
local ret_str
if ok then
    ret_str = tostring(ret)
else
    ret_str = "raise:" .. tostring(ret)
end
print("{result}" .. ret_str)
local inside, outside, first, kp, nsample = 0, 0, -1, 0, 0
local sample = ""
local function ud(v)
    if v < 0 then return v + 4294967296 end
    return v
end
for i = 0, TOTAL - 4, 4 do
    local v = safe_rd(BASE + i)
    if v ~= CANARY then
        local off = i - BUF_OFF
        if off >= 0 and off < {size} then
            inside = inside + 1
        else
            outside = outside + 1
            if first < 0 then first = i end
        end
        -- A qword shaped like 0xFFFF8xxx_xxxxxxxx is a kernel address. A copyout
        -- that fills our buffer with one handed over kernel memory, which is the
        -- finding worth chasing; the changed-dword count alone cannot say.
        if i <= TOTAL - 8 then
            local hi = safe_rd(BASE + i + 4)
            if hi ~= nil and ud(hi) >= 4294938624 then kp = kp + 1 end
        end
        if nsample < 4 then
            nsample = nsample + 1
            if nsample > 1 then sample = sample .. "|" end
            sample = sample .. string.format("%d:%s", off, tostring(v))
        end
    end
end
print(string.format("{scan}inside=%d outside=%d first=%d kp=%d sample=%s",
    inside, outside, first, kp, sample))
print("{done}")
"""

# Each layout is (name, Lua call expression). A1, SIZE and BUF are substituted.
LAYOUTS = {
    "a1_size_buf": "uint64(A1), uint64(SIZE), BUF, uint64(0), uint64(0), uint64(0)"
                   .replace("A1", "{a1}").replace("SIZE", "{size}"),
    "a1_buf_size": "uint64({a1}), BUF, uint64({size}), uint64(0), uint64(0), uint64(0)",
    "size_a1_buf": "uint64({size}), uint64({a1}), BUF, uint64(0), uint64(0), uint64(0)",
    "a1_size_buf_size": "uint64({a1}), uint64({size}), BUF, uint64({size}), uint64(0), uint64(0)",
}


def build_probe(num, layout, size, a1=0):
    """Return the Lua source for one (number, layout, size) triple."""
    return PROBE_TEMPLATE.format(
        begin=BEGIN.format(num=num, layout=layout, size=size),
        before=BEFORE.format(num=num, layout=layout, size=size),
        result=RESULT.format(num=num, layout=layout, size=size),
        scan=SCAN.format(num=num, layout=layout, size=size),
        done=DONE.format(num=num, layout=layout, size=size),
        num=num,
        layout=layout,
        size=size,
        a1=a1,
        call=LAYOUTS[layout].format(a1=a1, size=size),
        total=TOTAL,
        buf_off=BUF_OFF,
        canary=CANARY,
    )


def parse_response(output, num, layout, size):
    """Turn one probe response into (status, detail dict)."""
    if output is None:
        return CONNECT_FAILED, {}
    text = output
    begin = BEGIN.format(num=num, layout=layout, size=size)
    result_prefix = RESULT.format(num=num, layout=layout, size=size)
    scan_prefix = SCAN.format(num=num, layout=layout, size=size)
    detail = {"ret": None, "inside": None, "outside": None, "first": None,
              "kp": None, "sample": ""}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(result_prefix):
            detail["ret"] = line[len(result_prefix):]
        elif line.startswith(scan_prefix):
            body = line[len(scan_prefix):]
            for key in ("inside", "outside", "first", "kp"):
                found = re.search(key + r"=(-?\d+)", body)
                if found:
                    detail[key] = int(found.group(1))
            found = re.search(r"sample=(\S*)", body)
            if found:
                detail["sample"] = found.group(1)
    if detail["outside"] is not None:
        return RETURNED, detail
    if begin in text:
        return KILLED_IN_CALL, detail
    return NO_OUTPUT, detail


def verdict(record):
    """Name the finding a record carries, or an empty string for nothing new."""
    if record["status"] != RETURNED:
        return ""
    if (record.get("kp") or 0) > 0:
        return "KERNEL-POINTER"
    outside = record["outside"] or 0
    if outside > 0:
        return "OVERFLOW"
    if record["size"] == 0 and (record["inside"] or 0) > 0:
        return "WROTE_AT_ZERO_SIZE"
    return ""


def fuzz(numbers, layouts, sizes, a1_values, transport, delay=0.6,
         sleep=time.sleep, log=None, wait=None, on_record=None, skip=None):
    """Run one connection per triple and return a record per triple."""
    log = log or (lambda _msg: None)
    on_record = on_record or (lambda _record: None)
    skip = skip or set()
    records = []
    for num in numbers:
        for layout in layouts:
            for size in sizes:
                for a1 in a1_values:
                    if (num, layout, size, a1) in skip:
                        continue
                    record = {"num": num, "layout": layout, "size": size, "a1": a1,
                              "attempts": []}
                    waited = False
                    while True:
                        sleep(delay)
                        output = transport(build_probe(num, layout, size, a1))
                        status, detail = parse_response(output, num, layout, size)
                        record["attempts"].append({"status": status, "detail": detail})
                        record.update({"status": status, **detail})
                        log("sys %d %s size=%#x a1=%d: %s" % (num, layout, size, a1, status))
                        if status != CONNECT_FAILED:
                            break
                        if wait is None or waited:
                            record["aborted"] = True
                            break
                        log("loader is down; waiting for the game to restart it")
                        if not wait():
                            record["aborted"] = True
                            break
                        waited = True
                    records.append(record)
                    on_record(record)
                    if record.get("aborted"):
                        return records
                    record.setdefault("aborted", False)
    return records


def load_journal(path):
    """Return (records, keys) from a journal, ignoring a torn last line."""
    records, keys = [], set()
    path = Path(path)
    if not path.exists():
        return records, keys
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:  # a hard kill can leave half a line behind
            continue
        records.append(rec)
        keys.add((rec["num"], rec["layout"], rec["size"], rec["a1"]))
    return records, keys


def format_report(records):
    """Render the fuzz result as a fixed-width table."""
    lines = ["%-5s %-17s %-8s %-4s %-14s %-7s %-8s %-7s %s" % (
        "num", "layout", "size", "a1", "status", "inside", "outside", "first", "ret"),
        "-" * 96]
    for rec in records:
        lines.append("%-5d %-17s %-8s %-4d %-14s %-7s %-8s %-7s %s" % (
            rec["num"], rec["layout"], hex(rec["size"]), rec["a1"], rec["status"],
            "" if rec.get("inside") is None else rec["inside"],
            "" if rec.get("outside") is None else rec["outside"],
            "" if rec.get("first") is None else rec["first"],
            rec.get("ret") or "",
        ))
    lines.append("")
    counts = {}
    for rec in records:
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    lines.append("SUMMARY: %d probes, %s" % (
        len(records), ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))))
    hits = ["sys %d %s size=%#x: %s (inside=%s outside=%s kp=%s sample=%s)" % (
                r["num"], r["layout"], r["size"], verdict(r),
                r.get("inside"), r.get("outside"), r.get("kp"), r.get("sample") or "-")
            for r in records if verdict(r)]
    if hits:
        lines.append("Interesting:")
        lines.extend("  " + hit for hit in hits)
    else:
        lines.append("No handler wrote outside the size it was given, and no "
                     "changed dword paired into a kernel-shaped address.")
    return "\n".join(lines)


def save_report(report, records, stamp=None):
    """Write the table and a JSON record under results/phase17_new_vectors/."""
    out_dir = Path("results") / "phase17_new_vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = out_dir / ("bounds_fuzz_%s.txt" % stamp)
    json_path = out_dir / ("bounds_fuzz_%s.json" % stamp)
    txt_path.write_text(report + "\n", encoding="utf-8")
    json_path.write_text(json.dumps({"started_at": stamp, "records": records},
                                    indent=2), encoding="utf-8")
    return txt_path, json_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ps5-ip", required=True)
    parser.add_argument("--port", type=int, default=9026)
    parser.add_argument("--range", default="574-660")
    parser.add_argument("--skip", default="430",
                        help="comma/range of numbers never to call")
    parser.add_argument("--layouts", default=",".join(DEFAULT_LAYOUTS))
    parser.add_argument("--sizes", default=",".join(hex(s) for s in DEFAULT_SIZES),
                        help="declared buffer sizes to try; above 0x10000 risks a panic")
    parser.add_argument("--a1", default="0")
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--wait-for-loader", type=float, default=240.0)
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--log-file", default=None,
                        help="also append each progress line to this file")
    parser.add_argument("--journal", default=None,
                        help="append every record here as JSON lines; survives a crash")
    parser.add_argument("--resume", action="store_true",
                        help="skip the triples the journal already holds")
    args = parser.parse_args(argv)

    numbers = parse_range(args.range)
    skipped = set(parse_range(args.skip)) if args.skip else set()
    numbers = [n for n in numbers if n not in skipped]
    layouts = [name.strip() for name in args.layouts.split(",") if name.strip()]
    unknown = [name for name in layouts if name not in LAYOUTS]
    if unknown:
        parser.error("unknown layout(s): %s" % ", ".join(unknown))
    sizes = [int(part, 0) for part in args.sizes.split(",") if part.strip()]
    a1_values = [int(part, 0) for part in args.a1.split(",") if part.strip()]
    over = [s for s in sizes if s > 0x10000]
    if over:
        print("[!] sizes above 0x10000 can panic the console: %s"
              % ", ".join(hex(s) for s in over))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.save and not args.journal:
        (Path("results") / "phase17_new_vectors").mkdir(parents=True, exist_ok=True)
        args.journal = str(Path("results") / "phase17_new_vectors"
                           / ("bounds_fuzz_%s.jsonl" % stamp))

    if args.resume and not args.journal:
        candidates = sorted((Path("results") / "phase17_new_vectors").glob("bounds_fuzz_*.jsonl"))
        if candidates:
            args.journal = str(candidates[-1])

    prior, done = [], set()
    journal = None
    if args.journal:
        if args.resume:
            prior, done = load_journal(args.journal)
        journal = open(args.journal, "a", encoding="utf-8")

    log_stream = None
    if args.log_file:
        log_stream = open(args.log_file, "a", encoding="utf-8")

    def log(message):
        print(message, flush=True)
        if log_stream:
            log_stream.write(message + "\n")
            log_stream.flush()

    def on_record(rec):
        if journal:
            journal.write(json.dumps(rec) + "\n")
            journal.flush()
        hit = verdict(rec)
        if hit:
            log("HIT sys %d %s size=%#x: %s (inside=%s outside=%s kp=%s sample=%s)" % (
                rec["num"], rec["layout"], rec["size"], hit, rec.get("inside"),
                rec.get("outside"), rec.get("kp"), rec.get("sample") or "-"))

    transport = lambda src: tcp_transport(args.ps5_ip, args.port, src, args.timeout)
    wait = None
    if args.wait_for_loader:
        wait = lambda: wait_for_loader(args.ps5_ip, args.port, args.wait_for_loader,
                                       answers=True)
    records = prior + fuzz(numbers, layouts, sizes, a1_values, transport,
                           delay=args.delay, wait=wait, log=log,
                           on_record=on_record, skip=done)
    report = format_report(records)
    print(report)
    if args.save:
        txt_path, json_path = save_report(report, records, stamp=stamp)
        print("[*] wrote %s and %s" % (txt_path, json_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
