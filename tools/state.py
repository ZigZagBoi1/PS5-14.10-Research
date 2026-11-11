#!/usr/bin/env python3
"""Session state and run ledger for the 14.10 research tree.

The point of this tool is to keep facts OUT of the conversation. An agent that
has to remember something loses it at the next context compaction; an agent that
can read a ten-line state block and grep a flat ledger does not.

Files
-----
results/STATE.md   the one mutable state block (rewritten in place, not appended)
results/INDEX.md   append-only ledger, one line per console run

Commands
--------
    python tools/state.py show
    python tools/state.py set key=value [key=value ...]
    python tools/state.py row <probe> --claim TEXT --result TEXT
                                   [--grade M|S|I|V|D] [--capture PATH]
    python tools/state.py seed
    python tools/state.py check [--ip ADDR]

Grades
------
    M  measured on the console this session
    S  read from a source file or dump (offline)
    I  inference, not measured
    V  void: the probe died or never reached the handler, so the row proves nothing
    D  dead end, with the reason in --result

Read-only for the console: nothing here opens a socket except ``check --ip``,
which only attempts a TCP connect.
"""

import argparse
import datetime as _dt
import os
import re
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")
STATE = os.path.join(RESULTS, "STATE.md")
INDEX = os.path.join(RESULTS, "INDEX.md")

BEGIN = "<!-- STATE:BEGIN -->"
END = "<!-- STATE:END -->"

DEFAULT_STATE = [
    ("console", "unknown  (run: state.py check --ip <addr>)"),
    ("kernel_base", "unknown  (re-measure with .local/1331a.lua after every boot)"),
    ("kernel_base_measured", "-"),
    ("last_probe", "-"),
    ("active_question", "-"),
    ("next_action", "-"),
    ("open_risks", "-"),
    ("notes", "-"),
]

INDEX_HEADER = """# Run ledger

One line per console run. Append with `python tools/state.py row ...`; never edit
history. Search it before writing a probe: `grep -n 622 results/INDEX.md`.

A row without a capture path is not evidence. Grade `V` means the probe died or
never reached the handler: it is not a dead end and must not be cited as one.
Grade `?` marks a capture that has been indexed but not yet read and graded.
Date column: `YYYY-MM-DD HH:MM` comes from the capture's name, `YYYY-MM-DD` is a
date-only name, and a trailing `~` means the date was taken from the file's mtime.

| date (UTC) | probe | claim | result | grade | capture |
|---|---|---|---|---|---|
"""

CAPTURE_RE = re.compile(r"^(?P<probe>[A-Za-z0-9]+).*?(?P<d>\d{8})(?:_(?P<t>\d{6}))?\.txt$")

# Fields go into a Markdown table, so a pipe would add a column and a newline would
# add a row. Both are sanitised on the way in; the ledger is append-only and cannot
# be repaired afterwards.
def _cell(value):
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text.strip() or "-"



def _set_root(path):
    """Point every derived path at another tree (used by the tests)."""
    global ROOT, RESULTS, STATE, INDEX
    ROOT = os.path.abspath(path)
    RESULTS = os.path.join(ROOT, "results")
    STATE = os.path.join(RESULTS, "STATE.md")
    INDEX = os.path.join(RESULTS, "INDEX.md")


def _rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def _read_state():
    if not os.path.exists(STATE):
        return list(DEFAULT_STATE)
    text = open(STATE, encoding="utf-8", errors="replace").read()
    if BEGIN not in text or END not in text:
        return list(DEFAULT_STATE)
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    pairs = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("- ") or ":" not in line:
            continue
        key, value = line[2:].split(":", 1)
        pairs.append((key.strip(), value.strip()))
    return pairs or list(DEFAULT_STATE)


def _write_state(pairs):
    for key, value in pairs:
        if "\n" in str(key) or "\n" in str(value) or "\r" in str(key) or "\r" in str(value):
            raise SystemExit(
                "state values must fit on one line: %r" % (key,)
            )
    os.makedirs(RESULTS, exist_ok=True)
    body = "\n".join("- %s: %s" % (k, v) for k, v in pairs)
    text = (
        "# Research state\n\n"
        "Rewrite this block with `python tools/state.py set key=value`. It is the\n"
        "only memory that survives a context compaction, so keep it current and\n"
        "short. Volatile values (kernel base, console liveness) carry the time they\n"
        "were measured; they are measurements, not truths.\n\n"
        "%s\n%s\n%s\n\n"
        "Session start: this block, then the last ten rows of `results/INDEX.md`,\n"
        "then only the document section the active question names.\n" % (BEGIN, body, END)
    )
    with open(STATE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return pairs


def _indexed_captures():
    seen = set()
    if not os.path.exists(INDEX):
        return seen
    for line in open(INDEX, encoding="utf-8", errors="replace"):
        match = re.search(r"\|\s*(results/\S+?\.txt)\s*\|\s*$", line.rstrip())
        if match:
            seen.add(match.group(1))
    return seen


def _drop_rows_for_capture(capture):
    """Remove rows already bound to this capture, so a re-grade replaces one row."""
    if not capture or not os.path.exists(INDEX):
        return 0
    lines = open(INDEX, encoding="utf-8", errors="replace").read().splitlines()
    kept, dropped = [], 0
    for line in lines:
        match = re.search(r"\|\s*(results/\S+?\.txt)\s*\|\s*$", line.strip())
        if match and match.group(1) == capture:
            dropped += 1
            continue
        kept.append(line)
    if dropped:
        with open(INDEX, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(kept) + "\n")
    return dropped


def _append_rows(rows):
    os.makedirs(RESULTS, exist_ok=True)
    fresh = not os.path.exists(INDEX) or os.path.getsize(INDEX) == 0
    needs_separator = False
    if not fresh:
        with open(INDEX, "rb") as existing:
            existing.seek(-1, os.SEEK_END)
            needs_separator = existing.read(1) != b"\n"
    with open(INDEX, "a", encoding="utf-8", newline="\n") as fh:
        if fresh:
            fh.write(INDEX_HEADER)
        elif needs_separator:
            fh.write("\n")
        for row in rows:
            fh.write(
                "| %s | %s | %s | %s | %s | %s |\n"
                % tuple(_cell(v) for v in (
                    row["date"], row["probe"], row["claim"], row["result"],
                    row["grade"], row["capture"] or "-"))
            )


def _capture_stamp(path):
    """Return (stamp, probe, source) for one capture, or (None, None, None).

    Older captures carry a date and no clock time, and a few carry no date at all.
    Dropping them hides evidence: a capture that exists and cannot be found by
    `seed` is exactly the hole the ledger is meant to close. So the stamp falls back
    from the name's clock to the name's date to the file's own mtime, and the source
    decides how the row labels it.
    """
    name = os.path.basename(path)
    match = CAPTURE_RE.search(name)
    if match:
        probe = match.group("probe")
        clock = match.group("t") or "000000"
        try:
            stamp = _dt.datetime.strptime(match.group("d") + clock, "%Y%m%d%H%M%S")
        except ValueError:
            return None, probe, None
        return stamp, probe, "clock" if match.group("t") else "date"
    probe = re.match(r"[A-Za-z0-9]+", name)
    if not probe:
        return None, None, None
    try:
        stamp = _dt.datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        return None, probe.group(0), None
    return stamp, probe.group(0), "mtime"


def _iter_captures():
    for dirpath, _dirnames, filenames in os.walk(RESULTS):
        for name in sorted(filenames):
            # `_name.txt` is a tool log, not a run capture; the underscore is the
            # documented opt-out so `seed` can claim complete coverage of the rest.
            if name.endswith(".txt") and not name.startswith("_"):
                yield os.path.join(dirpath, name)


def cmd_seed(_args):
    already = _indexed_captures()
    rows = []
    for path in _iter_captures():
        rel = _rel(path)
        if rel in already:
            continue
        stamp, probe, source = _capture_stamp(path)
        if stamp is None or probe is None:
            continue
        # A label says where the time came from: exact clock, date only, or the file's
        # mtime (marked `~`, which is a property of the copy rather than the run).
        if source == "clock":
            label = stamp.strftime("%Y-%m-%d %H:%M")
        elif source == "date":
            label = stamp.strftime("%Y-%m-%d")
        else:
            label = stamp.strftime("%Y-%m-%d") + "~"
        rows.append({
            "date": label,
            "probe": probe,
            "claim": "-",
            "result": "-",
            "grade": "?",
            "capture": rel,
        })
    rows.sort(key=lambda r: (r["date"], r["probe"]))
    _append_rows(rows)
    print("seeded %d row(s) into %s" % (len(rows), _rel(INDEX)))
    return 0


def cmd_row(args):
    capture = args.capture
    if not capture:
        newest = None
        for path in _iter_captures():
            name = os.path.basename(path)
            if not name.startswith(args.probe):
                continue
            mtime = os.path.getmtime(path)
            if newest is None or mtime > newest[0]:
                newest = (mtime, path)
        if newest is None:
            print("warning: no capture matches probe %r; row records '-'" % args.probe,
                  file=sys.stderr)
        else:
            capture = _rel(newest[1])
    row = {
        "date": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "probe": args.probe,
        "claim": args.claim or "-",
        "result": args.result or "-",
        "grade": args.grade,
        "capture": capture,
    }
    replaced = _drop_rows_for_capture(capture)
    _append_rows([row])
    if replaced:
        print("replaced %d row(s) for %s" % (replaced, capture))
    print("appended: %s | %s | %s | %s" % (row["probe"], row["claim"], row["result"], row["grade"]))
    return 0


def cmd_set(args):
    pairs = _read_state()
    order = [key for key, _ in pairs]
    current = dict(pairs)
    for item in args.pairs:
        if "=" not in item:
            print("bad assignment %r (want key=value)" % item, file=sys.stderr)
            return 2
        key, value = item.split("=", 1)
        if key not in current:
            order.append(key)
        current[key] = value
    _write_state([(key, current[key]) for key in order])
    print("state updated: " + ", ".join(item.split("=", 1)[0] for item in args.pairs))
    return 0


def cmd_show(_args):
    pairs = _read_state()
    width = max(len(key) for key, _ in pairs)
    for key, value in pairs:
        print("%-*s  %s" % (width, key, value))
    return 0


def cmd_check(args):
    pairs = _read_state()
    print("== state ==")
    for key, value in pairs:
        print("  %-20s %s" % (key + ":", value))

    print("\n== ledger tail ==")
    if os.path.exists(INDEX):
        lines = [line.rstrip() for line in
                 open(INDEX, encoding="utf-8", errors="replace")]
        for line in lines[-11:]:
            print("  " + line)
    else:
        print("  (no %s yet)" % _rel(INDEX))

    ip = args.ip or os.environ.get("PS5_IP")
    if not ip:
        print("\n== console ==\n  skipped (no --ip and PS5_IP unset)")
        return 0
    print("\n== console %s:9026 ==" % ip)
    try:
        socket.create_connection((ip, 9026), timeout=3).close()
        print("  reachable")
    except OSError as exc:
        print("  UNREACHABLE: %s" % exc)
        print("  -> the game process is dead; ask the user to relaunch before any probe")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None,
                        help="research tree root (default: the repository)")
    sub = parser.add_subparsers(dest="command")

    show = sub.add_parser("show", help="print the state block")
    show.set_defaults(func=cmd_show)

    setter = sub.add_parser("set", help="set key=value pairs and rewrite the block")
    setter.add_argument("pairs", nargs="+")
    setter.set_defaults(func=cmd_set)

    row = sub.add_parser("row", help="append one run to results/INDEX.md")
    row.add_argument("probe")
    row.add_argument("--claim", default="-")
    row.add_argument("--result", default="-")
    row.add_argument("--grade", choices=list("MSIVD"), default="M")
    row.add_argument("--capture", default=None)
    row.set_defaults(func=cmd_row)

    seed = sub.add_parser("seed", help="index every capture not already in the ledger")
    seed.set_defaults(func=cmd_seed)

    check = sub.add_parser("check", help="resume checklist: state, ledger tail, console")
    check.add_argument("--ip", default=None)
    check.set_defaults(func=cmd_check)
    return parser


def main(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.root:
        _set_root(args.root)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
