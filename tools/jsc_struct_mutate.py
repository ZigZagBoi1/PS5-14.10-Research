"""Structural mutation fuzzer for JavaScriptCore stress tests.

The corpus replay runs code upstream already chose; this runs code nobody
chose. Numeric mutation was measured to be useless (16 855 runs, zero
findings), because JSC bugs are almost never about a constant being one
larger. They are about the shape of the code: which value is a prototype,
which property changes type inside a loop, whether a trap mutates the object
it was called on, whether a getter runs between two inline-cache hits.

So the mutations here are structural and syntax-preserving:

  setproto   change what a setPrototypeOf target becomes
  trap       insert a prototype mutation inside a handler trap
  wrap       wrap a statement in try/catch
  loop       wrap a statement in a hot loop (forces baseline/DFG tier-up)
  dup        duplicate a statement
  reorder    swap two adjacent statements
  gc         insert gc() pressure between statements

Every mutant is executed with the shell shim under an ASAN build; crashes,
assertions and ASAN reports are recorded in results/jsc_fuzz/struct.jsonl
and the offending script is kept under results/jsc_fuzz/current/.

    python3 tools/jsc_struct_mutate.py --jsc PATH --iterations 200 --jobs 8
"""

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webkit_crash_corpus import JSC_SHIM_JS, _jsc_body  # noqa: E402
from jsc_mutate import _classify  # noqa: E402

SRC = os.path.join("results", "webkit", "corpus", "jsc_src")
OUT = os.path.join("results", "jsc_fuzz")
FINDINGS = os.path.join(OUT, "struct.jsonl")
CURRENT = os.path.join(OUT, "current")

# Prototype values that change what the engine caches about an object without
# changing its StructureID when the object is poly-proto.
PROTOS = ["null", "Object.prototype", "{}", "[]", "makePolyProtoObject()"]

TRAP_NAMES = ("get", "ownKeys", "has", "getOwnPropertyDescriptor", "set",
              "deleteProperty", "defineProperty", "apply", "construct")

_lock = threading.Lock()


def chunks(source):
    """Split source into top-level statements, respecting strings and comments.

    Returns a list of text chunks that each end at a depth-0 semicolon or a
    depth-0 closing brace. A chunk list that does not reassemble into the
    original source is a bug, so the caller checks that.
    """
    out, buf = [], []
    depth = 0
    i, n = 0, len(source)
    quote = None
    while i < n:
        c = source[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(source[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
            buf.append(c)
            i += 1
            continue
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            buf.append(source[i:j])
            i = j
            continue
        if source.startswith("/*", i):
            j = source.find("*/", i)
            j = n if j < 0 else j + 2
            buf.append(source[i:j])
            i = j
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
            buf.append(c)
            i += 1
            if depth == 0 and c == "}":
                out.append("".join(buf))
                buf = []
            continue
        if c == ";" and depth == 0:
            buf.append(c)
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return [c for c in out if c.strip()]


def mutate_setproto(source, rng):
    """Point a setPrototypeOf at a different value."""
    key = "Object.setPrototypeOf("
    positions = []
    start = 0
    while True:
        k = source.find(key, start)
        if k < 0:
            break
        positions.append(k)
        start = k + 1
    if not positions:
        return None
    k = rng.choice(positions)
    # find the second argument's span
    i = k + len(key)
    depth, comma = 1, None
    quote = None
    while i < len(source):
        c = source[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1 and comma is None:
            comma = i
        i += 1
    if comma is None:
        return None
    end = source.rfind(")", 0, i + 1)
    if end < 0:
        return None
    return source[:comma + 1] + " " + rng.choice(PROTOS) + source[end:]


def mutate_trap(source, rng):
    """Insert a prototype mutation inside a handler trap body."""
    hits = []
    for name in TRAP_NAMES:
        for pattern in (name + ": function (", name + ": (", name + "(", name + " = function ("):
            start = 0
            while True:
                k = source.find(pattern, start)
                if k < 0:
                    break
                hits.append(k)
                start = k + 1
    if not hits:
        return None
    k = rng.choice(hits)
    brace = source.find("{", k)
    if brace < 0:
        return None
    inject = "\n  try { Object.setPrototypeOf(this.__h || {}, null); } catch (e) {}\n"
    return source[:brace + 1] + inject + source[brace + 1:]


def _simple(parts):
    """Indices of chunks that are standalone statements.

    A chunk ending in `}` may be the head of an if/else chain or a function
    declaration; wrapping or reordering those produces a syntax error, which
    wastes a run. Only `;`-terminated chunks that do not continue an earlier
    block are safe to move.
    """
    out = []
    for i, c in enumerate(parts):
        t = c.strip()
        if not t.endswith(";"):
            continue
        if t.startswith(("}", "else", "catch", "finally")):
            continue
        out.append(i)
    return out


def mutate_wrap(source, parts, rng):
    simple = _simple(parts)
    if not simple:
        return None
    i = rng.choice(simple)
    parts[i] = "try {" + parts[i] + "} catch (e) {}"
    return "".join(parts)


def mutate_loop(source, parts, rng):
    simple = _simple(parts)
    if not simple:
        return None
    i = rng.choice(simple)
    parts[i] = "for (let __i = 0; __i < 200; __i++) {" + parts[i] + "}"
    return "".join(parts)


def mutate_dup(source, parts, rng):
    i = rng.randrange(len(parts))
    parts.insert(i, parts[i])
    return "".join(parts)


def mutate_reorder(source, parts, rng):
    simple = _simple(parts)
    if len(simple) < 2:
        return None
    i = rng.choice(simple[:-1])
    if i + 1 not in simple:
        return None
    parts[i], parts[i + 1] = parts[i + 1], parts[i]
    return "".join(parts)


def mutate_gc(source, parts, rng):
    i = rng.randrange(len(parts))
    if not _simple(parts):
        return None
    parts.insert(i, "gc();")
    return "".join(parts)


MUTATORS = [
    ("setproto", mutate_setproto),
    ("trap", mutate_trap),
    ("wrap", mutate_wrap),
    ("loop", mutate_loop),
    ("dup", mutate_dup),
    ("reorder", mutate_reorder),
    ("gc", mutate_gc),
]


def apply(source, rng):
    """Apply one mutation, returning (name, text) or None if not applicable."""
    for name, fn in rng.sample(MUTATORS, len(MUTATORS)):
        try:
            if fn.__code__.co_argcount == 2:
                out = fn(source, rng)
            else:
                parts = chunks(source)
                if len(parts) < 2:
                    continue
                out = fn(source, parts, rng)
        except Exception:
            continue
        if out and out != source:
            return name, out
    return None


def run_one(jsc, text, timeout):
    fd, path = tempfile.mkstemp(suffix=".js", dir=CURRENT)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    env = dict(os.environ,
               ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1")
    started = time.time()
    try:
        done = subprocess.run([jsc, path], capture_output=True, timeout=timeout,
                              env=env)
        output = (done.stdout + done.stderr).decode("utf-8", "replace")
        kind = _classify(done.returncode, output)
        elapsed = time.time() - started
    except subprocess.TimeoutExpired:
        output, kind, elapsed = "", "timeout", time.time() - started
    if kind not in ("asan", "assert", "signal"):
        os.unlink(path)
        return kind, None, elapsed
    return kind, path, elapsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsc", required=True)
    ap.add_argument("--src", default=SRC)
    ap.add_argument("--iterations", type=int, default=200,
                    help="mutants per seed")
    ap.add_argument("--limit", type=int, default=0,
                    help="use only the first N seeds")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default="",
                    help="comma-separated seed substrings to fuzz")
    args = ap.parse_args()

    os.makedirs(CURRENT, exist_ok=True)
    seeds = sorted(os.listdir(args.src))
    if args.only:
        keys = [k for k in args.only.split(",") if k]
        seeds = [s for s in seeds if any(k in s for k in keys)]
    if args.limit:
        seeds = seeds[:args.limit]

    counts = {"clean": 0, "asan": 0, "assert": 0, "signal": 0,
              "timeout": 0, "parse": 0, "exception": 0, "skipped": 0}
    seen = set()
    total = len(seeds) * args.iterations
    done_count = 0

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = []
        for name in seeds:
            with open(os.path.join(args.src, name), encoding="utf-8",
                      errors="replace") as fh:
                source = _jsc_body(fh.read())
            for it in range(args.iterations):
                rng = random.Random((args.seed, name, it).__hash__())
                got = apply(source, rng)
                if not got:
                    counts["skipped"] += 1
                    done_count += 1
                    continue
                mut, text = got
                full = JSC_SHIM_JS + "\n" + text + "\n"
                futures.append((name, mut, it, pool.submit(run_one, args.jsc,
                                                           full, args.timeout)))
        for name, mut, it, fut in futures:
            kind, path, elapsed = fut.result()
            counts[kind if kind else "clean"] += 1
            done_count += 1
            if kind in ("asan", "assert", "signal"):
                key = (kind, name)
                with _lock:
                    if key not in seen:
                        seen.add(key)
                        rec = {"kind": kind, "seed": name, "mutation": mut,
                               "iteration": it, "seconds": round(elapsed, 1),
                               "script": path}
                        with open(FINDINGS, "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                print(f"{kind:8s} {name} [{mut}] {path}", flush=True)
            if done_count % 100 == 0:
                print(f"... {done_count}/{total} {counts}", flush=True)
    print("done:", counts)


if __name__ == "__main__":
    main()
