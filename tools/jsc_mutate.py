#!/usr/bin/env python3
"""Mutate JavaScriptCore regression tests and run them under the local jsc.

The console's engine predates the fixes that these tests were added with, so a
test that exercises a recently-fixed path is a good starting point for a
mutation: the fix is absent here, and a small change to the constants or the
control flow can reach a state the upstream test never covered.

Every run is a fresh `jsc` process. A finding is an ASAN report, a signal exit,
or a timeout; the mutated source is written next to the report so it can be
replayed with `jsc <file>`.

    python tools/jsc_mutate.py --jsc ~/webkit-7617/WebKitBuild/Debug/bin/jsc \
        --src results/webkit/corpus/jsc_src --iterations 40 --jobs 4
"""

import argparse
import concurrent.futures
import json
import pathlib
import random
import re
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from webkit_crash_corpus import JSC_SHIM_JS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "jsc_fuzz"

NUMBER = re.compile(r"(?<![\w.])(\d{1,7})(?![\w.])")
COMPARE = re.compile(r"(<=|>=|<|>|===|!==|==|!=)")
ARITH = re.compile(r"(?<=[\w\])])\s*([+\-*/%])\s*(?=[\w(\[])")


def mutate(source, rng):
    """Return a mutated source and the list of operations that were applied."""
    applied = []

    def bump_numbers(text):
        def repl(match):
            if rng.random() > 0.35:
                return match.group(0)
            value = int(match.group(1))
            choice = rng.random()
            if choice < 0.4:
                value = value + rng.choice([-1, 1, 2])
            elif choice < 0.7:
                value = rng.choice([0, 1, 2, 3, 7, 16, 255, 256, 4096])
            else:
                value = max(0, int(value * rng.choice([2, 4, 16])))
            return str(value)

        return NUMBER.sub(repl, text)

    def swap_compare(text):
        def repl(match):
            if rng.random() > 0.25:
                return match.group(0)
            table = {"<": "<=", "<=": "<", ">": ">=", ">=": ">", "==": "!=", "!=": "==",
                     "===": "!==", "!==": "==="}
            return table.get(match.group(1), match.group(1))

        return COMPARE.sub(repl, text)

    def swap_arith(text):
        def repl(match):
            if rng.random() > 0.2:
                return match.group(0)
            table = {"+": "-", "-": "+", "*": "/", "/": "*", "%": "*"}
            return table.get(match.group(1), match.group(1))

        return ARITH.sub(repl, text)

    def duplicate_line(text):
        lines = text.splitlines()
        if len(lines) < 3:
            return text
        index = rng.randrange(1, len(lines))
        lines.insert(index, lines[index])
        applied.append("duplicate-line")
        return "\n".join(lines)

    def truncate_loop(text):
        def repl(match):
            if rng.random() > 0.3:
                return match.group(0)
            return "for (var %s = 0; %s < %d; %s++)" % (
                match.group(1), match.group(1), rng.choice([0, 1, 2, 3, 8]), match.group(1))

        return re.sub(r"for \(var (\w+) = 0; \1 < [^;]+; \1\+\+\)", repl, text)

    for name, function in (("numbers", bump_numbers), ("compare", swap_compare),
                           ("arith", swap_arith), ("loop", truncate_loop)):
        if rng.random() < 0.6:
            mutated = function(source)
            if mutated != source:
                applied.append(name)
                source = mutated
    if rng.random() < 0.15:
        source = duplicate_line(source)
    return source, applied


def _classify(returncode, stderr):
    """Name the outcome of one jsc run, or None when it finished cleanly.

    A parse error is its own outcome on purpose. The first version of this
    harness fed the page shim (with its `<script>` wrapper) to jsc, so every run
    died on `SyntaxError: Unexpected token '<'` and was counted as clean: 16,855
    mutations and 2,280 verbatim cases measured nothing. Anything that stops the
    case from running has to be visible in the totals.
    """
    if "AddressSanitizer" in stderr or "runtime error:" in stderr:
        return "asan"
    if "ASSERTION FAILED" in stderr:
        # A debug-only assertion. The release build the console runs compiles
        # this check out, so the value that failed it keeps going: this is the
        # class that matters, not a harness error.
        return "assert"
    if returncode < 0 or returncode > 128:
        return "signal"
    if "SyntaxError" in stderr:
        return "parse"
    if "Exception:" in stderr or "Error:" in stderr:
        return "exception"
    return None


def run_one(jsc, source, timeout):
    """Run one source under jsc and classify the outcome."""
    script = JSC_SHIM_JS + "\n" + source + "\n"
    path = OUT / "current" / ("%d-%d.js" % (time.time() * 1000, random.randrange(1 << 30)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script, encoding="utf-8", errors="replace")
    env = {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
           "PATH": "/usr/bin:/bin"}
    try:
        done = subprocess.run([jsc, str(path)], capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"kind": "timeout", "path": str(path)}
    # jsc prints an uncaught exception to stdout, not stderr; a classifier that
    # read only stderr called every broken run clean.
    stderr = (done.stdout + done.stderr).decode("utf-8", "replace")
    kind = _classify(done.returncode, stderr)
    if kind is None:
        path.unlink(missing_ok=True)
        return None
    if kind in ("parse", "exception"):
        path.unlink(missing_ok=True)
    detail = stderr[-4000:] if kind == "asan" else stderr[-600:]
    return {"kind": kind, "path": str(path), "detail": detail}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsc", required=True, help="path to the jsc binary")
    parser.add_argument("--src", default="results/webkit/corpus/jsc_src",
                        help="directory of .js sources to mutate")
    parser.add_argument("--iterations", type=int, default=20,
                        help="mutated runs per source")
    parser.add_argument("--limit", type=int, default=0, help="only the first N sources")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--no-mutate", action="store_true",
                        help="run each source verbatim; the corpus itself is the input")
    parser.add_argument("--jobs", type=int, default=1,
                        help="how many jsc processes to keep in flight")
    args = parser.parse_args()

    jsc = str(pathlib.Path(args.jsc).expanduser())
    sources = sorted(pathlib.Path(args.src).glob("*.js"))
    if args.limit:
        sources = sources[:args.limit]
    if not sources:
        raise SystemExit("no sources in %s" % args.src)

    OUT.mkdir(parents=True, exist_ok=True)
    findings = OUT / "findings.jsonl"
    rng = random.Random(args.seed or None)
    counts = {"clean": 0, "asan": 0, "assert": 0, "signal": 0, "timeout": 0,
              "parse": 0, "exception": 0}

    lock = threading.Lock()
    done = 0

    def work(item):
        nonlocal done
        source_name, mutated, applied = item
        result = run_one(jsc, mutated, args.timeout)
        with lock:
            done += 1
            counts[result["kind"] if result else "clean"] += 1
            if result:
                result.update({"source": source_name, "ops": applied})
                with findings.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result) + "\n")
                print("%-8s %s %s" % (result["kind"], source_name, ",".join(applied)))
            if done % 100 == 0:
                print("... %d runs, %s" % (done, counts))
                sys.stdout.flush()

    jobs = []
    for source_path in sources:
        original = source_path.read_text(encoding="utf-8", errors="replace")
        if args.no_mutate:
            jobs.append((source_path.name, original, ["verbatim"]))
            continue
        for _ in range(args.iterations):
            mutated, applied = mutate(original, rng)
            if applied:
                jobs.append((source_path.name, mutated, applied))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for _ in pool.map(work, jobs):
            pass

    print("done: %s" % counts)


if __name__ == "__main__":
    main()
