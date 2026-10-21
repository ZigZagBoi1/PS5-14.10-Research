#!/usr/bin/env python3
"""Harvest public WebKit crash-regression tests for replay on the console.

Why this exists
---------------
The 14.10 User's Guide runs a WebKit built around Safari 17.0 (September 2023),
inside a firmware shipped in 2026. Nothing in the repository measures what that
engine does with the three years of crash fixes WebKit landed after it was cut.
WebKit's own layout tests reproduce each of those crashes, and they are public.
Replaying them on the console turns "maybe an old bug is reachable" into a
measurable question with a yes/no answer per test.

Pipeline
--------
1. `harvest`  -- commit search for crash fixes since the 17.0 branch point. Only
   commit metadata is kept, and the subject has to look like a crash fix.
2. `resolve`  -- one API call per surviving commit for *added* test files. This
   is what keeps the corpus honest: a test that the fix commit added, not a path
   mentioned in passing by a WPT resync.
3. `fetch`    -- download each test once, capped in size.

Everything lands in results/webkit/corpus/ with index.json recording path, the
commit that added it, subject and size. The files are third-party test content
kept for local replay; nothing here is committed.

Usage
-----
    python tools/webkit_crash_corpus.py harvest [--pages N]
    python tools/webkit_crash_corpus.py resolve [--limit N]
    python tools/webkit_crash_corpus.py fetch [--limit N]
    python tools/webkit_crash_corpus.py list

The `jsc` stage replays `JSTests` instead of `LayoutTests`. Those cases are
written for a bare JS engine, so each one is rendered into a self-contained page
with a small `jsc`-shell shim and run by `p172-jsc-corpus-runner.js`:

    python tools/webkit_crash_corpus.py jsc-harvest [--pages N]
    python tools/webkit_crash_corpus.py jsc-resolve [--limit N]
    python tools/webkit_crash_corpus.py jsc-fetch [--limit N]
    python tools/webkit_crash_corpus.py jsc-build
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "results", "webkit", "corpus")
INDEX = os.path.join(CORPUS, "index.json")
JSC_INDEX = os.path.join(CORPUS, "jsc_index.json")
JSC_SRC = os.path.join(CORPUS, "jsc_src")

DEFAULT_QUERY = "crash repo:WebKit/WebKit committer-date:>2023-09-20"
MAX_BYTES = 160 * 1024

CRASH_WORDS = re.compile(
    r"crash|null deref|nullptr|use[- ]after[- ]free|uaf\b|overflow|out[- ]of[- ]bounds|"
    r"assertion|security|type confusion|bad access|heap[- ]buffer",
    re.IGNORECASE,
)
SKIP_WORDS = re.compile(r"resync|^import |unreviewed, reverting|migrat", re.IGNORECASE)
TEST_SUFFIX = (".html", ".xhtml", ".svg")

# Features measured absent on the console (probes p162/p163), so a repro that needs
# one cannot reach the bug it guards: the test loads, throws, and reports OK. Keeping
# those in the corpus costs console time and returns a false negative.
UNAVAILABLE = re.compile(
    r"webgpu|webgl|webassembly|\bwasm\b|sharedarraybuffer|serviceworker|service-worker|"
    r"offscreencanvas|webaudio|indexeddb|webrtc|webcodecs|geolocation|"
    r"webxr|inspector/|^LayoutTests/media/|^LayoutTests/http/wpt/|"
    r"bluetooth|gamepad|notification|\busb\b",
    re.IGNORECASE,
)


def unavailable_reason(path):
    hit = UNAVAILABLE.search(path)
    return hit.group(0) if hit else None


def _gh(args):
    out = subprocess.run(["gh"] + args, capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise SystemExit("gh failed: " + out.stderr.strip()[:400])
    return out.stdout


def _load():
    if os.path.exists(INDEX):
        with open(INDEX, encoding="utf-8") as fh:
            return json.load(fh)
    return {"commits": {}, "tests": {}}


def _save(index):
    os.makedirs(CORPUS, exist_ok=True)
    with open(INDEX, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)


def harvest(query: str, pages: int) -> int:
    index = _load()
    seen = new = 0
    for page in range(1, pages + 1):
        raw = _gh([
            "api", "-X", "GET", "search/commits",
            "-f", "q=" + query,
            "-f", "sort=committer-date",
            "-f", "order=desc",
            "-f", "per_page=100",
            "-f", "page=%d" % page,
        ])
        items = json.loads(raw).get("items", [])
        if not items:
            break
        for item in items:
            seen += 1
            sha = item["sha"]
            msg = item["commit"]["message"]
            subject = msg.split("\n")[0]
            if sha in index["commits"]:
                continue
            if SKIP_WORDS.search(subject) or not CRASH_WORDS.search(subject):
                continue
            index["commits"][sha] = {
                "subject": subject[:180],
                "date": item["commit"]["committer"]["date"],
                "resolved": False,
            }
            new += 1
    _save(index)
    print("scanned %d commits, %d kept as crash fixes (%d new), %d total"
          % (seen, sum(1 for c in index["commits"].values() if not c.get("resolved")), new,
             len(index["commits"])))
    return 0


def resolve(limit: int) -> int:
    index = _load()
    done = 0
    for sha, meta in sorted(index["commits"].items(), key=lambda kv: kv[1]["date"], reverse=True):
        if done >= limit:
            break
        if meta.get("resolved"):
            continue
        raw = _gh(["api", "repos/WebKit/WebKit/commits/%s" % sha,
                   "--jq", '.files[] | select(.status=="added") | [.filename, .additions] | @tsv'])
        added = 0
        for line in raw.splitlines():
            path, _, _adds = line.partition("\t")
            if not path.startswith("LayoutTests/"):
                continue
            if not path.endswith(TEST_SUFFIX):
                continue
            if path.startswith("LayoutTests/imported/w3c"):
                continue
            if path in index["tests"] or path in index.get("skipped", {}):
                continue
            reason = unavailable_reason(path)
            if reason:
                index.setdefault("skipped", {})[path] = {
                    "path": path, "sha": sha, "date": meta["date"],
                    "subject": meta["subject"], "reason": reason}
                continue
            index["tests"][path] = {"path": path, "sha": sha,
                                    "date": meta["date"], "subject": meta["subject"]}
            added += 1
        meta["resolved"] = True
        meta["added"] = added
        done += 1
    _save(index)
    ready = sum(1 for t in index["tests"].values() if t.get("file"))
    print("resolved %d commits this run; %d tests known, %d downloaded"
          % (done, len(index["tests"]), ready))
    return 0


def fetch(limit: int) -> int:
    index = _load()
    got = 0
    for path in sorted(index["tests"]):
        entry = index["tests"][path]
        if entry.get("file"):
            continue
        if got >= limit:
            break
        url = "https://raw.githubusercontent.com/WebKit/WebKit/%s/%s" % (entry["sha"], path)
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                body = resp.read(MAX_BYTES + 1)
        except Exception as exc:  # noqa: BLE001 - a missing file is data, not a failure
            entry["error"] = str(exc)[:120]
            continue
        if len(body) > MAX_BYTES:
            entry["error"] = "too large"
            continue
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", path)[-110:]
        with open(os.path.join(CORPUS, name), "wb") as fh:
            fh.write(body)
        entry["file"] = name
        entry["size"] = len(body)
        entry.pop("error", None)
        got += 1
    _save(index)
    ready = sum(1 for t in index["tests"].values() if t.get("file"))
    print("fetched %d this run; %d ready in %s" % (got, ready, CORPUS))
    return 0


def prune() -> int:
    """Drop tests whose feature the console does not expose, and delete their bytes."""
    index = _load()
    skipped = index.setdefault("skipped", {})
    moved = 0
    for path in list(index["tests"]):
        reason = unavailable_reason(path)
        if not reason:
            continue
        entry = dict(index["tests"].pop(path))
        name = entry.pop("file", None)
        entry["reason"] = reason
        skipped[path] = entry
        if name:
            target = os.path.join(CORPUS, name)
            if os.path.isfile(target):
                os.remove(target)
        moved += 1
    _save(index)
    ready = sum(1 for t in index["tests"].values() if t.get("file"))
    print("pruned %d tests; %d kept, %d downloaded, %d skipped"
          % (moved, len(index["tests"]), ready, len(skipped)))
    return 0


# ---------------------------------------------------------------- JSC corpus
#
# JSTests cases are .js files for the `jsc` shell: they rely on the shell's own
# harness (shouldBe and friends, testLoopCount, noInline) and some on $vm, which
# is the shell's private inspector. The shim below covers the harness name by
# name; a case that needs $vm is dropped, because the console has no equivalent.
JSC_SHIM = r"""<script>
var __ok = 0, __fail = 0, __failNames = [];
function __is(a, b) { return (a === b) || (a !== a && b !== b); }
function __eq(a, b) {
  if (__is(a, b)) return true;
  if (typeof a === 'bigint' && typeof b === 'bigint') return a === b;
  try { return JSON.stringify(a) === JSON.stringify(b); } catch (e) { return false; }
}
function shouldBe(a, b, msg) { if (__eq(a, b)) { __ok++; } else { __fail++; if (__failNames.length < 5) __failNames.push(String(msg || '') + ' got=' + String(a) + ' want=' + String(b)); } }
function shouldNotBe(a, b, msg) { if (!__eq(a, b)) { __ok++; } else { __fail++; } }
function shouldBeTrue(a, msg) { shouldBe(a, true, msg); }
function shouldBeFalse(a, msg) { shouldBe(a, false, msg); }
function shouldBeUndefined(a, msg) { shouldBe(a, undefined, msg); }
function shouldBeNull(a, msg) { shouldBe(a, null, msg); }
function shouldBeEqualToString(a, b, msg) { shouldBe(a, b, msg); }
function shouldBeGreaterThan(a, b) { if (a > b) { __ok++; } else { __fail++; } }
function shouldBeGreaterThanOrEqual(a, b) { if (a >= b) { __ok++; } else { __fail++; } }
function shouldBeLessThan(a, b) { if (a < b) { __ok++; } else { __fail++; } }
function shouldBeLessThanOrEqual(a, b) { if (a <= b) { __ok++; } else { __fail++; } }
function shouldThrow(fn) { try { fn(); __fail++; } catch (e) { __ok++; } }
function shouldNotThrow(fn) { try { fn(); __ok++; } catch (e) { __fail++; } }
function shouldThrowError(fn) { shouldThrow(fn); }
function shouldNotThrowError(fn) { shouldNotThrow(fn); }
function testPassed() { __ok++; }
function testFailed(m) { __fail++; if (__failNames.length < 5) __failNames.push(String(m)); }
function describe() {}
function debug() {}
function print() {}
function noInline(f) { return f; }
var noDFG = noInline, noFTL = noInline, noOSRExitFuzz = noInline, noTailCalls = noInline;
var noEagerCompilation = noInline, noExceptions = noInline, noStructureCheck = noInline;
function evaluate(s) { try { return (0, eval)(s); } catch (e) { return undefined; } }
function markAndSweep() {}
function gc() { if (window.GCController) GCController.collectAll(); }
function drainMicrotasks() {}
function createGlobalObject() { return {}; }
function quit(status) { throw new Error('QUIT:' + status); }
window.onerror = function () { return true; };
var testLoopCount = 200;
</script>
"""

JSC_DIRECTIVE = re.compile(r"^\s*//@")
JSC_LOAD = re.compile(r"^\s*load\(")
JSC_VM = re.compile(r"\$(vm|262|host|debug|gc)\b")
# `quit()` and `transferArrayBuffer()` are the shell's own process control and
# detach primitive. A case that calls either to stop relies on behaviour the
# browser does not have: the throw is swallowed by the case's own catch and the
# recursion or loop that `quit` was meant to end keeps running. Measured on the
# console: the one such case in the corpus (index 201) never returned.
JSC_SHELL_ONLY = re.compile(r"\b(quit|transferArrayBuffer)\s*\(")
# `//@ skip if $memoryLimited` is the test suite's own statement that the case
# allocates more than a constrained runner allows. The browser is that
# constrained runner: the console answered "there is not enough free system
# memory" on the first such case it reached (index 288 of 513), which builds a
# 24 MCharacter program and evals it. The flag is written two ways in the tree
# ("skip if $memoryLimited" and "skip if $buildType == \"debug\" or
# $memoryLimited"), and a case that matches neither builds 179 MB of source and
# hangs the page on the console and in local Chromium alike (index 495 there).
JSC_MEMORY_LIMITED = re.compile(r"//@\s*skip\s+if\b[^\n]*\$memoryLimited\b")
# `//@ slow!` cases are the ones the suite expects to take minutes. They are kept
# - a slow case can still crash - but the page listing marks them so the runner
# gives that case a longer stall budget instead of tearing it down at four
# seconds.
# `//@ memoryHog!` is the suite's marker for a case that allocates far more than
# a normal run. The console answered "there is not enough free system memory" on
# the first one it reached (index 74 of 1932), which sets
# `arguments.length = 0x10000001` and asks Array.from for 268 million elements.
# Thirteen of the rebuilt corpus pages carry the marker, so they are dropped
# rather than costing a relaunch each.
JSC_MEMORY_HOG = re.compile(r"//@\s*memoryHog!")
JSC_SLOW = re.compile(r"//@\s*slow!")


def _load_jsc():
    if os.path.exists(JSC_INDEX):
        with open(JSC_INDEX, encoding="utf-8") as fh:
            return json.load(fh)
    return {"commits": {}, "tests": {}, "skipped": {}}


def _save_jsc(index):
    os.makedirs(CORPUS, exist_ok=True)
    with open(JSC_INDEX, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)


def jsc_harvest(pages: int) -> int:
    """List commits that touched JSTests/stress and JSTests/regress after 17.0."""
    index = _load_jsc()
    new = 0
    for sub in ("stress", "regress"):
        for page in range(1, pages + 1):
            raw = _gh(["api", "-X", "GET", "repos/WebKit/WebKit/commits",
                       "-f", "path=JSTests/%s" % sub,
                       "-f", "since=2023-09-20T00:00:00Z",
                       "-f", "per_page=100", "-f", "page=%d" % page])
            items = json.loads(raw)
            if not items:
                break
            for item in items:
                sha = item["sha"]
                if sha in index["commits"]:
                    continue
                index["commits"][sha] = {
                    "subject": item["commit"]["message"].split("\n")[0][:180],
                    "date": item["commit"]["committer"]["date"],
                    "resolved": False,
                }
                new += 1
    _save_jsc(index)
    print("harvested %d commits touching JSTests (%d tracked, %d unresolved)"
          % (new, len(index["commits"]),
             sum(1 for c in index["commits"].values() if not c.get("resolved"))))
    return 0


def jsc_resolve(limit: int) -> int:
    """Turn harvested crash-fix commits into JSTests test files."""
    index = _load_jsc()
    if not index["commits"]:
        # The layout harvest already searched the same commits; reuse its set.
        for sha, meta in _load()["commits"].items():
            index["commits"][sha] = {"subject": meta["subject"], "date": meta["date"],
                                     "resolved": False}
    done = 0
    for sha, meta in sorted(index["commits"].items(), key=lambda kv: kv[1]["date"], reverse=True):
        if done >= limit:
            break
        if meta.get("resolved"):
            continue
        raw = _gh(["api", "repos/WebKit/WebKit/commits/%s" % sha,
                   "--jq", '.files[] | select(.status=="added") | .filename'])
        added = 0
        for path in raw.splitlines():
            path = path.strip()
            if not path.startswith("JSTests/") or not path.endswith(".js"):
                continue
            if "/stress/" not in path and "/regress/" not in path:
                continue
            if path in index["tests"] or path in index["skipped"]:
                continue
            reason = unavailable_reason(path)
            if reason:
                index["skipped"][path] = {"path": path, "sha": sha,
                                          "date": meta["date"],
                                          "subject": meta["subject"], "reason": reason}
                continue
            index["tests"][path] = {"path": path, "sha": sha, "date": meta["date"],
                                    "subject": meta["subject"]}
            added += 1
        meta["resolved"] = True
        meta["added"] = added
        done += 1
    _save_jsc(index)
    print("resolved %d commits; %d JSTests known, %d downloaded, %d skipped"
          % (done, len(index["tests"]),
             sum(1 for t in index["tests"].values() if t.get("file")),
             len(index["skipped"])))
    return 0


def jsc_fetch(limit: int) -> int:
    """Download the test sources once, capped in size."""
    index = _load_jsc()
    os.makedirs(JSC_SRC, exist_ok=True)
    got = 0
    for path in sorted(index["tests"]):
        entry = index["tests"][path]
        if entry.get("file"):
            continue
        if got >= limit:
            break
        url = "https://raw.githubusercontent.com/WebKit/WebKit/%s/%s" % (entry["sha"], path)
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                body = resp.read(MAX_BYTES + 1)
        except Exception as exc:  # noqa: BLE001 - a missing file is data, not a failure
            entry["error"] = str(exc)[:120]
            continue
        if len(body) > MAX_BYTES:
            entry["error"] = "too large"
            continue
        name = path.rsplit("/", 1)[-1]
        if os.path.exists(os.path.join(JSC_SRC, name)):
            name = name[:-3] + "-" + entry["sha"][:8] + ".js"
        with open(os.path.join(JSC_SRC, name), "wb") as fh:
            fh.write(body)
        entry["file"] = name
        entry["size"] = len(body)
        entry.pop("error", None)
        got += 1
    _save_jsc(index)
    print("fetched %d this run; %d ready in %s"
          % (got, sum(1 for t in index["tests"].values() if t.get("file")), JSC_SRC))
    return 0


def _jsc_body(source: str) -> str:
    kept = [ln for ln in source.splitlines()
            if not JSC_DIRECTIVE.match(ln) and not JSC_LOAD.match(ln)]
    return "\n".join(kept)


# Each case page is its own document and hands control back to the runner when it
# is done. The console browser cannot hold one document with every case in an
# iframe: it answered "there is not enough free system memory" after 288 realms,
# and after that refusal a fresh document died on its eighth case, because the
# process keeps what its realms allocated. A page per case means the document
# that allocated the memory is destroyed when the case ends.
JSC_BOOT = """<script>
(function () {
  var m = /[?&]i=(\\d+)/.exec(location.search);
  if (!m) return;
  var i = +m[1];
  var s = null, n = 0;
  try {
    s = sessionStorage.getItem('v172s');
    n = +(sessionStorage.getItem('v172n') || 0);
  } catch (e) {}
  if (!s) {
    s = Math.random().toString(36).slice(2, 8);
    try { sessionStorage.setItem('v172s', s); } catch (e) {}
  }
  window.__v172 = {
    i: i,
    mark: function (tag) {
      n = n + 1;
      try { sessionStorage.setItem('v172n', n); } catch (e) {}
      var url = location.origin + '/beacon/V172-' + s + '-' + tag + '?t=' + Date.now() + '&n=' + n;
      try { if (navigator.sendBeacon && navigator.sendBeacon(url)) return; } catch (e) {}
      try { var x = new XMLHttpRequest(); x.open('GET', url, true); x.send(); } catch (e) {}
    }
  };
  window.__v172.mark('BEFORE-' + i);
})();
</script>"""

# The case page reports and then asks the runner for the next case. `next` comes
# from the runner, so the page itself holds no index beyond its own.
JSC_HANDOFF = """<script>
(function () {
  var v = window.__v172;
  if (!v) return;
  v.mark('OK-' + v.i + '-%(file)s');
  v.mark('GAP-' + v.i);
  var m = /[?&]next=(\\d+)/.exec(location.search);
  var next = m ? +m[1] : 0;
  var c = /[?&]c=(\\d+)/.exec(location.search);
  var sv = /[?&]v=([A-Za-z0-9]+)/.exec(location.search);
  var g = /[?&]g=(\\d+)/.exec(location.search);
  var e = /[?&]e=(\\d+)/.exec(location.search);
  // The batch ends where the runner said it ends; without that the handoff
  // would keep the chain alive for ever and `count` would bound nothing.
  if (e && next >= +e[1]) { v.mark('BATCH-END-' + v.i); return; }
  setTimeout(function () {
    location.replace('/probe/p172-jsc-corpus-runner.js?start=' + next +
                     '&count=' + (c ? c[1] : 40) + '&v=' + (sv ? sv[1] : '') +
                     '&g=' + (g ? g[1] : 0));
  }, 60);
})();
</script>"""


def jsc_build() -> int:
    """Render every fetched test into a page the console can load."""
    index = _load_jsc()
    ready = [t for t in index["tests"].values() if t.get("file")]
    ready.sort(key=lambda t: t["path"])
    for stale in os.listdir(CORPUS):
        if re.match(r"jsc-\d{3}-.*\.html$", stale):
            os.remove(os.path.join(CORPUS, stale))
    bodies = []
    dropped = 0
    for entry in ready:
        with open(os.path.join(JSC_SRC, entry["file"]), encoding="utf-8",
                  errors="replace") as fh:
            source = fh.read()
        if JSC_VM.search(source) or JSC_SHELL_ONLY.search(source):
            dropped += 1
            continue
        if JSC_MEMORY_LIMITED.search(source) or JSC_MEMORY_HOG.search(source):
            dropped += 1
            continue
        bodies.append((entry, source, bool(JSC_SLOW.search(source))))
    listing_out = []
    for n, (entry, source, slow) in enumerate(bodies, 1):
        subject = entry["path"].rsplit("/", 1)[-1]
        slug = re.sub(r"[^a-z0-9]+", "-", subject[:-3].lower()).strip("-")[:60]
        name = "jsc-%03d-%s.html" % (n, slug)
        head = ('<!doctype html><meta charset="utf-8"><title>%s</title>\n%s\n%s'
                '<pre id="err"></pre><script>try{\n' % (subject, JSC_BOOT, JSC_SHIM))
        tail = ('\n}catch(e){var d=document.getElementById(\'err\');'
                ' if(d) d.textContent=\'THROW: \'+e;}\n</script>'
                '<p>ok <script>document.write(__ok)</script> fail '
                '<script>document.write(__fail)</script></p>'
                + (JSC_HANDOFF % {"file": name}))
        with open(os.path.join(CORPUS, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(head + _jsc_body(source) + tail)
        item = {"path": "jsc", "file": name, "subject": subject}
        if slow:
            item["slow"] = True
        listing_out.append(item)
    with open(os.path.join(CORPUS, "jsc.json"), "w", encoding="utf-8") as fh:
        json.dump(listing_out, fh, indent=1)
    print("built %d pages (%d dropped as shell-only or memory-limited) into %s"
          % (len(listing_out), dropped, CORPUS))
    return 0


def listing() -> int:
    index = _load()
    ready = [t for t in index["tests"].values() if t.get("file")]
    print("%d tests known, %d downloaded, %d commits tracked"
          % (len(index["tests"]), len(ready), len(index["commits"])))
    for t in sorted(ready, key=lambda x: x["date"], reverse=True)[:20]:
        print("  %-62s %6d  %s" % (t["path"][-62:], t.get("size", 0), t["subject"][:52]))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description="Harvest WebKit crash regression tests")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("harvest")
    h.add_argument("--pages", type=int, default=5)
    h.add_argument("--query", default=DEFAULT_QUERY)
    r = sub.add_parser("resolve")
    r.add_argument("--limit", type=int, default=200)
    f = sub.add_parser("fetch")
    f.add_argument("--limit", type=int, default=200)
    sub.add_parser("prune")
    sub.add_parser("list")
    jh = sub.add_parser("jsc-harvest")
    jh.add_argument("--pages", type=int, default=5)
    jr = sub.add_parser("jsc-resolve")
    jr.add_argument("--limit", type=int, default=200)
    jf = sub.add_parser("jsc-fetch")
    jf.add_argument("--limit", type=int, default=200)
    sub.add_parser("jsc-build")
    args = ap.parse_args(argv)

    if args.cmd == "harvest":
        return harvest(args.query, args.pages)
    if args.cmd == "resolve":
        return resolve(args.limit)
    if args.cmd == "fetch":
        return fetch(args.limit)
    if args.cmd == "prune":
        return prune()
    if args.cmd == "jsc-harvest":
        return jsc_harvest(args.pages)
    if args.cmd == "jsc-resolve":
        return jsc_resolve(args.limit)
    if args.cmd == "jsc-fetch":
        return jsc_fetch(args.limit)
    if args.cmd == "jsc-build":
        return jsc_build()
    return listing()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
