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
    args = ap.parse_args(argv)

    if args.cmd == "harvest":
        return harvest(args.query, args.pages)
    if args.cmd == "resolve":
        return resolve(args.limit)
    if args.cmd == "fetch":
        return fetch(args.limit)
    if args.cmd == "prune":
        return prune()
    return listing()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
