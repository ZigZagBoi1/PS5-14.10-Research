"""Generate mutated JavaScriptCore test pages for an on-device fuzzing pass.

The guide browser already replays pages from the corpus dir one document at a time
(probe p172). This turns that harness into a fuzzer: take real regression tests, apply
the structural mutations from tools/jsc_struct_mutate.py, and write the results as
ordinary corpus pages with their own manifest, so a crash shows up as a `BEFORE-n`
with no matching `OK-n` in the server log.

    python tools/jsc_fuzz_pages.py --count 2000 --seed 7

Everything here is offline. The console pass is the runner's job.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jsc_struct_mutate as mutate  # noqa: E402
import webkit_crash_corpus as corpus  # noqa: E402


MANIFEST = "fuzz.json"


def render(name: str, subject: str, source: str) -> str:
    head = (
        '<!doctype html><meta charset="utf-8"><title>%s</title>\n%s\n%s'
        '<pre id="err"></pre><script>try{\n' % (subject, corpus.JSC_BOOT, corpus.JSC_SHIM)
    )
    tail = (
        "\n}catch(e){var d=document.getElementById('err');"
        " if(d) d.textContent='THROW: '+e;}\n</script>"
        "<p>ok <script>document.write(__ok)</script> fail "
        "<script>document.write(__fail)</script></p>"
        + (corpus.JSC_HANDOFF % {"file": name})
    )
    page = head + corpus._jsc_body(source) + tail
    # The shared handoff navigates back to the runner without a list selector, so
    # a fuzz page would hand off into the regression corpus. Name the manifest on
    # every handoff too.
    return page.replace(
        "/probe/p172-jsc-corpus-runner.js?",
        "/probe/p172-jsc-corpus-runner.js?list=%s&" % MANIFEST,
        1,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--src", default=corpus.JSC_SRC)
    ap.add_argument("--out", default=corpus.CORPUS)
    ap.add_argument("--manifest", default="fuzz.json")
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    sources = sorted(f for f in os.listdir(args.src) if f.endswith(".js"))
    if not sources:
        print("no sources in " + args.src)
        return 1

    for stale in os.listdir(args.out):
        if re.match(r"fz-\d+-.*\.html$", stale):
            os.remove(os.path.join(args.out, stale))

    listing = []
    made = 0
    tries = 0
    while made < args.count and tries < args.count * 4:
        tries += 1
        fname = rng.choice(sources)
        with open(os.path.join(args.src, fname), encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        # the same drops the regression build applies, so a fuzz case is not an OOM
        if (
            corpus.JSC_VM.search(source)
            or corpus.JSC_SHELL_ONLY.search(source)
            or corpus.JSC_MEMORY_LIMITED.search(source)
            or corpus.JSC_MEMORY_HOG.search(source)
            or (corpus.JSC_WATCHDOG_LOOP.search(source) and corpus.JSC_UNBOUNDED_LOOP.search(source))
        ):
            continue
        if corpus._huge_allocation(source) is not None:
            continue
        rounds = rng.choice((1, 1, 2))
        for _ in range(rounds):
            # apply() returns (name, text) and None when no mutator fits
            got = mutate.apply(source, rng)
            if not got:
                break
            source = got[1]
        slug = re.sub(r"[^a-z0-9]+", "-", fname[:-3].lower()).strip("-")[:40]
        name = "fz-%04d-%s.html" % (made + 1, slug)
        with open(os.path.join(args.out, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(name, fname, source))
        listing.append({"path": "fz", "file": name, "subject": fname})
        made += 1

    with open(os.path.join(args.out, args.manifest), "w", encoding="utf-8") as fh:
        json.dump(listing, fh, indent=1)
    print("wrote %d fuzz pages into %s (manifest %s)" % (len(listing), args.out, args.manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
