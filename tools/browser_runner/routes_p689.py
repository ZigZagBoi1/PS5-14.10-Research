#!/usr/bin/env python3
"""Routes for p689/p690 (phase: decider + heap-oracle v2).

WIRE-IN (1 line): in serve.py, right after the STATIC dict is defined
(e.g. below the `MIME = {...}` line), add:

    from routes_p689 import P689_ROUTES; STATIC.update(P689_ROUTES)

(serve.py runs with tools/browser_runner as CWD/sys.path[0], so the bare
module name resolves. Nothing else in serve.py needs to change.)

NOTE: even WITHOUT wiring in, serve.py's fallback already serves any file
under probes/phase13_webkit/ by name (serve.py do_GET probe_file branch),
so these routes exist for SHORT aliases and for pinning the default '/'.
"""

import pathlib

PROJECT = pathlib.Path(__file__).resolve().parent.parent.parent

P689_ROUTES = {
    '/p689':  PROJECT / 'probes' / 'phase13_webkit' / 'p689-decider8294.html',
    '/p689b': PROJECT / 'probes' / 'phase13_webkit' / 'p689-decider8294.html',
    '/p690':  PROJECT / 'probes' / 'phase13_webkit' / 'p690-oralo2.html',
    '/p690b': PROJECT / 'probes' / 'phase13_webkit' / 'p690-oralo2.html',
    '/p692':  PROJECT / 'probes' / 'phase13_webkit' / 'p692-ranges20.html',
    '/p691':  PROJECT / 'probes' / 'phase13_webkit' / 'p691-walk-forge-fixed.html',
    '/p693':  PROJECT / 'probes' / 'phase13_webkit' / 'p693-coop-vp-dispatch.html',
    '/p809':  PROJECT / 'probes' / 'phase13_webkit' / 'p809-elf-got-reader.html',
}
