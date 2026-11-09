#!/usr/bin/env python3
"""Print the state of a WebKit crash-corpus run.

The corpus server (tools/webkit_server.py, kept local) writes a run state
file next to the corpus it serves.  This reads that file and prints where the
run got to, which cases took the WebProcess down, and what the next guide
load will start from.

    python tools/webkit_corpus_status.py results/webkit/state.json
"""

import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}


def main(argv):
    if len(argv) > 1:
        path = Path(argv[1])
    else:
        path = Path(__file__).resolve().parent.parent / "results" / "webkit" / "state.json"
    state = load(path)
    if not state:
        print("no run state at %s (the guide has not been opened yet)" % path)
        return 0

    order = state.get("order", [])
    sessions = state.get("sessions", {})
    skipped = state.get("skipped", [])
    print("state file   : %s" % path)
    print("next case    : %s" % state.get("next", 0))
    print("skipped      : %s" % (", ".join(str(i) for i in skipped) if skipped else "none"))
    print("sessions     : %s" % (", ".join(order) if order else "none"))

    for session in order:
        sess = sessions.get(session, {})
        before = sess.get("before", {})
        done = sess.get("done", {})
        opened = sorted(int(k) for k in before)
        closed = sorted(int(k) for k in done)
        died = [c for c in opened if int(done.get(str(c), 0)) < int(before.get(str(c), 0))]
        print("  %s: opened %s, closed %s%s%s" % (
            session,
            opened[0] if opened else "-",
            closed[-1] if closed else "-",
            ", finished" if sess.get("finished") else "",
            ", died on %s" % died if died else "",
        ))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
