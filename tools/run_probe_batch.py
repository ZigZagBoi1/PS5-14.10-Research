#!/usr/bin/env python3
"""Run a bounded, sequential probe batch.

This wrapper is intentionally conservative: it sends each listed probe once,
stops on the first loader failure/timeout by default, and writes a batch
manifest that can be matched to the watchdog log. It does not relaunch the
game and does not infer that a reset was a kernel panic.

With ``--wait-for-loader`` a failure is a pause rather than the end of the run:
the batch announces that the game needs relaunching, polls the loader port until
it is back, retries that probe, and carries on with the rest of the list. The
console stays up across a killed loader, so the relaunch is the only manual step
and it happens whenever the operator sees the prompt.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from send_probe import (
    STRICT_FAILURES,
    send_lua,
    wait_for_loader,
)


def _iso_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main():
    parser = argparse.ArgumentParser(description="Run a bounded Lua probe batch")
    parser.add_argument("probes", nargs="+", help="Probe files, in execution order")
    parser.add_argument("--ip", default="10.0.0.96", help="PS5 IP (default: 10.0.0.96)")
    parser.add_argument("--port", type=int, default=9026, help="Lua loader port (default: 9026)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Idle read timeout per probe (default: 30)")
    parser.add_argument("--total-timeout", type=float, default=0.0,
                        help="Optional wall-clock limit per probe; 0 disables it")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Seconds to wait between successful probes")
    parser.add_argument("--save", action="store_true",
                        help="Save each response and JSON run record")
    parser.add_argument("--continue-on-failure", action="store_true",
                        help="Continue after reset/refusal/timeout (opt-in)")
    parser.add_argument("--wait-for-loader", type=float, default=0.0,
                        metavar="SECONDS",
                        help="on failure, poll up to SECONDS for the loader to "
                             "come back, retry that probe, then continue the batch")
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero if any probe did not complete cleanly")
    args = parser.parse_args()

    for probe in args.probes:
        if not os.path.isfile(probe):
            parser.error("probe file not found: %s" % probe)

    batch_started = time.monotonic()
    records = []
    print("[*] Batch start: %d probe(s), stop_on_failure=%s" %
          (len(args.probes), not args.continue_on_failure))
    for index, probe in enumerate(args.probes, 1):
        print("\n=== BATCH %d/%d: %s ===" % (index, len(args.probes), probe))
        started = time.monotonic()
        status = send_lua(args.ip, args.port, probe, args.save,
                          args.timeout, args.total_timeout,
                          write_metadata=args.save)
        retried = False
        if status in STRICT_FAILURES and args.wait_for_loader > 0:
            print("[*] %s - waiting for the loader (relaunch the game)." % status)
            if wait_for_loader(args.ip, args.port, timeout=args.wait_for_loader,
                               log=lambda msg: print(msg, flush=True)):
                started = time.monotonic()
                status = send_lua(args.ip, args.port, probe, args.save,
                                  args.timeout, args.total_timeout,
                                  write_metadata=args.save)
                retried = True

        record = {
            "index": index,
            "probe": os.path.abspath(probe),
            "status": status,
            "retried_after_relaunch": retried,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        records.append(record)

        if status in STRICT_FAILURES and not args.continue_on_failure:
            print("[*] Stopping batch after %s; relaunch/recheck the loader before retrying." % status)
            break
        if index < len(args.probes) and args.delay > 0:
            time.sleep(args.delay)

    manifest = {
        "started_at": _iso_timestamp(),
        "elapsed_seconds": round(time.monotonic() - batch_started, 3),
        "remote": "%s:%d" % (args.ip, args.port),
        "stop_on_failure": not args.continue_on_failure,
        "records": records,
    }
    if args.save:
        os.makedirs("results", exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join("results", "probe_batch_%s.json" % stamp)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")
        print("[*] Batch manifest: %s" % path)

    failed = [r for r in records if r["status"] in STRICT_FAILURES]
    print("[*] Batch complete: %d/%d probe(s), failures=%d" %
          (len(records), len(args.probes), len(failed)))
    if args.strict and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
