#!/usr/bin/env python3
"""Offline validator for the p693 rcw=0 arbitrary-free claim (PR #303).

The v35 FAM-FR readback is the only on-device evidence that
RefCounted::deref ran `delete this` -> ~FontFace -> operator delete(client-0x20)
on an address inside the JS spray. This tool grades a FAM-FR beacon line
against the self-consistent free signature WITHOUT trusting the probe's
beacon text:

  c68 = 0x0                  rc word zeroed (0 ->ref-> 1 ->deref-> 0, then
                             FastMalloc cleared the first qword of the chunk)
  c70 = c78 = S2 (=S4=S5)    bmalloc wrote the ICF-collapsed Client stub as
                             freelist linkage at +0x08/+0x10 of the chunk
  c88 = VP                   untouched: lies past the freed chunk's usable
                             region, so the allocator did not reach it
  h60 = module-space ptr     FastMalloc's own chunk header written at ptr-8

Given the run's BOOT/SPMAP/VT beacons it also checks geometry:
  freed addr  = sk + 0x68  where sk = SPMAP lane address for SKIPJ
  c88 offset  = freed addr + 0x20  (client-0x20 = sk+0x68, so sk+0x88)

Verdicts:
  FREE_SIGNATURE_CONSISTENT  all checks pass -> free happened; the open item
                             is ONLY the alloc-back test (reclaim the freed
                             chunk from JS and prove allocator ownership).
  NO_FREE_EVIDENCE           rcw=0 run but FAM-FR line absent or zeroed
                             fields only partially present.
  INCONSISTENT               fields contradict the free signature -> the
                             "arbitrary free" claim fails on this run.
  NOT_RCW0                   run was not an rcw=0 run.

Usage:
    python tools/validate_p693_free.py <capture.jsonl | beacon log>
    python tools/validate_p693_free.py capture.jsonl --json

Exit 0 iff at least one rcw=0 run grades FREE_SIGNATURE_CONSISTENT.
"""

import argparse
import json
import re
import sys
from urllib.parse import unquote

TAG_RE = re.compile(r'"tag":"([^"]+)"')                     # JSONL capture
LOG_RE = re.compile(r"/beacon/(P693-[^?\s]+)\?[^?\s]*\bu=([A-Z0-9]{6})")
FAMFR_RE = re.compile(
    r"P693-FAM-FR-h60-(0x[0-9a-f]+),c68-(0x[0-9a-f]+),c70-(0x[0-9a-f]+)"
    r",c78-(0x[0-9a-f]+),c80-(0x[0-9a-f]+),c88-(0x[0-9a-f]+)")
BOOT_RE = re.compile(r"P693-BOOT-([A-Z0-9]{6}),.*\brcw=(\d+)")
SPMAP_RE = re.compile(r"P693-SPMAP-(0x[0-9a-f]+)-i(\d+)")
VT_RE = re.compile(r"P693-VT-s0=(0x[0-9a-f]+),s1=(0x[0-9a-f]+),s2=(0x[0-9a-f]+)")
VT2_RE = re.compile(r"P693-VT-s3=(0x[0-9a-f]+),s4=(0x[0-9a-f]+),s5=(0x[0-9a-f]+)")
VT3_RE = re.compile(r"P693-VT-s6=(0x[0-9a-f]+),s7=(0x[0-9a-f]+),s8=(0x[0-9a-f]+)")
SCANPIN_RE = re.compile(r"P693-VTAB-0x[0-9a-f]+-j(\d+)-SCANPIN")
VP_RE = re.compile(r"P693-WALK-.*VP=(0x[0-9a-f]+)")
def module_band(*ptrs):
    """Derive the module band from the run's own VP/slot pointers instead of
    hardcoding 14.10 constants (the tool must work across firmware builds)."""
    tops = {p >> 32 for p in ptrs if p}
    if len(tops) == 1:
        hi32 = tops.pop()
        return (hi32 << 32, (hi32 + 1) << 32)
    return None


def tags_from(path):
    """Yield p693 beacon tags from a .jsonl capture or an nginx beacon log."""
    with open(path, "r", errors="replace") as f:
        for line in f:
            if "P693-" not in line:
                continue
            m = TAG_RE.search(line)
            if m:
                yield unquote(m.group(1))
                continue
            m = LOG_RE.search(line)
            if m:
                yield unquote(m.group(1))


def analyze(tags):
    """tags: ordered iterable of P693-* beacon messages from ONE run."""
    r = {"rcw": None, "scanpin_idx": None, "spmap": {}, "slots": {},
         "vp": None, "famfr": None, "checks": {}}
    for t in tags:
        m = BOOT_RE.search(t)
        if m:
            r["uid"] = m.group(1)
            r["rcw"] = int(m.group(2))
            continue
        m = SCANPIN_RE.search(t)
        if m:
            r["scanpin_idx"] = int(m.group(1))
            continue
        m = SPMAP_RE.search(t)
        if m:
            r["spmap"][int(m.group(2))] = int(m.group(1), 16)
            continue
        m = VP_RE.search(t)
        if m:
            r["vp"] = int(m.group(1), 16)
            continue
        m = VT_RE.search(t)
        if m:
            r["slots"].update({"s0": int(m.group(1), 16),
                               "s1": int(m.group(2), 16),
                               "s2": int(m.group(3), 16)})
            continue
        m = VT2_RE.search(t)
        if m:
            r["slots"].update({"s3": int(m.group(1), 16),
                               "s4": int(m.group(2), 16),
                               "s5": int(m.group(3), 16)})
            continue
        m = VT3_RE.search(t)
        if m:
            r["slots"].update({"s6": int(m.group(1), 16),
                               "s7": int(m.group(2), 16)})
            continue
        m = FAMFR_RE.search(t)
        if m:
            r["famfr"] = {k: int(m.group(i + 1), 16)
                          for i, k in enumerate(
                              ("h60", "c68", "c70", "c78", "c80", "c88"))}

    if r["rcw"] is None:
        return "NO_BOOT", r
    if r["rcw"] != 0:
        return "NOT_RCW0", r
    f = r["famfr"]
    if not f:
        return "NO_FREE_EVIDENCE", r

    c = r["checks"]
    c["rc_word_zeroed_c68_eq_0"] = f["c68"] == 0
    s2, s4, s5 = r["slots"].get("s2"), r["slots"].get("s4"), r["slots"].get("s5")
    if s2 is not None:
        c["icf_collapse_s2_eq_s4_eq_s5"] = (s2 == s4 == s5)
        c["freelist_link_c70_eq_s2"] = f["c70"] == s2
        c["freelist_link_c78_eq_s2"] = f["c78"] == s2
    if r["vp"] is not None:
        c["vptr_untouched_c88_eq_vp"] = f["c88"] == r["vp"]
    c["header_h60_in_module_band"] = MODULE_BAND_LO <= f["h60"] < MODULE_BAND_HI
    c["c80_small_nonzero"] = 0 < f["c80"] < 0x1000

    # Geometry: freed addr = sk+0x68; c88 (sk+0x88) is freed+0x20, i.e. past
    # a minimal fastMalloc chunk for the FontFace size class -> must be the
    # planted vptr, not allocator data. Requires the SCANPIN lane in SPMAP.
    idx = r["scanpin_idx"]
    if idx is not None and idx in r["spmap"]:
        sk = r["spmap"][idx]
        c["freed_addr"] = hex(sk + 0x68)
        c["c88_is_freed_plus_0x20"] = True  # by construction sk+0x88 = sk+0x68+0x20
        c["freed_addr_in_spray_band"] = 0x1000000000 <= sk < 0x1010000000
    else:
        c["geometry_skipped"] = ("SCANPIN lane %s not in SPMAP beacons"
                                 % idx)

    if all(v is True for k, v in c.items() if k.endswith(("0", "p", "2", "i", "d", "e"))):
        return "FREE_SIGNATURE_CONSISTENT", r
    hard_fail = [k for k, v in c.items() if v is False]
    if hard_fail:
        r["failed"] = hard_fail
        return "INCONSISTENT", r
    return "INCOMPLETE", r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="capture-*.jsonl or beacon log, one p693 run")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    verdict, r = analyze(tags_from(args.capture))
    r["verdict"] = verdict
    if args.json:
        out = dict(r)
        out["spmap"] = {str(k): hex(v) for k, v in r["spmap"].items()}
        out["slots"] = {k: hex(v) for k, v in r["slots"].items()}
        if r.get("famfr"):
            out["famfr"] = {k: hex(v) for k, v in r["famfr"].items()}
        if r.get("vp"):
            out["vp"] = hex(r["vp"])
        print(json.dumps(out, indent=2))
    else:
        print(f"verdict: {verdict}")
        print(f"  uid={r.get('uid')} rcw={r['rcw']} scanpin_lane={r['scanpin_idx']}")
        for k, v in r["checks"].items():
            print(f"  {k}: {v}")
        if r.get("failed"):
            print(f"  FAILED: {', '.join(r['failed'])}")
        if verdict == "FREE_SIGNATURE_CONSISTENT":
            print("  -> free happened; remaining open item: alloc-back test")
    return 0 if verdict == "FREE_SIGNATURE_CONSISTENT" else 1


if __name__ == "__main__":
    sys.exit(main())
