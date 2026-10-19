#!/usr/bin/env python3
"""Audit TIER 3 claims 16-22 in docs/VERIFIED_HANDLER_ANALYSIS.md.

Complements ``handler_claim_audit.py`` (TIER 1 claims 1-3) and
``tier2_claim_audit.py`` (TIER 2 claims 9-15). This tool covers the five TIER 3
claims whose evidence is a committed artifact rather than a code-reading
judgement:

  16  sysent table: au_event / flags across all 679 entries
  18  ucred.bin: the three Sony extension values and their offsets
  19  module structure map: the cited offsets as reads in a dynlib handler
  21  kernel_data.bin: the cited build-path and symbol strings
  22  sys 640: the disabled 8-argument stub and the code after it

Claims 17 (ACM vs priv_check) and 20 (auth-ID hierarchy) are code-reading
claims with no single artifact to pin; they are reported as UNRESOLVED here
rather than guessed at.

Offline and read-only. No console is contacted, and no 14.10 artifact exists in
this repository.

Usage:

  python tools/tier3_claim_audit.py           # verdict table
  python tools/tier3_claim_audit.py --check   # exit 1 on drift
"""

from __future__ import annotations

import collections
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"

SYSENT_RAW = DUMPS / "sysent_raw.bin"
UCRED = DUMPS / "ucred.bin"
KERNEL_TEXT = DUMPS / "kernel_text.bin"
KERNEL_DATA = DUMPS / "kernel_data.bin"
DATA_RVA = 0x1000000

SYSENT_ENTRY = 48
SONY_RANGE = range(532, 677)
NATIVE_RANGE = range(0, 532)

# struct sysent field offsets, by observation (see docs/TIER3_CLAIMS_AUDIT.md).
OFF_NARG = 0x00
OFF_AUEVENT = 0x10
OFF_SYCALL = 0x08
OFF_FLAGS = 0x2C

# Claim 18's three values.
UCRED_AUTHID = 0x4800000000000007
UCRED_CAPS0 = 0x40FF1CFFFFFFFFFF
UCRED_CAPS1 = 0xFFFFFFFFFFFFFFFF
UCRED_OFFSETS = {0x58: UCRED_AUTHID, 0x60: UCRED_CAPS0, 0x68: UCRED_CAPS1}

# Claim 19's module structure map.
MODULE_OFFSETS = [0x00, 0x28, 0x70, 0x78, 0x80, 0x88, 0x90,
                  0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x11D, 0x168]
DYLIB_HANDLER = 0x34BDC0   # sys 608 body; the one that copies the struct

# Claim 21's strings, as RVAs into kernel_data.bin.
DATA_STRINGS = {
    "build path": "W:/Build/J03950001/sys/freebsd/",
    "debug fn": "mp4_mDbg_test_context_read_write_process_memory_rw",
    "auth infra": "sceSblAuthMgr",
}

SYS_640 = 0xA90E10
SYS_640_STUB = bytes.fromhex("554889e531c05dc3")


def sysent_entries() -> list[bytes]:
    raw = SYSENT_RAW.read_bytes()
    return [raw[i * SYSENT_ENTRY:(i + 1) * SYSENT_ENTRY]
            for i in range(len(raw) // SYSENT_ENTRY)]


def dword(row: bytes, off: int) -> int:
    return int.from_bytes(row[off:off + 4], "little")


def qword(row: bytes, off: int) -> int:
    return int.from_bytes(row[off:off + 8], "little")


def claim16() -> dict:
    """All 115 real Sony syscalls: au_event=0, no DTrace, no Capsicum flags."""
    rows = sysent_entries()
    sony = [i for i in SONY_RANGE]
    native = [i for i in NATIVE_RANGE]

    sony_au = {i: dword(rows[i], OFF_AUEVENT) for i in sony}
    sony_nonzero = {i: v for i, v in sony_au.items() if v}
    native_nonzero = sum(1 for i in native if dword(rows[i], OFF_AUEVENT))

    sony_flags = collections.Counter(dword(rows[i], OFF_FLAGS) for i in sony)
    # 677 and 678 are malformed in the raw table (narg is a 32-bit truncation
    # of a pointer and +0x04 is 0xffffffff), so they are excluded from the
    # flag population and reported separately.
    flag_population = [i for i in range(len(rows)) if i not in (677, 678)]
    all_flags = collections.Counter(dword(rows[i], OFF_FLAGS) for i in flag_population)
    anomaly = {i: (dword(rows[i], OFF_NARG), dword(rows[i], 0x04)) for i in (677, 678)}

    # The one Sony exception must be a real body, not a nosys stub.
    text = KERNEL_TEXT.read_bytes()
    idx = {e["num"]: int(e["sy_call_off"], 16)
           for e in json.loads((DUMPS / "sysent_index.json").read_text())["entries"]}
    exception_bodies = {}
    for num in sony_nonzero:
        off = idx[num]
        rel = struct.unpack_from("<i", text, off + 1)[0]
        exception_bodies[num] = (off + 5 + rel) & 0xFFFFFFFFFFFFFFFF

    ok = (len(sony) == 145
          and list(sony_nonzero) == [658]
          and sony_nonzero[658] == 43069
          and native_nonzero > 0
          and set(all_flags) == {1, 4}
          and all(b != 0x265760 for b in exception_bodies.values()))
    return {
        "id": "16",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"{len(sony) - len(sony_nonzero)}/145 Sony entries have 0 at +0x10; "
            f"the exception is sys {list(sony_nonzero)} = "
            f"{list(sony_nonzero.values())}, whose body is "
            f"{[hex(b) for b in exception_bodies.values()]} (not the nosys "
            f"stub). Native entries: {native_nonzero}/532 nonzero at +0x10. "
            f"+0x2c takes only {sorted(all_flags)} across entries 0-676 "
            f"(Sony: {dict(sorted(sony_flags.items()))}); 677/678 are malformed "
            f"rows {anomaly}. The 'all 115' universal fails on the bytes; field "
            f"names are inferred, not named by the artifact."
        ),
        "ok": ok,
    }


def claim18() -> dict:
    """ucred Sony extensions at +0x58/+0x60/+0x68 with the cited values."""
    blob = UCRED.read_bytes()
    found = {off: qword(blob, off) for off in UCRED_OFFSETS}
    elsewhere = []
    for off in range(len(blob) - 7):
        if qword(blob, off) in UCRED_OFFSETS.values() and off not in UCRED_OFFSETS:
            elsewhere.append(off)
    ok = found == UCRED_OFFSETS and not elsewhere and len(blob) == 256
    return {
        "id": "18",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            f"ucred.bin ({len(blob)} B): "
            + ", ".join(f"+0x{o:02x} = 0x{v:016X}" for o, v in found.items())
            + f"; no other offset holds any of the three values "
            f"({len(elsewhere)} stray)."
        ),
        "ok": ok,
    }


def claim19() -> dict:
    """Module structure map: the cited offsets appear as reads in 608."""
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    text = KERNEL_TEXT.read_bytes()
    idx = {e["num"]: int(e["sy_call_off"], 16)
           for e in json.loads((DUMPS / "sysent_index.json").read_text())["entries"]}
    starts = set()
    for off in idx.values():
        if text[off] == 0xE9:
            rel = struct.unpack_from("<i", text, off + 1)[0]
            starts.add((off + 5 + rel) & 0xFFFFFFFFFFFFFFFF)
    ordered = sorted(starts)
    end = ordered[ordered.index(DYLIB_HANDLER) + 1]

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    reads: dict[int, list[int]] = {}
    for insn in cs.disasm(text[DYLIB_HANDLER:end], DYLIB_HANDLER):
        for m in re.finditer(r"\+ (0x[0-9a-f]+)\]", insn.op_str):
            reads.setdefault(int(m.group(1), 16), []).append(insn.address)

    missing = [off for off in MODULE_OFFSETS if off != 0x00 and off not in reads]
    ok = (not missing and end - DYLIB_HANDLER > 0
          and all(reads[o] for o in MODULE_OFFSETS if o != 0x00))
    return {
        "id": "19",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            f"{len(MODULE_OFFSETS) - 1}/{len(MODULE_OFFSETS)} offsets appear as "
            f"reads in the dynlib handler at {DYLIB_HANDLER:#x} "
            f"({end - DYLIB_HANDLER:#x} bytes); +0x00 (the next pointer) is a "
            f"bare dereference with no displacement, so this scan cannot see "
            f"it. Missing: {missing or 'none'}."
        ),
        "ok": ok,
    }


def claim21() -> dict:
    """The cited kernel data strings exist at the cited kind of location."""
    data = KERNEL_DATA.read_bytes()
    hits = {}
    for label, needle in DATA_STRINGS.items():
        raw = needle.encode()
        pos = data.find(raw)
        hits[label] = None if pos < 0 else DATA_RVA + pos
    dynlib_count = data.count(b"dynlib")
    ok = all(v is not None for v in hits.values()) and dynlib_count >= 50
    return {
        "id": "21",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            "; ".join(f"{k} @ {hex(v) if v else 'NOT FOUND'}"
                      for k, v in hits.items())
            + f"; 'dynlib' appears {dynlib_count}x in the data range. The '50+ "
              f"dynlib strings' count is met; the budget/mp4 string counts are "
              f"not individually pinned here."
        ),
        "ok": ok,
    }


def claim22() -> dict:
    """sys 640: disabled 8-arg stub returning 0, original code nearby."""
    text = KERNEL_TEXT.read_bytes()
    idx = {e["num"]: int(e["sy_call_off"], 16)
           for e in json.loads((DUMPS / "sysent_index.json").read_text())["entries"]}
    rel = struct.unpack_from("<i", text, idx[640] + 1)[0]
    body = (idx[640] + 5 + rel) & 0xFFFFFFFFFFFFFFFF
    head = text[body:body + 8]
    narg = struct.unpack_from("<i", SYSENT_RAW.read_bytes(), 640 * SYSENT_ENTRY)[0]
    # "Original code nearby": a separate function starts at body+0x10 and opens
    # with a one-shot initialisation guard (lock cmpxchg on a global).
    neighbour = text[body + 0x10:body + 0x10 + 0x18]
    guard = neighbour[:16]
    ok = (body == SYS_640 and head == SYS_640_STUB and narg == 8
          and neighbour[0] == 0x55
          and neighbour[6:11] == bytes.fromhex("b901000000")   # mov ecx,1
          and neighbour[13:16] == bytes.fromhex("f00fb1"))     # lock cmpxchg
    return {
        "id": "22",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            f"640 body {body:#x} = {head.hex()} (push rbp; mov rbp,rsp; xor "
            f"eax,eax; pop rbp; ret), 8 bytes, narg={narg}. A separate function "
            f"starts at {body + 0x10:#x} with a one-shot init guard "
            f"(`lock cmpxchg [global],1`), consistent with the claim's "
            f"'original code nearby'. The claim transcribes the second "
            f"instruction as 'mov rsp,rbp'; the bytes are `48 89 e5` = "
            f"`mov rbp,rsp`."
        ),
        "ok": ok,
    }


UNRESOLVED = [
    ("17", "Sony ACM credential system",
     "a code-reading claim about which handlers call ACM instead of "
     "priv_check; no single artifact names either function, so it is not "
     "pinned here"),
    ("20", "auth-ID hierarchy at proc+0x5d4/+0x5d8",
     "the two offsets are readable in several bodies, but the threshold "
     "semantics ('>= 0x3000000 extended DMEM', '>= 0x5000000 VM query') are "
     "behavioural, not byte-checkable"),
]


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    results = [claim16(), claim18(), claim19(), claim21(), claim22()]

    width = max(len(r["id"]) for r in results)
    print(f"{'claim':<{width}}  {'verdict':<10}  evidence")
    print(f"{'-' * width}  {'-' * 10}  {'-' * 40}")
    for r in results:
        print(f"{r['id']:<{width}}  {r['verdict']:<10}  {r['detail']}")
    for cid, subject, why in UNRESOLVED:
        print(f"{cid:<{width}}  {'UNRESOLVED':<10}  {subject}: {why}")

    drift = [r for r in results if not r["ok"]]
    print()
    if drift:
        print(f"DRIFT in {len(drift)} claim(s): {[r['id'] for r in drift]}")
        return 1 if check else 0
    print(f"{len(results)} claims match the committed artifacts; "
          f"{len(UNRESOLVED)} reported unresolved")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
