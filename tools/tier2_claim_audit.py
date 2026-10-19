#!/usr/bin/env python3
"""Audit the TIER 2 handler claims in docs/VERIFIED_HANDLER_ANALYSIS.md.

Claims 1-3 are covered by ``tools/handler_claim_audit.py``. This tool covers
claims 9-15 against the committed 13.60 artifacts:

  docs/dumps_13.60/sysent_index.json    syscall -> thunk RVA
  docs/dumps_13.60/kernel_text.bin      handler bodies (RVAs are offsets)

Offline and read-only. No console is contacted and no 14.10 artifact exists in
this repository, so every verdict below is about the 13.60 dump only.

Usage:

  python tools/tier2_claim_audit.py           # verdict table
  python tools/tier2_claim_audit.py --check   # exit 1 on drift

Verdict vocabulary:

  CONFIRMED   the claim's cited evidence exists and matches
  PARTIAL     the evidence exists but the claim overstates, miscounts, or
              attributes code to the wrong owner
  REFUTED     the cited evidence does not exist
  UNRESOLVED  this artifact cannot settle it

One caution that shapes several verdicts: the dump records no function extents.
A body "end" here is the next syscall body start, which is a safe upper bound
for "does this address belong to the cited handler" but not a claim about the
function's real size.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"

# Bodies resolved from sysent_index.json slots (see resolve()).
BODY_548 = 0xABBE60
BODY_565 = 0x6034E0
BODY_566 = 0x603710
BODY_598 = 0x34C990
BODY_612 = 0x34CE50
BODY_649 = 0x34CFA0
BODY_664 = 0x3B0FB0
BODY_665 = 0x3B1670
BODY_666 = 0x3B1680
BODY_670 = 0x3B28D0
BODY_675 = 0x2D36F0

NOSYS = 0x265760
SLOT_612 = 0x2655E0
SLOT_649 = 0x2655E8
SLOT_670 = 0x265748
UNMAPPED_SLOT_671_REGION = 0x265750

COPYIN = 0x259280
COPYOUT = 0x2591D0
COPYIN_MSG = 0xC1A3E0
ASSERT = 0xB22A30
STACK_CHK_FAIL = 0x6FD6B0

# Claim 14's PTE value mask, as the handler loads it.
PTE_MASK = 0xFFFFFFF0007B0000


def kernel() -> bytes:
    return (DUMPS / "kernel_text.bin").read_bytes()


def index() -> dict[int, int]:
    data = json.loads((DUMPS / "sysent_index.json").read_text(encoding="utf-8"))
    return {e["num"]: int(e["sy_call_off"], 16) for e in data["entries"]}


def jmp_target(blob: bytes, off: int) -> int | None:
    """Resolve the E9 rel32 at a sysent slot. Slot RVAs are already absolute."""
    if blob[off] != 0xE9:
        return None
    rel = struct.unpack_from("<i", blob, off + 1)[0]
    return (off + 5 + rel) & 0xFFFFFFFFFFFFFFFF


def resolve(blob: bytes, idx: dict[int, int], num: int) -> int | None:
    return jmp_target(blob, idx[num])


def disasm(start: int, end: int, blob: bytes):
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = False
    return list(cs.disasm(blob[start:end], start))


def calls(insns) -> list[tuple[int, int]]:
    """(site, target) for every direct call in a disassembly."""
    out = []
    for insn in insns:
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            out.append((insn.address, int(insn.op_str, 16)))
    return out


def rip_target(insn) -> int | None:
    """Absolute target of a rip-relative memory operand."""
    import re

    m = re.search(r"\[rip ([+-]) 0x([0-9a-f]+)\]", insn.op_str)
    if not m:
        return None
    disp = int(m.group(2), 16)
    if m.group(1) == "-":
        disp = -disp
    return (insn.address + insn.size + disp) & 0xFFFFFFFFFFFFFFFF


# --- claim checks ----------------------------------------------------------


def claim9(blob: bytes, idx: dict[int, int]) -> dict:
    """sys 612/649 get_obj_member: jump table over module fields."""
    b612 = resolve(blob, idx, 612)
    b649 = resolve(blob, idx, 649)
    body612 = disasm(BODY_612, BODY_649, blob)
    body649 = disasm(BODY_649, 0x34D120, blob)

    table_site = next((i for i in body649 if i.mnemonic == "jmp" and i.op_str == "rax"), None)
    # The relative table is the lea that feeds movsxd rax, [rcx + rax*4].
    movsxd = next((k for k, i in enumerate(body649)
                   if i.mnemonic == "movsxd" and "rax*4" in i.op_str), None)
    table_lea = None
    if movsxd is not None:
        for back in range(movsxd - 1, max(movsxd - 6, -1), -1):
            if body649[back].mnemonic == "lea" and body649[back].op_str.startswith("rcx,"):
                table_lea = body649[back]
                break
    index_bound = next((i for i in body649 if i.mnemonic == "cmp"
                        and i.op_str.startswith("eax, 7")), None)
    index_dec = next((i for i in body649 if i.mnemonic == "dec"
                      and i.op_str == "eax"), None)

    # Field offsets selected by the switch: each case loads the offset into
    # eax and reaches the shared ``mov rax, [r12 + rax]``. The relative table
    # itself is cited below but cannot be read: it lies outside this dump.
    fields = []
    for k, insn in enumerate(body649):
        if insn.mnemonic != "mov" or not insn.op_str.startswith("eax, 0x"):
            continue
        nxt = body649[k + 1] if k + 1 < len(body649) else None
        if nxt is None:
            continue
        reaches = (nxt.op_str.endswith("0x34d0c6") or nxt.address == 0x34D0C6)
        if reaches:
            fields.append(int(insn.op_str.split(", ")[1], 16))
    fields = sorted(fields)

    flags_tests = [i.address for i in body649
                   if i.mnemonic == "test" and "0x11d" in i.op_str and ", 0x10" in i.op_str]
    shared_load = [i.address for i in body649
                   if i.mnemonic == "mov" and i.op_str == "rax, qword ptr [r12 + rax]"]

    # 612 must not be the same function: no module-field switch at all.
    has_switch_612 = any(i.mnemonic == "jmp" and i.op_str == "rax" for i in body612)
    # 612 does require a copied qword equal to 0x10.
    cmp10 = [i.address for i in body612
             if i.mnemonic == "cmp" and i.op_str == "qword ptr [rbp - 0x38], 0x10"]

    ok = (
        b612 == BODY_612 and b649 == BODY_649
        and table_site is not None and index_bound is not None
        and index_dec is not None and table_lea is not None
        and shared_load and len(flags_tests) == 2
        and 0x78 in fields and 0xF8 in fields and 0x108 in fields
        and 0xE8 in fields and 0xF0 in fields
        and not has_switch_612 and bool(cmp10)
    )
    return {
        "id": "9",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"612 body {b612:#x} has no member switch (it requires a copied "
            f"qword == 0x10 at {cmp10[0]:#x}); 649 body {b649:#x} is the "
            f"8-entry switch: dec/ja {index_dec.address:#x}, table "
            f"{rip_target(table_lea):#x}, shared load {shared_load[0]:#x}, "
            f"fields {[hex(f) for f in fields]}, TLS flag tests at "
            f"{[hex(a) for a in flags_tests]}. Correct for 649, wrong for 612."
        ),
        "ok": ok,
    }


def claim10(blob: bytes) -> dict:
    """sys 675: 40-byte function, three global writes, zero calls, zero checks."""
    body = disasm(BODY_675, 0x2D3720, blob)
    stores = []
    for insn in body:
        if insn.mnemonic == "mov" and "rip" in insn.op_str and "ptr [" in insn.op_str:
            stores.append((insn.address, rip_target(insn), insn.op_str))
    call_sites = calls(body)
    branches = [i for i in body if i.mnemonic.startswith("j") or i.mnemonic == "call"]
    ret = next((i for i in body if i.mnemonic == "ret"), None)
    size = ret.address + ret.size - BODY_675 if ret else None
    ok = (
        size == 0x28
        and len(stores) == 3
        and not call_sites
        and len(branches) == 0
        and stores[0][2].endswith(", 1")
        and stores[1][2].endswith(", 0xffffffffffffffff")
        and stores[2][2].endswith(", 0")
    )
    return {
        "id": "10",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            f"body {BODY_675:#x} is {size} bytes ({size:#x}) ending at ret "
            f"{ret.address:#x}; three rip-relative stores, no call, no branch: "
            + "; ".join(f"{a:#x}->{t:#x} ({o.split(', ')[-1]})" for a, t, o in stores)
        ),
        "ok": ok,
    }


def claim11(blob: bytes) -> dict:
    """sys 598: two 8-byte values from dynlib_context+0xc8/+0xd0, no priv_check."""
    body = disasm(BODY_598, 0x34CAA0, blob)
    loads = [(i.address, i.op_str) for i in body
             if (i.mnemonic == "mov"
                 and (i.op_str == "rcx, qword ptr [rax + 0xc8]"
                      or i.op_str == "rax, qword ptr [rax + 0xd0]"))]
    copyouts = [(site, target) for site, target in calls(body) if target == COPYOUT]
    call_targets = sorted({t for _, t in calls(body)})
    ok = (
        [o for _, o in loads] == ["rcx, qword ptr [rax + 0xc8]",
                                  "rax, qword ptr [rax + 0xd0]"]
        and len(copyouts) == 2
        and call_targets == sorted({COPYIN_MSG, COPYOUT, ASSERT, STACK_CHK_FAIL})
        and any(i.mnemonic == "mov" and i.op_str == "edx, 8" for i in body)
    )
    return {
        "id": "11",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"body {BODY_598:#x}: loads [rax+0xc8] at {loads[0][0]:#x} and "
            f"[rax+0xd0] at {loads[1][0]:#x}; two {COPYOUT:#x} calls at "
            f"{[hex(s) for s, _ in copyouts]} of 8 bytes each. Complete call set "
            f"{[hex(t) for t in call_targets]}. No priv_check call is present, "
            f"but the artifact does not name priv_check's RVA, so that half is "
            f"an absence in a complete call list, not a named-check refutation."
        ),
        "ok": ok,
    }


def claim12(blob: bytes, idx: dict[int, int]) -> dict:
    """sys 670: a second handler at offset 0x480 doing cross-process events."""
    target = BODY_670 + 0x480
    prologue = blob[target:target + 4]
    slot_owners = {v: n for n, v in ((n, resolve(blob, idx, n)) for n in idx)}
    owner = slot_owners.get(target)
    # Direct edges to the function from anywhere in the text.
    edges = []
    for i in range(len(blob) - 5):
        if blob[i] in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            if (i + 5 + rel) & 0xFFFFFFFFFFFFFFFF == target:
                edges.append((i, "call" if blob[i] == 0xE8 else "jmp"))
    from_670 = [e for e in edges if BODY_670 <= e[0] < target]
    ok = (prologue == b"\x55\x48\x89\xe5" and owner is None
          and [e[0] for e in edges] == [UNMAPPED_SLOT_671_REGION]
          and not from_670)
    edge_text = (f"its only direct entry edge is the trampoline at {edges[0][0]:#x}"
                 if edges else "it has no direct entry edge")
    return {
        "id": "12",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"a function does start at 670+0x480 = {target:#x} "
            f"({prologue.hex()}); no sysent entry resolves to it; {edge_text}; "
            f"670's own body contains no call to it. 'Second handler of sys 670' "
            f"is not supported by this artifact."
        ),
        "ok": ok,
    }


def claim13(blob: bytes) -> dict:
    """sys 664/665/666: decl without lock at multiple offsets, zero lock prefixes."""
    out = {}
    for name, start, end in (("664", BODY_664, BODY_665),
                             ("665", BODY_665, BODY_666),
                             ("666", BODY_666, 0x3B2060)):
        insns = disasm(start, end, blob)
        out[name] = {
            "decl": [(i.address, i.op_str) for i in insns
                     if i.mnemonic == "dec" and "ptr [" in i.op_str],
            "lock": [i.address for i in insns if i.mnemonic.startswith("lock")],
            "size": end - start,
            "calls": calls(insns),
        }
    wrapper = blob[BODY_665:BODY_665 + 16]
    nosys_wrapper = (len(wrapper) == 16 and wrapper[7] == 0xE9
                     and jmp_target(blob, BODY_665 + 7) == NOSYS)
    ok = (nosys_wrapper
          and len(out["664"]["decl"]) == 0
          and len(out["666"]["decl"]) == 4
          and not out["664"]["lock"] and not out["665"]["lock"] and not out["666"]["lock"])
    return {
        "id": "13",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"dec-without-lock sites: 664 none, 665 none (16-byte wrapper that "
            f"tail-jumps to the nosys stub), 666 four at "
            f"{[hex(a) for a, _ in out['666']['decl']]}; zero lock-prefixed "
            f"instructions in all three. The claim's 'multiple offsets' hold "
            f"only for 666."
        ),
        "ok": ok,
    }


def claim14(blob: bytes) -> dict:
    """sys 565/566: indices 0-5, +0x160+i*8 vs +0x190+i*8, mask, ucred gate."""
    body565 = disasm(BODY_565, BODY_566, blob)
    body566 = disasm(BODY_566, 0x6039D0, blob)

    mask565 = [i for i in body565 if i.mnemonic == "movabs"
               and i.op_str == "rcx, 0xfffffff0007b0000"]
    bound565 = [i for i in body565 if i.mnemonic == "cmp" and i.op_str == "r12, 6"]
    setae565 = [i for i in body565 if i.mnemonic == "setae" and i.op_str == "al"]
    stores565 = [i for i in body565 if i.mnemonic == "mov" and "+ 0x160]" in i.op_str]

    bound566 = [i for i in body566 if i.mnemonic == "cmp" and i.op_str == "eax, -7"]
    stores566 = [i for i in body566 if i.mnemonic == "mov" and "+ 0x190]" in i.op_str]
    gate565 = [(s, t) for s, t in calls(body565) if t == 0x26D0A8]
    gate566 = [(s, t) for s, t in calls(body566) if t == 0x26D0A8]
    minus_one566 = [i.address for i in body566
                    if i.mnemonic == "cmp" and i.op_str == "r13d, -1"]

    def accepted_565(index: int) -> bool:
        # cmp r12, 6 ; setae al -> al=1 when index >= 6 -> reject
        return not (index >= 6)

    def accepted_566(index: int) -> bool:
        # lea eax, [r13 - 6] ; cmp eax, -7 ; jb reject
        # jb is unsigned: reject when (index-6) < 0xFFFFFFF9
        return not (((index - 6) & 0xFFFFFFFF) < 0xFFFFFFF9)

    bounds_ok = (all(accepted_565(i) for i in range(6))
                 and not accepted_565(6) and not accepted_565(0xFFFFFFFF)
                 and all(accepted_566(i) for i in range(6))
                 and not accepted_566(6) and not accepted_566(7))

    ok = (bool(mask565) and bool(bound565) and bool(setae565) and bool(stores565)
          and bool(bound566) and bool(stores566)
          and bool(gate565) and bool(gate566) and bounds_ok and bool(minus_one566))
    return {
        "id": "14",
        "verdict": "CONFIRMED" if ok else "DRIFT",
        "detail": (
            f"565 mask {mask565[0].address:#x}, bound {bound565[0].address:#x} "
            f"(index >= 6 rejected, simulated), {len(stores565)} indexed stores "
            f"at +0x160 with r12*8; 566 bound {bound566[0].address:#x} "
            f"(0-5 accepted, 6+ rejected, simulated; 0xffffffff admitted and "
            f"handled by the cmp at {minus_one566[0]:#x}), {len(stores566)} "
            f"stores at +0x190; both call 0x26d0a8 with [rdi+0x140] "
            f"({gate565[0][0]:#x}, {gate566[0][0]:#x})."
        ),
        "ok": ok,
    }


def claim15(blob: bytes) -> dict:
    """sys 548: per-entry 0x20-byte copyin inside the processing loop."""
    body = disasm(BODY_548, 0xABC510, blob)
    copyins = [(s, t) for s, t in calls(body) if t == COPYIN]
    # The loop: add r14,0x20 ; cmp r13,r15 ; je exit ; ... copyin edx=0x20
    step = [i.address for i in body if i.mnemonic == "add" and i.op_str == "r14, 0x20"]
    loop_cmp = [i.address for i in body
                if i.mnemonic == "cmp" and i.op_str == "r13, r15"]
    per_entry = []
    for site, _ in copyins:
        window = [i for i in body if abs(i.address - site) <= 0x20]
        if any(i.mnemonic == "mov" and i.op_str == "edx, 0x20" for i in window):
            per_entry.append(site)
    ok = bool(copyins) and bool(step) and bool(loop_cmp) and len(per_entry) == len(copyins)
    return {
        "id": "15",
        "verdict": "PARTIAL" if ok else "DRIFT",
        "detail": (
            f"body {BODY_548:#x}: {len(copyins)} {COPYIN:#x} calls, all preceded "
            f"by edx=0x20 ({[hex(s) for s in per_entry]}); loop advances by "
            f"0x20 at {step[0]:#x} and exits on r13==r15 at {loop_cmp[0]:#x}. "
            f"The TOCTOU precondition is structurally present. 'Type 2 chaining "
            f"uses previous result' and 'sandbox flag derivation' were not "
            f"checked and stay unresolved."
        ),
        "ok": ok,
    }


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    blob = kernel()
    idx = index()

    results = [claim9(blob, idx), claim10(blob), claim11(blob),
               claim12(blob, idx), claim13(blob), claim14(blob), claim15(blob)]

    width = max(len(r["id"]) for r in results)
    print(f"{'claim':<{width}}  {'verdict':<10}  evidence")
    print(f"{'-' * width}  {'-' * 10}  {'-' * 40}")
    for r in results:
        print(f"{r['id']:<{width}}  {r['verdict']:<10}  {r['detail']}")

    drift = [r for r in results if not r["ok"]]
    print()
    if drift:
        print(f"DRIFT in {len(drift)} claim(s): {[r['id'] for r in drift]}")
        return 1 if check else 0
    print(f"all {len(results)} claims match the committed artifact")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
