#!/usr/bin/env python3
"""Audit tier-1 claims 4-8 of docs/VERIFIED_HANDLER_ANALYSIS.md.

Read-only and offline. Every input is a committed repository file:

  docs/dumps_13.60/sysent_index.json      syscall -> thunk slot RVA
  docs/dumps_13.60/kernel_text.bin        handler bodies (15,132,096 bytes)
  docs/sysent-names-13.60.csv             name cross-reference
  results/kernel_handlers/asm/sys_626.asm committed disassembly (RDMSR count)

Handler bodies are resolved by following the slot's ``E9 rel32`` with
base 0. Function extents are not recorded in the dump, so a body is bounded
by the first terminator that is followed by padding and a prologue
(``55 48 89 e5``) or by the next sysent body start.

Usage:
  python tools/tier1_claims_audit.py           # verdict table
  python tools/tier1_claims_audit.py --check   # exit 1 if any pinned fact drifts

A "REFUTED" row below means the claim's own cited evidence does not exist in
this artifact. It is not a statement that the kernel is safe.
"""

from __future__ import annotations

import bisect
import csv
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
ASM = ROOT / "results" / "kernel_handlers" / "asm"
NAMES = ROOT / "docs" / "sysent-names-13.60.csv"

PRIV_CHECK = 0xB2BB00          # call 0xb2bb00, per docs/HANDLER_CLAIM_CORRECTIONS.md
AUTH_HELPERS = (0x609110, 0x609040, 0x6090D0, 0x609150, 0x6092D0)
PROLOGUE = bytes.fromhex("554889e5")

# sys 622 auth gate
MASK_A = 0xF8FFF000000D5       # 0x7dce0e, window 0x100-0x133
MASK_B = 0x600000000000        # 0x7dd00b, bits 45/46 -> cmd 0x12d/0x130
MASK_A_WIDTH = 0x34
MASK_A_JA = 0x7DCE4F           # no-auth landing block
MASK_A_JBIT = 0x7DD00B

# sys 626 MSR formulas
MSR_A = 0xC0010241             # index <= 3, formed with OR
MSR_B = 0xC0010189             # index > 3, formed with ADD
MSR_HELPER = 0xC0010231        # 0x605000, formed with LEA [r14+r14-0x3ffefdcf]

# sys 629
CITED_CRED_CHECK = 0xCECC90


def load():
    index = {e["num"]: int(e["sy_call_off"], 16)
             for e in json.loads((DUMPS / "sysent_index.json").read_text(encoding="utf-8"))["entries"]}
    kernel = (DUMPS / "kernel_text.bin").read_bytes()
    return index, kernel


INDEX, KERNEL = load()
SLOTS = {n: INDEX[n] for n in (588, 622, 626, 629, 638, 639)}
BODIES = {n: SLOTS[n] + 5 + struct.unpack_from("<i", KERNEL, SLOTS[n] + 1)[0] for n in SLOTS}
STARTS = sorted(BODIES.values())


def _capstone():
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    return cs


def insns(start: int, end: int) -> list:
    return list(_capstone().disasm(KERNEL[start:end], start))


def text(i) -> str:
    return f"{i.mnemonic} {i.op_str}".strip()


def call_targets(start: int, end: int) -> list[tuple[int, int]]:
    """Direct E8 call sites as (site, target). Indirect calls are invisible."""
    out = []
    for i in insns(start, end):
        if i.mnemonic == "call" and i.op_str.startswith("0x"):
            out.append((i.address, int(i.op_str, 16)))
    return out


def func_extent(start: int, limit: int = 0x8000) -> int:
    """End (exclusive) of the function at ``start``.

    A function ends at the first ret/ud2/unconditional jmp followed by
    nop/int3 padding and a prologue, or landing on a known sysent body start.
    """
    for i in insns(start, min(start + limit, len(KERNEL))):
        if i.mnemonic not in ("ret", "ud2", "jmp"):
            continue
        if i.mnemonic == "jmp" and not i.op_str.startswith("0x"):
            continue
        end = i.address + i.size
        j = end
        while j < len(KERNEL) and KERNEL[j] in (0x90, 0xCC):
            j += 1
        if KERNEL[j:j + 4] == PROLOGUE or j in STARTS:
            return end
    return start + limit


def owner(addr: int) -> int | None:
    i = bisect.bisect_right(STARTS, addr) - 1
    return STARTS[i] if i >= 0 else None


def insn_at(addr: int) -> str:
    got = insns(addr, addr + 15)
    return text(got[0]) if got else "<no insn>"


def bytes_at(addr: int, n: int = 8) -> str:
    return KERNEL[addr:addr + n].hex()


# --- pure models, tested separately -----------------------------------------

def bitmask_a_index(cmd: int) -> int | None:
    """The bit index the 0x7dce18 ``bt`` would use, or None if the gate is skipped.

    The gate is ``lea eax,[r14-0x100]; cmp eax,0x33; ja no_auth; bt rcx,rax``.
    ``ja`` is unsigned-strictly-above, so the window is delta <= 0x33 and any
    cmd < 0x100 wraps to 0xffffff00..0xffffffff and takes the no-auth branch
    before the bit test ever runs. There is no underflowing bit index.
    """
    delta = (cmd - 0x100) & 0xFFFFFFFF
    return delta if delta < MASK_A_WIDTH else None


def mask_a_checked() -> list[int]:
    """Commands in 0x100-0x133 whose bit is set (i.e. that reach an auth call)."""
    return [0x100 + i for i in range(MASK_A_WIDTH) if (MASK_A >> i) & 1]


def mask_a_skipped() -> list[int]:
    return [0x100 + i for i in range(MASK_A_WIDTH) if not (MASK_A >> i) & 1]


def mask_b_hits() -> list[int]:
    return [0x100 + i for i in range(MASK_A_WIDTH) if (MASK_B >> i) & 1]


def auth_checked_commands() -> int:
    """27 = 22 bitmap-A + 2 bitmap-B + 3 triple-gate specials."""
    return len(mask_a_checked()) + len(mask_b_hits()) + 3


def msr_for_index(index: int, hw_max: int = 7) -> int | None:
    """MSR number the 626 body reads, or None when the index guard rejects it.

    0x604f7e  lea ecx,[rbx+rbx]        ; ecx = 2*index
    0x604f81  cmp ebx,3 ; ja 0x604f90
    0x604f86  or  ecx,0xc0010241       ; index <= 3
    0x604f90  add ecx,0xc0010189       ; index > 3
    The guard at 0x604f75 is ``cmp ebx,ecx(hw_max); seta cl`` -> reject above.
    """
    if index < 0 or index > hw_max:
        return None
    if index <= 3:
        return (2 * index) | MSR_A
    return (2 * index) + MSR_B


def helper_msr(index: int) -> int:
    """0x605043 form: ``lea ecx,[r14+r14-0x3ffefdcf]`` == 0xc0010231 + 2*index."""
    return (2 * index) - 0x3FFEFDCF & 0xFFFFFFFF


def eacces_proceeds(rc: int) -> bool:
    """588 at 0xabc6d1: ``cmp eax,0xd; je proceed; test eax,eax; jne error``."""
    return rc == 0 or rc == 0xD


# --- observed facts ---------------------------------------------------------

def observed() -> dict[str, object]:
    o: dict[str, object] = {}

    # --- resolution ---------------------------------------------------------
    for n in SLOTS:
        o[f"slot{n}"] = SLOTS[n]
        o[f"body{n}"] = BODIES[n]
        o[f"slotbytes{n}"] = bytes_at(SLOTS[n], 8)

    # --- claim 4: sys 622 ---------------------------------------------------
    o["c4_ladder"] = [insn_at(a) for a in
                      (0x7DCDF5, 0x7DCE02, 0x7DCE09, 0x7DCE0C, 0x7DCE0E,
                       0x7DCE18, 0x7DCE1C)]
    o["c4_gate_bytes"] = [bytes_at(a, 8) for a in (0x7DCE09, 0x7DCE0C, 0x7DCE0E)]
    o["c4_ja_target"] = 0x7DCE0C + 2 + struct.unpack_from("<b", KERNEL, 0x7DCE0D)[0]
    o["c4_jae_target"] = 0x7DCE1C + 6 + struct.unpack_from("<i", KERNEL, 0x7DCE1E)[0]
    o["c4_mask_a_popcount"] = bin(MASK_A).count("1")
    o["c4_checked"] = mask_a_checked()
    o["c4_skipped"] = mask_a_skipped()
    o["c4_checked_n"] = len(mask_a_checked())
    o["c4_skipped_n"] = len(mask_a_skipped())
    o["c4_mask_b"] = mask_b_hits()
    o["c4_total_checked"] = auth_checked_commands()
    o["c4_cmd_below_100_skips"] = all(bitmask_a_index(c) is None for c in range(0x100))
    o["c4_cmd_100_133_skip"] = [c for c in range(0x100, 0x134)
                                if bitmask_a_index(c) is not None
                                and not (MASK_A >> (c - 0x100)) & 1]
    o["c4_auth_calls"] = [(hex(a), hex(t)) for a, t in
                          call_targets(0x7DCD40, 0x7E4810) if t in AUTH_HELPERS]
    o["c4_extent_prologues"] = sum(
        1 for a in range(0x7DCD40, 0x7E4810)
        if KERNEL[a:a + 4] == PROLOGUE)
    o["c4_dispatcher"] = (0x7DCD40, func_extent(0x7DCD40))
    o["c4_priv_calls"] = [(hex(a), hex(t)) for a, t in
                          call_targets(0x7DCD40, 0x7E4810) if t == PRIV_CHECK]
    o["c4_534_reproducible"] = False
    o["c4_95pct"] = round(100 * 534 / 561, 1)

    # --- claim 5: sys 588 ---------------------------------------------------
    b588 = BODIES[588]
    o["c5_extent"] = (b588, func_extent(b588))
    o["c5_calls"] = [(hex(a), hex(t)) for a, t in call_targets(b588, func_extent(b588))]
    o["c5_priv"] = [x for x in o["c5_calls"] if x[1] == hex(PRIV_CHECK)]
    o["c5_auth"] = [x for x in o["c5_calls"] if int(x[1], 16) in AUTH_HELPERS]
    o["c5_cred_offsets"] = [(hex(i.address), i.op_str) for i in
                            insns(b588, func_extent(b588))
                            if any(f"+ 0x{f}]" in i.op_str for f in ("5d4", "5d8"))]
    o["c5_bounds"] = [insn_at(a) for a in (0xABC623, 0xABC627, 0xABC62D, 0xABC631,
                                           0xABC635, 0xABC638, 0xABC63B, 0xABC63E,
                                           0xABC643)]
    o["c5_eacces"] = [insn_at(a) for a in (0xABC6CC, 0xABC6D1, 0xABC6D4,
                                           0xABC6D6, 0xABC6D8)]
    o["c5_je_target"] = 0xABC6D4 + 2 + struct.unpack_from("<b", KERNEL, 0xABC6D5)[0]
    o["c5_jne_target"] = 0xABC6D8 + 2 + struct.unpack_from("<b", KERNEL, 0xABC6D9)[0]
    o["c5_eacces_bytes"] = [bytes_at(a, 6) for a in (0xABC6D1, 0xABC6D4, 0xABC6D8)]
    o["c5_proceed_block"] = [insn_at(a) for a in (0xABC6DA, 0xABC6E7, 0xABC6EC)]
    o["c5_copyin"] = [(hex(a), hex(t)) for a, t in
                      call_targets(b588, func_extent(b588)) if t == 0x259900]
    o["c5_range_gate"] = [insn_at(a) for a in (0xABC6A8, 0xABC6AC, 0xABC6B8, 0xABC6BB)]
    o["c5_eacces_model"] = [eacces_proceeds(r) for r in (0, 0xD, 1, 22)]

    # --- claim 6: sys 638/639 ----------------------------------------------
    b638, e638 = BODIES[638], func_extent(BODIES[638])
    b639, e639 = BODIES[639], func_extent(BODIES[639])
    o["c6_extents"] = ((b638, e638), (b639, e639))
    o["c6_text_len"] = len(KERNEL)
    o["c6_table_base"] = 0x6BE60A + 0x3257316          # 638 lea rcx,[rip+..]
    o["c6_table_base_639"] = 0x6BE864 + 0x32570BC      # 639 lea rdi,[rip+..]
    o["c6_count"] = 0x6BE5F6 + 0x325932A               # 638 mov eax,[rip+..]
    o["c6_count_639"] = 0x6BE83D + 0x32590E3           # 639 mov eax,[rip+..]
    o["c6_mode"] = 0x6BE71B + 0x33B1E94                # both (cmp at 0x6be65d / 0x6be715)
    o["c6_globals_outside_text"] = all(
        a >= len(KERNEL) for a in (o["c6_table_base"], o["c6_count"], o["c6_mode"]))
    o["c6_search"] = [insn_at(a) for a in (0x6BE62A, 0x6BE631, 0x6BE638, 0x6BE63E,
                                           0x6BE642, 0x6BE646, 0x6BE64D)]
    o["c6_search_639"] = [insn_at(a) for a in (0x6BE87B, 0x6BE889, 0x6BE88C,
                                               0x6BE8B3, 0x6BE8BF, 0x6BE8C2)]
    o["c6_copyout"] = [(hex(a), hex(t)) for a, t in
                       call_targets(b638, e638) if t == 0x2591D0]
    o["c6_copyout_639"] = [(hex(a), hex(t)) for a, t in
                           call_targets(b639, e639) if t == 0x2591D0]
    o["c6_copy_sizes"] = [insn_at(a) for a in (0x6BE75F, 0x6BE794, 0x6BE7C9)]
    o["c6_priv"] = [(hex(a), hex(t)) for s, e in ((b638, e638), (b639, e639))
                    for a, t in call_targets(s, e) if t == PRIV_CHECK]
    o["c6_auth"] = [(hex(a), hex(t)) for s, e in ((b638, e638), (b639, e639))
                    for a, t in call_targets(s, e) if t in AUTH_HELPERS]
    o["c6_record"] = [insn_at(a) for a in (0x6BE642, 0x6BE664, 0x6BE669)]
    o["c6_result_638"] = [insn_at(a) for a in (0x6BE72D, 0x6BE730, 0x6BE734)]
    o["c6_result_639"] = [insn_at(a) for a in (0x6BEA46, 0x6BEA4A, 0x6BEA4D,
                                               0x6BEA50)]
    o["c6_names"] = _names((638, 639))

    # --- claim 7: sys 626 ---------------------------------------------------
    b626, e626 = BODIES[626], func_extent(BODIES[626])
    o["c7_extent"] = (b626, e626)
    o["c7_rdmsr_body"] = [i.address for i in insns(b626, e626) if i.bytes == b"\x0f\x32"]
    o["c7_formula"] = [insn_at(a) for a in (0x604F7E, 0x604F81, 0x604F84,
                                            0x604F86, 0x604F8C, 0x604F90, 0x604F96)]
    o["c7_msr"] = [msr_for_index(i) for i in range(8)]
    o["c7_msr_rejected"] = [msr_for_index(i) for i in (8, 0xFFFFFFFF)]
    o["c7_helper"] = (0x605043, [i.address for i in insns(0x605000, func_extent(0x605000))
                                 if i.bytes == b"\x0f\x32"])
    o["c7_helper_form"] = insn_at(0x60503B)
    o["c7_helper_msr"] = [helper_msr(i) for i in range(4)]
    o["c7_reachable"] = len(o["c7_rdmsr_body"]) + len(o["c7_helper"][1])
    o["c7_file_rdmsr"] = _asm_rdmsr_count(626)
    o["c7_file_range"] = _asm_rdmsr_range(626)
    o["c7_priv"] = [(hex(a), hex(t)) for a, t in call_targets(b626, e626)
                    if t == PRIV_CHECK]
    o["c7_auth"] = [(hex(a), hex(t)) for a, t in call_targets(b626, e626)
                    if t in AUTH_HELPERS]
    o["c7_table"] = 0x604E61 + 0x111E75B
    o["c7_table_outside"] = o["c7_table"] >= len(KERNEL)
    o["c7_guard"] = [insn_at(a) for a in (0x604F57, 0x604F63, 0x604F6D,
                                          0x604F72, 0x604F75, 0x604F77,
                                          0x604F7A, 0x604F7C)]
    o["c7_cmds"] = [insn_at(a) for a in (0x604E4D, 0x604E51, 0x604E54)]

    # --- claim 8: sys 629 ---------------------------------------------------
    b629, e629 = BODIES[629], func_extent(BODIES[629])
    o["c8_extent"] = (b629, e629)
    o["c8_cmp"] = (0x91C64B, bytes_at(0x91C64B, 4), insn_at(0x91C64B))
    o["c8_je"] = (0x91C652, bytes_at(0x91C652, 6),
                  0x91C652 + 6 + struct.unpack_from("<i", KERNEL, 0x91C654)[0])
    o["c8_je_disp"] = o["c8_je"][2] - b629
    o["c8_skipped"] = [hex(a) for a in
                       (0x91C66C, 0x91C69B, 0x91C6A4, 0x91C6B6, 0x91C6CE, 0x91C6EB)]
    o["c8_fastpath"] = [insn_at(a) for a in (0x91C6F8, 0x91C6FA, 0x91C6FD,
                                             0x91C701, 0x91C706, 0x91C70A,
                                             0x91C70E, 0x91C715)]
    o["c8_cred_cited_bytes"] = bytes_at(CITED_CRED_CHECK, 16)
    o["c8_cred_cited_refs"] = _refs(CITED_CRED_CHECK)
    o["c8_cred_real"] = (0x91C6B6, insn_at(0x91C6B6))
    o["c8_delegate"] = (0x91BCA0, insn_at(0x91BCA0))
    o["c8_delegate_cred"] = [(hex(a), insn_at(a)) for a in
                             (0x91BDE9, 0x91BDF6, 0x91BDCB, 0x91BE11)]
    o["c8_names"] = _names((629,))
    return o


def _names(nums) -> dict[int, str]:
    if not NAMES.exists():
        return {}
    out = {}
    with NAMES.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                n = int(row["number"])
            except (TypeError, ValueError):
                continue
            if n in nums:
                out[n] = row["name"]
    return out


def _asm_rdmsr_count(num: int) -> int:
    path = ASM / f"sys_{num}.asm"
    if not path.exists():
        return -1
    return sum(1 for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
               if ln.rstrip().endswith("rdmsr"))


def _asm_rdmsr_range(num: int) -> tuple[int, int] | None:
    path = ASM / f"sys_{num}.asm"
    if not path.exists():
        return None
    base = 0xFFFFFFFF8A9C0000
    addrs = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.rstrip().endswith("rdmsr"):
            continue
        head = ln.split(":", 1)[0]
        try:
            addrs.append(int(head, 16) - base)
        except ValueError:
            continue
    return (min(addrs), max(addrs)) if addrs else None


def _refs(target: int) -> dict[str, list[int]]:
    """Direct branch and immediate references to ``target`` in the whole text."""
    calls, imms = [], []
    for i in range(len(KERNEL) - 4):
        op = KERNEL[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", KERNEL, i + 1)[0]
            if (i + 5 + rel) & 0xFFFFFFFFFFFFFFFF == target:
                calls.append(i)
    for width in (4, 8):
        needle = target.to_bytes(width, "little")
        pos = KERNEL.find(needle)
        while pos >= 0:
            imms.append(pos)
            pos = KERNEL.find(needle, pos + 1)
    return {"branches": calls, "immediates": imms}


# --- pinned expectations ----------------------------------------------------

EXPECT = {
    "slot622": 0x265E98, "body622": 0x7DCD40,
    "slot588": 0x265E08, "body588": 0xABC5F0,
    "slot626": 0x265EB8, "body626": 0x604CF0,
    "slot629": 0x265ED0, "body629": 0x91C640,
    "slot638": 0x265F10, "body638": 0x6BE5C0,
    "slot639": 0x265F18, "body639": 0x6BE800,
    "slotbytes622": "e9a36e5700cccccc",
    "slotbytes588": "e9e3678500cccccc",
    "slotbytes626": "e933ee3900cccccc",
    "slotbytes629": "e96b676b00cccccc",
    "slotbytes638": "e9ab864500cccccc",
    "slotbytes639": "e9e3884500cccccc",

    "c4_ladder": ["cmp r14d, 0x270", "lea eax, [r14 - 0x100]", "cmp eax, 0x33",
                  "ja 0x7dce4f", "movabs rcx, 0xf8fff000000d5", "bt rcx, rax",
                  "jae 0x7dd00b"],
    "c4_gate_bytes": ["83f833774148b9d5", "774148b9d5000000", "48b9d5000000ff8f"],
    "c4_ja_target": 0x7DCE4F,
    "c4_jae_target": 0x7DD00B,
    "c4_mask_a_popcount": 22,
    "c4_checked_n": 22,
    "c4_skipped_n": 30,
    "c4_mask_b": [0x12D, 0x12E],
    "c4_total_checked": 27,
    "c4_cmd_below_100_skips": True,
    "c4_auth_calls": [("0x7dce29", "0x609110"), ("0x7dce3a", "0x609040"),
                      ("0x7dcf3c", "0x609110"), ("0x7dcf51", "0x6090d0"),
                      ("0x7dd026", "0x609110"), ("0x7dd03b", "0x6090d0")],
    "c4_extent_prologues": 53,
    "c4_dispatcher": (0x7DCD40, 0x7DDBA3),
    "c4_priv_calls": [],
    "c4_95pct": 95.2,

    "c5_extent": (0xABC5F0, 0xABC70E),
    "c5_calls": [("0xabc663", "0xc1a3e0"), ("0xabc676", "0x259900"),
                 ("0xabc6cc", "0x81f770"), ("0xabc6e7", "0x2d2e50"),
                 ("0xabc707", "0x6fd6b0")],
    "c5_priv": [],
    "c5_auth": [],
    "c5_cred_offsets": [],
    "c5_bounds": ["cmp qword ptr [rbx + 0x20], r13", "ja 0xabc6ee",
                  "mov rcx, qword ptr [rbx + 0x28]", "mov r15, qword ptr [rsi + 8]",
                  "sub rcx, r13", "setbe dl", "cmp rcx, r15", "setb cl",
                  "jne 0xabc6ee"],
    "c5_eacces": ["call 0x81f770", "cmp eax, 0xd", "je 0xabc6da",
                  "test eax, eax", "jne 0xabc6ee"],
    "c5_je_target": 0xABC6DA,
    "c5_jne_target": 0xABC6EE,
    "c5_eacces_bytes": ["83f80d740485c0", "740485c07514", "7514488d4db0"],
    "c5_proceed_block": ["lea rcx, [rbp - 0x50]", "call 0x2d2e50", "xor eax, eax"],
    "c5_copyin": [("0xabc676", "0x259900")],
    "c5_range_gate": ["cmp r13d, 0xe", "ja 0xabc6da",
                      "cmp r15, rax", "jb 0xabc6da"],
    "c5_eacces_model": [True, True, False, False],

    "c6_extents": ((0x6BE5C0, 0x6BE7F7), (0x6BE800, 0x6BEB13)),
    "c6_text_len": 15132096,
    "c6_table_base": 0x3915920,
    "c6_table_base_639": 0x3915920,
    "c6_count": 0x3917920,
    "c6_count_639": 0x3917920,
    "c6_mode": 0x3A705AF,
    "c6_globals_outside_text": True,
    "c6_search": ["lea r9d, [rdi + rdx]", "shr r8d, 0x1f", "sar r8d, 1",
                  "shl r9, 4", "cmp qword ptr [r9 + rcx], rsi",
                  "jle 0x6be620", "jl 0x6be62a"],
    "c6_search_639": ["lea r10d, [r8 + rcx]", "sar r9d, 1", "movsxd r10, r9d",
                      "movsxd r14, dword ptr [r10 + rdi + 8]",
                      "cmp r14, rdx", "jle 0x6be870"],
    "c6_copyout": [("0x6be767", "0x2591d0"), ("0x6be79c", "0x2591d0"),
                   ("0x6be7d1", "0x2591d0")],
    "c6_copyout_639": [("0x6bea83", "0x2591d0"), ("0x6beab8", "0x2591d0"),
                       ("0x6beaed", "0x2591d0")],
    "c6_copy_sizes": ["mov edx, 8", "mov edx, 0x10", "mov edx, 4"],
    "c6_priv": [],
    "c6_auth": [],
    "c6_record": ["cmp qword ptr [r9 + rcx], rsi",
                  "mov rdi, qword ptr [rsi + rcx - 0x10]",
                  "mov rsi, qword ptr [rsi + rcx - 8]"],
    "c6_result_638": ["add rax, qword ptr [rbx]", "movsxd rcx, dword ptr [rbp - 0x28]",
                      "add rax, rcx"],
    "c6_result_639": ["movsxd rdx, dword ptr [rbp - 0x28]", "mov rcx, qword ptr [rbx]",
                      "add rdx, rax", "sub rcx, rdx"],
    "c6_names": {638: "utc_to_localtime", 639: "localtime_to_utc"},

    "c7_extent": (0x604CF0, 0x604FF5),
    "c7_rdmsr_body": [0x604F8C, 0x604F96],
    "c7_formula": ["lea ecx, [rbx + rbx]", "cmp ebx, 3", "ja 0x604f90",
                   "or ecx, 0xc0010241", "rdmsr", "add ecx, 0xc0010189",
                   "rdmsr"],
    "c7_msr": [0xC0010241, 0xC0010243, 0xC0010245, 0xC0010247,
               0xC0010191, 0xC0010193, 0xC0010195, 0xC0010197],
    "c7_msr_rejected": [None, None],
    "c7_helper": (0x605043, [0x605043, 0x60506E, 0x60508A, 0x6050A0]),
    "c7_helper_form": "lea ecx, [r14 + r14 - 0x3ffefdcf]",
    "c7_helper_msr": [0xC0010231, 0xC0010233, 0xC0010235, 0xC0010237],
    "c7_reachable": 6,
    "c7_file_rdmsr": 46,
    "c7_priv": [],
    "c7_auth": [],
    "c7_table": 0x17235BC,
    "c7_table_outside": True,
    "c7_guard": ["cmp dword ptr [r15 + 8], 0", "cmp qword ptr [r15 + 0x18], 0",
                 "cmp qword ptr [rsi + 0x20], 0", "setne dl", "cmp ebx, ecx",
                 "seta cl", "or cl, dl", "jne 0x604fd7"],
    "c7_cmds": ["mov ecx, dword ptr [rsi]", "cmp ecx, 5", "ja 0x604f28"],

    "c8_extent": (0x91C640, 0x91C73D),
    "c8_cmp": (0x91C64B, "48833e01", "cmp qword ptr [rsi], 1"),
    "c8_je": (0x91C652, "0f84a0000000", 0x91C6F8),
    "c8_je_disp": 0xB8,
    "c8_skipped": ["0x91c66c", "0x91c69b", "0x91c6a4", "0x91c6b6", "0x91c6ce",
                   "0x91c6eb"],
    "c8_fastpath": ["xor ebx, ebx", "mov rsi, qword ptr [r14]",
                    "mov edx, dword ptr [r14 + 8]",
                    "movzx ecx, word ptr [r14 + 0x10]",
                    "mov r8d, dword ptr [r14 + 0x18]", "cmp rsi, 1",
                    "cmovne rsi, rbx", "call 0x91bca0"],
    "c8_cred_cited_bytes": "0800000000000000b87ece81ffffffff",
    "c8_cred_cited_refs": {"branches": [], "immediates": []},
    "c8_cred_real": (0x91C6B6, "call 0x6092d0"),
    "c8_delegate": (0x91BCA0, "push rbp"),
    "c8_delegate_cred": [("0x91bde9", "mov r8d, dword ptr [rax + 0x5c0]"),
                         ("0x91bdf6", "mov r9d, dword ptr [rax + 0x5d0]"),
                         ("0x91bdcb", "cmp r15d, 0x200000"),
                         ("0x91be11", "cmp r15d, 0x200000")],
    "c8_names": {629: "physhm_open"},
}

VERDICTS = {
    "4": ("PARTIAL", "gate bypass at 0x7dce02-0x7dce4f is real; 27 checked "
                     "reproduces (22+2+3) but 534 does not; the bit index never "
                     "underflows"),
    "5": ("CONFIRMED", "no priv_check/auth-id/ucred read in the body; "
                       "0xabc6d1 treats EACCES as proceed"),
    "6": ("PARTIAL", "binary search + unguarded copyout confirmed; the record is "
                     "{key, offset, correction}, not region base/size/offset"),
    "7": ("PARTIAL", "0xc0010241+2i and 0xc0010189+2i exact; 2 RDMSR in the body, "
                     "6 reachable, 46 in the file window"),
    "8": ("PARTIAL", "cmp/je 0xb8 exact and the five skips are real; 0xcecc90 is "
                     "not code and is referenced nowhere"),
}

# Drift is measured against these: a row is "holds" when its observed value
# equals EXPECT, otherwise it is "DRIFT" and --check exits 1.
ROWS = [
    ("4", "body-rva", "sys 622 slot 0x265e98 -> body 0x7dcd40", "body622"),
    ("4", "ladder", "unsigned window check at 0x7dce02-0x7dce0c", "c4_ladder"),
    ("4", "gate-bytes", "gate instruction bytes", "c4_gate_bytes"),
    ("4", "ja-target", "ja lands on the no-auth block 0x7dce4f", "c4_ja_target"),
    ("4", "jae-target", "jae lands on the second bitmap 0x7dd00b", "c4_jae_target"),
    ("4", "mask-a-count", "22 set bits in 0xf8fff000000d5 within 0x34", "c4_checked_n"),
    ("4", "mask-a-skipped", "30 of 0x100-0x133 skip the gate", "c4_skipped_n"),
    ("4", "mask-b", "second bitmap selects 0x12d and 0x130", "c4_mask_b"),
    ("4", "checked-total", "22+2+3 = 27 checked commands", "c4_total_checked"),
    ("4", "below-100", "every cmd < 0x100 skips the bitmap gate", "c4_cmd_below_100_skips"),
    ("4", "auth-sites", "6 auth-helper calls in the 31,440-byte extent", "c4_auth_calls"),
    ("4", "no-priv", "no priv_check call in the extent", "c4_priv_calls"),
    ("4", "dispatcher-extent", "dispatcher 0x7dcd40-0x7ddba3; sub-handlers follow at 0x7ddbb0",
     "c4_dispatcher"),
    ("5", "body-extent", "sys 588 body 0xabc5f0-0xabc70e", "c5_extent"),
    ("5", "calls", "the body's five direct calls", "c5_calls"),
    ("5", "no-priv", "no priv_check call in the body", "c5_priv"),
    ("5", "no-auth", "no auth-id helper call in the body", "c5_auth"),
    ("5", "no-ucred", "no [reg+0x5d4]/[reg+0x5d8] read in the body", "c5_cred_offsets"),
    ("5", "bounds", "range check at 0xabc623-0xabc643", "c5_bounds"),
    ("5", "eacces", "cmp eax,0xd; je proceed at 0xabc6d1", "c5_eacces"),
    ("5", "eacces-targets", "je 0xabc6da, jne 0xabc6ee", "c5_je_target"),
    ("5", "eacces-model", "proceed on 0x0 and 0xd, error otherwise", "c5_eacces_model"),
    ("5", "extra-validation", "a 0x20-byte copyin precedes the bounds check", "c5_copyin"),
    ("5", "range-gate", "device-window gate at 0xabc6a8-0xabc6bb", "c5_range_gate"),
    ("6", "body-extents", "638 0x6be5c0-0x6be7f0, 639 0x6be800-0x6beb0c", "c6_extents"),
    ("6", "text-len", "kernel_text.bin is 15,132,096 bytes", "c6_text_len"),
    ("6", "table", "both handlers index the table at RVA 0x3915920", "c6_table_base"),
    ("6", "count", "both read the count at RVA 0x3917920", "c6_count"),
    ("6", "mode", "both read the mode at RVA 0x3a705b0", "c6_mode"),
    ("6", "globals-outside", "table/count/mode are outside the text artifact", "c6_globals_outside_text"),
    ("6", "search", "638 does a signed upper-bound binary search", "c6_search"),
    ("6", "search-639", "639 does the same search with the correction added", "c6_search_639"),
    ("6", "copyout", "638 copies out 8/16/4 bytes through 0x2591d0", "c6_copyout"),
    ("6", "copyout-639", "639 copies out 8/16/4 bytes through 0x2591d0", "c6_copyout_639"),
    ("6", "copy-sizes", "copy lengths 8, 0x10, 4", "c6_copy_sizes"),
    ("6", "no-priv", "no priv_check in either body", "c6_priv"),
    ("6", "no-auth", "no auth-id helper call in either body", "c6_auth"),
    ("6", "record", "16-byte record: key qword, offset dword, correction dword", "c6_record"),
    ("6", "result-638", "638 returns input + offset + correction", "c6_result_638"),
    ("6", "result-639", "639 returns input - offset - correction", "c6_result_639"),
    ("6", "names", "name map: 638 utc_to_localtime, 639 localtime_to_utc", "c6_names"),
    ("7", "body-extent", "sys 626 body 0x604cf0-0x604ff5", "c7_extent"),
    ("7", "rdmsr-body", "exactly two RDMSR (0f 32) in the body", "c7_rdmsr_body"),
    ("7", "formula", "0xc0010241 OR 2i for i<=3, 0xc0010189 + 2i above", "c7_formula"),
    ("7", "msr-values", "MSR numbers for index 0-7", "c7_msr"),
    ("7", "msr-guard", "index 8 and 0xffffffff are rejected", "c7_msr_rejected"),
    ("7", "helper", "0x605000 holds 4 RDMSR sites", "c7_helper"),
    ("7", "helper-form", "helper forms 0xc0010231 + 2i by lea", "c7_helper_form"),
    ("7", "helper-msr", "helper MSR numbers for index 0-3", "c7_helper_msr"),
    ("7", "reachable", "2 body + 4 helper = 6 RDMSR reachable from 626", "c7_reachable"),
    ("7", "file-count", "sys_626.asm lists 46 rdmsr instructions", "c7_file_rdmsr"),
    ("7", "no-priv", "no priv_check in the body", "c7_priv"),
    ("7", "no-auth", "no auth-id helper call in the body", "c7_auth"),
    ("7", "dispatch-table", "the command table at 0x17235bc is outside the text", "c7_table_outside"),
    ("7", "guard", "domain/index/pointer guard at 0x604f57-0x604f7c", "c7_guard"),
    ("8", "body-extent", "sys 629 body 0x91c640-0x91c73d", "c8_extent"),
    ("8", "cmp", "48 83 3e 01 = cmp qword ptr [rsi], 1", "c8_cmp"),
    ("8", "je", "0f 84 a0 00 00 00 -> 0x91c6f8", "c8_je"),
    ("8", "je-disp", "the branch is je 0xb8 from the body start", "c8_je_disp"),
    ("8", "skips", "allocation/copyin/path/auth/compare sites it jumps over", "c8_skipped"),
    ("8", "fastpath", "arg0==1 passes literal 1 to 0x91bca0", "c8_fastpath"),
    ("8", "cred-cited", "0xcecc90 bytes are table data, not code", "c8_cred_cited_bytes"),
    ("8", "cred-refs", "nothing in the text branches to or embeds 0xcecc90", "c8_cred_cited_refs"),
    ("8", "cred-real", "the skipped credential check is call 0x6092d0", "c8_cred_real"),
    ("8", "delegate", "the fast path enters 0x91bca0", "c8_delegate"),
    ("8", "delegate-cred", "the delegate reads proc+0x5c0/+0x5d0 and gates on 0x200000",
     "c8_delegate_cred"),
    ("8", "name", "name map: 629 physhm_open", "c8_names"),
]


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    obs = observed()
    drift = []
    per_claim: dict[str, list[bool]] = {}
    width = max(len(r[1]) for r in ROWS)
    print(f"{'claim'.ljust(5)}  {'check'.ljust(width)}  verdict   observation")
    print(f"{'-' * 5}  {'-' * width}  -------   -----------")
    for claim, name, _desc, key in ROWS:
        got = obs.get(key, "<missing>")
        want = EXPECT.get(key, "<unpinned>")
        ok = got == want
        per_claim.setdefault(claim, []).append(ok)
        if not ok:
            drift.append(f"{claim}/{name}")
            shown = f"got {got!r} want {want!r}"
        else:
            shown = _short(got)
        print(f"{claim.ljust(5)}  {name.ljust(width)}  {'holds  ' if ok else 'DRIFT  '}  {shown}")
    print()
    print(f"{'claim'.ljust(6)}  {'verdict'.ljust(10)}  evidence")
    print(f"{'-' * 6}  {'-' * 10}  --------")
    for claim in sorted(VERDICTS):
        verdict, why = VERDICTS[claim]
        ok = all(per_claim.get(claim, [False]))
        label = verdict if ok else "DRIFT"
        print(f"{claim.ljust(6)}  {label.ljust(10)}  {why}")
    print()
    print("claim statements audited:")
    for claim, name, desc, _key in ROWS:
        if name in ("body-rva", "body-extent", "cmp", "formula", "eacces", "record"):
            print(f"  {claim}: {desc}")
    failed = [c for c in per_claim if not all(per_claim[c])]
    total = sum(len(v) for v in per_claim.values())
    print()
    print(f"{total - len(drift)}/{total} pinned facts hold")
    if drift:
        print("drifted: " + ", ".join(drift))
    return 1 if (check and drift) else 0


def _short(value) -> str:
    text = repr(value)
    return text if len(text) <= 150 else text[:147] + "..."


if __name__ == "__main__":
    sys.exit(main(sys.argv))
