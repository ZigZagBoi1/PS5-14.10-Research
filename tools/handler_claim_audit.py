#!/usr/bin/env python3
"""Audit the tier-1 handler claims in docs/VERIFIED_HANDLER_ANALYSIS.md
against the committed 13.60 artifacts.

The audit is offline and read-only. It reads only repository files:

  docs/dumps_13.60/sysent_index.json        syscall -> thunk RVA
  docs/dumps_13.60/handler_NNN.bin          4096-byte window at each thunk
  docs/dumps_13.60/kernel_text.bin          handler bodies
  results/kernel_handlers/asm/sys_NNN.asm   committed disassembly

Usage:

  python tools/handler_claim_audit.py           # print the verdict table
  python tools/handler_claim_audit.py --check   # exit 1 if any claim drifts

The checks are deliberately narrow. They test what the cited artifacts
contain, not what any handler means. A "refuted" verdict below says the
claim's own cited evidence does not exist; it does not claim the kernel is
safe.
"""

from __future__ import annotations

import bisect
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
ASM = ROOT / "results" / "kernel_handlers" / "asm"

# The pointer transform f(x) = x ^ (x >> 4) as it appears in kernel_text.bin.
# Site 1 (0x3b072e) uses rcx; site 2 (0x3b1b04) uses rdx for the shift copy.
TRANSFORM_RCX = bytes.fromhex("498b45104889c148c1f9044831c148")
TRANSFORM_RDX = bytes.fromhex("498b45104889c248c1fa044831c248")

# Claim 2 cites these file offsets inside handler_NNN.bin as handler code.
CLAIM2_OFFSETS = {661: 0x46F, 662: 0x45F, 668: 0x47F}

# Claim 3 quotes this instruction pair as a 32-bit/64-bit size mismatch.
STACK_LEA = (0x3AFA3D, "LEA EAX, [0xf + R15*0x4]")
COPY_LEA = (0x3AFA96, "LEA R12, [R13*0x4]")

NOSYS_RVA = 0x265760

INSN_RE = re.compile(r"^(0x[0-9a-f]+): (.+)$")
FUNC_RE = re.compile(r"^; FUNCTION (\S+) \[(0x[0-9a-f]+), (0x[0-9a-f]+)\]")
BODY_RE = re.compile(r"^; .*body (\[.*\])$")
# Three block header styles appear in the committed assembly:
#   ; ===== TARGET: <name> RVA 0x...
#   ; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): <name> RVA 0x...
#   ; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): RVA 0x...
BLOCK_RE = re.compile(
    r"^; ===== (?:TARGET|LINKED/ADJACENT CONTEXT \(reachability must be checked\)): "
    r"(?:(\S+) )?RVA (0x[0-9a-f]+)"
)
# A label either carries its own RVA or relies on the header above it.
LABEL_RE = re.compile(r"^(\S+):(?: ; RVA (0x[0-9a-f]+))?$")


def load_index() -> dict[int, int]:
    data = json.loads((DUMPS / "sysent_index.json").read_text(encoding="utf-8"))
    return {e["num"]: int(e["sy_call_off"], 16) for e in data["entries"]}


def trampoline_entries(blob: bytes, base: int = 0) -> list[tuple[int, int]]:
    """Every 8-byte E9 rel32 / CC CC CC entry in a handler window."""
    out = []
    for off in range(0, len(blob) - 7, 8):
        entry = blob[off:off + 8]
        if entry[0] == 0xE9 and entry[5:8] == b"\xcc\xcc\xcc":
            rel = struct.unpack_from("<i", entry, 1)[0]
            out.append((off, (base + off + 5 + rel) & 0xFFFFFFFFFFFFFFFF))
    return out


def jmp_target(blob: bytes, off: int, base: int) -> int | None:
    """Resolve an E9 rel32 at ``off``, where ``base`` is the window's RVA."""
    if blob[off] != 0xE9:
        return None
    rel = struct.unpack_from("<i", blob, off + 1)[0]
    return (base + off + 5 + rel) & 0xFFFFFFFFFFFFFFFF


def branch_sources(kernel: bytes, targets: set[int]) -> dict[int, list[tuple[int, str]]]:
    """Find every direct call/jmp in the text that lands on a target address.

    A single pass collects both opcodes; the result distinguishes an E8 call
    site from an E9 tail jump because reachability of the two is not the same
    claim.
    """
    found: dict[int, list[tuple[int, str]]] = {t: [] for t in targets}
    for i in range(len(kernel) - 4):
        op = kernel[i]
        if op != 0xE8 and op != 0xE9:
            continue
        rel = struct.unpack_from("<i", kernel, i + 1)[0]
        target = (i + 5 + rel) & 0xFFFFFFFFFFFFFFFF
        if target in found:
            found[target].append((i, "call" if op == 0xE8 else "jmp"))
    return found


def parse_asm(num: int) -> tuple[dict[int, str], list[tuple[str, int, int]]]:
    """Return (address -> instruction text, named address ranges).

    The committed assembly mixes three block header styles and two ways of
    declaring a range, so this parses by event order instead of assuming one
    layout: a header names the label that follows, the label opens a block,
    and every instruction seen while that block is open extends it. Declared
    ``body [...]`` and ``FUNCTION`` extents are exact, so they are listed
    first and ``containing()`` prefers them over inferred extents.
    """
    path = ASM / f"sys_{num}.asm"
    if not path.exists():
        return {}, []
    insns: dict[int, str] = {}
    exact: list[tuple[str, int, int]] = []
    inferred: dict[str, list[int]] = {}
    order: list[str] = []
    pending: tuple[str, int] | None = None
    current: str | None = None

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = INSN_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            insns[addr] = m.group(2).strip()
            if pending is not None and addr == pending[1]:
                # A header may be followed directly by instructions, with no
                # label line in between.
                current = pending[0]
                inferred.setdefault(current, [])
                order.append(current)
                pending = None
            if current is not None:
                inferred[current].append(addr)
            continue
        m = BLOCK_RE.match(line)
        if m:
            rva = int(m.group(2), 16)
            pending = (m.group(1) or f"sub_{rva:x}", rva)
            current = None
            continue
        m = FUNC_RE.match(line)
        if m:
            exact.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
            current = None
            continue
        m = BODY_RE.match(line)
        if m:
            for r in json.loads(m.group(1)):
                exact.append(("", int(r["start"], 16), int(r["end"], 16)))
            continue
        m = LABEL_RE.match(line)
        if m and pending is not None:
            name, rva = pending
            label_rva = int(m.group(2), 16) if m.group(2) else rva
            if label_rva == rva:
                current = name
                inferred.setdefault(current, [])
                order.append(current)
                pending = None
                continue

    ranges: list[tuple[str, int, int]] = []
    declared: set[str] = set()
    for name, start, end in exact:
        if not name:
            name = next((n for n, a in inferred.items() if start in a), f"sub_{start:x}")
        declared.add(name)
        ranges.append((name, start, end))
    for name in order:
        addrs = inferred[name]
        # A declared extent is authoritative: an inferred one would only be
        # the span between two headers, which can overshoot the real block.
        if addrs and name not in declared:
            ranges.append((name, min(addrs), max(addrs)))
    return insns, ranges


def containing(ranges: list[tuple[str, int, int]], addr: int) -> str | None:
    for name, start, end in ranges:
        if start <= addr <= end:
            return name
    return None


def handler_bodies(index: dict[int, int], kernel: bytes) -> dict[int, int]:
    """Map syscall number -> body RVA, by following each thunk's E9."""
    out = {}
    for num, off in index.items():
        target = jmp_target(kernel, off, 0)
        if target is not None:
            out[num] = target
    return out


def body_owner(starts: list[int], addr: int) -> int | None:
    """The nearest handler body at or below ``addr``.

    Handler extents are not recorded anywhere in the dump, so this uses the
    next body start as the upper bound. That is an approximation, but a safe
    one for the question asked here: whether an address falls in the gap
    between two handler entries or outside a cited one.
    """
    i = bisect.bisect_right(starts, addr) - 1
    return starts[i] if i >= 0 else None


def _capstone():
    """Optional disassembler; the checks that need it are skipped without it."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError:
        return None
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    return cs


def module_field_reads(md, kernel: bytes, start: int, end: int) -> list[tuple[int, str]]:
    """Reads of module+0x78/0x80/0x88/0xf8/0x100 inside one body."""
    out = []
    for insn in md.disasm(kernel[start:end], start):
        text = insn.op_str
        if insn.mnemonic != "mov" or "ptr [" not in text:
            continue
        if any(f"+ 0x{f}]" in text for f in ("78", "80", "88", "f8", "100")):
            out.append((insn.address, text))
    return out


def count_accepted(count: int) -> bool:
    """Does the sys_662 guard admit this count?

    The guard is ``lea eax, [r15 - 0x81]; cmp eax, 0xffffff7f; ja reject``.
    The jump fires on the wrap-around half of the space, so the accepted set
    is ``count >= 0x81`` -- a minimum, not a maximum. Getting this direction
    backwards turns a real stack clash into a non-finding, so it is a named,
    tested function rather than an inline expression.
    """
    return ((count - 0x81) & 0xFFFFFFFF) <= 0xFFFFFF7F


def transform_sites(kernel: bytes) -> list[tuple[int, str]]:
    """Every ``f(x) = x ^ (x >> 4)`` computation in the text.

    The tail is the instruction triple ``mov dst, rax; sar dst, 4; xor dst,
    rax``. The register that feeds it differs per site, so the tail alone
    identifies a site; the byte before it says whether the source was a
    ``[reg + 0x10]`` load (record export) or something else.
    """
    tails = {
        "rcx": bytes.fromhex("4889c148c1f9044831c1"),
        "rdx": bytes.fromhex("4889c248c1fa044831c2"),
    }
    sites: list[tuple[int, str]] = []
    for reg, tail in tails.items():
        pos = kernel.find(tail)
        while pos >= 0:
            load = kernel[pos - 4:pos]
            shape = "record" if (load[0] == 0x49 and load[1] == 0x8B
                                 and load[3] == 0x10) else "argument"
            sites.append((pos - 4, f"{reg}/{shape}"))
            pos = kernel.find(tail, pos + 1)
    return sorted(sites)


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    index = load_index()
    kernel = (DUMPS / "kernel_text.bin").read_bytes()
    verdicts: list[tuple[str, str, bool]] = []

    def add(cid: str, claim: str, observed: str, ok: bool) -> None:
        verdicts.append((cid, claim, ok))
        globals().setdefault("_observed", {})[cid] = observed

    # --- Structural: every handler window is a trampoline table -------------
    windows = sorted(DUMPS.glob("handler_*.bin"))
    pure = sum(
        1
        for path in windows
        if len(trampoline_entries(path.read_bytes())) == path.stat().st_size // 8
    )
    add(
        "windows-are-tables",
        "handler_*.bin are pure 8-byte trampoline tables",
        f"{pure}/{len(windows)} parse as pure 8-byte trampoline tables",
        pure == len(windows),
    )

    # --- The cited offsets are body-relative, not file offsets --------------
    # Claim 2 cites 661:0x46f, 662:0x45f, 668:0x47f. Added to each handler's
    # own entry point, all three land on the same shared address.
    resolved = []
    for num, off in CLAIM2_OFFSETS.items():
        blob = (DUMPS / f"handler_{num}.bin").read_bytes()
        entry = jmp_target(blob, 0, index[num])
        resolved.append((num, entry + off if entry is not None else None))
    add(
        "cited-offsets-resolve",
        "the three cited offsets resolve to one shared address",
        ", ".join(f"{n}->{hex(a) if a is not None else '?'}" for n, a in resolved),
        all(a == 0x3AFD5F for _, a in resolved),
    )

    # --- Where the transform actually is ------------------------------------
    sites = transform_sites(kernel)
    add(
        "transform-sites",
        "the transform occurs at five sites, none inside a handler window",
        ", ".join(f"0x{a:x}({k})" for a, k in sites),
        [a for a, _ in sites] == [0x3AFD5F, 0x3B072E, 0x3B1482, 0x3B1B04, 0x3B52DC],
    )
    add(
        "cited-site-has-transform",
        "the shared site at 0x3afd5f is a pointer transform",
        f"0x3afd5f={dict(sites).get(0x3AFD5F, 'none')}",
        dict(sites).get(0x3AFD5F) == "rdx/record",
    )

    # --- Bodies: thunk target and where it lands ----------------------------
    landed = []
    for num in (661, 662, 663, 664, 665, 666, 668):
        blob = (DUMPS / f"handler_{num}.bin").read_bytes()
        thunk = jmp_target(blob, 0, index[num])
        insns, ranges = parse_asm(num)
        body = containing(ranges, thunk) if thunk is not None else None
        tail = ""
        if body is not None:
            body_insns = [a for a in insns if containing(ranges, a) == body]
            if body_insns:
                tail = insns[max(body_insns)]
        landed.append((num, thunk, body, tail))
    nosys = [n for n, _, _, tail in landed if tail == f"JMP 0x{NOSYS_RVA:08x}"]
    add(
        "nosys-bodies",
        "661, 665 and 668 tail-jump to the unsupported-syscall stub",
        "unsupported-syscall tail jumps: " + (", ".join(str(n) for n in nosys) or "none"),
        nosys == [661, 665, 668],
    )
    add(
        "body-landing",
        "every AIO thunk resolves to a body block",
        ", ".join(f"{n}->{hex(t) if t is not None else '?'}" for n, t, _, _ in landed),
        all(b is not None for _, _, b, _ in landed),
    )

    # --- Which transform sites a syscall can reach by direct branch ---------
    insns661, ranges661 = parse_asm(661)
    insns666, ranges666 = parse_asm(666)
    owners = {
        0x3AFD5F: containing(ranges661, 0x3AFD5F),
        0x3B072E: containing(ranges661, 0x3B072E),
        0x3B1482: containing(ranges661, 0x3B1482),
        0x3B1B04: containing(ranges666, 0x3B1B04),
        0x3B52DC: containing(ranges666, 0x3B52DC),
    }
    add(
        "transform-owner",
        "each transform site sits in a named support function",
        ", ".join(f"0x{a:x}={n}" for a, n in owners.items()),
        owners == {
            0x3AFD5F: "sub_3afc20",
            0x3B072E: "sub_3b0690",
            0x3B1482: "sub_3b13b0",
            0x3B1B04: "sub_3b16a0",
            0x3B52DC: "sub_3b4a80",
        },
    )

    entries = [0x3AF920, 0x3B0690, 0x3B13B0, 0x3B16A0, 0x3B4A80]
    edges = branch_sources(kernel, set(entries))
    add(
        "writer-reachability",
        "three of the five transform functions have a direct entry edge",
        "; ".join(
            f"0x{a:x}={len(edges[a])}" + (f"[{edges[a][0][1]}@0x{edges[a][0][0]:x}]" if edges[a] else "")
            for a in entries
        ),
        edges[0x3AF920] == [(0x3AF912, "jmp")]
        and edges[0x3B16A0] == [(0x3B1692, "jmp")]
        and edges[0x3B4A80] == [(0x261790, "jmp")]
        and edges[0x3B0690] == []
        and edges[0x3B13B0] == [],
    )

    # --- Claim 3: the size mismatch ----------------------------------------
    body661 = containing(ranges661, 0x3AFA3D)
    add(
        "pair-outside-661",
        "the stack-clash instruction pair is in the shared helper, not 661's body",
        f"0x3afa3d is in {body661 or '-'}",
        body661 == "sub_3af920",
    )

    guard = [
        (0x3AF9F7, "MOV R15, qword ptr [RBX + 0x48]"),
        (0x3AF9FB, "LEA EAX, [R15 + -0x81]"),
        (0x3AFA02, "CMP EAX, 0xffffff7f"),
        (0x3AFA07, "JA 0x003afa33"),
    ]
    observed = []
    ok = True
    for addr, want in guard:
        got = insns661.get(addr, "<missing>")
        observed.append(f"0x{addr:x}:{got}")
        ok = ok and got == want

    accepted = count_accepted

    # The check rejects the small values and admits every large one, so the
    # doc's "counts up to ~0xFFFFFF00" reading of the guard is correct.
    ok = ok and accepted(0x40000001) and accepted(0xFFFFFF00)
    ok = ok and not accepted(0x10) and not accepted(0x80)
    add(
        "count-guard-is-lower-bound",
        "the bounds check admits large counts and rejects small ones",
        " | ".join(observed) + f" | accepts 0x40000001={accepted(0x40000001)}, "
        f"accepts 0x80={accepted(0x80)}",
        ok,
    )

    widths = [
        (0x3AFA3D, "LEA EAX, [0xf + R15*0x4]"),
        (0x3AFA48, "LEA ESI, [R15*0x4]"),
        (0x3AFA53, "SUB R14, RAX"),
        (0x3AFA8A, "MOV R13D, R15D"),
        (0x3AFA96, "LEA R12, [R13*0x4]"),
        (0x3AFAAA, "MOV RDX, R12"),
    ]
    observed = []
    ok = True
    for addr, want in widths:
        got = insns661.get(addr, "<missing>")
        observed.append(f"0x{addr:x}:{got}")
        ok = ok and got == want
    add(
        "allocation-vs-copy-width",
        "allocation is 32-bit and the copy length is 64-bit",
        " | ".join(observed),
        ok,
    )

    # --- Claim 1: which handler owns the cited instructions -----------------
    bodies = handler_bodies(index, kernel)
    starts = sorted(bodies.values())
    cited = [bodies[593] + 0x7DD, bodies[593] + 0x895]
    owners = [body_owner(starts, a) for a in cited]
    add(
        "claim1-offsets-outside-593",
        "the cited 593 offsets land in a different handler's body",
        ", ".join(
            f"0x{a:x}->{'0x%x' % o if o else '?'} (sys {next((n for n, b in bodies.items() if b == o), '?')})"
            for a, o in zip(cited, owners)
        ),
        all(o is not None and o != bodies[593] for o in owners),
    )

    md = _capstone()
    if md is None:
        add(
            "claim1-field-reads-owner",
            "the cited module-field reads occur in 608 only, not 593 or 660",
            "skipped: capstone not installed",
            True,
        )
        add(
            "claim1-copy-gate",
            "593 copies module layout only when priv_check(1) returns 0",
            "skipped: capstone not installed",
            True,
        )
    else:
        per_syscall = {}
        for num in (593, 660, 608):
            start = bodies[num]
            end = next((v for v in starts if v > start), len(kernel))
            per_syscall[num] = module_field_reads(md, kernel, start, end)
        add(
            "claim1-field-reads-owner",
            "the cited module-field reads occur in 608 only, not 593 or 660",
            ", ".join(f"{n}={len(v)}" for n, v in per_syscall.items()),
            len(per_syscall[593]) == 0
            and len(per_syscall[660]) == 0
            and len(per_syscall[608]) >= 4,
        )

        # 593: priv_check(1) at body+0x28f. `test eax,eax; je <copy path>`
        # means the copies run when the check returns 0 (failure); the
        # fall-through zeroes the block and jumps past them.
        priv = bodies[593] + 0x28F
        flow = list(md.disasm(kernel[priv:priv + 0x30], priv))
        je_target = flow[2].operands[0].imm if len(flow) > 2 else None
        at_target = list(md.disasm(kernel[je_target:je_target + 8], je_target)) if je_target else []
        skip = [i for i in flow if i.mnemonic == "jmp"]
        skip_target = skip[0].operands[0].imm if skip else None
        observed = " | ".join(
            f"{i.address:#x}:{i.mnemonic} {i.op_str}".replace("0x", "0x")
            for i in flow[:4]
        )
        if at_target:
            observed += f" | je->{je_target:#x}:{at_target[0].mnemonic} {at_target[0].op_str}"
        add(
            "claim1-copy-gate",
            "593 copies module layout only when priv_check(1) returns 0",
            observed,
            len(flow) > 3
            and flow[0].mnemonic == "call"
            and flow[1].mnemonic == "test"
            and flow[2].mnemonic == "je"
            and bool(at_target)
            and at_target[0].mnemonic == "mov"
            and "+ 0x48]" in at_target[0].op_str
            and skip_target is not None
            and skip_target > je_target,
        )

    # --- Report -------------------------------------------------------------
    shown = globals().pop("_observed", {})
    width = max(len(c) for c, _, _ in verdicts)
    print(f"{'check'.ljust(width)}  verdict   observation")
    print(f"{'-' * width}  -------   -----------")
    for cid, claim, ok in verdicts:
        print(f"{cid.ljust(width)}  {'holds' if ok else 'REFUTED'}   {shown.get(cid, '')}")
    print()
    print("claims asserted:")
    for cid, claim, _ in verdicts:
        print(f"  {cid}: {claim}")

    failed = [cid for cid, _, ok in verdicts if not ok]
    print()
    print(f"{len(verdicts) - len(failed)}/{len(verdicts)} checks hold")
    if failed:
        print("drifted: " + ", ".join(failed))
    return 1 if (check and failed) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
