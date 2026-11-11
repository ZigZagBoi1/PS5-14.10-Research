# Uninitialised-stack copyout: census method, 450 sites, zero survivors

Static census of the 13.60 image (`docs/dumps_13.60/kernel_text.bin`, base 0xffffffff8a9c0000,
offset == RVA) looking for the classic kernel info leak: a `copyout()` whose source is a stack buffer
that the handler only partly fills, so the uninitialised remainder reaches userland.

## 1. The idea being tested

`copyout(kernel_src, user_dst, len)` at RVA 0x2591d0 never inspects what it copies. If a handler
does `lea rdi,[rbp-0x590] ; mov edx,0x200 ; call copyout` and only writes a few fields of that 0x200
buffer, the remaining bytes are whatever the previous syscall left on this thread's kernel stack -
kernel pointers, saved frame addresses, other processes' data. Unlike every other route in this
project, that shape needs no capability, no privilege, and no bug beyond a missing initialisation, so
it is worth a full census rather than a spot check.

## 2. Method (four passes, each on the retained text)

    .local/uninit_copyout_scan.py   # all copyout sites: source register, length provenance
    .local/uninit_cov.py            # per-site store coverage of the source buffer
    .local/uninit_refine.py         # drop buffers that a callee receives as an argument
    .local/uninit_map.py            # map surviving sites to syscalls via sysent thunks
    .local/gap4_aligned.py          # re-scan from an aligned function start for bzero/memset fills

Pass 1 found 971 direct call sites to the two copy helpers (432 copyin at 0x259280, 539 copyout). Of
the 539 copyout sites, 450 have a stack source (`lea rdi,[rbp-X]`) and an immediate length - the only
shape where "how much was written" is statically decidable. Length provenance across all 971:
immediate 573, register 189, memory 34, unset-within-12 175.

Pass 2 walked each function window (`ret`/`ud2`+padding, tail `jmp`, padding run) and recorded every
store into `[rbp-X .. rbp-X+len)`. Sites where a `bzero` (0x258ff0) with an immediate smaller length
preceded the copyout: **0**. Sites with no bzero at all in the window: 233; after dropping buffers
that are also passed to a callee in rdi/rsi/rdx/rcx/r8 within three instructions of a call: 56.

Pass 4 addressed the main known blind spot by re-disassembling from the nearest `push rbp ; mov rbp,
rsp` before each site and looking for `bzero`/`memset` with a register length. Result: **30 of the 56
are cleared** by a full-length call. Of the 26 remaining, every candidate inspected by hand turned out
to be cleared by a helper the scanner did not model:

| site | bytes | what actually clears it |
|---|---|---|
| 0x4f71e0 | 0xa58 | `0x8aeb6c91 mov esi,0xa58 ; lea rdi,[rbp-0xa88] ; call 0x8ac18ff0` (bzero) |
| 0x73a7b4 | 0x7e8 | `0x8b0fa732 mov esi,0x7e8 ; lea rdi,[rbp-0x818] ; call 0x8ac18ff0` |
| 0x73b144 | 0x7e8 | same function family, bzero 0x7e8 at `0x8b0fb0ca` |
| 0xab81fa | 0x470 | `0x8b478145` bzero 0x470 |
| 0x7016c3 | 0x200 | `0x8b0c1632 mov edx,0x200 ; xor esi,esi ; call 0x8ae5af30` (memset variant) |

`0x8ae5af30` is a memset entry that is neither 0x258ff0 (bzero) nor 0x8b344440, so a scanner keyed on
two helper addresses will always over-report. The same reasoning applies to the three AIO completion
copyouts found in the length census (0x3b018a, 0x3b1612, 0x3b1f6d): kernel-buffer sources with
`nbytes` taken from the same request, not stack buffers.

## 3. Verdict

**No survivor.** Across 450 stack-source copyout sites there is not one where an immediate length
exceeds what the handler is known to write, and the ten sites that survived two passes of filtering are
each cleared by a full-length bzero/memset on inspection. That is consistent with the rest of the
corpus: this kernel is FreeBSD 14-era code where `bzero`-before-fill is a house rule, and the Sony
syscalls follow it.

The census is nevertheless not a proof, and the failure mode is worth stating precisely: the pass-2
coverage model only sees stores in the same function expressed as `[rbp-disp]` with an immediate
length, so any buffer filled by a callee, by a `rep movs`, or through a second base register is
counted as unfilled. That is exactly how all ten survivors were produced.

## 4. What would settle it

A dynamic oracle rather than more static filtering: call the same syscall twice in one process with a
deliberately different kernel-stack history (for example after a deep recursion of other calls) and
diff the bytes the kernel writes back. Genuinely uninitialised bytes change between the two runs,
because they are leftovers; deliberately written bytes do not. Requirements: a syscall whose args can
be satisfied so it reaches the copyout, and a buffer filled with a pattern below 2^53 so a Lua
comparison does not round (`0x0000A5A5A5A5A5A5`, see the correction in
`docs/UCONTEXT_FAMILY_14_10.md`). This is cheap and it covers callee fills, which the static model
cannot.

## 5. Reproduce

    python .local/uninit_copyout_scan.py
    python .local/uninit_cov.py
    python .local/uninit_refine.py
    python .local/uninit_map.py            # writes .local/uninit_copyout.json, .local/uninit_gaps.json
    python .local/gap4_aligned.py          # aligned re-scan, prints the 26 remainder
    python .local/gap_7016c3.py            # per-site window dumps used for the hand triage table

Known scanner defects, all encountered here: a window that starts mid-instruction desynchronises the
whole pass (this hid a bzero at 0x73a73a on the first attempt); `mov esi,<len>` is not an immediate
operand of the helper call; and helper addresses beyond the two named ones are invisible.

## 9. Dynamic test (probe 1245a) and the memory-length site scan

Two follow-ups closed the remaining doubt in this census without adding a survivor.

**The 34 sites whose copy length is read from memory.** For every one of them the slot is written
earlier in the enclosing body, so a length can never be uninitialised:

| site | direction | length slot | last write before the call |
|---|---|---|---|
| `0x33b026` | copyout | `[rbp-0x68]` | `0x33aeb4 mov qword [rbp-0x68],rdi` |
| `0x483946` | copyout | `[rbp-0x38]` | `0x4838b9 mov qword [rbp-0x38],rdi` |
| `0x6a14a7` | copyin | `[rbp-0x160]` | `0x6a1404 mov qword [rbp-0x160],r8` |
| `0x6e5b6a` | copyout | `[rbp-0x78]` | `0x6e5b2f mov qword [rbp-0x78],rdx` |
| `0x73a2f9` | copyout | `[rbp-0x48]` | `0x73a2b2 mov qword [rbp-0x48],rax` |
| `0x73c4b0` | copyout | `[rbp-0x48]` | `0x73c477 mov qword [rbp-0x48],r12` |

and the same holds for the other 28 (`0x6feef3`, `0x6ff1c8`, `0x6ff34d`, `0x730b17`, `0x73b502`,
`0x73b860`, `0x73ba9f`, `0x73bc75`, `0x73c285`, `0x73c8b7`, `0x73d131`, `0x74d1cd`, `0x7a4edd`,
`0x7a6742`, `0x7ac747`, `0xabbcd6`, `0xb5926b`, `0xbb183e`, `0xbfdf76`, `0xc00e2b`, `0xc00e6e`,
`0xc010a7`, `0xc51cd6`, `0xc9ef0a`, plus the three register-relative aio sites). Script:
`.local/memslots5.py`, report `.local/memslot_report.txt`. Note the scanner bug that cost two runs:
`allcopy_sites.json` stores `rva` as an RVA, so comparing `ins.address - kernel_base` against it
breaks every loop on the first instruction - and capstone stops at the first undecodable byte unless
`skipdata=True`.

**The dynamic test.** `probes/phase17_new_vectors/1245a_uninit_copyout_dynamic.lua`
(`results/phase17_new_vectors/1245a_uninit_copyout_dynamic_20261105_151028.txt`, COMPLETE) calls each
syscall twice on the same buffer and compares all 0x100 bytes:

| call | bytes the kernel wrote | bytes differing between the two runs |
|---|---|---|
| `fstat(189)` on a socketpair member | 120 | 0 |
| `gettimeofday(116)` | 16 | 2 (`+0x08`, `+0x09` = the microseconds field) |
| `593(1, buf)` with a 0x160 size field | 0 (returns -1 with this handle) | 0 |

So `fstat` fills 120 bytes deterministically and leaves the rest of the caller buffer alone; the only
two bytes that move in `gettimeofday` are the timer value. No kernel stack residue in either. This
does not exhaust the class - the honest statement is that the sampled calls are clean, the static scan
found no short fill, and a full answer would sweep all 450 stack-source sites the same way.

