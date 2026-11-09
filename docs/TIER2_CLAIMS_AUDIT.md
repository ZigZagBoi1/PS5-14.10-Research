# TIER 2 handler claims 9-15: audit against the 13.60 dump

Status: **static audit of `docs/VERIFIED_HANDLER_ANALYSIS.md` TIER 2.** Every
address is an RVA into `docs/dumps_13.60/kernel_text.bin`, resolved from
`docs/dumps_13.60/sysent_index.json` (slot RVA -> E9 rel32 -> body RVA). No
console was contacted. No 14.10 artifact exists in this repository, so nothing
here is a 14.10 claim.

TIER 1 claims 1-3 were corrected in [HANDLER_CLAIM_CORRECTIONS.md](HANDLER_CLAIM_CORRECTIONS.md)
and are re-checked by `tools/handler_claim_audit.py`. This note covers claims
9-15 and is re-checked by `tools/tier2_claim_audit.py` (`--check` exits 1 on
drift).

## Verdict table

| claim | subject | verdict | decisive evidence |
|---|---|---|---|
| 9 | sys 612/649 `get_obj_member` | **PARTIAL** | 649 is the 8-entry field switch; 612 is a different handler and has no switch |
| 10 | sys 675 global reset | **CONFIRMED** | 40-byte body, three stores, no call, no branch |
| 11 | sys 598 info leak | **PARTIAL** | two 8-byte copyouts from `+0xc8`/`+0xd0` confirmed; "zero priv_check" is unverifiable here, and the claim omits the assert gate |
| 12 | sys 670 second handler at `+0x480` | **PARTIAL** | a function starts there, but no sysent entry resolves to it and 670 does not call it |
| 13 | sys 664/665/666 non-atomic refcount | **PARTIAL** | `dec` without `lock` exists only in 666; 665 is a 16-byte wrapper |
| 14 | sys 565/566 PTE writes | **CONFIRMED** | mask, both index bounds, both offsets, both credential gates |
| 15 | sys 548 TOCTOU | **PARTIAL** | 0x20-byte per-entry `copyin` in the loop confirmed; two sub-claims not checked |

## Body resolution

| syscall | slot | body | next body start |
|---|---|---|---|
| 548 | `0x265d60` | `0xabbe60` | `0xabc510` (559) |
| 565 | `0x265dd8` | `0x6034e0` | `0x603710` (566) |
| 566 | `0x265de0` | `0x603710` | `0x6039d0` (567) |
| 598 | `0x2655d0` | `0x34c990` | `0x34caa0` (599) |
| 612 | `0x2655e0` | `0x34ce50` | `0x34cfa0` (649) |
| 649 | `0x2655e8` | `0x34cfa0` | `0x37ec40` (454) |
| 664 | `0x265728` | `0x3b0fb0` | `0x3b1670` (665) |
| 665 | `0x265730` | `0x3b1670` | `0x3b1680` (666) |
| 666 | `0x265738` | `0x3b1680` | `0x3b2060` (669) |
| 670 | `0x265748` | `0x3b28d0` | `0x3ce150` (586) |
| 675 | `0x265458` | `0x2d36f0` | `0x312ed0` (362) |

The last column is the next *sysent body start*, not the function's end. For
649, 670 and 675 the gap is large, so those three extents are upper bounds
only; each section below uses the function's own `ret`/padding instead.

## Claim 9 — sys 612/649 `get_obj_member` [PARTIAL]

**The claim:** "Jump table returns mapbase (0x78), init_proc (0xf8), fini_proc
(0x108) with ZERO priv_check calls in entire handler file. TLS fields (0xe8,
0xf0) gated by flag 0x10 at module+0x11d."

**649 confirms it.** Body `0x34cfa0`:

```
0x34cfca  mov r12,[rax+0x3e8]          ; module list head (or NULL)
0x34cfdb  cmp qword [rax+0x148],0      ; NULL -> assert path
0x34cfe5  lea r14,[r12+0x70]           ; list lock
0x34d000  mov r12,[r12]                ; walk
0x34d00c  cmp [r12+0x28],rax           ; match handle
0x34d013  movzx eax, byte [rbx+8]      ; member type
0x34d017  dec eax; cmp eax,7; ja       ; types 1-8
0x34d01e  lea rcx,[rip+0x117328b]      ; relative table at 0x14c02b0
0x34d02c  jmp rax                      ; 8 cases
```

The eight cases select a module field offset that is then loaded by the shared
`mov rax,[r12+rax]` at `0x34d0c6` and copied out 8 bytes at `0x34d0fc`. The
offsets are `0x78`, `0xe8`, `0xf0`, `0xf8`, `0x108`, `0x168`. The two TLS cases
test `byte [r12+0x11d] & 0x10` first (`0x34d02e`, `0x34d0a6`) and return 0 when
the bit is clear, exactly as claimed.

**612 does not.** Body `0x34ce50` has no switch (`jmp rax` does not appear),
copies in a single qword from arg0, requires it to equal `0x10`
(`0x34cead` `cmp qword [rbp-0x38],0x10`), then builds a 0x10-byte record and
copies it out. Whatever 612 is, this artifact does not make it a member query.
That is consistent with the console evidence: probe 54k returned -1 for member
values 0-8 on 612, while 649 returned addresses for types 1-4, 7, 8.

**Also note:** the switch's relative table at `0x14c02b0` is *outside*
`kernel_text.bin` (15,132,096 bytes = `0xe6e5c0`), so the table's entries are
not in this dump. The case addresses above come from the disassembly, not from
reading the table.

## Claim 10 — sys 675 global reset [CONFIRMED]

**The claim:** "40-byte function. Three global writes, zero calls, zero checks:
`*(int*)(RIP+0x17c2bf0) = 1; *(int64_t*)(RIP+0x2a8dfd8) = -1;
*(int64_t*)(RIP+0x2a8c918) = 0`."

Body `0x2d36f0`, 40 bytes (`0x28`), ending at `ret` `0x2d3717`:

```
0x2d36f0  push rbp; mov rbp,rsp
0x2d36f4  mov dword [rip+0x17c2be2], 1        -> 0x1a962e0
0x2d36fe  mov qword [rip+0x2a8dfbf], -1       -> 0x2d616c8
0x2d3709  mov qword [rip+0x2a8c8f4], 0        -> 0x2d60008
0x2d3714  xor eax,eax; pop rbp; ret
```

Zero calls, zero branches, three writes of exactly the claimed values. The
claim's three constants do not reproduce the resolved targets if read as
instruction-start-relative displacements; the encodings are `0x17c2be2`,
`0x2a8dfbf` and `0x2a8c8f4`. Cite the resolved addresses, not those constants.

## Claim 11 — sys 598 info leak [PARTIAL]

**The claim:** "Two 8-byte values from dynlib_context+0xc8/+0xd0 returned
without privilege check. Zero priv_check calls in entire handler file."

Body `0x34c990`:

```
0x34c9ab  mov rax,[rdi+8]              ; proc
0x34c9af  mov rax,[rax+0x3e8]          ; context pointer
0x34c9b9  je 0x34ca57                  ; NULL -> assert + panic
0x34c9bf  mov rcx,[rax+0x10]
0x34c9c3  cmp qword [rcx+0x148],0
0x34c9cb  je 0x34ca57                  ; zero -> assert + panic
0x34c9d1  mov rcx,[rax+0xc8]
0x34c9ec  mov rax,[rax+0xd0]
0x34ca11  call 0x2591d0                ; copyout 8 bytes to [rsi]
0x34ca44  call 0x2591d0                ; copyout 8 bytes to [rsi+8]
```

The two copies are confirmed, in that order, 8 bytes each, to the two user
pointers taken from the uap. The complete call set of the body is
`{0x2591d0 copyout, 0xc1a3e0 copyin-log, 0xb22a30 assert, 0x6fd6b0 stack_chk}`.

Two corrections:

1. **"Zero priv_check calls" cannot be positively established here.** The
   artifact does not name `priv_check`'s RVA, so the honest statement is "the
   body's call list is complete and contains no credential check", not "priv_check
   was searched for and not found".
2. **The claim omits a gate that matters.** Both NULL conditions jump to
   `0x34ca57`, which loads a file/function/format triple and calls `0xb22a30`
   with `esi = 0x717`. That is the kernel assert shape: a process whose
   `proc+0x3e8` context or `[ctx+0x10]+0x148` is NULL reaches an assertion,
   not an errno return. A reachability probe should treat that as a panic path,
   not a failure path.

## Claim 12 — sys 670 cross-process events [PARTIAL]

**The claim:** "Second handler at offset 0x480: PID-based process lookup →
direct access to target_proc->0xc48 event table. Only validation: slot_index <=
target_proc->event_max."

A function does start at `0x3b28d0 + 0x480 = 0x3b2d50`
(`55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 38`). Three facts do not
support calling it "the second handler of sys 670":

- No entry in `sysent_index.json` resolves to `0x3b2d50`.
- Its only direct entry edge anywhere in the text is the trampoline at
  `0x265750` (`e9 fb d5 14 00 cc cc cc`), a slot that no syscall number in the
  index maps to. (671's slot is `0x265f90`, not `0x265750`.)
- 670's own body, from `0x3b28d0` to `0x3b2d50`, contains no call to it.

So the function is real and reachable from a trampoline, but "second handler at
offset 0x480 of sys 670" is a claim about the dispatch path that this artifact
does not show. The `+0xc48` / `event_max` details were not checked; they are
unresolved, not refuted.

## Claim 13 — sys 664/665/666 non-atomic refcount [PARTIAL]

**The claim:** "`decl (%rax)` WITHOUT LOCK prefix at multiple offsets. Zero
lock-prefixed instructions in entire file."

| syscall | body | size | `dec` on memory | `lock`-prefixed |
|---|---|---|---|---|
| 664 | `0x3b0fb0` | 0x6c0 | none | 0 |
| 665 | `0x3b1670` | 0x10 | none | 0 |
| 666 | `0x3b1680` | 0x9e0 | 4 (`0x3b1d30`, `0x3b1d43`, `0x3b1e99`, `0x3b1f2e`) | 0 |

Two of 666's four sites are `dec dword [rax]`; the other two are
`dec dword [r8+r14*4+0x160]`. The zero-`lock` half of the claim holds for all
three bodies. The "at multiple offsets" half holds only for 666, and 665 is not
a handler body at all:

```
0x3b1670  push rbp; mov rbp,rsp; xor esi,esi; pop rbp
0x3b1677  jmp 0x265760                 ; the unsupported-syscall stub
```

## Claim 14 — sys 565/566 PTE writes [CONFIRMED]

**The claim:** "Both handle indices 0-5 (not split ranges as originally
claimed). Write to different module offsets: 0x160+i*8 (sys 565) vs 0x190+i*8
(sys 566) — low/high PTE halves. Value mask 0xfffffff0007b0000, ucred gate
confirmed."

565 (`0x6034e0`):

```
0x6034f6  movabs rcx, 0xfffffff0007b0000
0x603506  cmp r12, 6; setae al          ; reject index >= 6
0x60350d  test r13, rcx; setne cl       ; value must fit the mask
0x603608  mov [rbx+r12*8+0x160], r13
```

566 (`0x603710`):

```
0x603728  lea eax,[r13-6]; cmp eax,-7; jb   ; accept 0..5
0x6037db  cmp r13d,-1; je 0x603925          ; -1 is its own path
0x6037e5  mov [r15+r13*8+0x190], r12
```

Both bounds are simulated, not read off the mnemonic. 565's `setae` rejects
`index >= 6`. 566's unsigned compare rejects `(index - 6) < 0xfffffff9`, which
is exactly `index >= 6` *except* that `0xffffffff` is admitted; that value is
then handled by the `cmp r13d,-1` branch, which writes the single-field
`[rax+0x190]` instead of an indexed slot. Both bodies call `0x26d0a8` with
`[rdi+0x140]` (`0x60355f`, `0x60374e`) before the write, which is consistent
with a credential gate.

## Claim 15 — sys 548 TOCTOU [PARTIAL]

**The claim:** "Per-entry 0x20-byte copyin in processing loop. Userland array
can be modified between iterations. Type 2 operation chaining uses previous
result. Sandbox flag derivation confirmed."

Body `0xabbe60`:

```
0xabbf5b  add r14, 0x20                 ; next user entry
0xabbf5f  cmp r13, r15; je 0xabc257     ; loop end
0xabbf7e  add r12, r14                  ; user base + entry offset
0xabbf86  mov edx, 0x20
0xabbf95  call 0x259280                 ; copyin 0x20 bytes, per iteration
```

The 0x20-byte per-entry copyin inside the loop is confirmed, and the loop
re-reads from user memory each iteration, so the TOCTOU precondition is
structurally present. The other two sub-claims — type-2 operation chaining and
sandbox flag derivation — were not checked here and remain **unresolved**.

## What this audit does not establish

- **13.60 only.** The dump's acquisition authenticity is unresolved and no
  verified 14.10 image exists in this repository. A 13.60 body does not
  establish what the same syscall number does on 14.10.
- **No exploitability claim.** Every verdict above is about whether the claim's
  cited instructions exist and mean what it says, not about whether the
  behaviour can be triggered from the loader.
- **Absence of a named check is not proof of absence of a check.** Where a
  claim asserts "zero priv_check calls", this audit reports the complete call
  list instead, because the artifact does not name that function's RVA.
- **Function extents are approximate** except where a `ret` plus padding is
  cited. The dump records no symbol or extent table.
- **No console evidence is used or produced.** Console-side results cited above
  (probe 54k's member query, probe 55e) are quoted only to show agreement with
  the static reading, not as proof of it.
