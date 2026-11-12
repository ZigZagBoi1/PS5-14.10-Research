# Corrections to `docs/VERIFIED_HANDLER_ANALYSIS.md` tier-1 claims

This note re-checks the three `[CONFIRMED DEFINITIVE]` entries at the top of
[`VERIFIED_HANDLER_ANALYSIS.md`](VERIFIED_HANDLER_ANALYSIS.md) against the
committed 13.60 artifacts in `docs/dumps_13.60/` and
`results/kernel_handlers/asm/`.

Claims 1 and 2 do not survive as written, and both fail the same way: the
cited offsets are handler-relative, but they resolve into a *different*
handler than the one named.

- Claim 1 cites three addresses relative to syscall 593's entry. They land
  inside syscall 608's body, two functions later. The instruction-level
  finding is real for 608; the "three duplicate syscalls" framing is not
  (§1a).
- Claim 2 cites three offsets as three separate sites. They all resolve to
  one shared site, and of the three syscalls in the heading only 662 can
  reach it — 661 and 668 are unsupported-syscall stubs (§2-§4).

The pointer transform itself is real and instruction-verified. Claim 3
(stack clash) does not survive: its guard is an upper bound of 128 (§5).

Scope: 13.60 only. These artifacts are a fixed dump whose acquisition
authenticity is not independently established (see
`docs/dumps_13.60/README.md`). Nothing here is a 14.10 result, and nothing
here was produced by running a console.

Reproduce everything with:

```
python tools/handler_claim_audit.py           # verdict table
python tools/handler_claim_audit.py --check   # exit 1 if a corrected claim drifts
python -m unittest tools.test_handler_claim_audit
```

---

## 1. `handler_NNN.bin` are trampoline tables, not handler bodies

Every `docs/dumps_13.60/handler_NNN.bin` is exactly 4096 bytes and parses
end-to-end as a table of 8-byte entries: `E9 <rel32>` followed by
`CC CC CC`. All 145 files parse completely (512 entries each, no partial
entry, no zero word). The `sy_call_off` value in
`docs/dumps_13.60/sysent_index.json` is the RVA of one of those slots, and
the slot's `jmp` lands on the body in `kernel_text.bin`.

| syscall | `sy_call_off` | body RVA |
|---|---|---|
| 593 | `0x265588` | `0x34b7b0` |
| 622 | `0x265e98` | `0x7dcd40` |
| 661 | `0x265710` | `0x3af8f0` |
| 662 | `0x265718` | `0x3af900` |
| 663 | `0x265720` | `0x3b01f0` |
| 664 | `0x265728` | `0x3b0fb0` |
| 665 | `0x265730` | `0x3b1670` |
| 666 | `0x265738` | `0x3b1680` |
| 668 | `0x265708` | `0x3af8e0` |

Consequence: a byte offset inside `handler_NNN.bin` is an offset inside a
table, so citing one as an instruction address is wrong. This is the trap
that produced the claim-2 citation below. The doc's other offsets are
handler-relative and are fine — for example claim 1 cites a `priv_check` at
`0x7dd`, and body `0x34b7b0 + 0x7dd = 0x34bf8d`, which is exactly the
`call 0xb2bb00` that gates the TLS branch.

---

## 1a. Claim 1's cited offsets resolve into syscall 608's body

Claim 1 (`docs/VERIFIED_HANDLER_ANALYSIS.md:52-77`) is headed
"sys 593/608/660 dynlib_get_info_ex" and cites three addresses:

- `priv_check at 0x7dd` — `0x34b7b0 + 0x7dd` = `0x34bf8d`
- `priv_check at 0x895` — `0x34b7b0 + 0x895` = `0x34c045`
- `Between them (0x7f4-0x883)` — `0x34bfa4`-`0x34c033`

All three instructions exist. None of them belong to syscall 593.

Resolving every one of the 679 sysent thunks to its body and sorting the
result gives the function layout in this region:

| syscall | body start | body ends (next entry) |
|---|---|---|
| 593 | `0x34b7b0` | `0x34bc60` |
| 660 | `0x34bc60` | `0x34bdc0` |
| 608 | `0x34bdc0` | `0x34c350` |

593's body finishes with `jmp 0x34bbd0` at `0x34bc4f` and `nop` padding to
`0x34bc60`. The three cited addresses sit at `0x34bf8d`, `0x34c045` and
`0x34bfa4`-`0x34c033`, i.e. inside **608**, past two whole handler bodies.
The offsets are correct relative to 593's entry, which is what makes this
easy to miss: a linear disassembly started at `0x34b7b0` runs straight
through 660 and into 608 without any obvious seam, because the padding
between functions is `nop` rather than `int3`.

### What each of the three syscalls actually does

| syscall | body size | reads `module+0x78/0x80/0x88/0xf8/0x100` |
|---|---|---|
| 593 | `0x4b0` | no |
| 660 | `0x160` | no |
| 608 | `0x590` | yes (5 sites, `0x34bfa4`-`0x34c01e`) |

So the struct map in claim 1 — `+0x110` mapbase, `+0x118` text_size,
`+0x11c` data_base_off, `+0x148` init_proc, `+0x150` fini_proc, `+0x158`
eh_frame_hdr — is **608's** layout, verified at `0x34bfad`-`0x34c025`:

```asm
0x34bfa4  mov  rax, qword ptr [r15 + 0x78]
0x34bfad  mov  qword ptr [r14 + 0x110], rax     ; mapbase
0x34bfb4  mov  eax, dword ptr [r15 + 0x80]
0x34bfbb  mov  dword ptr [r14 + 0x118], eax     ; text_size
0x34bfc2  mov  eax, dword ptr [r15 + 0x88]
0x34bfc9  mov  dword ptr [r14 + 0x11c], eax     ; data_base_off
0x34c002  mov  rax, qword ptr [r15 + 0xf8]
0x34c009  mov  qword ptr [r14 + 0x148], rax     ; init_proc
0x34c010  mov  rax, qword ptr [r15 + 0x108]
0x34c017  mov  qword ptr [r14 + 0x150], rax     ; fini_proc
0x34c01e  mov  eax, dword ptr [r15 + 0x100]
0x34c025  mov  dword ptr [r14 + 0x158], eax     ; eh_frame_hdr
```

Between the two `priv_check` calls the stores are genuinely unconditional —
both branches of the `cmp eax, 1; jne` at `0x34bf92` converge on `0x34bfa4`
— so the substance of the claim survives for 608. What does not survive is
"THREE duplicate syscalls expose the same data".

593 has its own copy path with a **different field map**: it reads
`[r15+0x50]` and `[r15+0x60]` and writes `+0x108`, `+0x110`, `+0x114`,
`+0x118`, `+0x120`, `+0x124` — a different structure, plausibly the TLS or
old-style segment path the claim mentions. And its gate runs the other way:

```asm
0x34ba32  mov  edi, 1
0x34ba37  mov  byte ptr [r14 + 0x107], 0
0x34ba3f  call 0xb2bb00            ; priv_check(1)
0x34ba44  test eax, eax
0x34ba46  je   0x34ba74            ; check FAILED -> copy path
0x34ba48  lea  rdi, [r14 + 0x108]
0x34ba4f  mov  esi, 0x40
0x34ba54  mov  dword ptr [r14 + 0x148], 0
0x34ba5f  call 0x258ff0            ; zero the block instead
0x34ba64  jmp  0x34bb5b            ; skip the copies
```

A caller that holds the capability gets a zeroed 0x40-byte block; a caller
that does not gets the module layout. That is the same direction as 608, but
it is 593's own code at 593's own offsets, and it copies different fields.

660 is a `0x160`-byte wrapper that reads a handle, walks to
`[cred+0x10]` → `[+0x148]`, and loads a `rip`-relative string before calling
out. It contains none of the field reads and is not a duplicate of 608 at
the instruction level.

### Consequence

The "5 confirmed" dynlib/module row in the verification summary is really
one handler's evidence counted three times. The instruction-level finding
for 608 stands on its own; the claim that 593 and 660 expose the same
struct does not, and the 14.10 relevance is narrower than stated — 593 is
the syscall the 14.10 probes exercised, and it is *not* the handler this
evidence describes.

---

## 2. Claim 2's three offsets resolve to one shared site

The claim reads:

> Transform `f(x) = x ^ (x >> 4)` ... Pattern confirmed byte-identical in all
> three handlers (661:0x46f, 662:0x45f, 668:0x47f).
>
> — `docs/VERIFIED_HANDLER_ANALYSIS.md:90`

Added to each handler's own entry point, the three cited offsets land on the
same address:

| citation | entry | entry + offset |
|---|---|---|
| 661:0x46f | `0x3af8f0` | `0x3afd5f` |
| 662:0x45f | `0x3af900` | `0x3afd5f` |
| 668:0x47f | `0x3af8e0` | `0x3afd5f` |

So the observation is one instruction site, not three, and the three offsets
differ only because the three entry points differ. `0x3afd5f` is inside the
helper at `0x3af920`, which is reached from **662 only**:

* 662 body `0x3af900` ends in `jmp 0x3af920` at `0x3af912`.
* 661 body `0x3af8f0` and 668 body `0x3af8e0` both end in
  `jmp 0x265760` — the common unsupported-syscall stub — at `0x3af8f7`
  and `0x3af8e7` respectively. 665 (`0x3b1670`) does the same at
  `0x3b1677`.

661, 665 and 668 cannot reach the transform. Only 662 can, and only through
the shared batch helper.

---

## 3. The transform is real, and it occurs five times

The transform is `f(x) = x ^ (x >> 4)`, computed as
`mov dst, rax; sar dst, 4; xor dst, rax`. It appears at five sites in
`kernel_text.bin`, in two shapes:

| site | shape | containing function | direct entry edge |
|---|---|---|---|
| `0x3afd5f` | record store | `sub_3afc20` (inside `0x3af920`) | `jmp 0x3af912` from 662 |
| `0x3b072e` | record store | `sub_3b0690` | **none** |
| `0x3b1482` | record store | `sub_3b13b0` | **none** |
| `0x3b1b04` | record store | `sub_3b16a0` | `jmp 0x3b1692` from 666 |
| `0x3b52dc` | call argument | `sub_3b4a80` | `jmp 0x261790` (slot in another dispatch table) |

"Direct entry edge" is a scan of the whole text for `E8`/`E9` rel32 branches
that land on the function entry. Indirect calls are invisible to that scan,
so "none" means no direct branch, not "dead code".

### The record shape

Four sites write a 24-byte record. The clearest is the one the doc cites, at
`0x3afd43`-`0x3afd72`:

```asm
0x3afd43  mov  eax, dword ptr [rsi + r13*4]      ; status code, indexed
0x3afd47  mov  rdi, qword ptr [rbx + 0x40]       ; record buffer
0x3afd4b  lea  rcx, [r13 + r13*2]                ; index * 3
0x3afd50  mov  dword ptr [rdi + rcx*8], eax      ; +0x00  status dword
0x3afd53  mov  rax, qword ptr [r14 + 0x18]
0x3afd57  mov  rax, qword ptr [rax]              ; double dereference
0x3afd5a  mov  qword ptr [rdi + rcx*8 + 8], rax  ; +0x08  untransformed qword
0x3afd5f  mov  rax, qword ptr [r14 + 0x10]
0x3afd63  mov  rdx, rax
0x3afd66  sar  rdx, 4
0x3afd6a  xor  rdx, rax
0x3afd6d  mov  qword ptr [rdi + rcx*8 + 0x10], rdx ; +0x10  transformed qword
0x3afd72  mov  r14, qword ptr [r14 + 0x20]       ; next node
```

Two things follow that the doc does not say:

1. The record carries a **second, untransformed** qword at `+0x08`, read
   through a double dereference of `[r14 + 0x18]`. Whatever protection the
   transform is supposed to provide to `+0x10`, the adjacent field has none.
2. `f` is invertible by construction (`x = y ^ (y >> 4) ^ (y >> 8) ^ ...`,
   16 steps for a 64-bit value), so even the transformed field is a plain
   obfuscation, as the doc says — but it is one field of a record whose
   other pointer field is raw.

The site at `0x3b1b04` has the same shape with the record base in `rsi` and
is gated on a runtime predicate, `0x3b1acb`-`0x3b1ae3`:

```asm
0x3b1acb  cmp  qword ptr [rbx + 0x58], 0
0x3b1ad0  setnz byte ptr [rbx + 0x50]
0x3b1ad4  call 0xb078d0
0x3b1ad9  test eax, eax
0x3b1adb  setnz al
0x3b1ade  and  al, byte ptr [rbx + 0x50]
0x3b1ae1  cmp  al, 1
0x3b1ae3  jnz  0x3b1b17            ; skip the record write
```

`0xb078d0` reads two globals and returns true when the first is 3 or the
second is 4:

```asm
0xb078d4  mov  ecx, dword ptr [rip + 0xddcb92]
0xb078df  cmp  ecx, 3
0xb078e2  je   0xb078f2            ; return 1
0xb078e4  mov  ecx, dword ptr [rip + 0xddcb82]
0xb078ec  cmp  ecx, 4
0xb078ef  sete al
```

So the export path is state-dependent. What the record buffer at
`[rbx + 0x40]` / `[rbx + 0x58]` points at, and whether any caller makes it
user-visible, is **not established** by the dump. The record layout is a
structural observation; it is not evidence of a userland leak.

### The fifth site is not a record write

At `0x3b52dc` the transformed value is passed as an argument instead:

```asm
0x3b52c6  call 0xb078d0
0x3b52cb  test eax, eax
0x3b52cd  jz   0x3b52ef            ; skip
0x3b52cf  mov  rax, qword ptr [r12 + 0x10]
0x3b52d4  mov  edi, dword ptr [r12]
0x3b52d8  mov  rcx, qword ptr [r13]
0x3b52dc  mov  rsi, qword ptr [r13 + 8]
0x3b52e0  mov  rdx, rax
0x3b52e3  sar  rdx, 4
0x3b52e7  xor  rdx, rax
0x3b52ea  call 0xa4550
```

`0xa4550` is `int3`-filled in this dump, so the callee is unreadable here.
That is an artifact gap, not a finding.

---

## 4. Reachability, as far as direct branches go

| syscall | body | tail | reaches a transform site |
|---|---|---|---|
| 661 | `0x3af8f0` | `jmp 0x265760` | no |
| 662 | `0x3af900` | `jmp 0x3af920` | yes (`0x3afd5f`) |
| 663 | `0x3b01f0` | `jmp 0x3b0210` | no |
| 664 | `0x3b0fb0` | `jmp 0x3b0fd0` | no |
| 665 | `0x3b1670` | `jmp 0x265760` | no |
| 666 | `0x3b1680` | `jmp 0x3b16a0` | yes (`0x3b1b04`) |
| 668 | `0x3af8e0` | `jmp 0x265760` | no |

Three of the seven AIO entries are pure unsupported-syscall stubs. That
matches `results/kernel_handlers/INDEX.md:144-151`, which already describes
661 and 665 as "disabled AIO entry routed to common unsupported-syscall
handling" and 668 as an "Unsupported-operation forwarding wrapper". The
tier-1 claim contradicts the repo's own index.

---

## 5. Claim 3 does not hold: the guard is an upper bound of 128

Claim 3 (`docs/VERIFIED_HANDLER_ANALYSIS.md:101-119`) says a 32-bit `lea`
overflows while a 64-bit `lea` does not, so large counts reach a truncated
stack allocation. The width mismatch is real. The reachability is not: the
guard rejects every count above `0x80` before the allocation is reached.

```asm
0x3af9f7  mov  r15, qword ptr [rbx + 0x48]   ; count
0x3af9fb  lea  eax, [r15 - 0x81]
0x3afa02  cmp  eax, 0xffffff7f
0x3afa07  ja   0x3afa33                      ; take the WORK path
```

The branch polarity is the whole question, and the fall-through decides it.
`0x3afa33` begins the buffer setup (`mov [rbx+0x10], r14`, then the
`cmp r15d, 2` split and the `lea`/`sub rsp` pair). The fall-through at
`0x3afa09` sets `r15d = 0x16` (EINVAL), logs at line `0xea1`, and jumps to the
common exit `0x3b01aa`. So `ja` fires on the **accepted** path, and the
accepted set is the 128 values whose `count - 0x81` wraps into
`0xffffff80..0xffffffff`:

| count | `(count - 0x81) mod 2^32` | verdict |
|---|---|---|
| `0x0` | `0xffffff7f` | rejected (EINVAL) |
| `0x1` | `0xffffff80` | accepted |
| `0x10` | `0xffffff8f` | accepted |
| `0x80` | `0xffffffff` | accepted |
| `0x81` | `0x0` | rejected |
| `0x40000001` | `0x3fffff80` | rejected |
| `0xffffff00` | `0xfffffe7f` | rejected |
| `0xffffffff` | `0xffffff7e` | rejected |

So this is a **maximum** check of 128, not a minimum. The doc's "allows
counts up to ~0xFFFFFF00" is false, and the stack clash it describes is
unreachable on this build.

The width mismatch itself is still in the code:

```asm
0x3afa37  cmp  r15d, 2
0x3afa3b  jc   0x3afa75            ; counts < 2 take a fixed buffer
0x3afa3d  lea  eax, [0xf + r15*4]  ; 32-bit size
0x3afa48  lea  esi, [r15*4]        ; 32-bit size
0x3afa50  and  eax, 0xfffffff0
0x3afa53  sub  r14, rax            ; stack allocation, 32-bit size
0x3afa56  and  r14, -0x20
0x3afa5a  mov  rsp, r14
0x3afa5d  mov  rdi, rsp
0x3afa60  sub  rdi, rax            ; second stack buffer, same 32-bit size
0x3afa63  and  rdi, -0x20
0x3afa67  mov  rsp, rdi
...
0x3afa8a  mov  r13d, r15d          ; zero-extend the count
0x3afa96  lea  r12, [r13*4]        ; 64-bit copy size
...
0x3afaaa  mov  rdx, r12            ; copy length
0x3afaad  call 0x259280            ; copyin
```

At the maximum admitted count the allocation is `(0xf + 0x80*4) & ~0xf`,
i.e. `0x200`, and the copy length is `0x200`. The two widths agree over the
whole reachable domain, so the truncation cannot be triggered. It would only
matter if the guard were widened.

One attribution point stands regardless of the polarity: the pair is not in
661's body. The 661 body is 12 bytes (`0x3af8f0`-`0x3af8fb`) and tail-jumps to
the unsupported-syscall stub; the quoted instructions are in the shared helper
at `0x3af920`, which 662 reaches. The doc's heading says "sys 661/662"; the
code path is 662 only, because 661 is a stub on this build.

**Process note.** This section was first written with the polarity inverted,
because `ja` reads like a rejection test and the target label was not traced.
`tools/handler_claim_audit.py`'s `count_accepted` carried the same inversion,
and its tests were written to match the function rather than the bytes, so the
suite passed while asserting the wrong machine. The check is now named
`count-guard-is-upper-bound` and pins `0x80` accepted, `0x81` rejected and `0x0`
rejected. The lesson is in §8.

## 6. What survives

**Claim 1, reattributed.** The unconditional struct copy is real, in syscall
608's body at `0x34bdc0`:

```asm
0x34bfa4  mov  rax, qword ptr [r15 + 0x78]  ; mapbase
0x34bfad  mov  qword ptr [r14 + 0x110], rax
0x34bfb4  mov  eax, dword ptr [r15 + 0x80]  ; text_size
0x34bfbb  mov  dword ptr [r14 + 0x118], eax
0x34bfc2  mov  eax, dword ptr [r15 + 0x88]  ; data_base_off
0x34bfc9  mov  dword ptr [r14 + 0x11c], eax
0x34c002  mov  rax, qword ptr [r15 + 0xf8]  ; init_proc
0x34c009  mov  qword ptr [r14 + 0x148], rax
```

The `priv_check` at `0x34bf8d` does gate only the TLS branch: on success it
runs `memset(r12, 0, 0x100)` at `0x34bf9c` and then falls through to the
same copies, so both paths reach `0x34bfa4`.

What does not survive is the multiplication. 593 has a different field map
and its own gate (§1a); 660 has neither. The "three duplicate syscalls"
framing is a single handler's evidence counted three times.

For 14.10 the practical consequence is a narrowing, not a widening: the
repo guide's primitive table (`CLAUDE.md`, "Userland module-base discovery")
records `dynlib_get_info(593)` returning base information for 39 userland
modules on 14.10, but 593 is *not* the handler this 13.60 evidence describes.
Whatever 593 does on 14.10 was observed directly and does not inherit these
instruction-level citations. And in any case these are **userland** module
addresses: they defeat userland ASLR, not kernel ASLR.

**Claim 3.** Refuted (§5). The guard rejects every count above `0x80`.

---

## 7. Artifact and analysis quality notes

* `results/kernel_handlers/analysis/sys_593.md`, `sys_608.md`, `sys_588.md`,
  `sys_598.md` and `sys_612.md` are 248-byte thunk-only stubs. The handler
  claims for those syscalls are not backed by the committed analysis files;
  they have to be re-derived from `kernel_text.bin`.
* `results/kernel_handlers/asm/sys_593.asm` and `sys_608.asm` are 118-byte
  single-instruction thunk stubs — the two syscalls claim 1 is about are the
  two with no committed body disassembly, while `sys_660.asm` (628 KB) has
  full content. Coverage is uneven across the 145 files even though every
  syscall 532-676 has one.
* `sys_660.md`, `sys_661.md`, `sys_662.md`, `sys_664.md` and `sys_665.md`
  are "trampoline window" documents, consistent with the table structure
  above.
* The `sys_666.asm` context blocks use an older header format
  (`LINKED/ADJACENT CONTEXT ... RVA 0x...`) with no declared extent, so any
  automated consumer that expects `body [...]` ranges will silently miss
  them. `tools/handler_claim_audit.py` handles both formats.
* `0xa4550` is `int3`-filled, so at least one call target in the dumped text
  is not recoverable from this artifact.

---

## 8. Limits of this note

* Static only. No console was contacted and no 14.10 artifact exists in this
  repository.
* The dump's acquisition authenticity is unresolved; a wrong image would
  invalidate every address here. The structural arguments (trampoline
  tables, body-relative offsets, guard order) are internally consistent and
  cross-checked against `results/kernel_handlers/asm/`, which is the same
  artifact.
* "No direct entry edge" is not "unreachable". Indirect calls through
  registers or tables are not visible to a rel32 scan.
* Nothing here claims a 14.10 vulnerability, kernel read/write, or KASLR
  defeat. The corrected picture is narrower than the original claim: one
  obfuscated pointer field in a 24-byte record, written behind a runtime
  state predicate, next to an untransformed pointer field.

---

## 9. Follow-up: the obfuscated pointer never reaches userland

Claim 2 said the writer at `0x3afd5f` puts `ptr ^ (ptr >> 4)` "into the caller's output
record". The writer is real; the destination is not the caller's buffer.

The 24-byte records are allocated inside the helper, not supplied by the caller:

    0x3afaf4  JZ 0x3afb60              ; feature predicate (0xb078d0) returned 0 -> no records
    0x3afaf6  MOV R14, [RBX+0x18]      ; count
    0x3afb0e  LEA RDI, [RAX+RAX*2]     ; 3 * count * 8 = count * 0x18
    0x3afb12  CALL 0x00c08b50          ; malloc -> [RBX+0x40]

`[RBX+0x40]` is the record buffer. The writer fills it:

    0x3afd47  MOV RDI, [RBX+0x40]
    0x3afd4b  LEA RCX, [R13+R13*0x2]
    0x3afd50  MOV [RDI+RCX*8], EAX          ; +0x00 status
    0x3afd53  MOV RAX, [R14+0x18] / MOV RAX, [RAX]
    0x3afd5a  MOV [RDI+RCX*8+0x8], RAX      ; +0x08 untransformed kernel pointer
    0x3afd5f  MOV RAX, [R14+0x10]
    0x3afd66  SAR RDX, 0x4 / XOR RDX, RAX
    0x3afd6d  MOV [RDI+RCX*8+0x10], RDX     ; +0x10 obfuscated kernel pointer

and only two things ever read that buffer again:

    0x3b0141  CALL 0x000a3960          ; (td, count, records) internal AIO bookkeeping
    0x3b0150  CALL 0x00c08df0          ; free(records)

The single copyout in the function is a different buffer:

    0x3b017b  MOV R12, [RBX+0x8]       ; status array (kernel stack / per-count buffer)
    0x3b017f  MOV RSI, [RBX+0x60]      ; uap+0x10, the caller's pointer
    0x3b0183  MOV RDX, [RBX+0x58]      ; count * 4
    0x3b018a  CALL 0x002591d0          ; copyout: count * 4 bytes of status words

So userland receives `count * 4` bytes of `0x8002xxxx` status words and nothing else. There is
no disclosure, obfuscated or otherwise, and no way to make the record buffer the copyout
source: `[RBX+0x60]` comes from `uap+0x10`, and `[RBX+0x58]` is `count * 4` set at `0x3afaee`.

Two consequences:

* The AIO delete family exports no kernel addresses on any firmware. `docs/AIO_DEBUG_726_727_13_60.md`
  covers the two calls that do, and they are outside the 14.10 dispatch table.
* On 14.10 the count guard behaves as an upper bound, not a lower bound.
  `probes/phase17_new_vectors/486a_aio662_gate.lua` measured `count = 1, 4, 16, 128 -> 0` and
  `count = 129 -> -1` (`results/phase17_new_vectors/486a_aio662_gate_20261024_110855.txt`).
  The 13.60 `count >= 0x81` acceptance and the 32/64-bit `lea` mismatch behind it do not exist
  on the target.

## 10. Allocation-size and length arithmetic audit (13.60 corpus)

Axis: every handler in results/kernel_handlers/decompiled/ (145 files, sys 532-676) plus the
functions Ghidra recovered in the same 4096-byte windows, audited for five shapes: P1
allocation-size integer overflow (malloc(a*b) from uap fields, then copyin of a*b), P2
signed/unsigned length mix (int32 length used as a size / negative count past a lower-bound
check), P3 copyin length taken from a different field than the one validated, P4 user index
into a kernel array with a missing / off-by-one / signed bound check, P5 uap field used
directly as a kernel pointer or added to one.

Method: 82 variable-size allocation expressions in the corpus collapse to 25 distinct
(function, size-expression) pairs, and 132 func_0x00259280 (copyin) call sites collapse to 29
distinct length expressions; both reduced sets were read in the .c pseudocode and every
surviving candidate re-read as instruction bytes out of docs/dumps_13.60/kernel_text.bin with
capstone 5.0.7 (work/kdis.py, base 0xffffffff8a9c0000, skipdata=True). Byte quotes below are
disassembler output for the stated RVA, not transcription. No console access, no network.

### 10.1 Ranked table

| # | syscall | handler / worker RVA | pattern | pseudocode | confirming bytes | reachable on 14.10 | primitive |
|---|---|---|---|---|---|---|---|
| 1 | 599 | 0x34caa0 -> 0x34cc90 | P5 | `func_0x00259280(local_b0, param_1 + 0xcd0, 4)` where local_b0 is bytes 8..15 of the 0x20-byte buffer memset at sys_649.c:1071 (sys_649.c:1099) | 34cd43 4c8bb558ffffff mov r14,[rbp-0xa8] / 34cd76 4c89f7 mov rdi,r14 / 34cd7c e8ffc4f0ff call 0x8ac19280 | yes, no uap argument; gated only by a descriptor installed at proc-context +0xc8/+0xd0 | 4-byte kernel read from an attacker-chosen kernel VA into obj+0xcd0, plus mapped/unmapped oracle via the return code |
| 2 | (none in corpus) | 0x2d3920 | P2 + P4 | `memset(obj->[0x30] + movsxd(idx) << 5, 0x20)` | 2d3bae 4c637580 movsxd r14,[rbp-0x80] / 2d3bbb 49c1e605 shl r14,5 / 2d3bc2 call 0x8ac18ff0 | not reachable as written - no caller of 0x2d3920 anywhere in the asm corpus | signed index -> 0x20-byte kernel heap write at obj+0x30+idx*0x20, negative idx writes below the array |
| 3 | 666 | 0x3b1680 -> 0x3b16a0 -> 0x3b2080 | P1 | `malloc(count*0x28); copyin(uap_ptr, buf, count*0x28)` | guard 3b217e 418d867fffffff lea eax,[r14-0x81] / 3b2185 3d7fffffff cmp eax,0xffffff7f / 3b218a 771e ja | CLOSED - 1 <= count <= 0x80 enforced before both operations | none |
| 4 | 667 | 0x4a31a0 | P1 | `malloc((long)(int)lVar2 * 0x28)` where lVar2 = [proc+0xb48] | 4a32da MOVSXD RBX,[R15+0xb48]; 4a32fa SHL RAX,3; 4a32fe LEA RDI,[RAX+RAX*4]; 4a3318 CMP EBX,[R15+0xb48]; JGE retry | CLOSED - pid->count gate 0..0x2710, sign-extended size cannot wrap, growth recheck before fill | none |
| 5 | 657 | 0x9a9f40 (+ 0x9aa380, 0x9aa860) | P4 | PTE batch writer, slot from bitmap _DAT_03ba5ed8 | guards `param_3 <= uVar12 < param_4 && uVar10 <= param_4-uVar12`, `(uVar10 & 0xfffff800)==0`, 64KB alignment | CLOSED - range and batch-size guards | none |
| 6 | 673 | 0x9ab1f0 (+ 0x9ab370) | P4 | two-range attribute walk, 3-slot local array | CMP RDX,R12; JC / CMP RCX,R12; JC / TEST R14W,R15W; index counters CMP ESI,0x1; JG and CMP R13D,0x2 | CLOSED - both ranges re-validated against the map entry, slot counters bounded | none |
| 7 | 674 | 0xabb980 | P1 + P3 | `copyout(&rec, out_ptr, min(0x48, uap[8]))` | abbaf5 488b95f8feffff mov rdx,[rbp-0x108] / abbaff e8ccd679ff call 0x8ac191d0 | CLOSED - length clamped to 0x48 before every copyout; record pointer arithmetic only advances the user pointer | none |
| 8 | 649, 656, 659, 660, 672 | 0x34b910 (blob consumer) | P2 + P3 | `memset(&local_f8,0xa8); copyin(desc, &local_100, 8); if (local_100 < 0xa9) copyin(desc, &local_f8, local_100)` | 0xa8 memset at sys_649.c:1360, gate at :1368 | CLOSED - length field capped below 0xa9 against a 0xa8 buffer, exact fit | none |
| 9 | 532 | 0xaf1730 | P1 | `lVar3 = malloc(param_4); memcpy(lVar3, param_2, param_3)` | guard `param_4 == 0 || param_2 == 0 || param_4 <= param_3 - 1` -> error (sys_532_deep.c:403) | CLOSED - destination is never smaller than the copied length | none |
| 10 | 618 | 0xabd0f0 | P4 | `*(byte *)(lVar6 + 0x9d) < 9` dispatch through 0x18dbf68 | table bounds 0..8 | CLOSED - table-index class (already recorded in section 5) | none |

### 10.2 F1 (open, highest value): syscall 599 hands an attacker-chosen kernel address to copyin

The 599 dispatch target is 0x34caa0 (results/kernel_handlers/asm/sys_599.asm:4, thunk 0x2655d8
JMP 0x0034caa0). Its body takes the syscall context only - RSI is never read, so the call has
no user argument block - locks and unlocks the object behind [ctx+8], and then, only when the
mode check at 0x8b4e7250 returns 0, calls the worker:

    34cb40  4585ff              test r15d, r15d
    34cb43  756f                jne  0x34cbb4          ; mode check failed -> return r15d
    34cb45  498b7e08            mov  rdi, [r14 + 8]   ; worker arg
    34cb49  e842010000          call 0x34cc90

Inside the worker (RVA 0x34cc90) the descriptor is fetched by sub_34c8c0 into a 0x60-byte
local at [rbp-0x90], and a 0x20-byte local blob at [rbp-0xb0] is zeroed first:

    34ccc3  488dbd50ffffff      lea  rdi, [rbp - 0xb0]
    34ccca  e821c3f0ff          call 0x8ac18ff0        ; memset(blob, 0x20)
    34cccf  488db570ffffff      lea  rsi, [rbp - 0x90]
    34ccd9  e8e2fbffff          call 0x8ad0c8c0        ; sub_34c8c0(ctx, &desc)

The descriptor is accepted as well-formed when size >= 0x50, flags >= 3 and desc+0x48 != 0;
that test is the three-way OR at 0x34cd1c-0x34cd41, and the jne polarity puts the *malformed*
case on the early-return path (blob+8 is still zero there, so it returns 0 and does nothing):

    34cd1c  83bd7cffffff03      cmp  dword ptr [rbp - 0x84], 3     ; desc+0x0c flags
    34cd2a  4883bd70ffffff50    cmp  qword ptr [rbp - 0x90], 0x50  ; desc+0x00 size
    34cd41  7546                jne  0x34cd89                     ; all three good -> blob path

The well-formed path reads 8 bytes of a user blob, rejects any length above 0x20, copies at
most 0x20 bytes over the same 0x20-byte stack blob (so the copy itself is an exact fit, not an
overflow), and falls into the pointer read:

    34cd89  65488b3c2500000000  mov  rdi, gs:[0]
    34cda0  488d75d0            lea  rsi, [rbp - 0x30]
    34cda4  ba08000000          mov  edx, 8
    34cda9  4c89f7              mov  rdi, r14                ; desc+0x48, user pointer
    34cdac  e8cfc4f0ff          call 0x8ac19280              ; copyin -> length
    34cddf  4c8b75d0            mov  r14, [rbp - 0x30]       ; blob[0..8]
    34cde3  4983fe21            cmp  r14, 0x21
    34cde7  7222                jb   0x34ce0b               ; <= 0x20 -> copy blob
    34cdf9  ...                 call 0x8ac1d410              ; else log + 0x16
    34ce26  488db550ffffff      lea  rsi, [rbp - 0xb0]       ; dst = blob
    34ce2d  4c89ff              mov  rdi, r15                 ; desc+0x48
    34ce30  4c89f2              mov  rdx, r14                 ; len <= 0x20
    34ce33  e848c4f0ff          call 0x8ac19280              ; copyin user blob
    34ce43  e9fbfeffff          jmp  0x34cd43               ; re-enter pointer read

and then:

    34cd43  4c8bb558ffffff      mov  r14, [rbp - 0xa8]       ; blob bytes 8..15, user data
    34cd4a  4d85f6              test r14, r14
    34cd4d  0f8484000000        je   0x34cdd7               ; zero -> return 0
    34cd65  4881c3d00c0000      add  rbx, 0xcd0
    34cd71  ba04000000          mov  edx, 4
    34cd76  4c89f7              mov  rdi, r14                 ; <== attacker u64 as a kernel VA
    34cd79  4889de              mov  rsi, rbx                 ; dest = obj+0xcd0
    34cd7c  e8ffc4f0ff          call 0x8ac19280              ; copyin(kaddr, obj+0xcd0, 4)
    34cd81  4189c6              mov  r14d, eax
    34cd84  e972ffffff          jmp  0x34ccfb               ; stack cookie check, return eax

Ghidra's own pseudocode for the same worker is worth reading next to the bytes, because it is
why the defect reads as harmless at source level (results/kernel_handlers/decompiled/sys_649.c:
1054-1100, and byte-identical copies at sys_656.c:1050, sys_659.c:1075, sys_660.c:1093,
sys_672.c:1056):

    int sub_34cc90(long param_1)
      undefined1 local_b8 [8]; long local_b0; ulong local_98; uint local_8c;
      *(undefined4 *)(param_1 + 0xcd0) = 0;
      func_0x00258ff0(local_b8, 0x20);                     // :1071 memset of 0x20 bytes
      iVar3 = sub_34c8c0(param_1, &local_98);
      if (local_50 != 0 && (0x4f < local_98 && 2 < local_8c)) {     // ptr, size >= 0x50, flags >= 3
        iVar3 = func_0x00259280(lVar2, &local_38, 8);               // :1080 length
        if (0x20 < local_38) { ... iVar3 = 0x16; }                  // :1085 <= 0x20
        iVar3 = func_0x00259280(local_50, local_b8, local_38);      // :1091 blob copy
      }
      if (local_b0 == 0) { iVar3 = 0; }                             // :1094
      else { iVar3 = func_0x00259280(local_b0, param_1 + 0xcd0, 4); } // :1099  <== kernel VA

Ghidra sized the buffer from the declaration (local_b8 [8]) instead of from the memset that
initialises it (0x20), so local_b0 became a separate, apparently uninitialised local. It is in
fact bytes 8..15 of the same 0x20-byte object that the second copyin overwrites with user data.
At the instruction level the identity is unambiguous: the memset at 0x34ccca uses lea
rdi,[rbp-0xb0], the blob copy at 0x34ce26 uses lea rsi,[rbp-0xb0], and the pointer read at
0x34cd43 reads [rbp-0xa8].

blob bytes 8..15 are never validated, are not compared against any kernel address range, and
are used verbatim as the *source* of a kernel-to-kernel copy. The destination is a fixed field
of the object the caller passed in ([arg+8], +0xcd0); the syscall returns the copyin status, so
a caller gets a one-bit answer per call: 0 = the address is mapped and readable, EFAULT-style
nonzero = not readable. The 4 bytes read are parked in obj+0xcd0; no reader of +0xcd0 exists
anywhere in the corpus (the field is only zeroed and written, at sys_649.c:1070/1099,
sys_656.c:1060/1089, sys_659.c:1085/1114, sys_660.c:1103/1132, sys_672.c:1066/1095), so the
content is not disclosed by this call alone. The primitive as it stands is an arbitrary kernel
address oracle - the standard way to defeat KASLR from a syscall that takes no arguments - with
a stored 4-byte salvage that any future reader of +0xcd0 would expose.

What the audit could not show: which call installs the descriptor at the descriptor slot
(+0xc8 user pointer, +0xd0 length, ORBI magic, size >= 0x50, flags >= 3, +0x48 -> 0x20-byte
blob). sub_34c8c0 reads it but nothing in the 13.60 corpus writes it, so the installer is
outside the decompiled set. Until that installer is identified on 14.10 the finding is a real
missing-validation defect with an unproven entry path, which is why the probe below is written
as a differential (mapped vs unmapped source address) rather than as an address leak.

### 10.3 F2 (unproven reachability): signed index heap write in sub_2d3920

0x2d3920 (the 675 window) walks a list, caps the count at 0xfff, allocates count*0x20:

    2d3acf  4181fcff0f0000      cmp  r12d, 0xfff
    2d3ad6  0f8431030000        je   0x2d3e0d           ; bail out at the cap
    2d3aef  4489e7              mov  edi, r12d
    2d3af7  48894dc8            mov  [rbp - 0x38], rcx
    2d3afb  48c1e705            shl  rdi, 5
    2d3aff  e84c509300          call 0x8b5c8b50        ; malloc(count << 5)

so the allocation itself cannot overflow (count <= 0xfff). The fill, however, does not use that
buffer - it writes into an array owned by another object, indexed by a sign-extended 32-bit
local, with no compare against the array size:

    2d3b90  8b4650              mov  eax, [rsi + 0x50]
    2d3bae  4c637580            movsxd r14, dword ptr [rbp - 0x80]   ; 32-bit index, sign-extended
    2d3bb2  488b7830            mov  rdi, [rax + 0x30]               ; array base
    2d3bb6  be20000000          mov  esi, 0x20
    2d3bbb  49c1e605            shl  r14, 5
    2d3bbf  4c01f7              add  rdi, r14
    2d3bc2  e82954f8ff          call 0x8ac18ff0        ; memset(base + idx*0x20, 0x20)
    2d3beb  4a89443110          mov  [rcx + r14 + 0x10], rax           ; second store, same index

A negative [rbp-0x80] gives a large negative byte offset, i.e. a 0x20-byte write below the
array. Status: no caller. 0x2d3920 is never called anywhere in the asm corpus (the only hit is
its own definition at sys_675.asm:4284), and its map-walk helper 0x2cedc0 is called only from
0x2d3a0f inside the same function, so nothing in this corpus can enter it. Listed as a
candidate that becomes live if a 14.10 dispatch table entry points at 0x2d3920.

### 10.4 Closed: the AIO submit chain behind syscall 666

0x3b1680 is a 10-line wrapper (mov rax,[rsi]; mov edx,[rsi+8]; mov rcx,[rsi+0x10]; mov
rsi,rax; jmp 0x3b16a0) into 0x3b16a0 and then 0x3b2080. Both the count check and the
allocation/copyin pair live there, and both bounds exist:

    3b217a  4c8b7310            mov  r14, [rbx + 0x10]      ; count from uap
    3b217e  418d867fffffff      lea  eax, [r14 - 0x81]
    3b2185  3d7fffffff          cmp  eax, 0xffffff7f
    3b218a  771e                ja   0x3b21aa               ; accept iff 1 <= count <= 0x80
    3b21d9  428d04f500000000    lea  eax, [r14*8]
    3b21ed  448d2c80            lea  r13d, [rax + rax*4]     ; count * 0x28 in 32 bits
    3b21f1  4c89ef              mov  rdi, r13
    3b21f4  e857698500          call 0x8b5c8b50             ; malloc(count * 0x28)
    3b2219  4c89ea              mov  rdx, r13                 ; same length
    3b221c  e85f70eaff          call 0x8ac19280              ; copyin

The 32-bit lea cannot wrap once count <= 0x80, and the copyin length is literally the
allocation size. The same guard covers the count*0x58 and count*8 allocations at sys_658.c:2241
and :2256. Closed.

### 10.5 Closed: syscall 667 (0x4a31a0)

The allocation size comes from a signed 32-bit thread count and is sign-extended before the
multiply, so a negative count produces a very large size that fails allocation rather than a
small one that overflows later:

    4a32da  MOVSXD RBX, dword ptr [R15 + 0xb48]
    4a32fa  SHL    RAX, 0x3
    4a32fe  LEA    RDI, [RAX + RAX*0x4]        ; count * 0x28

The pid argument is range-checked 0..0x2710 via CALL 0x782a40 then LEA EDX,[RCX-0x2711] / CMP
EDX,0xffffd8f0 / JC at 0x4a31e7, the count is re-read after the allocation and any growth frees
and retries (CMP EBX,[R15+0xb48]; JGE 0x4a3357 at 0x4a3318), and the copyout length is clamped
by local_50. Closed.

### 10.6 Closed: 657 (0x9a9f40) and 673 (0x9ab1f0)

657 takes a single 0x20-byte argument block (sys_657.c:158), requires flags == 0 and count >=
0, and dispatches on local_60[0]-1U < 5. The batch writer sub_9aa380 takes its slot index from
a 64-bit bitmap (_DAT_03ba5ed8, trailing-zero index <= 63), builds the buffer address as lVar5 +
(iVar4 << 0xd), and before each record enforces param_3 <= uVar12 < param_4 together with uVar10
<= param_4 - uVar12, which is the wrap-free form of range+length, plus 64KB alignment
((uVar12 & 0xffff) == 0) and a batch cap ((uVar10 & 0xfffff800) == 0, i.e. < 0x800 dwords =
0x2000 bytes); sub_9aa860 repeats the same guards with an extra (*(byte *)(param_5+0x18) &
0xcc) == 0 condition. 673's two ranges are re-validated against the map entry (CMP RDX,R12; JC
and CMP RCX,R12; JC), 64KB alignment is tested with TEST R14W/R15W, and the 3-slot local array
in 0x9ab370 is indexed by counters bounded with CMP ESI,0x1; JG and CMP R13D,0x2. Closed.

### 10.7 Closed: 674 (0xabb980)

uap layout: [0] out pointer, [8] out size, [0x10] max records, [0x20] == 0x40000000 magic.
Entry addresses are bounded by MOV RAX,0x80000000000 / DEC / CMP [RBX+0x20],RAX / JA, and every
copyout uses the clamped size:

    abbaf5  488b95f8feffff    mov  rdx, [rbp - 0x108]      ; min(0x48, uap[8])
    abbafc  4c89fe            mov  rsi, r15
    abbaff  e8ccd679ff        call 0x8ac191d0             ; copyout(record, cur, len)

The record cursor then advances by the raw uap[8] (ADD R15,[RBP-0x110]), which overlaps or
skips regions of the *caller's* buffer only. No kernel write is influenced by the unclamped
value. Closed.

**Correction, 2026-11-10: uap[8] is a record STRIDE, not an out size.**  The listing makes the
three roles disjoint, and only the first is clamped:

    abba3f  MOV RBX,[RBX+0x8]          ; map entry list
    abba46  CMP R12,0x48               ; R12 = uap[8]
    abba65  CMOVC RAX,R12              ; [rbp-0x108] = min(uap[8], 0x48) -> copy width
    abba53  MOV [RBP-0x110],R12        ; [rbp-0x110] = uap[8] raw        -> stride
    abbacb  CMP R13,[RBP-0xf0]         ; [rbp-0xf0] = uap[0x10] max records
    abbaff  CALL 0x002591d0            ; copyout(&rec, cursor, min(uap[8],0x48))
    abbb08  ADD R15,[RBP-0x110]        ; cursor += uap[8] raw

So one call touches `min(entries, uap[0x10])` records, each copied at `cursor + i*uap[8]` with a
width of `min(uap[8], 0x48)`, and **nothing relates that span to any buffer length** -- there is
no length argument at all.  Consequences the earlier note missed:

* a stride below `0x48` makes the records overlap, so a caller choosing stride 8 gets one
  eight-byte record field per slot, and stride `0x1000` scatters 72-byte records a page apart;
* the count is bounded only by the number of map entries and `uap[0x10]`, so a caller that
  declares more records than its buffer holds takes a linear overrun into whatever follows.

Measured: `results/phase36_realargs/1563a_sys674_record_bound_20261110_194414.txt` (grade M) --
316 records x 72 bytes = `0x58E0` written at a caller-chosen base; limits 8/1/0 truncate to
`0x240`/`0x48`/nothing; a limit of 4000 changes nothing because the map caps it.  The overrun is
real enough to kill the loader: `results/phase36_realargs/1564a_sys548_map_fixed_boundary_20261110_194737.txt`
(grade V) died at `[0] pid=312` because its record buffer was `memory.alloc(0x4000)` for a
400-record limit.  The conclusion above still holds -- `copyout` cannot reach kernel memory (the
`0x800000000000` check in `0x8ac191d0`) and cannot write a page without the write bit
(`1565a`: pointing the buffer at eboot's prot-5 `executable` segment returns `rv=-1` with 0 of 16
dwords changed) -- so this is a caller-side overrun, not a kernel write primitive.  A follow-up
probe should still print `errno` in that last case, which it did not.

### 10.8 Closed: the shared descriptor-blob consumer (649 / 656 / 659 / 660 / 672)

This is the correct sibling of F1 and the contrast is worth recording. Same sub_34c8c0
descriptor source, then a 0xa8-byte buffer is zeroed and the length field is checked before the
variable-length copy:

    sys_649.c:1360  func_0x00258ff0(&local_f8, 0xa8);
    sys_649.c:1367  uVar4 = func_0x00259280(lVar1, &local_100, 8);
    sys_649.c:1368  if ((uVar4 == 0) && (uVar4 = 0x16, local_100 < 0xa9))
    sys_649.c:1370      uVar4 = func_0x00259280(local_128, &local_f8, local_100);

local_100 <= 0xa8 against a 0xa8 memset, so the copy is an exact fit. The blob fields at +0x70
and +0x88 are then passed to sub_34b910 (RVA 0x34b910), which is a 4-byte copyin whose source
is the field itself (0x34b934 MOV EDX,0x4 / MOV RDI,R14 / JMP 0x00259280) - a user pointer
validated by copyin, not a kernel pointer. Closed.

### 10.9 Residual risk and what is not covered

* 0x2d3920 (section 10.3) is the only unguarded write shape found; it is unreachable from this
  corpus, so it needs a dispatch-table comparison against 14.10 to be promoted or dropped.
* The F1 installer for the descriptor slot is missing from the corpus. Everything else about
  599 is confirmed at instruction level.
* Files whose analysis/*.md and asm/*.asm are thunk-only stubs (593, 608, 588, 598, 612) carry
  no body to audit, and 0xa4550 is int3-filled, so its callees cannot be recovered here.
* Handlers with no variable-size allocation and no user-influenced copyin length were screened
  out by the two censuses (25 allocation pairs, 29 copyin length expressions); their absence
  from this section is a census result, not an omission.
