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
(stack clash) checks out, and gains a precise statement of its guard (§5).

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

## 5. Claim 3 holds, and the guard is a lower bound

Claim 3 (`docs/VERIFIED_HANDLER_ANALYSIS.md:101-119`) says a 32-bit `lea`
overflows while a 64-bit `lea` does not, and that large counts pass the
bounds check. Both halves are correct. The guard's direction is worth
writing down exactly, because it reads like an upper bound and is not.

```asm
0x3af9f7  mov  r15, qword ptr [rbx + 0x48]   ; count
0x3af9fb  lea  eax, [r15 - 0x81]
0x3afa02  cmp  eax, 0xffffff7f
0x3afa07  ja   0x3afa33                      ; reject
```

`ja` fires when `(count - 0x81) mod 2^32 > 0xffffff7f`, which is the
wrap-around half of the space. The accepted set is `count >= 0x81`:

| count | verdict |
|---|---|
| `0x10` | rejected |
| `0x80` | rejected |
| `0x81` | accepted |
| `0x40000001` | accepted |
| `0xffffff00` | accepted |
| `0xffffffff` | accepted |

So this is a **minimum** check, not a maximum. It rejects the small values
and admits every large one.

The mismatch is then explicit in the next block:

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

With `count = 0x40000001` the allocation is `(0x40000001*4 + 0xf) & ~0xf`
truncated to 32 bits, i.e. `0x13` bytes, and the copy length is
`0x100000004`. That is the stack clash the doc describes.

One correction of detail rather than substance: the pair is not in 661's
body. The 661 body is 12 bytes (`0x3af8f0`-`0x3af8fb`) and tail-jumps to the
unsupported-syscall stub; the quoted instructions are in the shared helper
at `0x3af920`, which 662 reaches. The doc's heading says "sys 661/662"; the
code path is 662 only, because 661 is a stub on this build.

---

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

**Claim 3.** Holds (§5).

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
