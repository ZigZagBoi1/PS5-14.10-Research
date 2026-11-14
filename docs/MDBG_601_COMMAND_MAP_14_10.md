> **Closed as a kernel-R/W route, 2026-11-04 (tenth boot).** 1195a measured all 0x28 command slots with `arg3 = 0x28`; no command writes 0x28 bytes to `arg2`, none writes `arg3`, and the attach body `0x8b6612d5` / dispatcher `0x8b662320` have zero direct callers in the whole image, so those cases are not in 14.10's table. The map below remains accurate as a *behavioural* description. See [SYS601_SECOND_STAGE_14_10](SYS601_SECOND_STAGE_14_10.md) section 9.

# 601 (mdbg_service) command map on 14.10, measured

> **Correction, 2026-11-04 (seventh boot).** Two claims in this document are wrong or unsupported, see
> [SYS601_SECOND_STAGE_14_10.md](SYS601_SECOND_STAGE_14_10.md):
> 1. **"-1" here is errno-blind.** The loader's syscall path is the libkernel wrapper
>    (`gettimeofday+7`), which returns **-1 for every error**; the errno only exists in libc errno
>    (`get_error_string()`). Every -1 in the tables below conflates EPERM(1), EINVAL(22) and
>    ENOSYS(78). The handler itself can only return 0, 1, 4, 0x16, 0x1c, 0x23, 0x3f or 0x4e.
> 2. **The type gate at `0xca2320` is not behind attach-only state.** It is behind bit 8 of
>    `td+0x528`, and 601 contains the setter itself (`0xca131f: or qword [td+0x528], 0x100`) in a case
>    body that reads `td_proc` from the *calling thread* — no kernel pointer is needed, contrary to
>    the conclusion below. Types 3 and 7 then reach the main body, which is a whole blob-ingest
>    interface with a per-process 0x80000 kernel buffer.
>
> Also measured since: `601(0x00, mapped buffer, non-zero arg3)` **wedges the loader** (1192a).
> `601(0x00, buf, 0)` stays safe (1170a).

All calls are `601(cmd, buf, len, 0, 0, 0)` with a 0xA5A5A5A5-filled buffer unless stated. "writes"
means bytes in the buffer that differ from the sentinel.

## Commands 0x00-0x2F

| cmd | rv | writes | notes |
|---|---|---|---|
| 0x00 | 0 | 8 B | always `{0x00000100, 0x00000000}`, independent of buffer, length and flags |
| 0x01 | -1 | none | |
| 0x02 | -1 | none | |
| 0x03 | — | — | **panic**: body takes a raw `struct proc*` (SMAP #PF) |
| 0x04 | — | — | **panic**, same reason |
| 0x05 | -1 | none | |
| 0x06 | -1 | none | |
| 0x07 | 0 | none | |
| 0x08 | — | — | **parks forever** in the kernel (1170a) |
| 0x09 | 0 | none | |
| 0x0A | -1 | none | |
| 0x0B | 0 | none | |
| 0x0C | — | — | **parks forever** (1172a, and 1175a parked it on a thread) |
| 0x0D | 0 | none | |
| 0x0E | 0 | 8 B | always `{0, 0}`, independent of length/flags |
| 0x0F | -1 | none | |
| 0x10 | -1 | none | |
| 0x11 | -1 | none | |
| 0x12 | -1 | none | |
| 0x13 | 0 | none | |
| 0x14 | 0 | none | |
| 0x15 | -1 | none | |
| 0x16 | -1 | none | |
| 0x17 | -1 | none | |
| 0x18 | -1 | none | |
| 0x19 | 0 | none | |
| 0x1A | 0 | 4 B | always `{0}` |
| 0x1B | — | — | **kills the process** (no crash blob, LOADER-DEAD) |
| 0x1C | -1 | none | |
| 0x1D | 0 | none | |
| 0x1E | -1 | none | |
| 0x1F | -1 | none | |
| 0x20 | 0 | none | |
| 0x21-0x26 | -1 | none | |
| 0x27 | — | — | **kills the process** (1171a) |
| 0x28-0x2F | -1 | none | |

No command in this range ever wrote ASCII, and the word `mDBG` has still never appeared in any capture
(`grep -r mDBG results/` = 0 hits, one session of sweeps later).

## The argument shape is settled (1179a)

* arg1 is the buffer and arg2 is the length. Swapping them (`0x200, buf`) or putting the buffer in
  arg3 returns -1 for every command that otherwise returns 0.
* arg3, arg4, arg5 do not change any observed answer (`1` in either slot, and 0x200 vs 0x4000 length).
* The three writing commands write the same two/four bytes regardless of length, so they are
  out-parameters of a fixed size, not a stream.

## What this does and does not say about the log drain

`docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 describes a body that memcpy's the kernel log list into a
0x4000 bounce buffer and `uiomove`s it to the caller, with no credential check. Nothing in 0x00-0x2F
behaves that way, and 0x0E's constant `{0,0}` is the closest shape (a "bytes read" counter that is
always zero).

The reconciliation is the type gate at `0xca2320`, called from the shared entry at `0xca1833`: with
`(*(u64*)(td+0x528) & 0x100) == 0` only types 3, 4, 5 and 7 are dispatched, and that bit is set by the
**attach** command, which needs a kernel `struct proc*`. So the drain is most likely gated behind the
same state bit as everything else useful in 601, and the -1 answers in the table above are that gate.

## Method notes, so this is repeatable

* One command per thread (`probes/phase17_new_vectors/1176b_mdbg_threaded_sweep.lua`,
  `1177a_mdbg_sweep_high.lua`) absorbs the parkers: see `docs/SACRIFICIAL_THREAD_14_10.md`.
* The heavy buffer work must stay on the main thread; a child that did 2048 native memory ops killed
  the process with no crash blob (1176a).
* Sentinel comparisons must be hex (`0xA5A5A5A5` = 2779096485). Two probes compared against a decimal I
  derived by hand and printed `changed=1024` on an untouched buffer.

## Commands 0x30-0xFF: all of them answer -1 and write nothing (1180a, 1181a)

`1180a` swept 0x30-0x4F (32 commands, 2.8 s) and `1181a` swept 0x50-0xFF (176 commands); every single one
returned `-1` with an untouched buffer, no park, no kill, no panic. Together with the table above the
whole 8-bit command space is now measured:

| class | commands |
|---|---|
| writes a fixed out-param and returns 0 | 0x00 {0x100,0}, 0x0E {0,0}, 0x1A {0} |
| returns 0, writes nothing | 0x07 0x09 0x0B 0x0D 0x13 0x14 0x19 0x1D 0x20 |
| returns -1 | everything else, 0x21-0x26, 0x28-0x2F, 0x30-0xFF |
| parks forever | 0x08, 0x0C |
| kills the process | 0x1B, 0x27 |
| panics the console | 0x03, 0x04 |

## Conclusion: 601 is closed as an unprivileged kernel-read source

Nothing in 601's command space copies kernel text or a kernel pointer into a user buffer as uid 1.
The log drain in `docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 is real code, but it is not reachable from
this credential with any of the seven argument shapes tried in `1179a`, and the most likely reason is the
type gate at `0xca2320`: with `(*(u64*)(td+0x528) & 0x100) == 0` only types 3, 4, 5 and 7 dispatch, and
that bit is set by the attach command, which requires a kernel `struct proc*`. 601 therefore inherits
the same shape as the rest of the corpus: a real primitive that needs a leak to unlock a leak.

## Update 2026-11-09: the entry command is an attach call with a flags word, not a buffer

`1383a` re-ran commands `0x00`-`0x0B` over four argument shapes with errno resolved
(`results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt`). The table above
stands, with two corrections and one structural finding.

**Corrections.** `0x02`, `0x05` and `0x06` are **ENOSYS(78)** on 14.10, not EPERM - those slots are
the nosys trampoline, so the 13.60 bodies for them (0x05 was a 0xb8-byte proc read) are not in the
14.10 table. `0x0A` is **EPERM(1)**, i.e. a real body behind the credential predicate.

**`0x0C` does not kill, it parks.** The connection stays open with zero bytes returned and no fault
dump; the process is alive but the calling thread never returns. That is the same behaviour as
`0x08` and it is what `1175a` used to park a throwaway thread.

**`0x01` is the attach command, and `arg2` is a flags word, not a pointer.** In the 13.60 body at
`0xca067f` (shared with `0x24`; the only difference is `r13 = 1` vs `2`, set from `cmp eax,0x24`):

```
ca067f  xor r13d,r13d / cmp eax,0x24 / setne [rbp-0x118] / inc r13d   ; r13 = 1 (0x01) or 2 (0x24)
ca06ad  mov edx,0x10 / mov rsi,[rbp-0xf0 ref] / mov rdi,r15           ; arg1 = source
ca06b5  call 0x259280                                                 ; copyin 16 bytes -> EFAULT if null
ca07xx  mov rcx,[rbp-0xf0] / mov rdx,[rbp-0xe8]                       ; the struct's two qwords
        mov r8,r12 / shr r8,8 / bextr eax,r12d,0x206 / test r12b,0x20 ; arg2 = flags
ca1a16  call 0xc9c9f0(r13, arg2>>8, bits 6-7 of arg2)
ca19c3  call 0xc9cf30(r13, arg2&1, bits 1-2, bits 3-5, arg2>>8, &[rbp-0x110])
ca1ae5  or QWORD [process+0x560],0x10000000                           ; the success tail
```

So the measured `EINVAL(22)` for `601(0x01, page, page)` is the helper refusing `0xA5A5...` as a
flags word (`bit 5` set selects `0xc9cf30`, bits 6-7 select the class), not a refusal of the
16-byte struct, and the null cases are the copyin failing first. `0x01` therefore has a
measurable predicate worth sweeping: a zeroed struct with `arg2` over small flag values. If it
returns 0 it sets `process+0x560` bit 28 and installs the object at `process+0x568`, which is the
precondition for every remaining 601 site that answers with real data (`ca0a9a` dword of
`[[process+0x568]+0xe8]`, `ca197b` five qwords from `obj+0x60..+0x80`, `ca1b8b` 0x480 bytes from
`obj+0x578` followed by `kfree`). `probes/phase35_dead_end_reruns/1384a_sys601_cmd01_payload.lua`
sweeps that flags word.

**What this does not change.** No `0x00`-`0x2F` command has ever written a kernel pointer to a user
buffer, the second stage is still gated by bit 8 of `td+0x528` and credential bit 62, and the log
drain remains unreachable. The finding is a measurable predicate on the one attach-shaped command,
not a primitive.

## Update 2026-11-09 (second pass): 0x0D-0x1A with errno, and 0x11 is lethal on arg2

`1383b` (`results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt`) ran
commands `0x0D`-`0x1A` over four argument shapes with errno resolved. The probe died inside
`0x11`, so `0x11`-`0x1A` beyond the first two shapes are still unmeasured.

| cmd | 0/0 | arg1 = buffer | arg2 = buffer |
|---|---|---|---|
| 0x0D | 0 | 0 | 0 |
| 0x0E | `-1` EFAULT(14) | **0, writes 2 zero dwords** | `-1` EFAULT(14) |
| 0x0F | `-1` EPERM(1) | `-1` EPERM(1) | `-1` EPERM(1) |
| 0x10 | `-1` EINVAL(22) | `-1` EINVAL(22) | `-1` EINVAL(22) |
| 0x11 | `-1` EFAULT(14) | `-1` EINVAL(22) | **kills the process** |

Two things follow. First, `0x0E` takes its output buffer in **arg1**, not arg2 - the 0/0 shape is
EFAULT and the arg2 shape is EFAULT too, so the earlier "0x0E writes `{0,0}` independent of the
argument shape" line was measured with the buffer in arg1 already. Second, the error codes
separate "wrong slot" from "gate refused": `0x10` answers EINVAL for every shape, i.e. it rejects
the arguments before any gate, while `0x0F` answers EPERM for every shape, i.e. it is gated.

`0x11` with a mapped pointer in arg2 **kills the process** (the capture stops on the `0x11 a1` line
and 9026 answered CONNECTION_REFUSED 2 s later). With arg2 null it is EFAULT and with arg1 non-null
it is EINVAL, so `0x11`'s body does something to the arg2 pointer that faults in kernel mode. That
is a crash, not a leak, and it is now on the skip list: `{0x03, 0x04, 0x08, 0x0C, 0x1B, 0x27}` plus
`0x11` for the arg2 shape.

## Correction 2026-11-10: cmd 0x01's arg3 is a LENGTH, and the "EINVAL for all shapes" row is a slot error

Every attach probe in the corpus put a **flags word** in arg3. `1384a`'s helper is

```lua
local function trial(label, cmd, sptr, flags)
    return mk(601)(uint64(cmd), uint64(sptr), uint64(flags), uint64(0), uint64(0), uint64(0))
end
```

so its 32-value flag sweep varied `arg3` over `{0, 1, 2, 0x20, 0xC0, ...}` and its 24 struct
shapes varied the two qwords at `arg2`. The 13.60 body says the case at
`0xffffffff8b6611ce` reads arg3 as a **count of qwords** and validates it with an unsigned
range test:

```asm
0x8b6611ce  mov   r13,[r8+8]          ; proc
0x8b6611d2  lea   rdi,[rbp-0xf0]      ; 0x78-byte stack buffer
0x8b6611d9  mov   esi,0x78
0x8b6611e5  call  0xffffffff8ac18ff0  ; bzero(local, 0x78)
0x8b6611ea  lea   rax,[r12-0x10]      ; r12 = uap[2] = arg3
0x8b6611f5  cmp   rax,-0xe
0x8b6611f9  jb    0xffffffff8b662215  ; unsigned: keep only arg3 in [2, 15]
0x8b661221  mov   rdi,r15             ; r15 = uap[1] = arg2
0x8b661227  shl   r12,3               ; arg3 * 8
0x8b661228  call  0xffffffff8ac19280  ; copyin(arg2, local, arg3*8)
0x8b661237  mov   rbx,[rbp-0xf0]      ; local[0]
0x8b66123e  mov   r15,[rbp-0xe8]      ; local[1]
0x8b661245  cmp   rbx,1
0x8b66124d  cmp   rcx,2               ; rcx = local[1] - 3
0x8b66125c  jne   0xffffffff8b661b11  ; EINVAL
```

`cmp rax,-0xe / jb` on `rax = arg3 - 0x10` keeps `arg3 - 0x10` in `[-14, -1]`, i.e. exactly
`arg3` in `[2, 15]` — the 0x78-byte buffer divided by 8. So:

- **arg2** is the struct, **arg3** is its length in qwords, bounded 2..15;
- the struct must begin `{1, local[1] in {3,4}}`, and a length of 2 copies exactly those two;

`1384a` could never satisfy both: lengths 0 and 1 are below the bound, `0x20` and `0xC0` are
above it, and its zeroed struct fails `local[0] == 1` anyway. The uniform `EINVAL(22)` it
recorded was **the length gate at `0x8b6611f9`**, not a credential gate. The same applies to
the "0x01 EINVAL for all shapes" line in the second-pass table above.

The case that follows it in code order, `0x8b6612d5`, is the attach body the corpus already
documents (`0x8b65afc0` context creator, `or qword [td+0x528],0x100`, `[ctx+0x94] = [td+0x9c]`,
return 0 or 4), so a well-formed `{1,3}` with `arg3 = 2` is the first call in the corpus that
can reach it. `1538a` measures that shape, with four controls that must stay EINVAL (length 1,
length 16, struct `{2,3}`, struct `{1,5}`).

Whether `0x8b6611ce` belongs to command `0x01` is **not proven**: the dispatch table at
`0x8e031160` is outside every dump, and the case bodies do not appear in index order. `1538a`
therefore also re-asks `0x11` and `0x1B`, and treats a change in their answers as the evidence
that a context now exists.

### 601's copy geometry, audited end to end (2026-11-10)

The body `0xffffffff8b660630`..`0xffffffff8b6623fc` (1732 instructions in `.local/ktext_ins.pkl`)
contains **twelve** `copyin` calls (`0xffffffff8ac19280`, convention `(rdi = user source,
rsi = kernel destination, rdx = length)` as recorded in `docs/ARG1_CLASSES_14_10.md:308`).
Eleven of them pass a constant length, and the twelfth is the only variable one in the family:

| site | length | kernel destination (`rsi`) | user source (`rdi`) |
|---|---|---|---|
| `0x8b6606b5` | `0x10` | `[rbp-0xf0]` | `r15` |
| `0x8b660e12` | `0x20` | `[rbp-0xf0]` | `r12` |
| `0x8b660f93` | `0x18` | `[rbp-0xf0]` | `r12` |
| `0x8b660ff9` | `0x480` | `r14` = the `malloc(0x480)` at `0x8b660fc8` | `r15` |
| `0x8b66106d` | `0x18` | `[rbp-0xf0]` | `r12` |
| `0x8b661104` | `0x48` | `[rbp-0xf0]` | `r15` |
| `0x8b661227` | `r12 = arg3 * 8` | `[rbp-0xf0]`, a `0x78`-byte buffer | `r15` |
| `0x8b6614f5` | `0x20` | `[rbp-0xf0]` | `r12` |
| `0x8b6616e9` | `0x18` | `[rbp-0x110]` | `r15` |
| `0x8b661733` | `0x40` | `[rbp-0xf0]` | `rbx` = `struct[+0x10]` of the `0x18`-byte struct just copied |
| `0x8b6617ac` | `0x480` | `r15` = the `malloc(0x480)` at `0x8b661762` | `rbx` = the same `struct[+0x10]` |
| `0x8b662377` | `0x3c` | `[rbp-0x74]` (the blob-ingest 60-byte struct) | `r15` |

The two `0x480` copies are the largest, and both write into a buffer allocated with exactly
`0x480` bytes immediately beforehand — `0x8b660fbe mov edi,0x480` / `0x8b660fc8 call 0x8b5c8b50`
for the first, and `0x8b661755`/`0x8b661762` for the second — so they are exact-fit, not
over-copies. Neither `malloc` result is NULL-checked before the copy, which would turn an OOM
into a kernel store at address 0; that is not attacker-inducible to a chosen address and is
recorded only so the next reader does not re-find it. The variable one is bounded by the arithmetic itself: `0x8b6611ea lea rax,[r12-0x10]`
with `0x8b6611f5 cmp rax,0 - 0xe` and `0x8b6611f9 jb` keeps only `arg3` in `[2,15]`, and
`0x8b661211 shl r12,3` turns that into at most `120` bytes into a `0x78`-byte buffer.

Consequence: **601 has no length-arithmetic bug.** Every copy either has a constant length into a
slot sized for it, or a length derived from a value that a preceding range check has already
clamped to the destination's capacity. Any bug in this family has to be in what the copied
structures *mean*, not in how much is copied.

One detail worth keeping because it is easy to invert: the same body also calls
`0xffffffff8ac190b0`, which is a plain `bcopy` with no user-address validation and no `stac`
(`0x8ac190e5 rep movsq`), and `0xffffffff8ac191d0`, which is `copyout` with the user pointer in
`rsi` (`0x8ac1922a xchg rdi,rsi` after validating `rsi+rdx` at `0x8ac191f3`/`0x8ac19202`). Only
`0x8ac19280` validates `rdi+rdx` and takes the user pointer first.

## Correction, 2026-11-10: `0x8b65afc0` is a get-or-create, and every caller therefore creates the context

`docs/SYS601_SECOND_STAGE_14_10.md:135` labels the call at `ca12e0` "proc reference", and the
attach case reads `r13 = [r14+0x568]` two instructions after it. That labelling has since been
used to argue that the helper only takes a reference and that a `NULL` slot therefore means no
context exists. The helper's own body says otherwise:

```
8b65b102  lea  rdi,[rip - 0xa303b9]     ; a function pointer stored in the new object
8b65b109  mov  dword [r15+0x100], 1     ; state = 1
8b65b114  mov  dword [r15+0x138], 0
8b65b11f  mov  qword [r15+0x140], r8
8b65b126  mov  qword [r15+0x148], r14   ; r14 = proc
8b65b12d  mov  dword [r15+0x118], 0
8b65b138  mov  qword [r15+0x120], rdi
8b65b142  mov  qword [r15+0x128], r14
8b65b14e  mov  qword [r14+0x568], r15   ; <-- installs the context in the process
```

`r15` is the fresh `malloc(0x1f0)` result, so `0x8b65b14e` publishes it. **`0x8b65afc0` is a
get-or-create**: it locks `proc+0x148`, returns the existing `[proc+0x568]` if there is one, and
otherwise builds an object, initialises `+0x100 = 1`, `+0x120`/`+0x140` function pointers,
`+0x128`/`+0x148` = `proc`, and stores it.

Two consequences, both of which the earlier note inverted:

- Every 601 case that calls this helper **creates the context if it is missing**. The `ENOMEM(12)`
  branch in the 0x23 body (`0x8b661cd6`/`0x8b661cdd`) is the *creation-failed* path, not evidence
  that 0x23 requires a pre-existing context. `1538b`'s `0x23 arg3=3 → rv=0` is therefore consistent
  with 0x23 doing the creating itself.
- The teardown path sets `[proc+0x568] = 0` and writes `7` into `[ctx+0x100]`
  (`0x8b6635e9`/`0x8b6635f3`/`0x8b66364a`), so `+0x100` is a lifecycle state (1 = live, 7 = torn
  down), not a flag.

The all-eight-callers list stands: `0x8b65af05`, `0x8b6607c3`, `0x8b660f48`, `0x8b661122`,
`0x8b6612e3`, `0x8b661caa`, `0x8b66255b`, `0x8b6626c0` — all inside the 601 body.

### The channel object at `ctx+0xf0` has exactly one installer and one consumer

```
8b66114e  mov  rbx,[rax+0xf0]        ; already installed?
8b661161  test rbx,rbx
8b661164  jne  0x8b661de7            ; yes -> skip straight to the name classifier
8b66117b  call malloc(0xd8)
8b66119e  cmp  qword [rax+0xf0], 0   ; re-check under the lock
8b6611a6  je   0x8b661dd2
8b661dd2  mov  [rax+0xf0], rbx       ; publish
8b6611c9  ... free(rbx)              ; the losing allocation is freed, not leaked
```

The installer is the case at `0x8b6610db`, and the only other reader is the 0x1B family at
`0x8b662013` (`rax = [[proc+0x568]+0xf0]`, `test rax,rax`, `je return 3`). Nothing else in the
kernel reads `ctx+0xf0`, so the caller-supplied qwords that 0x1B writes sit in an object that only
601 itself looks at, and only as a non-NULL test. **Reaching 0x1B would give a kernel-heap write
of chosen bytes at fixed offsets inside a `0xd8` object whose own address is not knowable; it
would not give an addressed write.** That is why the 0x1B family is only worth a run if the
object's contents turn out to be interpreted somewhere the text does not show.

#### The classifier, the nine names, and where each code writes

The installer case and the "0x1B family" are **the same case**. `0x8b662013` is the tail of the
body that begins at `0x8b6610db`; the name classifier sits between them, so the object is allocated
first and the dispatch follows in the same call:

```
ca10f5  lea  rsi,[rbp-0xf0] / mov edx,0x48 / mov rdi,r15
ca1104  call 0x8ac19280           ; copyin(arg2, local, 0x48)   arg2 = a caller struct
ca1114  mov  byte [rbp-0xa9],0    ; local+0x47 = 0, so the name at local+0x28 is NUL-terminated
ca1122  call 0x8b65afc0           ; get-or-create the mdbg context
ca1de7  nine strncmp(local+0x28, <literal>, <len>)   -> ebx = 1..9, or 0 when none match
ca1ffb  dec  ebx / cmp ebx,8 / ja -> EINVAL(22)      ; the no-match path
ca2013  rax  = [[proc+0x568]+0xf0] / r14d = 3 when the ctx or the object is NULL
ca203d  dec  ebx / cmp ebx,8 / ja 0x8b66223e (EINVAL); dispatch table at 0xffffffff8e031210
ca2200  xor  r14d,r14d            ; rv = 0 on every dispatched path
```

The nine literals, read byte-exact out of `docs/dumps_13.60/kernel_data.bin` (data base
`0xffffffff8b9c0000`):

| VA | literal | len | code |
|---|---|---|---|
| `0x8bd1965f` | `Sce.PSM:AppName` | `0x10` | 1 |
| `0x8bd42c26` | `Sce.PSM:SdbInfo` | `0x10` | 2 |
| `0x8bce51a9` | `Sce.PSM:LogArea` | `0x10` | 3 |
| `0x8bcc5161` | `Sce.Debug:UserObjArray` | `0x17` | 4 |
| `0x8bc9c08b` | `Sce.Debug:Gnm` | `0x0e` | 5 |
| `0x8bd241af` | `Sce.Debug:Gn2` | `0x0e` | 6 |
| `0x8bce51b9` | `Sce.Debug:Gn3` | `0x0e` | 7 |
| `0x8bc86e96` | `Sce.Debug:Gn4` | `0x0e` | 8 |
| `0x8bd38646` | `Sce.Debug:KPNoverride` | `0x16` | 9 |

Every dispatched path sets a flag byte and stores qwords of the caller struct (`struct+0x08`,
`+0x10`, `+0x18`, `+0x20`) into the `0xd8` object. All nine bodies, in address order:

| body | flag | object offsets written |
|---|---|---|
| `0x8b662058` | `[+0xd4] |= 0x02` | `+0x00`, `+0x08`, `+0x10`, `+0x18` |
| `0x8b66208f` | `[+0xd4] |= 0x20` | `+0x60`, `+0x68` |
| `0x8b6620b1` | `[+0xd4] |= 0x08` | `+0x30`, `+0x38`, `+0x40`, `+0x48` |
| `0x8b6620e9` | `[+0xd4] |= 0x10` | `+0x50`, `+0x58` |
| `0x8b66210b` | `[+0xd5] |= 0x01` | `+0xb0`, `+0xb8`, `+0xc0`, `+0xc8` |
| `0x8b66214f` | `[+0xd4] |= 0x04` | `+0x20`, `+0x28` |
| `0x8b662171` | `[+0xd4] |= 0x40` | `+0x70`, `+0x78`, `+0x80`, `+0x88` |
| `0x8b6621ac` | `[+0xd4] |= 0x80` | `+0x90`, `+0x98`, `+0xa0`, `+0xa8` |
| `0x8b6621ed` | `[+0xd5] |= 0x02` | dword at `+0xd0` |

Every offset is inside `0xd8`, and no body dereferences a caller value: the dispatch is nine stores
and one flag OR. That matters for probing, because it means `601(0x1B, struct, 9)` cannot fault on
the qwords regardless of what they contain — the only caller-controlled address in the whole case
is `arg2` itself, which `copyin` validates.

The consequence for the corpus is a correction, not a new primitive. The `0x1B` LOADER-DEAD row
came from `1355a`, whose capture ends at `calling 0x1B ...` after a failed attach; and `1195a`
swept every slot with `arg2` = a mapped page filled with `0xA5`, which fills the name field with
`A5`s, so it could only ever reach the EINVAL path. Both are consistent with a kill *somewhere* in
the family, but neither isolates it, and the listing above offers no fault. `1541a` measures the
matching-name and non-matching-name answers directly, which is the only way to learn whether the
14.10 body matches the 13.60 one.

#### The `td+0x578` upload/download pair, and why it is not a probe target

`td+0x578` holds a pointer to a kernel-allocated buffer that a later command copies out and frees.
The pair is legible in the listing:

```
; upload
8b660fc3  mov  edx,0x102
8b660fc8  call 0x8b5c8b50            ; malloc(0x480)
8b660fee  mov  edx,0x480
8b660ff3  mov  rdi,[rbp-0xe8]        ; user source  (copyin: rdi = user, rsi = kernel)
8b660ff9  call 0x8ac19280            ; copyin(arg2, buffer, 0x480)
8b661000  je   0x8b661d36            ; success
8b661010  call 0x8b5c8df0            ; failure -> free the buffer and return
8b661d84  mov  [r13+0x578],r14       ; <-- the buffer is registered on the thread
8b661d8b  mov  qword [r13+0x580],0
8b661d96  mov  qword [r13+0x588],0
8b661da1  mov  qword [r13+0x590],0

; download
8b661b2c  r12 = [td+0x578] ; r15 = [td+0x580]
          and  [td+0x528], ~0x400
8b661b..  mov  edx,0x480 / mov rdi,r12 / mov rsi,[rbp-0xe8]
          call 0x8ac191d0            ; copyout(dst = user, src = r12, 0x480)
          call 0x8b5c8df0            ; free(r12)
          mov  qword [td+0x578],0
```

`copyout`'s argument order was re-derived from its own prologue and confirmed — `0x8ac191f0 mov rax,rsi / add rax,rdx / 0x8ac19202 cmp rax,0x800000000000`, `0x8ac19227 and rsi,0x7fffffffffff`, `0x8ac1922a xchg rdi,rsi`, `stac`/`rep movsq`/`clac`, EFAULT `mov rax,0xe` at `0x8ac19259` — so **the user pointer is `rsi` and the kernel source is `rdi`**. The download therefore reads *from* the registered pointer and copies *to* the caller's destination, then frees the registered pointer. With the upload above it is a sane pair: the kernel owns the buffer, the caller owns only the bytes.

**What breaks the pair is a second registrant.** Two other cases copyin a `0x20` struct and store all four of its qwords straight into the thread:

```
8b660e03  lea  rsi,[rbp-0xf0] / mov edx,0x20 / mov rdi,r12
8b660e12  call 0x8ac19280            ; copyin(arg2, local, 0x20)
8b660e44  test eax,0x400             ; already registered? -> shared tail at 0x8b661573
8b660e4f  or   rax,0x1000000
8b660e55  mov  [r8+0x528],rax
8b660e5c  mov  rax,[rbp-0xf0] / 8b660e63  mov [r8+0x578],rax
8b660e6a  mov  rax,[rbp-0xe8] / 8b660e71  mov [r8+0x580],rax
```
and the same shape at `0x8b66152e`..`0x8b66156c`, which additionally writes `+0x588` and `+0x590`. `r8 = r13 = td`, so these are the same field. **A caller-supplied qword becomes the download's kernel source and free target.**

That is an arbitrary 0x480-byte kernel read with a `free()` of the same address afterwards, and `0x8b5c8df0` is a zone deallocator rather than a checked free: `call 0x8b29e330` / `call 0x8afd5a70` / `movzx r12d,[rax+0x6b]` / `page-align the pointer` / `call 0x8b29e330` / `call 0x8b549290` / `mov rdi,[rax+8]` / `test byte [rdi+0x4a],0x20`. It resolves the pointer's owning page and dereferences zone metadata, so a pointer that is not a kmalloc object corrupts kernel memory or panics inside the syscall — before the caller can read the copyout buffer it just filled.

Recorded so it is not re-derived, and so nobody spends a run on it: **the download could be identified safely** (with `td+0x578` still zero it answers EFAULT and the `test rdi,rdi / je` skips the free), **but it can never be used safely** — the read and the free are one call, and the free is not protected by the onfault handler that makes the copy survive an unmapped source.

#### 1541a: 0x1B kills with a well-formed struct, so the 13.60 body does not run

`results/phase36_realargs/1541a_sys601_cmd1b_name_gate_20261110_161109.txt` (pid 214, capture ends
inside the first call, 9026 then `CONNECTION_REFUSED`):

```
[A] a name that matches none of the nine, called FIRST so that a death here isolates the
    preamble (copyin + ctx create + malloc) rather than the nine-way store
  bogus name                   601(0x1B, buf, 9) ...
```

Every input to that call was controlled and valid: `S` was a mapped 0x100-byte buffer zeroed at
4-byte granularity, `copyin`'s 0x48 bytes contained four sentinel qwords and a name of twenty `Z`
characters, and `arg3` was 9 — inside the `[2,15]` bound of the only length-shaped body in the
function. Nothing in the 13.60 listing can fault on that shape: a non-matching name reaches
`ca203d dec ebx / cmp ebx,8 / ja ca223e` and returns EINVAL(22) without touching the object.

So 0x1B is lethal on 14.10 for a reason the 13.60 body does not predict, and this is the third
independent shape to die there (`1195a` arg3=0x28 with an `0xA5`-filled page, `1355a` arg3=0x100,
`1541a` arg3=9 with a real name field). The remaining argument 1541a did not vary is `arg3`; if the
14.10 body treats it as a pointer - the shape `573`'s cases use, dereferencing the caller pointer
with no `copyin` - then a small integer is a bad address and the fault is immediate and identical in
all three captures. `1542a` sends a mapped page there and repeats the name gate, with `arg3 = 0` as
a NULL-dereference confirmatory rung placed last.

Until that runs, the status of 0x1B is **kills on every shape tried**, and the `ctx+0xf0` write
family is unreachable from a game process. The table above stays as the description of what the
13.60 code would do, not as something that has been measured on 14.10.

#### Closure, 2026-11-10: 0x1B is an unconditional killer, and 601 is finished

Two more shapes were measured after 1541a, both killing the connection's process at the same point:

| probe | call | arg3 | result |
|---|---|---|---|
| `1542a` | `601(0x1B, struct, page)` | mapped 0x1000 page | capture ends after the call line |
| `1543a` | `601(0x1B, struct, 0)` | `0` | capture ends after the call line |

Captures: `results/phase36_realargs/1542a_sys601_cmd1b_arg3_pointer_20261110_161943.txt`,
`results/phase36_realargs/1543a_sys601_cmd1b_arg3_zero_20261110_162129.txt`. Together with `1355a`
(arg3=0x100), `1176b`/`1177a` (arg3=0x1000), and `1541a` (arg3=9), every argument shape presented to
command 0x1B on 14.10 has died: five distinct `arg3` values including zero, `arg2` always a mapped
buffer, `arg1` always 0x1B.

The 13.60 body cannot fault on any of them. Its preamble is `copyin(arg2, stack, 0x48)` from a mapped
buffer, a byte store into that buffer, the get-or-create, and a `malloc(0xd8)`; the classifier only
reads the copied name; and a non-matching name returns EINVAL(22) at `ca203d..ca223e` without
touching the object. So the fault is not in the path the listing describes, and no argument value a
game process can supply avoids it.

**0x1B therefore joins `0x03`/`0x04` as an unconditional killer on 14.10.** The `ctx+0xf0` write
family stays unreachable, which is the outcome the command map already predicted (the LOADER-DEAD
row) and 1176b/1177a first measured. 601 is closed as a primitive source: every non-lethal command
either ignores its arguments (`0x00`, `0x0E`, `0x1A`) or is gated by a capability the game process
does not hold, and the two commands that would give a controlled kernel write die before reaching it.

One correction filed alongside this: `1404a`'s line `idx=0x1B rv=-1 errno=22` is **not** command 0x1B.
That probe sweeps an index in **arg2** with `arg1` fixed at `0x12`
(`probes/phase36_realargs/1404a_sys601_cmd12_index.lua:89`: `sc601(uint64(0x12), uint64(i), uint64(OUT), ...)`),
so the line names an index value. It must never be cited as evidence that 0x1B is safe. Ledger rows
`1542a`, `1543a` and `1404a-note` carry both facts.

## Closure, 2026-11-10 (second): the forwarder is a debugger stop, and the download is unreachable

Two bodies in the 601 region were still unexplained after the 0x1B closure. Both resolve, and both
resolve to *unreachable*, so this file's conclusion does not change: 601 is not a primitive source.

### The download path at `0x8b661032` needs a registration bit that no reachable command sets

The only case that reaches the 0x480-byte copyout is entered at `0x8b661032`:

```
8b661032  mov  r14d, 0x16                    ; EINVAL
8b661038  test r15, r15
8b66103b  jne  0x8b66221c                    ; arg3 must be zero
8b66105e  lea  rsi, [rbp - 0xf0]
8b661065  mov  edx, 0x18
8b66106a  mov  rdi, r12                      ; r12 = arg2
8b66106d  call 0x8ac19280                    ; copyin(arg2, local, 0x18)
8b661080  cmp  qword [rbp - 0xe8], 0         ; struct + 0x08 = user destination
8b661088  je   0x8b661b21                    ; NULL -> r14d = 0xe (EFAULT)
8b6610a1  call 0x8ae86a00                    ; mtx_lock(td + 0x148)
8b6610a6  mov  rax, [r15 + 0x528]
8b6610b0  test eax, 0x400
8b6610b5  jne  0x8b661b2c                    ; registered -> download
8b6610bb  (unlock)
8b6610cd  mov  r14d, 2                       ; not registered -> rv = 2
```

and the download itself:

```
8b661b2c  and  rax, ~0x400
8b661b32  mov  r12, [r13 + 0x578]            ; source pointer
8b661b46  mov  [r13 + 0x528], rax
8b661b51  call 0x8ae86fa0                    ; unlock before the copy
8b661b59  test r12, r12 ; je 0x8b661f1c
8b661b80  mov  edx, 0x480
8b661b85  mov  rdi, r12                      ; kernel source
8b661b88  mov  rsi, r14                      ; user destination
8b661b8b  call 0x8ac191d0                    ; copyout
8b661b9d  call 0x8b5c8df0                    ; free the source
8b661ba2  mov  qword [r13 + 0x578], 0
```

So a registered `td+0x578` yields a 0x480-byte kernel read *and* a free of that pointer. That is
exactly the shape worth chasing, and it is closed by measurement rather than by argument: **the
"not registered" answer is `rv = 2`, and no command in `1538b`'s `0x00`-`0x26` sweep returned 2**
(`results/phase36_realargs/1538b_sys601_length_owner_sweep_20261110_154233.txt`: the value set is
`0`, `-1 EPERM`, `-1 EINVAL`, `-1 ENOSYS`, `-1 EFAULT`). The case is either absent from the 14.10
dispatch table or sits on one of the six commands that were skipped as lethal (`0x03`, `0x04`,
`0x08`, `0x0C`, `0x1B`, `0x27`), and `0x1B` is measured to kill with `arg3 = 0`
(`results/phase36_realargs/1543a_sys601_cmd1b_arg3_zero_20261110_162129.txt`), which this case
would not do.

The two qword writers (`0x8b660e63`/`0x8b660e71` and `0x8b661542`-`0x8b66156c`) do not help: they
`or [td+0x528], 0x1000000` and store at `+0x578`, but they neither set `0x400` nor clear it, and the
download tests `0x400` alone. A caller qword cannot be married to the download by these two bodies.

### The ioctl forwarder is the debugger's stop-the-world, not a data interface

`0x8b661a99` tail-calls `0x8b65fa20(rdi = obj, esi = ioctl_number)`. That function takes
`mtx_lock(proc+0x148)`, calls `0x8b65f7b0`, and then dispatches on a global function pointer. The body
of `0x8b65f7b0` is the tell:

```
8b65f817  or   qword [proc + 0x560], 0x4000
8b65f826  or   dword [proc + 0xb0], 0x800
8b65f830  call 0x8af1fba0
8b65f838  call 0x8b65e140
8b65f855  test byte [obj + 0x529], 1
8b65f8f1  mov  r14, [proc + 0x10]            ; thread list
8b65f92e  test eax, 0x100
8b65f935  and  rax, ~0x200
8b65f93b  mov  [r14 + 0x528], rax            ; per-thread flags
```

Setting `proc+0x560 |= 0x4000` and `proc+0xb0 |= 0x800`, then walking `proc+0x10` and clearing bit
`0x200` on every thread, is a **stop/resume of the whole process** — the debugger's attach primitive.
The accepted command numbers are a fixed allowlist at `0x8b65fae0`:

```
8b65fae4  mov  eax, 1
8b65fae9  cmp  edi, 0xa002830d ; jle 0x8b65fb10
8b65faf1  lea  ecx, [rdi + 0x5ffd7cf2]        ; cmd - 0xa002830e
8b65faf7  cmp  ecx, 0x14
8b65fafc  mov  edx, 0x100007
8b65fb01  bt   edx, ecx                       ; bits 0, 1, 2
8b65fb06  cmp  edi, 0xa002c315
8b65fb10  cmp  edi, 0xa0020102
8b65fb18  cmp  edi, 0xa0020311
8b65fb20  cmp  edi, 0xa0020319
```

so exactly seven numbers pass: **`0xa002830e`, `0xa002830f`, `0xa0028310`, `0xa002c315`,
`0xa0020102`, `0xa0020311`, `0xa0020319`**. Every one of them is a debugger control; none is a
copy-in/copy-out data command, and the gate `test byte [obj+0x529], 1` plus the debug-object
requirement is the same wall `1384a` hit and `1385a` could not install. `0xa0020102` is also the
constant compared in the writer case at `0x8b6614c1`, which ties that case to this same forwarder.

Consequence, recorded so it is not re-derived: **601 has no reachable body that stores a
caller-controlled pointer and later reads through it.** The command surface is a debugger session
manager, and a game process cannot open a session.
