# The capability context, sys 636/638/643/675, and why none of them is a primitive

Date: 2026-11-04 (eighteenth boot, cont.)
Image: `docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`, file offset == RVA.
Every RVA below is a 13.60 RVA. Measurements were taken live on 14.10 through the Lua loader
(TCP 9026, 192.168.1.121). Nothing here is a 14.10 static claim.

---

## 1. What this probe run actually established

| probe | claim under test | verdict |
|---|---|---|
| 1209a | sys 636 loads a user array into a static kernel array | **CLOSED** - gate refuses with EPERM before the copy |
| 1209a (P4/P5) | sys 638 reads the timezone table | **CONFIRMED LIVE** - returns real tz offsets, 16 B/call, index bounded |
| 1210a | sys 643 ORs a mask into `proc+0xa34` and something observes it | **CLOSED** - 32 bits OR-ed, oracle battery unchanged |
| static | sys 675 writes three kernel globals | **CLOSED** - all three are statistics counters |

Two of these were previously open: 636 had never been probed, and 643 carried a
"behaviourally inert" note with no bit sweep behind it. Both are now measured.

---

## 2. sys 636 - the timezone table loader (body RVA `0x6be4d0`)

Full body, annotated:

```
6be4d0  push rbp / mov rbp,rsp / push r15,r14,rbx / push rax
6be4da  mov rdi,[rdi+0x140]          ; ctx = [td+0x140]  (td is the first syscall argument)
6be4e1  mov rbx,rsi                  ; rbx = uap
6be4e4  call 0x8afc8f90              ; CAPABILITY TEST, returns bit 62 of [ctx+0x60]
6be4e9  test eax,eax ; je 0x6be58d   ; not held -> mov eax,1 ; ret        = EPERM
6be4f1  mov ecx,0xfffffdff
6be4f6  add ecx,[rbx+8]              ; ecx = uap[8] - 0x201
6be4f9  mov eax,0x16                 ; EINVAL
6be4fe  cmp ecx,0xfffffe00 ; jb exit ; passes only for uap[8] in [1,0x200]
6be50a  lea rdi,[0x3915900] ; call 0x8b60bb20   ; mtx_lock(tz_lock)
6be51c  mov r15d,[rbx+8]             ; count
6be520  mov r14,[rbx]                ; user source pointer
6be535  shl r15,4                    ; len = count*16
6be53e  lea rsi,[0x3915920]          ; kernel destination = the tz table
6be545  mov rdi,r14
6be548  mov rdx,r15
6be54b  call 0x8ac19280              ; copyin(user_src, kdest, count*16)
6be557  mov esi,[rbx+8]
6be56d  mov [0x3917920],esi          ; tz_count = count
6be578  call 0x8b60c4b0              ; mtx_unlock
6be588  mov eax,r14d ; ret
```

Addresses are exact: table base **RVA 0x3915920**, lock **RVA 0x3915900**, count **RVA 0x3917920**.
Note `0x3917920 - 0x3915920 = 0x2000 = 0x200 * 16`: **the count global sits immediately after the
array and the accepted count is exactly the number of entries that fit.** The bound is not a
separate guess, it is the array size. There is no overflow here even if the gate were open.

The capability test itself, RVA `0x608f90`:

```
608f90  mov rax,[rdi+0x60]
608f98  shr rax,0x3e
608f9c  and eax,1
608fa0  ret
```

Measured (probe 1209a, capture `results/phase17_new_vectors/1209a_636_tz_table_load_20261104_223151.txt`):

| call | rv | get_error_string |
|---|---|---|
| `636(1, tab)` | 0 | `1 Operation not permitted` |
| `636(0x200, tab)` | 0 | `1 Operation not permitted` |
| `636(0x201, tab)` | 0 | `1 Operation not permitted` |
| `636(0, tab)` | 0 | `1 Operation not permitted` |

All four answer identically, including the two counts the bound check would reject: **the gate runs
first, so the bound is unreachable from userland.** We do not hold bit 62. Closed with two
independent mechanisms (gate, and exact-size array).

---

## 3. sys 638 - the timezone lookup, and a methodology correction

638 was described in the corpus as "the only working kernel read, 16 B/call, index bounded". It is
weaker than that, but the interesting part of this run is how it reports.

Measured in the same connection, immediately after four EPERM refusals:

```
638 key=3      rv=0  err="1 Operation not permitted"
  o8 = 0x0000000000000E13   o16[0] = 0xFFFFFFFFFDC7BB70
  o16[1] = 0x0000000000000E10   o4 = 0x00000E10
638 key=0x100  rv=0  err="1 Operation not permitted"
  o8 = 0x0000000000000F10   o16[0] = 0xFFFFFFFFFDC7BB70
  o16[1] = 0x0000000000000E10   o4 = 0x00000F10
```

0xE10 = 3600 = one hour, and 0xF10 = 3856: the lookup returns real timezone data for two different
keys. **The call succeeded while get_error_string still said EPERM** - errno is only written on
failure, so a stale code survives an entirely successful call. The output buffer, not the reported
string, is the proof of success. Any future probe that treats `get_error_string()` as a per-call
status will mis-read every success that follows a failure.

On the bound: the entry is read at `0x6be664` (`mov rdi,[rsi+rcx-0x10]`) *before* the explicit
`cmp esi,eax ; jb` at `0x6be6ae`, but the index comes from a binary search that seeds `edx = 1` and
clamps with `cmp edx,edi ; jge`, so the index is in `[1,count]` by construction and the read is
`table[index-1]`. The 16-byte copyout happens only on the in-range path. Confirmed: bounded read of
a 0x2000-byte static array, 16 bytes per call. Not a primitive.

---

## 4. sys 643 - the unconditional write into `proc+0xa34`

Body RVA `0xa37660` is 0x30 bytes and has no gate at all:

```
a37660  push rbp / mov rbp,rsp / push r14 / push rbx
a37667  mov rbx,rsi              ; uap
a3766a  mov esi,[rsi]            ; mask = uap[0]
a3766c  mov r14,rdi              ; td
a3766f  lea rdi,[rip+0x92a26c]   ; a logging name
a37678  call 0x8ac1d410          ; log
a3767d  mov eax,[rbx]            ; mask
a3767f  mov rcx,[r14+8]          ; td->td_proc
a37683  or dword ptr [rcx+0xa34],eax
a37689  xor eax,eax ; ret        ; returns 0
```

An unprivileged, unvalidated **32-bit OR into a fixed offset of our own `struct proc`**. This is the
strongest-looking shape in the whole table: an arbitrary write primitive with a pinned destination.
The question is entirely "what reads `proc+0xa34`".

Every reference to `+0xa30`, `+0xa34` and `+0xa38` in the image (39 total, whole-image displacement
scan) splits into three groups, and only five instructions ever read `+0xa34`:

```
2cc0c0  mov eax,[proc+0xa34] ; test al,1 -> jne error path
2cc0ce                        test al,2 -> selects one of two branches
3cb8ec  test byte [proc+0xa34],1 -> jne skip
3cb946  movzx ecx,byte [proc+0xa34] ; shr 1 ; and 1   -> stored at [rbp-0x34]
3cb959  movzx eax,byte [proc+0xa34] ; shr 2 ; and 1   -> stored at [rbp-0x33]
```

Bits 0, 1 and 2 only. Bits 3-31 of `proc+0xa34` have no reader anywhere in the image. The two
consumers are one large function starting at `0x2cbdb0` and a Sony subsystem in the `0x3cb6xx` region;
neither grants anything - bit 0 means "take the error/skip branch", bits 1 and 2 are copied into an
object handed to `0x8aec0910` / `0x8aec1660`.

Measured (probe 1210a, capture `.../1210a_643_a34_bit_sweep_20261104_223550.txt`): one connection,
baseline oracle battery (`608`, `674`, `547`, `638`, `605`, `602`, `607`), then 32 rounds of
`643(1<<b)` followed by the same battery. Every round: `rv=0`, process alive, battery byte-identical.
All 32 bits are now accumulated in the process and nothing observable changed.

Caveat, recorded honestly: the probe's own DIFF marker is worthless because it compared the errno
strings too, and errno is stale across successes (section 3). The *content* of the battery is
identical in all 33 lines, which is the real result; the marker was noise.

Verdict: 643 is a genuine pinned-address OR-write with no gate, and it is worthless, because the
only consumer bits steer two Sony code paths a game process never reaches with authority.
**Do not re-open this without a new reader of `+0xa34` - the scan above is exhaustive for that
displacement.**

---

## 5. The capability context at `[td+0x140]`

636's gate and one of 643's consumers both load `[td+0x140]` and then test bits of `[ctx+0x58]` and
`[ctx+0x60]`. That pointer addresses a whole family of tiny predicate functions at RVA
`0x608e00`-`0x609600`:

| RVA | test | call sites in the image |
|---|---|---|
| `0x608f90` | bit 62 of `[ctx+0x60]` | **508** |
| `0x608fb0` | bit 61 of `[ctx+0x60]` | 3 (`0x3c145f`, `0x68feb9`, `0x6b9659`) |
| `0x608fd0` | bit 60 of `[ctx+0x60]` | 3 (`0xada465`, `0xaf15ab`, `0xc36ca5`) |
| `0x608ff0` | range test on `[ctx+0x58] & 0xff0f000000000000` | 42 |
| `0x609020` .. `0x6093e0` | equality of `[ctx+0x58]` against a tagged constant `0x48000000_XXXXXXXX` | 1-66 each |

`0x6b9640` packages two of them:

```
6b9640  cap_test(sel /*edi*/, ctx /*rsi*/)
   sel==0 -> return 1
   sel==1 -> return 0x8afc8fb0(ctx)      ; bit 61
   sel==2 -> return 0x8afc8f90(ctx)      ; bit 62
   else   -> log an assertion and return 0
```

and `0x68feb9` shows how the two bits combine into a level:

```
68fea0  call 0x8afc8f90(ctx)  ; bit62
68fea5  mov ecx,1
68feaa  test eax,eax ; jne done        ; bit62 -> level 1
68feb9  call 0x8afc8fb0(ctx)  ; bit61
68fec0  test eax,eax ; setne cl ; add ecx,ecx   ; bit61 -> level 2
```

So the context carries a 2-bit level plus a set of named tags, and **bit 62 alone gates 508 call
sites** - by far the most valuable single bit in the image, and 636 proves we do not have it. The
tags (`0x4800000000000003/06/07/15/1e/1f/21/22/36/3b/3f/100c`, `0x4800000010000003/05/09/0f/10`,
`0x4800000000020002`) are consumed by sys 612, 649, 594, 604, 535, 536, 455, 466, 482, 346,
253, 232 and 670.

Correction (2026-11-05): **532 does not belong in that list.** Its extent `0xaf0040-0xaf133e` calls
exactly one capability helper, `0xaf0123 -> 0x609080`, and that helper compares `cred+0x58` against
`0x4800000000010003` (25 bytes, one basic block, exact 64-bit equality, no mask and no fail-open).
`0x4800000000020002` is the immediate of `0x6091d0`, whose callers - `0x69a180`, `0xada436`,
`0xc36e1f` - 532 never reaches. The pairing was produced by matching the constant to the wrong
helper in a cluster listing and is withdrawn.

The decisive question is whether anything reachable *writes* `[ctx+0x58]` or `[ctx+0x60]`.
Whole-image scan: 1,551 instructions load a pointer from `[reg+0x140]`; **zero** of them are
followed within 0x140 bytes by a store to `[same_reg+0x58]` or `[same_reg+0x60]`. The context is
installed when the process is created and is immutable from userland. That is the same conclusion
the 597 route reached from the other direction (`proc+0x3e8` + `[ctx+0x140]` is likewise only
touched at creation), now confirmed over a different structure.

---

## 6. sys 675 - three global writes, re-examined

Body `0x2d36f0`, no argument load at all:

```
mov dword ptr [0x1a962e0], 1        ; g1
mov qword ptr [0x2d616c8], -1       ; g2
mov qword ptr [0x2d60008], 0        ; g3
xor eax,eax ; ret
```

Whole-image rip-relative reference scan for those three addresses: 40 / 15 / 5 references, and every
one is a counter operation - `lock add qword [..],1`, `lock cmpxchg`, `lock xadd`, `cmp qword [..],0` -
clustered at `0x2c8f9d`-`0x2cf7ef` and `0x3c5093` / `0x3d05e4`. 675 is a statistics / free-list
reset. No gate reads any of the three.

---

## 7. Standing corrections

* Any probe that treats `get_error_string()` as a per-call status is wrong after the first success.
  Section 3 shows a successful 638 reporting EPERM.
* A "behaviourally inert" verdict on a pinned-address write must be backed by a full bit sweep plus
  an exhaustive reader scan. 643 now has both; the earlier note did not.
* The census of "which syscalls are gated on a capability bit" is now expressible: the predicate
  family at `0x608e00`-`0x609600` is that census. Anything reached from `0x608f90` is bit-62-gated
  and therefore unavailable to a game process by construction.
