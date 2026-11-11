# The PMC/MSR chain behind syscalls 565 and 566 (13.60 image, 14.10 context)

Status: static analysis of the only kernel image in this corpus,
`docs/dumps_13.60/kernel_text.bin` (13.60 .text, base 0xffffffff8a9c0000,
file offset == RVA, length 0xE6E5C0). Every instruction below was disassembled from the
exact body start of the function that contains it; no windows are shared between
functions. Syscall bodies are taken from `docs/dumps_13.60/sysent_index.json` and
decoded through the `e9 rel32` trampolines in 0x265760..0x266500.

**Verdict up front.** The chain does reach `wrmsr`, in three separate wrappers, and the
**MSR numbers are never attacker-influenced**. They are `mov ecx, imm32` constants
(0xC0010200..0xC001020B for the 565/566 pair; 0xC0010230..0xC001023B and
0xC0010188..0xC0010247 for 625/626). The attacker controls *which of six* slots (index
bounded to {-1,0..5}) and the *data*. 565's data is masked and then force-ORed; 566's
data is an unmasked 64-bit qword, but it lands in a performance-counter *count* MSR, not
in an event-select or control MSR. Nothing in the image derives an MSR number from a
structure field. The 565/566 write is a performance-counter programming surface, not an
MSR-number primitive.

---

## 1. Call graph

```
565 (0x6034e0)  --store [ctx+idx*8+0x160]--> 0x602d40 kick_a --+-- td == curthread --> 0x602830 pmc_program_all (12 wrmsr)
                                                              +-- else -> td+0x380 |= 2, ipi_notify(cpu,4) -> spin
566 (0x603710)  --store [ctx+idx*8+0x190]--> 0x602e80 kick_b --+-- td == curthread --> inline 6 wrmsr (0xC0010201..0B)
                                                              +-- else -> td+0x380 |= 2, ipi_notify(cpu,6) -> spin
563 (0x602fe0)  --kick_a at 0x603111 / 0x603205   (enable: sets td+0x380 = 1)
567 (0x6039d0)  --writes td+0x380 = 5, ipi_notify(cpu,7) or same-thread 6 rdmsr -> [ctx+0x190..0x1b8], copyout 8 bytes
625 (0x603c90)  --own wrmsr/rdmsr of 0xC0010230..0xC001023B, 0xC0010240..0xC0010247, 0xC0010188..0xC0010197
626 (0x604cf0)  --own rdmsr of the same families, copyout
```

`0x602d40` and `0x602e80` take the **thread** in rdi, not the PMC object; each re-loads
`[td+0x3f8]` itself. `0x6027e0` (called on the target CPU once the pending bit is
serviced) also ends in `0x602830`, so the remote path and the same-thread path converge on the
same twelve constant MSRs.

## 2. The three wrmsr wrappers

### 2.1 `0x602830` — pmc_program_all, twelve `wrmsr`

Reached from `0x602dc3` (kick_a, same-thread) and `0x602808` (deferred programmer
`0x6027e0`, used after an IPI). Head, verbatim:

```
602830  push rbp
602831  mov  rbp, rsp
602834  mov  rax, qword ptr [rdi + 0x3f8]
60283b  mov  ecx, 0xc0010201
602840  mov  rax, qword ptr [rax + 0x190]
602847  mov  rdx, rax
60284a  shr  rdx, 0x20
60284e  wrmsr
```

Twelve repetitions of that block: `[ctx+0x190,0x198,0x1a0,0x1a8,0x1b0,0x1b8]` go to
`0xC0010201,0x203,0x205,0x207,0x209,0x20B`, and then
`[ctx+0x160,0x168,0x170,0x178,0x180,0x188]` go to
`0xC0010200,0x202,0x204,0x206,0x208,0x20A`. EAX = low 32 bits of the qword,
EDX = bits 63:32 — the whole qword is written, so 566's unmasked value reaches
PerfCtr0..5 count MSRs verbatim.

### 2.2 `0x602e80` — kick_b, inline six `wrmsr` (566 only)

```
602e87  mov  rax, qword ptr [rdi]
602e8a  cmp  dword ptr [rdi + 0x400], 4
602e91  jne  0x602fbc
602e97  mov  rax, qword ptr gs:[0]
602ea0  cmp  rdi, rax
602ea3  je   0x602f14
```

Same thread -> the inline block at 0x602f14, six copies of:

```
602f14  mov  rax, qword ptr [rdi + 0x3f8]
602f1b  mov  ecx, 0xc0010201
602f20  mov  rax, qword ptr [rax + 0x190]
602f27  mov  rdx, rax
602f2a  shr  rdx, 0x20
602f2e  wrmsr
```

Other thread:

```
602ea5  or   byte ptr [rdi + 0x380], 2
602ebf  call 0x4c7520                 ; unlock td->td_lock
602ed4  call 0x4c7190                 ; lock a global
602ed9  mov  edi, dword ptr [r14 + 0x524]
602ee0  mov  esi, 6
602ee5  call 0x81e4d0                 ; ipi_notify(cpu, 6)
602eea  test byte ptr [r14 + 0x380], 6
602f00  pause                         ; spin until the target CPU clears bits 1|2
```

### 2.3 `0x6029e0` — stop/latch (called from `0x602de0`, action 5)

Writes the six **control** MSRs from `[ctx+0x160..0x188]` (immediates
0xC0010200/202/204/206/208/20A), then latches the counters back:

```
mov ecx, 0xc0010201 / rdmsr / mov eax,eax / shl rdx,0x20 / or rdx,rax
mov rax,[rdi+0x3f8] / mov [rax+0x190],rdx        ; and 0x198/0x1a0/0x1a8/0x1b0/0x1b8
```

So `+0x190..+0x1b8` is both a write target (566 programs it into the hardware) and a
read-back target (567, and this stop path).

## 3. Every path that consumes `+0x160..+0x18f` / `+0x190..+0x1bf`

| consumer | array | direction | MSR numbers |
|---|---|---|---|
| 0x602830 (12 wrmsr) | both | ctx -> MSR | 0xC0010200..20B, all `mov ecx,imm32` |
| 0x6029e0 stop | +0x160 | ctx -> MSR | 0xC0010200..20A even, immediates |
| 0x6029e0 latch | +0x190 | MSR -> ctx | 0xC0010201..20B odd, immediates |
| 0x602e80 inline | +0x190 | ctx -> MSR | 0xC0010201..20B odd, immediates |
| 567 same-thread 0x603ae2 | +0x190 | MSR -> ctx | 0xC0010201..20B odd, immediates |
| 567 out 0x603bc8 | +0x190 | ctx -> user | `mov rax,[rax+r13*8+0x190]`, then `copyout` 8 bytes |
| 565 store | +0x160 | user -> ctx | n/a |
| 566 store | +0x190 | user -> ctx | n/a |

Nothing else in the image touches either range. A scripted scan of 0x600000..0x607000 for
`+ 0x150]`, `+ 0x158]`, `+ 0x1c0]`, `+ 0x1c8]` finds no reference at all, so those fields are
not part of this object's used layout in this image (they may belong to a neighbouring
structure or to the allocator's header).

## 4. 565: what actually lands in `+0x160`

```
6034ee  mov  r12d, dword ptr [rsi + 8]      ; index
6034f2  mov  r13, qword ptr [rsi + 0x10]    ; value
6034f6  movabs rcx, 0xfffffff0007b0000
603506  cmp  r12, 6
60350a  setae al
60350d  test r13, rcx
603510  setne cl
603513  or   cl, al
603515  jne  0x6036f8                       ; reject
60351e  movabs rax, 0xf000000ff
603528  movabs rcx, 0x100000070
603532  and  rax, r13
603535  cmp  rax, rcx
603538  je   0x603540
60353a  cmp  rax, 0x6e
60353e  jne  0x60354d                       ; skip the mask entirely
603540  movabs rax, 0xfff8400ff
60354a  and  r13, rax
...
6035fe  or   r13, 0x410000                 ; force bit 22 (EN) and bit 16 (USR)
603608  mov  qword ptr [rbx + r12*8 + 0x160], r13
603610  call 0x602d40
```

Consequences for the value written into `0xC0010200+2i`:

* bits 36..63 and bits 16,17,19,20,21,22 are **forced to zero** by the `test` mask
  0xfffffff0007b0000, which runs before either path;
* bits 16 and 22 are then **forced to one** by `or r13, 0x410000`;
* the strict `0xfff8400ff` mask (which also clears UnitMask bits 8..15 and bits 32..35)
  is applied **only** when `(value & 0xf000000ff)` is 0x100000070 or 0x6e; otherwise bits
  0..15, 18, 23..31 and 32..35 pass through as the caller supplied them;
* the index gate is `cmp r12,6 / setae al`, i.e. index 0..5 for this path.

The store address is `[ctx + idx*8 + 0x160]` with `ctx = [td+0x3f8]` and idx <= 5, so
it stays inside the six-entry control array. Nothing else is written.

Value semantics (AMD Zen PMC): `MSRC001_0200+2i` is a PerfCtr event-select register —
bits 0..7 EventSelect, 8..15 UnitMask, 16 USR, 17 OS, 18 EDGE, 19 PC, 20 INT, 22 EN,
23 INV, 24..31 CounterMask. The kernel therefore lets the caller pick *which event* to
count (EventSelect is caller data), forces user-mode counting and enables the counter.
Bits 32..35 can survive the mask on the non-0xfff8400ff path; on AMD those bits are
documented reserved, so a nonzero value there is a candidate `#GP` inside `wrmsr` at
kernel CPL. That is a value-side robustness question (at most a local fault), not an MSR
number primitive, and it was not exercised on 14.10.

## 5. 566: the unmasked qword

```
60371e  mov  r13d, dword ptr [rsi + 8]
603722  mov  r14d, 0x16
603728  lea  eax, [r13 - 6]
60372c  cmp  eax, -7
60372f  jb   0x6039b1                       ; reject unless (idx-6) >= -7  => idx in {-1,0..5}
603738  mov  r12, qword ptr [rsi + 0x10]    ; value, no mask anywhere
...
6037e5  mov  qword ptr [r15 + r13*8 + 0x190], r12
6037fe  call 0x602e80
```

No validation of the value at all: the full 64-bit qword goes into
`[ctx+idx*8+0x190]`, and `0x602e80` / `0x602830` then write it to
`0xC0010201+2i`. A performance counter's count field is writable data by design, so an
attacker-chosen qword here changes a counter, nothing else. The six target MSRs are
hard-coded immediates in five separate places.

## 6. 567 (read side) exists and copies out

```
6039f5  mov  r13d, dword ptr [rsi + 8]
6039f9  cmp  r13, 5
6039fd  ja   0x603c21                      ; index 0..5
603a45  cmp  dword ptr [r15 + 0x380], 1
603a4d  jne  0x603bbe                       ; thread must be PMC-enabled
603ae2  mov  ecx, 0xc0010201 / rdmsr ... (six times, 0xC0010201,03,05,07,09,0B)
603c10  lea  rdi, [rbp - 0x38]
603c14  mov  edx, 8
603c19  mov  rsi, rbx                       ; rbx = [arg+0x10] = user destination
603c1c  call 0x2591d0                       ; copyout
```

So the pair is a complete counter oracle on the caller's own thread: 563 enables, 565
programs event-select, 566 loads a count, 567 reads the latched count back to userland.
That is a *sandboxed* read of six MSRs, not a read of arbitrary kernel memory: the
source is `[ctx+r13*8+0x190]` with r13 <= 5, and `copyout`'s kernel side is never
checked (0x2591d0 masks only the user destination) — but the address is a fixed field of
a fixed object, so there is no attacker-selected kernel address here either.

14.10 status: 177a-177d accepted 563-566 and rejected 567 for twelve layouts, and 625/626
return -1 (`docs/SYS565_566_SIX_QWORD_ARRAYS_14_10.md`). The 13.60 bodies above are
therefore a map of what the code can do, not a statement that 14.10 exposes 567/625/626.

## 7. Structure map

### 7.1 Thread (`rdi` of the kick functions)

| offset | type | evidence |
|---|---|---|
| +0x000 | lock ptr | `mov rax,[rdi]` then `add rdi,0x18 / call 0x4c7520` (mtx_unlock) |
| +0x008 | proc ptr | `mov rbx,[rdi+8]` then `add rbx,0x148 / call 0x4c6fa0` in 563/564/565/566 |
| +0x380 | u32 state | 563 sets 1 (0x603106), 564 sets 0 (0x603386,0x60347a), kicks `or ...,2`/`4`, 567 sets 5 (0x603a72) |
| +0x400 | u32, must be 4 | `cmp dword ptr [rdi+0x400],4 / jne skip` in both kicks and 567 — reads as td_state TDS_RUNNING |
| +0x3f8 | void *pmc | dereferenced to reach all twelve slots |
| +0x524 | u32 cpu id | `mov edi,[rbx+0x524]` immediately before `call 0x81e4d0` |

An earlier note in `docs/SYS565_566_SIX_QWORD_ARRAYS_14_10.md` says 0x602d40 reads
`[obj+0x400]`; that is the thread, not the PMC object. Corrected here.

### 7.2 PMC context (`[td+0x3f8]`)

| offset | meaning |
|---|---|
| +0x160,+0x168,+0x170,+0x178,+0x180,+0x188 | six u64 control values -> 0xC0010200,02,04,06,08,0A |
| +0x190,+0x198,+0x1a0,+0x1a8,+0x1b0,+0x1b8 | six u64 counter values -> 0xC0010201,03,05,07,09,0B (and latch destination) |
| +0x150, +0x158, +0x1c0 | no reference anywhere in 0x600000..0x607000 |

Allocator: no `mov [reg+0x3f8], <fresh allocation>` exists among the 29 qword stores into
`[reg+0x3f8]` in the image (0x280098 per-cpu rdtsc scratch, 0x452bf9, 0x4f2de1=0,
0x542d25=-1, 0x5e62f2, 0x57026d, 0x663382=0x1e8480, 0x7a0b60, 0x7aed45/0x7aed97, 0x7aee2d,
0x7aef43, 0x7af663, 0x7af825, 0x86bb93=0, 0x887e20, 0xa34925). With no data section in
the dump, the *initialisation* site is not identifiable here; what is proven is that the
object must already exist (and `td+0x380` must be 1, i.e. 563 already run) before 565's
store path or 567's copyout path can execute.

## 8. `0x81e4d0` — ipi_notify

```
81e4da  cmp  esi, 0xff
81e4e0  jne  0x81e4f9
81e4ef  lock or qword ptr [rip + 0x32525b1], rax     ; global "all CPUs" bitmap
81e4f9  cmp  esi, 0xd
81e4fc  jae  0x81e542
81e50d  shlx esi, eax, esi                            ; pending bit = 1 << action
81e520  mov  ecx, dword ptr [rdi + rdx*4]             ; per-cpu pending word
81e52b  lock cmpxchg dword ptr [rdi + rdx*4], r8d
81e533  test ecx, ecx
81e535  je   0x81e547                                 ; first pending request -> IPI
81e54c  lea  rcx, [rip + 0x12bab3d]
81e564  mov  rcx, qword ptr [rcx + 0xa8]              ; registered per-cpu callback
81e56e  ror  rax, 3
81e572  cmp  rax, 1
81e576  ja   0x81e588                                 ; panic (0x44f8c0)
81e586  jmp  rcx
```

Actions observed from the PMC code: 4 (program-all, kick_a), 5 (stop/latch, kick_stop),
6 (reload counts, kick_b), 7 (get counters, 567). The callback is validated against a
fixed reference (0x273448/0x273450, `ror rax,3; cmp rax,1`) before the indirect jump.
The registration side lives in data; it is not resolvable in a `.text`-only image, so
which function services action 4/5/6/7 on the target CPU is inferred from `0x6027e0`
(`test byte ptr [rbx+0x380],6 / call 0x602830 / and byte ptr [rbx+0x380],0xf9`) rather
than read directly.

## 9. Whole-image `wrmsr` census

Method: Capstone linear sweep of the full 0xE6E5C0 image = 5,343,048 instructions; every
`wrmsr` (0f 30) site then resolved backwards to the nearest definition of ECX (stopping at
a `call`, which clobbers ECX). 488 sites total.

| class | count | notes |
|---|---|---|
| ECX = constant immediate | 476 | `mov ecx,imm32` (468) or `movabs rcx,imm64` (8, 0xC0000110..0xC0000117) |
| ECX from a bounded index inside 625 | 8 | 4 `lea`, 4 `or/add` on an index already proven <= 5 / <= 7 |
| ECX from boot-time loop state | 3 | MTRR (0x5f0ca8, 0x5f0d3b) and the 0x400-range sweep (0x976a59) |
| ECX from a register in a callerless helper | 1 | 0x259b35 |

### 9.1 The twelve non-immediate sites, and why none of them is a user-controlled MSR number

```
604294  or   cl, al              ; from the 625 gate below
60427b  lea  ecx, [r14 - 6]
60428e  cmp  ecx, -7
604296  jne  reject              ; accepts r14 in {-1,0,1,2,3,4,5}
60431b  lea  ecx, [r14 + r14 - 0x3ffefdcf]     ; 0xC0010231 + 2*idx
6047f3  lea  ecx, [r14 + r14 - 0x3ffefdcf]     ; same, all-six path

604244  cmp  r14d, 5
604248  ja   reject                           ; this case accepts idx 0..5
604261  mov  esi, r14d
604272  jmp  0x604840
60486a  mov  r14d, esi
6048cf  lea  ecx, [r14 + r14 - 0x3ffefdd0]     ; 0xC0010230 + 2*idx
60494b  lea  ecx, [r14 + r14 - 0x3ffefdd0]     ; retry path

6049c8  lea  ecx, [rdi + rdi]
6049cf  cmp  edi, 3
6049dc  or   ecx, 0xc0010240                  ; idx<=3 -> 0xC0010240,42,44,46
6049e8  add  ecx, 0xc0010188                  ; idx>3  -> 0xC0010190,92,94,96 (idx<=7)
604c76  or   ecx, 0xc0010241                  ; -> 0xC0010241,43,45,47
604ce5  add  ecx, 0xc0010189                  ; -> 0xC0010191,93,95,97

259b35  mov  ecx, edi                          ; helper 0x259b10 wrmsr(msr,val); zero direct callers
5f0c9a  lea  ecx, [rsi + 1]                    ; MTRR phys base/mask, esi = 0x200 + 2k
5f0d35  mov  ecx, esi
976865  mov  r12d, 0x401                       ; boot sweep, r12d += 4, cmp 0x41d
976a56  mov  ecx, r12d
```

Reachability:

* **625/626 are live syscall bodies** in `sysent_index.json`, so the eight bounded sites are
  reachable from a syscall *in 13.60*. Every one of them is preceded by a compare that pins the
  index: `cmp r14d,5 / ja`, `lea ecx,[r14-6] / cmp ecx,-7`, or
  `cmp edi,3`+`cmp r14d,ecx` against a 3-or-7 value derived from the CPU model check at
  0x6da810 (0x60432a-0x604345). The reachable MSR set is therefore exactly
  0xC0010230..0xC001023B, 0xC0010240..0xC0010247 and 0xC0010188..0xC0010197.
  On 14.10, 625/626 return -1 for every layout probed, so this whole family is behind a
  gate there.
* **0x5f0ca8 / 0x5f0d3b** are inside the MTRR/cache routine that ends `wbinvd / mov rax,cr3 /
  mov cr3,rax / mov ecx,0x2ff / rdmsr`. esi enumerates 0x200+2k over the variable MTRR
  count. No direct caller exists in .text (referenced from an init table in data).
* **0x976a59** zeroes MSR r12d while r12d walks 0x401, 0x405, ... 0x41D
  (`add r12d,4 / cmp r12d,0x41d / je`). The number is a compile-time loop sequence,
  not input; no direct caller in .text.
* **0x259b35** `mov ecx,edi` in the generic `wrmsr(msr,value)` helper at 0x259b10 (its
  `rdmsr` twin is 0x259ad0; both install a pcb onfault via `gs:[0x20]+0x108`). **Zero
  direct callers image-wide.** It is the only site in the image where a full 64-bit
  attacker value could meet a full 32-bit attacker MSR number — and nothing calls it. If a
  future 14.10 image gains a caller, that is the site to re-examine first.

### 9.2 Constant-immediate MSR numbers (grouped, with multiplicity)

| family | MSRs (count) |
|---|---|
| PMC / perf | 0xC0010200..0xC001020B (4 each), 0xC0010230..0xC001023B (10 even, 4 odd), 0xC0010240..0xC0010247 (4/2), 0xC0010188..0xC0010197 (1-4 each) |
| SVM / misc AMD | 0xC001001F, 0xC0010041 (6), 0xC0010062-006B (1 each), 0xC0011019-011B, 0xC0011024-01102B, 0xC0011033 (15), 0xC0011074-1077 |
| EFER / STAR / LSTAR / CSTAR / SFMASK / FS / GS / TSC_AUX | 0xC0000080-0084 (3 each), 0xC0000100 (5), 0xC0000101 (8), 0xC0000102-0103, 0xC000010F, 0xC0000110-0117 (8 via movabs) |
| architectural / model | 0x1B, 0xE7 (4), 0xE8 (4), 0x17B, 0x199/0x19A (3), 0x1D9 (5), 0x250, 0x277, 0x2FF (2), 0x400-0x419 (one each), 0x6E0 (3), 0x80B/0x80F/0x828/0x82F/0x830/0x832/0x834-0x838/0x83E/0x841/0x850-0x852, 0x1107, 0x110B |

118 distinct MSR numbers, 476 immediate sites. Everything a syscall can reach is in the
PMC/perf group; the rest are CPU init, context switch (0xC0000110..0117), MTRR, and
machine-check/thermal paths that no syscall body references.

## 10. Verdict

1. **Does the chain reach `wrmsr`?** Yes, three ways: `0x602830` (12 wrmsr, called from
   kick_a same-thread and from the deferred programmer `0x6027e0`), `0x602e80`'s inline
   block (6 wrmsr, 566 only), and `0x6029e0` (6 wrmsr + 6 rdmsr, stop path).
2. **Is the MSR number attacker-influenced?** No. Every one of them is
   `mov ecx, imm32`. The only thing the caller selects is *which of six* slots, via an
   index that 565 validates as `cmp r12,6 / setae` (0..5) and 566 as
   `lea eax,[r13-6] / cmp eax,-7 / jb` ({-1,0..5}). MSR numbers written by the
   pair: 0xC0010200/02/04/06/08/0A (control) and 0xC0010201/03/05/07/09/0B (count).
3. **Can an attacker-chosen qword land in an attacker-chosen MSR?** Not through any
   instruction sequence in this image. 566's unmasked qword reaches only 0xC0010201+2i
   count registers. 565's value is filtered by 0xfffffff0007b0000, usually masked by
   0xfff8400ff, and then ORed with 0x410000 before the store.
4. **What is the residual risk?** (a) 565 can carry bits 32..35 of `0xC0010200+2i` when the
   value misses the 0xfff8400ff mask; if those bits are reserved on the part, `wrmsr`
   faults at kernel CPL — a local fault/DoS question, untested on 14.10. (b) `0x259b35` is a
   generic wrmsr(msr,value) helper with no callers; it is the one latent primitive that
   would matter if 14.10 (or a later firmware) starts calling it. Neither is a kernel
   read, and neither is reachable today.
5. **For the READ hunt:** this chain gives no kernel read. 567 would be a read of six
   fixed counter fields through `copyout` (0x2591d0), gated on `td+0x380 == 1` and an index
   `<= 5`; on 14.10 it rejects every probed layout. The `copyout` source is
   `[ctx+r13*8+0x190]`, not a caller-supplied pointer, so it is not an arbitrary-read
   primitive even where it works.

## 11. Reproduce

```
.local/dis_565.py            565/566 bodies, masks, kick calls
.local/scan_3f8.py           stores into [reg+0x3f8] image-wide
.local/scan_160_190.py       references to +0x150/+0x158/+0x160../+0x1c0
.local/pmc_dis1.py           CFG-following dumper used for the kick functions
.local/pmc_resolve.py        the 488-site wrmsr census + ECX provenance classifier
.local/pmc_wrmsr_rows.json   per-site rows (addr, kind, defining instruction, window)
.local/pmc_b565.py .local/pmc_b566.py .local/pmc_b848.py .local/pmc_b976.py .local/pmc_bipi.py
                             the exact dumps quoted above
```

One Capstone process at a time; a full sweep is ~4.2 s and 5.3 M instructions.
