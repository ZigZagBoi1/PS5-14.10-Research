# Microarchitectural feasibility on PS5 14.10 (from the Lua loader, no console)

Status: paper analysis + offline binary work, 2026-11-04. Deliverable of the microarch mission.
Substrate: docs/dumps_13.60/kernel_text.bin (15.1 MB, len 0xE6E5C0, file offset == RVA, base
0xffffffff8a9c0000 for 13.60; 14.10 base is 0xffffffff8a000000 per docs/TZ_TABLE_638_14_10.md:31-35),
docs/dumps_13.60/sysent_raw.bin (32592 B = 679 x 0x30 entries), .local/loader_payload/offsets.lua
and native.lua (read only, grep level). No eboot/libc dump exists in the repo, so every libc claim
below is a runtime-scan requirement, not a fact.

## 0. Verdict table (ranked by payoff per unit of work)

| # | hypothesis | verdict | cheapest discriminating measurement |
|---|---|---|---|
| H1 | kernel AVX helper leaves kernel data in live YMM (no vzeroupper anywhere) | IMPLEMENTABLE-IF (probe 1071a) | marker in ymm -> syscall 1..679 -> dump ymm; one mismatch = kernel read primitive |
| H2 | 625/626 PMC counters are real hardware event counters -> cache oracle | IMPLEMENTABLE-IF (probe 1072a) | 12 accepted 625 shapes x 3 workloads (L1 / L2 / DRAM), read 626 cmd 6 around each |
| H3 | L1 same-offset Prime+Probe calibrated on the timezone table | GATED on H2 (or a libc rdtsc gadget) | same probe as H2; wall-clock timing is already dead (92 us floor) |
| H4 | Zenbleed CVE-2023-20593 | NEEDS-NATIVE-EXEC, and target != kernel | byte-scan libc for a ymm store (c5 fc 11 / c5 fe 7f) and for cpuid (0f a2) |
| H5 | Spectre v1 vs 638/639 | DEAD | none - the disassembly has no second (gathering) load |
| H6 | ROP chain with timing/flush primitives | IMPLEMENTABLE for syscalls, DEAD for rdtsc/clflush/prefetch as the loader stands | byte-scan libc for 0f 31 c3 / 0f ae 3f c3 / 0f 18 07 |

Everything below is either a measured number, a quoted instruction, or an explicitly labelled
hypothesis. Sections 1-3 answer the three assigned questions; 4-6 are new hypotheses H1-H3.

## 1. Zenbleed (CVE-2023-20593) - H4

### 1.1 The leaking instruction sequence
Cause: on Zen 2, vzeroupper does not clear the upper 128 bits of the ymm registers when the
register is in a certain rename/merge state; a following VEX-encoded instruction that writes only
the low 128 bits merges its result with the *stale physical register* instead of a zero, so the
upper half of the architectural ymm is whatever the previous user of that physical register left
there. Leak shape (the canonical PoC loop, one iteration):

    vmovdqu  ymm0, [rbx]      ; dirty a physical register with attacker-known data
    vzeroupper                ; architecturally zeroes bits 255:128
    vmovdqu  xmm1, [rbx+32]   ; 128-bit VEX write: upper half must be 0, may be restored stale
    vmovdqu  [rdi], ymm1      ; store 32 B; bytes 16..31 are the leak

The discriminating byte is in 16..31 of the store, so a PoC must be able to issue a 256-bit store
(vmovdqu / vmovups ymm, 3 bytes: c5 fe 7f / c5 fc 11) and must run AVX-256 (XCR0 YMM enabled).
A second, simpler variant that needs no explicit vzeroupper: any sequence that leaves a ymm
register's upper half merge-pending (vzeroupper is simply the cheapest way to hit the state).

### 1.2 What a PoC needs
- loop shape: a tight loop of the four instructions above (no syscalls, no locking); stack usage 0;
- registers: 1 pointer register for source and destination of a 32 B-aligned scratch buffer,
  one ymm destination; the storer must not be interrupted (a signal between vzeroupper and the
  store is harmless; a context switch is not, it changes the physical register);
- timing: none. This is not a side channel, it is a direct read of the register file; the only
  quantity is *residency* - the useful data is what the same physical core ran before (SMT sibling
  or the previous thread on that core, including the kernel if it ran between our slices);
- harvest: XOR the upper 16 bytes against a known pattern; 0 everywhere = not vulnerable or no
  stale data; non-zero and stable across thousands of iterations = vulnerable.

### 1.3 Fix level, and is it present on 14.10?
The fix is a microcode (AGESA/microcode patch) update shipped by AMD in mid-2023; it makes
vzeroupper clear the upper halves. The microcode revision is exposed only through MSR 0x8B,
which is not reachable from this loader:
- no /dev/cpuctl and no /dev/msr on this image (docs/DEVFS_NAMESPACE_14_10.md:203,215;
  docs/DEVFS_GAP_ANALYSIS_14_10.md:57 - both refused/absent, closed);
- the loader has no cpu_features / cpuid / feature export (grep of native.lua for
  feature|cpuid|rdtsc|clock: 0 hits; offsets.lua gadget_table has 38 gadget names, none of them
  cpuid/rdtsc/msr);
- the only MSR window we can drive is the PMC block: 626 cmd 5 reads 0xc0010241+2i for i<=3 (all
  zero), 625/626 write/read the 0xc0010230-0xc001023b L2 bank. 0x8b is not in that window.
So: the fix cannot be *observed*. Likelihood it is present: high. hw.model = 100-000000189
(docs/ALL_RESULTS.md:11358) is Oberon, Zen 2; firmware 14.10 ships ~Oct 2025, i.e. 2.3 years after
the AMD patch, and Sony rebuilds microcode with each major fw. Verdict: assume fixed, design as if
fixed, and do not spend console time on it.

### 1.4 What is observable without executing new code
CPUID is reachable *if and only if* userspace-reachable code already contains the instruction.
Search targets in the game's libc at runtime (native.read_buffer over its text): 0f a2 (cpuid),
and for a usable call the shape 0f a2 89 d8 c3 (cpuid; mov eax,ebx; ret) or 89 c8 / 89 d0 for
ecx/edx. native.fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9) sets rax (=EAX leaf) and rcx
(=ECX subleaf) and returns rax, so four such gadgets (or four calls with different mov) yield all
of EAX/EBX/ECX/EDX of leaf 1 and leaf 7. Same trick gives rdtsc (0f 31) and, with a mov eax,edx
suffix, the high 32 bits. This is the only honest answer to 'CPUID from userland, no new code':
it is a gadget hunt, and the hunt is cheap (a byte scan of 3-4 MB).

### 1.5 Why Zenbleed is the wrong tool here even if the CPU is vulnerable
The kernel's copy paths are vector-free: the copyout helper at VA 0xffffffff8ac191d0 is
55 48 89 e5 65 48 8b 04 25 20 00 00 00 ... 48 87 f7 (xchg rdi,rsi) ... fc 0f 01 cb (stac)
f3 48 a5 (rep movsq) ... f3 a4 (rep movsb) 0f 01 ca (clac). Kernel secrets therefore never land in
a ymm register, so a perfect Zenbleed primitive yields other *user* contexts' data (game, GPU,
audio threads), not kernel memory. That is not the mission's target.

## 2. Spectre v1 against 638/639 - H5 (DEAD)

638 utc_to_localtime, 13.60 RVA 0x6be5c0, exact head:
  55 48 89 e5 41 57 41 56 53 48 83 ec 28   lea r15,[rip+..] (0x391c310)
  48 8d 3d 25 73 25 03 (lea rdi, 0x3915900)  48 89 f3 (mov rbx,rsi)  31 f6 31 d2 31 c9
  49 8b 07 (mov rax,[r15])  48 89 45 e0   e8 60 cd 58 00 (call helper)
  8b 05 2a 93 25 03 (mov eax,[count] = RVA 0x3917920)  85 c0  0f 84 b6 00 00 00
  ba 01 00 00 00 (lo=1)   48 8d 0d 16 73 25 03 (lea rcx, table = RVA 0x3915920)
  83 f8 02 (cmp eax,2) 7c 40   48 8b 33 (mov rsi,[rbx])  ba 01 00 00 00   89 c7 (hi=count)
  loop head 0x6be626: 41 ff c0 (inc r8d) 44 89 c2 (mov edx,r8d) 39 fa (cmp edi,edx) 7d 25 (jge)
    44 8d 0c 17 (lea r9d,[rdi+rdx]) 45 89 c8 41 c1 e8 1f 45 01 c8 41 d1 f8 (mid = (hi+lo)/2)
    4d 63 c8 49 c1 e1 04 (r9 = mid*16) 49 39 34 09 (cmp [r9+rcx],rsi) 7e d8 (jle loop)
    44 89 c7 (hi=mid) 39 fa 7c db (jl loop)
  exit: 48 63 f2 48 c1 e6 04 48 8b 7c 0e f0 48 8b 74 0e f8 (load record fields)

Three facts kill the v1 hypothesis:
1. every memory operand is [mid*16 + table] where mid is computed from the loop bounds, and the
   bounds themselves come from the count global and from previously loaded *public* keys, so the
   speculative address set is inside [table, table+0x1040) (docs/TZ_TABLE_638_14_10.md:248-253:
   260 records, 0x1040 B, nothing outside);
2. the loaded value goes only into a cmp/jle - it never becomes an address, a shift count, or a
   store offset; there is no second array anywhere in the function;
3. no cache-observable residue exists to recover even if (1) failed: the only ways to observe a
   line are (a) a userland cache oracle on a kernel line, (b) the #PF presence oracle - and (b) is
   page-granular and reports presence only (no bytes), so it cannot resolve a mispredicted record.
639 is the mirror image (same table, same arithmetic) and adds only the lo-2 read that docs
1164a refuted (the guard runs). The 42-site copyout audit already established no handler forms
arr[idx] with idx loaded from kernel data.
Verdict: DEAD, no console time worth spending. The only re-opening would be a new handler of the
form x = secret_array[table[i] & 0xff]; none exists in the audited set.

## 3. ROP feasibility for a microarch loop - H6

### 3.1 Capacity
- A chain is an array of 8-byte gadget addresses; the loader pivots RSP into it (probe 883b: a
  padded straight-line chain with RSP 0x400 above the head reaches the kernel).
- A syscall step costs 6 slots (pop rdi; pop rsi; pop rdx; pop rax; call stub; pop rsp; ret = 7),
  so a 1 MB stack = 131072 slots = ~18k syscalls, and 10000 slots = ~1400 syscalls.
- A loop is possible *only* with the re-pivot: 'ending with pop rax <loop>; jmp rax restores RIP
  but not RSP, so the second iteration reads uninitialised stack and the process dies'
  (docs/AIO_RANGE_14_10_EVIDENCE.md:128-131). With pop rsp <loop>; ret, probe 872a ran a
  3000-round and a 4000-round spin loop with no death, pacing each round by parking in read(2).
- Contradiction to resolve before trusting a long loop: docs/CHANGELOG.md:363-366 records that
  882a/883a/884a/885a 'show the same chain cannot be looped - pop rsp reset dies, a 500-call
  linear chain dies'. The 872a loop evidently differs by the read(2) park. Design rule: park on a
  blocking read, keep the loop image in its own mmap region with >=0x1000 of untouched stack below
  the head, and unroll by 4 instead of relying on a single re-pivot.

### 3.2 What a chain can express (offsets.lua gadget_table, 38 names, 5 games)
Present: ret; pop rsp/rbp/rax/rbx/rcx/rdx/rdi/rsi/r8; pop r13; pop r14; pop r15;
mov [rdi],rax; mov [rdi],rsi; mov [rdi],eax; mov rax,[rax]; mov [rax+8],rcx; mov [rax+0x28],rdx;
mov [rcx+0xa0],rdi; add rax,rcx; add rax,r8; add [rax],ebx; add [rax],ecx; add [rax],edi;
inc dword [rax]; cmp [rax],ebx; seta/setb/sete/setg/setl/setne al; shl rax,cl;
mov r9,rbx; call [rax+8]; mov r9,r13; call [rax+8]; mov esp,0xf00000b9 / 0xfb0000bd.
Absent: syscall;ret, rdtsc, clflush, prefetch*, cpuid, jmp reg, xchg, lfence/mfence.
Example offsets (RaspberryCube): pop rsp;ret 0xa12, pop rax;ret 0xa02, pop r8;ret 0xa01,
ret 0xd2811, mov [rdi],rax;ret 0x9522b.
So a chain can: issue any syscall with 5 controlled arguments (r8 only if the game has pop r8),
read and write user memory through fixed-offset stores, do integer arithmetic and byte compares,
shift by cl, and make exactly one kind of data-dependent branch: call [rax+8] with r9 set -
i.e. dispatch through a function pointer table we control. That is enough for a loop and a
state machine.
It cannot: measure time, flush a line, prefetch, or read a register the loader does not pop. There
is no serialising instruction and no counter in the expressible set, so any chain-side timing must
come from a libc gadget or from a syscall (626 cmd 6 is the only counter syscall we have).

### 3.3 Concrete gadget-hunting requirements (byte patterns, all scannable at runtime)
Scan the game's libc text with native.read_buffer and match:
  0f 31 c3                    rdtsc; ret                 (plus 48 89 17 c3 mov [rdi],rdx for high half)
  0f ae 3f c3                 clflush [rdi]; ret
  0f 18 07 / 0f 0d 0f         prefetchnta [rdi] / prefetchw [rdi]
  0f ae e8 c3 / 0f ae f0 c3   lfence / mfence; ret
  0f a2 89 d8 c3              cpuid; mov eax,ebx; ret   (89 c8 = ecx, 89 d0 = edx)
  0f 05 c3                    syscall; ret (would remove the stub dependency)
  c5 fc 11 07 c3              vmovups [rdi],ymm0; ret   (the Zenbleed / YMM dump gadget)
  c5 fc 10 07 c3              vmovups ymm0,[rdi]; ret
Validation rule: a hit may be a suffix of a longer instruction, so dump 16 bytes before each hit
and prefer hits preceded by c3/e8/48-8b-style boundaries; the final test is calling it (a wrong
decode shows up as an immediate fault). Budget: one probe that scans and prints hits; it needs no
native exec and no crash tolerance.

## 4. H1 (new, ranked 1): YMM cross-privilege clobber by the kernel's own AVX helper

### 4.1 Evidence (measured today, offline)
In 15.1 MB of kernel text:
- 0x876870 is a real function: 55 48 89 e5 41 56 53 48 83 e4 e0 48 81 ec 60 07 00 00 (0x760 frame),
  body uses vbroadcastss (c4 e2 7d 18), vcmpss (c5 f4 c2 05 ...), 256-bit vmovups loads
  (c5 fc 10) x15, 256-bit stores c5 fc 11 x44 (first 0x876a8f), c5 fd 11 x8 (first 0x258116),
  c5 fd 7f x33 (first 0x876fbc); 53 call sites target RVA 0x876000-0x87a000.
- vzeroupper (c5 f8 77): **0 occurrences in the whole text**. vmovdqu ymm store (c5 fe 7f): 0.
- xsave (0f ae /4) x5, xrstor (0f ae /5) x18, fxsave (0f ae /0) x9.
Interpretation: the kernel does 256-bit AVX float math and never clears the upper halves; the FPU
bracket exists (xsave/xrstor) but is used at only a handful of sites, so either every caller of
0x876870 is inside fpu_kern_enter/leave, or some path leaves architectural ymm state dirty.

### 4.2 Mechanism and why it is a read primitive
Architectural ymm state is not saved at the syscall boundary (xsave happens on context switch or
inside fpu_kern_enter). If any syscall path runs the AVX helper unbracketed, then (a) our ymm
registers are silently replaced with kernel data, and (b) that data is recoverable entirely in
userland: libc may already contain a ymm store (any AVX memcpy does), so the chain is
  marker -> syscall -> dump ymm0..15 via fcall_with_rax(store_gadget, 0, buf, 0, 0)
and the dumped 32 bytes per register are kernel float constants, kernel stack words, or kernel
pointers, depending on what the helper loaded. 512 bytes per sweep, no native exec, no kernel bug
of the usual memory-safety kind, and no cache timing.

### 4.3 Probe 1071a (the single cheapest discriminating measurement)
A: scan libc for c5 fc 11 / c5 fe 7f / c5 fc 10 and print hits; if there is no ymm store in the
   whole game image, stop: the leak cannot be harvested from this process (H1 = DEAD, H4 = DEAD).
B: calibrate: put a 32-byte pattern in ymm0 (libc memcpy of 64 B, or the load gadget), dump it
   back, confirm a byte-exact round trip.
C: for sc = 1..679: set marker, make_syscall(sc, benign args), dump ymm0/1, compare. Log any
   mismatch with the bytes.
D: for each mismatch, repeat 100x: stable bytes = kernel rodata/stack (a read primitive); varying
   bytes with pointer shape = kernel heap/stack (a KASLR + memory read primitive).
E: for the winning syscall, dump all 16 ymm registers (16 fcall steps) = up to 512 bytes.
Expected outcome if the kernel is well behaved: zero mismatches everywhere - which is a *cheap*
and complete refutation of this whole class, and worth having in writing.

## 5. H2 (new, ranked 2): the 625/626 PMC surface as a hardware cache oracle

### 5.1 Measured state
- 625 admits commands 17..23 and accepts only (arg1,arg2) in {0x0D,0x0E,0x0F,0x10} x {1,2,3};
  it programs the L2 PMC bank (MSR window 0xc0010231+2i, helper at 0x605000 computes
  lea ecx,[r14+r14-0x3ffefdcf] = 0xc0010231+2*index; 626 body ffffffff8afc4cf0).
- 626 cmd 5 idx 0..3 reads 0xc0010241+2i, all zero. 626 cmd 6 (626(6,0,0,p4,p5)) returns 0 and
  writes **8 live 32-bit counters**, high dwords zero: p4 = 46DC0497, 2A7F371A, 2D574472, 2C349CA8;
  p5 = 99373B94, 866CA5E2, 94DE7430, 94B25CF2, each advancing (+0x1D9E3 per call in slot 0),
  idx>0 -> -1, p4==p5 allowed, NULL/unmapped page -> -1 (probe 796d, 2026-10-26).
- 566/567 give a per-thread 64-bit slot array: 566(tid,idx,val) then 567(tid,idx,out) round-trips
  idx 0..7 exactly, idx>=8 reads 0xEEEEEEEEEEEEF000, 565 stores a selector that 567 reads back as
  0xA5A600000000, out must be a user pointer (probes 327a 2026-10-22, 983a 2026-11-03, 983b).
- docs/ATTACK_SURFACE.md:190-191 lists 625/626 as -1; that is superseded by 327a/796d on 14.10
  (the earlier probe used a different argument shape).

### 5.2 Hypothesis
Eight counters that advance on every call and never carry a high dword are either (a) 32-bit
cycle counters per core (a TSC/APERF view) or (b) real event counters (L2 accesses/misses, core
events). If (b), we own a hardware observation channel: no timing noise, no rdtsc, no clflush,
and it would let us count the cache events of kernel work - the missing piece of every attack in
this class. If (a), we still get a cycle-resolution timestamp sampled inside the kernel, which is
the only way to do aggregate timing (the wall-clock route is dead: clock_gettime(232) costs
92-95 us per call, probe 56j, docs/ALL_RESULTS.md:9299-9300, and address-dependent write()
differences are only 1-3%, so a 10 ns signal is four orders of magnitude below the floor).

### 5.3 Probe 1072a (the single cheapest discriminating measurement)
For each of the 12 accepted (arg1,arg2) shapes: 625(cmd,arg1,arg2,0) then
  read 626(6) -> A; 10k dependent loads over a 4 KB buffer (L1) -> read -> B;
  10k over 512 KB (L2) -> read -> C; 10k over 64 MB (DRAM) -> read -> D.
Decision table per counter slot:
- D > C > B: event counter on memory hierarchy -> H2 confirmed, build the oracle on it.
- all equal but scaling with wall time: cycle counter -> usable as a timestamp only (aggregate
  timing, 1073a below).
- all zero: the counters are not ours to read -> H2 DEAD, and nothing else in this class survives.
Cost: one probe, seconds, no crash risk.

## 6. H3 (ranked 3): L1 same-offset Prime+Probe, calibrated on the timezone table

Set math that makes this cheap: Zen 2 L1D is 32 KB / 8-way / 64 sets, so the set index is VA bits
6..11 - entirely inside the 4 KB page offset. Therefore the set of a kernel line is computable
from its *page offset alone*, which is KASLR-invariant, and a userland line at the same page
offset lands in the same set. No physical address, no kernel address, no KASLR knowledge needed.
The timezone table (14.10: VA 0xffffffff8e2d5920, RVA 0x42d5920, page offset 0x920; count at
0xffffffff8e2d7920, mode 0x47105b0, lock 0x42d5900, 260 records x 16 B = 0x1040;
docs/TZ_TABLE_638_14_10.md:31-35,248-253) gives record i at page offset 0x920+16i, so
set(i) = ((0x920 + 16i) >> 6) & 0x3f.
Calibration signal is *known*: we choose the input, the key->record map is measured (1161a/1164a),
so we know exactly which set the kernel's binary search touches on each call. That turns 638 into
a reference transmitter for the oracle: prime our line in set(i), call 638(input for record i),
re-time our line. If hot/cold separates on a known signal, the oracle works; if it does not, no
cache attack of any kind exists on this image.
Gate: needs a timer. 1072a decides that (either an event counter or a cycle counter); otherwise
the rdtsc gadget hunt of 3.3 decides. Without one of those, H3 is DEAD by arithmetic.

## 7. Ranked recommendations, with the first console action
1. Probe 1071a (H1). Cheapest possible path to a genuine kernel read from pure userland.
   Falsifiable in one run; a clean negative also closes Zenbleed-on-this-image for good.
2. Probe 1072a (H2). Decides whether *any* cache oracle exists; every timing-based idea in this
   repo's backlog depends on the answer.
3. Probe 1073a (the libc gadget census of 3.3). Cheap, reusable, and it is the only route to
   rdtsc/clflush/cpuid/syscall without native exec.
4. Only then: 1074a (H3 calibration) with whichever timer 1072a/1073a produced.
5. Do not spend anything on: Zenbleed PoC work (NEEDS-NATIVE-EXEC, wrong target), Spectre v1 on
   638/639 (DEAD by disassembly), Lua wall-clock timing (92 us floor).

## 8. Open contradictions and hazards found while writing this
- Loop feasibility: docs/AIO_RANGE_14_10_EVIDENCE.md:121-139 (872a, 3000-4000 rounds, no death)
  vs docs/CHANGELOG.md:363-366 (882a-885a, pop rsp reset dies, 500-call chain dies). Reconcile by
  using the read(2)-parked loop shape; do not assume a bare re-pivot loop is safe.
- 620: docs/ATTACK_SURFACE.md:185 measures free_stack ret 0, while TODO.md:104-110 describes a
  kernel VM self-modification with MODE 5 on (saved_rip-0x80)&~0x3fff - i.e. a possible W^X
  bypass. Probe 99a sections B/C were written but never run. This is the cheapest route to native
  exec, and native exec would unlock every technique this memo marks NEEDS-NATIVE-EXEC.
- 625/626: ATTACK_SURFACE.md:190-191 says -1, 327a/796d say 0 with live counters; trust the later
  measurement but keep the argument-shape difference in mind when writing new probes.
- sysent_raw.bin cannot map handlers to call sites: all 679 sy_call entries sit in RVA
  0x265760-0x266xxx (stubs), far below the AVX call sites (0x331de9 and up). Probe 1071a's sweep
  is therefore also the only way to learn which syscalls enter the AVX helper.

## 9. Closed here, do not re-derive
- /dev/cpuctl, /dev/msr, /dev/mem: absent/refused (DEVFS docs).
- Loader has no cpuid/feature/rdtsc export (native.lua grep, 0 hits).
- clock_gettime(232) wall clock: 92-95 us per call, insufficient for cache work.
- 638/639 arithmetic: no secret-dependent address, no gathering load, table fully public and
  bounded to [table, table+0x1040).
- Kernel copyout path is scalar (stac/rep movsq/rep movsb/clac), no vector state.