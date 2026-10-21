# Novel Combined Attack Chains — PS5 14.10

> **Date:** 2026-10-21
> **Context:** Phase 22 threading-enhanced probes. All chains combine 2+ vectors
> from different subsystems. These are THEORY — no probes written yet.
> **Prerequisite:** thr_create(430) with CS=0x43/SS=0x3B confirmed working (PR #60).

---

## Chain 1: GHOST HANDLE — fd Refcount Leak × Handle Namespace Type Confusion

### Vectors combined
- CVE-2019-5607 fd refcount leak (socketpair + SCM_RIGHTS)
- Handle namespace type confusion (sys 557/558 at process+0xc48)
- Threading (thr_create for parallel fd pump)

### The insight
CVE-2019-5607 alone needs ~4 billion iterations to overflow uint32 f_count —
impractical even with threads. But the GOAL isn't overflow: it's creating a
**temporarily elevated refcount** on a struct file, then closing the fd while
the socket buffer still holds references. The dangling struct file stays
allocated in the kernel slab cache.

Meanwhile, the handle namespace at process+0xc48 shares slab caches across five
subsystems with ZERO credential checks. If struct file and IPC objects (event
flags ~0x80 bytes, semaphores ~0x60 bytes) share a slab size class, we can
reclaim the dangling struct file's memory with an IPC object.

The type confusion is bidirectional: operations through the extracted
SCM_RIGHTS fd hit the old struct file layout, while IPC operations (sys 540
ef_open, sys 551 sem_post) hit the same memory as an IPC object. Field overlap
at different offsets gives a controlled read/write primitive.

### Step-by-step chain
```
1. socketpair(135) → sv[0], sv[1]
2. target_fd = socket(97, AF_INET, SOCK_STREAM)
3. Thread B (157a spinner on gettimeofday) — scheduling pressure
4. Main thread: loop N times sendmsg(28, sv[0], SCM_RIGHTS=[target_fd])
   → each send calls fhold(target_fd), refcount climbs
5. setsockopt(105, sv[1], SO_RCVBUF, 1) — shrink receive buffer
6. Continue sending → buffer full → EAGAIN → fhold fires but delivery fails
   → refcount leaks (THE BUG: no fdrop on error path)
7. close(6, target_fd) — decrements refcount by 1, but leaked refs keep
   struct file alive in kernel slab
8. Spray IPC objects: sys 538 (ef_create) × 64 — event flags (~0x80 bytes)
   target the same slab cache as struct file
9. recvmsg(27, sv[1]) — extracts fd referencing the OLD struct file memory,
   which is now an event flag object
10. getsockopt(118) on the confused fd → reads event flag internals as
    struct file fields → kernel heap pointers leak (KASLR defeat)
11. setsockopt(105) on the confused fd → writes to event flag at struct
    file offsets → controlled kernel write
```

### What it achieves
- Kernel heap pointer leak (KASLR defeat) via confused getsockopt
- Controlled kernel write via confused setsockopt
- No need for full uint32 overflow — partial refcount elevation + close is enough

### Probability assessment
- **CVE-2019-5607 reachable on 14.10:** MEDIUM-HIGH (13.60 binary confirmed
  unpatched, 14.10 timeline tight for Sony to backport)
- **Slab overlap between struct file and IPC objects:** MEDIUM (depends on
  FreeBSD zone allocator size classes — both are 64-128 byte objects)
- **Overall:** MEDIUM — strongest if probe 89a Section A confirms SCM_RIGHTS works

### Required probes
- 89a Section A (SCM_RIGHTS reachability)
- 89a Section B (refcount leak verification)
- 88b Section A (IPC syscall reachability — event flags, semaphores)
- 88a Section B (sys 557 generic object creation)

---

## Chain 2: DUAL VECTOR — sys 620 VM Self-Mod × sys 617 HW Write × sys 563 PMU Bypass

### Vectors combined
- sys 620 (VM self-modification, zero args, no credential check)
- sys 617 (hardware register write, 1 byte, no credential check)
- sys 563-566 (PMU enable/disable, selector=0 bypasses credentials)
- Threading (child thread shifts sys 620's target page)

### The insight
sys 620 computes its target page from the caller's saved RIP:
`(saved_RIP - 0x80) & ~0x3fff`. From the main thread this targets an eboot
page; from a child thread (libkernel gettimeofday wrapper) it targets a
libkernel page. Two DIFFERENT VM objects get hit by the same mode-5 operation.

sys 617 writes a byte to hardware MMIO (base+0x25310) with no auth. The
written byte goes through a lookup table — 256 possible hardware states. If
ANY of those states controls a global permission predicate (like the gate at
`(~global_u32[0x8e681390]) & 1` that guards sys 617 itself), it could toggle
kernel enforcement.

sys 563 (PMU enable, selector=0) sets bit 22 in performance counter MSRs.
PMC-based Performance Monitor Interrupts (PMIs) fire into the kernel's NMI
handler. If we can trigger a PMI while sys 620's VM operation is in-flight,
the NMI handler might execute in a context where page protections are
transiently modified.

### Step-by-step chain
```
Phase A — Baseline:
1. sys 547 (VM region query) on eboot code page → record protection bits
2. sys 547 on libkernel code page → record protection bits
3. sys 624 (VM op counter) → baseline count

Phase B — Hardware state sweep:
4. for byte = 0..255:
     sys 617(byte)           — write hardware register
     sys 620()               — VM self-mod on eboot page
     sys 547 on eboot page   — check if protection changed
     sys 624                 — check if VM counter advanced
   → Find which byte values cause sys 620 to ACTUALLY modify page attrs

Phase C — Dual-thread page targeting:
5. thr_create(430) child → gettimeofday loop in libkernel
6. sys 617(winning_byte) from Phase B
7. sys 620() from main thread → targets eboot page
8. sys 620 from... BUT child can only loop ONE syscall.
   WORKAROUND: create child with RIP pointing to a syscall;ret gadget
   that calls sys 620 instead of gettimeofday. The child's saved RIP
   will be inside its OWN code page, not libkernel.
   → sys 620 targets a THIRD page (our mmap'd code page)

Phase D — PMU race amplification:
9. sys 563(selector=0) → enable PMC on current thread
10. sys 565(selector=0) → configure event selector for retired instructions
11. Set counter near overflow → PMI fires during next sys 620 execution
12. NMI during VM operation = transient protection state
13. mprotect(74, page, PROT_READ|PROT_WRITE|PROT_EXEC) — try W^X bypass
```

### What it achieves
- W^X bypass via VM page attribute modification (mode 5)
- Hardware-assisted race amplification via PMU NMI
- Arbitrary code execution if mprotect(RWX) succeeds after mode-5 change

### Probability assessment
- **sys 620 actually modifies page attrs:** LOW-MEDIUM (mode 5 might be a
  no-op or a cache flush, not a protection change)
- **sys 617 byte affects permission predicates:** LOW (hardware register
  likely controls display/GPU, not security)
- **PMU NMI during VM operation:** LOW (timing is extremely tight)
- **Overall:** LOW — but the payoff is direct W^X bypass, worth the probe time

### Required probes
- 99b Section A (sys 620 reachability + VM counter observation)
- 99b Section B (sys 620 + mprotect retest)
- 99a Section A (sys 617 reachability + byte sweep)
- Phase22 probe 99b (threaded sys 620)
- 89a Section A (sys 625 MSR reachability — related PMC subsystem)

---

## Chain 3: SLAB ORACLE — GPU cmd 0x20 KASLR Leak × Handle UAF × sendsig() Frame Write

### Vectors combined
- GPU sys 532 cmd 0x20 (48-byte config copyout, potential kernel pointers)
- Handle namespace cross-subsystem UAF (event flag → semaphore spray)
- sendsig() trap frame write to controlled RSP (thr_create + GPU mmap)
- sys 624 VM op counter as side channel

### The insight
Three independent KASLR defeat paths feed into one exploitation chain. The
redundancy matters because any single leak path might be patched, but all
three being patched is unlikely:

1. **GPU cmd 0x20** copies 48 bytes of GPU subsystem config. If ANY qword
   is a kernel .text or heap address, KASLR is defeated with one syscall.

2. **Handle UAF poll**: after cross-subsystem UAF (create event flag →
   delete → spray semaphores → poll stale handle), the poll output may
   contain the semaphore's internal waitq linked-list pointers — these are
   kernel heap addresses.

3. **sendsig() frame write**: thr_create a child with RSP pointing into
   GPU mmap pages. When the child faults, sendsig() writes the ENTIRE
   trapframe (including pcb_fsbase, pcb_gsbase, segment base addresses)
   to RSP-128 in our GPU pages. These PCB values are kernel addresses.

Once KASLR is defeated by ANY of the three, the handle UAF write primitive
becomes targeted: we know WHERE kernel structures live, so we can corrupt
specific function pointers or credentials.

### Step-by-step chain
```
Phase 1 — Triple KASLR oracle:
1a. sys 532(cmd=0x20, output_buf) → scan 6 qwords for 0xFFFF8... prefix
1b. sys 538(ef_create) → delete → sys 549(sem_create) × 16 → sys 543(ef_poll)
    on stale handle → scan output for kernel heap pointers
1c. thr_create(430) with RSP=gpu_mmap_addr+0x1000, RIP=0xDEAD
    → child faults → sendsig() writes trapframe to gpu_mmap_addr+0x1000-128
    → read pcb_fsbase/pcb_gsbase from GPU pages

Phase 2 — KASLR slide calculation:
2. kernel_base = leaked_text_ptr - known_offset (from 13.60 symbols)
   heap_base_range = leaked_heap_ptr & ~0xFFFFF (page-align estimate)

Phase 3 — Targeted UAF exploitation:
3. Create event flag → delete → spray semaphores
4. Signal stale event flag handle → writes into semaphore at wrong offsets
5. With KASLR defeated: write a known kernel function pointer address
   into the semaphore's corrupted field
6. sem_post on the corrupted semaphore → kernel follows corrupted pointer
   → redirected execution

Phase 4 — Kernel code execution:
7. sys 624 counter before/after each step as progress oracle
8. If redirected: pivot to kernel ROP using leaked text base
```

### What it achieves
- Redundant KASLR defeat (3 independent paths)
- Targeted kernel write via handle UAF (not blind heap corruption)
- Potential kernel code execution via corrupted function pointer

### Probability assessment
- **At least ONE KASLR path works:** HIGH (three independent sources)
- **Handle UAF gives a write primitive:** MEDIUM (depends on handle
  invalidation behavior — stale handle might be rejected)
- **Targeted code execution:** MEDIUM-LOW (requires precise offset knowledge
  from 13.60 matching 14.10)
- **Overall:** MEDIUM — the triple oracle is the novel contribution

### Required probes
- 87b Section B (GPU cmd 0x20 KASLR scan)
- 88b Section C (cross-subsystem UAF)
- Phase17 probe 78c (sendsig frame write to GPU mmap)
- 87a Section A (GPU command reachability)
- 88a Section A (IPC syscall reachability)

---

## Chain 4: THREAD FORGE — thr_create Heap Spray × kldsym KASLR × CVE-2020-7457 IPv6 UAF

### Vectors combined
- thr_create(430) rapid spray (kernel struct thread slab fill)
- kldsym(337) instant KASLR defeat (if reachable)
- CVE-2020-7457 IPv6 setsockopt race (ip6_pcbopts UAF)
- Threading for concurrent setsockopt race

### The insight
CVE-2020-7457's UAF frees `in6p_outputopts` — a small kernel heap allocation.
The freed memory enters the slab free list. If we can predict or control what
REPLACES it, we turn a UAF into a controlled object.

thr_create(430) allocates struct thread (~1KB) from the thread slab. But
struct thread ALSO contains embedded sub-objects at known offsets:
`td_sigacts`, `td_ucred`, `td_proc` pointers. When the thread is destroyed
(after fault), these sub-structures may be freed separately, creating
smaller allocations in the same slab caches as in6p_outputopts.

The sequence: spray threads → trigger IPv6 UAF → freed in6p_outputopts
reclaimed by a thread sub-object → setsockopt reads/writes the thread's
internal pointers through the in6p_outputopts interface.

kldsym(337) provides the kernel addresses needed to make the write targeted.
Without kldsym, the write is blind; with it, we can overwrite specific
kernel credentials (ucred at known offset from allproc).

### Step-by-step chain
```
Phase 1 — KASLR defeat:
1. kldsym(337, 0, 1, "allproc") → kernel address of process list
2. kldsym(337, 0, 1, "prison0") → root jail address
3. If kldsym blocked: fall back to GPU cmd 0x20 or sendsig() oracle

Phase 2 — Thread slab priming:
4. thr_create(430) × 8 with different controlled RSP/RIP values
   → 8 struct thread objects allocated in kernel slab
5. Let threads fault → cleanup frees sub-objects (sigacts, ucred refs)
   → smaller freed chunks enter slab free lists

Phase 3 — IPv6 UAF trigger:
6. fd = socket(97, AF_INET6, SOCK_DGRAM, 0)
7. thr_create(430) → child thread (Thread B)
   BUT child can only loop ONE syscall... so:
   WORKAROUND: Thread B loops setsockopt(105) by using make_syscall
   from the MAIN thread in a tight interleave pattern:
     Main: setsockopt(fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, data_A)
     Main: setsockopt(fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, data_B)
   The child thread provides SCHEDULING PRESSURE (gettimeofday loop)
   that widens the race window between the two main-thread calls.
8. ip6_pcbopts race: old opts freed, new opts allocated
   → freed in6p_outputopts reclaimed by thread sub-object from Phase 2

Phase 4 — Controlled read/write:
9. getsockopt(118, fd, IPV6_2292PKTOPTIONS) → reads thread sub-object
   fields through in6p_outputopts layout → kernel pointer leak
10. setsockopt(105, fd, IPV6_2292PKTOPTIONS, crafted_data)
    → writes to thread sub-object at in6p_outputopts offsets
11. With KASLR defeated: target ucred→cr_uid field → set to 0 → root
```

### What it achieves
- Privilege escalation via ucred corruption (uid=0)
- Thread heap spray provides PREDICTABLE reclaim objects
- kldsym gives targeted writes (not blind corruption)

### Probability assessment
- **kldsym(337) reachable:** MEDIUM (never tested in isolation — 57c unrun)
- **CVE-2020-7457 reachable:** MEDIUM (AF_INET6 confirmed, IPV6_2292PKTOPTIONS
  untested)
- **Thread sub-object reclaims in6p_outputopts:** LOW-MEDIUM (slab size class
  alignment uncertain)
- **Overall:** LOW-MEDIUM — high payoff (direct root) if kldsym + IPv6 work

### Required probes
- 57c (kldsym direct test)
- Phase22 probe for CVE-2020-7457 (not yet written)
- 88b Section A (thread creation works, known from PR #60)
- 87b Section B (fallback KASLR via GPU)

---

## Chain 5: MIRROR WORLD — GPU PTE W^X Bypass × _umtx_op UAF × CClosure Redirect

### Vectors combined
- GPU PTE modification via sys 653 (no priv_check) + sys 547 (VM region query)
- _umtx_op(454) UMTX_OP_SHM race (CVE-2024-43102, CVSS 10.0)
- CClosure +0x20 function pointer redirect (confirmed writable)
- sys 624 VM op counter as progress oracle

### The insight
The individual vectors each have a critical weakness alone:
- GPU PTE bypass (sys 653) can make a page writable but we need something
  to WRITE there (and the page must also be executable)
- _umtx_op UAF gives kernel heap R/W but needs KASLR and a target
- CClosure redirect can call arbitrary function pointers but only within
  the existing W^X constraints (we can jump but not inject code)

Combined: _umtx_op UAF provides the KASLR leak (freed shmfd contains kernel
pointers). GPU PTE bypass makes our code page writable (defeating W^X). Then
we write actual shellcode to the now-RWX page. CClosure redirect jumps to it.

The key insight is the ORDER: UAF first (for KASLR), PTE second (for W^X),
shellcode write third, CClosure jump fourth. Each primitive's weakness is
covered by another primitive's strength.

### Step-by-step chain
```
Phase 1 — Verify umtx_op reachability:
1. make_syscall(454)(0, 0x10, 0x1, 0, 0)
   → UMTX_OP_SHM + UMTX_SHM_CREAT
   → if rv >= 0: _umtx_op is LIVE

Phase 2 — KASLR defeat via umtx_op UAF:
2. Thread A: UMTX_OP_SHM + UMTX_SHM_CREAT → creates shared memory
3. Thread B (scheduling pressure via gettimeofday loop)
4. Main thread: rapid UMTX_SHM_DESTROY + UMTX_SHM_LOOKUP cycle
   → UAF on shmfd → read kernel pointers from stale mapping
5. kernel_base = leaked_ptr - known_offset

Phase 3 — GPU PTE W^X bypass:
6. mmap(477) a page (RW, anonymous)
7. sys 547 on the page → read current VM object type + protection bits
8. sys 653(page_addr) with various arg0 values
   → if ret=0: GPU PTE modification succeeded
9. sys 547 again → check if protection bits changed
10. If execute bit now set: page is RWX → W^X defeated

Phase 4 — Shellcode injection:
11. Write x86-64 shellcode to the now-RWX page:
    - setuid(0) via direct syscall
    - or: overwrite ucred at kernel_base+offset (from Phase 2)
    - or: call kernel's kexec with our payload

Phase 5 — CClosure redirect to shellcode:
12. Read CClosure at Lua C function +0x20 → saved function pointer
13. Write shellcode page address to CClosure +0x20
14. Call the Lua C function → dispatch follows +0x20 → our shellcode
15. sys 624 after each step → monotonic counter confirms kernel
    operations occurred

Phase 6 — Verification:
16. getuid() → if 0: root achieved
17. Or: execute payload that patches kernel security flags
```

### What it achieves
- Full chain: KASLR defeat → W^X bypass → arbitrary code execution → root
- Each primitive covers another's weakness
- sys 624 as progress oracle at every step

### Probability assessment
- **_umtx_op(454) reachable:** UNKNOWN (ops 5 and 21 work, SHM untested —
  probe 110a prepared)
- **sys 653 modifies GPU PTE:** MEDIUM (no priv_check confirmed in entry,
  but the operation might be a no-op without GPU context)
- **CClosure redirect works:** HIGH (confirmed writable in prior probes)
- **Overall:** LOW — requires ALL three vectors to work, but the payoff is
  a complete jailbreak chain from userland to kernel root

### Required probes
- 110a (_umtx_op SHM race test)
- 98b Section A (sys 547 VM region query on GPU mmap)
- 98b Section B (sys 653 reachability)
- 98b Section C/D (PTE modification + W^X bypass)
- 84a Section A (sys 653 reachability)
- 87b Section B (GPU cmd 0x20 as fallback KASLR)

---

## Cross-Reference Matrix

| Chain | KASLR defeat | Write primitive | Code exec | Threading | Crash risk |
|-------|-------------|-----------------|-----------|-----------|------------|
| 1 GHOST HANDLE | getsockopt confusion | setsockopt confusion | indirect (ptr overwrite) | optional (pump speed) | LOW |
| 2 DUAL VECTOR | — (not needed for W^X) | sys 620 mode 5 | mprotect RWX | required (dual target) | MODERATE |
| 3 SLAB ORACLE | triple oracle (GPU/UAF/sendsig) | handle UAF signal | ptr redirect | required (sendsig) | MODERATE |
| 4 THREAD FORGE | kldsym (instant) | IPv6 UAF reclaim | ucred corruption | required (race) | MODERATE |
| 5 MIRROR WORLD | umtx_op UAF | GPU PTE W^X | CClosure + shellcode | required (umtx race) | HIGH |

## Priority for Console Testing

1. **Chain 1 (GHOST HANDLE)** — least dependencies, lowest crash risk, strongest
   individual vectors. Test 89a-A first (SCM_RIGHTS), then 88b-A (IPC reachability).

2. **Chain 3 (SLAB ORACLE)** — triple KASLR oracle is independently valuable even
   if the UAF write fails. Test 87b-B (GPU cmd 0x20), then 88b-C (handle UAF).

3. **Chain 5 (MIRROR WORLD)** — highest payoff (full chain) but most dependencies.
   Test 110a (_umtx_op SHM) and 98b-A/B (GPU PTE) first — they gate everything.

4. **Chain 4 (THREAD FORGE)** — depends on unrun probe 57c (kldsym). Run 57c first;
   if kldsym works, this chain jumps to #1 priority.

5. **Chain 2 (DUAL VECTOR)** — lowest individual probability but unique approach
   (hardware-assisted race). Run after higher-probability chains are tested.
