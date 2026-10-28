# Exploit Strategy Assessment — PS5 14.10

> **Last updated:** 2026-10-25 (consolidated review)

## Current Position (2026-10-25) — Direct KASLR Spray via AIO Free

The goal is unchanged: userland code execution → kernel R/W → hypervisor bypass.

**PIVOT (2026-10-25):** All AIO race paths are closed (see below). The exploit
strategy pivots from race-based double-free to **direct KASLR spray**: 662 deletes
an AIO request object (R, 48B in a 64B UMA zone) whose R+0x00 and R+0x08 fields
contain kernel thread addresses (`curthread+0x390`, `curthread+0x08`) that are NOT
zeroed before `uma_zfree`. After 662 frees R, spray matching-size objects to reclaim
the slot and read back the surviving kernel pointers through the spray object's
readback interface. **No race condition is required.**

See `docs/AIO_DOUBLE_FREE_14_10.md` for the full AIO write-up and race closure details.

### Primary Exploit Chain (Active — Revised 2026-10-25)

```
                         ┌─ HAVE ─┐          ┌─ NEED ─┐
userland code exec ──►   AIO 662     ──►   heap spray   ──►   KASLR defeat  ──►   kernel R/W   ──►   HV bypass
(Lua loader)             free R obj        reclaim R's         read kptr from       via gadgets        (Byepervisor)
                         (single call)     64B UMA slot        spray readback       (eboot ROP)
```

**Stage 1 — Free R (HAVE):** A single 662 call deletes an AIO request, freeing R
(48B, 64B UMA zone). R+0x00 = `curthread+0x390` and R+0x08 = `curthread+0x08` are
kernel thread addresses NOT zeroed before `uma_zfree` (verified 13.60 decompile).
No race needed — one 662 call on a polled ID is sufficient.

**Stage 2 — Spray & Reclaim (NEXT):** After 662 frees R, spray matching-size (64B
bucket) kernel allocations to reclaim R's slot. The spray object overwrites R's
memory, but the question is whether R+0x00/R+0x08 survive the spray constructor.
Candidates for 64B zone spray:
- `namedobj_create(557)` — 48B objects, same zone as R
- `evf_create(538)` — needs size measurement (probe 69l via sys 624 oracle)
- `IP_OPTIONS setsockopt` — controlled data in matching-size allocation
- A (id array, 48B) — same zone as R, freed alongside R

**Stage 3 — KASLR Defeat:** Read back through the spray object's readback interface
to expose the kernel thread addresses that survived at R+0x00/R+0x08. This gives a
`curthread` kernel address, defeating KASLR.

**Stage 4 — Kernel R/W:** With a kernel address, use eboot ROP gadgets (read gadget
scan, probe 69m) for arbitrary kernel memory reads/writes.

**Stage 5 — Hypervisor:** With kernel R/W, apply Byepervisor technique.

### Primitives That Exist

| Primitive | Evidence | Limits |
|---|---|---|
| Lua code execution on TCP 9026 | loader | userland only |
| **★ AIO R-object free (KASLR target)** | 662 frees R with kernel ptrs at +0x00/+0x08 | requires 669 submit + 664 poll; race paths closed (72c) |
| Arbitrary tested syscall invocation | `make_syscall` | kernel-side checks still apply |
| Child thread ROP syscalls (4-arg) | 271g/272a | pop rax/rdi/rsi/rdx/rcx; no r8/r9 = max 4 args |
| thr_new(455) with arg delivery | 56l | rdi=arg, simpler than thr_create(430) |
| GPU pool mapping, userland R/W | 477 with flags `0x1002` | 384 MiB max, zeroed on alloc (348a) |
| CClosure function redirect | 56c/56f, 56d-56d7 | selected Lua C targets + eboot gadgets |
| native.fcall_with_rax | 129b | arbitrary userland function calls |
| POSIX shm (shm_open/ftruncate/mmap) | 391a-391d | MAP_SHARED works; shm_open2(571) is nosys |
| EVFILT_TIMER + socketpair pipeline | 271i | kqueue works with timers and AF_UNIX |
| Event and named objects | 538/540/544-546, 557 | process-scoped (342a) |
| sys 624 VM operation counter | 52b | +5 per mmap, zero jitter; side channel |
| Userland module-base discovery | 593 on 39 modules | kernel ASLR is separate |

### Walls That Are Measured

- **W^X enforced at hypervisor level** — mprotect(EXEC) refused; mmap(RWX) strips
  EXEC; sys 588 accepts but PTE never gets execute bit (124a). No bypass path exists.
- **No kernel pointer** — exhaustive scan across every accessible syscall, all CTL_*
  sysctl trees, device ioctls (32M calls), signal frames, routing sockets,
  getsockopt, fstat, ucontext, ancillary data — zero kernel pointers found.
- **No KASLR defeat** — 17+ techniques tested, all dead. GPU pages zeroed (348a),
  NET_RT_DUMP false positives (56e2), timing noise only (56h-56i2).
- **The jail holds** — authid gates (535/536/563-566), credential bit 62 (618/646/671),
  device context empty (532/622), fork/rfork blocked.
- **kld* family lethal** — kldstat(308), kldnext(307), kldsym(337) all kill on touch.

## AIO Race Paths Closed (2026-10-25)

All AIO race-based exploitation paths are confirmed dead:

- **662-vs-663 race (72a-72c):** 663's waiter holds a refcount on Q via atomic
  XADD.LOCK at `0x3b3ec8` — `entry_dispose` sees non-zero refcount and skips free.
  20/20 CLEAN in probe 72c with simultaneous-wake gate approach. The dangling-waiter
  UAF hypothesis does not hold: Q is reference-counted, not ownership-transferred.
- **662-vs-662 race (65l):** The double-SUCCESS reports are double-STATUS only —
  Thread B finds NULL after Thread A clears the slot. The D exclusive lock serializes
  the actual free path. 65l is a TOCTOU on the status check, not on the free.
- **3-thread slot reuse (69g):** Generation-checked IDs (71a) block slot reuse.
  After 662 frees an ID, the generation counter increments; a new 669 submit gets a
  new generation, and the old ID resolves to nothing. Thread B cannot re-free C's
  new objects because the stale ID fails the generation check.

**Conclusion:** The AIO subsystem's locking and reference counting are robust against
all tested race patterns. The exploit path pivots to direct KASLR spray, which does
not require any race condition.

## Direct KASLR Spray (No Race Needed)

The KASLR leak does NOT require any race condition. The key insight from the 13.60
decompile verification (`docs/2026-10-25/VERIFICATION_DECOMPILE.md`):

**R sub-object kernel pointer residue:**
- R+0x00 = `curthread+0x390` (kernel thread address, written during AIO submission)
- R+0x08 = `curthread+0x08` (kernel thread address, written during AIO submission)
- R+0x10 is zeroed before free, but R+0x00 and R+0x08 are NOT
- R is 48B, allocated from a 64B UMA zone bucket (zone `0x1ab59e0`)

**Attack flow (single-threaded, no race):**
1. Submit AIO request via 669 → kernel allocates R, writes `curthread` addresses
2. Poll via 664 → request completes
3. Delete via 662 → R is freed back to UMA zone; kernel pointers survive in freed memory
4. Spray matching 64B-zone objects (namedobj, evf, IP_OPTIONS) to reclaim R's slot
5. Read back through the spray object's readback interface → exposed kernel pointers

**Critical unknowns:**
1. **Do spray objects land in R's 64B zone?** Probe 69l measures via sys 624 VM
   operation counter. namedobj (557) creates 48B objects — same nominal size as R,
   likely same zone. evf (538) size unknown.
2. **Does the spray constructor overwrite R+0x00/R+0x08?** The spray object's
   initialization may or may not touch those specific offsets. If the spray object
   is smaller or has a different layout, the kernel pointers may survive at offsets
   the spray object does not initialize.
3. **What readback interface exposes those bytes?** Probe 69d tests reading through
   namedobj/evf/setsockopt readback. For namedobj, `namedobj_delete(558)` or a
   hypothetical query call may expose internal bytes. For evf, the event flag read
   calls (544/545/546) return the flag value which may overlap with R+0x00.
4. **Eboot read gadget for post-KASLR kernel reads:** Probe 69m scans eboot for
   `mov rax,[rdi];ret` or equivalent gadgets usable with `native.fcall_with_rax`
   to read arbitrary kernel memory once a KASLR base is known.

**AIO freed object hierarchy (verified 13.60):**

| Object | Size | Zone | Contains after free |
|--------|------|------|---------------------|
| R (request) | 48B | 64B (`0x1ab59e0`) | **R+0x00 = curthread+0x390, R+0x08 = curthread+0x08** |
| I (entry) | 88B | 128B (`0x1ab5900`) | sync object, file refcount |
| Q (queue) | 88B | 128B (`0x1ab5970`) | completion header (ref-counted) |
| A (id array) | 48B | 64B (`0x1ab5a50`) | ID storage |

## Remaining Challenges (2026-10-25, Updated)

1. **Spray zone matching** — must confirm namedobj/evf/IP_OPTIONS land in R's 64B
   UMA zone on 14.10 (13.60 analysis says 48B → 64B bucket, but 14.10 may differ).
   Probe 69l uses sys 624 VM-op oracle to measure.
2. **Readback interface** — need a syscall that reads back bytes from the spray
   object at offsets overlapping R+0x00/R+0x08. Probe 69d tests candidates.
3. **Spray constructor behavior** — the spray object's init may overwrite the kernel
   pointers at R+0x00/R+0x08. Must characterize what each spray candidate writes.
4. **No 14.10 kernel image** — every handler dossier is 13.60; probes are cross-build
   guesses. A kernel dump would reveal the exact layout and optimal spray target.
5. **W^X at hypervisor level** — no RWX pages possible; all code execution must be
   via ROP or existing gadgets.
6. **Read gadget** — need `mov rax,[rdi];ret` or similar in eboot for kernel memory
   reads after KASLR defeat. Probe 69m scans.

## Current Priorities (2026-10-25, Revised — Direct KASLR Spray)

### ★ Priority 1: Spray Zone Measurement (probe 69l)

Before spraying, confirm that candidate objects land in R's 64B UMA zone bucket:

1. **Measure namedobj(557) allocation size** — use sys 624 VM-op counter delta
   before/after creating namedobj objects. If delta matches R's zone, namedobj is
   the spray candidate. R is 48B nominal → 64B UMA bucket.
2. **Measure evf(538) allocation size** — same sys 624 oracle. evf objects may be
   larger (88B → 128B bucket), which would NOT reclaim R's slot.
3. **Measure IP_OPTIONS setsockopt** — setsockopt with IP_OPTIONS allocates a
   controlled-size buffer. If the allocation hits the 64B zone, it provides
   attacker-controlled data at R's offsets.

### ★ Priority 2: KASLR Readback (probe 69d)

After spray reclaims R's slot, read back the kernel pointers:

1. **namedobj readback** — if 557 reclaims R, does any call (558 delete, or a query)
   expose bytes at R+0x00/R+0x08? The name string may overlap those offsets.
2. **evf readback** — evf flag read calls (544/545/546) return the flag value. If
   the flag word overlaps R+0x00/R+0x08, the kernel pointer leaks directly.
3. **IP_OPTIONS readback** — `getsockopt(IP_OPTIONS)` reads back the option buffer.
   If it reclaimed R's slot, the kernel pointers are in the returned data.

### ★ Priority 3: Eboot Read Gadget (probe 69m)

Scan eboot's 4.6MB RX .text for gadgets usable for kernel memory reads:
- `mov rax,[rdi]; ret` — direct 8-byte read via `native.fcall_with_rax`
- `mov eax,[rdi]; ret` — 4-byte read
- `movzx eax,[rdi]; ret` — 1-byte read
- Any load-and-return pattern reachable via CClosure +0x20 redirect

### Priority 4: Kernel Image Acquisition

A 14.10 kernel dump would immediately reveal:
- Whether R's zone is identical to 13.60 (64B bucket for 48B objects)
- Whether the spray constructor overwrites R+0x00/R+0x08
- Handler implementations for all 145+ syscalls (currently using 13.60 cross-build)

Investigate: debug stubs, coredump paths, update client HTTP interception.

### Deprioritized (Still Available)

| Vector | Status | Why deprioritized |
|--------|--------|-------------------|
| AIO race exploitation | All paths closed (72a-72c) | 663 refcounted, 662 serialized, gen-check blocks reuse |
| CClosure gadget ROP | Working (56c/56f/56d) | Userland only; KASLR spray is kernel path |
| Network packet injection | RAW socket works | SCTP/IPv6/TCP fuzz found 0 crashes (48a-50d) |
| Native sysent 677-734 | 677 kills at touch | Credential-gated (275b-275d) |
| Device ioctl | 32M calls tested | Zero exploitable commands (273a-287a) |
| System sockets | Compositor protocol mapped | DoS only, no memory corruption (361b-377a) |
| dynlib_dlsym(591) | Never tested with valid args | probe 69k queued, but not on critical path |

## Dead Ends (Do Not Retry)

The full dead-ends list is maintained in CLAUDE.md and `docs/DEAD_ENDS.md`. Key
categories below. See those files for exhaustive per-probe citations.

| Category | Summary |
|----------|---------|
| **KASLR (17+ techniques)** | AF_ROUTE sanitized (53b), kinfo_proc sentinels only (43d), NET_RT_DUMP false positives (56e2), GPU pages zeroed (348a), timing noise (56h-56i2), mincore rejects kernel VA (43l), CClosure stack reads userland only (56d5-56d7), sysctl deep scan clean (56g3), all CTL_* trees clean |
| **W^X bypass** | mprotect(EXEC) refused, mmap strips EXEC, sys 588 accepted but hypervisor blocks PTE execute bit (124a), sys 548 batch VM -1 (55b), sys 643 chicken switches no effect (55a) |
| **Device/driver** | 32M ioctl calls across 31 nodes zero exploitable (273a-287a), all 34 /dev nodes overcopy-clean (387a/387c), GPU mappings unreadable (380a), dmem0/1/2 GPU-only (262a/263a) |
| **Network fuzz** | SCTP 39 variants (48b), IPv6 83 variants (48c), TCP 182 segments (49a), IPv6 frag 280 (49b), exotic protocols 86 (50a) — zero crashes total |
| **CVEs** | CVE-2026-49418 msync dead (58a/58b), CVE-2026-49412 IPV6_MSFILTER removed (50e2/50e3), CVE-2026-45257 KTLS absent (50f), CVE-2026-49427/49428 shm_open2 nosys (391a-391d), CVE-2026-49419 jail -1 (392a), CVE-2026-3038 sa_len=127 no panic (56e), ZDI-26-784 kqueue race 10K+ clean (271g-271i), netcontrol Poops dead (223a-234a) |
| **Syscall families** | kld* lethal (56k4/56k5/171a), osem -1 (252a/253a), jitshm -1 (251a), physhm mapped but unreadable (315a-321a), blockpool no mapping (183a/191a), sys 601 debugger no session (322a-324a), sys 622 device control no context (241a-247a), sys 532 handle forgery empty table (429a-433a) |
| **AIO race exploitation** | 662-vs-663 refcounted (72a-72c, 20/20 CLEAN), 662-vs-662 serialized (65l double-STATUS only), 3-thread gen-check blocks reuse (71a) |
| **Object lifetime races** | 7 native-speed races clean (410a-422b), concurrent child races clean (385a), double-close/UMTX/socket zero anomalies |
| **Object handles** | Predictable (generation << 13 \| slot), LIFO, generation-checked — second release returns -1, stale id resolves to nothing (435a-445a) |
| **BSD native range** | ~400 syscalls tested (388a-392f), zero kernel pointers, fstatfs/getfsstat/mod* blocked |
| **Ioctl full sweep** | ALL 34 /dev nodes clean across 48,446 calls (387a/387c) + 32M calls on gc/dce (273a-287a). Zero overcopy, zero kernel pointers |

## Phase Summary

### Phase 16 — AIO Race → Direct KASLR Spray (2026-10-23 to 2026-10-25)
**Ran:** 65a–72c (AIO race development, race closure, KASLR spray pivot)

**Key results:**
- AIO double-STATUS confirmed (65l) — 65/480 double-SUCCESS, but NOT double-free
- **All AIO race paths closed (72a-72c):** 663 refcounted (Q survives), 662 serialized
  (D exclusive lock), generation-checked IDs block 3-thread slot reuse
- 13.60 decompile verified R+0x00/R+0x08 kernel pointer residue (not zeroed)
- **Pivot to direct KASLR spray** — no race needed, single 662 free + spray reclaim
- Child thread infrastructure validated: thr_new(455), fake TCB fix (384b)
- 663 blocking behavior confirmed (71h), child 669 works (71g)
- 665/668 dead (71e/71f/71f2)

### Phase 15 — KASLR Exhaustive + CClosure Gadgets (2026-10-23)
**Ran:** 56d–56s, 271g–271i, 384b–392f

**Key results:**
- Eboot gadget catalog: rax=0/1/6/7/8 confirmed (56d5-56d7)
- Child thread ROP syscalls (271g), fake TCB fix (384b), multi-arg (386a)
- EVFILT_TIMER + socketpair (271i), kqueue race exhausted (271g-271i)
- All 34 /dev nodes ioctl overcopy clean (387a/387c)
- BSD-native range 1-530 exhausted (388a-392f)
- CVE-2026-49427/49428/49419 all dead (391a-392a)

### Phase 14 — Deep Syscall Survey + CClosure (2026-10-18)
**Ran:** 54a–56c/56f

**Key results:**
- CClosure +0x20 redirect to Lua C functions confirmed (56c/56f)
- 17 KASLR techniques tested, zero kernel pointers
- sys 624 VM counter characterized (52b)
- sys 674 VM map: 317 regions, all userland (55e/55f)

## Relapse Exploit Intelligence

The **Relapse exploit** (fw 7.00-13.60) is partially portable to 14.10:
- **AF_ROUTE KASLR** — **DEAD** on 14.10 (53b)
- **AIO double-free race** — **CLOSED** on 14.10 (72a-72c). The 662-vs-662 race (65l)
  is double-STATUS only (serialized by D exclusive lock). The 662-vs-663 race is
  safe by design (663 waiter holds Q refcount via XADD.LOCK). Generation-checked IDs
  block 3-thread slot reuse. Sony's 14.20 post-lock-drop generation revalidation
  may address a different race window; on 14.10 the existing locks/refcounts suffice.
- **AIO R-object KASLR residue** — **ALIVE** on 14.10 (13.60 verified). The freed R
  object retains kernel thread pointers at R+0x00/R+0x08. The exploit pivots from
  race-based UAF to direct spray-after-free for KASLR defeat.
- **Key difference:** 661 (BSD aio_read) kills, but 669 (Sony batch submit) works.
  The AIO IDs for 662's delete come from 669, not 661.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us userland memory read/write through the `memory.*` API and syscall invocation through the `syscall.*` API. `make_syscall()` bypasses the Lua resolver filter for tested syscall numbers; kernel-side restrictions still apply, and it does not provide raw kernel memory access. These are the currently documented interfaces, not necessarily the entire attack surface.

## Historical Priorities (2026-10-21, SUPERSEDED)

The priorities listed here are superseded by the 2026-10-25 priorities at the top
of this document. The AIO double-free race (65l) was confirmed as double-STATUS
only (not double-free) on 2026-10-25, and all AIO race paths closed (72a-72c).
The exploit pivots to direct KASLR spray via R-object kernel pointer residue.
Earlier: CVE-2026-49418 (msync) confirmed dead (58a/58b). UMTX PI-mutex races
produced DoS only (160f-160j). Native sysent 677-734 is credential-gated (275b-275d).
CClosure gadget ROP is working but userland-only.
