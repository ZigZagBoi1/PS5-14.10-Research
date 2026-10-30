# Exploit Strategy Assessment — PS5 14.10

> **Last updated:** 2026-10-28 (post-AIO closure)

## Current Position (2026-10-28) — Lua Surface Exhausted, WebKit Only Path

The goal is unchanged: userland code execution → kernel R/W → hypervisor bypass.

**STATUS (2026-10-28):** The Lua loader kernel attack surface is **exhausted**. AIO 662
is **dead on 14.10** — the boot tunable that gates the submit path never opens, the
delete never drops its table lock, and the subsystem dispatches no I/O. The "doubles"
in probe 65l were double-STATUS reports (both threads report success, only one frees).
See `docs/AIO_GATE_14_10.md`.

**The only remaining kernel path is WebKit Canvas UAF (CVE-2026-43720).**

### Primary Exploit Chain (Active — Revised 2026-10-28)

```
                         ┌─ HAVE ─┐         ┌── NEED ──┐
userland code exec ──►   WebKit Canvas  ──►  info leak   ──►  kernel exploit  ──►  HV bypass
(Lua loader OR           UAF write           (alt to          (via arb R/W        (Byepervisor)
 browser entry)          primitive            IPV6_2292        from WebKit)
                         (CVE-2026-43720)     PKTOPTIONS)
```

**Stage 1 — Canvas UAF (CONFIRMED):** CVE-2026-43720 is confirmed on PS5 14.10
(pastawithpesto). Canvas `getContext()` reentrancy triggers a UAF on a 768B FastMalloc
slot. Same-type reclamation gives bidirectional R/W.

**Stage 2 — Info Leak (BLOCKED):** The Prolapse chain uses `IPV6_2292PKTOPTIONS` to
leak a raw heap pointer as a JS number. This option is **blocked on 14.10** (setsockopt
returns -1). An alternative info leak mechanism is needed.

**Stage 3 — Arbitrary R/W → Kernel:** With info leak + Canvas UAF write primitive,
build arbitrary R/W in the WebProcess, then pivot to kernel exploitation (e.g. via
syscall from the compromised WebProcess, or a second kernel vulnerability reachable
from the browser's sandbox).

**Stage 4 — Hypervisor:** With kernel R/W, apply Byepervisor technique.

### Primitives That Exist

| Primitive | Evidence | Limits |
|---|---|---|
| Lua code execution on TCP 9026 | loader | userland only; kernel surface exhausted |
| WebKit Canvas UAF (CVE-2026-43720) | confirmed on device | write primitive; info leak blocked |
| Arbitrary tested syscall invocation | `make_syscall` | kernel-side checks still apply |
| Child thread ROP syscalls (5-arg) | 271g/272a/396f | pop rax/rdi/rsi/rdx/rcx/r8; max 5 args |
| thr_new(455) with arg delivery | 56l | rdi=arg, simpler than thr_create(430) |
| thr_create(430) with full register control | 156c/156d | GP regs + RIP + RSP + CS/SS |
| GPU pool mapping, userland R/W | 477 with flags `0x1002` | 384 MiB max, zeroed on alloc (348a) |
| CClosure function redirect | 56c/56f, 56d-56d7 | selected Lua C targets + eboot gadgets |
| native.fcall_with_rax | 129b | arbitrary userland function calls |
| POSIX shm (shm_open/ftruncate/mmap) | 391a-391d | MAP_SHARED works; shm_open2(571) is nosys |
| EVFILT_TIMER + socketpair pipeline | 271i | kqueue works with timers and AF_UNIX |
| sigreturn frame injection | 417/421 | cookie=RFLAGS(0x202), IOPL rejected (816c) |
| Event and named objects | 538/540/544-546, 557 | process-scoped (342a) |
| sys 624 VM operation counter | 52b | +5 per mmap, zero jitter; side channel |
| Userland module-base discovery | 593 on 39 modules | kernel ASLR is separate |
| Full eboot gadget catalog | 56s, pop set documented | pop_rax/rdi/rsi/rdx/rcx/r8 + mov/syscall combos |

### Walls That Are Measured

- **W^X enforced at hypervisor level** — mprotect(EXEC) refused; mmap strips EXEC at
  creation (803c-803i); sys 588 accepts but PTE never gets execute bit (124a); sys 548
  protect clamped to creation protection. No bypass path exists.
- **No kernel pointer from Lua side** — exhaustive scan across every accessible syscall,
  all CTL_* sysctl trees, device ioctls (32M calls), signal frames, routing sockets,
  getsockopt, fstat, ucontext, ancillary data — zero kernel pointers found.
- **No KASLR defeat** — 17+ techniques tested, all dead. GPU pages zeroed (348a),
  NET_RT_DUMP false positives (56e2), timing noise only (56h-56i2).
- **The jail holds** — authid gates (535/536/563-566), credential bit 62 (618/646/671),
  device context empty (532/622), fork/rfork blocked.
- **kld* family lethal** — kldstat(308), kldnext(307), kldsym(337) all kill on touch.
- **AIO subsystem INERT** — boot tunable gates submit; delete never drops lock; no I/O
  dispatched (docs/AIO_GATE_14_10.md). The entire AIO exploitation line is dead on 14.10.
- **dmem0 is GPU bus space** — not system RAM; kernel image not reachable (563a-563k).
- **mmap strips PROT_EXEC at creation** — bit 2 is cleared by the VM layer, max_protection
  equals stored protection; sys 548's protect path cannot add X (803c-803i).

## AIO 662 — CLOSED (2026-10-27)

**The AIO exploitation line is DEAD on 14.10.** This section archives the findings.

### Root cause: boot tunable gates the TOCTOU window

The delete drops the table lock only when `[W+4]` (in-flight flag) is non-zero AND
`[W+0xc]` (poll flag) is set. `664` sets `[W+0xc]`, but nothing reachable sets `[W+4]`:
the submit path that would write it is behind the boot tunable `0x8b4c78d0`, and that
gate never opens on 14.10. A delete on this firmware is therefore an under-lock teardown.
The TOCTOU window that 14.20 patches does not exist on 14.10.

### AIO race paths closure timeline

| Date | Finding | Probes |
|------|---------|--------|
| Oct 23 | 65l: 65/480 "double-success" reports | 65d-65l |
| Oct 25 | All race paths closed: 663 refcounted, 662 serialized, gen-check blocks reuse | 72a-72c |
| Oct 25 | Pivot to "direct KASLR spray" (R-object residue) | 69l-69m |
| Oct 26 | 16-deleter storm: one winner, 15 first-lookup misses, zero allocator damage | 817a-818a |
| Oct 26 | Delete re-lookup branch opened by poll, not submit; race is duplicate status | 791b-791f |
| Oct 27 | Boot tunable gates the lock drop — TOCTOU window does not exist on 14.10 | 882a-886a |
| Oct 28 | Zone-128 RTHDR spray: 0 overlaps confirms no underlying free | 75a-75e |
| Oct 28 | **Conclusion: AIO subsystem is INERT on 14.10** | AIO_GATE_14_10.md |

### What the AIO line taught us

- Sony's kernel uses a custom allocator with type-partitioned zones, not stock UMA
- The handle table is generation-checked (stale IDs resolve to nothing)
- Object lifetimes are reference-counted (663 waiter holds Q via atomic XADD.LOCK)
- The D exclusive lock serializes all cleanup — no concurrent free is possible
- 65l's "doubles" prove only that both threads pass validation before the lock, not that both free

## Remaining Attack Surface

### ★ WebKit Canvas UAF (CVE-2026-43720) — Only Live Vector

| Component | Status |
|-----------|--------|
| Canvas getContext() UAF | **CONFIRMED** on 14.10 (pastawithpesto) |
| 768B FastMalloc slot reclamation | Same-type only (no IsoHeap, no Gigacage) |
| Write primitive | Claimed in p553 (bidirectional R/W via same-type reclaim) |
| Info leak (IPV6_2292PKTOPTIONS) | **BLOCKED** on 14.10 |
| Alternative info leak | **NOT IDENTIFIED** — the sole remaining blocker |
| JIT | DISABLED (LLInt only) |
| WebAssembly / SharedArrayBuffer / WebGL | NOT AVAILABLE |

**Blocker:** The Prolapse info leak uses `IPV6_2292PKTOPTIONS` to read a raw heap
pointer as a JS number. This option returns -1 on 14.10. Without it, the Canvas UAF
write primitive cannot be aimed. Finding an alternative info leak is the critical path.

**Browser access:** The Lua loader runs in a game process, not the browser. Getting
WebKit code running requires either:
1. A method to launch the browser from the game process (not currently known)
2. A standalone browser entry (user navigates to exploit page)
3. A Lua-to-browser bridge (e.g. via shared memory or IPC)

See `docs/PROLAPSE_CANVAS_UAF.md` for full technical details.

### kptr_hunt.py Offline Candidates

`tools/kptr_hunt.py` analyzed 13.60 handler decompilations and identified 17
OBJECT-sourced `copyout` candidates — handlers that copy kernel object contents to
userland. These are worth testing with real arguments on 14.10 if any are reachable
from the game process. The analysis is offline (static) and has not been validated
live.

### Kernel Image Acquisition

A 14.10 kernel dump would immediately settle:
- Whether any 13.60 handler analysis applies to 14.10
- Exact zone layouts and allocator internals
- Handler implementations for the kptr_hunt.py candidates
- Whether the AIO gate is truly firmware-specific or architectural

Acquisition paths: firmware PUP decryption, hardware dump, scene leak, Prolapse release.

## Measurements Since Oct 25

| Date | Finding | Probes |
|------|---------|--------|
| Oct 26 | sigreturn installs caller-supplied frame; cookie = RFLAGS(0x202); IOPL rejected | 813a-816c |
| Oct 26 | sys 548 works: op 1=unmap, 2=protect, 3=map; W^X holds (protect clamped to creation) | 803c-803i |
| Oct 26 | sys 626 reads perf counters (cmd 5/6), not MSRs; no KASLR route | 796a-796d |
| Oct 26 | dmem0 is GPU bus space (device aperture), not system RAM | 563a-563k |
| Oct 26 | mmap strips PROT_EXEC at creation; max_prot=stored_prot | 803c-803i |
| Oct 26 | Module copyouts reject oversized length (593 validates size field) | 801a |
| Oct 26 | vmmcall bytes not available in executable pages; W^X wall blocks | 798a |
| Oct 26 | Object table 549/558 doesn't share IDs from this process | 799a |
| Oct 27 | thr_create child can reach loader stub but cannot loop (frame overwrites chain) | 882a-885a |
| Oct 27 | AIO boot tunable definitively gates the TOCTOU window | AIO_GATE_14_10.md |
| Oct 28 | Zone-128 RTHDR spray: 0 overlaps, confirms no underlying free | 75a-75e |
| Oct 28 | kptr_hunt.py: 17 OBJECT-sourced copyout candidates from 13.60 | offline analysis |

## Deprioritized (Still Available)

| Vector | Status | Why deprioritized |
|--------|--------|-------------------|
| CClosure gadget ROP | Working (56c/56f/56d) | Userland only; no kernel path |
| Network packet injection | RAW socket works | 700+ packets, zero crashes |
| Native sysent 677-734 | Credential-gated (275b-275d) | Cannot reach without privilege |
| Device ioctl | 32M+ calls tested | Zero exploitable commands |
| System sockets | Compositor protocol mapped | DoS only |
| AIO (entire subsystem) | INERT on 14.10 | Boot tunable, D exclusive lock |
| osem waiter-wake race | Synchronous wake, gen-checked | No exploitable window |

## Dead Ends (Do Not Retry)

The full dead-ends list is maintained in `docs/DEAD_ENDS.md`. Key categories:

| Category | Summary |
|----------|---------|
| **★ AIO 662 (entire line)** | Boot tunable gates submit; delete never drops lock; doubles are STATUS not FREE; subsystem INERT (AIO_GATE_14_10.md) |
| **KASLR (17+ techniques)** | AF_ROUTE sanitized (53b), kinfo_proc sentinels (43d), NET_RT_DUMP false positives (56e2), GPU zeroed (348a), timing noise (56h-56i2), sysctl deep scan clean (56g3) |
| **W^X bypass** | mprotect(EXEC) refused, mmap strips EXEC, sys 588 HV blocks PTE X bit (124a), sys 548 clamped (803d-803i) |
| **Device/driver** | 32M+ ioctl calls zero exploitable, all 34 nodes overcopy-clean, GPU unreadable, dmem0 GPU bus space |
| **CVEs** | msync dead (58a/58b), IPV6_MSFILTER removed (50e2/50e3), KTLS absent (50f), shm_open2 nosys (391a-391d), jail -1 (392a), kqueue solid (271g-271i), netcontrol dead (223a-234a) |
| **Syscall families** | kld* lethal, osem dead, jitshm -1, physhm unreadable, blockpool no mapping, debugger no session, device control no context, handle forgery empty table |
| **Object lifetime races** | 7 native-speed races clean (410a-422b), concurrent child races clean (385a) |
| **BSD native range** | ~400 syscalls tested (388a-392f), zero kernel pointers |
| **IPv6 RTHDR spray** | 0 overlaps across 75a-75e; underlying 662 is double-STATUS |

## Relapse / Lapse / Prolapse Intelligence

### Relapse (fw 7.00-13.60) — portability to 14.10

- **AF_ROUTE KASLR** — **DEAD** on 14.10 (53b)
- **AIO double-free race** — **DEAD** on 14.10 (AIO_GATE_14_10.md)

### Lapse (abc, PS5 1.00-10.01)

Used the same AIO 662 bug with socket+evf spray. The bug is INERT on 14.10 (boot
tunable), so the Lapse chain is not portable.

### Prolapse (notnotzecoxao, PS5 14.00-14.10)

Announced but not released. Uses Canvas UAF (CVE-2026-43720) via WebKit. The info
leak vehicle (`IPV6_2292PKTOPTIONS`) is blocked on 14.10, so the public Prolapse
chain may need adaptation for this firmware. Monitoring for release.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN):
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox

The Lua loader gives userland memory read/write and syscall invocation. The kernel
attack surface from this entry point is exhausted.

## Historical Priorities (SUPERSEDED)

**2026-10-25:** Pivoted from AIO race to "direct KASLR spray" via R-object kernel
pointer residue. This was invalidated on Oct 27 when the boot tunable was identified —
no AIO object is freed on 14.10, so there is no residue to read.

**2026-10-23:** AIO double-free probe 65l showed 65/480 "doubles". These were
interpreted as kernel double-frees; they are actually double-STATUS reports where
both threads pass validation but only one frees. The entire AIO investigation line
(65a-886a, spanning 5 days) produced no kernel memory corruption.
