# Untested Theories — PS5 14.10

> **Last updated:** 2026-10-25. AIO double-free (65l) confirmed as the primary
> exploit path. Theories below are either DEAD, CONFIRMED, or deprioritized in
> favor of the heap spray exploitation chain. See `docs/EXPLOITATION_STATUS.md`.

## Theory 0: AIO Double-Free Heap Spray → Kernel R/W (NEW — TOP PRIORITY)

**Priority: ★★★ HIGHEST**

**Status:** Double-free CONFIRMED (probe 65l, 2026-10-23). Heap spray NOT YET CONFIRMED.

The AIO `aio_multi_delete` (syscall 662) TOCTOU race produces a kernel double-free
with ~13.5% per-ID hit rate. Two child threads calling 662 on the same polled ID
array freed 65 out of 480 IDs by both threads across 30 iterations.

**What remains:**
1. Identify the freed kernel object's size and slab zone
2. Spray matching-size kernel allocations to reclaim the freed slot
3. Detect overlap via 663/666/667 readback on stale AIO IDs
4. Extract kernel pointer from reclaimed object → KASLR defeat
5. Overwrite function pointer → kernel code execution

**Spray candidates:** namedobj(557), evf(538), setsockopt, shm metadata, pipe headers

**Probes:** 65m-67m2 (in progress)

---

## Theory 1: `kern.proc.pid` Full Dump Contains Kernel Pointers

**Priority: ~~HIGHEST~~ DEAD** — Probe 43d dumped full 1096B. Only sentinel values (0xFFFFFFFF_00000000), zero real kernel pointers.

Probe 42a confirmed `sysctl kern.proc.pid` works via `make_syscall()` and returns 1,096 bytes of `kinfo_proc`. However, the dump only sampled every 8th qword — most of the structure was never printed.

In FreeBSD, `struct kinfo_proc` (1,096 bytes) contains multiple kernel pointers:

- `ki_paddr` — pointer to `struct proc` in kernel memory
- `ki_addr` — pointer to `struct user`
- `ki_tracep` / `ki_textvp` — kernel vnode pointers
- `ki_fd` — pointer to the filedesc table
- `ki_vmspace` — pointer to the process vmspace

The probe found `0xFFFFFFFF00000000` at offset +0x060, but this is likely a bitmask/flag field (e.g. `ki_flag`), not a real kernel pointer. The real kernel pointers (`ki_paddr`, `ki_addr`, etc.) sit at other offsets that were skipped by the every-8th-qword sampling.

**What was already tested:** Probe 42a dumped kern.proc.pid but only printed every 8th qword (8 out of ~137 qwords). The full 1,096 bytes were never examined.

**Test:** Write a probe that dumps ALL 1,096 bytes of `kern.proc.pid`, scanning for values matching `0xFFFFxxxx_xxxxxxxx` (kernel VA range). If kernel pointers leak, combine with the ROP chain hijack to call sysctl with crafted MIBs targeting known offsets from those pointers → kernel R/W.

**Why it could work:** The sysctl sandbox filter appears to be in `syscall.resolve()`, not the kernel itself (proven by 41w). `kern.proc.pid` is a standard FreeBSD sysctl that copies out the full kinfo_proc, and Sony may not have scrubbed kernel pointers from it since sysctl was "blocked."

---

## Theory 2: `kern.proc.vmmap` Needs a Larger Buffer

**Priority: ~~HIGH~~ DEAD** — Probe 43d tested with 64K-256K buffers: ret=-1. Blocked on 14.10.

---

## Theory 3: IPv6 RTHDR Uninitialized Memory Leak

**Priority: LOW (mostly tested)**

Probe 09 shows `setsockopt(IPV6_RTHDR)` accepts buffers up to 8,184 bytes, but readback is always 0. Probe 09 also tested:
- 200 alloc/free churn rounds on same socket → no leak
- 32 multi-socket PKTINFO alloc → no cross-socket leaks
- Close upper half, read lower half → no UAF signs
- PKTOPTIONS after churn → 8,192 bytes all zero

**What remains untested:** Reading `IPV6_PKTOPTIONS` on a **connected** IPv6 socket (probe 09 only tested unconnected). The connected-socket path assembles options differently in FreeBSD and might copy from the routing header allocation's uninitialized tail. Long shot given how thoroughly probe 09 got zeros.

---

## Theory 4: Re-test "Blocked" Syscalls via `make_syscall()`

**Priority: ~~HIGHEST~~ EXHAUSTED** — The BSD-native range (1-530) is fully tested across ~400 syscalls (probes 388a-392f), and Sony range 532-676 is extensively surveyed (51a-55f, 334a-342a). Zero kernel pointers found.

**Confirmed working via make_syscall:**
| Syscall | Number | Result | Status |
|---------|--------|--------|--------|
| `sysctl` | 202 | WORKS — kern.proc.pid returns 1096B, no kernel pointers | **Useful, no kptrs** |
| `fstat` | 189 | WORKS — stat struct, no kernel pointers (43e, 56o) | **No kptrs** |
| `ioctl` | 54 | WORKS — reaches all 34 /dev drivers, 32M calls tested | **No exploitable commands** |
| `thr_new` | 455 | **WORKS** — child threads with ROP syscalls (383a, 271g) | **Key primitive** |
| `pipe` | 42 | Returns fds 0,0 | **Dead** |
| `dup` / `dup2` | 41 / 90 | Returns -1 | **Dead** |
| `pipe2` | 542 | Not tested | **UNTESTED** |

**Update (2026-10-25):** Exhaustive survey complete. Only pipe2(542) remains untested. thr_new(455) was the major find — it enables the AIO double-free race.

---

## Theory 5: ktimer Signal Delivery as Kernel Corruption Vector

**Priority: LOW (deprioritized — AIO double-free is the active kernel path)**

Probe 42a confirmed ktimer_create (clocks 0+4), ktimer_settime, and ktimer_getoverrun work. Threading IS available (thr_new(455) works), so timer+thread races are possible. However, the AIO double-free (Theory 0) is a confirmed corruption primitive and should be pursued first.

---

## Theory 6: TCP Input-Side Attacks via Connect-Back

**Priority: ~~HIGH~~ LOW (deprioritized — extensive network fuzz with zero results)**

Probe 49a delivered 182 crafted TCP segments into an ESTABLISHED loopback connection (RST, SACK, PAWS, option parser len=0/255, URG, zero-window, ACK storm, SYN flood). Zero crashes. Probe 48b tested 39 SCTP chunk variants, 48c tested 83 IPv6 extension header variants, 49b tested 280 IPv6 fragment reassembly attacks, 50a tested 86 exotic protocol packets (IGMP/GRE/ESP/AH/PIM/OSPF/VRRP). **Total: 700+ network attack packets, zero crashes.**

The PS5 kernel's network stack appears well-hardened. Remaining untested TCP classes (MD5/AO options, simultaneous open) are unlikely to yield results given the zero-crash record.

---

## Theory 7: IP Options from Real Network (Bypass Output Validation)

**Priority: ~~MEDIUM~~ LOW (deprioritized — 700+ network packets tested with zero crashes)**

Probe 37 confirmed that malformed IP option lengths are rejected at `ip_output()` before reaching `ip_dooptions()`. Input-side (`ip_input()`) doesn't have this pre-validation. However, given 700+ network attack packets across all protocol families yielded zero crashes (48b, 48c, 49a, 49b, 50a), the network stack appears hardened. AIO double-free is the active kernel path.

---

## Theory 8: Fragment Reassembly Queue Exhaustion

**Priority: ~~MEDIUM~~ LOW (deprioritized — 280 fragment attacks tested, zero crashes)**

Probe 49b tested 280 IPv6 fragments targeting ip6_reass() (overlapping/teardrop, queue exhaustion 50+101-bomb, huge totals 65535+, atomic frags, interleaving, ext hdr combos, nested frag-in-frag). Zero crashes. Standard ip_reass() also handles all 7 cases correctly (probe 39). Network stack is well-hardened.

---

## Theory 9: `fstat` via `make_syscall()` for Kernel Pointer Leak

**Priority: ~~MEDIUM~~ DEAD** — Probe 43e confirmed fstat(189) works via make_syscall, but the returned stat struct contains no kernel pointers. st_ino and st_dev are ordinary values.

---

## Cross-Reference: Combined Attack Chains

### Chain A: kinfo_proc → kernel R/W (Theories 1 + existing primitives)
1. Dump `kern.proc.pid` → extract `ki_paddr` (struct proc pointer)
2. Use ROP chain hijack to call sysctl with MIB targeting `kern.proc.filedesc` or read from known proc offsets
3. Walk kernel structures from proc → ucred → cr_uid = 0 (root)
4. Or: proc → p_fd → fd_ofiles → struct file → f_data → socket kernel object → arbitrary kernel R/W

### Chain B: fstat via make_syscall → kernel address leak (Theories 4+9)
1. Confirm `fstat(189)` works via make_syscall on a socket fd
2. On older FreeBSD, `st_ino` for sockets encodes the kernel socket address
3. Combine with kinfo_proc pointers to locate kernel structures
4. Use ROP chain hijack to read/write at known kernel offsets

### Chain C: thr_new → AIO double-free → heap spray → kernel R/W (ACTIVE)
1. ✅ thr_new(455) works — child threads with ROP syscalls confirmed (271g/272a)
2. ✅ AIO double-free confirmed (65l) — 662 TOCTOU race with two child threads
3. ⬜ Heap spray to reclaim freed slot with controlled data
4. ⬜ Read kernel pointer from reclaimed object → KASLR defeat
5. ⬜ Overwrite function pointer → kernel code exec → kernel R/W

### ~~Chain D: AIO race condition (Theories 18+19, Relapse-class) — PARTIALLY ALIVE~~
- AF_ROUTE KASLR: **DEAD** on 14.10 (53b)
- AIO double-free: **ALIVE** on 14.10 (65l) — the TOCTOU race in `aio_multi_delete`
  survives. Sony patched this in 14.20. A new KASLR technique is needed (the
  double-free itself may provide it via kernel pointer readback).

---

# ROP Chain Hijack — Deeper Exploitation Theories

The existing ROP chain hijack (probe 41z) gives: overwrite `fn_addr` (call target) + all argument slots (rdi, rsi, rdx, rcx, r8), trigger any syscall, restore. This is equivalent to **arbitrary syscall with fully controlled arguments**. The following theories explore syscalls and techniques that have NOT been tried through this primitive.

---

## Theory 10: `kldstat` (308 / 367) via make_syscall — Kernel Module Base Leak (KASLR Defeat)

**Priority: ~~HIGHEST~~ DEAD** — Probes 56k4/56k5 confirmed sys 307 (kldnext) and sys 308 (kldstat) instantly kill the process on 14.10.

`kldstat` returns `struct kld_file_stat` for a loaded kernel module, which includes:
- `name` — module filename
- `address` — **kernel virtual address where the module is loaded**
- `size` — module size

On FreeBSD, `kldstat(1, &stat)` returns info about the kernel itself (fileid 1 is always the kernel). The `address` field is the **kernel base address** — this defeats KASLR in one call.

**Syscall numbers:** Standard FreeBSD `syscalls.master` defines `kldstat` as **308** (306 is `kldfind`, 307 is `kldnext`, 309 is `kldfirstmod`). Probe 02 sweep table had mapped 367. Probe 43a tests both 308 and 367.

**Test:** `make_syscall(308)` and `make_syscall(367)` with fileid=1 and a buffer for `struct kld_file_stat` (256 bytes). If it returns the kernel base address, combine with known FreeBSD r230171 kernel symbol offsets to locate any kernel function or data structure.

**Why this could be the whole game:** kernel base + known offsets from the same build = addresses of `copyin`, `copyout`, `prison0`, `rootvnode`, and the credential structures. No pointer chasing needed.

---

## Theory 11: `kldsym` (337) via make_syscall — Resolve ANY Kernel Symbol

**Priority: ~~HIGHEST~~ DEAD** — Probe 171a called `make_syscall(337)(1, KLDSYM_LOOKUP, &kld_sym_lookup)` with `version = 24`, `symname = "prison0"` at a zeroed user buffer, and the process terminated inside the call before the first result row was printed. That matches 307 (kldnext) and 308 (kldstat), so the whole `kld*` family is lethal to call on 14.10 regardless of arguments. See `results/phase17_new_vectors/171a_kldsym_lookup_20261020_183815.txt`.

`kldsym(fileid, KLDSYM_LOOKUP, &kld_sym_lookup)` resolves a kernel symbol by name and returns its address. This is the kernel equivalent of `dlsym()`.

**Never tested.** Not even resolved in probe 02 (it tested kldload/kldunload/kldfind/kldnext/kldstat/kldfirstmod but not kldsym).

**Test:** `make_syscall(337)` with fileid=1 (kernel), command=1 (KLDSYM_LOOKUP), and a `struct kld_sym_lookup` containing the symbol name. Try resolving:
- `prison0` — the root jail, contains kernel cred pointers
- `allproc` — linked list of all processes
- `kernel_pmap` — kernel page map for direct physical memory access
- `copyin` / `copyout` — if you know their addresses you can build a kernel R/W gadget

If this works, it gives you the address of literally anything in the kernel by name. Combined with the ROP chain hijack to call those functions, this is full kernel code execution.

---

## Theory 12: `sysarch` (165) via make_syscall — GS Base Manipulation

**Priority: ~~HIGH~~ DEAD** — Probe 43c confirmed GET_GSBASE(130) returns 0. No kernel pointer leaked.

On amd64 FreeBSD, `sysarch(AMD64_SET_GSBASE, &addr)` sets the GS segment base register. The kernel accesses `curthread` via `%gs:0` — the GS base points to the current thread's `struct thread`.

**FreeBSD constants (<machine/sysarch.h>):**
- `AMD64_GET_FSBASE = 128`
- `AMD64_SET_FSBASE = 129`
- `AMD64_GET_GSBASE = 130`
- `AMD64_SET_GSBASE = 131`
- `AMD64_GET_XFPUSTATE = 132`

**Test sequence:**
1. `sysarch(AMD64_GET_GSBASE [130], &buf)` — read current GS base (might leak a kernel thread pointer)
2. If GET works, `sysarch(AMD64_SET_GSBASE [131], &fake_addr)` — set GS base to a controlled heap address
3. With a fake `curthread` structure in the heap, any kernel code that dereferences `curthread->td_ucred` follows your controlled pointer → credential replacement → root

**Risk:** Setting GS base wrong will immediately crash the next kernel access. Calling 129 (SET_FSBASE) with 0 also crashes userland. But GET_GSBASE (130) alone (reading the value) is safe and could leak a kernel address.

---

## Theory 13: Sysctl Write Paths — `kern.securelevel` and Friends

**Priority: ~~HIGH~~ DEAD (partially tested)**

Probe 43f tested kern.securelevel write: returned -1. Reads of kern.coredump, security.bsd.unprivileged_proc_debug, kern.maxproc also returned -1, so their writes were not reached. Probe 56g3 scanned ALL accessible CTL_* subtrees (kern/vm/net/hw/machdep/debug/proc) — zero kernel pointers found. Only hw.model (48B) and kinfo_proc (1096B) return data. Sysctl deep scan is exhausted.

The write path cannot lower securelevel from userland — kernel rejects it.

---

## Theory 14: Sony-Specific Syscalls (538–600+) — Unexplored Surface

**Priority: ~~MEDIUM-HIGH~~ EXHAUSTED**

The entire Sony range 532-676 has been extensively surveyed (probes 51a-55f, 334a-342a, 241a-258a). Key results:
- 533/534 (jitshm): -1 (251a)
- 535/536 (dl list/info): -1 (251a)
- 538/540/557 (evf/namedobj): work but process-scoped, no kptrs (342a, 254a)
- 547/559/560 (VM container/debug): work but no capability change (255a-258a)
- 549-556 (osem): all -1 (252a/253a)
- 561/562 (suspend/resume): 561 kills (257a)
- 563-567 (PMC): bounded PCB write, no leak (327a)
- 572 (VM info): -1 or empty (54i)
- 587 (credential): returns +0x0C = 0x20000000, no kptrs (55e)
- 601 (process control): debugger, no session (322a-324a)
- 622 (device control): ABI corrected, no data/overrun/pointer (241a-247a)
- 624 (VM counter): +5 per mmap, useful side channel (52b)
- 637 (phys mem limit): writes to child+0x280 but inert (339a/340a)
- 643 (chicken switches): accepted, no effect (55a)
- 671 (resource class): memory budget only (55e)
- 674 (VM map): 317 regions, all userland (55e/55f)

11 accessible syscalls deep-tested with output buffers — zero kernel pointers (51a/51b).

---

## Theory 15: Chained ROP Hijack — Multi-Call Kernel Walkthrough

**Priority: ~~MEDIUM~~ DEAD (prerequisites dead)**

This theory required either a kernel pointer from kinfo_proc (Theory 1 — DEAD, no kptrs in 1096B dump) or kldsym (Theory 11 — DEAD, kld* family kills on touch). With kinfo_proc containing only sentinels and kldsym lethal, the chained walkthrough has no starting address.

The fn_addr/chain fields' dispatch role is also unknown (45c controls undermined the earlier model). Child thread ROP via thr_new(455) provides a better userland execution primitive.

---

## Theory 16: `kern.proc.filedesc` Sysctl — Socket Kernel Address Leak

**Priority: ~~HIGH~~ DEAD** — Probe 43d tested: ret=-1, needed=0. Blocked on 14.10.

---

## Theory 17: `procctl` (544) via make_syscall — Process Control

**Priority: ~~MEDIUM~~ DEAD** — Probe 56p tested all 7 procctl status commands (REAP_STATUS, TRAPCAP, ASLR, STACKGAP, NO_NEW_PRIVS, WXMAP, PDEATHSIG): all return -1 with zero bytes written. Completely blocked for game process.

---

---

## Theory 18: AF_ROUTE Socket KASLR Defeat

**Priority: ~~HIGH~~ DEAD** — Retest 53b (2026-10-18) delivered RTM_GET successfully (hdr=152, write ret=168, valid 136-byte response with version=5, type=4, pid=112). All payload is zeroed sockaddr structures — zero kernel pointers. Kernel sanitizes route messages on 14.10.

---

## Theory 19: AIO via make_syscall — ★ CONFIRMED EXPLOITABLE

**Priority: ~~HIGH~~ ★★★ CONFIRMED — AIO double-free is the primary exploit path**

The AIO family is alive and exploitable on 14.10:
- 661 (BSD aio_read): **LETHAL** — kills process (54c/54f)
- 669 (Sony batch submit): **WORKS** — queues AIO requests (352a-352k)
- 664 (poll): **WORKS** — returns request states
- 662 (multi_delete): **★ TOCTOU DOUBLE-FREE CONFIRMED** (65l)
- 663 (multi_wait): **WORKS** — returns states per ID
- 666/667: **WORKS** — additional readback paths
- 670 (init): **WORKS** but poisons 662 delete path — must NOT call

See `docs/AIO_DOUBLE_FREE_14_10.md` and `docs/AIO_BATCH_14_10.md`.

---

## Theory 20: Lua VM Allocator Exploitation

**Priority: LOW (speculative)**

The Lua 5.1 VM's internal allocator manages all objects (strings, tables, userdata, closures). JSC structured-clone pool mismatch techniques from WebKit exploits could apply to Lua's GC in concept:
- Force GC to free an object still referenced (mark phase confusion)
- String interning hash collisions leading to use-after-free
- Table rehashing with controlled allocation sizes
- Integer overflow in `string.rep` or table operations
- Metatable confusion between userdata types

However, this gives userland corruption which we **already have** via GPU mmap. Only valuable if it can reach kernel memory directly (unlikely) or provide a primitive we're missing.

**Not probed yet.** Low priority unless all kernel-direct approaches fail.

---

## Phase 10 Test Results (2026-10-16)

### TESTED — Results Summary

| Theory | Probe | Result | Status |
|--------|-------|--------|--------|
| 18: AF_ROUTE KASLR | 43o, 53b | Retest 53b: valid response, all zeroed sockaddr — zero kernel pointers | **DEAD** — kernel sanitizes route messages on 14.10 |
| 19: AIO via make_syscall | 43p, 54c, 54f | 661 kills (two shapes); 662-670 never reached | **SCOPE-CORRECTED** — 661 lethal, remainder untested |
| 10: kldstat | 43a, 56k4 | sys 307/308 instantly kill process | **DEAD** — lethal on 14.10 |
| 11: kldsym | 171a | Dies inside the call, first `try()` printed nothing | **DEAD** — 337 kills like 307/308; the `kld*` family is lethal on 14.10 |
| 1: kinfo_proc full dump | 43d | 1096B dumped, only `0xFFFFFFFF_00000000` sentinel | **DEAD** — no kernel pointers |
| 16: kern.proc.filedesc | 43d | ret=-1, needed=0 | **DEAD** — blocked |
| 13: sysctl writes | 43f | One securelevel-labeled write returned -1; coredump/debug/maxproc writes not reached | **PARTIAL** — other write paths not established |
| 12: sysarch GET_GSBASE | 43c | GS base = 0 | **DEAD** — no kernel pointer |
| 4/9: blocked syscall re-test | 43e | fstat works (no kptrs), ioctl=-1, dup=-1, thr_new=crash | **PARTIAL** — fstat alive but useless |
| 14: Sony syscall sweep | 43g, 46a/47a, 51a–51c | 557 return characterized as a version-dependent formula; surveys are incomplete | **No exploit evidence** |
| 2: kern.proc.vmmap | 43d | ret=-1 with 64K-256K buffers | **DEAD** — blocked |

### TESTED — New Findings (not previously theorized)

| Finding | Probe | Status |
|---------|-------|--------|
| **fn_addr + slot0 writes persist** | 43i, 45c | Writable fields and ordinary syscall results persisted after selected mutations | **No function-call primitive established; dispatch role remains unknown** |
| mtypeprotect returns 1 for RWX | 43h, 43k, 45c | Return value did not establish executable memory; no code execution path demonstrated |
| kern.msgbuf returns 8 bytes only | 43j | **DEAD** — filtered/stub |
| mincore rejects kernel VA | 43l | **DEAD** — no KASLR oracle |
| sockopt accepts large buffers | 43m | **DEAD** — kernel clamps copy, not overflow |
| /dev/hid ioctl = Sony error | 43n | **DEAD** — 0x80740004 on all ioctls |
| Syscall 620 alive | 43k, 46a | Returns 0 for tested inputs; sentinel checks report no changes. Full semantics unresolved. **LOW PRIORITY** |

### Current assessment (2026-10-25)

**A confirmed kernel memory corruption primitive exists:** the AIO `aio_multi_delete`
(syscall 662) TOCTOU double-free (probe 65l). This is the first kernel-level
vulnerability confirmed on 14.10. The remaining gap is heap spray to reclaim the
freed slot with controlled data, followed by KASLR defeat via kernel pointer readback.

No kernel pointer leak has been found through any other path. All KASLR techniques
(17+) are dead. The double-free itself is the most promising KASLR vector: if the
freed AIO sub-object contains a kernel back-pointer, reclaiming it with controlled
data and reading back through a stale reference would leak a kernel address.
