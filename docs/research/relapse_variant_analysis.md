# Relapse Exploit Variant Analysis for PS5 14.10

## Date: 2026-10-18

---

## 1. What Relapse Exploits (Exact Bug)

### Overview
Relapse is a two-stage kernel exploit for PS5 fw 7.00-13.60. It chains:
1. **KASLR defeat** via AF_ROUTE socket info leak
2. **Kernel R/W** via use-after-free race condition in Sony's custom AIO subsystem

### Stage 1: KASLR Defeat — AF_ROUTE Info Leak

**File:** `src/relapse_exploit.js`, method `leakKernelBase()`

The exploit opens an `AF_ROUTE` (PF_ROUTE=17) raw socket, sends an `RTM_GET` routing message with a crafted oversized `AF_INET6` author sockaddr (len=255), and reads the kernel's reply. The reply's "author" field at offset +184 contains a kernel `.text` return address leaked from the routing stack frame.

**Specifics:**
- `socket(AF_ROUTE=17, SOCK_RAW=3, 0)` opens a routing socket
- Message type `RTM_GET` (0x04) with `RTA_DST | RTA_AUTHOR` (0x41)
- The author sockaddr has `sa_len=255, sa_family=AF_INET6`
- The oversized sockaddr causes the kernel to copy stack data containing a return address
- The leak is at `author + 184` bytes in the reply
- Kernel base = `leaked_addr - retStatic` (fw-specific offset; for 13.60: `retStatic = 0x00AE2DA0`)

**14.10 status: DEAD.** Probe 43o confirmed the AF_ROUTE socket opens but routing replies contain zero kernel pointers. Sony patched the info leak.

### Stage 2: Kernel R/W — Sony AIO Use-After-Free

**File:** `src/relapse_exploit.js`, method `armKernelReadWrite()` and related methods

This is the core vulnerability. It uses a **use-after-free race condition** in Sony's custom AIO (Asynchronous I/O) subsystem — specifically in the interaction between `AIO_MULTI_WAIT` and `AIO_SUBMIT_CMD`.

#### The Sony Custom AIO Syscalls Used

| Syscall | Number | Name | Role in Exploit |
|---------|--------|------|-----------------|
| 0x29D | 669 | `AIO_SUBMIT_CMD` | Submit AIO requests (reclaim freed memory) |
| 0x297 | 663 | `AIO_MULTI_WAIT` | Wait on AIO group (triggers free of waiter nodes) |
| 0x298 | 664 | `AIO_MULTI_POLL` | Poll AIO request states |
| 0x29A | 666 | `AIO_MULTI_CANCEL` | Cancel individual AIO requests (decrement primitive) |
| 0x29C | 668 | `AIO_CREATE` | Create AIO context |
| 0x295 | 661 | `AIO_SUBMIT` | Submit standard AIO requests |
| 0x29E | 670 | `AIO_INIT` | Initialize AIO subsystem |

These are **NOT** the standard FreeBSD AIO syscalls (255-465). They are Sony-custom replacements in the 661-670 range.

#### The Bug: UAF Race in Waiter Nodes

The exploit flow:

1. **Setup:** Park AIO worker threads by submitting reads on blocking socketpairs (`parkAioWorkers`). This ensures deterministic kernel thread scheduling.

2. **Claim pending requests:** Submit AIO read requests via `AIO_SUBMIT_CMD` on blocking socketpairs. Wait until requests reach "pending" state via `AIO_MULTI_POLL`.

3. **Build waiter nodes:** Allocate userspace buffer formatted as AIO request structures, with fields carefully overlapping sysctl OID metadata targets:
   - Offset +0x00: first target address (e.g., `deadSink` field of sysctl OID A)
   - Offset +0x08: second target address (e.g., `kindByte3` of sysctl OID A)
   - Offset +0x10: `nodeMutex` address (kernel mutex for synchronization)

4. **The Race (`runReclaimBatch`):**
   - Issue `ioctl(0xffffffff, churnRequest, nodes)` calls to churn kernel allocator state
   - Call `AIO_MULTI_WAIT` — this **frees waiter nodes** in the kernel when the wait times out
   - Immediately spray `AIO_SUBMIT_CMD` to **reclaim the freed memory** with attacker-controlled content
   - The reclaimed memory now overlaps with sysctl OID internal structures

5. **Decrement primitive (`flipOidKind`):** Each `AIO_MULTI_CANCEL` call on the reclaimed requests **decrements** a byte at the target address. The exploit uses this to flip the sysctl OID `kind` field from `0x80048002` (read-only) to `0x70048002` (writable).

6. **Kernel R/W via sysctl:** With the OID made writable:
   - Writing to OID A (`kern.smp.cpus`) sets the low 32 bits of the read/write target
   - Reading/writing OID B (`kern.smp.maxcpus`) reads/writes at that target address
   - A third OID C is later flipped to handle the high 32 bits

7. **Fast R/W via pipes:** After slow sysctl-based R/W is established, the exploit creates pipe pairs, overwrites pipe buffer pointers via kernel write to point at each other (pipe bootstrap), giving fast arbitrary kernel read/write.

8. **Privilege escalation:** Overwrites ucred (uid=0, all caps), removes sandbox, lifts dynlib restrictions.

#### Kernel Functions Involved (13.60)

From the sysent table and kernel_text.bin:

| Syscall | Handler Stub (RVA) | Real Handler (RVA) | Function |
|---------|-------------------|-------------------|----------|
| 663 (AIO_MULTI_WAIT) | 0x265720 | 0x3B01F0 | The vulnerable wait — frees waiter nodes |
| 669 (AIO_SUBMIT_CMD) | 0x265740 | 0x3B2060 | Submit with command — used for memory reclaim |
| 666 (AIO_MULTI_CANCEL) | 0x265738 | 0x3B1680 | Cancel — provides decrement primitive |
| 664 (AIO_MULTI_POLL) | 0x265728 | 0x3B0FB0 | Poll states — used to track request lifecycle |

The AIO implementation lives at kernel text RVA `0x3AF8E0 - 0x3B28D0` (approximately 12KB of code). The vulnerable code path is specifically in the `AIO_MULTI_WAIT` handler at `0x3B01F0`, where waiter nodes are freed without proper synchronization against concurrent `AIO_SUBMIT_CMD` operations.

#### Offsets Used (13.60)

From `offsets/13.60.js`:
```
nodeMutex:     0x01A9BAB8
AIO group offsets: { num: 0x00, state: 0x08, waiters: 0x50 }
AIO idTable:   { pages: 0x220, slotStride: 0x30, entryType: 0x160 }
OID A (kern.smp.cpus):    base=0x028CEF68, kind=0x028CEF7C, arg1=0x028CEF80
OID B (kern.smp.maxcpus): base=0x028CEE40, kind=0x028CEE54, arg1=0x028CEE58
OID C (sysctl [9,8]):     base=0x02BF1C38, kind=0x02BF1C4C, arg1=0x02BF1C50
allproc:       0x03589E80
rootvnode:     0x03E0B510
proc.pid:     0x0BC
proc.ucred:   0x040
proc.fd:      0x048
proc.aioInfo: 0x0C48
```

---

## 2. What Was Patched on 14.10

Based on probe results from our research:

### Confirmed Patched
1. **AF_ROUTE info leak** — routing socket opens but replies contain zero kernel pointers (probe 43o)
2. **Standard FreeBSD AIO syscalls (255-465)** — sandbox-killed at kernel level (probe 43p)

### NOT Tested (Critical Gap)
3. **Sony custom AIO syscalls (661-670)** — Probe 43p was killed at the first standard AIO syscall (aio_error, #317) and never reached Phase 4's scan of the 661-670 range. The Sony AIO syscalls that Relapse actually uses have NEVER been tested on 14.10 via make_syscall().

This is a critical oversight. The scan in Phase 4 of probe 43p included syscalls 661-670 in the candidate list, but the process was killed in Phase 2 before reaching them.

---

## 3. Variant Possibilities on 14.10

### Variant A: Sony AIO Syscalls Still Accessible (HIGH PRIORITY)

**Hypothesis:** Sony may have only patched the standard FreeBSD AIO syscalls (255-465) at the kernel sandbox level but left their custom AIO subsystem (661-670) accessible. The sandbox enforcement for standard vs. Sony syscalls may use different code paths.

**Why plausible:**
- Standard AIO (255-465) and Sony AIO (661-670) are entirely separate implementations
- Sony's sandbox check likely uses a syscall whitelist/blacklist — Sony syscalls may be on a different list
- The `make_syscall()` bypass already proved that some "blocked" syscalls are only blocked in the Lua-side `resolve()` filter
- Sony may have added kernel-level blocks for standard AIO after Relapse, but their own AIO is a different subsystem

**What to test:** A probe that directly calls `make_syscall(663)` (AIO_MULTI_WAIT) with safe NULL args, preceded by `make_syscall(670)` (AIO_INIT) and `make_syscall(668)` (AIO_CREATE).

### Variant B: Partial Fix in Waiter Node Lifecycle (MEDIUM PRIORITY)

**Hypothesis:** If Sony AIO syscalls are still accessible, the specific UAF may be "fixed" with a reference count increment, but a variant race could exist in:
- The interaction between `AIO_MULTI_WAIT` timeout and `AIO_MULTI_CANCEL`
- Group state transitions (the `state` field at offset +0x08 in the group struct)
- The ID table lookup (`lookupAioGroup` — generation/type checks) which may have off-by-one or TOCTOU issues

**Why plausible:** UAF patches often add reference counting or locking to the specific path reported, but miss variant paths. The AIO subsystem has multiple interacting state machines (request states, group states, waiter lists) that create a large attack surface for races.

### Variant C: Different Sysctl OID Targets (LOW PRIORITY)

**Hypothesis:** Even if the AIO UAF is fully patched, the sysctl OID manipulation technique (flipping `kind` to make read-only OIDs writable) may work with a different memory corruption primitive. Any single-byte decrement or write to a known kernel address could flip an OID.

**Why plausible:** The sysctl OID abuse is the R/W primitive, not the bug itself. If we find any other corruption primitive (heap overflow, integer overflow, double-free), the OID technique ports directly — we just need different offsets for 14.10 OID locations. The `sysent_rva +0xe6e5c0` being the same across 13.60 and 14.10 suggests limited structural changes.

### Variant D: KASLR via Different Info Leak (MEDIUM PRIORITY)

**Hypothesis:** Even without AF_ROUTE, KASLR can potentially be defeated via:
- Timing side-channels on the Sony AIO subsystem (if accessible)
- Syscall 624 (live VM counter) as a heap layout oracle
- Uninitialized stack data in Sony syscall handlers (the 627-676 range is largely untested)

---

## 4. Required Probes

### Probe 52a: Sony AIO Accessibility Test (CRITICAL — DO THIS FIRST)

Test whether Sony custom AIO syscalls (661-670) survive via `make_syscall()`:

```lua
-- CRASH_CLASS: HIGH
-- PROBE 52a: Sony Custom AIO via make_syscall
--
-- Probe 43p only tested FreeBSD AIO (255-465), which is sandbox-killed.
-- Relapse uses Sony's CUSTOM AIO: syscalls 661-670 (0x295-0x29E).
-- These have NEVER been tested on 14.10 via make_syscall().

-- Test order (safest first):
-- 1. 664 (AIO_MULTI_POLL) — read-only poll, safest
-- 2. 670 (AIO_INIT) — init subsystem
-- 3. 668 (AIO_CREATE) — create context
-- 4. 663 (AIO_MULTI_WAIT) — the vulnerable call
-- 5. 669 (AIO_SUBMIT_CMD) — submit with command
-- 6. 666 (AIO_MULTI_CANCEL) — cancel
-- 7. 661 (AIO_SUBMIT) — submit
-- 8. 662 (AIO_MULTI_DELETE) — delete
-- 9. 665 (AIO_GET_DATA) — get data

-- Each tested with NULL/zero args in pcall, with canary between each.
-- If ANY survive, the Relapse bug class is potentially alive.
```

**Expected outcomes:**
- If syscalls return -1 (error): AIO subsystem is accessible but args are wrong. **THIS IS GOOD** — it means the syscall handler ran and returned, not sandbox-killed.
- If process dies: Sony AIO is kernel-level sandbox-killed, same as FreeBSD AIO. Dead end.
- If syscalls return 0: AIO subsystem is fully accessible. Test with real arguments immediately.

### Probe 52b: Sony AIO with Real Arguments

If 52a shows the syscalls survive, test with proper arguments:
- Create AIO context via `AIO_INIT`/`AIO_CREATE`
- Submit a blocked read via `AIO_SUBMIT_CMD` on a socketpair
- Poll with `AIO_MULTI_POLL`
- Wait with `AIO_MULTI_WAIT` (short timeout)
- Cancel with `AIO_MULTI_CANCEL`

This would confirm whether the full AIO lifecycle works, which is a prerequisite for the UAF race.

### Probe 52c: Relapse UAF Reproduction Attempt

If 52b shows full AIO lifecycle works, attempt a simplified version of the Relapse race:
- Claim pending requests on blocking socketpairs
- Call `AIO_MULTI_WAIT` with a short timeout
- Race with `AIO_SUBMIT_CMD` sprays
- Check if reclaimed memory overlaps (use timing and `AIO_MULTI_POLL` state checks)

This tests whether the specific UAF is still present or was patched.

---

## 5. Key Insight

**The most critical finding of this analysis is that probe 43p NEVER tested the Sony AIO syscalls that Relapse actually uses.** The probe tested standard FreeBSD AIO (syscalls 255-465), which are sandbox-killed. But Relapse uses Sony's custom AIO replacement (syscalls 661-670), which is an entirely different kernel subsystem. The process was killed at the first standard AIO call, preventing the Phase 4 sweep from ever reaching the Sony range.

Probe 52a is the single highest-priority probe to write and send next.
