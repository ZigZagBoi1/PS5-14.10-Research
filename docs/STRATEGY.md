# Exploit Strategy Assessment — PS5 14.10

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

### ★★★ FALSE ALARM RETRACTED (2026-10-16): W^X "Defeat" Was Illusory
**Probe 45c recorded syscall results persisting when `fn_addr` values were changed or invalid and after tested chain entries were corrupted. This supports that the tested calls do not rely on those values; the probe does not identify the complete dispatch implementation. The earlier "W^X defeat" interpretation from 44a is not supported as code execution: invalid `fn_addr` values produced no crash, and the syscall still returned. Earlier ROP/fn_addr execution claims are not credited.
- mtypeprotect(585) MAY change page permissions, but we have no way to jump to the page
- The ROP chain is vestigial metadata, not an active code path
- `make_syscall().__call` goes through a C-level wrapper directly
- **We need a new code execution primitive AND KASLR defeat**

## Remaining Challenges

1. **No threading** → no race conditions (TOCTOU, UAF-via-race, refcount races)
2. **W^X + XOM** → mtypeprotect may change permissions but we cannot jump to code pages (fn_addr is dead). XOM blocks reading system lib .text.
3. **No native code execution is established by these tests** → probe 45c undermines the earlier `fn_addr`/ROP execution interpretation; the complete dispatch implementation remains unidentified.
4. **Minimal syscall surface** → most syscalls blocked even via make_syscall
5. **KASLR defeat** → every direct info leak path tested and dead. Need kernel base address.

## Tier 1: RAW Socket Packet Injection (Most Promising)

**Status:** RAW socket + IP_HDRINCL confirmed working. Crafted UDP packets reach kernel `ip_input()`.

**Why:** Bypasses the syscall sandbox entirely. The kernel parses our crafted packet data in network stack context, not behind the syscall filter. The network input path is orders of magnitude larger than the syscall surface we can reach directly.

**Attack vectors within this path:**
- **IP fragment reassembly (`ip_reass()`)** — historically one of the most bug-prone areas in BSD kernels. Overlapping fragments, tiny fragments, fragment timeout interactions. *Status: testing blocked by bind() issue, needs retry.*
- **IP options parsing (`ip_dooptions()`)** — LSRR, SSRR, record-route, timestamp options hit complex allocation and copy code paths. These don't need fragment reassembly.
- **Protocol demux** — unusual protocol numbers, ICMP input processing
- **UDP input edge cases** — malformed UDP headers, zero-length payloads, broadcast addresses

**Next steps:**
1. Fix the bind() issue (try port 31338 which worked in probe 34, or investigate port restrictions)
2. Test IP options (LSRR/SSRR/record-route/timestamp) — no reassembly needed
3. Retry fragment reassembly with a working listener
4. Test ICMP injection

## Tier 2: TCP Connect-Back (Network-Side Attack)

**Status:** Not yet attempted.

**Why:** Connect the PS5 back to our machine via TCP, then send malformed TCP from the attacker side using scapy. The kernel's `tcp_input()` is enormous.

**Attack vectors:**
- TCP SACK processing (CVE-2019-11477 "SACK Panic" class)
- TCP urgent/OOB data state machine
- TCP option parsing loop (`tcp_dooptions()`)
- Malformed TCP window scaling
- TIME_WAIT state manipulation

**Requirement:** Scapy or raw socket on attacker machine to craft TCP packets.

## Tier 3: Unprobed Syscalls

**Status:** Never tested.

| Syscall | Why interesting |
|---------|----------------|
| `ktimer_create/settime` (235-238) | POSIX timers create kernel objects with complex lifecycle. Timer callbacks run in kernel context. |
| `accept4` (541) | TCP accept with flags — different sandbox path than accept? |
| `preadv/pwritev` (289-290) | Vectored I/O with offset — different kernel path than readv/writev |
| `copy_file_range` (580) | File-to-file copy in kernel — complex VFS interaction |
| `cap_rights_limit/get` (533+) | Capsicum capabilities may interact oddly with PS5 sandbox |
| `msync` (226) | Caused crash in probe 30 — never isolated |
| `minherit` (250) | Never tested |

## Tier 4: Long Shots

- **SCM_RIGHTS queue exhaustion** — rapid fd passing without receiving. Stresses fd table and mbuf allocation, but no threads = hard to create race.
- **SO_TIMESTAMP on TCP sockets** — might deliver cmsg with kernel timestamp addresses (untested on network sockets, only tested on UNIX where it gives nothing)
- **PS5 custom socket flags during active I/O** — toggling 0x2000/0x10000 mid-transfer might hit untested paths, but they're just boolean flags

## ~~Tier 5: ROP Chain Hijack~~ — DEAD (probe 45c)

**Status:** Earlier execution-control interpretation is unsupported by probe 45c. In that probe, syscall results persisted with changed or invalid `fn_addr` values and tested chain-entry corruption. This does not establish the complete dispatch implementation.

## Dead Ends (Do Not Retry)

| Attack | Why dead |
|--------|----------|
| sigaltstack kernel write | copyout() validates, kills process |
| sigprocmask manipulation | Complete no-op |
| W^X bypass / mprotect EXEC | Always denied |
| Code page gadget scan | XOM — SIGBUS on read |
| Threading / race conditions | fork/rfork/thr_new all blocked |
| AIO exploitation (via resolve() AND make_syscall) | sandbox-killed at kernel level — confirmed dead via both paths (probes 19, 43p) |
| kqueue/kevent | kevent always -1 |
| ioctl/sysctl | Blocked |
| F_SETFL bypass | Cosmetic only — kernel ignores flags |
| F_SETOWN/SIGIO | Truly blocked |
| IPv6 extension header injection | sendmsg blocked for HBH/RTHDR/DSTOPTS |
| TCP_INFO pointer leak | No kernel pointers in 236-byte struct |
| PS5 custom socket options | Simple boolean toggles, no complex parsing |
| SNDBUF=1 overflow | Kernel handles correctly, partial writes clean |
| minherit / msync | **Instant process kill on first call** (probes 38/42b) |
| memfd_create | Stub — returns fake fd, no real object |
| getrandom / ppoll / cap_rights | Blocked |
| ktimer_gettime / ktimer_delete | Blocked (create/settime/getoverrun work — weird split) |
| 0x1A3A4EE0 "vtable" chase | Unmapped address; 41k-era objects were heap-spray artifacts (41m–41q) |
| Loopback malformed IP options | ip_output validates lengths before ip_dooptions — need real-network input |
| sysctl kernel pointer leaks | ALL blocked: kern.proc.all, kern.file, kstack, auxv, sigtramp, tcp.pcblist, route.dump — sandbox in kernel (probes 42a-b, 42h2) |
| Module data segments for kptrs | 121 "pointers" are all constants/masks (-1, -8, -16). Zero real kernel pointers (probe 42c2) |
| /dev/dmem0 for kernel access | dmem0 maps GPU GDDR6 partition only. Phys 0 has hardware regs, rest is zeros/unmapped. No system RAM access (probes 42e-42g) |
| kenv syscall (390) | Instant process kill — sandbox (probe 42g2) |
| TCB/FS base for kptrs | Contains only userland TLS pointers, no kernel addresses (probe 42c2) |
| AF_ROUTE KASLR (Relapse technique) | Probe 43o reported no pointers in one 108-byte response; tested RTM_GET writes failed. This attempt does not establish patch status across variants. |
| AIO via make_syscall | Sandbox kill is kernel-level, not resolve()-side. aio_error instant-kills even raw (probe 43p) |
| kldstat / kldsym | Both sandbox-killed at kernel. No KLD introspection possible (probes 43a, 43b) |
| kinfo_proc kernel pointers | Full 1096B dump: only sentinel values, no real kernel pointers (probe 43d) |
| kern.proc.filedesc | Blocked — ret=-1, size=0 (probe 43d) |
| kern.proc.vmmap (large buffers) | ret=-1 with 64K-256K buffers (probe 43d) |
| sysctl write paths | All writes blocked: securelevel, coredump, maxproc, debug (probe 43f) |
| sysarch GET_GSBASE | Returns 0 — no kernel curthread pointer leaked (probe 43c) |
| ioctl via make_syscall | Returns -1 for all tested ioctls even via raw syscall (probe 43e) |
| dup/dup2 via make_syscall | Returns -1 (probe 43e) |
| thr_new via make_syscall | Crashes process (probe 43e) |
| kern.msgbuf full read | Returns only 8 bytes stub — filtered (probe 43j) |
| mincore KASLR oracle | All kernel VA probes return -1. Userland only (probe 43l) |
| sockopt buffer overflow | Kernel clamps copy length internally — not an overflow (probe 43m) |
| /dev/hid ioctl | All ioctls return Sony error 0x80740004 (probe 43n) |
| ROP chain hijack / fn_addr redirect | In probe 45c, syscall results persisted with altered/invalid `fn_addr` values and tested chain-entry corruption; this does not establish the complete dispatch implementation. |
| W^X bypass via mtypeprotect + fn_addr | False positive — mtypeprotect may change perms but fn_addr never calls the page. No code execution path exists. (probes 44a, 45a-c) |
| Shellcode execution via fn_addr | All return values = pid regardless of shellcode content. Memory writes from shellcode never land. Code is never executed. (probes 45a, 45b, 45c) |

## Live Results Summary (2026-10-15 session)

**Ran:** 36 (ports), 37 (IP options), 38 (syscall sweep), 39 (frags), 41m/41n/41o/41p/41q (vtable chase), 42a (ktimer), 42b (memfd/msync).

**New usable surface:** ktimer create/settime/getoverrun on clocks 0+4. accept4/preadv/pwritev/copy_file_range resolve but need real fds. SCTP socket creation untested.

**New tooling insight:** the crash record (magic 0x13371337) leaks the module code base + heap pointers on every SIGSEGV — a per-process ASLR oracle. Gadgets can be resolved offline from a same-build binary dump.

**Loader behavior:** fresh process + fresh ASLR per connection; heap scanning must be anchor-relative; mapped heap ends in a guard page — always scan DOWN from known-mapped, print progress to survive the 30s socket timeout.

## Relapse Exploit Intelligence (fw 7.00-13.60)

The **Relapse exploit** (Sep 29, 2026) is the last public PS5 kernel exploit chain, targeting fw 7.00-13.60. Patched in fw 14.00 (Sep 16, 2026). Key techniques:

1. **KASLR defeat via AF_ROUTE socket** — `socket(PF_ROUTE=17, SOCK_RAW)` + `RTM_GET` queries leak kernel `.text` pointers from routing table entries. This is completely different from our sysctl scanning approach. **Probe 43o tests this.**

2. **`aio_multi_wait` UAF** — The actual kernel bug was a use-after-free race condition in Sony's `aio_multi_wait` syscall. The specific bug is patched, but the AIO subsystem itself might be accessible via `make_syscall()`. We only tested AIO through `resolve()` (which kills the process), never via raw syscall numbers. **Probe 43p tests this.**

3. **Bug class is alive even if specific bugs are patched** — Relapse used a race condition in AIO. If AIO works via make_syscall, the entire async race condition class opens up: concurrent kernel operations without userland threading.

**What we should steal from Relapse:**
- AF_ROUTE KASLR defeat — probe 43o (the technique is independent of the UAF bug)
- AIO bypass test — probe 43p (sandbox kill might be Lua-side only)
- Race condition methodology — if AIO lives, we can build UAF/TOCTOU primitives

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us: arbitrary memory read/write (via `memory.*` API), syscall invocation (via `syscall.*` API), and the `make_syscall()` bypass for raw kernel access. This is our entire attack surface.

## Next Priorities (Updated 2026-10-17 after kernel dump analysis)

### The Situation
Probe 45c undermines the earlier ROP-chain and `fn_addr` execution interpretation: tested syscall results persisted despite the changes recorded in that probe. Network fuzzing (584+ variants, probes 49a/49b/50a-50d) produced zero crashes. However, **kernel dump analysis of FW 13.60** has revealed a massive untested attack surface.

### ★★★ BREAKTHROUGH: Kernel Dump Sysent Analysis (2026-10-17)

Reverse-engineered the PS5 13.60 kernel live RAM dump and successfully decoded the **complete sysent table**: 679 entries, 308 implemented syscalls. Key finding: **116 Sony-custom syscalls in the 532-676 range**, of which only 3 have been tested (557, 593, 620). The syscalls cluster into identifiable subsystems:

| Group | Syscalls | Handler Region | Likely Subsystem |
|-------|----------|---------------|-----------------|
| dynlib | 591-599, 608, 612, 649, 656, 659, 660, 672 | TEXT+0x340000 | Dynamic linker (includes known 593) |
| vm | 547, 548, 559, 572, 588, 607, 613, 615, 618, 620, 624, 628, 637, 642, 646, 647, 671, 674 | TEXT+0xab0000 | VM/memory management |
| sysC | 549-556 | TEXT+0xc10000 | Unknown Sony subsystem (8 tightly packed) |
| sysD | 538-546 | TEXT+0xba-bb0000 | Unknown Sony subsystem (9 handlers) |
| proc | 563-567, 625-626 | TEXT+0x600000 | Process/scheduling |
| dev | 661-670 | TEXT+0x3b0000 | Device/IPC (newer, high-numbered) |
| thread | 616, 632-634 | TEXT+0x430000 | Threading primitives |
| event | 600-606, 611, 643 | TEXT+0xa30000 | Event/notification |

Full mapping saved in `docs/ps5_13.60_sysent.json`.

### Priority 1: Sony Syscall Survey (probes 51a/51b) — HIGHEST PRIORITY
**113 untested Sony syscalls.** Probe 51a tests all of them with safe args to determine which are accessible from the sandbox. Probe 51b does deep testing of accessible ones with output buffers, looking for kernel pointer leaks. Any one of these could:
- Leak a kernel pointer (KASLR defeat)
- Have a buffer handling bug (kernel R/W)
- Accept complex structures with exploitable parsing

### Priority 2: Dynlib Group Deep Dive (591-599, 608, 649, 659)
These sit next to `dynlib_get_info` (593) which we know returns module info. The other dynlib syscalls likely handle module loading, symbol lookup, and segment mapping. They may return kernel addresses that `dynlib_get_info` sanitizes.

### Priority 3: VM/Memory Group (547, 572, 607, 628, 642, 671, 674)
18 syscalls near the mmap/memory subsystem. Several take 4-6 args suggesting complex buffer operations. High chance of copyout bugs or uninitialized memory leaks.

### Priority 4: Network Fuzzing from PC (if syscall survey fails)
TCP input-side attacks, SCTP, IPv6 NDP — only worthwhile if the Sony syscall survey comes up empty.

### Priority 5: Sandbox Logic Reverse Engineering
The kernel dump's sysctl handler (TEXT+0x5481e0) shows the sandbox check function. Understanding how it works could reveal bypass techniques.
