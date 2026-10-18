# Exploit Strategy Assessment — PS5 14.10

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

### ★★★ FALSE ALARM RETRACTED (2026-10-16): W^X "Defeat" Was Illusory
**Probe 45c proved make_syscall() bypasses the ROP chain entirely.** fn_addr is never called as code. The "W^X defeat" from 44a was a false positive — our code page was never executed. ud2, null, and unmapped fn_addr produce no crash. Chain corruption has zero effect on syscall behavior. The entire fn_addr/ROP exploit model is dead.
- mtypeprotect(585) MAY change page permissions, but we have no way to jump to the page
- The ROP chain is vestigial metadata, not an active code path
- `make_syscall().__call` goes through a C-level wrapper directly
- **We need a new code execution primitive AND KASLR defeat**

## Remaining Challenges

1. **No threading** → no race conditions (TOCTOU, UAF-via-race, refcount races)
2. **W^X + XOM** → mtypeprotect may change permissions but we cannot jump to code pages (fn_addr is dead). XOM blocks reading system lib .text.
3. **No native code execution** → make_syscall() uses a C wrapper, not the ROP chain. fn_addr redirect is dead. We can only call syscalls, not arbitrary functions.
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

**Status:** INVALIDATED. Probe 45c proved `make_syscall()` bypasses the ROP chain entirely. fn_addr is never called. Chain corruption has zero effect. The chain is vestigial metadata.

## Dead Ends (Do Not Retry)

| Attack | Why dead |
|--------|----------|
| sigaltstack kernel write | copyout() validates, kills process |
| sigprocmask manipulation | Complete no-op |
| W^X bypass / mprotect EXEC | Always denied |
| Code page gadget scan | XOM — SIGBUS on read |
| Threading / race conditions | fork/rfork/thr_new all blocked |
| AIO exploitation | Older resolver probes were negative. Probe 43p's saved log ends immediately before standard aio_error(317), so raw-path outcome and Sony syscall 663 remain untested in this repo. |
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
| kenv syscall (390) | 42a/42g2 captures end at the call header without result or kill record; outcome unresolved |
| TCB/FS base for kptrs | Contains only userland TLS pointers, no kernel addresses (probe 42c2) |
| AF_ROUTE KASLR (Relapse technique) | Probe 43o's RTM_GET write returned -1 and its read echoed the request; delivery failed, so leak and patch status are unknown (retest 53b prepared) |
| AIO via make_syscall | Probe 43p is incomplete: saved output ends before the aio_error(317) result. Do not infer a kernel-side kill or a tested 663 outcome. |
| kldstat / kldsym | 43a/43b logs are header-only; no result or kill record (retest 53c prepared) |
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
| ROP chain hijack / fn_addr redirect | make_syscall() bypasses ROP chain entirely via C wrapper. fn_addr never called. ud2/null/unmapped = no crash. Chain corruption = no effect. (probe 45c) |
| W^X bypass via mtypeprotect + fn_addr | False positive — mtypeprotect may change perms but fn_addr never calls the page. No code execution path exists. (probes 44a, 45a-c) |
| Shellcode execution via fn_addr | All return values = pid regardless of shellcode content. Memory writes from shellcode never land. Code is never executed. (probes 45a, 45b, 45c) |

## Live Results Summary (2026-10-15 session)

**Ran:** 36 (ports), 37 (IP options), 38 (syscall sweep), 39 (frags), 41m/41n/41o/41p/41q (vtable chase), 42a (ktimer), 42b (memfd/msync).

**New usable surface:** ktimer create/settime/getoverrun on clocks 0+4. accept4/preadv/pwritev/copy_file_range resolve but need real fds. SCTP socket creation untested.

**New tooling insight:** the crash record (magic 0x13371337) leaks the module code base + heap pointers on every SIGSEGV — a per-process ASLR oracle. Gadgets can be resolved offline from a same-build binary dump.

**Loader behavior:** fresh process + fresh ASLR per connection; heap scanning must be anchor-relative; mapped heap ends in a guard page — always scan DOWN from known-mapped, print progress to survive the 30s socket timeout.

## Relapse Exploit Intelligence (fw 7.00-13.60)

The **Relapse exploit** (Sep 29, 2026) is the last public PS5 kernel exploit chain, targeting fw 7.00-13.60. Patched in fw 14.00 (Sep 16, 2026). Key techniques:

1. **KASLR defeat via AF_ROUTE socket** — public Relapse research reports this on supported firmware. Probe 43o's RTM_GET write failed and its read echoed the request, so it did not test for the leak on 14.10. Retest 53b is prepared.

2. **`aio_multi_wait` UAF** — Relapse used an AIO bug on supported firmware. Probe 43p does not reach the Sony syscall 663 scan, so the saved 14.10 results contain no test of that handler.

3. **Portability is unproven** — A historical exploit technique is a research lead, not evidence that the bug or its prerequisites exist on a later firmware.

The AF_ROUTE request in 43o was not delivered (`write ret=-1`); its read was a request echo, so that run does not test for a leak. Probe 43p is incomplete in its saved output and provides no Sony syscall 663 result. Log truncation by itself is not proof of a kernel kill.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us: arbitrary memory read/write (via `memory.*` API), syscall invocation (via `syscall.*` API), and the `make_syscall()` bypass for raw kernel access. This is our entire attack surface.

## Current Priorities (2026-10-17 evidence review)

There is no demonstrated kernel exploit primitive on 14.10. Probe 45c showed that `make_syscall()` bypasses the Lua resolver but does not call the writable `fn_addr` or ROP chain. Probe 43o did not deliver its AF_ROUTE request. Probe 43p's saved log stops before its first standard AIO call result and before its planned scan; it does not close the Sony syscall 663 path. See the corrected coverage note in [the secondary exploit audit](SECONDARY_EXPLOIT_AUDIT_13.60.md).

The 13.60 dump is useful as a static reference, but it is not a 14.10 kernel image. The newly supplied index duplicates the existing 13.60 index in this repository for syscall 0–676 (same argument counts and normalized handler offsets; absolute addresses differ with KASLR). Its 677–678 argument counts are implausible, and the separate name map needs reconciliation before aggregate syscall counts are relied upon. See [the evidence audit](EVIDENCE_AUDIT_2026-10-17.md).

Next work should reconcile the 13.60 raw table and syscall names, preserve exact probe outcomes without interpreting successful returns as vulnerabilities, and obtain a verified 14.10 kernel-code image or live dump before making firmware-specific handler claims. The standard Lua loader and current probe evidence do not provide kernel read/write or native kernel execution. Do not repeat probes already recorded unless their source logs change.
