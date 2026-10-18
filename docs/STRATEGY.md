# Exploit Strategy Assessment — PS5 14.10

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

### ★★★ FALSE ALARM RETRACTED (2026-10-16): W^X "Defeat" Was Illusory
**Probe 45c recorded syscall results persisting when `fn_addr` values were changed or invalid and after tested chain entries were corrupted. This supports that the tested calls do not rely on those values; the probe does not identify the complete dispatch implementation. The earlier "W^X defeat" interpretation from 44a is not supported as code execution: invalid `fn_addr` values produced no crash, and the syscall still returned. Earlier ROP/fn_addr execution claims are not credited.
- mtypeprotect(585) MAY change page permissions, but we have no way to jump to the page
- Tested syscall results persisted after selected fn_addr and chain mutations; the metadata's dispatch role remains unknown
- Probe 46b reports a shared C-function __call address, but its implementation and relationship to the metadata have not been established
- **We need a new code execution primitive AND KASLR defeat**

## Remaining Challenges

1. **No threading** → no race conditions (TOCTOU, UAF-via-race, refcount races)
2. **W^X + XOM** → mtypeprotect may change permissions, but no execution from the test page is demonstrated. Probe 45c undermines the earlier fn_addr execution interpretation; the dispatch path remains unknown. XOM blocks reading system lib .text.
3. **No native code execution is established by these tests** → probe 45c undermines the earlier `fn_addr`/ROP execution interpretation; the complete dispatch implementation remains unidentified.
4. **Minimal syscall surface** → most syscalls blocked even via make_syscall
5. **KASLR defeat** → no kernel base leak is established. Some tested paths returned no pointer, while AF_ROUTE and KLD attempts were incomplete or undelivered.

## Tier 1: RAW Socket Packet Injection (Most Promising)

**Status:** RAW socket + IP_HDRINCL confirmed working. Crafted UDP packets reach kernel `ip_input()`.

**Why:** Once raw-socket creation and packet transmission are available, crafted traffic reaches kernel network parsers. This explores a different input surface; it does not bypass kernel restrictions or prove exploitability.

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

## Tier 5: ROP Chain Hijack — Unsupported by Current Evidence (probe 45c)

**Status:** Earlier execution-control interpretation is unsupported by probe 45c. In that probe, syscall results persisted with changed or invalid `fn_addr` values and tested chain-entry corruption. This does not establish the complete dispatch implementation.

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
| AF_ROUTE KASLR (Relapse technique) | Probe 43o's RTM_GET write returned -1 and its read returned 108 bytes with zero detected pointers and unresolved attribution; successful delivery is not established, so leak and patch status are unknown (retest 53b prepared) |
| AIO via make_syscall | Probe 43p is incomplete: saved output ends before the aio_error(317) result. Do not infer a kernel-side kill or a tested 663 outcome. |
| kldstat / kldsym | 43a/43b logs are header-only; no result or kill record (retest 53c prepared) |
| kinfo_proc kernel pointers | Full 1096B dump: only sentinel values, no real kernel pointers (probe 43d) |
| kern.proc.filedesc | Blocked — ret=-1, size=0 (probe 43d) |
| kern.proc.vmmap (large buffers) | ret=-1 with 64K-256K buffers (probe 43d) |
| sysctl write paths | 43f recorded one failed securelevel-labeled write. coredump/maxproc/debug reads failed, so their writes were not reached; this does not establish all writes blocked |
| sysarch GET_GSBASE | Returns 0 — no kernel curthread pointer leaked (probe 43c) |
| ioctl via make_syscall | Returns -1 for all tested ioctls even via raw syscall (probe 43e) |
| dup/dup2 via make_syscall | Returns -1 (probe 43e) |
| thr_new via make_syscall | Crashes process (probe 43e) |
| kern.msgbuf full read | Returns only 8 bytes stub — filtered (probe 43j) |
| mincore KASLR oracle | All kernel VA probes return -1. Userland only (probe 43l) |
| sockopt buffer overflow | Kernel clamps copy length internally — not an overflow (probe 43m) |
| /dev/hid ioctl | All ioctls return Sony error 0x80740004 (probe 43n) |
| ROP chain hijack / fn_addr redirect | In probe 45c, syscall results persisted with altered/invalid `fn_addr` values and tested chain-entry corruption; this does not establish the complete dispatch implementation. |
| W^X bypass via mtypeprotect + fn_addr | The earlier claim is unsupported: the available returns did not prove page execution, and 45c results persisted after selected metadata mutations. No native code execution path is established. (probes 44a, 45a-c) |
| Shellcode execution via fn_addr | Proposed writes did not land and returns stayed equal to PID; 45c further undermined the assumed dispatch path. These runs do not establish shellcode execution or prove every path cannot execute code. (probes 45a, 45b, 45c) |

## Live Results Summary (2026-10-15 session)

**Ran:** 36 (ports), 37 (IP options), 38 (syscall sweep), 39 (frags), 41m/41n/41o/41p/41q (vtable chase), 42a (ktimer), 42b (memfd/msync).

**New usable surface:** ktimer create/settime/getoverrun on clocks 0+4. accept4/preadv/pwritev/copy_file_range resolve but need real fds. SCTP socket creation untested.

**New tooling insight:** the crash record (magic 0x13371337) leaks the module code base + heap pointers on every SIGSEGV — a per-process ASLR oracle. Gadgets can be resolved offline from a same-build binary dump.

**Loader behavior:** fresh process + fresh ASLR per connection; heap scanning must be anchor-relative; mapped heap ends in a guard page — always scan DOWN from known-mapped, print progress to survive the 30s socket timeout.

## Relapse Exploit Intelligence (fw 7.00-13.60)

The **Relapse exploit** (Sep 29, 2026) is the last public PS5 kernel exploit chain, targeting fw 7.00-13.60. Patched in fw 14.00 (Sep 16, 2026). Key techniques:

1. **KASLR defeat via AF_ROUTE socket** — public Relapse research reports this on supported firmware. Probe 43o's RTM_GET write failed and its read returned 108 bytes with zero detected pointers and unresolved attribution, so a valid disclosure test on 14.10 is not established. Retest 53b is prepared.

2. **`aio_multi_wait` UAF** — Relapse used an AIO bug on supported firmware. Probe 43p does not reach the Sony syscall 663 scan, so the saved 14.10 results contain no test of that handler.

3. **Portability is unproven** — A historical exploit technique is a research lead, not evidence that the bug or its prerequisites exist on a later firmware.

Probe 43o recorded `write ret=-1` and a 108-byte read with zero detected pointers. The read's origin and successful request delivery are unresolved, so the run does not establish a valid disclosure test. Probe 43p is incomplete in its saved output and provides no Sony syscall 663 result. Log truncation by itself is not proof of a kernel kill.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us userland memory read/write through the `memory.*` API and syscall invocation through the `syscall.*` API. `make_syscall()` bypasses the Lua resolver filter for tested syscall numbers; kernel-side restrictions still apply, and it does not provide raw kernel memory access. These are the currently documented interfaces, not necessarily the entire attack surface.

## Current Priorities (2026-10-17 evidence review)

There is no demonstrated kernel exploit primitive on 14.10. Probe 45c recorded tested calls persisting after specific fn_addr and chain mutations, which undermines the earlier execution interpretation but does not identify the dispatch implementation. Probe 43o did not deliver its AF_ROUTE request. Probe 43p's saved log stops before its first standard AIO call result and before its planned scan; it does not close the Sony syscall 663 path. See the corrected coverage note in the secondary exploit audit.

The 13.60 dump is useful as a static reference, but it is not a 14.10 kernel image. The newly supplied index duplicates the existing 13.60 index in this repository for syscall 0–676 (same argument counts and normalized handler offsets; absolute addresses differ with KASLR). Its 677–678 argument counts are implausible, and the separate name map needs reconciliation before aggregate syscall counts are relied upon. See [the evidence audit](EVIDENCE_AUDIT_2026-10-17.md).

Next work should reconcile the 13.60 raw table and syscall names, preserve exact probe outcomes without interpreting successful returns as vulnerabilities, and obtain a verified 14.10 kernel-code image or live dump before making firmware-specific handler claims. The standard Lua loader and current probe evidence do not provide kernel read/write or native kernel execution. Do not repeat probes already recorded unless their source logs change.
