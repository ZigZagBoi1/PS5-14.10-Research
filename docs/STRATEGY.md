# Exploit Strategy Assessment — PS5 14.10

> **Evidence scope (2026-10-18):** The 45c controls concern selected syscall-object metadata mutations, not every loader path. Later 56c/56f captures record selected CClosure redirects to existing Lua C functions with returned values and restoration. Those userland results do not establish arbitrary native calling conventions, a working ROP chain, injected-page execution, kernel R/W, or KASLR defeat. See [the evidence ledger guide](RESEARCH_EVIDENCE.md) and Findings 79/82.

> **Historical scope:** The narrative below preserves the earlier 43–53 research state; its unrun/open labels and broad execution conclusions are not current status. Later research remains in the probe index and Findings 79–82. The 2026-10-17 audits are dated snapshots, not summaries of every later result.

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

### ★★★ FALSE ALARM RETRACTED (2026-10-16): W^X "Defeat" Was Illusory
**Probe 45c recorded syscall results persisting when `fn_addr` values were changed or invalid and after tested chain entries were corrupted. This supports that the tested calls do not rely on those values; the probe does not identify the complete dispatch implementation. The earlier "W^X defeat" interpretation from 44a is not supported as code execution: invalid `fn_addr` values produced no crash, and the syscall still returned. Earlier ROP/fn_addr execution claims are not credited.
- mtypeprotect(585) MAY change page permissions, but we have no way to jump to the page
- Tested syscall results persisted after selected fn_addr and chain mutations; the metadata's dispatch role remains unknown
- Probe 46b reports a shared C-function __call address, but its implementation and relationship to the metadata have not been established
- **At this historical cutoff, fn_addr execution and KASLR defeat were not established; later selected CClosure redirects are separate evidence**

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
| `msync` (226) | 30 ends at `mlock: rv=0`; 42b ends after its msync region address. No msync result or termination cause recorded |
| `minherit` (250) | Probe 38 ends at the minherit section header; no call result or termination record |

## Tier 4: Long Shots

- **SCM_RIGHTS queue exhaustion** — rapid fd passing without receiving. Stresses fd table and mbuf allocation, but no threads = hard to create race.
- **SO_TIMESTAMP on TCP sockets** — might deliver cmsg with kernel timestamp addresses (untested on network sockets, only tested on UNIX where it gives nothing)
- **PS5 custom socket flags during active I/O** — toggling 0x2000/0x10000 mid-transfer might hit untested paths, but they're just boolean flags

## Tier 5: CClosure +0x20 → Eboot Gadget ROP (Most Active)

**Status:** Selected Lua C function redirects confirmed working (56c/56f). rawequal→rawget, rawget→type produced target-like outputs with successful restoration.

**Why:** CClosure +0x20 points to the C function called when a Lua closure is invoked. By writing a different function address, we redirect execution. If eboot gadgets (ret, pop rdi;ret, etc.) can be called this way, we can build a controlled execution chain.

**Next steps:**
1. Redirect +0x20 to `ret` gadget — verify clean return
2. Redirect to `pop rdi; ret` — verify argument control via Lua stack
3. Chain gadgets to call a syscall with fully controlled registers
4. Use this to invoke sysctl or other syscalls with arguments the normal path doesn't allow

**Limitations:** Machine-register argument control and arbitrary native targets are not yet established. The Lua calling convention passes arguments on the Lua stack, not in CPU registers — bridging this gap is the key challenge.

## Tier 6: Native Sysent 677–734 (Untested Surface)

**Status:** 58 syscalls completely untested. Probes 57a/57b written, awaiting execution.

**Why:** The native ELF64 sysent has 735 entries (0–734). We've only surveyed 0–676. The remaining 58 are native-only handlers that may include:
- `virtual_query_by_pid` (728) — could leak kernel VM info about other processes
- `mmap2` (725) — alternate mmap path that might bypass W^X restrictions
- Unknown Sony hardware/security syscalls

**Next steps:** Run probe 57a for initial triage, then 57b for deep testing of any that return non-negative values.

## ~~Tier 7~~ DEAD: ROP Chain Hijack via fn_addr (probe 45c)

Earlier execution-control interpretation is unsupported. Tested calls persisted after selected fn_addr and chain mutations.

## Dead Ends (Do Not Retry)

| Attack | Why dead |
|--------|----------|
| sigaltstack kernel write | copyout() validates, kills process |
| sigprocmask manipulation | Complete no-op |
| W^X bypass / mprotect EXEC | Always denied |
| Code page gadget scan | XOM — SIGBUS on read |
| Threading / race conditions | fork/rfork/thr_new all blocked |
| AIO exploitation | Older resolver probes were negative. Probe 43p's saved log ends immediately before standard aio_error(317), so raw-path outcome and Sony syscall 663 remain untested in this repo. |
| kqueue/kevent with timeout | zero-timeout register/poll/delivery works incl. combined calls (20/21); only the 100ms-timeout call returns -1 (30c). See [kevent analysis](KEVENT_TIMEOUT_VARIABLE.md). Not a leak; delivery primitive only. |
| ioctl/sysctl | Blocked |
| F_SETFL bypass | Cosmetic only — kernel ignores flags |
| F_SETOWN/SIGIO | Truly blocked |
| IPv6 extension header injection | sendmsg blocked for HBH/RTHDR/DSTOPTS |
| TCP_INFO pointer leak | No kernel pointers in 236-byte struct |
| PS5 custom socket options | Simple boolean toggles, no complex parsing |
| SNDBUF=1 overflow | Kernel handles correctly, partial writes clean |
| minherit / msync | 38 ends at the minherit section header; 42b after the msync region address. No call result or termination cause recorded |
| memfd_create | Stub — returns fake fd, no real object |
| getrandom / ppoll / cap_rights | Blocked |
| ktimer_gettime / ktimer_delete | 42a labels (settime=236, delete=237) are transposed from upstream (236=delete, 237=settime); the "odd split" matches that transposition. Differential prepared (probe 56l, unrun), no verdict change — see [corrected-MIB note](CORRECTED_MIB_14_10_EVIDENCE.md) |
| 0x1A3A4EE0 "vtable" chase | Unmapped address; 41k-era objects were heap-spray artifacts (41m–41q) |
| Loopback malformed IP options | ip_output validates lengths before ip_dooptions — need real-network input |
| sysctl kernel pointer leaks | kern.proc.all + kern.file refused on correct OIDs (valid dead ends). kstack/pcblist "blocked" verdicts rest on wrong MIBs — correct leaves `{1,14,15}`/`{4,2,6,11}` never sent; retest prepared (probe 56l, unrun), no verdict change — see [corrected-MIB note](CORRECTED_MIB_14_10_EVIDENCE.md) |
| Module data segments for kptrs | 121 "pointers" are all constants/masks (-1, -8, -16). Zero real kernel pointers (probe 42c2) |
| /dev/dmem0 for kernel access | dmem0 maps GPU GDDR6 partition only. Phys 0 has hardware regs, rest is zeros/unmapped. No system RAM access (probes 42e-42g) |
| kenv syscall (390) | 42a/42g2 captures end at the call header without result or kill record; outcome unresolved |
| TCB/FS base for kptrs | Contains only userland TLS pointers, no kernel addresses (probe 42c2) |
| AF_ROUTE KASLR (Relapse technique) | **CONFIRMED DEAD** — retest 53b: valid response, all zeroed sockaddr, zero kernel pointers. Kernel sanitizes route messages on 14.10. |
| Sys 661 kill (one number of 661-670) | 661 kills instantly for two argument shapes (probes 54c, 54f); 662-670 unmeasured — single-connection sweeps stop at 661. **SCOPE-CORRECTED** — see `docs/AIO_RANGE_14_10_EVIDENCE.md`. |
| kldstat/kldnext (307/308) | **CONFIRMED DEAD** — instantly kill process (probes 56k4, 56k5). kldsym(337) never reached. |
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
| sys 626 RDMSR | Returns -1 for all MSR indices across all arg layouts (probes 54a2, 54k) |
| sys 567 RDMSR read | Returns -1 for all MSR indices (probe 54k) |
| sys 629 jail bypass | All arg patterns return -1 (probe 54b) |
| sys 643 chicken switches | All 32 bits accepted but no observable effect — mprotect(RWX) still fails (probe 55a) |
| sys 548 batch VM ops | All operation codes return ret=-1 (probe 55b) |
| sys 622 device control | Sony error 0x800E0001 on all 400+ commands — no device context (probe 55c) |
| sys 601 process control | Most commands return -1, no init state (probe 55d) |
| sys 674 VM map kernel ptrs | 317 regions, all userland VA, zero kernel pointers (probes 55e, 55f) |
| sys 672/673/675/676 | All dead (-1 or no useful effect) (probe 55e) |
| sys 631 | Instantly kills process (probe 52a) |
| sys 627-630 | All PCALL-FAIL (probe 52a) |
| sys 572 VM info | Returns -1 or empty buffers (probe 54i) |
| sys 612 | Returns -1 for all member values (probe 54k) |
| SCTP chunk fuzzing | 39 variants, zero crashes (probe 48b) |
| IPv6 extension header fuzzing | 83 variants, zero crashes (probe 48c) |
| TCP state machine injection | 182 segments, zero crashes (probe 49a) |
| IPv6 fragment reassembly attacks | 280 fragments, zero crashes (probe 49b) |
| Exotic protocols (IGMP/GRE/ESP/AH/PIM/OSPF/VRRP) | 86 packets, zero crashes (probe 50a) |

## Live Results Summary

### Phase 14/15 (2026-10-18)
**Ran:** 54a–56l (deep syscall survey, CClosure redirect, KASLR exhaustive search), 57a/57b written (native sysent 677–734, unrun).

**Key results:**
- **CClosure +0x20 redirect confirmed** — selected Lua C targets (rawequal→rawget, rawget→type) produced target-like outputs with restore (56c/56f)
- **17 KASLR techniques tested, zero kernel pointers found** — every accessible path sanitized or blocked
- **sys 661 kills (narrowly)** — instant kill for two argument shapes (54c/54f); 662-670 were never executed in either capture
- **sys 674 VM map** — 317 named regions with protections, all userland VA (55e/55f)
- **sys 624 VM counter** — +5 per mmap, zero jitter, monotonic side channel (52b)
- **58 native-only syscalls (677–734) remain untested** — probes 57a/57b queued

### Phase 6–10 (2026-10-15/16)
**Ran:** 36–39 (raw packets), 41m–41q (vtable chase), 42a–42j (KASLR), 43a–43p (theories).

**Crash record:** magic 0x13371337 leaks module code base + heap pointers on every SIGSEGV — a per-process ASLR oracle.

## Relapse Exploit Intelligence (fw 7.00-13.60) — ROUTE DEAD, AIO UNMEASURED

The **Relapse exploit** (Sep 29, 2026) targeted fw 7.00-13.60. Patched in fw 14.00 (Sep 16, 2026). The AF_ROUTE technique is confirmed dead on 14.10; the AIO one was never measured past its first syscall:

1. **KASLR defeat via AF_ROUTE socket** — **DEAD on 14.10.** Retest 53b delivered a valid RTM_GET request and received a proper 136-byte response, but all payload is zeroed sockaddr structures. Zero kernel pointers. Kernel sanitizes route messages.

2. **`aio_multi_wait` UAF** — 14.10 evidence is one syscall: 661 kills for two argument shapes (probes 54c/54f). The rest of 662-670 was never reached, so the Relapse AIO prerequisite is untested, not disproven, on 14.10. See `docs/AIO_RANGE_14_10_EVIDENCE.md`.

3. **Portability is half-disproven** — the AF_ROUTE leak is confirmed non-functional on 14.10 (53b), but the AIO prerequisite is untested beyond 661 (see `docs/AIO_RANGE_14_10_EVIDENCE.md`). A sweep of 662-670 closes the question; a new technique is needed either way unless one of those numbers returns.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us userland memory read/write through the `memory.*` API and syscall invocation through the `syscall.*` API. `make_syscall()` bypasses the Lua resolver filter for tested syscall numbers; kernel-side restrictions still apply, and it does not provide raw kernel memory access. These are the currently documented interfaces, not necessarily the entire attack surface.

## Current Priorities (2026-10-19 update)

There is no demonstrated kernel exploit primitive on 14.10. The Relapse exploit class (AF_ROUTE + AIO) is confirmed dead. All 17 tested KASLR techniques returned zero kernel pointers. The strongest primitive is CClosure +0x20 redirect, which supports selected existing Lua C targets (56c/56f).

**Priority 1: Native sysent 677–734 (58 untested syscalls)**
The ELF64 sysent table has 735 entries. Only 0–676 have been surveyed. Key targets:
- `virtual_query_by_pid` (728) — cross-process VM query, potential KASLR via another process's kernel objects
- `mmap2` (725) — alternate mapping path, potential W^X bypass
- Probes 57a (survey) and 57b (deep test) are written and queued.

**Priority 2: CClosure → eboot gadget ROP**
56c/56f confirmed redirecting CClosure +0x20 to existing Lua C functions. Next: redirect to eboot RX gadgets (ret, pop rdi;ret, etc.) to build controlled execution. If gadgets can be called with controlled arguments, this enables arbitrary syscall invocation with full register control.

**Priority 3: Loader internals**
The C-level syscall dispatch implementation remains unidentified. Reversing the loader binary could reveal writable function pointers or additional primitives.

**Priority 4: Corrected MIB retests (56l)**
sysctl kstack ({1,14,15}) and pcblist ({4,2,6,11}) were tested with wrong MIBs. Corrected probe 56l is written but unrun.

**Priority 5: kldstat/kldsym retest (53c)**
53c never ran (connection refused). kldstat(308) is now confirmed lethal (56k4), but kldsym(337) was never directly tested — kldnext kills first. A probe that calls kldsym directly without kldnext could still work.
