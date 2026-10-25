# Exploit Strategy Assessment — PS5 14.10

> **Evidence scope (2026-10-18):** The 45c controls concern selected syscall-object metadata mutations, not every loader path. Later 56c/56f captures record selected CClosure redirects to existing Lua C functions with returned values and restoration. Those userland results do not establish arbitrary native calling conventions, a working ROP chain, injected-page execution, kernel R/W, or KASLR defeat. See [the evidence ledger guide](RESEARCH_EVIDENCE.md) and Findings 79/82.

> **Historical scope:** The narrative below preserves the earlier 43–53 research state; its unrun/open labels and broad execution conclusions are not current status. Later research remains in the probe index and Findings 79–82. The 2026-10-17 audits are dated snapshots, not summaries of every later result.

## Current position (2026-10-22)

The goal is unchanged: userland code execution to kernel read/write, then the
hypervisor. What has changed is how much of the surface is now measured, so this
section is the status and everything below it is history.

### Primitives that exist

| primitive | evidence | limits |
|---|---|---|
| Lua code execution on TCP 9026 | loader | userland only |
| Arbitrary tested syscall invocation | `make_syscall`, entry at `syscall_address` (`gettimeofday_import + 7`) | kernel-side checks still apply |
| Thread creation with controlled registers | 156c/156d, short recipe 272a | child runs in eboot's RX text; no TLS; no `mprotect(EXEC)` |
| GPU pool mapping, userland read/write | 477 with flags `0x1002` | finite: a fresh process mapped 8 + 64 + 256 MiB and no more; nothing returns pages to the pool |
| Event and named objects | 538/540/544/545/546, 557 | registry is process-scoped (342a); handles from another family are refused (347a) |
| Fixed-offset 8-byte kernel store | 637 | destination is `child+0x280` of the caller's own process; effect on outcomes not established |

### Walls that are measured, not assumed

- **No credential context.** 618, 646 and 671 gate on bit 62 of the word at
  `*(td+0x140)+0x60`; the credential dump (587) shows `+0x08` zero and only
  `0x20000000` at `+0x0C`. No recovered handler writes `cred+0x58`, so the
  identity comes from the launched image.
- **No device context.** 622's `0x100` group answers with a single status dword
  or `0x8002004E`; its `0x200` group answers `0xFFFFFFFF`; `0x400` with a
  successful copyin dies after the copy. 532's handle integrity check is fully
  forgeable (the input is caller-controlled) and still stops at an empty
  registration table. 654 and 657 need object type `0x9d == 11`; none of the 314
  regions in this process's map qualifies.
- **No kernel pointer.** Every leak-shaped call returns sentinels or zeroed
  records: route messages, kinfo_proc, the 674 region dump, 587, 618/646, the
  module query, and the 634 ucontext snapshot (zeroed first, no tail).
- **No arbitrary kernel address.** Across all 145 handler dossiers exactly two
  handlers store a caller-chosen value: 637 writes it to `child+0x280` of the
  caller's own process object, and 625 writes it to performance-counter MSRs at
  indices bounded to `-1..5` and `0..3` (and 625 has never been called). Neither
  destination is caller-influenced.
- **Death on touch.** 561, 661, 665, 668 and the whole `kld*` family plus
  `sysctlbyname` kill the process at the call; 662-664, 666, 667 and 669 return
  `-1`; 670 returns 0 and changes nothing observable.
- **The jail.** The process sees `/`, `/app0`, `/dev`, `/savedata0`,
  `/av_contents` and one private directory. 34 device nodes open, and every
  driver-specific command offered is refused. Three system sockets outside the
  jail accept a connection (`GnmCompositorRestricted`, `VrTracker2DomainSock`,
  `AgcCompositorSppSocket`) and send no greeting.
- **WebKit.** The 1903-page regression corpus ran to 121 on the console; every
  divergence so far is a hang, not a memory error, and 1070 sources screened
  under ASAN reported none. The font-face trigger from the public write-up hangs
  the guide instead of crashing it.

### What is left

1. **Obtain a 14.10 kernel image.** Every handler dossier is 13.60, so every
   probe is a cross-build guess. The console's update client speaks plain HTTP to
   `pc.ps5.update.playstation.net`, but the captured path 404s off-console and a
   PUP needs console-side decryption.
2. **The death-on-touch handlers with shaped arguments** (561, 661, 665, 668).
3. **Unmeasured contracts**: 657's record batch, 549-556 as one object family,
   and 625's 23-command MSR interface, which has no credential read in its root.
4. **Finish the JSC corpus** (121/1903) and decide whether a hang-only result
   closes the browser route.

Anything else on this page should be read as the 2026-10-16 position, kept for
provenance.

## Historical position (2026-10-16)

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
| minherit | 38 ends at the minherit section header; no call result or termination cause recorded |
| msync via 226 (nosys) | 226 is a nosys stub — real msync is 65 (PR #70, DEM9N101). Earlier probes called dead air. Probe 58a corrected and queued. |
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
| netcontrol(99) netevent UAF | **CONFIRMED DEAD** — 14.10 leaks the socket reference on close-before-unregister instead of freeing it. No double-free, no dangling pointer. Public exploit chain (Poops) precondition does not hold. (probes 223a–234a, PR #69 ng643) |
| Sony object families (jitshm/osem/debug_init) | jitshm(533/534) -1, osem(549–556) -1, debug_init(560) no-op, suspend_process(561) kills. namedobj(557/558) not name-keyed — no UAF via collision. set_vm_container(559) is a query. EVF set-vs-cancel race clean. (probes PR #72, ng643) |
| thr_get_ucontext(634) | Writes nothing for any arg shape, even with alive child TID. Dead. (probe 235a, PR #71 ng643) |
| blockpool_batch(657) | Returns status dword 0 only, no device-memory copy. Still writes after close(h) but write is worthless. (PR #71 ng643) |
| query_memory_protection(547) | Userland-only VM lookup. All 32 kernel addresses return -1. No KASLR oracle. (PR #71 ng643) |
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

## Relapse / Lapse Exploit Intelligence — DELETE MITIGATED, CANCEL CORRUPTS AIO

The **Relapse exploit** (Sep 29, 2026) targeted fw 7.00-13.60. Patched in fw 14.00. The **"lapse family"** kexploit raced `aio_multi_delete` (662) — Coixao (Oct 24) identified the exact path: a TOCTOU in the delete lock-drop gap where a racing create can reclaim the freed slot, causing delete to free sub-objects of the new object (UAF/double-free). Sony added a generation-ID revalidation in **14.20** to kill this race.

1. **KASLR defeat via AF_ROUTE socket** — **DEAD on 14.10.** Retest 53b: zero kernel pointers. Kernel sanitizes route messages.

2. **`aio_multi_delete` (662) TOCTOU race** — **RACE WINDOW OPEN BUT MITIGATED on 14.10.** Probe 540b achieved 384/384 swap detections (status `0x80020010`). However, 540c verified that the kernel detects the swap and **aborts the free**: spray requests remain healthy, original IDs become undeletable zombies. This is a partial mitigation — not the full 14.20 gen-ID fix, but sufficient to prevent the UAF via delete. See `probes/phase29_aio_race/540a-540c`.

3. **`aio_multi_cancel` (666) and `aio_multi_wait` (663) TOCTOU race** — **NO REVALIDATION, AIO SUBSYSTEM CORRUPTION on 14.10.**
   - 541a (cancel, completed requests): returned `0x00000003` (success) with ZERO swap detections. No damage on completed.
   - **541b (cancel, in-flight requests): corrupts the entire AIO subsystem.** Cancel of in-flight socketpair reads — while spray reclaims slots — returns state `0x4`/`0x2`. Post-race: ALL 128 spray requests stuck in state=0x1, sentinel data untouched, delete returns `0x80020010`. Fresh requests also fail (UNHEALTHY). Process hangs after corruption (required power cycle).
   - 541c (cancel + write trigger): writing BEEF to socketpairs after corruption produces no data in either buffer. Cancel fully aborted the original I/O (state=0x4) but orphaned the spray requests' scheduling metadata. Not a direct write primitive.
   - **541d (wait, in-flight requests): SAME CORRUPTION as cancel.** Wait with timeout={0,0} on in-flight requests — while spray reclaims slots — produces identical subsystem corruption: spray stuck at state=0x1, originals at 0x1/0x2, fresh requests UNHEALTHY. Wait on completed requests is harmless (sentinel unchanged, spray healthy).
   - **Pattern:** Sony added revalidation to delete(662) but NOT to cancel(666) or wait(663). Both corrupt AIO when racing in-flight requests. The corruption is subsystem-wide, not per-slot.
   - **Escalation direction:** The corruption orphans spray requests (never enqueued to VFS). Next: exploit the corrupted scheduling state — e.g. re-submit to a corrupted slot, or use poll(664) to read cross-object metadata from the corrupted slot. See `probes/phase29_aio_race/541a-541d`.

4. **Scene intelligence (Oct 2026):**
   - **Gezine (@gezine_dev, Oct 19)**: Video showing ★Debug Settings active on 14.10 = confirmed kernel R/W. "kexploit I used at 13.xx was patched at 14.00, it's not relapse." "Old way to dump executables does not work at 14.xx. Maybe HV exploit really is needed."
   - **Coixao (@notnotzecoxao, Oct 24)**: Identified `aio_multi_delete` as the lapse family kexploit path. Confirmed Prolapse (Canvas UAF) coming to 14.00/14.10.
   - Gezine's 14.10 kexploit is NOT Relapse and NOT the AIO race we tested — it's an unknown exploit.

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us userland memory read/write through the `memory.*` API and syscall invocation through the `syscall.*` API. `make_syscall()` bypasses the Lua resolver filter for tested syscall numbers; kernel-side restrictions still apply, and it does not provide raw kernel memory access. These are the currently documented interfaces, not necessarily the entire attack surface.

## Current Priorities (2026-10-25 update)

There is no demonstrated kernel exploit primitive on 14.10. Gezine has kernel R/W on 14.10 via an unknown (unpublished) kexploit. The Relapse AIO race path is partially mitigated (swap detected and prevented, 540b/540c). CVE-2019-5607 is fully patched (527b-527d). All 17 tested KASLR techniques returned zero kernel pointers. Physical memory path exhausted (dmem0 = GPU pool only, pager extension = VM-only). The hypervisor appears strengthened in 14.xx (executable dumping no longer works with just kernel R/W per Gezine).

### Closed vectors this session
- **CVE-2019-5607 (ghost handle)** — DGRAM/STREAM/SEQPACKET all clean. Zero phantom fds. Patched.
- **aio_multi_delete TOCTOU race** — Race window open (384/384 swaps) but kernel aborts the free after detecting the swap. Partial mitigation present on 14.10.
- **fd-close/sendmsg race (534f)** — T2 wins trivially (fd closed before T1's 2nd send). No type confusion. Would need per-iteration barrier sync (no branch gadgets available).
- **Physical memory path** — GPU pool only, no system RAM access. mmap_dmem verifies ownership+size. Pager extension is VM-only.

### Remaining attack surface

**Priority 1: ★★★ AIO cancel corruption escalation (541b breakthrough)**
`aio_multi_cancel` (666) has NO swap revalidation and corrupts the AIO subsystem when racing in-flight requests. Spray requests stuck in state=0x1, I/O never fires, entire subsystem broken. Next steps:
- **541c**: After the race, write data to the original socketpairs. If the kernel's deferred read completion fires on the corrupted request, WHERE does it write? Original buffer? Spray buffer? Neither? This discriminates between "metadata corruption" and "kernel write to controlled address".
- **541d**: Vary the spray request data pointers to point at interesting targets (e.g. known kernel-adjacent userland pages). If cancel cross-wires the I/O destination, completing the original read writes to the spray buffer → **kernel write primitive**.
- **541e**: Test `aio_multi_wait` (663) for the same missing revalidation.

**Priority 2: ★★ Kernel image acquisition**
Without a 14.10 kernel dump, every probe is a cross-build guess from 13.60 dossiers. Gezine's kexploit is unknown — having the real sysent table and handler code would reveal what they found. PUP decryption, alternative dump paths, or community collaboration needed.

**Priority 3: ★ WebKit Prolapse info leak contribution**
Canvas UAF (CVE-2026-43720) confirmed on 14.10. IsoHeap OFF, Gigacage OFF. The sole blocker is reading a heap pointer as a JS number. This requires browser-side work (JavaScript), not Lua. Our contribution: ASLR data, module layout, threading primitives.

**Priority 4: Threaded UMTX PI-mutex races**
UMTX_OP_WAIT/WAKE/MUTEX functional. PI-mutex allocates `umtx_pi` objects with historical UAF/race bugs. Same stagger technique from 540b could apply.

**Priority 5: Native sysent 677–734 (58 untested syscalls)**
Key targets: `virtual_query_by_pid` (728), `mmap2` (725). Probes 57a/57b queued.

**Priority 6: Loader internals**
The C-level syscall dispatch implementation remains unidentified. Reversing the loader binary could reveal writable function pointers or additional primitives.
