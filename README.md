# PS5 Firmware 14.10 - Kernel Research

Open community kernel exploit research on PlayStation 5 firmware **14.10**. This project attacks the PS5 security stack from two directions: a **Lua 5.1 loader** (TCP 9026, via game save exploit) for direct kernel/syscall research, and a **WebKit/JSC crash corpus** targeting the console's browser engine. 1,100+ probes written, 1,200+ result captures, 113 technical documents, 104 merged PRs, 150+ documented dead ends, 37 research phases, 845 commits.

> **Goal:** Userland code execution -> kernel R/W -> hypervisor bypass. Kernel read/write on 14.10 is **not demonstrated**. The Lua loader gives us powerful userland primitives (threading, heap R/W, arbitrary function calls, syscall invocation). Kernel ASLR defeat and a validated kernel vulnerability are the current blockers.

---

## License

This work is licensed under [CC BY-NC 4.0](LICENSE). You are free to share and adapt it, but you **must give credit** (link to this repository and name the author) and you **may not use it commercially**. If you post findings from this research, credit [@ZiggyVall](https://x.com/ZiggyVall) and link back to this repo.

---

## Funding — PLEASE DONATE

<a href="https://www.paypal.me/SalwanStudios">
<img src="https://img.shields.io/badge/DONATE-PayPal-blue?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate via PayPal" height="60"/>
</a>

> **When donating via PayPal, please send as Friends & Family** (not Goods & Services) to avoid payment holds and fees.

### Thank You to Our Donors

These people believed in this research and put their money where their mouth is. It means the world <3

```
Ivan Milinski  ·  Felix Dietz  ·  Brian Alejandro Camacho  ·  Jonathan Moreau  ·  Frank Munsche  ·  Mohammed Kazi  ·  Ismael Jesus  ·  Cassidy Poynter  ·  Mohammad Islam  ·  Flix Rely  ·  Paul E Fox  ·  K Lam  ·  Sean Verkempinck  ·  Jacob Maurer  ·  Benjamin Höglinger
```

---

## Attack Surface Overview

The PS5 security stack has multiple layers. This project researches all of them:

```
+------------------------------------------------------------------+
|                    PS5 Security Architecture                      |
|                                                                   |
|  +---------------------------+  +-----------------------------+   |
|  |   ENTRY VECTOR 1          |  |    ENTRY VECTOR 2           |   |
|  |   Lua 5.1 Loader          |  |    WebKit / JSC             |   |
|  |   (TCP 9026, game save)   |  |    (browser engine)         |   |
|  +------------+--------------+  +-------------+---------------+   |
|               |                               |                   |
|  +------------v-------------------------------v---------------+   |
|  |                   USERLAND (Game Process)                   |   |
|  |  Heap R/W  |  Thread ROP  |  Syscall invoke  |  CClosure   |   |
|  +----------------------------+----------------------------+--+   |
|                               |                            |      |
|  +----------------------------v----------------------------v--+   |
|  |              FreeBSD KERNEL (Sony-modified)                 |   |
|  |  676 syscalls (measured sysent)  |  Sony device drivers     |   |
|  |  UMTX subsystem  |  VM subsystem  |  Network stack          |   |
|  +----------------------------+----------------------------+--+   |
|                               |                            |      |
|  +----------------------------v----------------------------v--+   |
|  |              DEVICE DRIVERS / COPROCESSORS                  |   |
|  |  /dev/ajm (A53 ARM coprocessor)  |  /dev/gc  |  /dev/dce   |   |
|  |  34 of 76 /dev nodes open from game process                 |   |
|  +----------------------------+-------------------------------+   |
|                               |                                   |
|  +----------------------------v-------------------------------+   |
|  |              HYPERVISOR                                     |   |
|  |  (requires kernel R/W to reach)                             |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
```

### Entry Vector 1: Lua 5.1 Loader (Primary)

The game **Hamidashi Creative** (Artemis/Lua engine) loads a modified save file that starts a TCP listener on port 9026. We send Lua probe scripts over the network. This gives us:

- Direct memory read/write via `memory.*` API
- Syscall invocation via `make_syscall(N)` (bypasses Lua-side filter; kernel restrictions still apply)
- GPU mmap for large heap R/W (256+ pages, no guard pages)
- CClosure function pointer redirect for calling existing Lua C functions
- `native.fcall_with_rax` for arbitrary userland function calls
- Thread creation via `thr_create(430)` with full register control
- Per-connection ASLR (fresh process per TCP connection)

### Entry Vector 2: WebKit / JSC (Browser Engine)

The PS5's built-in browser runs a WebKit engine forked before Safari 17.0 (Sep 2023 branch, JIT disabled, LLInt only). This project maintains:

- **518-case JSC crash corpus** targeting WebKit bugs fixed after the Safari 17.0 branch (harvested by `tools/webkit_crash_corpus.py`). **Run on-console** (PR #81, #116): LayoutTests cases hang rather than crash — the LLInt-only interpreter may not reach the vulnerable code paths that JIT would
- **17 browser probes** (phase13_webkit): MetadataTable overflow, engine fingerprint, capability map, crash oracle, corpus runner
- **Poly-proto OOM reproducer** (12 lines, exhausts WebProcess memory in ~1 second, PR #77)
- **p172 iframe runner** for executing crash cases on-console (each case in its own document, PR #77)
- **WebKit canary battery** (11 probes testing Relapse scope-leak, popup isolation, etc.)
- **CSSFontFace UAF** (CVE-2026-43715) tested on 14.10 (PR #84)
- Cross-reference with [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) for MetadataTable overflow (CVE-2026-64784, confirmed on two 14.10 consoles) and CSSFontFace UAF (CVE-2026-43715)

Key WebKit findings: No WebAssembly, no SharedArrayBuffer, no WebGL. All 3 Relapse WebKit bugs patched. Relapse browser stage confirmed dead on 14.10 (PR #115). Popup isolation is dead (all methods kill WebProcess). Regexp hang reduced to 3 code units (PR #79). Game files are readable from the browser but their segments are encrypted (PR #107).

See [docs/WEBKIT_FINDINGS.md](docs/WEBKIT_FINDINGS.md), [docs/WEBKIT_CORPUS.md](docs/WEBKIT_CORPUS.md), [docs/WEBKIT_LENGTH_WINDOW_AUDIT.md](docs/WEBKIT_LENGTH_WINDOW_AUDIT.md).

---

<!-- RESEARCH_PROGRESS:START -->
## Research progress

[![14.10 evidence-weighted milestone estimate: 44/100](docs/images/research_progress.svg)](docs/PROGRESS_AUDIT.md)

**44/100 (~44%) on a subjective, evidence-weighted milestone rubric.** This is not a measured percentage of unknown exploit work, time remaining, or probability of success. **Kernel read/write on 14.10 is not demonstrated.** Hypervisor bypass is excluded from this score.

| Milestone | Points earned / weight |
|---|---:|
| 14.10 research environment | 10/10 |
| Probe tooling and captured evidence | 10/10 |
| Target characterization | 15/15 |
| Kernel attack surface mapping | 9/10 |
| Validated 14.10 kernel vulnerability | 0/15 |
| Demonstrated 14.10 kernel read/write | 0/25 |
| Repeatable complete kernel exploit | 0/15 |

Audited 2026-10-23. [Evidence and counting rules](docs/PROGRESS_AUDIT.md) · [Machine-readable rubric](docs/progress.json) · [Website](https://marwanmohamed.ca/researchps5#research-progress)

**Correction:** Probe 45c retracts earlier `fn_addr`/ROP execution and W^X-bypass claims. Those are not credited by this meter; historical diagrams and older findings are not current proof. 13.60 artifacts do not establish 14.10 exploitability.
<!-- RESEARCH_PROGRESS:END -->

---

## Confirmed Working Primitives

These are the tools we can use right now on 14.10:

| Primitive | How | Probe |
|-----------|-----|-------|
| **Child thread ROP syscalls** | `thr_new(455)` spawns child with controlled stack. Full 4-arg ROP: pop_rax, pop_rdi, pop_rsi, pop_rdx, pop_rcx gadgets. getpid, write, socketpair confirmed from child. No r8/r9 gadgets (max 4 args). | 271g/272a, 384b/386a |
| **Child thread TLS fix** | `sysarch(SET_FSBASE=129, &fake_tcb)` as first child ROP op. 4KB self-referencing buffer. Without it, any failing syscall crashes on `%fs:0` errno access. | 384b |
| **Thread ROP execution** | `thr_create(430)` with CS=0x43/SS=0x3B, full GP register control. Also `thr_new(455)` with simpler `start_func(arg)` interface. | 156c/156d, 56l |
| **Kernel copyout TOCTOU** | Blocking syscalls (recv, kevent) don't re-validate buffer VA after wakeup. munmap + MAP_FIXED remap during block redirects kernel write to new page (15/15 both paths). Kernel sanitizes output data. | 398d/398e, PR #137 |
| **Arbitrary userland function calls** | `native.fcall_with_rax`: getpid=0x22a, socket=0x16, close=0x0 all correct | 129b |
| **C11 threading** | `Thrd_create` spawns 5+ concurrent threads with join. `Atomic_fetch_add_8` as entry verified. Budget: 8 children max. | 126g/126h, PR #71 |
| **Heap R/W (256+ pages)** | GPU mmap adjacency, no guard pages | 41c |
| **CClosure function redirect** | Selected existing Lua C targets (rawequal/rawget/type) produced target-like outputs with restore checks. Eboot gadget execution via +0x20 redirect. | 56c/56f, 56d-56d7 |
| **Raw syscall invocation** | `make_syscall(N)` for tested numbers. Bypasses Lua-side filter only; kernel restrictions apply. | multiple |
| **Userland ASLR bypass** | `dynlib_get_info(593)` returns base addresses for 39 userland modules. Kernel ASLR is separate. | 41o |
| **Full process VM map** | sys 674 returns 317 named regions with protections. All userland VA, zero kernel pointers. | 55e/55f |
| **EVFILT_TIMER + socketpair** | kqueue(362) + kevent(363) with EVFILT_TIMER(-7) at 1ms resolution. AF_UNIX socketpair (SOCK_DGRAM) pipeline confirmed. | 271i |
| **Network packet injection** | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder | 34-39 |
| **sys 624 VM operation counter** | +5 per mmap, zero jitter, monotonic. Side channel for counting kernel VM ops. | 52b |
| **Device inventory** | 34 of 76 `/dev` nodes open from game process. ioctl(54) reaches all 34 drivers. Full overcopy scan across all nodes: clean. | 259a-287a, 387c |
| **UMTX functional** | UMTX_OP_WAIT blocks on value match, NWAKE_PRIVATE returns 0, MUTEX_LOCK writes owner TID | 56i2, 152k |
| **Event flag family (538-546)** | evf_create(538) returns handles, evf_wait blocks, evf_trywait returns immediately. Live kernel objects. | 65 (PR #65) |
| **Jail mapping** | Game process jail measured: restricted filesystem, no fork/rfork, limited device access, port binding restricted to 1024-32767. | PR #85 |
| **13.60 contract index** | 145/145 Sony syscall handler argument shapes recovered from 13.60 kernel decompile. Enables targeted 14.10 probing. | PR #80 |

---

## Hard Walls (What's Blocking Us)

| Wall | Detail |
|------|--------|
| **No kernel pointers found** | 30+ info leak surfaces tested (sendsig frames, GPU pages, cmsg, stat, routing, sysctl, getsockopt, credential, ucontext, sigaction, dirent, rusage, timestamps, poll, kqueue). Zero kernel pointers. GPU page pool zeroed on allocation (8M qwords scanned). |
| **W^X enforced at hypervisor** | `mmap(RWX)` gives RW only. `mprotect(EXEC)` always refused. sys 588 returns 0 but PTE never gets execute bit. sys 548 batch VM ops return -1. Hypervisor enforces below kernel. |
| **Execute-only memory (XOM)** | System lib .text is XO (reading crashes past pcall). Eboot .text is RX (readable). |
| **kldstat/kldnext/kldsym lethal** | sys 307/308/337/570 are nosys stubs, raise SIGSYS. With SIGSYS ignored they return -1. |
| **AF_ROUTE sanitized** | Kernel zeroes all pointers in route messages. Relapse KASLR technique dead on 14.10. NET_RT_DUMP "kernel pointers" proven false positives (sockaddr boundary artifacts). |
| **RDMSR blocked** | sys 626 and sys 567 return -1 for all MSR indices. |
| **No timing side channel** | mprotect on kernel addrs returns 0 immediately (early return). clock_gettime overhead drowns sub-microsecond signals. |
| **fork/rfork blocked** | `thr_create(430)` and `thr_new(455)` both work for threading. `fork`/`rfork` stay blocked. |
| **Sysent ends at 676** | 677+ all kill the process. 679-734 credential-gated (return -1 even from child thread via ROP). |
| **Device ioctls exhausted** | 34 open /dev nodes, ~80K ioctl calls (256 groups x sizes x directions). Only `/dev/gc` (25 cmds) and `/dev/usbctl` (2 cmds) respond; zero overcopy, zero kernel pointers. |
| **UMTX_OP_SHM stubbed** | All sub-ops return 0 but do nothing. CVE-2024-43102 not exploitable on 14.10. |
| **netcontrol UAF dead** | Reference leak, not free. ExploitNetControlImpl precondition does not hold. |
| **All major CVEs dead** | msync CVE-2026-49418 (MS_INVALIDATE returns -1), IPV6_MSFILTER CVE-2026-49412 (API removed), KTLS CVE-2026-45257 (not included), kqueue race ZDI-26-784 (locking solid). |
| **Object lifetimes hold** | 7 native-speed races (AIO, fstat, kevent, close/open, semaphore) all clean. 10,000+ kqueue races, 0 anomalies. |

### Tested KASLR Candidates (All Failed)

| Technique | Result | Probe |
|-----------|--------|-------|
| AF_ROUTE kernel pointer leak (Relapse) | Sanitized | 53b |
| mincore/msync/madvise oracle | Lethal | 56k |
| Timing side-channel via CClosure redirect | SMAP blocks | 56j |
| Signal handler fault recovery oracle | Handler bypasses pcall | 56k2/56k3 |
| RDMSR (sys 626, 567) | Returns -1 | 54k |
| kldstat/kldnext (sys 307, 308) | Lethal | 56k4/56k5 |
| mod* syscalls (sys 300-302) | Returns -1 | 56k5 |
| kldsym (sys 337) | Lethal | 171a |
| sysctl kernel pointer scan | All sentinels | multiple |
| sys 674 VM map (317 regions) | All userland VA | 55e/55f |
| sys 649 module members | Userland addresses only | 54k |
| kinfo_proc full dump | Only sentinels | multiple |
| net.route.iflistl scan | sockaddr/MAC, no pointers | 54f |
| sys 593 deep struct scan | NID hashes, not pointers | 54f |
| sys 639/638 memory region | Returns -1 | 54f |
| kern.proc.filedesc/vmmap | Blocked (ret=-1) | multiple |
| sys 588 (13.60 exploit path) | No-op on 14.10 | 54d |
| GPU pool uninitialized pages | Pool zeroes all pages on allocation (8M qwords = 0) | 348a |
| NET_RT_DUMP deep scan | All "kernel ptrs" are sockaddr boundary artifacts | 56e/56e2 |
| CClosure deep Lua stack read | Only userland heap/eboot pointers | 56d5-56d7 |
| sys 624 side channel | No intra-kernel discrimination | 56f |
| Sysctl deep scan (all CTL_* trees) | Zero kernel pointers | 56g3 |
| Timing KASLR (mprotect batch) | Scheduling noise only | 56h-56i2 |
| Ioctl overcopy scan (34 /dev nodes) | All clean, zero overcopy | 56m, 387a/387c |
| Signal delivery frame (sendsig) | 2128B frame zero-initialized, all userland | 56r |
| Thread ucontext register dump | All 304 dwords userland, zero kernel ptrs | 56n |
| getsockopt (TCP_INFO, SO_LINGER, etc.) | No kernel pointers | 56n |
| Unix SCM_CREDS / sigaction / fstat / getdirentries | All clean | 56o |
| getrusage / SO_TIMESTAMP / procctl / getrlimit | All clean | 56p |
| CVE-2026-3038 sa_len=127 overflow | Accepted without panic, likely patched | 56e |

---

## Current Priority Vectors

These are the active leads, ranked by potential. Updated 2026-10-23.

### 1. Kernel copyout TOCTOU exploitation

Blocking syscalls (recv, kevent) don't re-validate buffer VA after wakeup (PR #137). munmap + MAP_FIXED remap during the block redirects kernel write to a new page (15/15 both paths). Kernel sanitizes output data, so no kernel pointer leak yet, but the TOCTOU itself is a write-redirection primitive. Can we redirect copyout to GPU-mapped or device-mapped memory?

### 2. Kernel image acquisition

Without a 14.10 kernel dump, we can't identify new attack surface or verify sysent layout differences from 13.60. The 13.60 companion repo has kernel dumps; we need to either find an accessible path to dump 14.10 kernel .text, or diff the 13.60 code against 14.10 behavioral observations.

### 3. JSC crash corpus (518 cases)

Post-Safari-17.0 regression tests targeting WebKit bugs the PS5 browser engine predates. Corpus generated by `webkit_crash_corpus.py` (PR #75). **Run on-console** (PRs #81, #116): LayoutTests cases hang rather than crash on the LLInt-only interpreter. MetadataTable overflow (CVE-2026-64784) confirmed on two 14.10 consoles by pastawithpesto. Needs fresh CVE cases or targeted StructureID/MarkedBlock corruption approaches.

### 4. BSD-native syscall range (1-530)

The Sony-private range (532-676) is **exhausted**: all 145 handlers have 13.60 contracts, and almost every one has been called with real arguments on 14.10. Only 3 remain untested (604/636 lack decoded contracts; 658 fdatasync has no buffer). The standard FreeBSD range (1-530) has ~400 syscalls with no decompiled contracts — some may have Sony-specific modifications or bugs not present in upstream FreeBSD. This is the largest unexplored syscall surface.

### 5. AIO batch count overflow

sys 669 doesn't clamp count to buffer: 0x14000 into 4KB overwrites heap. Self-corruption only (not boundary break), but combined with TOCTOU or heap feng shui may become useful.

### 6. New CVE assessment

Continuously assess newly published FreeBSD CVEs against the 14.10 attack surface. The kernel build date (Sep 28 2026) gives us a clear cutoff for which patches are likely included.

### Closed since last update
- ~~Ioctl overcopy scan~~ — All 34 open /dev nodes swept (~80K calls). Zero overcopy, zero kernel pointers (387a/387c). Praetorian ioctl may require credentials the game process lacks.
- ~~msync CVE-2026-49418~~ — MS_INVALIDATE returns -1 on all mappings (58a/58b). Dead.
- ~~UMTX PI-mutex races~~ — DoS only (crash after 5-7 rounds, system hang). No kptr leak, no controlled write (160f-160j).
- ~~Syscalls 530-532, 537~~ — All nosys stubs, return -1 (56j).
- ~~CVE-2026-49412 IPV6_MSFILTER~~ — Sony removed RFC 3678 API entirely (50e2/50e3).
- ~~CVE-2026-45257 KTLS~~ — Sony did not include KTLS (50f).
- ~~Kqueue race ZDI-26-784~~ — 10,000+ races, 0 anomalies. Kernel locking solid (271g-271i).

---

## CVE Assessments

This project has assessed 12+ FreeBSD CVEs against the 14.10 attack surface:

| CVE | Title | Status | Document |
|-----|-------|--------|----------|
| CVE-2026-49418 | msync device-pager UAF | **Dead** - MS_INVALIDATE returns -1 on all mappings | [Assessment](docs/CVE-2026-49418-PS5-14.10.md) |
| CVE-2024-43102 | UMTX SHM race | **Dead** - SHM stubbed | [Evidence](docs/UMTX_454_EVIDENCE.md) |
| CVE-2026-49412 | IPV6_MSFILTER UAF | **Dead** - Sony removed RFC 3678 API | [Evidence](docs/MSYNC_CVE_2026_49418.md) |
| CVE-2026-45257 | KTLS page-cache overwrite | **Dead** - Sony did not include KTLS | [Evidence](docs/MSYNC_CVE_2026_49418.md) |
| CVE-2026-49419 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-49419-PS5-14.10.md) |
| CVE-2026-49422 | RACK TCP | Assessed | [Assessment](docs/CVE-2026-49422-PS5-14.10.md) |
| CVE-2026-49424 | Linuxulator | Assessed | [Assessment](docs/CVE-2026-49424-PS5-14.10.md) |
| CVE-2026-49427 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-49427-PS5-14.10.md) |
| CVE-2026-58083 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-58083-PS5-14.10.md) |
| CVE-2026-58090 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-58090-PS5-14.10.md) |
| CVE-2026-58093 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-58093-PS5-14.10.md) |
| CVE-2026-45258 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-45258-PS5-14.10.md) |
| CVE-2026-7270 | Kernel vulnerability | Assessed | [Assessment](docs/CVE-2026-7270-ASSESSMENT.md) |
| CVE-2019-5607 | SCM_RIGHTS | Binary verified | [Chain](docs/CVE-2019-5607-EXPLOIT-CHAIN.md) |

---

## Exploit Chain Overview

```mermaid
graph LR
    A["Hamidashi Creative<br/>(Artemis Engine)"] -->|modified save file| B["Lua 5.1 Loader<br/>TCP 9026"]
    B -->|memory.* / syscall.*| C["Confirmed userland primitives<br/>Thread ROP, CClosure redirect,<br/>Heap R/W, arbitrary calls"]
    C -->|"No validated kernel base"| D["KASLR defeat<br/>not demonstrated"]
    D -->|requires KASLR defeat| E["Kernel R/W<br/>not demonstrated"]
    E -->|requires kernel R/W| F["Hypervisor bypass<br/>not demonstrated"]

    style A fill:#2d5016,stroke:#4a8c2a,color:#fff
    style B fill:#2d5016,stroke:#4a8c2a,color:#fff
    style C fill:#2d5016,stroke:#4a8c2a,color:#fff
    style D fill:#8b0000,stroke:#cd5c5c,color:#fff
    style E fill:#8b0000,stroke:#cd5c5c,color:#fff
    style F fill:#8b0000,stroke:#cd5c5c,color:#fff
```

---

## Environment

| Property | Value |
|----------|-------|
| Firmware | 14.10 |
| Kernel | FreeBSD r230171 (Sep 28 2026) |
| Entry points | Lua 5.1 loader on TCP 9026 + WebKit browser engine |
| Page size | 16 KB (0x4000) |
| CPU | Zen 2, 8C/16T (16 logical cores) |
| Securelevel | 1024 (PS5-specific) |
| Measured sysent | 676 entries (677+ lethal) |
| Open /dev nodes | 34 of 76 (gc, dce, ajm, dmem0-2, rng, gic, camera, usb, hid, bt, notification*, HMD sets) |
| Consoles tested | 2 (primary + second-console confirmation, PR #95) |

---

## Repository Structure

```
probes/                              # 1,100+ Lua probe scripts across 37 phases
  phase1_identity_layout/            # 01-08: system ID, syscalls, memory layout
  phase2_kernel_objects/             # 09-21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/            # 22-26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/               # 27-31: threading, fd passing, socket opts
  phase5_buffer_io/                  # 32-33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/               # 34-39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/          # 40-41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/              # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/              # 42b-42j: KASLR attempts, ROP architecture
  phase10_untested_theories/         # 43a+: theory-driven probes
  phase11_network_attacks/           # 48a-50d: SCTP, IPv6, TCP inject, exotic protocols
  phase12_kernel_analysis/           # 51a+: kernel dump sysent analysis
  phase12_kernel_dump/              # Kernel dump analysis tools
  phase13_52batch/                  # 52a-52b: Sony syscall survey 627-676 + 624 oracle
  phase13_53batch/                  # 53a-53d: evidence-audit retests
  phase13_webkit/                   # 17 browser probes: MetadataTable, engine fingerprint, corpus runner
  phase14_cclosure_redirect/         # CClosure +0x20 redirect experiments
  phase14_final_push/               # 54a-56l: deep syscall survey, CClosure, KASLR exhaustive
  phase15_native_sysent/            # 57a+: native sysent survey, msync CVE probe
  phase16_thr_create_crash/          # thr_create(430) crash analysis and CS=0x43 fix
  phase17_new_vectors/              # 339 probes: massive vector exploration
  phase17_seg_hypothesis/           # Segment register hypothesis testing
  phase17_threading/                # Threading primitive development
  phase18_race_conditions/          # Race condition setup
  phase18_race_ingredients/         # Race primitive building blocks
  phase19_umtx_454/                 # 22 probes: UMTX on syscall 454 (corrected from 557)
  phase22_threaded_races/           # 20 probes: PI-mutex races, gadget catalog, child syscalls
  phase23_ajm_a53/                  # AJM ioctl NID sweep (A53 coprocessor path)
  phase24_kernel_leak_hunt/         # Latest kernel pointer search attempts

results/                             # 1,200+ raw output captures (same phase structure)

tools/                               # 90+ scripts and utilities
  send_probe.py                      # Primary probe sender (Python, TCP with 8B LE prefix)
  send_probe.ps1                     # PowerShell probe sender (no Python required)
  run_probe_batch.py                 # Bounded sequential probe execution
  kaslr_bruteforce.py               # Multi-connection KASLR brute-force driver
  syscall_isolation_sweep.py         # One-connection-per-syscall measurement
  webkit_crash_corpus.py            # JSC regression test harvester (518 cases)
  verify_offline.py                  # CI: hardware-free evidence verification
  analyze_result.py                  # Result file parser and kernel pointer scanner
  deep_result_scanner.py            # Cross-result pattern finder
  bounds_fuzz.py                    # Sony handler buffer size fuzzer
  restart_pressure.py               # Resource accumulation measurement across kills
  console_control/                  # Unattended PS5 control via Remote Play
  browser_battery/                  # WebKit canary test battery
  browser_runner/                   # On-device crash case runner
  ghidra/                           # Ghidra analysis scripts for 13.60 kernel
  v1360-dumper/                     # 13.60 kernel dump tools (C payload + receiver)

docs/                                # 113 technical documents
  ATTACK_SURFACE.md                  # Complete syscall status map (676 entries)
  FINDINGS.md                        # Detailed technical findings
  PROBE_INDEX.md                     # Every probe with status and key result
  STRATEGY.md                        # Exploit strategy and dead ends
  UNTESTED_THEORIES.md              # Ranked exploit theories
  RESEARCH_PAPER.md                 # Full technical research paper
  RESEARCH_EVIDENCE.md              # Evidence ledger guide
  THREADING_ALIVE_14_10.md          # thr_create(430) full decode
  SYSENT_PRESENCE_14_10.md          # Measured sysent boundaries (676 entries)
  WEBKIT_FINDINGS.md                # WebKit engine findings and capability map
  WEBKIT_CORPUS.md                  # JSC crash corpus documentation
  AJM_IOCTL_REVERSAL_13_60.md      # Sony NID-hash ioctl command discovery
  NETCONTROL_14_10.md               # netcontrol UAF analysis (dead on 14.10)
  UMTX_454_EVIDENCE.md             # UMTX syscall correction (557 was wrong)
  CVE-*.md                          # 12+ CVE assessments
  ALL_RESULTS.md                    # Every result concatenated (for large-context AI)
  ALL_PROBES.md                     # Every probe concatenated (for large-context AI)
  USERLAND_ENTRY.md                 # Full setup guide and game details
```

---

## Quick Start

```bash
# Send a probe (Python)
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/phase14_final_push/56c_redirect_nonvm.lua

# Send a probe (PowerShell, no Python required)
.\tools\send_probe.ps1 probes\phase14_final_push\56c_redirect_nonvm.lua -Save

# Run multiple probes sequentially
python tools/run_probe_batch.py probes/phase22_threaded_races/271*.lua

# KASLR brute force driver (multi-connection)
python tools/kaslr_bruteforce.py --ps5-ip YOUR_PS5_IP --step 0x200000

# Syscall isolation sweep (one connection per number)
python tools/syscall_isolation_sweep.py --range 661-670

# Harvest WebKit crash corpus from public regression tests
python tools/webkit_crash_corpus.py --output probes/phase13_webkit/

# Hardware-free CI verification (no console needed)
python3 tools/verify_offline.py
```

See [tools/README.md](tools/README.md) for full tool documentation.

---

## Userland Entry

The exploit chain uses **Hamidashi Creative** (a Japanese visual novel on the Artemis/Lua engine) as the entry point. A modified save file embeds the Lua loader, which starts a TCP listener on port 9026.

```mermaid
graph TD
    A["PS5: Play game, create save"] -->|USB| B["Find PSN Account ID<br/>(hex, from save folder)"]
    B -->|USB| C["Jailbroken PS4: Apollo activates<br/>profile with MATCHING Account ID"]
    C --> D["Decrypt save under<br/>matched profile"]
    D -->|USB| E["PC: Embed Lua loader"]
    E -->|USB| F["Jailbroken PS4: Re-encrypt save"]
    F -->|USB| G["PS5: Import save, launch game"]
    G --> H["Black screen + notification:<br/>'lua loader is loaded'<br/>Listening on TCP 9026"]
    H -->|"LAN: send_probe.py"| I["PC sends Lua probes<br/>over TCP"]

    style B fill:#8b0000,stroke:#cd5c5c,color:#fff
    style C fill:#8b0000,stroke:#cd5c5c,color:#fff
    style H fill:#2d5016,stroke:#4a8c2a,color:#fff
    style I fill:#2d5016,stroke:#4a8c2a,color:#fff
```

> Red = critical step (Account ID must match or PS5 rejects the save)

- **Game:** Hamidashi Creative - free demo on Japanese PSN
- **Loader:** Based on [shahrilnet/remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- **Kernel offsets:** From [@hammer-83](https://github.com/hammer-83)'s [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader) (fw 1.00-10.01 only; 14.10 offsets TBD)
- **Entry method:** Save file exploit via PS4 backwards compatibility

See [docs/USERLAND_ENTRY.md](docs/USERLAND_ENTRY.md) for the full setup guide.

---

## Use AI to Help

All research data is in this repo so anyone can feed it to their AI model of choice.

**For maximum-context models (1M+ tokens):**
- Feed `docs/ALL_RESULTS.md` + `docs/ALL_PROBES.md` + `CLAUDE.md` for the entire research corpus
- Ask the model to find novel KASLR defeat paths that haven't been tried
- Ask it to cross-reference 13.60 kernel dumps against 14.10 behavior

**For smaller context models:**
1. Start with `README.md` and `CLAUDE.md` for the full picture
2. Feed `docs/STRATEGY.md` for what's been tried and what's next
3. Feed `docs/FINDINGS.md` for all technical findings
4. Point it at specific probe results in `results/` for raw data analysis

**What we need help with most:**
- **KASLR defeat** - 20+ techniques tested, all dead. Need a novel information leak path. Every accessible interface has been scanned for kernel pointers: sysctl, route sockets, signal frames, fstat, getrusage, getsockopt, device ioctls, VM map, thread ucontext — all clean.
- **14.10 kernel image acquisition** - without a dump we can't find new attack surface. The Praetorian KASLR ioctl may live on a device the game process can't open.
- **13.60 to 14.10 kernel diff analysis** - the companion repo has 13.60 kernel dumps. What changed in the Sony syscall handlers?
- **FreeBSD r230171 source analysis** - find exploitable code paths reachable from our ~40 working syscalls. The Sony-private range (532-676) is largely exhausted; the BSD-native range (1-530) has no decompiled contracts.
- **WebKit/JSC crash analysis** - run the 518-case corpus on-console, analyze any crashes. MetadataTable overflow confirmed by pastawithpesto.

---

## Related Research

### V13.60 Kernel Research
The companion [PS5 V13.60 Research](https://github.com/ZigZagBoi1/PS5-V13.60-Research) repository maintains the firmware 13.60 Relapse and Byepervisor-Reborn research. Relapse's 13.60 support does not imply support on 14.10 (AF_ROUTE KASLR is confirmed dead here).

### WebKit Research (pastawithpesto)
[pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) covers the browser side of the same 14.10 chain:
- Their Stages 1-2: WebKit corruption -> arbitrary R/W
- This repo: userland/kernel side (Lua loader, syscall surface, kernel exploitation)
- MetadataTable overflow (CVE-2026-64784) confirmed on two 14.10 consoles
- CSSFontFace UAF (CVE-2026-43715) device test deployed
- Their Stage 3/4 kernel candidates validated against our [ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md)

---

## Key Constraints

- **W^X enforced** - `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails
- **Execute-only memory (XOM)** - system lib .text is XO (reading crashes); eboot is RX
- **Limited threading** - `fork`/`rfork` blocked; `thr_create(430)` works with CS=0x43/SS=0x3B; `thr_new(455)` works with simpler `start_func(arg)` interface
- **Per-connection ASLR** - fresh process per TCP connection, all addresses must be re-derived
- **SMAP enforced** - no timing differentiation between mapped/unmapped kernel VA
- **No kernel pointers found** - extensive scanning across every accessible interface
- **/dev/dmem0** - GPU aperture only, cannot access CPU/kernel physical memory
- **Port binding restricted** - bind() returns -1 for ports >= 40000, use 1024-32767

---

## Contributors

- **[ng643](https://github.com/ng643)** (Rithik Janarthanan) - 64 PRs (#6-8, #11-18, #21-27, #37, #39-40, #44, #55-57, #60-62, #65-69, #71-72, #75, #77, #79-81, #83-94, #96, #98-100, #106-107, #109-110, #113-116): Evidence corrections, Tier 1/2/3 handler claim audits, CVE assessments, thr_create(430) full decode + user-mode proof, kevent timeout matrix, syscall label table, WebKit OOB audit, 14.10 WebKit fingerprint, JSC crash corpus (harvester + on-console replay), device inventory (34/76 nodes) + ioctl space end-to-end measurement, UMTX high ops, netcontrol UAF closure (leak not free), Sony object family sweep (all families closed), thread budget measurement, sysent presence mapping + absence rule correction, jail mapping, 13.60 argument contract index (145 handlers), AIO batch with contract args, physhm_open measurement, sys 532/601/654 contract probes, per-process object table measurement, native syscall chains from thread context, game file encryption confirmation, Relapse browser stage dead on 14.10, system socket mapping, msync gate confirmation, thr_create stack-init unreachable proof
- **[AJV20](https://github.com/AJV20)** - PRs #47-54: PowerShell capture path fixes, CI bounded hardware-free verification, ledger JSON validation, p161 chunk regression coverage, ledger-to-artifact binding, AIO/kevent evidence reconciliation, colliding capture preservation, failed evidence pair cleanup
- **[4TheDoctor](https://github.com/4TheDoctor)** (The Doc) - PRs #19-20, #28, #64, #101-105, #117: CVE assessments (49418/58093/49427/49428/49424/49422/49412/45257), thr_* family survey, child thread ROP execution (arbitrary 4-arg syscalls from child), UMTX PI mutex races, SROP + 83-probe exhaustive KASLR scan (zero kernel pointers), UMTX_OP_SHM stub confirmation (CVE-2024-43102 dead), IPV6_MSFILTER/KTLS dead, ioctl overcopy full sweep (all 34 /dev nodes clean), child thread fake TCB fix
- **[pastawithpesto](https://github.com/pastawithpesto)** - PRs #4-5: Complete kernel handler reverse engineering (145/145 syscalls fw 13.60), WebKit entry vector analysis
- **[cobrajet302gt](https://github.com/cobrajet302gt)** - PRs #30, #32-33, #36, #46: CS=0/iretq thr_create(430) panic hypothesis + probes, live 14.10 WebKit stage-1 test, WebKit canary battery (11 probes), browser entry infrastructure, unattended console control via Remote Play
- **[Unkown607](https://github.com/Unkown607)** - PRs #9, #31, #34-35, #58: 13.60 syscall name maps, compat-table capture identification, static thr_create(430) panic root-cause analysis (13.60 decompile), exploit surface analysis (3 CVEs + 5 race windows), CVE-2019-5607 binary verification (fhold confirmed at TEXT+0x53c5f2, no fdrop in error path)
- **[Portablelle](https://github.com/Portablelle)** - PRs #41-43, #45: umtx 454 evidence correction (phase 1-2 probes called syscall 557 not 454), corrected probes, UMTX_OP_SHM/ROBUST_LISTS reachability probe, WebKit cross-link refresh, p161 blob fix
- **[DEM9N101](https://github.com/DEM9N101)** - PRs #70, #95: msync syscall number correction (226 nosys → 65 real, kernel-dump verified), second-console confirmation results (device-mmap write path hard-crash intel, UMTX_SHM ENOSYS matrix, ktimer sweep, thr_create confirm)
- **[0x7067](https://github.com/0x7067)** - PR #76: 13.60 ioctl NID command code extraction + probe 271a preparation
- **[kaydzer0305-png](https://github.com/kaydzer0305-png)** - PR #10: Offline evidence auditing framework
- **[wsjardijn](https://github.com/wsjardijn)** - Early research contributions

---

## Documentation Index

| Document | Contents |
|----------|----------|
| [CLAUDE.md](CLAUDE.md) | AI guide: probe template, helpers, dead ends, current priorities |
| [CHANGELOG.md](CHANGELOG.md) | Phase-by-phase progress timeline |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to this project |
| [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) | Complete syscall status map (676 entries) |
| [docs/FINDINGS.md](docs/FINDINGS.md) | Detailed technical findings |
| [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) | Every probe with status and key result |
| [docs/STRATEGY.md](docs/STRATEGY.md) | Exploit strategy, tiers, and dead ends |
| [docs/UNTESTED_THEORIES.md](docs/UNTESTED_THEORIES.md) | Ranked exploit theories |
| [docs/RESEARCH_PAPER.md](docs/RESEARCH_PAPER.md) | Full technical research paper |
| [docs/RESEARCH_EVIDENCE.md](docs/RESEARCH_EVIDENCE.md) | Evidence ledger guide |
| [docs/THREADING_ALIVE_14_10.md](docs/THREADING_ALIVE_14_10.md) | thr_create(430) full decode and mcontext layout |
| [docs/WEBKIT_FINDINGS.md](docs/WEBKIT_FINDINGS.md) | WebKit engine findings and capability map |
| [docs/WEBKIT_CORPUS.md](docs/WEBKIT_CORPUS.md) | JSC crash corpus documentation |
| [docs/USERLAND_ENTRY.md](docs/USERLAND_ENTRY.md) | Userland exploit setup guide |
| [docs/SYSCALL_CONTRACTS_13_60.md](docs/SYSCALL_CONTRACTS_13_60.md) | 145/145 Sony handler argument contracts (13.60 decompile) |
| [docs/SYSENT_PRESENCE_14_10.md](docs/SYSENT_PRESENCE_14_10.md) | Measured sysent: which calls are present, absent, or lethal |
| [docs/DEVICE_IOCTL_14_10.md](docs/DEVICE_IOCTL_14_10.md) | Device ioctl space end-to-end measurement |
| [docs/SYSTEM_SOCKETS_14_10.md](docs/SYSTEM_SOCKETS_14_10.md) | /system_tmp compositor sockets measurement |
| [docs/NETCONTROL_14_10.md](docs/NETCONTROL_14_10.md) | netcontrol(99) UAF analysis: leak not free |
| [docs/OBJECT_FAMILIES_14_10.md](docs/OBJECT_FAMILIES_14_10.md) | Sony object families: evf, osem, namedobj, jitshm — all closed |
| [docs/AIO_BATCH_14_10.md](docs/AIO_BATCH_14_10.md) | AIO batch submit/reap measurement |
| [docs/ALL_RESULTS.md](docs/ALL_RESULTS.md) | Every result in one file (for AI ingestion) |
| [docs/ALL_PROBES.md](docs/ALL_PROBES.md) | Every probe in one file (for AI ingestion) |

---

## Why This Is Open Source

By publishing every probe, every finding, and every commit publicly, this project is permanently disqualified from Sony's PlayStation Bug Bounty Program. That's a deliberate choice.

This research is for the community. When a kernel primitive is found, it won't be sold, it won't be held back, and it won't be gatekept. It'll be published here, for free, for anyone to use.

Everything here has been funded out of pocket. Donations help offset that cost, but they're never mandatory. This is a research project, not a product. It takes as long as it takes.

**Contributors welcome.** Whether you have the hardware or just want to analyze FreeBSD kernel code, there's work to do. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR defeat technique and AIO race condition methodology
- Artemis engine Lua research: the PS5 homebrew scene

## License

This research is for educational and authorized security research purposes only.
