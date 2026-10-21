# Changelog

## Phase 23 — Offline ioctl catalog (2026-10-21)

- Console unreachable from the research host (port 9026 closed, no route); offline work continued.
- Recovered the full 13.60 capture set from git blobs (kernel_text.bin 15MB, kernel_data.bin 4MB) into `docs/dumps_13.60/` analysis.
- `tools/extract_ioctl_catalog.py`: scan + capstone verification of ioctl dispatchers in 13.60 kernel text; 9 verified dispatchers, 57-code curated list (`docs/IOCTL_CATALOG_13_60.md`).
- Probe 271a prepared: ioctl command-code matrix over 10 openable /dev nodes (companion to PR #74's device inventory).
- Queue when the console returns: 58a (msync CVE-2026-49418 reachability), 271a, 243a (thread slot reclaim).
- Offline: syscalls 528-531/537 are nosys slots on 13.60; 532 is real (narg 5, permission gate 0x2aa, type bitmask 0x800003d4/0x2a). Probe 272a prepared (`docs/SYSCALL_532_13_60_ANALYSIS.md`).
- Offline: extracted the full 454 umtx 27-op jump table from the 13.60 capture (ops 0/1 stubbed EOPNOTSUPP, 26 stubbed, table+CFI check documented; `docs/UMTX_OPS_13_60.md`). Probe 273a prepared: op5 waiter vs mmap MAP_FIXED mapping replacement race.
- Offline: re-read the 13.60 set_mcontext (rva 0xa0ac60) via the recovered text — the context CS field is never read; SS is copied raw. Resolves the 189a contradiction and retires the CS missing-mask narrative; probe 274a prepared.
- Offline: resolved all 58 sysent tail thunks (677-734) from the 13.60 CSV against the recovered text - 53 real (wait6, cap_*, pipe2, ppoll, numa_*, apr_*, mmap2, virtual_query_by_pid...), 695-699 nosys. Probe 275a prepared: real-args calls into the 14.10 kill range.
- Offline: decoded syscall 728 virtual_query_by_pid argument shape from its 13.60 handler (pid/addr/flags-0x20000/outbuf/count, two gates). Probe 275b prepared.
- Offline: decoded the Sony AIO family from the 13.60 capture - 661/668 are nosys stubs, 669 submit_cmd takes (cmd{1,2}, buf, size>=0x81, type{1,2,3}), 670 init takes zeros; 14.10 sweep already showed 670 returning 0. Probe 276a prepared (Relapse surface recheck; see docs/AIO_FAMILY_13_60_DECODE.md).
- Offline: decoded syscall 725 mmap2 (6-arg mapping variant, extended flag forms, 0x200000 special path, proc+0xc81 gate). Probe 277a prepared: W^X policy through the second mapping entry point.
- Probe 278a prepared: CClosure control-return gadget ladder (ret / xor-eax-eax / pop-rdi) on rawequal +0x20 with 56c's parser and restore discipline - the Lua stack readback variant is the new primitive.

## Phase 22 — Device inventory, ioctl surface, JSC corpus, UMTX high ops (2026-10-21)

### PRs #74–#75 review summary

- **34 of 76 /dev nodes open from game process** (PR #74, ng643): First real `/dev` listing via `getdirentries`(196) reveals 32-bit dirent layout (u32/u16/u8/u8). Open: `gc`, `dce`, `ajm`, `ajmi`, `rng`, `gic`, `notification0/6/7`, `camera`, `usb`, `usbctl`, `dmem0-2`, HMD sets, `bt`, `hid`, plus standard nodes. `ioctl(54)` reaches all 34 drivers — they reject commands, not the kernel. Command encoding is not small integers; needs driver table.
- **AIO(661) confirmed dead with real fd** (PR #74, ng643): `/dev/zero` fd + full `aiocb` struct still kills. Third argument shape tested. Dead.
- **UMTX ops 16-22 all block** (PR #74, ng643): Sentinel-word experiments show ops 18-21 leave words untouched (thread didn't return). op 19 wrote 0x1 non-deterministically in one run. Blocked/returned threads indistinguishable.
- **518-case JSC crash corpus ready** (PR #75, ng643): `webkit_crash_corpus.py` scrapes 397 WebKit commits after Safari 17.0 branch, extracts 518 JS test cases. p172 iframe runner built. Popup isolation dead (all kill WebProcess). **No cases run on console yet — high potential.**

### New dead ends added
- Device ioctl sweep (all 34 open nodes, commands 0x00-0xFF return -1)
- AIO(661) with real fd on /dev/zero — still kills
- UMTX ops 18-21 block unreadably
- WebKit popup isolation (all methods kill WebProcess)

### TODOs from this review
1. **Targeted device ioctl research** — need Sony command codes from 13.60 Ghidra for gc/dce/gic/camera/notification drivers
2. **Run JSC corpus (p172)** — 518 cases targeting post-Safari-17.0 WebKit bugs
3. **Repeat UMTX op 19** — non-deterministic 0x1 write deserves more samples

## Phase 21 — Object families, thread budget, netcontrol closure, msync fix (2026-10-21)

### PRs #69–#72 review summary

- **★ msync syscall number corrected 226→65** (PR #70, DEM9N101): sysent rebuild from 13.60 dump shows entry 226 is nosys, real msync is 65 with sy_narg=3 and 16KB page-aligned MS_INVALIDATE path. Prevents a false negative on the CVE-2026-49418 device-pager UAF probe (58a). Also corrects fspacectl 580→572. **This is the gold: the device-pager UAF path via msync(65) on GPU-mmap pages is the next CVE-class test.**
- **Netcontrol reference leak CONFIRMED — UAF is DEAD on 14.10** (PR #69, ng643): 12 probes (223a–234a) show register takes a socket reference that leaks on close-before-unregister. No double-free, no dangling pointer. The public Poops/ExploitNetControlImpl chain's precondition does not hold. ifindex -1 queue is permanently wedged until power cycle.
- **Sony object families exhausted — all dead** (PR #72, ng643): 10 probes sweep jitshm(533/534), dl_get_list/info(535/536), osem(549–556), namedobj(557/558), set_vm_container(559), debug_init(560), suspend_process(561), evf set-vs-cancel race. Every family is unreachable, lacks name-keyed lookup, or is a no-op query.
- **Thread budget measured + EVF clarified** (PR #71, ng643): 14 probes (235a–248a). Safe budget is ≤8 children. EVF holds exactly one waiter (second gets immediate refusal). thr_get_ucontext(634) writes nothing. blockpool_batch(657) returns status only. query_memory_protection(547) is userland-only — no KASLR oracle. 238a–240a crash retracted (probe bug, not kernel fault — fixed by parking child on `jmp $` gadget).

### New dead ends added
- netcontrol(99) netevent queue UAF (14.10 leaks reference, no free)
- jitshm(533/534), osem(549–556), debug_init(560), suspend_process(561)
- namedobj(557/558) name collision (not name-keyed, no UAF path)
- thr_get_ucontext(634), blockpool_batch(657), query_memory_protection(547)

### TODOs from this review
1. **Run probe 58a** with corrected msync(65) — test CVE-2026-49418 device-pager UAF on GPU-mmap pages
2. **Run probe 243a** (thread slot reclaim) — queued but never executed
3. **Threaded UMTX PI-mutex races** with corrected parking pattern (≤8 children)
4. **Multi-flag EVF waiter races** (one waiter per flag, N flags)
5. **Syscalls 530–532, 537** still unmeasured from the Sony object range

## Phase 19 — UMTX SHM reachability + thr_create CS=0x43 confirmation (2026-10-20)

- **UMTX_OP_SHM(25) on syscall 454 CONFIRMED REACHABLE** (probe 151a): all sub-ops (create=1, destroy=4, alive=8) return 0 on 14.10. CVE-2024-43102 attack surface is open.
- **thr_create CS=0x43 PREVENTS KERNEL PANIC** (probe 80a, 5 runs): zeroed ucontext panics (CS=0), but CS=0x43/SS=0x3B yields rv=-1 with real TIDs and no panic. Thread creation fails (rv=-1) but the process survives — the panic root cause (13.60 decompile PRs #30/#31) is confirmed on 14.10.
- **PS5 mcontext offsets differ from standard FreeBSD**: MC_RIP=0x90, MC_CS=0x98, MC_RSP=0xA8, MC_SS=0xB0 (all -0x10 from textbook amd64). Probe 146a had wrong offsets — fixed layout needed.
- **kernel.lua source dumped** (probe 150a): full ipv6_kernel_rw module, kernel_offset table, native.fcall/fcall_with_rax APIs confirmed.
- **native.fcall_with_rax CONFIRMED WORKING**: getpid=0x22a, socket=0x16, close=0x0 all return correct values.
- **Thrd_create (C11 threading) CONFIRMED**: 5+ concurrent threads, join works, Atomic_fetch_add_8 as entry point verified.
- Probes 151b-151e crashed from resource exhaustion (too many allocs/pipes/fstat). 152a/153a designed with safety constraints.
- New probes written: 152a (SHM heap race + GPU reclaim), 153a (threaded SHM race with Thrd_create)

## Cross-link — related WebKit research (2026-10-19)

- **README "Related WebKit Research" section** linking pastawithpesto/PS5-14.10-Jailbreak-Research as the browser side of the same 14.10 chain (their Stages 1-2 = WebKit corruption → R/W; this repo = userland/kernel side; their Stage 3/4 candidates validated against our ATTACK_SURFACE).
- **WEBKIT_FINDINGS.md refreshed** with an "Updates Since This Snapshot" block: p156 corruption confirmed on a second independently-owned 14.10 console (bait-and-switch required, plain p142 survive does not hold), p160 Relapse death independently reproduced, CVE-2026-43715 CSSFontFace UAF device test deployed, their kernel audit (CVE-2026-45251 not yet assessed here), and the length-window audit cross-referenced.

## Evidence correction — the umtx corpus called syscall 557, not `_umtx_op(454)` (2026-10-19)

- **Phase-1/2 "umtx" probes (04, 10-13) and the first revision of probe 82a bound `sc_umtx_op` to syscall 557** — the 13.60 capture labels 557 as `namedobj_create` and 454 as `_umtx_op`. Probe 10's "SHM double-destroy OK" and "oversized robust accepted" findings described 557 calls and are inconsistent with FreeBSD `_umtx_op` semantics. See [docs/UMTX_454_EVIDENCE.md](docs/UMTX_454_EVIDENCE.md).
- **454 is alive on 14.10:** probe 56i2's section [F] is the only saved 454 execution — op 5 (MUTEX_LOCK) ret=0 with a TID-shaped owner writeback, op 21 (NWAKE_PRIVATE) ret=0. Probe 56i's SHM(25)/WAKE2(22) sections never ran (capture ends in section B).
- **UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never exercised on 454**, and FreeBSD 11 reads their key/params pointer from `uaddr1` (4th positional arg) — a layout no earlier probe used. CVE-2024-43102 reachability is open, not answered.
- Probe 110a prepared (`probes/phase19_umtx_454/110a_umtx_shm_reachability.lua`, CRASH_CLASS: LOW): correct-layout SHM lifecycle/churn, robust-lists registration, mutex owner readback, and a same-shape syscall 557 negative control.
- Probe 82a repaired: `make_syscall(454)` binding, `SHM_DESTROY` flag corrected 3→4, SHM/ROBUST_LISTS arguments moved to the `uaddr1` position.
- Updated ATTACK_SURFACE.md (`_umtx_op` row), PROBE_INDEX.md (rows 10-13, 56i, 56i2, 82a, 110a), and added `tools/test_umtx454_correction.py`.

## WebKit — length-window audit (2026-10-19)

- **Audit:** the p146 result `.length = 81400` on 100,000-character strings does not give an out-of-bounds read. `charCodeAt` is gated by `JSString::canGetIndex` (`i < length()`), so a smaller length narrows the readable window to 0-81399 instead of extending it past the 100,000-char buffer.
- **Corrected** Finding 2/3 impact text and the status table in `docs/WEBKIT_FINDINGS.md`; the ASLR-leak stage is now marked blocked on length or data-pointer control.
- **Noted** that `54g`'s OOB branch requires `len > STR_LEN` and cannot fire under the recorded p146 value.
- **New probe** `probes/phase13_webkit/p161-length-window.js`: re-runs the p146 groom and measures the window directly (`LAST` at `len-1`, `TAIL` at index 99999, `PAST` at `len`, `SUB` to confirm the buffer). `?mode=pair` repeats the run with two identifier keys at identical source size to test whether the written length value is content-dependent.
- **New doc** `docs/WEBKIT_LENGTH_WINDOW_AUDIT.md` with the arithmetic (`38348816 * 112 = 2^32 + 100096`), the JSC read path, and the three paths that would produce a real OOB primitive.

## Phase 14c — Controlled Function Redirect Confirmed (2026-10-18)

- **★★★ CONTROLLED CClosure REDIRECT PROVEN END-TO-END** (probe 56c)
  - All 4 test redirects returned the target function's output:
    - rawequal → rawget: `rawequal(t,"foo")` returned `"bar"`
    - rawget → type: `rawget(42,"x")` returned `"number"`
    - select → tostring: `select(42)` returned `"42"`
    - rawequal → tostring: `rawequal(42)` returned `"42"`
  - Write+restore cycles: 0.0001s each, all functions restored correctly
  - **Critical insight:** `type()` cannot be redirected because `memory.write_dword` internally calls `type()` — non-VM functions (rawequal, rawget, select) redirect freely
  - 56a/56b confirmed the type() hang mechanism; 56c solved it by targeting non-VM functions
  - **This is a confirmed arbitrary code execution primitive with controlled dispatch and return**
- Updated FINDINGS.md with Finding 82
- Updated PROBE_INDEX.md with 56c results

## Phase 14b — CClosure Function Pointer Confirmed (2026-10-18)

- **★★★ BREAKTHROUGH: CClosure +0x20 confirmed as C function dispatch pointer** (probes 55g, 54r)
  - 55g: writing +1 to +0x20 low dword → immediate garbage output + crash (misaligned execution)
  - 54r: all 7 tested functions' +0x20 targets are real x86-64 prologues (`push rbp; mov rbp, rsp`)
  - 54q reinterpreted: the 15s timeout was a successful redirect to tonumber's C code, not a hang
  - CClosure lives in SceLibcHeap (prot=0x3 RW) — fully writable
  - **This is an arbitrary function pointer redirect primitive**
- **Syscall 624 characterized** as VM operation counter: +5 per mmap, zero jitter, monotonic (probe 52b)
- **Syscall 631 confirmed lethal** — kills process past pcall (probe 52a)
- Syscalls 627-630 all PCALL-FAIL (probe 52a)
- Updated CLAUDE.md evidence correction: userland code execution via CClosure redirect IS established
- Updated FINDINGS.md with Findings 79-81
- Updated PROBE_INDEX.md with 55g, 54r, 52a, 52b results

## Phase 10d — Relapse Intelligence Integration (2026-10-16)

- Analyzed Relapse exploit (fw 7.00-13.60) for techniques applicable to fw 14.10
- Developed `43o_afroute_kaslr` — AF_ROUTE socket RTM_GET KASLR defeat (Relapse's proven technique)
- Developed `43p_aio_bypass` — AIO syscalls via make_syscall to test if sandbox kill is resolve()-side only
  - If AIO lives: reopens the entire race condition bug class without threading
  - Tests all 10 FreeBSD AIO syscalls (aio_read, aio_write, lio_listio, etc.)
  - Hunts for Sony's aio_multi_wait in syscall range 532-700
- Added Theories 18-20 and Attack Chain D to UNTESTED_THEORIES.md
- Added Relapse intelligence and userland exploit chain documentation to STRATEGY.md
- Key insight: AIO was only tested via resolve() (probes 19-19g), never via make_syscall
  - The same pattern as sysctl: resolve() said blocked, make_syscall proved it works
  - If this pattern holds for AIO, we get kernel-level concurrency without threading

## Phase 10b — Deep Data Analysis & New Exploit Vectors (2026-10-16)

- Comprehensive cross-phase data audit uncovered 8 new findings (Findings 28–35) from overlooked probe results
- Developed 5 new probes (`43j`–`43n`) targeting newly discovered vectors:
  - `43j_msgbuf_full_read`: Full kern.msgbuf read (up to 64KB) for KASLR-defeating boot messages
  - `43k_cpuusage_deep`: sceKernelGetCpuUsage(617) with proper buffers + mtypeprotect(585) W^X bypass test
  - `43l_mincore_kaslr`: mincore() as KASLR side-channel oracle probing kernel VA ranges
  - `43m_sockopt_overflow`: PS5 socket option 256-byte buffer potential kernel heap overflow
  - `43n_hid_ioctl`: /dev/hid + ioctl(54) via make_syscall for HID driver kernel state access
- Key discoveries from audit:
  - sceKernelMtypeprotect (585) returned success (ret=1) — only Sony syscall to return positive
  - sceKernelGetCpuUsage (617) returned success (ret=0) — live Sony syscall with empty buffer
  - kern.msgbuf returned 8 bytes with value 0x7EF710000 — full read may leak kernel addresses
  - mincore() works as memory residency oracle — side-channel KASLR probing possible
  - PS5 socket options accept 256-byte buffers for 4-byte boolean flags — potential kernel heap overflow
  - /dev/hid opens successfully — ioctl untested via make_syscall
  - thr_self returns real TID (101819) — kernel thread handle
  - fn_addr has constant 0x9FE5 prefix across all ASLR'd processes — reduced entropy

## Phase 10 — Untested Theories & Probe Suite Preparation (2026-10-16)

- Developed 9 targeted probes (`43a`–`43i`) addressing Tier S and Tier A theories:
  - `43a_kldstat_kaslr`: `kldstat` tested against both syscall 308 (standard FreeBSD) and 367 to defeat KASLR
  - `43b_kldsym_resolve`: `kldsym` (337) to look up arbitrary kernel symbols by name (`prison0`, `allproc`, `copyin`, `copyout`)
  - `43c_sysarch_gsbase`: `sysarch` GET_GSBASE (op 130) to leak kernel `curthread` address
  - `43d_kinfo_proc_full`: Full byte-by-byte dump of all 1,096 bytes of `kern.proc.pid` and `kern.proc.filedesc`
  - `43e_blocked_syscall_bypass`: Raw `make_syscall` testing of `thr_new` (455), `ioctl` (54), `dup`/`dup2`, `pipe2` (542)
  - `43f_sysctl_write`: Sysctl write testing on `kern.securelevel` (-1), `kern.coredump`, and debug MIBs
  - `43g_sony_syscall_sweep`: Comprehensive automated sweep of Sony syscalls 540–700
  - `43h_mtypeprotect_wxbypass`: Memory type and protection investigation via `sceKernelMtypeprotect` (585)
  - `43i_fn_redirect`: ROP chain function target redirect and persistence verification across syscall invocations
- Fixed critical bugs across probe suite:
  - Corrected `sysarch` command numbers in `43c` (130 is `GET_GSBASE`; avoided fatal crash from calling 129 `SET_FSBASE` with NULL)
  - Fixed byte-reading routines in `43a` and `43d` (`safe_rb` byte access instead of `safe_rd` dword truncation)
  - Fixed undefined global `MB` variable in `42g_rop_kptr_leak.lua`
- Repository consolidation: unified tools and complementary phase results from split downloads.

## Phase 9 — KASLR Defeat Attempts & ROP Architecture Deep Dive (2026-10-16)

- **ROP Chain Call Architecture Decoded (probe 42i):**
  - Mapped complete gadget sequence across entire 0x300-byte chain
  - Decoded argument loading pattern (`pop rax` -> `mov rax,[rax]` -> `pop rdi` -> `mov [rdi],rax`)
  - Pinpointed exact argument source slots (`0x31071C040`–`0x31071C0B0`) and destination registers (rdi, rsi, rdx, rcx, r8, rsp pivot)
  - Confirmed stack pivot gadget (`pop rsp; ret` at eboot+0x9A2) targets `fcall_stub.fn_addr`
- **Dense Sysctl & Kinfo_proc Auditing (probes 42b, 42c, 42e, 42h2):**
  - Clarified false-positive kernel pointer alerts: `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are sentinels/bitmasks
  - Identified live sysctl leaf nodes: `kern.version`, `kern.ostype`, `kern.osrelease`, `hw.machine`, `hw.pagesize`
  - Confirmed sandbox blocks `kern.proc.all`, `kern.file`, `kern.proc.kstack`, `kern.proc.auxv`, and `net.inet.tcp.pcblist`
- **Physical Memory Survey via `/dev/dmem0` (probes 42d, 42f, 42f2, 42g–42g4):**
  - Direct memory device fd=22/24 opened successfully
  - Scanned 90+ physical offsets: offset 0x0 returns GPU hardware register `0x80000000_C0012800`
  - Tested 4GB, 4.5GB, and high physical address spaces: unmapped or all zeros
  - Proves `/dev/dmem0` access is strictly isolated to GPU memory and cannot map kernel/CPU physical RAM
- **Thread and Sandboxed Subsystem Exploration (probes 42d, 42f, 42j):**
  - `thr_self` returns valid TID (101819); `procctl` ASLR/stackgap/priv controls blocked
  - Probed Sony syscalls 576–619: `sceKernelMtypeprotect` (585) returns 1; `sceKernelGetCpuUsage` (617) works; memory queries blocked
  - Confirmed `kenv` (390) and `msync` (226) are instant-kill syscalls

## Phase 8 — Live Network Path Testing (2026-10-15/16)

- TCP connect-back fuzz confirmed working end-to-end (probe 40)
- Port bind policy mapped: 1024–32767 open, <1024 and ≥40000 blocked (probe 36)
- `ip_reass()` verified correct on all 7 standard fragment cases (probe 39)
- IP options rejected at `ip_output()` before reaching `ip_dooptions()` (probe 37)
- ktimer surface partially open: create/settime work, gettime/delete blocked (probe 42a)
- `memfd_create` is a stub; `msync` confirmed as instant-kill syscall (probe 42b)
- Crash handler decoded as ASLR oracle (magic `0x13371337`, leaks module base)
- Kernel info via sysctl: FreeBSD r230171, securelevel=1024, 16KB pages (probe 42a)

## Phase 7 — Heap Exploitation & ROP (2026-10-15)

- GPU mmap heap R/W primitive: 256+ adjacent pages, no guard pages (probes 41c–41e)
- ASLR bypass: `dynlib_get_info` leaks all 39 module bases (probe 41o)
- Complete ROP gadget catalog extracted from eboot (probes 41r–41t)
- Loader ROP chain reverse-engineered: full call mechanism mapped (probe 41v)
- **ROP chain hijack confirmed** — chain + fn_addr writable from heap (probe 41z)
- Vtable chase closed: 41k-era objects were heap-spray artifacts (probes 41m–41q)

## Phase 6 — Raw Packet Injection (2026-10-15)

- RAW socket + IP_HDRINCL confirmed working (probe 34)
- Crafted UDP packets reach kernel `ip_input()` through loopback

## Phase 5 — Buffer & I/O Edge Cases (2026-10-15)

- `MSG_DONTWAIT` (0x80) discovered as the real nonblocking mechanism (probe 33f)
- F_SETFL confirmed cosmetic-only: kernel ignores flag changes (probes 32–33c)

## Phase 4 — IPC & Network Internals (2026-10-15)

- `writev` works (IOV_MAX=1024), SCM_RIGHTS validated (probe 30b)
- F_SETFL is cosmetic; poll() works; kqueue fd allocates but kevent returns -1 (probe 30c)
- TCP_INFO: 236 bytes, no kernel pointer leaks; 23 SOL_SOCKET options (probe 31b)
- PS5 custom socket options (0x2000–0x100000) are boolean flags, not exploitable (probe 31c)

## Phase 3 — Signals & Code Execution (2026-10-15)

- W^X strictly enforced; execute-only memory (XOM) on system libs (probes 26–26e)
- sigaltstack kernel write dead: copyout() validates destinations (probes 23–25)
- sigprocmask is a no-op (probe 25c)

## Phase 2 — Kernel Object Stress (2026-10-15)

- Threading fully blocked: fork/rfork/thr_new all return -1 (probe 27)
- AIO completely sandbox-killed (probes 19–19g)
- UMTX/nwake behavior mapped (probes 10–13)
- Device ioctls all blocked by sandbox (probe 14)

## Phase 1 — Identity & Layout (2026-10-15)

- Firmware 14.10 confirmed, Lua 5.1 loader on TCP 9026
- ~40 working syscalls mapped out of 600+
- Process memory layout and filesystem access mapped
