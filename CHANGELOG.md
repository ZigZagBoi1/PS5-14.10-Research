# Changelog

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
