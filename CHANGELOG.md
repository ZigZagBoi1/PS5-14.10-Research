# Changelog

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
