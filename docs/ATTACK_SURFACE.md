# Complete Attack Surface Map — PS5 14.10

## Syscall Status

### Fully Working
| Syscall | Number | Notes |
|---------|--------|-------|
| `read` | 3 | Works on socket fds |
| `write` | 4 | Works on socket fds |
| `close` | 6 | Standard fd close |
| `getpid` | 20 | Returns process PID |
| `recvmsg` | 27 | Full functionality with MSG_DONTWAIT |
| `sendmsg` | 28 | Full functionality with MSG_DONTWAIT |
| `socket` | 97 | AF_INET, AF_INET6, AF_UNIX; STREAM, DGRAM, RAW |
| `connect` | 98 | TCP and raw socket connect |
| `bind` | 104 | Works on loopback (port restrictions may apply) |
| `setsockopt` | 105 | Limited options writable (see below) |
| `listen` | 106 | TCP listen works |
| `getsockopt` | 118 | Most options readable |
| `readv` | 120 | Up to IOV_MAX=1024 iovecs |
| `writev` | 121 | Up to IOV_MAX=1024 iovecs, 1025 rejected |
| `socketpair` | 135 | AF_UNIX SOCK_STREAM |
| `shutdown` | 134 | Standard shutdown |
| `poll` | 209 | Correct POLLIN/POLLHUP/POLLNVAL semantics |
| `mmap` | 477 | RW only (no EXEC). MAP_FIXED works. |
| `munmap` | 73 | Standard |
| `madvise` | 75 | Most advisories work (not MADV_PROTECT) |
| `mlock` | 203 | Works |
| `sigaction` | 416 | Can set SIG_IGN/SIG_DFL, install handlers |
| `fcntl` | 92 | F_GETFL works; F_SETFL cosmetic only |

### Partially Working / Limited
| Syscall | Notes |
|---------|-------|
| `setsockopt` | Only: TCP_NODELAY, TCP_KEEPINIT, SO_SNDBUF, SO_RCVBUF, SO_RCVLOWAT, SO_LINGER, SO_TIMESTAMP, IP_TTL, IP_MINTTL, IP_HDRINCL, PS5 custom flags |
| `mmap` | RW only — PROT_EXEC always stripped. MAP_FIXED works for page-aligned remapping. |
| `fcntl F_SETFL` | Returns -1 but updates visible flags. **Kernel does NOT honor the flags** (O_NONBLOCK has no effect). Each call REPLACES flags (not OR). |
| `sigaltstack` | Can set alternate stack, but signal delivery to it triggers copyout() validation → EFAULT → process killed |
| `kqueue` / `kevent` | Valid fd; tested read, signal, user, and timer filters register or produce events. See saved probes 20 and 21. Copy-on-fork behavior is untested; process creation returned -1 in probe 27. |
| Sony sys 649 (module member) | ret=0 for member types 1-4, 7, 8 — returns userland module addresses only, no kernel pointers. (probe 54k, 2026-10-18) |
| Sony sys 674 (VM map) | Returns 317 named regions with protections. All userland VA, zero kernel pointers. (probes 55e/55f, 2026-10-18) |
| Sony sys 624 (VM op counter) | +5 per mmap, zero jitter, monotonic. Useful as kernel-operation side channel. (probe 52b, 2026-10-18) |
| Sony sys 587 (credential metadata) | ret=0, returns 0x88 bytes. Only +0x0C = 0x20000000. No kernel pointers. (probe 55e, 2026-10-18) |
| Sony sys 671 (resource class) | Returns memory budget values. Explicit selectors need credential bit 62. (probe 55e, 2026-10-18) |
| Sony sys 643 (chicken switches) | All 32 bits accepted (ret=0) but no observable effect on W^X/sandbox. (probe 55a, 2026-10-18) |
| Sony sys 675 (reset globals) | ret=0, resets 3 globals. mprotect(RWX) still fails after. (probe 55e, 2026-10-18) |
| Sony sys 533/534 (jitshm) | `jitshm_create` returns -1 for sizes `0`, `0x1000`, `0x4000`, `0x100000` and flags `0`, `1`, `0xFFFFFFFF`; `jitshm_alias` returns -1 for a socket fd and fd `0xFFFF`. No descriptor exists to alias. (probe 251a, 2026-10-21) |
| Sony sys 535/536 (dl list/info) | Both return -1 with a zeroed struct carrying only its size at `+0`, and write nothing. (probe 251a, 2026-10-21) |
| Sony sys 549-556 (osem) | `osem_create` returns -1 for eight scalar shapes and for a NUL-terminated name pointer in either slot; the wait/post/cancel half was never reachable. (probes 252a/253a, 2026-10-21) |
| Sony sys 557/558 (namedobj) | The name is accepted but is not a key: four `557` calls on one name give four objects (`0x208`-`0x20B`). `558` frees by handle, reissues the index, and returns -1 for `0xDEAD` and `0`. (probe 254a, 2026-10-21) |
| Sony sys 559 (set_vm_container) | -1 for ids `0`-`8`, `0xF`, `0x100`, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFE`, `0x100000000`; only `0xFFFFFFFF` returns `1` (the current container) and it switches nothing - the `547` record of a mapping is identical either side of it. (probes 255a/256a, 2026-10-21) |
| Sony sys 560 (debug_init) | `560(1)` returns `0`; every gated call answers exactly as before it (`656`, `593` mode 1, `634`, `mprotect` RX/RWX, `643`), so the success has no observable capability. (probes 257a/258a, 2026-10-21) |
| Sony sys 561/562 (suspend/resume process) | `561(0)` kills the process at touch, so `562` was never measured. (probe 257a, 2026-10-21) |
| `_umtx_op` (454) | Ops 5 (MUTEX_LOCK) and 21 (NWAKE_PRIVATE) returned 0 via make_syscall, op 5 writing a TID-shaped owner word (probe 56i2, 2026-10-18). The earlier "umtx" probes 04/10-13 actually called syscall 557 (namedobj_create) — see [UMTX_454_EVIDENCE](UMTX_454_EVIDENCE.md). SHM(25)/ROBUST_LISTS(26) and the wider op matrix untested; probe 110a prepared. |

### Completely Blocked (return -1 or killed)
| Syscall | Number | Notes |
|---------|--------|-------|
| `fork` | 2 | Blocked |
| `rfork` | 251 | Blocked |
| `thr_new` | 455 | Blocked |
| `dup` | 41 | Blocked |
| `dup2` | 90 | Blocked |
| `fstat` | 189 | Blocked via resolve(); WORKS via make_syscall — no kernel pointers in output (probe 43e) |
| `pipe` | 42 | Blocked |
| `pipe2` | 542 | Blocked |
| `ioctl` | 54 | Blocked |
| `sysctl` | 202 | Blocked via resolve(); WORKS via make_syscall — kern.proc.pid returns 1096B, no kernel pointers (probes 41w, 42a, 43d) |
| `mprotect` | 74 | PROT_EXEC always denied |
| `aio_read` | 255 | Blocked — kills process (confirmed 2026-10-18 via probes 54c/54f) |
| `aio_write` | 256 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_return` | 314 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_suspend` | 315 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_cancel` | 316 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_error` | 317 | Blocked — kills process (confirmed 2026-10-18) |
| Sony AIO 661 (event_create) | 661 | Instantly kills process for the two tested argument shapes (probe 54c, 2026-10-18). The **batch** entry 669 is not lethal and works: `669(cmd, reqs, count 1..128, class 1..3, ids)` queues requests that 664/666/662 drive and reap, `cmd=1` reads and `cmd=2` writes, and the result word reports the bytes moved (probes 352a-352k, 2026-10-22). 661 is one entry, not the family - see `docs/AIO_BATCH_14_10.md` |
| Sony sys 626 (RDMSR) | 626 | ret=-1 for all 11 MSR indices, 3 arg layouts (probe 54k, 2026-10-18) |
| Sony sys 567 (RDMSR read) | 567 | ret=-1 for all MSR indices, flat + struct args (probe 54k, 2026-10-18) |
| Sony sys 629 (jail bypass) | 629 | ret=-1 for all arg patterns; kld* retests crash (probe 54b, 2026-10-18) |
| Sony sys 598 (dynlib context) | 598 | ret=-1 for all arg patterns (probe 54f, 2026-10-18) |
| Sony sys 612 | 612 | ret=-1 for member values 0-8 (probe 54k, 2026-10-18) |
| Sony sys 639/638 (memory region) | 639 | ret=-1 for all address ranges (probe 54f, 2026-10-18) |
| `shm_open` | 482 | Crashes loader |
| `sendto` | 133 | Crashes syscall.resolve() |
| `recvfrom` | 29 | Crashes syscall.resolve() |
| `fcntl F_SETOWN` | — | Truly blocked (F_GETOWN stays -1) |
| `sigprocmask` | 340 | No-op: returns 0 but never modifies mask |
| `kevent` with nonzero timeout | 363 | Returns -1 with a 100ms timeout (probe 30c, PART 6). Zero-timeout register, poll, batch register, and delivery all work: 3+ events (probe 20), 31 signals, 20 user, 2000 knotes (probe 21) — including combined add+poll calls. See [the kevent analysis](KEVENT_TIMEOUT_VARIABLE.md). |
| `kldstat` | 308 | Instantly kills process (probes 56k4, 2026-10-18) |
| `kldnext` | 307 | Instantly kills process (probe 56k5, 2026-10-18) |
| Sony sys 548 (batch VM ops) | 548 | ret=-1, processed=0 for all opcodes (probe 55b, 2026-10-18) |
| Sony sys 622 (device control) | 622 | **ABI corrected (241a-247a, 2026-10-21)**: six slots are `cmd, sub, buffer, secondary address, size <= 0x40, extra`. `0x200-0x270` and `0x813` run and return `0` with `0xFFFFFFFF`; `0x400-0x493` kills whenever the `copyin` from `arg3` succeeds, at any size. No data, no overrun, no pointer |
| Sony sys 601 (process control) | 601 | Most commands ret=-1, no init state (probe 55d, 2026-10-18) |
| Sony sys 672 (dynlinker list) | 672 | ret=-1, predicate gate failed (probe 55e, 2026-10-18) |
| Sony sys 676 (CPU mode) | 676 | ret=-1, gate failed (probe 55e, 2026-10-18) |
| Sony sys 631 | 631 | Instantly kills process (probe 52a, 2026-10-18) |
| Sony sys 627-630 | 627 | PCALL-FAIL / exception for all four (probe 52a, 2026-10-18) |

### Untested (Potential Targets)
| Syscall | Number | Notes |
|---------|--------|-------|
| `ktimer_create` | 235 | **WORKS** — clocks 0 (REALTIME) and 4 (MONOTONIC), cap 27 timers |
| 236 (42a: `ktimer_settime`) | 236 | 42a's label; upstream numbers 236 as `ktimer_delete` (1 arg) — numbering disputed, differential prepared in probe 56l (unrun) |
| `ktimer_getoverrun` | 239 | **WORKS** |
| `ktimer_gettime` | 238 | Probe-labeled gettime blocked on 42a-created ids; interpretation depends on the disputed 236/237 pair |
| 237 (42a: `ktimer_delete`) | 237 | 42a's label; upstream numbers 237 as `ktimer_settime` (4 args) — numbering disputed, differential prepared in probe 56l (unrun) |
| Sony sys 563-566 (PMC config) | 563 | ret=0 but effect is PMC configuration, not info leak (probes 54f, 2026-10-18) |
| `ppoll` | 545 | Blocked |
| `cap_rights_limit/get` | 533/515 | Blocked |
| `memfd_create` | 585 | Stub — returns fake fd=1 |
| `minherit` | 250 | Outcome unresolved: probe 38 ends at the minherit section header, without a result or termination record |
| `msync` | 226 | Outcome unresolved: 42b ends after its msync region address, without a result or termination record |
| `accept` / `accept4` | 30 / 541 | Resolves, EBADF on bad fd; needs live TCP listener test |
| `preadv` / `pwritev` | 289/290 | Resolve, EBADF on bad fd; no real file fd available to test |
| `copy_file_range` | 580 | Resolves, EBADF; untestable without file fds |
| `getsockname` | 32 | Works |
| `getpeername` | 31 | Resolves |
| `sctp_peeloff` | 471 | Resolves (SCTP socket creation untested) |
| Native sysent 677-734 | 677-734 | **58 untested entries** — includes virtual_query_by_pid(728), mmap2(725), posix_fadvise(727), cpuset_getaffinity(734). Probe 57a prepared. |

## Thread ucontexts: suspend and read work, set does not (probes 325a, 326a, 2026-10-22)

| syscall | shape | result |
|---|---|---|
| 632 `thr_suspend_ucontext` | `(tid, 0)` | `0` on a thread this process created |
| 633 `thr_resume_ucontext` | `(tid, 0)` | `0` |
| 634 `thr_get_ucontext` | `(tid, buffer)` | `-1` while the thread runs; `0` after 632, copying 0x4c0 bytes |
| 635 `thr_set_ucontext` | `(tid, buffer)` | `-1` |

The 634 copy is the suspended thread's saved register set: RIP at `+0xE0`, CS at `+0xE8`, RFLAGS at `+0xF0`, RSP at `+0xF8`, matching the values `thr_create` was given. Fourteen qwords were nonzero and none was a kernel pointer, so the 0x500-byte snapshot is zeroed before the fields are filled and the unused tail does not leak.

The interesting half is the one that is missing. 635 would let an existing thread's RIP and RSP be rewritten after creation, which `thr_create` cannot do; it returns `-1` on 14.10. The 13.60 dossier gives its body as `mov eax, 0x4e; ret`, a stub returning 78, so this entry does not match the capture at all - a reminder that a dossier's "stub" verdict is a 13.60 statement.

## Performance counters: a bounded write into the thread's pcb, fully validated (probe 327a, 2026-10-22)

`sys_563.md`-`sys_567.md` describe a PMC subsystem whose selector is 0 (every thread of this process), 1..99999 (a process id) or a thread id. The process path first requires `cred+0x58 == 0x4800000000010003` and answers 3 when it does not match; the zero path is scoped to the current pid. Measured on the caller's own threads:

| call | result |
|---|---|
| `563(0)` enable | `0` |
| `564(0)` disable | `0` |
| `566(tid, 0, 0x1234)` | `0` |
| `566(tid, 1, 0x5678)` | `0` |
| `566(tid, 6, 0)` | `-1` (index must be 0..5 or `0xffffffff`) |
| `565(tid, 0, 0x11)` | `0` |
| `565(tid, 0, 0x10000)` | `-1` (a bit the handler rejects) |
| `567(tid, 0, out)` | `0`, `out = 0x1234` |
| `563(0x7FFFFFFF)` | `-1` |

The read-back is the useful control: the value written with 566 comes back through 567, so the store really lands in `PCB+0x190+8*index` and the six slots are the whole range. The event-select word goes through the documented mask - a rejected bit returns `-1` rather than being silently cleared - and an out-of-range counter index is refused before any store.

So this family gives a caller six qwords of kernel-side state on its own threads and nothing else. It is not a primitive, and the interesting half (another process's pcb) is behind an authid no game process holds.

## mmap_dmem refuses every shape, and the authid gates hold (probes 330a-333a, 2026-10-22)

`sys_628.md` recovers six slots - address `+0x00`, length `+0x08`, descriptor `+0x10`, protection `+0x18`, flags `+0x20`, offset `+0x28` - with 16 KiB alignment on address, length and offset, protection limited to mask `0x3f3`, flags excluding `0x009fdf2f`, and **descriptor `-1` bypassing** the device lookup at `0x8ad833e0`. That last clause is what made the syscall worth calling: a descriptor that bypasses the device check plus an aligned physical offset reads as a physical-memory mapper.

It is not one on 14.10. Twenty-four calls covering descriptor `-1`, a `/dev/dmem0` descriptor, a `/dev/zero` descriptor and `0`, three protections, flag `0x40`, a nonzero address hint and two offsets **all return `-1`**. The refusal is uniform, so it does not depend on the descriptor at all: the entry rejects before the device lookup, which puts `mmap_dmem` in the same class as every other device-context call.

The direct-memory nodes themselves open: `dmem0` (fds 22/23), `dmem1` (24/25), `dmem2` (26/27), `dce` (28/29), `gic` (30/31), `gc` (32/33) and `zero` (34/35), each in both modes.

### The authid gates

Six handlers compare `cred+0x58` against an identity value before doing any work: 535 and 536 (dynamic-linker list by pid) and 563-566 (performance counters). Probes 327a and 322a always used selector `0`, which skips the check. Called with this process's own pid, **all six return `-1`** while the selector-`0` paths still return `0`, so the gate is exactly the wall the dossier describes and it is not bypassable by naming your own process.

`587` (credential record) is the only handler that exposes the structure. It copies 0x88 bytes starting at `target_cred+0x58`, but on the privilege-failure path - the one a game process reaches - only an allowlist and the capability word survive; every other byte stays zero. Asking it about pids `0`, `1`, `2`, `5`, `16` and `30` returns `0` each time with a single nonzero dword at record `+0x0C` (`cred+0x64`): `0x20000000` for this process and `0x40000000` for the system processes. Record `+0x08` (`cred+0x60`, the word whose **bit 62** gates 618, 646 and 671) is zero for both.

So the identity at `cred+0x58` is never readable and never writable from userland: no handler in the recovered set writes it, and a process inherits it from the image it was launched as. The gated families stay closed without a kernel write.

## Device Nodes (probes 259a-263a, 2026-10-21)

`/dev` is readable from the game process with `open` + `getdirentries`, and the kernel reports the **32-bit dirent layout** (`u32 ino`, `u16 reclen` at `+4`, `u8 type` at `+6`, `u8 namlen` at `+7`, name at `+8`). 76 nodes exist; **34 open** and 42 refuse with `-1`.

| Open (34) | Refused (42) |
|-----------|--------------|
| `random`, `urandom`, `dipsw`, `fd`, `stdin`, `null`, `zero`, `deci_stdin`, `hmd2_cmd`, `hmd2_imu`, `hmd2_leddet`, `hmd2_gaze`, `hmd_cmd`, `hmd_snsr`, `hmd_3da`, `hmd_dist`, `bt`, `hid`, `dmem0`, `dmem1`, `dmem2`, `gc`, `ajmi`, `ajm`, `dce`, `rng`, `gic`, `notification0`, `notification6`, `notification7`, `usbctl`, `camera`, `usb`, `ugen0.2` | `dbggc`, `deci_stdout`, `deci_stderr`, the rest of `deci_tty*`, `uvd_dec`, `uvd_enc`, `sbl_srv`, `encdec`, `fttrm`, `duid`, `acm`, `a53mm`, `a53mmsys`, `mp3`, `notification1`-`notification5`, `standard` `tty`, `hmd2_track`, `hmd2_image`, `hmd2_gen_data`, `hmd2_slam_trace`, `ctty`, `sce_zlib`, `ugen0.1`, `ugen1.1`, `ugen2.1` |

The descriptors are real and the syscall is not filtered. `read` works on `zero`, `random`, `null` and `urandom`, `FIOCLEX`/`FIONCLEX` return `0` on all five tested nodes, and `FIONBIO` returns `0` on the simple devices but `-1` on `dce`, which is the proof that `dce` has its own `d_ioctl` and that the refusal comes from the driver. `/dev/dce` returned `-1` for commands `0x00`-`0xFF` with a null buffer, with a `0x1000` buffer, and with a request struct whose first dword is the command, so the encoding is not a small integer. (probes 264a-268a, 2026-10-21)

**The whole command space was then measured** (probes 274a-287a, 2026-10-22; full write-up in [DEVICE_IOCTL_14_10.md](DEVICE_IOCTL_14_10.md)). Thirty-two million calls across 31 nodes covered every direction, the whole 14-bit length field and every command byte. The result is a table of two entries:

- `/dev/dce` answers exactly one driver command, `0x80088209` (`_IOW(0x82, 9, 8)`). It requires exactly 8 bytes, ignores their content, returns `0`, writes nothing, and repeats without effect. Inert.
- `/dev/gc` answers twenty-five commands in group `0x81`, with structure sizes of 4, 8, `0x10`, `0x18`, `0x28`, `0x30`, `0x48` and `0x888` bytes. They copy a struct in, write small constants back (`0x101`, `3`, `0x80000000`, `0x0C`, `0x5C`, `0x10`, `0`), and reject a null pointer. None of them follows an address taken from the struct (283a), none of them changes behaviour when the struct bytes change (285a, 287a), and every write stays inside the declared length.

One graphics command, `0xC0048125`, blocks the calling thread forever: the console keeps rendering and the loader keeps accepting connections, but the thread stays inside the driver and the app fails on exit with a black screen. It returned `0` before `0x80888123` had run and hangs afterwards, so the blocking state is reachable, not random. A hang is not a primitive: it hands back no address and corrupts nothing the caller can observe.

`dmem0` and `dmem1` map physical memory with `O_RDWR` + `PROT_READ` + `MAP_SHARED` and a physical address as the file offset, but every offset above 0 reads all-zero and the page at 0 holds GPU hardware registers (`0x80000000_C0012800` first). `dmem2` refuses every shape. The aperture-only reading stands.

## Bind Policy (probe 36)
- Ports <1024: blocked. Ports ≥40000: blocked. 1024–32767: open.
- Listener port for all future probes: **31337/31338** (confirmed working).

## Network Input Path Status (probes 37/39)
- `ip_reass()`: all standard fragment cases handled correctly — deeper fuzz (queue exhaustion, timeout, 64+ frags) still open.
- `ip_dooptions()`: runs on loopback injection (LSRR/SSRR/TS-overflow get processed and dropped), but **malformed option lengths are rejected in ip_output before reaching the parser**. Input-side option fuzzing must come from the real network (PC → PS5 LAN IP), not loopback.

## Socket Options Accessible

### SOL_SOCKET (level 0xFFFF) — 23 options
```
0x0001 SO_DEBUG          0x0002 SO_ACCEPTCONN     0x0004 SO_REUSEADDR
0x0008 SO_KEEPALIVE      0x0010 SO_DONTROUTE      0x0020 SO_BROADCAST
0x0080 SO_LINGER         0x0100 SO_OOBINLINE      0x0200 SO_REUSEPORT
0x0400 SO_TIMESTAMP      0x0800 SO_NOSIGPIPE
0x1001 SO_SNDBUF         0x1002 SO_RCVBUF         0x1003 SO_SNDLOWAT
0x1004 SO_RCVLOWAT       0x1005 SO_SNDTIMEO       0x1006 SO_RCVTIMEO
0x1007 SO_ERROR          0x1008 SO_TYPE
0x1011 SO_SETFIB         0x1012 SO_USER_COOKIE    0x1013 SO_TS_CLOCK
```

### PS5 Custom Socket Options (Sony-extended)
```
0x2000   — boolean flag bit in so_options
0x10000  — boolean flag bit
0x20000  — boolean flag bit
0x40000  — boolean flag bit
0x100000 — boolean flag bit
```
All are simple on/off toggles. set(any_nonzero) → readback = option_number. Same behavior on all socket types. **Not exploitable.**

### TCP Level (level 6)
- `TCP_NODELAY` (1) — writable
- `TCP_KEEPINIT` (128) — writable
- `TCP_INFO` (32) — 236 bytes readable, all protocol metadata, no kernel pointers
- `TCP_CONGESTION` (64) — "newreno"

### IP Level (level 0)
- `IP_TTL` (4) — writable (accepts 256, -1)
- `IP_MINTTL` (66) — writable
- `IP_HDRINCL` (2) — writable on RAW sockets (value reads back as 8 = INP_HDRINCL flag)


## Sony 601-660: measured on 14.10 (2026-10-20)

One connection per number, six zero `uint64` arguments, via
`tools/syscall_isolation_sweep.py --range 601-660 --wait-for-loader 120`.
Capture: `results/phase15_native_sent/syscall_isolation_sweep_20261020_194148.txt`.

| syscall | 13.60 name | zero-arg result |
|---|---|---|
| 601 | `mdbg_service` | -1 |
| 602 | `randomized_path` | 0 |
| 603 | `rdup` | -1 |
| 604 | `dl_get_metadata` | -1 |
| 605 | `workaround8849` | -1 |
| 606 | `is_development_mode` | 0 |
| 607 | `get_self_auth_info` | -1 |
| 608 | `dynlib_get_info_ex` | -1 |
| 609 | `budget_getid` | kills |
| 610 | `budget_get_ptype` | -1 |
| 611 | `get_paging_stats_of_all_threads` | -1 |
| 612 | `get_proc_type_info` | -1 |
| 613 | `get_resident_count` | -1 |
| 614 | `prepare_to_suspend_process` | kills |
| 615 | `get_resident_fmem_count` | -1 |
| 616 | `thr_get_name` | -1 |
| 617 | `set_gpo` | 0 |
| 618 | `get_paging_stats_of_all_objects` | -1 |
| 619 | `test_debug_rwmem` | -1 |
| 620 | `free_stack` | 0 |
| 621 | `suspend_system` | kills |
| 622 | `ipmimgr_call` | kills (returns 0 with a real request, `55c`) |
| 623 | `get_gpo` | -1 |
| 624 | `get_vm_map_timestamp` | 3377 |
| 625 | `opmc_set_hw` | -1 |
| 626 | `opmc_get_hw` | -1 |
| 627 | `get_cpu_usage_all` | -1 |
| 628 | `mmap_dmem` | -1 |
| 629 | `physhm_open` | -1 |
| 630 | `physhm_unlink` | -1 |
| 631 | `resume_internal_hdd` | kills |
| 632 | `thr_suspend_ucontext` | -1 |
| 633 | `thr_resume_ucontext` | -1 |
| 634 | `thr_get_ucontext` | -1 |
| 635 | `thr_set_ucontext` | -1 |
| 636 | `set_timezone_info` | -1 |
| 637 | `set_phys_fmem_limit` | -1 |
| 638 | `utc_to_localtime` | 0 |
| 639 | `localtime_to_utc` | 0 |
| 640 | `set_uevt` | 0 |
| 641 | `get_cpu_usage_proc` | -1 |
| 642 | `get_map_statistics` | -1 |
| 643 | `set_chicken_switches` | 0 |
| 644, 645 | unnamed in the 13.60 capture | -1 |
| 646 | `get_kernel_mem_statistics` | -1 |
| 647 | `get_sdk_compiled_version` | -1 |
| 648 | `app_state_change` | -1 |
| 649 | `dynlib_get_obj_member` | -1 |
| 650 | `budget_get_ptype_of_budget` | kills |
| 651 | `prepare_to_resume_process` | kills |
| 652 | `process_terminate` | -1 |
| 653 | `blockpool_open` | handle (22, then 23, 24, then -1) |
| 654 | `blockpool_map` | -1 |
| 655 | `blockpool_unmap` | -1 |
| 656 | `dynlib_get_info_for_libdbg` | -1 |
| 657 | `blockpool_batch` | 0 (zeroes 16 bytes at arg3 when arg2=0) |
| 658 | `fdatasync` | -1 |
| 659 | `dynlib_get_list2` | -1 |
| 660 | `dynlib_get_info2` | -1 |

### Follow-up probes on the interesting slots

- **619 `test_debug_rwmem` (179a)** - fifteen argument layouts, including the calling pid in
  arg1, a canary page in each of arg1..arg3, and `(pid, src, dst, size, write)` in both
  directions. Every call returned `-1` and no byte changed. The handler runs and refuses all
  of it, which reads as a privilege or process-flag gate rather than an argument problem.
  Capture `results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194308.txt`.
- **625 `opmc_set_hw` / 626 `opmc_get_hw` (180a, 181a, 182a)** - 625 accepts exactly
  `arg1` in `{0x0D, 0x0E, 0x0F, 0x10}` with `arg2` in `{1, 2, 3}` and returns `0`; everything
  else is `-1`. 626 returned `-1` for 1270 shapes, including the exact pairs 625 accepts, both
  with a canary page in arg3 and with NULL. So the setter takes a narrow window and the getter
  never answers - no MSR read, no readback. Captures
  `results/phase17_new_vectors/180a_opmc_hw_20261020_194332.txt`,
  `181a_opmc_set_hw_surface_20261020_194345.txt`,
  `182a_opmc_get_hw_surface_20261020_194421.txt`.
- **653-657 blockpool (183a, 184a)** - `blockpool_open` is not a stub: it returns 22, then 23,
  then 24, then `-1` for every later call in the same process, so it allocates handles from a
  small per-process pool. `blockpool_map` and `blockpool_unmap` returned `-1` for every shape
  tried, including the live handle in arg1 with size and buffer variants. `blockpool_batch`
  returns `0` and zeroes the first 16 bytes of arg3 when arg2 is 0, and `-1` for arg2 1-8. No
  mapping was obtained. Captures
  `results/phase17_new_vectors/183a_blockpool_20261020_194445.txt`,
  `184a_blockpool_batch_20261020_194508.txt`.
- **654 takes a range in this process's map, and no region qualifies (311a, 312a)** -
  `results/kernel_handlers/analysis/sys_654.md` recovers the real contract: `narg=5`, slots
  `(address, length, operation, flags, reserved)`, with 64 KiB alignment on both address and
  length, flags limited to bits `0x33`, zero reserved, and operations `0`, `3`, `10` routed one
  way and `11`-`20` another. 183a called it as `(handle, 0, 0x1000, buf)` - a blockpool handle
  where the address belongs - so no call had ever reached the body. Supplied correctly on a
  64 KiB-aligned GPU mapping, operations `0`-`20` and flags `0`-`0x40` all return `-1` and the
  `547` region record is unchanged. The contract rejects any entry whose object type byte at
  `+0x9d` is not `11`, so 312a walked every region the process map reports - **314 regions, 82
  of them 64 KiB aligned** - and called `654(start, 0, 0, 0, 0)` on each. **Zero accepted.** No
  mapping a game process owns carries that object type, which is the same wall 673 hit. Captures
  `results/phase17_new_vectors/311a_sys654_range_op_20261022_121159.txt`,
  `312a_sys654_region_scan_20261022_121245.txt`.
- **653 handles are file descriptors (190a, 191a)** - proven, not inferred: a socket taken first
  answered `22`, then `653` answered `23`, `24`, `25` and `-1`; `close(23)` returned `0` and the
  next open answered `22` again. Restarting the loader process resets the sequence, so the limit
  is three concurrent handles per process and closing frees a slot. Everything the descriptor
  could be asked to do refuses: `mmap` with `MAP_SHARED` and with `0x1002` flags, two protections,
  two lengths -> `-1`; `read`, `write` and `ioctl` -> `-1`; `654 blockpool_map` and `655
  blockpool_unmap` -> `-1` for five layouts; `673 blockpool_move` -> `-1`. `657 blockpool_batch`
  is the exception: it returns `0` and zeroes the dword at arg3 **even when the handle was just
  closed**, so it does not revalidate the descriptor - but the only thing it writes is zeroes, so
  there is no readback. The family allocates real state and exposes no way to use it. Captures
  `results/phase17_new_vectors/190a_blockpool_fd_semantics_20261021_113658.txt`,
  `191a_blockpool_descriptor_20261021_114008.txt`.
- **Event flags and named objects are live kernel objects (192a-202a)** - the 538-544 family is
  not a stub. `538 evf_create` accepts a name pointer and a non-zero initial bit count and hands
  back a handle; `557 namedobj_create` shares the same table; `544 set`, `543 poll`, `542 wait`,
  `539 delete` and `558 delete` all work. Handles are `0x2000 | index` with the generation in the
  upper bits (518, 545 and 8737 are the same index at different generations), and the table
  checks the class: `558` on an evf handle and `539` on a namedobj handle both return `-1` and
  leave the object alive, and `543/544/541` reject a namedobj handle. `543(handle, bits, mode)`
  with mode `1` or `2` returns `0` only when the requested bit is set; mode `0` and a clear bit
  return `-1`; polling does not consume the bit. `542(handle, bits, mode, result, timeout)` with
  a null timeout blocks, and a `544` from the main thread wakes it with the satisfied mask in
  `result` (200a section C: `DEADBEEF` -> `1`). `539 delete` on a flag with a blocked waiter
  returns `0` and wakes the waiter with mask `0` (201a). Captures
  `results/phase17_new_vectors/192a_stateful_abi_20261021_115932.txt` through
  `202a_evf_wait_layout_20261021_120645.txt`.
- **The handle generation is three bits and wraps after eight reuses (210a-212a)** - the handle
  word is `generation << 13 | index`. Twenty create/delete rounds on one slot give `207`, `2207`,
  `4207`, `6207`, `8207`, `A207`, `C207`, `E207`, then `207` again, so the counter has eight
  values and no wider tag. The consequence is exact handle reuse: after eight churns a handle
  captured on the first round is byte-identical to the live object's handle, and `544` through
  that stale value set the live flag's bit (`trywait` then returned `0`). The class check still
  holds, so the alias is confined to one class and cannot become a type confusion: `558` on an
  evf handle and `539` on a namedobj handle return `-1` and leave the object usable (213a).
  Captures `results/phase17_new_vectors/210a_evf_generation_wrap_20261021_121823.txt`,
  `211a_evf_generation_sequence_20261021_121831.txt`,
  `212a_evf_stale_handle_20261021_121844.txt`, `213a_evf_class_blind_20261021_121853.txt`.
- **Create names are bounded, not truncated (216a)** - `538`/`557` accept names up to 31
  characters and return `-1` at 32, and `-1` for a NULL name, so the copy has a fixed target and a
  length check rather than a length-trusting copy. Capture
  `results/phase17_new_vectors/216a_evf_name_bound_20261021_122014.txt`.
- **A blocked waiter is only reclaimed by deleting its object** - `thr_kill(tid, 0)` is a
  liveness query (`0` means alive) and does not stop a thread that is asleep in a kernel wait.
  Each such thread holds a slot permanently, and the process holds a ceiling of live child threads
  that varies per loader: 25 on one, eleven on another with two waiters, nine on a third, every
  accepted spawn returning `0` with the pid unchanged and the next blocking inside `thr_create`
  with the socket still accepting. Treat eight children as the working limit for one probe. Parked waiters never exit, so that capacity is spent by every waiter a session
  spawns; `546 evf_cancel` and a completed `544 evf_set` do not obviously return the slot, which
  `probes/phase17_new_vectors/243a_thread_slot_reclaim.lua` measures.
- **A child thread must park when its call returns (241a, 242a)** - a child spawned with
  `RIP = syscall_address` resumes inside the loader's own syscall wrapper when the call returns, so
  a zeroed stack makes it `ret` to address 0 and run wild inside the loader. That is what turned
  the console's output to binary garbage in 238a-240a and killed the process; it is not a kernel
  fault. Put the `jmp $` gadget at `RSP+0` (eight copies at `stack+0x3000`) so the wrapper's `ret`
  parks the thread, or spawn with `RIP = jmp $` when the child needs no syscall. Capture
  `results/phase17_new_vectors/241a_evf_cancel_parked_20261021_150126.txt`.
- **634 `thr_get_ucontext` writes nothing even for a live TID (235a)** - a spinning child was
  spawned and confirmed alive (`thr_kill(tid,0)` -> `0`), then `634` was called as `(tid, buf)`,
  `(tid, buf, 0x400)`, `(buf, tid)` and `(tid, buf, 0x1000)`, plus with the caller's own tid: every
  call left a canary page untouched and the process survived. The suspended-thread route to a
  register dump is therefore not reachable through this call as documented. Capture
  `results/phase17_new_vectors/235a_ucontext_live_tid_20261021_145605.txt`.
- **657 `blockpool_batch` writes its own status word, not a copy (236a)** - `653()` returned 131
  and `657(h, n, buf)` wrote one dword `0` at `buf+0` for every `n` in 0..8, returning `0` only
  for `n = 0` and `-1` for 1..8, repeating the write on three consecutive calls, and still writing
  after `close(h)`. So the write is an unconditional out-status and the descriptor is not
  revalidated; there is no batch copy to aim. Capture
  `results/phase17_new_vectors/236a_blockpool_batch_write_20261021_145629.txt`.
- **547 is not a mapped/unmapped oracle for kernel space (237a)** - the control pair pins the
  call down: a mapped page returns `0` with record `[0x111FC000 0x3 0x11200000 0x3 0x3 0x610020]`,
  the same address after `munmap` returns `-1` with the canary intact, and a never-mapped
  `0x100000` returns `-1`. Then 32 kernel addresses - 16 across `0xFFFFFFFF80000000` in 128 MiB
  steps and 16 across `0xFFFF800000000000` in 4 GiB steps - all returned `-1` and wrote nothing.
  No KASLR oracle. Capture
  `results/phase17_new_vectors/237a_query_protection_oracle_20261021_145710.txt`.
- **The dynlib family refuses canaries and leaks nothing (247a, 248a)** - a canary-filled
  struct makes `593` return `-1` because the handler reads version/flag fields; zeroed with only
  the size at `+0`, `593(0, struct{size=0x160})` returns `0` and fills 17 dwords with the module
  name at `+0x008`. `660 dynlib_get_info2` is identical to `593` for handle 0, `656
  dynlib_get_info_for_libdbg` refuses every layout tried (consistent with a debugger-credential
  gate), and `659 dynlib_get_list2` writes a count `0x13` at `+0x004` and still fails. The
  kernel-half scan is zero across twelve layouts.
- **No kernel pointer from 547, 619 or the statistics calls (198a, 199a)** - `547
  query_memory_protection(addr, out)` writes a 24-byte region record: start, `3`, end, `3`, `3`,
  and a per-process dword. It is a region lookup, not an address translation: `heap` and
  `heap+0x80` return the same record, a code pointer and a kernel address return `-1`, and no
  field is kernel-shaped. `619 test_debug_rwmem` returns `-1` for eight source/destination/length
  orders with a filled source and an untouched destination, and copies nothing. `611`, `618`,
  `642` and `646` return `-1` for three buffer/size layouts and write no byte of a canary page.
  Captures `results/phase17_new_vectors/198a_query_memory_record_20261021_120317.txt`,
  `199a_rwmem_statistics_20261021_120421.txt`.
- **netcontrol (99) still accepts the netevent queue commands (218a)** - the ABI is
  `__sys_netcontrol(ifindex, cmd, buf, size)`: with `ifindex = -1`, `cmd 0x20000003` registers
  the socket named by the int at `buf[0]` and returns `0`, and `cmd 0x20000007` unregisters it
  and returns `0`. The validation is real: `-1` for fd `0xFFFF` or `0`, for a NULL buffer, and
  for `size` 0 or 4; `0` for `size` 8, 16 and 64. Register, unregister and register again on the
  same open fd each return `0`, and three fresh sockets register and unregister cleanly, so the
  register is not one-shot and does not refuse a descriptor it has seen. Of the sixteen commands
  `0x20000000`-`0x2000000F`, only `0x03` and `0x07` are accepted. This is the API the public
  Poops chain drives to free a file and its `ucred`; every call here kept the descriptor open
  while it was registered, so the use-after-free that chain depends on was not touched by this
  probe - 232a-234a below close the registered descriptor and answer whether it survives.
  Capture
  `results/phase17_new_vectors/218a_netcontrol_abi_20261021_140851.txt`.
- **A registration holds a reference, so the public Poops trigger leaks instead of freeing
  (219a-234a)** - registering a socket takes a reference on it and unregistering returns that
  reference, which is readable from the peer of a `socketpair` (syscall `135`): with no
  registration the peer reads `0` (EOF) once the other end is closed, with a registration it
  still reads `-1` (connected), and with register then unregister before the close it reads `0`
  again. So a descriptor closed while registered does not free the socket, and the unregister of
  that dead descriptor returns `-1` and never drops the reference. What 219a and 221a measured is
  therefore a **leak of one socket plus a permanently owned queue**, not a use-after-free: on
  14.10 the descriptor lookup refuses, which is exactly the fix the public chain (documented only
  to 12.00) would need. Nothing here is a memory-corruption primitive. The queue is per interface
  (`224a`: index `-1` dead, index 1 alive), and only `ifindex -1` - the index the public ABI uses
  - is single-owner and spent for the boot, across process death and every later process; a power
  cycle clears it (`227a`, `228a`). Slab refill with 96 sockets, 32 `538` flags, 32 `557` objects
  and 8 kqueues changes nothing (`232a`). Captures
  `results/phase17_new_vectors/233a_netcontrol_peer_state_20261021_144705.txt`,
  `234a_netcontrol_ref_release_20261021_144722.txt`; full write-up in `docs/NETCONTROL_14_10.md`.
- `220a` is **not evidence**: it ran in the same process after 219a, so its `-1` registers are
  effects of the wedge 219a created rather than answers about its own trigger. The clean-order
  trigger is `probes/phase17_new_vectors/222a_netcontrol_clean_trigger.lua`, which skips its
  trigger unless a control register/unregister pair returned `0` first.

## Recovered handler contracts, measured on 14.10 (probes 235a-237b, 2026-10-21)

The 13.60 capture carries 145 decompiled handlers, and nine of them ship an
analyst-recovered argument struct. `docs/SYSCALL_CONTRACTS_13_60.md` indexes
them; these probes were built from that index instead of from six zero
arguments, and three of them answered.

| syscall | recovered contract | measured on 14.10 |
|---|---|---|
| 547 | `{ address, user_region }`, 0x18-byte record | **works**: `ret=0`, start/end/`prot` filled. Heap buffer `prot=3`; GPU page `prot=0x33` |
| 659 | `{ handles_out, capacity, count_out }` | **works**: `ret=0 count=3`, handles `0x13`, `0x14` |
| 660 | `{ module_handle, pad, info_inout }`, gate `size == 0x160` | `-1` for handles `0x13`, `0x14`, `0x15` and gates `0x100`/`0x160`/`0x200`; the gate word is left as written, so nothing was copied out |
| 662 | `{ ids, count, results }`, count 1..128 | **alive**: `ret=0` and a per-item status `0x80020003` |
| 663 | `{ ids, count, states, wait_mode, timeout_inout }` | **alive**: `ret=0`, status `0x80020003` |
| 664 | `{ ids, count, states }` | **alive**: `ret=0`, status `0x80020003` |
| 533 | `{ unused_slot_0, size, flags }` | `-1` for sizes `0x4000`/`0x10000` and flags `0`..`3` |
| 548 | `{ descriptor, flags, user_operations, count, user_processed }` | `-1` with descriptor `0`; the anon page in 236a did not map, so only that one call is recorded |
| 657 | `{ commands, count, processed, flags }` | `-1`, `processed=0` with object `0` |

Two results change earlier conclusions.

**The AIO batch entries are not lethal and not absent.** 662, 663 and 664 return
`0` and write one status per id. Eleven id encodings were tried - `0`, the two
module handles, the handles with slot indices 0-3 in the high 16 bits, and slot
indices alone - and a two-id call; every one produced `0x80020003`. The entries
therefore validate the id namespace rather than the arguments, and every earlier
six-zero sweep at 661-670 was refused by the `count` check (contract: 1..128)
before it reached one of these. Capture:
`results/phase17_new_vectors/237a_aio_ids_and_protection_20261021_210533.txt`.

**W^X is now confirmed by read-back, not by a return value.** 547 reports the
region record for an address, so the protection of a page can be read before
and after a call. `mprotect(page, 0x4000, 7)`, `(…, 5)` and `(…, 4)` each return
`-1` and leave the record byte-identical (`prot=0x33`), while the page stays
writable. The earlier wording - "mprotect(EXEC) always fails" - was measured by
the return value alone; this is the first measurement of what the page looks
like afterwards. Capture:
`results/phase17_new_vectors/237b_mprotect_oracle_20261021_210838.txt`.

660 is closed for this process. 659 hands out handles `0x13` and `0x14`; 660 refuses
those, refuses `0`, refuses the address of a mapped page, refuses `page+0x28`, and
refuses the **38 module handles** that 592 (`dynlib_get_list`, `ret=0 count=0x27`)
hands out, with the size gate set to `0x160` at `+0x00` and at `+0x10`. In every
case the gate word is left as written, so no copyout happens at all - the handle is
rejected before the record is built. Capture:
`results/phase17_new_vectors/240a_660_module_handles_20261021_211236.txt`.

The id namespace of 662/663/664 is not reachable by brute force either: 512
encodings - slot `0..255` with handle `0x13`, then handle `0..255` alone - produce
one outcome, `ret=0` with `0x80020003`. Captures:
`results/phase17_new_vectors/239a_aio_id_slots_20261021_211151.txt`.

**Correction (2026-10-22): the ids come from 669, and 669 does not kill.** The
sentence that stood here - "whatever an id names is created by 661, and 661 kills
on touch" - was wrong. There are two submit entries, not one. `669(cmd, reqs,
count, class, ids)` takes a batch of descriptors (stride `0x28`: offset, count,
pointer, result pointer, fd), returns `0`, and writes real ids into `ids`;
`cmd=1` reads, `cmd=2` writes, and the completion writes the byte count into the
result pointer. 24 requests completed in one process. See
`docs/AIO_BATCH_14_10.md` and probes 352a-352k.

548 and 657 stay closed: 238a swept the first argument over `0..31` and the page
address and every call returned `-1` with `processed=0` and the region record
unchanged. Capture:
`results/phase17_new_vectors/238a_548_657_first_arg_20261021_211117.txt`.

## The AIO batch entry works, and the GPU pool zeroes its pages (probes 346a-352k, 2026-10-22)

Two measured corrections and one positive result.

**669 is a working batch submit.** `669(cmd, reqs, count 1..128, class 1..3, ids)`
with descriptors at stride `0x28` (`+0` offset, `+8` byte count, `+0x10` pointer,
`+0x18` result pointer, `+0x20` fd). `cmd=1` reads and `cmd=2` writes; 3 and above
are refused at the entry. A completed request is `state=0x3` from 664, and the
result word carries the bytes moved (`0x10` for a 16-byte read of `/dev/urandom`,
with different data on every read). Identifiers are slot-tagged with a generation
in the high word, so a deleted id does not address the next request. 24 requests
were outstanding at once without a refusal, and deleting four freed those slots
for the next four.

The refusal path is subtle: **669 returns `0` whether or not it queued anything**,
and a spent queue answers `0x80020005` in the result word only. Any measurement
that reads the return value alone will call a refused request a success.

**The destination is range-checked.** `data = 0x1000` (unmapped) and
`data = 0xFFFF8000_00000000` (kernel half) both come back `0x8002000E` (EFAULT),
each followed by a control that completes normally, so the check is a user-range
test rather than a page walk. A kernel-half result pointer is likewise not
written. **The byte count is not clamped to the buffer**, though: `count =
0x14000` into a 4 KiB destination writes the whole count through the process
heap and kills the loader. That is self-corruption, not a boundary break.

**The GPU pool zeroes on allocation.** A fresh process maps 6 × 64 MiB = 384 MiB
and the seventh is refused, and mappings are never returned within a process. A
dense scan of one complete 64 MiB chunk every 8 bytes - 8 388 608 qwords - found
**zero** nonzero qwords, and a 49 152-sample sweep across all 384 MiB found zero
kernel-shaped words and zero strings (348a, 137.7 s). The uninitialised-page
KASLR leak is dead on 14.10.

**637's store is inert.** Mapping three chunks, calling `637(0, 0xFFFFFFFF)` and
then mapping again reaches the same ceiling of six chunks (346b: 3 before, 3
after). Earlier readings that attributed a ceiling change to the store were
explained by the pool already being consumed in that process.

**osem's slot order is not the dossier's.** On 14.10 `549` is
`(name, attributes, initial, maximum)`; the 13.60 dossier has the name last, and
every earlier call passed a NULL or bad pointer in slot 0. With the order fixed
the family works: 555 post, 554 poll (second poll `-1`), 556 cancel, 553 wait with
an expiring timeout that writes the remaining budget back through the pointer, 551
opens a shared name as a second handle, 550 deletes and 552 closes.

## The "-1" population, called with real pointers (probes 334a-342a, 2026-10-22)

A `-1` from six zero arguments says the handler rejected that call, not that it
is absent. Thirty-five of those rows were called with six shapes - zeros, a
zeroed 4 KiB page in each of slots 0, 1 and 2, and two mixed shapes - and six
of them answered. Full write-up in [OBJECT_FAMILIES_14_10.md](OBJECT_FAMILIES_14_10.md).

| syscall | name | six zeros | real pointer |
|---|---|---|---|
| 538 | `evf_create` | `-1` | handle, `16901` for the first one in a process |
| 540 | registry lookup | `-1` | handle for a registered name, `-1` for an unregistered one |
| 557 | `namedobj_create` | `-1` | handle |
| 598 | `dynlib_get_proc_param` | `-1` | `0`, `0x60` at `+0` |
| 659 | `dynlib_get_list2` | `-1` | `0`, `3` at `+0` and `0x14` at `+8` |
| 637 | `set_phys_fmem_limit` | `-1` | `0` above current usage, blocks below it |
| 572 | `virtual_query` | `-1` | `0` |

637 is the only one of them that writes. With target id 0 the capability helper
that gates 618, 646 and 671 is skipped and the caller's 64-bit value is stored at
`parent+0x200 -> child+0x280` under `child+0x278`; ids 1, 2 and 5 are refused, so
the exemption is for the caller's own process. The offset is fixed and its
meaning is unknown, and no path was found that reads it back or moves it.

The evf family (544 set, 545 clear, 546 cancel) accepts a handle the process
created, rejects every value it was never given, and refuses deletion (`541`
returns `-1`). `543 poll` refused both mode values tried. Named objects
registered with attribute `0x100` resolve in-process but **not** after a
relaunch, so the registry does not hand one process a handle to another
process's object.

## Sys 532: the largest Sony handler, called for the first time (probes 305a-309a, 2026-10-22)

`results/kernel_handlers/analysis/sys_532_deep.md` describes the biggest
Prospero handler in the 13.60 capture: a 0x4000-byte dispatch over ~70 commands,
a user-controlled size, a 0x818-byte stack buffer, and seven candidate defects.
`probes/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv.lua` was written for
it on 18 October and **never executed** - no capture exists - so every earlier
statement about 532 rested on the decompile alone. It has now run.

The entry is real: 532 dispatches, and it answers with Sony status codes rather
than `-1` for the commands that skip the privilege check.

| command | measured on 14.10 | meaning |
|---|---|---|
| `0x00`, `0x03`, `0x05`, `0x10`, `0x2C`, `0x31`, `0x36`, `0x41`, `0x45` | `-1`, buffer untouched | privilege check refused |
| `0x18`-`0x1D` | `ret=0`, `out[0] = 0x800D0204` | handle checksum rejected |
| `0x1E` | `ret=0`, `out[0] = 3` | handleless status, constant across every sub |
| `0x20`, size `0x30` | `ret=0`, `out[0] = 0x800D0219` | SANDBOXED at the one size it accepts |
| `0x20`, every other size | `ret=0`, `out[0] = 0x800D0208` | exactly `0x30` bytes, not a range |
| `0x2F` | `ret=0`, `out[0] = 0` | handleless no-op |

**The size gate is at `0x800`.** `0x18` with sizes `0` through `0x800` returns
the handle error; `0x801` and above return `0x800D0208` (INVALID_SIZE) instead.
That matches the decompiled `cmp rcx, 0x801`.

**The handle integrity check is forgeable.** The dossier's formula -
`byte[3] + byte[0] + byte[1] + byte[2] + byte[5]*byte[4]` in the low 16 bits,
compared against bytes `[6:7]`, with `byte[4] xor 0x6b` as the type index - was
implemented as written and the handler moved from `0x800D0204` to `0x800D0203`
for every type `0` through `0xC`, with a zero checksum and with nonzero ones.
A check every caller must satisfy, whose entire input the caller controls, was
satisfied from user space in one probe. What it stops is corruption, not a
caller who reads the decompile.

That is where the surface stops. `0x800D0203` is the type/table lookup, and the
registration table it indexes is empty for a game process - the same wall as the
device index on 622 (305a, 306a: twenty ungated commands, one status dword each,
`0xFFFFFFFF` or `0x8002004E`, unchanged by every index `0`-`15`) and the device
context on `0x400`. Nothing here leaks a pointer, copies an unexpected length, or
writes outside the caller's buffer.

Probes `87a`, `305a`, `306a`, `307a`, `308a`, `309a` and their captures are in
this commit. `308a` is the one that matters: without it the handle path looks
closed, and with it the boundary moves to the registration table.
