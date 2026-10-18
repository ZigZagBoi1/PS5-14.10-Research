# Detailed Technical Findings — PS5 14.10

## Finding 1: W^X + Execute-Only Memory (XOM)

**Probes:** 26, 26b, 26c, 26d, 26e

The PS5 enforces write-XOR-execute strictly:
- `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` → grants `RW` only (EXEC stripped)
- `mprotect(PROT_EXEC)` → always fails with -1
- Code pages are **execute-only**: attempting to read from the code segment causes SIGBUS
- The crash handler at address `0x533118f4` handles SIGILL/SIGBUS/SIGSEGV; output starts with `77` followed by binary data

**Impact:** No ROP/JOP gadget scanning from userland. No code injection. Must find kernel R/W through data-only paths.

---

## Finding 2: Threading Completely Blocked

**Probe:** 27

All threading primitives return -1:
- `fork()` — blocked
- `rfork()` — blocked  
- `thr_new()` — blocked

**Impact:** No race conditions possible. Eliminates TOCTOU, UAF-via-race, refcount race classes entirely.

---

## Finding 3: sigaltstack Kernel Write is Dead

**Probes:** 22, 23, 24, 25, 25b

The classic sigaltstack trick (set altstack to kernel address → signal delivery writes sigframe there) fails because:
- `copyout()` validates the destination address during signal frame delivery
- Writing to a kernel address triggers EFAULT
- The kernel then kills the process

`sigprocmask` is also a no-op — returns 0 but the signal mask is never modified.

---

## Finding 4: F_SETFL is Cosmetic Only

**Probes:** 30b, 30c, 33a–33c

`fcntl(F_SETFL, O_NONBLOCK)` returns -1 but **updates the visible flags word** (F_GETFL shows the change). However the kernel **does not honor the flags**:
- O_NONBLOCK has no effect on actual read/write behavior
- O_APPEND flag also set but not honored  
- O_ASYNC flag also set but not honored
- Each F_SETFL call REPLACES the flags word (not bitwise OR)

The sandbox intercepts F_SETFL, rejects it (returns -1), but patches the userland-visible flags struct field. The actual kernel I/O path checks a separate internal socket state.

`F_SETOWN` is truly blocked — returns -1 AND the value is not applied (F_GETOWN stays -1). No SIGIO possible.

---

## Finding 5: MSG_DONTWAIT is the Real Nonblocking Mechanism

**Probes:** 33d, 33e, 33f

Since F_SETFL O_NONBLOCK is fake, nonblocking I/O must use per-call flags:
- `sendmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`
- `recvmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`

Confirmed behavior:
- `recv(empty socket)` → returns -1 immediately (EAGAIN)
- `send(full buffer)` → returns -1 immediately (EAGAIN)
- SNDBUF=1 partial writes work correctly (request 4 bytes → rv=1)
- 100x rapid send/recv cycling: 100/100 success
- Both buffers=1, 50x cycling: 50/50 success

**CRITICAL:** `sendto` (syscall 133) and `recvfrom` (syscall 29) **crash the Lua loader** when registered in `syscall.resolve()`. Use only `sendmsg`/`recvmsg`.

---

## Finding 6: SCM_RIGHTS fd Passing Works Correctly

**Probes:** 28, 30b

Unix domain socket credential passing via SCM_RIGHTS is fully functional:
- Can pass 16+ file descriptors in a single message
- 5x send/recv cycle: all 5 correct (refcounts accurate)
- No refcount leak or double-free observed
- Passed fds are usable (can read/write/close)

---

## Finding 7: RAW Socket + IP_HDRINCL = Kernel Packet Injection

**Probe:** 34

This is the **most significant finding** for exploit development:
- `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` succeeds → fd allocated
- `setsockopt(IP_HDRINCL)` → rv=0 (reads back as 8 = INP_HDRINCL)
- `sendmsg()` with crafted IP+UDP packet to 127.0.0.1 → **packet reaches UDP listener**
- Confirmed: `BEEFCAFE` payload data arrived intact
- RAW socket `bind()` and `connect()` to loopback both work

TCP SYN packet was dropped — likely due to invalid TCP checksum (sent 0). TCP requires valid checksums even on loopback.

**Impact:** We can inject arbitrary IP packets into the kernel's `ip_input()` path. This opens:
- IP fragment reassembly (`ip_reass()`)
- IP options parsing (`ip_dooptions()`)
- Protocol demultiplexing
- ICMP input processing
- Any protocol handler reachable via loopback

---

## Finding 8: Fragment Reassembly — Inconclusive (Bind Issue)

**Probes:** 35, 35b

All fragment reassembly tests returned no data. However, probe 35b revealed the root cause: **`bind()` was returning -1** for the UDP listener port. Without a valid listener, no packets can be received regardless of reassembly.

The bind failure may be due to:
- Port range restrictions on the PS5
- Socket/fd limit reached
- Specific port number filtering

**Status:** Needs re-testing with verified bind success before concluding anything about fragment reassembly.

---

## Finding 9: PS5 Custom Socket Options are Benign

**Probe:** 31c

Five Sony-extended SOL_SOCKET options exist:
```
0x2000, 0x10000, 0x20000, 0x40000, 0x100000
```

All are **boolean flag bits** in the socket's `so_options` field. The option number IS the bitmask value:
- `setsockopt(SO_0x2000, 1)` → readback = 0x2000
- Same behavior on all socket types (UNIX, TCP, RAW, IPv6 RAW)
- No complex parsing, no buffer handling, no kernel pointer exposure

**Not exploitable.**

---

## Finding 10: poll() is Fully Functional

**Probe:** 32c

`poll()` works with correct BSD semantics:
- `nfds=0` → rv=0 (immediate return)
- Invalid fd → POLLNVAL (0x0020)
- `fd=-1` → ignored (standard behavior)
- Closed peer → POLLIN|POLLHUP (0x0051)
- `read(closed peer)` → rv=0 (EOF)
- Mixed fd array → correct per-fd results

---

## Finding 11: TCP_INFO Contains No Kernel Pointers

**Probe:** 31b

The 236-byte TCP_INFO structure was fully dumped and scanned:
- Contains only protocol metadata: timestamps, RTT values, window sizes, congestion state
- Connected vs unconnected socket comparison shows expected field changes
- **No kernel addresses leaked** — all pointer-sized values are protocol counters or timestamps

---

## Finding 12: Memory Layout

**Probe:** 03

Key addresses observed:
- Signal handler (crash): `0x533118f4`
- Code segment is execute-only (cannot read)
- Heap is RW, stack is RW
- `MAP_FIXED` works for page-aligned addresses in userland range

---

## Finding 13: AIO Outcomes Are Not Uniformly Established

**Probes:** 19, 19b–19g, 43p; focused retest 53a prepared, not run.

Older probe summaries describe AIO calls as blocked or as causing the loader to exit, but those summaries do not establish a common kernel-level termination for every call. The raw `19g` record shows `aio_error` returning `rv=-1`. The saved `43p` output ends immediately before its first raw AIO call result, so it supplies no result or kill record for the `make_syscall()` path. It also does not reach the planned Sony syscall scan or test syscall 663.

**Conclusion:** Exact behavior remains scoped to each logged call, argument set, and invocation path. Do not describe the AIO family as completely sandbox-killed or infer a kernel kill from a missing output tail. Retest 53a is prepared to capture per-call outcomes; it has not been run.

---

## Finding 14: kqueue Allocates but kevent is Dead

**Probes:** 20, 21

- `kqueue()` → returns a valid fd
- `kevent()` → always returns -1 regardless of changelist content
- The fd is usable for close() but nothing else

---

## Finding 15: writev with IOV_MAX Boundary

**Probe:** 30b

- `writev` with 16 iovecs of 64 bytes each (1024 total) → rv=1024 ✓
- `writev` with 1024 iovecs of 1 byte each (1024 total) → rv=1024 ✓
- `writev` with 1025 iovecs → rejected (IOV_MAX=1024)

No buffer overflow at the IOV_MAX boundary. Kernel handles correctly.

---

## Finding 16: Port Bind Policy (probe 36, live)

- Ports **<1024 blocked** (rv=-1), ports **≥40000 blocked**
- Ports 1024–32767 work: 1024, 5000, 8080, 9027, 31337–31340 all bind (UDP+TCP)
- TCP 9026 fails (loader owns it); UDP 9026 binds (different protocol slot)
- INADDR_ANY binds fine; SO_REUSEADDR double-bind correctly rejected
- **This solves the 35/35b mystery:** nothing was wrong with bind on good ports; the earlier failure was port-selection-related

---

## Finding 17: ip_reass() Handles All Standard Cases Correctly (probe 39, live)

With a working listener on 31338, all fragment cases reassemble correctly:
- baseline 2-frag, out-of-order, overlap (-8B), tiny-first (8B), dup-final-overwrite, 9×8B chain — **all delivered with correct data**
- First-fragment-wins on overlap (BSD semantics preserved)
- proto=47 fragments correctly not delivered to UDP listener
- **No crash, no corruption.** Basic ip_reass attack surface is well-behaved; deeper fuzzing (timeout expiry, reassembly queue limits, 64+ fragment chains) still untested.

---

## Finding 18: ip_dooptions() Processes Options but Drops Routed Ones (probe 37, live)

- Well-formed RR/TS/NOP: sent and delivered
- Malformed option lengths (len=0, oversized, truncated): **rejected at send time** (rv=-1) — `ip_output()` validates before `ip_dooptions()` ever runs on loopback. The classic length-confusion cases never reach the parser this way.
- **LSRR, SSRR, TS-overflow-flag: send OK but NOT delivered** — kernel processes the option and drops/redirects the packet. Source routing is disabled, as expected, but this confirms option-processing code runs.
- To reach input-side `ip_dooptions()` with malformed lengths, packets must arrive from the **real network** (PC-side scapy), not loopback injection — output-path validation is the gatekeeper.

---

## Finding 19: Crash Record = ASLR Oracle (probes 41m/41o, live)

The crash handler (magic `0x13371337`) emits a ~280-byte binary record on SIGSEGV:
- `+0x08`: signal number (0x0b = SIGSEGV)
- `+0x28`: fault address (si_addr)
- `+0x20/+0x40/+0x58/+0x60/+0x80/+0xD0`: heap pointers (Lua state registers)
- `+0xB8/+0xF8/+0x100`: **code pointers into the main module**
- Code base shifted 0x2393xxxx → 0x2558xxxx between runs: **per-process ASLR, but the delta is consistent across all code pointers** — one crash leaks the module base.
- Heap base `0x3_10000000` region is stable across sessions; only the top frontier moves.

**Strategic value:** any future PC-control primitive (fake vtable etc.) needs gadget addresses. The crash record hands you the module base every time; gadgets can be resolved offline from a dumped copy of the same binary (Relapse can dump on ≤13.60).

---

## Finding 20: The 0x1A3A4EE0 "vtable" is a Session Artifact (probes 41m–41q, live)

- `0x1A3A4EE0` as a raw address is **unmapped** (SIGSEGV, si_addr confirmed 0x1A3A4E00)
- Full scans of the entire mapped heap `[0x310000000, 0x310DC0000)` plus 4 MB anchor-relative windows: **zero objects with dword 0x1A3A4EE0 exist** in fresh sessions
- The 41i/41k/41l "objects with vtable header" were artifacts of that session's heap spray (41j AFAF spray) — not naturally occurring loader objects
- **Do not chase this value without recreating the 41j spray conditions first**

---

## Finding 21: New Syscall Map (probes 38/42a/42b, live)

**Newly confirmed working:**
- `ktimer_create` (clock 0=REALTIME, 4=MONOTONIC), `ktimer_settime`, `ktimer_getoverrun` — **partially open POSIX timer surface**
- `getsockname` — works
- `accept4`, `preadv`, `pwritev`, `copy_file_range` — resolve and error correctly on bad fds (untested on real fds; no usable file fd exists since memfd is stubbed)

**Newly confirmed blocked/stubbed:**
- `ktimer_gettime`, `ktimer_delete` — blocked even on valid ids (inconsistent with settime being open — odd split)
- `getrandom` — blocked
- `ppoll` — blocked
- `cap_rights_limit/get` — blocked
- `memfd_create` — stub, returns fake fd=1
- itimerspec validation is CORRECT (nsec>1e9, negative, huge sec all rejected)
- Timer cap: 27 concurrent timers

**Newly confirmed DEADLY (instant process kill, no crash record):**
- `minherit` — kills on first call (this was the probe-29/30 killer)
- `msync` — kills on first call (the second probe-30 killer, isolated in 42b)

---

## Finding 22: Loader Session Model (live observations)

- pid increments across connections (451→458→472→493→500): the loader respawns a fresh process per TCP connection, **fresh ASLR each probe**
- Heap anchors shift per session (0x310878000, 0x310bdcfc0, 0x310e05520…) — all heap scanning must be **anchor-relative**, never hardcoded
- The mapped heap top ends in a guard page (fault at exactly page-aligned 0x310DC0000); scanning UP into the guard kills the process. Scan DOWN from a known-mapped address, or keep progress output flowing to survive the 30s socket timeout.

---

## Finding 23: Early ROP-Chain Interpretation (superseded by probe 45c)

Probes 41v/41z found ROP-shaped metadata in the Lua loader's heap, including writable `fn_addr` and argument slots. At the time, the metadata was mistaken for the active syscall path.

Probe 45c later showed that `make_syscall()` continues to work when `fn_addr` points to NOP, `ud2`, null, or unmapped memory, and when the recorded chain is corrupted. The chain is not an established execution path; the claimed arbitrary-function call and stack-pivot primitives are not confirmed.

---

## Finding 24: Direct Memory Physical Addressing Constraints

**Probes:** 15, 18, 42d, 42f, 42f2, 42g–42g4

- `/dev/dmem0` opens reliably at `fd=22` (or `fd=24`).
- Direct physical mmap survey across 90+ physical offsets revealed:
  - **Offset 0x00000000:** Consistently returns `0x80000000_C0012800` (GPU hardware status/control register).
  - **Offsets > 0x0 up to 4GB:** Return all zeros or fail.
  - **Offsets ≥ 4GB (DRAM range):** Return zeros or fail (`0xFFFFFFFFFFFFFFFF`).
- **Conclusion:** `/dev/dmem0` is an interface to the GPU's dedicated GDDR6 memory aperture, not system CPU DRAM. It cannot be used to read or modify kernel page tables or kernel data structures directly.

---

## Finding 25: FreeBSD sysarch AMD64 Architecture & Segments

**Probes:** 42b, 42c, 43c

- Standard FreeBSD `<machine/sysarch.h>` defines:
  - `AMD64_GET_FSBASE = 128`
  - `AMD64_SET_FSBASE = 129`
  - `AMD64_GET_GSBASE = 130`
  - `AMD64_SET_GSBASE = 131`
- `sysarch(128)` confirms `FSBASE` holds the userland Thread Control Block (TCB) at `0x88xxxxxxxx`. Scanning the TCB reveals only userland TLS thread pointers.
- Calling `sysarch(129)` with a zero buffer overwrites `FSBASE` to 0, which immediately crashes userland libc.
- `AMD64_GET_GSBASE (130)` queries `%gs:0`, which in FreeBSD points directly to the kernel's `curthread` structure.

---

## Finding 26: Sysctl Tree Traversal and False-Positive Sentinels

**Probes:** 42b, 42c, 42e, 42h2

- Dense memory dumps from `kinfo_proc` (+0x060) and `fstat` (+0x068) frequently show `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF`. These are **sentinel values / bitmasks** (`-1`, `0xFFFFFFFF`), NOT kernel pointers. Real kernel pointers are in the canonical higher half `0xFFFF8xxx_xxxxxxxx`.
- Walking the sysctl MIB tree (`42e`) via `sysctl.name2oid` / MIB exploration shows that Sony's kernel rejects non-leaf MIB queries or returns size 0.
- Live readable leaf MIBs: `kern.version`, `kern.ostype`, `kern.osrelease`, `hw.machine`, `hw.pagesize`, `kern.securelevel` (1024).

---

## Finding 27: Process-Termination Claims and Evidence Gaps

**Probes:** 19, 29, 30, 38, 42a, 42b, 42g2

Several old probe notes describe calls as instant kills, but a truncated socket capture alone cannot distinguish a kernel termination from a Lua failure, connection loss, or capture truncation. The AIO and kenv claims in particular were too broad: 43p ends before its first AIO result, 19g records `aio_error` returning `-1`, and the 42a/42g2 logs stop at the kenv header.
1. `minherit` (syscall 250) — process termination was observed in the cited runs.
2. `msync` (syscall 226) — process termination was observed in probe 42b.
3. `kenv` (syscall 390) — unresolved: the 42a and 42g2 captures stop at the call header, with no result or kill record.
4. AIO-family outcomes vary across the available records; 19g records `aio_error rv=-1`, while 43p ends before its first AIO result. Do not label all `aio_*` calls as kills. The raw 14.10 AIO retest is pending (53a).
5. Reading Execute-Only Memory (XOM) system lib `.text` sections — unrecoverable userland faults were observed in the cited probes.

---

## Finding 28: sceKernelMtypeprotect (Syscall 585) Returns Success

**Probes:** 42f

Sony's `sceKernelMtypeprotect` (syscall 585) returned `ret=1` — a positive value indicating success with a status code — while all neighboring Sony syscalls (576, 580, 581, 586, 616, 619) returned -1. This syscall changes memory type protections on PS5 and may bypass the standard W^X enforcement that blocks `mprotect(EXEC)`. If `mtype_protect` operates on a different protection domain (GPU memory types, SPU pages), it could grant execute permissions that `mprotect` cannot.

**Impact:** Potential W^X bypass. Probe 43h and 43k test this with actual mmap'd pages and various protection arguments. If RWX can be achieved, arbitrary code execution without ROP becomes possible.

---

## Finding 29: sceKernelGetCpuUsage (Syscall 617) Is Live

**Probes:** 42f

`sceKernelGetCpuUsage` (syscall 617) returned `ret=0` with an empty 8-byte buffer. This is the only other Sony-specific syscall besides 585 that succeeded. PS5 has 16 logical cores (Zen 2 8C/16T), and CPU usage data structures in the kernel typically contain per-CPU scheduler data, thread lists, and pointers to kernel structures. A larger output buffer or per-CPU index argument may reveal kernel addresses.

**Impact:** Potential kernel info leak. Probe 43k tests with various buffer sizes and argument patterns.

---

## Finding 30: kern.msgbuf Returns Data (Partial Read)

**Probes:** 42b

`sysctl kern.msgbuf` (MIB {1, 33}) returned 8 bytes with value `0x7EF710000`. The kernel message buffer (`dmesg`) is typically 32-256KB and contains boot messages including kernel module load addresses, memory layout, driver init data, and KASLR base. The 8-byte value `0x7EF710000` (~34 GB range) could be a direct-map physical address or a pointer to the message buffer region. A full-size read could capture the entire dmesg output with KASLR-defeating addresses.

**Impact:** Most promising KASLR defeat vector. Probe 43j reads the full buffer (up to 64KB) and scans for kernel pointers.

---

## Finding 31: mincore() Works as Memory Residency Oracle

**Probes:** 42i

`mincore()` (syscall 78) returned `ret=0` with `vec=0x1F` (5 consecutive pages resident). This syscall reports whether virtual address pages are backed by physical memory. It can be used as a side-channel oracle: probing page residency at guessed kernel virtual addresses may detect the kernel base without a direct pointer leak (cache-based KASLR defeat). Even if kernel VA probing fails, it maps the full process VA space layout.

**Impact:** Side-channel KASLR oracle. Probe 43l tests kernel VA range probing and process VA space mapping.

---

## Finding 32: PS5 Socket Options Accept Oversized Buffers

**Probes:** 31c

Five PS5-specific socket options (0x2000, 0x10000, 0x20000, 0x40000, 0x100000) all accept `setsockopt(len=256)` with `rv=0`. These are boolean flags (4 bytes) but the kernel accepted 256-byte writes on UDP, TCP, and RAW sockets. If the kernel copies the full user buffer length into a smaller kernel struct field, this is a kernel heap overflow — writing 256 bytes into a 4-byte field would corrupt adjacent kernel heap objects.

**Impact:** Potential kernel heap corruption primitive. Probe 43m tests with progressively larger buffers (up to 4KB) and checks getsockopt return length for over-read indicators.

---

## Finding 33: /dev/hid Opens Successfully

**Probes:** 42c

`/dev/hid` (the HID/Human Interface Device driver) opens with `fd=24`. While ioctl was "blocked" via `syscall.resolve()`, it is untested via `make_syscall(54)`. The HID driver manages PS5 controller/gamepad input and exposes device descriptors, report buffers, and internal state through ioctls. If ioctl works via make_syscall, we gain access to HID kernel state which may contain kernel addresses.

**Impact:** Potential kernel info leak or write primitive via HID ioctls. Probe 43n tests ioctl(54) via make_syscall with standard HID and USB ioctl codes.

---

## Finding 34: thr_self Returns Real Thread ID

**Probes:** 42j

`thr_self()` succeeded with `ret=0`, returning `tid=101819`. While this is not directly a kernel pointer, the thread ID is a handle into kernel thread structures. Combined with other primitives, the TID could be used to locate the `struct thread` in kernel memory (e.g., via `kern.proc.pid` if it leaks `ki_tdaddr`).

**Impact:** Building block for kernel exploitation. The TID value is consistent and identifies the kernel thread object.

---

## Finding 35: fn_addr Encoding Pattern (0x9FE5 Prefix)

**Probes:** 42f, 42g, 42h, 42i, 42j

All fn_addr values across different PIDs share a constant `0x9FE5` upper 16-bit prefix with ASLR-varying middle bits and `0130` suffix:
- PID 582: `0x9FE510A60130`
- PID 610: `0x9FE511078130`
- PID 645: `0x9FE510DF0130`

The `0x9FE5` constant survives ASLR and may encode a non-randomized memory region, a GPU command buffer prefix, or an instruction encoding (`E5 9F` = `IN EAX, 0x9F` on x86-64). Understanding this encoding is key to reliable fn_addr manipulation across connections.

**Impact:** Reliable ROP chain targeting. The constant prefix means fn_addr has only ~32 bits of entropy rather than 48.

---

## Finding 36: AF_ROUTE Request Delivery Was Not Established (probe 43o)

**Probes:** 43o

- `socket(PF_ROUTE=17, SOCK_RAW, 0)` succeeds → `fd=22`
- `RTM_GET` for the default route (0.0.0.0): the write returns -1, so the request was not delivered
- The 108-byte read is an echo of the probe's own request; its sockaddr begins at `+0x5C`, matching the constructed 92-byte header
- Writes for the other tested destinations also fail
- Passive listen returns the same 108-byte echo
- sysctl `NET_RT_DUMP` and `NET_RT_IFLIST` fallbacks also produced no kernel pointers

**Conclusion:** The AF_ROUTE leak was not validly tested. The failed writes and echoed request cannot establish either a leak or a 14.10 patch. A corrected retest is prepared as 53b and remains unrun.

---

## Finding 37: Raw AIO Result Is Unresolved (probe 43p)

**Probe:** 43p

- The saved output shows the sysctl canary succeeded, then prints that `aio_error` syscall 317 is about to be called.
- The file ends before any result, error, or post-call canary is printed.
- The planned later Sony syscall scan, including syscall 663, therefore has no result in the saved run.

**Conclusion:** The saved log is incomplete and does not establish the outcome of syscall 317 or the state of Sony syscall 663 on 14.10. Treat both as untested by this artifact; see [the secondary exploit audit](SECONDARY_EXPLOIT_AUDIT_13.60.md).

---

## Finding 38: kldstat/kldsym Results Are Missing (probes 43a, 43b)

**Probes:** 43a, 43b

- The 43a log is 145 bytes and contains only a header
- The 43b log is 116 bytes and contains only a header
- Neither log contains a syscall result, error, or kill record

**Conclusion:** The outcomes and cause of truncation are unknown. KLD introspection has not been established as blocked or successful. Retest 53c is prepared and remains unrun.

---

## Finding 39: `fn_addr` and ROP-Field Writes Are Inert (probes 43i, 45c)

Probe 43i confirmed that writes to `fn_addr` and slot 0 persist in heap memory. Persistence alone did not show those fields control execution. Probe 45c then changed those fields to invalid targets, corrupted the chain, and observed normal syscall results with no crash.

**Conclusion:** These are writable metadata fields, not an arbitrary function-call primitive. Do not use them as a kernel read/write path.

---

## Finding 40: fstat Works via make_syscall, ioctl/dup Still Blocked (probe 43e)

**Probes:** 43e

- `fstat` (syscall 189) via make_syscall → **works** on fd 0, 3, 4, 5. Returns full stat structs.
  - `+0x68` contains `0xFFFFFFFF_FFFFFFFF` — sentinel, not kernel pointer
  - Different inode numbers per fd (0x2A, 0x18, 0x63, 0x64)
  - All files show same timestamps and `st_blksize=0x4000` (16KB = PS5 page size)
- `ioctl` (syscall 54) via make_syscall → returns -1 for FIONREAD, TIOCGETA, SIOCGIFADDR
- `dup`/`dup2` (syscalls 41/90) → return -1
- `thr_new` (syscall 455) → crashed the process (garbled output = crash record)

**Conclusion:** fstat works but leaks no kernel pointers. ioctl is kernel-blocked even via make_syscall. Threading remains completely blocked.

---

## Finding 41: GS Base is Zero, FS Base is Userland (probe 43c)

**Probes:** 43c

- `sysarch(GET_FSBASE=128)` → `0x8817C8080` (userland TCB, expected)
- `sysarch(GET_GSBASE=130)` → `0x0` (zero — no kernel `curthread` pointer leaked)
- `sysarch(GET_XFPUSTATE=132)` → `ret=0`

**Conclusion:** GS base does not contain a kernel pointer on PS5. This is likely because `%gs` is not used for `curthread` in the PS5 kernel variant, or Sony zeroed it in userland context.

---

## Finding 42: Sysctl Write Paths All Blocked (probe 43f)

**Probes:** 43f

- `kern.securelevel` write(-1) → ret=-1
- `kern.coredump` read/write → ret=-1
- `security.bsd.unprivileged_proc_debug` → ret=-1
- `kern.maxproc` → ret=-1
- `kern.somaxconn` → ret=0, val=1024 (readable but not writable)
- `tcp.mssdflt`, `kern.maxfiles` → ret=-1

**Conclusion:** All sysctl write paths are blocked. Cannot lower securelevel or enable coredumps.

---

## Finding 43: Sony Syscall 557 Returns Live Data (probe 43g)

**Probes:** 43g

- Sweep of syscalls 540-650 found **syscall 557 returns `ret=16901`** — a non-error positive value
- The process was killed shortly after (likely hit a kill-trigger syscall in the sweep)
- Syscall 620 also returned `ret=0` (alive but empty)
- All other swept syscalls returned -1

**Conclusion:** Syscall 557 is a live Sony-custom syscall returning meaningful data. Needs targeted investigation with proper arguments. The value 16901 (0x4205) could be a status code, count, or flags.

---

## Finding 44: mtypeprotect Returns 1 for All Protection Values Including RWX (probes 43h, 43k)

**Probes:** 43h, 43k

- `sceKernelMtypeprotect` (syscall 585) returns `ret=1` for all tested protection values:
  - PROT_READ|PROT_EXEC (RX): ret=1
  - PROT_READ|PROT_WRITE|PROT_EXEC (RWX): ret=1
  - PROT_EXEC only: ret=1
  - PROT_READ|PROT_WRITE (RW): ret=1
  - PROT_READ only: ret=1
- After calling mtypeprotect(RWX), the page is still readable and writable
- Standard `mprotect(RX)` still returns -1 on the same page
- Execution test was not performed (safety flag in probe)

**Conclusion:** mtypeprotect consistently returns 1 (success?) but does not appear to change `mprotect`-visible permissions. It may operate on a separate protection domain (GPU memory types) or its return value of 1 may indicate "not applicable" rather than success. Needs execution test to determine if EXEC permission was actually granted.

---

## Finding 45: kern.msgbuf Returns Only 8 Bytes (probe 43j)

**Probes:** 43j

- Size query returns 8 bytes (not the expected 32-256KB dmesg buffer)
- Content: `0x00 0x40 0xBE 0xEF 0x07 0x00 0x00 0x00` — looks like a truncated header or sentinel
- `kern.features` returns `00000000-0000-0000-0000-000000000000` (null UUID)
- `kern.boottime` readable: `0x6AD29A84` (Unix timestamp) + microseconds
- `kern.proc.auxv` blocked (ret=-1)

**Conclusion:** kern.msgbuf is heavily filtered — returns a minimal 8-byte stub instead of the full dmesg. No kernel pointers available through this path.

---

## Finding 46: mincore Cannot Probe Kernel VA Space (probe 43l)

**Probes:** 43l

- mincore works correctly on userland mappings (eboot, GPU mmap)
- Returns `vec=[0x0B, 0x0B, 0x0B, 0x09]` for eboot text pages
- **All kernel VA probes return -1**: KERNBASE (0xFFFF8000_*), DMAP (0xFFFFF800_*), high kernel (0xFFFFFF80_*)
- Unmapped userland addresses correctly return -1
- Interesting: address `0x800000000` (32GB) returns ret=0, vec=0x00 (mapped but not resident)

**Conclusion:** mincore validates that the address is in the current process's VA space. Kernel addresses are rejected. No KASLR oracle via mincore.

---

## Finding 47: Socket Options Accept Large Buffers but Don't Overflow (probe 43m)

**Probes:** 43m

- `setsockopt` accepts buffers up to 4096 bytes for SO_SNDBUF (0x1001) and PS5 custom options
- `getsockopt` always returns the correct 4-byte value regardless of input size
- Same behavior on UDP, TCP, and RAW sockets
- Standard options (SO_KEEPALIVE, SO_DONTROUTE, etc.) also accept 256-byte buffers

**Conclusion:** The kernel likely clamps the copy length to the expected option size internally. No kernel heap overflow — the large accept is benign (kernel ignores excess bytes). Not exploitable.

---

## Finding 48: /dev/hid Open but ioctl Returns Sony Error (probe 43n)

**Probes:** 43n

- `/dev/hid` opens at fd=23
- `fstat(/dev/hid)` works — different inode (0x5A) from pipe fds
- All ioctl codes return `-2143617020` (`0x80740004`) — a Sony-specific error code meaning the operation is not supported for this device type
- FIONREAD returns 0 (no data available)
- `read()` returns 0
- `/dev/null`, `/dev/zero`, `/dev/urandom` all open successfully
- `/dev/console`, `/dev/tty`, `/dev/bpf`, `/dev/crypto`, `/dev/pf` all blocked

**Conclusion:** ioctl via make_syscall reaches the kernel (not sandbox-killed), but the HID device rejects all tested ioctl codes with a Sony error. The error code `0x80740004` appears device-specific. Other devices (/dev/bpf, /dev/crypto) remain blocked at open().

---

## Finding 49: CpuUsage Returns Empty Data, Syscall 620 Alive (probe 43k)

**Probes:** 43k

- `sceKernelGetCpuUsage` (617) with buffers from 8 to 4096 bytes: ret=0 but all-zero output
- Per-CPU queries (cpu 0-15): all ret=0, zero data
- Various argument patterns (null, 1, -1): all zero
- Syscall 620: ret=0 (another live Sony syscall, unknown function)
- Syscalls 615, 616, 618, 619: all ret=-1

**Conclusion:** CpuUsage returns success but no data — likely requires specific argument structures or calling conventions not yet discovered. Syscall 620 is alive but unknown.

---

## Finding 50: `mtypeprotect` Did Not Establish Native Code Execution (probes 44a, 45c)

Probe 44a interpreted successful returns from `mtypeprotect` and normal syscall results as proof that an RWX mapping executed. Probe 45c established that `make_syscall()` bypasses the ROP/`fn_addr` path entirely. The NOP, `ud2`, and redirected-target checks therefore provide no evidence that the test page ran.

**Conclusion:** W^X bypass and native code execution are unconfirmed. A return value of 1 from `mtypeprotect` is not proof that a page became executable or that instructions ran.

---

## Finding 51: Sony Syscall 557 is a Type/Status Query (probe 44b)

**Probes:** 44b

- Returns `0x4205` (16901) **only when arg1 is a valid buffer address**
- Returns -1 with no args, null args, or with arg1 as a small integer
- No data written to the output buffer (0 changed dwords)
- Neighboring syscalls 553-561 all return -1
- Value breakdown: byte 0 = 0x05 (flags?), byte 1 = 0x42 (type 66?)

**Conclusion:** Syscall 557 appears to be a process type/sandbox level query. The return value itself IS the data (not written to a buffer). The value 0x4205 likely encodes the process sandbox class. Not directly useful for KASLR but documents the sandbox state.

---

## Finding 52: Sockopt Heap Corruption Not Possible (probe 44c)

**Probes:** 44c

- Sprayed 40 sockets around target, wrote 4KB patterns to PS5 custom options
- No corruption detected on any adjacent socket at any buffer size (64-4096)
- SO_SNDBUF/SO_RCVBUF reject oversized buffers (ret=-1)
- getsockopt always returns exactly 4 bytes

**Conclusion:** The kernel's `sosetopt()` path clamps the copy to the option's expected size. The large `setsockopt()` acceptance is benign — excess bytes are ignored, not written to kernel heap. Confirmed not exploitable.

---

## Finding 53: Creative Sysctl Paths — NET_RT_IFLISTL Returns 6.5KB (probe 44d)

**Probes:** 44d

- **NET_RT_IFLIST** (MIB {4,17,0,0,3,0}): returns 1408 bytes, no kernel pointers
- **NET_RT_IFLISTL** (MIB {4,17,0,0,5,0}): returns **6536 bytes** of interface data, no kernel pointers
- **kern.usrstack**: returns `0x7EF5A8000` (userland stack top)
- **kern.proc.auxv**: returns only 4 bytes (truncated/filtered: `0x08008011`)
- **kern.proc.sigtramp**: returns 0
- Signal handlers: all at `0x511FD8F4` (userland crash handler address — another ASLR data point)
- Blocked: pathname, groups, rlimit, umask, osrel, cwd, ps_strings, hw.pagesizes

**Conclusion:** NET_RT_IFLISTL provides substantial network interface data but Sony scrubbed all kernel pointers from it. The signal handler address `0x511FD8F4` is consistent with eboot ASLR (confirms the crash handler offset). No KASLR defeat from these paths.

---

## Finding 54: Apparent Shellcode Execution (probe 45a; superseded by 45c)

Probe 45a recorded normal syscall returns and an `actual_len` buffer change and initially attributed them to shellcode. Probe 45c later showed that `make_syscall()` does not dispatch through `fn_addr` or the ROP chain. The 45a observations therefore do not establish that the shellcode ran.

---

## Finding 55: Shellcode Side Effects Were Not Demonstrated (probe 45b; superseded by 45c)

Probe 45b found no observable writes from the proposed shellcode path and noted that return values stayed equal to the process ID. Probe 45c resolved the ambiguity: ordinary `make_syscall()` calls bypass the ROP chain and `fn_addr`. Native shellcode execution remains unconfirmed.

---

## Finding 56: make_syscall() Bypasses ROP Chain Entirely — fn_addr Is Never Called (probe 45c) ★★★

**Probe:** 45c (execution reality check — patched to skip XO reads)

**DEFINITIVE RESULT: The ROP chain and fn_addr are NOT USED by make_syscall(). Syscalls go through a C-level wrapper.**

Evidence from four independent tests:

1. **Sysctl with NOP fn_addr (Section C):** Redirected fn_addr to a NOP+ret on our code page, then called sysctl(202). **Sysctl returned full 1096 bytes of valid kinfo_proc data.** If fn_addr were the syscall entry point, a NOP+ret cannot produce valid sysctl output. The chain does syscalls independently of fn_addr.

2. **Stub offset redirect (Section D):** Redirected fn_addr to fn_orig+0 through fn_orig+15 (mid-instruction offsets). **Every single offset returned pid=135.** Misaligned instruction entry would crash or return different values if the code were ever called.

3. **Crash tests (Sections H-J):**
   - `ud2` (guaranteed illegal instruction) at fn_addr → **NO CRASH, returned pid=135**
   - Unmapped address (`0xDEAD0000`) as fn_addr → **NO CRASH**
   - NULL (0x0) as fn_addr → **NO CRASH**
   If the chain called through fn_addr, ANY of these would SIGILL/SIGSEGV.

4. **ROP chain corruption (Section K):** Overwrote chain entries [0..7] with `0x41414141_41414141`. **getpid STILL returned 135.** The chain is not executed during make_syscall() calls.

**Additional structural findings:**
- fn_addr value `0x9FE5_11100130` does NOT match any loaded module's text range — it's in unmapped/unknown address space
- fn_addr is NOT in eboot (eboot text: `0x08CF4000`, size `0x494000`)
- The pipe string shows the chain structure but it's vestigial — decorative metadata, not an active code path

**What this means:**
- The "W^X defeat" from 44a was a **false positive** — mtypeprotect may change page permissions, but fn_addr never calls our code
- The fn_addr/slot0 "arbitrary function call primitive" from 43i is **dead** — writes persist but have no effect
- The entire ROP chain exploitation model (Tier 5 in STRATEGY.md) is **invalidated**
- `make_syscall().__call` likely invokes a C function in the Lua loader that directly calls the kernel via `syscall` instruction, completely bypassing the ROP chain

**Remaining attack surface:** Network-side attacks (TCP/IP from PC to PS5), Sony syscall investigation (557/620), and any new syscall paths not yet tested. The shellcode/fn_addr/ROP path is completely dead.

## Finding 57: Syscall 557 Accepts Struct Input, Returns Different Values Per Version (probe 46a)

**Probe:** 46a (Sony syscall deep — crashed mid-probe on format string bug)

Syscall 557 behavior depends on argument format:
- No args or simple integer args → returns **-1** (not the 16901 seen earlier)
- With struct `{size=0x200}` → returns **16901** (0x4205) — consistent with earlier probes
- With struct `{ver=1, size=0x200}` → returns **518** (0x206) — **different return value with version field!**
- With `(0, {size=0x160})` → returns -1, but **kernel modified the struct** — first dword changed to `0x160`

The version-dependent return values suggest this is a versioned kernel query interface. The struct modification proves the kernel reads AND writes to our buffer. Needs a follow-up probe that doesn't crash (fix `%b` format specifier) to sweep the full argument space.

## Finding 58: Loader Dispatch Architecture — __call Is a C Function (probe 46b)

**Probe:** 46b (loader dispatch analysis — output truncated at Section D)

The Lua loader's syscall dispatch mechanism:
- All `syscall.*` entries (pipe, getpid, sysctl, etc.) are **plain Lua tables**, not userdata
- They share a common metatable at `0x3110237c0` with these methods:
  - `__call` (function: `0x311023aa0`) — the actual syscall dispatcher, a C function
  - `__tostring` — generates the ROP chain debug string
  - `create_initial_chain` — builds the chain structure
  - `new` — constructor
  - `arg_addr` — argument slot table
  - `chain` — the ROP chain data (the full 0x2F0-byte structure)

**Key insight:** Both original syscall objects AND `make_syscall()` copies share the **same `__call` C function**. The ROP chain exists in the metatable as data, but `__call` uses its own internal dispatch (likely a direct C-level `syscall` instruction). This confirms why 45c showed the chain is vestigial.

The `__call` C function address `0x311023aa0` is in the loader's memory space. Understanding its internals could reveal if there's a writable function pointer or dispatch table we can redirect.

## Finding 59: socketpair Works via make_syscall — New IPC Primitive (probe 46d)

**Probe:** 46d (socket bypass)

- `socketpair(AF_LOCAL, SOCK_STREAM)` via make_syscall → **ret=0, fd0=22, fd1=23** — works!
- `socketpair` does not exist in `syscall.resolve()` (nil)
- Socket creation is otherwise identical between make_syscall and resolve — no hidden socket types
- SCTP still fails (-1) via both paths
- TCP connect-back to PC timed out (no server running)

socketpair gives us a bidirectional local IPC channel within the same process. This could be useful for: self-pipe tricks, poll/select testing, or as a data channel if we find code execution.

## Finding 60: Syscall 557 Returns Formula-Based Metric, Not Exploitable (probes 47a, 46a re-run)

**Probes:** 47a (version sweep 0-255), 46a (re-run with format fix)

Syscall 557 returns values that follow a formula: `ret = base + ver` where base varies per connection:
- Connection 1 (earlier): base ≈ 517 → ver=0 gives 16901 (0x4205), ver=1 gives 518
- Connection 2 (47a): base ≈ 517 → ver=1 gives 518, linear through ver=255
- Connection 3 (46a re-run): base ≈ 1038 → ver=0 gives 1038, ver=1 gives 1039

The size field also affects the return linearly (log2-based). Buffer modification only happens in a specific 2-arg pattern, writing 0x160 back — just the size echoed. No kernel pointers, no exploitable behavior. **Syscall 557 is a resource/allocation metric query, dead for exploitation.**

Syscall 620 always returns 0 regardless of arguments and doesn't modify buffers. Also dead.

## Finding 61: CClosure Write Test Skipped — Address Parse Bug in 47a (probe 47a)

Probe 47a's critical Section C (writable CClosure function pointer test) produced **zero output** because the `__call` address `"function: 3108dbaa0"` has no `0x` prefix — the regex `match("0x([0-9a-fA-F]+)")` returns nil. The entire CClosure scan was silently skipped.

This parse issue was addressed by 47b. The remaining evidence gap is separate: 47b's write loop omitted offset +0, so it does not establish whether the C function pointer is writable. Retest 53d covers the missing offset and restores each tested value immediately; it does not attempt control-flow redirection.

Key chain metadata from 47a Section B:
- `chain.stack_base = 0x3109b60f0` (ROP chain base)
- `chain.jmpbuf = 0x3109b8130` (longjmp buffer — could be writable!)
- `chain.recover_from_call = 0x3109b8100`
- `chain.fcall_stub = table: 3108d00e0`
- `chain.retval_addr = table: 3108ae100`
- `chain.finalized = true`, `chain.enable_mock_push = false`

## Finding 62: SCM_RIGHTS Over Socketpair — Incomplete (probe 47a)

sendmsg with SCM_RIGHTS on socketpair succeeds (ret=4) and recvmsg succeeds (ret=4), but the cmsg data was all zeros — the ancillary data wasn't properly received. Either the cmsg buffer layout is wrong, or the kernel stripped the control message. LOCAL_PEERCRED returns uid=1, gid=1, pid=0 — sandbox credentials.

## Finding 63: CClosure C Function Pointer Writability Is Unresolved (probe 47b) ★★

**Probe:** 47b (CClosure hijack — fixed uint64 format bug)

The 47b log examined a CClosure, but its write loop covered offsets `{16,24,32,40,48}` and omitted `+0`. The log also labels `+16` writable in one section while other sections make conflicting statements about the candidate at `+0`.

| Offset | Value | Writable | Purpose |
|--------|-------|----------|---------|
| +0 | `0x3_105AF820` | **NOT TESTED** | Candidate pointer; write loop omitted this offset |
| +8 | `0x206` | — | Type flags |
| +16 | `0x3_105AF820` | CONFLICTING | Log labels this writable in one section; interpretation is inconsistent |
| +24 | `0x3_104CE000` | Reported writable | Field role is not independently established |
| +32 | `0x3_10549160` | Reported writable | Field role is not independently established |
| +40 | `0xF8AFAFAF_AFAFAFAF` | Reported writable | The log calls it sentinel/padding; no dispatch effect is shown |
| +48 | `0x1_83D58EE0` | Reported writable | Value range alone does not identify it as executable code |

**No conclusion about offset +0 is supported.** The `+16` observation is inconsistent across the log, so it should not be used to infer the layout or control-flow behavior. Retest 53d checks all relevant qword offsets and records restoration status.

**ROP chain and `fn_addr`:** probe 45c demonstrated that `make_syscall()` continues to work when those metadata fields are invalidated or the chain is corrupted. Their writability does not show that this dispatch path consumes them.

**Status:** no native code execution is demonstrated. The `make_syscall()` ROP/`fn_addr` theory was disproved by 45c. The separate CClosure `+0` writability question remains unresolved; 53d is prepared to test memory writes and restoration, with no redirect attempt.

---

## Finding 64: SCTP Raw Socket Available — New Kernel Attack Surface (probe 48a) ★★

**Probe:** 48a (SCTP/IPv6/ICMP protocol availability sweep)

SCTP raw sockets are available on the PS5:
- `socket(AF_INET, SOCK_RAW, 132)` returns fd=22 — **SCTP raw socket open**
- SCTP stream/dgram/seqpacket all fail (-1) — only raw mode works
- SCTP/INET6 stream and seqpacket also fail

SCTP is a complex protocol with its own state machine, chunk processing, and association management in the FreeBSD kernel (`netinet/sctp_*`). Raw SCTP sockets allow crafting arbitrary SCTP chunks that hit the kernel's SCTP input path — a large, rarely-audited code surface.

**Impact:** SCTP input processing (init/cookie/data/sack/heartbeat chunks) is a fresh kernel attack surface. FreeBSD's SCTP implementation has had historical vulnerabilities. Crafted SCTP packets from the PC to PS5 can exercise this code.

---

## Finding 65: IPv6 Fully Available — TCP, UDP, RAW, ICMPv6 All Open (probe 48a) ★★

**Probe:** 48a

IPv6 is fully operational:
- TCP/IPv6: OPEN (fd=22)
- UDP/IPv6: OPEN (fd=22)
- RAW/IPv6: OPEN (fd=22)
- ICMPv6/IPv6: OPEN (fd=22)
- DGRAM/IPv6 proto=0: OPEN
- IPV6_V6ONLY default=1, can be disabled (dual-stack possible)
- 17 IPv6 raw protocols available (0,1,2,6,17,41,47,50,51,58,59,89,103,112,132,136,255)

**Impact:** IPv6 adds entire parallel kernel code paths — NDP, IPv6 fragment reassembly, extension header processing, ICMPv6 handling. These are separate implementations from IPv4 and represent substantial untested kernel attack surface.

---

## Finding 66: 143 Raw IPv4 Protocols All Create Sockets (probe 48a)

**Probe:** 48a

Every IP protocol number from 0 to 142 successfully creates a SOCK_RAW socket. Notable named protocols: HOPOPT(0), ICMP(1), IGMP(2), IP-in-IP(4), TCP(6), UDP(17), IPv6-encap(41), GRE(47), ESP(50), AH(51), ICMPv6(58), OSPF(89), PIM(103), VRRP(112), SCTP(132), UDPLite(136).

Socket option enumeration on a UDP socket shows standard SOL_SOCKET options (SNDBUF=9216, RCVBUF=42080) and IPPROTO_IP options including IP_OPTIONS (len=0), IP_RECVOPTS, IP_RECVRETOPTS, IP_RECVDSTADDR, IP_IPSEC_POLICY, IP_RECVORIGDSTADDR.

**Impact:** Each protocol's kernel input handler is reachable from the network. Protocols like GRE, ESP, AH, IGMP, PIM, VRRP have complex parsers that may not be hardened on PS5.

---

## Finding 67: IP Options Listener Works, Awaits PC-Side Injection (probe 46c)

**Probe:** 46c (IP options listener)

The PS5 successfully:
- Created UDP socket (fd=22) and bound to port 31338
- Set IP_RECVOPTS sockopt (ret=0)
- Created RAW(UDP) socket (fd=23) for IP header access
- Ran 1200-iteration receive loop (120s window)

Received 0 packets — the PC-side `ip_fragment_inject.py` was not running during the window. The listener infrastructure works; this is a coordinated two-machine test requiring simultaneous PC+PS5 execution.

**Impact:** Test infrastructure validated. When run with PC-side injection, this will test whether IP options survive to the PS5 application layer and whether malformed options can trigger kernel bugs in `ip_dooptions()`.

---

## Finding 68: SCTP Chunk Parser Handles All 39 Fuzz Variants Without Crash (probe 48b)

**Probe:** 48b (SCTP loopback fuzz via raw IP + IP_HDRINCL to 127.0.0.1)

Sent 39 malformed SCTP packets to loopback via `sendto()` on raw socket with IP_HDRINCL. All packets delivered successfully (ret = packet length). No crashes.

Variants tested: INIT with len=0/1/3/0xFFFF, vtag!=0, 0/0xFFFF streams, rwnd=0; ABORT with T-bit; SHUTDOWN cum_tsn=max; ERROR cause_len=0; HEARTBEAT 124B payload; COOKIE_ECHO garbage/empty; COOKIE_ACK no-assoc; SACK with 100 gaps/max gaps+dups/undersized; multi-chunk INIT+ABORT, double INIT, 50 ABORTs, type 0-15 chain; unknown chunk types 62-255 with all action bits; FWD_TSN max/48 streams. Also sent 5 variants to LAN IP (10.0.0.96).

**Impact:** The SCTP chunk parser (`sctp_input()` → `sctp_process_init()` etc.) is robust against basic malformed chunks. Deeper attacks needed: established SCTP associations (INIT→INIT-ACK→COOKIE-ECHO→COOKIE-ACK handshake), state-dependent chunks (DATA/SACK/FWD-TSN on live associations), and timing-based attacks.

---

## Finding 69: IPv6 Extension Header Parser Handles All 83 Fuzz Variants Without Crash (probe 48c)

**Probe:** 48c (IPv6 extension header fuzz via raw IPv6 socket to ::1)

Sent 83 malformed IPv6 packets with crafted extension headers. Zero crashes, zero send errors.

Sections tested:
- **Hop-by-Hop (B):** PadN overrun (len=100), len=255 with 8B sent, Router Alert, Jumbo 4GB, unknown types with all action bits (0x40/0x80/0xC0/0x3F/0x7F/0xBF/0xFF), double HBH
- **Routing (C):** Type 0 CVE (deprecated), segleft=255 overflow, Type 2 MobileIPv6, unknown type 255, len=0 with segleft=10 underflow, len=255 truncated
- **Fragment (D):** Start reassembly, max offset (8191), overlapping fragments, atomic fragment, 32 fragment bomb IDs, nested fragment headers
- **Destination Options (E):** Home Address (MobileIPv6), unknown types with action bits
- **Chained Headers (F):** Full chain (HBH→RH→Frag→Dest→None), 16-deep nesting, self-loop, HBH not first, Routing→HBH mid-chain
- **ICMPv6 (G):** NS too short, NS option length=0 (parser loop risk), RA max lifetimes, Redirect option length=0, Echo 1KB, unknown types 200-255
- **No Next Header (H):** payload_len=0, payload_len=16 with next=59
- **Payload Length (I):** len=0 with data, len=65535 truncated, version=4/0 confusion

**Impact:** FreeBSD's IPv6 extension header processing is hardened against malformed packets at this level. Next-level attacks: actual IPv6 fragment reassembly with real first+last fragments, NDP cache poisoning with valid checksums, and IPv6-in-IPv4 tunneling edge cases.

---

## Finding 70: TCP_INFO Leaks Sequence Numbers at Offsets +108/+112 (probe 49a) ★★

**Probe:** 49a (TCP stateful injection via loopback)

TCP_INFO (236 bytes on PS5, getsockopt level=6 optname=32) exposes exact TCP sequence numbers:
- **Offset +108 (dword):** SND_NXT — changes by exact byte count of sent data
- **Offset +112 (dword):** RCV_NXT — changes by exact byte count of received data

Observed values — Before data exchange: CLI +108=`0x7F10A75E`, SRV +108=`0x57DB27AD`. After client sends 100B, server sends 50B: CLI +108=`0x7F10A7C2` (+100), SRV +108=`0x57DB27DF` (+50).

Differential analysis method: dump TCP_INFO before and after sending a known number of bytes, scan for dwords that changed by exactly that count. This reliably identifies sequence number fields without needing FreeBSD header definitions.

Combined with loopback checksum bypass (if_simloop sets CSUM_DATA_VALID), this enables injection of crafted TCP segments into live connections with exact sequence/ack targeting.

**Impact:** New primitive. TCP_INFO seq number extraction + raw IP socket + loopback checksum bypass = ability to inject arbitrary TCP segments into established connections. Critical for targeting deep TCP state machine code (SACK processing, challenge ACK, persist timer).

---

## Finding 71: TCP State Machine Handles 182 Injected Segments Without Crash (probe 49a)

**Probe:** 49a (TCP stateful injection via loopback)

Injected 182 crafted TCP segments into an ESTABLISHED loopback connection. Zero crashes.

Sections tested:
- **RST injection (D):** exact-seq RST, SYN-in-ESTABLISHED, FIN+ACK, RST+SYN combo, all-flags 0xFF, zero-window, window-shrink, URG pointer past data (past/future), future/past seq data, future ACK
- **TCP options (E):** SACK 1-block, 4-block max, left>right invalid, overlapping, zero-width, len mismatch, in-window SACK, timestamp PAWS violation (future/past), MSS in non-SYN, WinScale in non-SYN, TCP-MD5 fake digest, unknown option kind=253, option length=0 (parser crash target), length=1 undersize, length=255 overread
- **State transitions (F):** data after FIN, RST in TIME_WAIT, SYN recycle, 100 ACK storm, 50 SYN flood to random ports

Notable: RST injection with exact seq did NOT tear down the connection (state remained ESTABLISHED=4). The kernel likely implements RFC 5961 challenge ACK protection, requiring an ACK challenge/response before honoring RST.

Ports ≥40000 are blocked (bind returns -1) — use ports 1024-32767.

**Impact:** FreeBSD's TCP input processing is hardened against crafted segment injection at this level. The SACK processing, option parser, and state machine all handled malformed input cleanly. Deeper targets: race conditions with simultaneous data transfer + injection, or kernel timer manipulation via persist/keepalive.

---

## Finding 72: IPv6 Fragment Reassembly Handles 280 Fragments Without Crash (probe 49b)

**Probe:** 49b (IPv6 fragment reassembly state attacks)

Sent 280 IPv6 fragments targeting the kernel's ip6_reass() reassembly code. Zero crashes, zero send errors.

Sections tested:
- **Baseline (B):** 2-fragment, 3-fragment, out-of-order, reverse-order reassembly
- **Overlapping (C):** exact duplicate, teardrop (different data at same offset), fully contained, overlapping last fragment, conflicting last fragments (different total lengths), zero-offset overlap with different sizes
- **Tiny/minimum (D):** minimum 8-byte fragments, sub-minimum (4B) with MF=1, zero-length payload, 8 minimum-size chain, gap in fragment offsets
- **Queue exhaustion (E):** 50 incomplete reassemblies (first-frag-only), 101-fragment bomb (6432B total), fragment ID reuse after completion
- **Huge totals (F):** max-size reassembly (65535B), over-max (65592B), way-over-max (65784B)
- **Edge cases (G):** atomic fragments (off=0 MF=0), atomic interrupting pending reassembly, fragment ID=0, ID=0xFFFFFFFF, 3 simultaneous reassemblies
- **Offset boundaries (H):** fragments with gaps, swiss-cheese pattern, gap-filling, late large first fragment
- **Extension header combos (I):** HBH+fragment, Routing+fragment, DestOpt+fragment, nested fragment-in-fragment
- **Interleaving (J):** 3 interleaved IDs, 10 interleaved with reverse completion, same ID from different sources
- **ICMPv6 fragments (K):** fragmented Echo Request, fragmented NDP Router Solicitation
- **Payload length (L):** declared vs actual mismatch, zero payload length with fragment

**Impact:** FreeBSD's `ip6_reass()` / `frag6_input()` implementation is hardened. No crash from overlaps, queue stress, huge reassembly, or extension header combos. RFC 5722 (overlapping fragment drop) appears correctly implemented.

---

## Finding 73: Exotic Protocol Handlers All Robust — 86 Packets, No Crashes (probe 50a)

**Probe:** 50a (IGMP, GRE, ESP, AH, PIM, OSPF, VRRP + batch protocol sweeps)

Sent 86 packets across 8 protocol families via raw socket + IP_HDRINCL to loopback:
- **IGMP (B):** general/specific query, v1/v2 report, v2 leave, v3 report with 65535 groups/sources (truncated), truncated (4B), zero-length, unknown type 0xFF
- **GRE (C):** basic encap, checksum/key/sequence flags, all flags, recursive GRE-in-GRE, truncated, zero-length, version 1 (PPTP), IPv6 payload, reserved flags + bad version
- **ESP (D):** SPI=0/1/0xFFFFFFFF, truncated (4B), zero-length, 512B payload
- **AH (E):** basic, SPI=0, truncated (8B), payload_len=0/255, zero-length
- **PIM (F):** Hello, Register, Assert, unknown type 15, version 0, truncated (1B), zero-length
- **OSPF (G):** Hello, zero-length, truncated (8B)
- **Misc (H):** EGP, L2TPv3, IP-in-IP, IPv6-in-IPv4 (hop limit=0), VRRP, experimental proto 253, proto 0 (HOPOPT), batch sweeps of protos 3-7, 9-15, 60-70, 130-142

**Impact:** All exotic protocol input handlers are robust against basic malformed packets. The kernel drops invalid packets cleanly without crashing. These protocols may still have deeper state-dependent bugs (e.g., GRE tunnel establishment, IGMP group membership state).

---

## Finding 74: TCP Keepalive Options Blocked by Sandbox (probe 50b)

**Probe:** 50b (timer manipulation — partial, timed out after Section A)

TCP keepalive socket options are blocked:
- `SO_KEEPALIVE=1`: works (ret=0)
- `TCP_KEEPIDLE=1`: ret=-1 (blocked)
- `TCP_KEEPINTVL=1`: ret=-1 (blocked)
- `TCP_KEEPCNT=1`: ret=-1 (blocked)
- MAX values (all three): ret=-1

Write after peer close: succeeded (ret=16). 50x rapid keepalive toggle: survived.

The probe timed out after Section A (keepalive) — likely stalled on a blocking timer/sleep operation in a later section. Sections B-H (linger, timeouts, buffer resize, shutdown races) were not reached.

**Impact:** TCP keepalive timer manipulation is blocked at the setsockopt level. The kernel doesn't allow tuning keepalive intervals from this sandbox. Timer-based UAF attacks via keepalive are not viable.

---

## Finding 75: Sandbox FD Limit is ~63 (probe 50c)

**Probe:** 50c (resource exhaustion — partial, timed out after Section A)

TCP connection flood hit the fd limit at 63 connections (target was 200). Socket creation starts failing after fd=63 — this is the sandbox's file descriptor limit. All 63 connections were cleanly closed afterward.

The probe then attempted backlog flood (100 connects to listen backlog=1) and timed out — likely blocked on connect() to a full backlog.

**Impact:** The sandbox limits each process to ~63 open file descriptors. This constrains resource exhaustion attacks but also means fd exhaustion is easy to trigger. Combined with raw sockets using fd slots, heavy socket operations could starve the process of fds.

---

## Finding 76: Probe 50d Consistently Crashes Loader (probe 50d)

**Probe:** 50d (cross-protocol tunneling)

50d consistently returns 0 bytes and kills the Lua loader. After 50d is sent, all subsequent probes (including `print("PING")`) also return 0 bytes until the loader is manually restarted on the PS5.

After loader restart, 50c works (produces output), confirming the loader is functional. Sending 50d immediately kills it again. Even a minimal version with just the helper functions and a raw socket creation (identical to 50a's working code) fails after 50d has run.

The crash is persistent across connections — 50d doesn't just kill the per-connection process, it puts the loader itself into a broken state where it accepts TCP connections but doesn't execute Lua.

**Possible causes:**
1. A Lua parse error specific to 50d's source that corrupts the loader's Lua state
2. The raw socket proto=255 + tunnel packet construction triggering a kernel state corruption that affects the loader process
3. Memory corruption from the tunnel packets that persists in the loader's address space

**Impact:** This is the most interesting failure mode observed — a probe that reliably kills the entire loader, not just the per-connection process. Needs the probe-writing session to debug the Lua source for parse errors, or this could be a real kernel/loader bug.

---

## Finding 77: Sony Syscall Survey Output Is Partial (probe 51a)

The saved log `results/51a_sony_syscall_survey_20261016_214814.txt` says it attempted 110 calls, but contains 55 per-syscall result records. The later zero-argument rerun contains only 29 records and stops at syscall 560. Treat the survey as partial; it does not establish coverage of the full 532–676 range.

In the saved records, calls 596, 572, and 563–566 returned 0, and call 624 returned 3377. A return of 0 only establishes that this argument pattern returned successfully. A return of -1 is ambiguous without captured `errno` and valid arguments; it does not prove a syscall is blocked or absent.

## Finding 78: Deep Sony-Syscall Checks Did Not Find a Kernel Pointer (probe 51b)

The saved `51b_accessible_syscall_deep` log records 30 call patterns. It adds successful zero-argument returns for 585, 606, and 643, and a zero return from 640 with a zero-filled output buffer. Together with 51a, this identifies several calls worth understanding, but not a vulnerability.

The output buffers exercised in this probe contained no observed kernel pointers. The 624 return changed from 3377 to 3376 between separate connections; this is not enough to establish a counter, side channel, or kernel-state leak.

Other evidence limits the interpretation:

- Probe 46a/47a characterized syscall 557's return as a version-dependent formula; the `%b` formatting error interrupted the first run. No kernel pointer or memory corruption was demonstrated.
- Probe 51c saved only results for syscalls 625 and 626, so its claimed 54-call survey did not complete in the available log.
- Probe 51b's later `dynlib_cluster_fuzz` file contains only the header and start of phase 1; it has no usable results.

The raw result files are the source of truth. Success returns from unusual syscall numbers should be treated as behavior to characterize, not as evidence of an exploit primitive.
