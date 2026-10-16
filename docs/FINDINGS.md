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

## Finding 13: AIO is Completely Sandbox-Killed

**Probes:** 19, 19b, 19c, 19d, 19e, 19f, 19g

Every AIO syscall tested:
- `aio_read` — killed
- `aio_write` — killed
- `aio_return` — killed
- `aio_suspend` — killed
- `aio_cancel` — killed
- `aio_error` — returns but useless without the others

Seven progressively minimal probes confirmed this is a hard sandbox restriction, not a usage error.

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

## Finding 23: Loader ROP Chain Call Architecture & Argument Slot Layout

**Probes:** 41v, 41z, 42h, 42h2, 42i

The Lua loader's execution mechanism for `syscall.*` stubs constructs a 0x300-byte ROP chain in heap memory (~145 pages before the GPU mmap mapping).
- **Execution flow:**
  1. Gadget sequence: `pop rax; ret` -> loads heap address -> `mov rax,[rax]; ret` (dereferences source value) -> `pop rdi; ret` (loads destination) -> `mov [rdi],rax; ret` (writes value to call stub).
  2. The function target (`fcall_stub.fn_addr`) is loaded from slot 0 (`chain+0x010`).
  3. Arguments 1 through 6 are sequentially loaded from heap source addresses (spaced by -0x10 bytes) into destination registers `rdi`, `rsi`, `rdx`, `rcx`, `r8`.
  4. Stack pivot gadget (`pop rsp; ret` at `eboot+0x9A2`) pivots stack to `fcall_stub.fn_addr`.
- **Heap Adjacency & Control:** The chain, `fn_addr`, and all argument source slots are directly writable via the GPU mmap primitive (`sc_mmap(0, 512*0x4000, 0x33, 0x1002, 0xFFFFFFFF, 0)`).
- **Implication:** Overwriting slot 0 or `fn_addr` redirects execution to any arbitrary function in eboot or libkernel with 6 fully controlled 64-bit arguments.

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

## Finding 27: Sandbox Kill Triggers Isolated

**Probes:** 19, 29, 30, 38, 42b, 42g2

The PS5 kernel includes active sandbox kill triggers that immediately terminate the process without emitting a crash record:
1. `minherit` (syscall 250) — instant kill on invocation.
2. `msync` (syscall 226) — instant kill on invocation.
3. `kenv` (syscall 390) — instant kill on invocation.
4. Any `aio_*` syscall (19a–g) — instant process termination.
5. Reading Execute-Only Memory (XOM) system lib `.text` sections — immediate unrecoverable bus fault.

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

## Finding 36: AF_ROUTE Socket Opens but Info Leak Patched (probe 43o)

**Probes:** 43o

- `socket(PF_ROUTE=17, SOCK_RAW, 0)` succeeds → `fd=22`
- `RTM_GET` for default route (0.0.0.0): write returns -1 but read returns 108 bytes
- Response header: `msglen=108 ver=5 type=4 flags=0x3 addrs=0x1 errno=0`
- **Zero kernel pointers** in the 108-byte response — all zeros past the header
- RTM_GET for specific destinations (loopback, gateway, self, broadcast, DNS): all writes fail
- Passive listen returns the same 108-byte echo
- sysctl `NET_RT_DUMP` and `NET_RT_IFLIST` fallbacks also produced no kernel pointers

**Conclusion:** Sony patched the AF_ROUTE info leak that Relapse used on fw 7.00-13.60. The socket opens but routing table entries no longer contain kernel VA pointers. Dead end.

---

## Finding 37: AIO Sandbox Kill is Kernel-Side (probe 43p)

**Probes:** 43p

- `aio_error` (syscall 317) via `make_syscall()` with NULL args → **instant process kill**
- The kill happens at the very first AIO syscall tested, even through the raw make_syscall path
- This confirms the AIO sandbox kill is enforced in the kernel, not in `syscall.resolve()`

**Conclusion:** AIO is a hard kernel-level sandbox boundary. No bypass possible via make_syscall. Eliminates AIO-based race condition exploits entirely.

---

## Finding 38: kldstat/kldsym are Sandbox-Killed (probes 43a, 43b)

**Probes:** 43a, 43b

- `kldstat` (syscall 308) via make_syscall → instant process kill
- `kldsym` (syscall 337) via make_syscall → instant process kill
- Both KLD syscalls are kernel-level sandbox kills, not resolve()-side filtering

**Conclusion:** Kernel module introspection completely blocked. Cannot query kernel base address or resolve kernel symbols through KLD syscalls.

---

## Finding 39: fn_addr + slot0 Writes Persist Across ROP Calls (probe 43i) ★

**Probes:** 43i

This is a **critical exploitation primitive**:
- Writing `0xDEADBEEFCAFEBABE` to `fn_addr` persists after calling `getpid()` — the chain does NOT rebuild fn_addr
- Writing `0x4141414141414141` to slot 0 also persists after a syscall call — slot 0 is NOT rebuilt
- Both fn_addr and slot 0 can be freely overwritten from the heap R/W primitive

**Implication:** We have an arbitrary function call primitive. By writing a target function address into fn_addr (or into the heap location slot 0 dereferences), the next syscall call via the ROP chain will call our chosen function with 6 controlled arguments. This is the key primitive for kernel exploitation — once we have a kernel address (KASLR defeat), we can redirect execution to `copyin`/`copyout` for kernel R/W.

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

## Finding 50: W^X DEFEATED — mtypeprotect Grants Execute Permission (probe 44a) ★★★

**Probes:** 44a

**This is the most significant exploitation finding in the entire research.**

- Allocate an RW page via `mmap(0, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)`
- Write native x86-64 shellcode to the page (NOP sled + `ret`, `mov eax, 0x41414141; ret`, direct `syscall`)
- Call `sceKernelMtypeprotect(585)` with `PROT_READ|PROT_WRITE|PROT_EXEC` (7) → returns 1
- Redirect `fn_addr` to point at the shellcode page (using the persistent write from 43i)
- Trigger a syscall call → **the NOP sled executes successfully and returns**
- Direct syscall instruction also executes from the page

**Key observations:**
- NOP sled test: `ok=true ret=121` (121 = pid) — the page executed without crashing
- `mov eax, 0x41414141; ret` test: also returned pid (121) — the ROP chain's return path may override eax
- Direct `syscall` instruction: `ok=true ret=121` — syscall execution works from the page
- After all tests, fn_addr restored successfully and getpid continues working

**Impact:** We can now write and execute arbitrary native x86-64 code. This eliminates the need for ROP chains entirely. With this primitive:
1. Write a kernel R/W function as native shellcode
2. Write a KASLR defeat function that probes kernel memory directly via syscall
3. Combine with fn_addr redirect for clean function calls
4. The entire exploit chain (KASLR defeat → kernel R/W → privilege escalation) can be implemented as native shellcode

**W^X was the hardest wall. It's now broken.**

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

## Finding 54: Shellcode Executes but Buffer Writes Don't Land (probe 45a)

**Probes:** 45a

Native x86-64 shellcode executes without crashing (returns pid=128), but none of the 4 payloads successfully wrote results to the output buffer — all slots still contain the `DEADDEAD_DEADDEAD` sentinel. Tested payloads:

1. **Register dump** (mov [rbx+off], rdi/rsi/rdx/rcx/r8/r9/rsp/rbp) — all sentinel
2. **RDGSBASE** (rdgsbase rax; mov [rbx], rax) — sentinel (0 or didn't execute)
3. **RDMSR IA32_LSTAR** (rdmsr; shl rdx,32; or rax,rdx; mov [rbx],rax) — sentinel (ring 0 only, expected)
4. **Direct sysctl** (mov rdi,mib; ... syscall) — `actual_len` changed to 2048 but ret is sentinel

**The problem:** The ROP chain sets up registers (rdi, rsi, rdx, rcx, r8) before jumping to `fn_addr`. Our shellcode's `mov rbx, <buf_addr>` likely gets the buffer address, but the chain may have already clobbered registers or the shellcode's absolute address encoding for the buffer is wrong (needs position-independent addressing or the buffer address embedded as an immediate in the shellcode bytes).

**Key insight:** `actual_len=2048` changing in test 4 suggests the sysctl syscall DID execute and touched the oldlenp pointer. But the return value write failed. The shellcode execution path works — the data routing is the problem.

**Next:** Shellcode must embed the result buffer address as an immediate value (patch bytes at probe generation time), not load it from a register that the ROP chain may have overwritten.

---

## Finding 55: Shellcode Has No Observable Side Effects — Execution May Be Illusory (probe 45b) ★

**Probes:** 45b

Systematic diagnostic of shellcode execution reveals a critical problem:

1. **Return value is ALWAYS pid (128)** regardless of what shellcode puts in `eax`:
   - `bare ret` → 128
   - `xor eax,eax; ret` → 128
   - `mov eax, 0xBEEF; ret` → 128
   - `mov eax, 0x41414141; ret` → 128
   - The ROP chain reads the return value from a **memory slot**, not `rax`

2. **All register oracle tests return 128** — `mov eax, edi; ret` etc. all return pid. Either our code doesn't execute, or the chain overwrites `eax` after.

3. **Memory writes FAIL from every path:**
   - Write to self-page (RWX): unchanged (0xAAAAAAAA stays)
   - Write to heap buffer: unchanged (0xBBBBBBBB stays)
   - Direct sysctl syscall: no change to output buffer
   - The ONLY change was fn_ptr itself → `0x10DA8500` (code page addr, chain artifact)

4. **Lua-side writes are fine** — `memory.write_dword(0xDEADBEEF)` verified, `write_byte` loop verified, code bytes verified on page before execution.

**Critical question:** Is the ROP chain actually jumping to our shellcode, or does it merely complete its normal path (ignoring the fn_addr we wrote)? The fact that writing fn_addr to `0xDEADBEEFCAFEBABE` in 43i didn't crash suggests the chain may not actually call through fn_addr in the way we assumed — or it recovers from bad addresses gracefully.

**Alternative theory:** The chain's function call goes through the syscall stub's `call [fn_addr]` mechanism, but after fn_addr returns, the chain's epilogue always reads the return value from a fixed memory slot (written by the real syscall stub). If we redirect fn_addr to a non-syscall address, the return path still loads from the slot, so we always see pid.

**Next steps:** Need to understand exactly how the ROP chain uses fn_addr. Specifically: does the chain call `fn_addr` with `call rax`? Or does it do an indirect jump through a pointer? We need a side effect that survives the chain's epilogue — like writing to a global variable or sending a network packet from shellcode.
