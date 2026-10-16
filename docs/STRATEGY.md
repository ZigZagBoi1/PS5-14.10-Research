# Exploit Strategy Assessment — PS5 14.10

## Current Position

We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is **kernel R/W** to enable hypervisor bypass (Byepervisor).

### ★★★ BREAKTHROUGH (2026-10-16): W^X Defeated
**`sceKernelMtypeprotect(585)` grants RWX on mmap'd pages.** Native x86-64 shellcode executes from mmap'd pages via fn_addr redirect. This means:
- Arbitrary native code execution (no more ROP-only)
- Direct `syscall` instruction works from shellcode
- Can now write kernel R/W as native shellcode once KASLR is defeated
- **KASLR defeat is the sole remaining blocker**

## Remaining Challenges

1. **No threading** → no race conditions (TOCTOU, UAF-via-race, refcount races)
2. ~~**W^X + XOM**~~ → **W^X DEFEATED via mtypeprotect(585)**. XOM still blocks reading system lib .text.
3. **Minimal syscall surface** → most syscalls blocked even via make_syscall
4. **KASLR defeat** → every direct info leak path tested and dead. Need kernel base address.

## Tier 1: RAW Socket Packet Injection (Most Promising)

**Status:** RAW socket + IP_HDRINCL confirmed working. Crafted UDP packets reach kernel `ip_input()`.

**Why:** Bypasses the syscall sandbox entirely. The kernel parses our crafted packet data in network stack context, not behind the syscall filter. The network input path is orders of magnitude larger than the syscall surface we can reach directly.

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

## Tier 5: ROP Chain Hijack → Arbitrary Function Call (NEW — Phase 8)

**Status:** Chain fully decoded, all slot addresses mapped. fn_addr writable. UNTESTED: actual redirect.

**Why:** The Lua loader builds a complete ROP chain in heap memory for every syscall. The chain, fn_addr (function call target), and all 13 argument slots are writable from the GPU mmap heap primitive. Overwriting slot 0 changes what function gets called.

**Key addresses (per-session — re-derive via `tostring(syscall.pipe)`):**
- `ropchain @ <addr>` — chain body start
- `fcall_stub.fn_addr: <addr>` — function pointer, holds syscall stub address
- Chain+0x010 → slot 0 (heap addr) — **source for fn_addr value**
- Slots 1-12 → argument values at ~0x38-byte stride

**Chain structure (repeating pattern per arg):**
```
pop rax; <slot_addr>          — load heap pointer
mov rax,[rax]                 — dereference to get value
pop rdi; <dest_addr>          — load destination
mov [rdi],rax                 — write value to call stub
```

**Known from probes 41z + 42i:**
- fn_addr is loaded FROM slot 0 by the chain itself
- All slots are in the heap R/W zone (~145 pages before GPU mmap)
- Chain is rebuilt each Lua syscall call — writes get overwritten
- Probe 43i (`43i_fn_redirect.lua`, ready to send) tests whether slot 0 survives rebuild and verifies fn_addr redirection

**Attack plan:**
1. Overwrite slot 0 to point to a buffer containing a libkernel function address
2. Trigger a syscall — the chain loads OUR address into fn_addr
3. IF the chain rebuilds slot 0: need to find the TEMPLATE that gets copied into the chain and modify that instead
4. Target functions: `sceKernelMapDirectMemory` (to map kernel physical pages), or a libkernel internal that returns kernel pointers
5. Once we have kernel base: redirect fn_addr to `copyin`/`copyout` for arbitrary kernel R/W

**Blockers:**
- Timing: chain rebuilt per call, so writes may not survive to execution
- Need to find the chain template in the loader's data
- Kernel base address still unknown (all sysctl leaks blocked, dmem0 is GPU-only)

## Dead Ends (Do Not Retry)

| Attack | Why dead |
|--------|----------|
| sigaltstack kernel write | copyout() validates, kills process |
| sigprocmask manipulation | Complete no-op |
| W^X bypass / mprotect EXEC | Always denied |
| Code page gadget scan | XOM — SIGBUS on read |
| Threading / race conditions | fork/rfork/thr_new all blocked |
| AIO exploitation (via resolve() AND make_syscall) | sandbox-killed at kernel level — confirmed dead via both paths (probes 19, 43p) |
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
| kenv syscall (390) | Instant process kill — sandbox (probe 42g2) |
| TCB/FS base for kptrs | Contains only userland TLS pointers, no kernel addresses (probe 42c2) |
| AF_ROUTE KASLR (Relapse technique) | Socket opens but response has zero kernel pointers — info leak patched (probe 43o) |
| AIO via make_syscall | Sandbox kill is kernel-level, not resolve()-side. aio_error instant-kills even raw (probe 43p) |
| kldstat / kldsym | Both sandbox-killed at kernel. No KLD introspection possible (probes 43a, 43b) |
| kinfo_proc kernel pointers | Full 1096B dump: only sentinel values, no real kernel pointers (probe 43d) |
| kern.proc.filedesc | Blocked — ret=-1, size=0 (probe 43d) |
| kern.proc.vmmap (large buffers) | ret=-1 with 64K-256K buffers (probe 43d) |
| sysctl write paths | All writes blocked: securelevel, coredump, maxproc, debug (probe 43f) |
| sysarch GET_GSBASE | Returns 0 — no kernel curthread pointer leaked (probe 43c) |
| ioctl via make_syscall | Returns -1 for all tested ioctls even via raw syscall (probe 43e) |
| dup/dup2 via make_syscall | Returns -1 (probe 43e) |
| thr_new via make_syscall | Crashes process (probe 43e) |
| kern.msgbuf full read | Returns only 8 bytes stub — filtered (probe 43j) |
| mincore KASLR oracle | All kernel VA probes return -1. Userland only (probe 43l) |
| sockopt buffer overflow | Kernel clamps copy length internally — not an overflow (probe 43m) |
| /dev/hid ioctl | All ioctls return Sony error 0x80740004 (probe 43n) |

## Live Results Summary (2026-10-15 session)

**Ran:** 36 (ports), 37 (IP options), 38 (syscall sweep), 39 (frags), 41m/41n/41o/41p/41q (vtable chase), 42a (ktimer), 42b (memfd/msync).

**New usable surface:** ktimer create/settime/getoverrun on clocks 0+4. accept4/preadv/pwritev/copy_file_range resolve but need real fds. SCTP socket creation untested.

**New tooling insight:** the crash record (magic 0x13371337) leaks the module code base + heap pointers on every SIGSEGV — a per-process ASLR oracle. Gadgets can be resolved offline from a same-build binary dump.

**Loader behavior:** fresh process + fresh ASLR per connection; heap scanning must be anchor-relative; mapped heap ends in a guard page — always scan DOWN from known-mapped, print progress to survive the 30s socket timeout.

## Relapse Exploit Intelligence (fw 7.00-13.60)

The **Relapse exploit** (Sep 29, 2026) is the last public PS5 kernel exploit chain, targeting fw 7.00-13.60. Patched in fw 14.00 (Sep 16, 2026). Key techniques:

1. **KASLR defeat via AF_ROUTE socket** — `socket(PF_ROUTE=17, SOCK_RAW)` + `RTM_GET` queries leak kernel `.text` pointers from routing table entries. This is completely different from our sysctl scanning approach. **Probe 43o tests this.**

2. **`aio_multi_wait` UAF** — The actual kernel bug was a use-after-free race condition in Sony's `aio_multi_wait` syscall. The specific bug is patched, but the AIO subsystem itself might be accessible via `make_syscall()`. We only tested AIO through `resolve()` (which kills the process), never via raw syscall numbers. **Probe 43p tests this.**

3. **Bug class is alive even if specific bugs are patched** — Relapse used a race condition in AIO. If AIO works via make_syscall, the entire async race condition class opens up: concurrent kernel operations without userland threading.

**What we should steal from Relapse:**
- AF_ROUTE KASLR defeat — probe 43o (the technique is independent of the UAF bug)
- AIO bypass test — probe 43p (sandbox kill might be Lua-side only)
- Race condition methodology — if AIO lives, we can build UAF/TOCTOU primitives

## Userland Exploit Chain

Entry is a **save file exploit** in a PS4-backwards-compatible game demo (Japanese PSN). The chain:
1. PS5 save → USB → jailbroken PS4 → decrypt → embed Lua loader → re-encrypt → PS4 → USB → PS5
2. Loading the save spawns the Lua 5.1 loader on TCP 9026
3. Per-connection ASLR: each TCP connect spawns a fresh process with new address space
4. The game process runs in a PS4-compatibility sandbox (may differ from native PS5 sandbox)

The Lua loader gives us: arbitrary memory read/write (via `memory.*` API), syscall invocation (via `syscall.*` API), and the `make_syscall()` bypass for raw kernel access. This is our entire attack surface.

## Next Priorities (Updated 2026-10-16 after Phase 10 sweep)

### The Situation
Phase 10 tested 16 probes and eliminated nearly all direct KASLR defeat vectors. Every sysctl, KLD, sysarch, AF_ROUTE, mincore, and AIO path is dead. **The only confirmed exploitation primitive is the fn_addr/slot0 redirect (probe 43i) — we can call any function with 6 controlled arguments, but we don't have a kernel address to call.**

### Priority 1: Investigate Sony Syscall 557 (returns 16901)
Syscall 557 is a live Sony-custom syscall returning a non-error value. Unknown function. Could return kernel pointers in a proper output buffer. Needs targeted probing with various argument patterns.

### Priority 2: mtypeprotect Execution Test
mtypeprotect returns 1 for all protection values including RWX. If execution permission is actually granted, we have a W^X bypass — arbitrary shellcode execution. Write a probe that writes known shellcode to a page, calls mtypeprotect(RWX), then redirects fn_addr to the shellcode page.

### Priority 3: TCP Input-Side Attacks (Network-Side)
Fake-IP ARP-responder technique works; full handshake + 26 malformed segments delivered. Expand: TCP SACK processing, urgent pointer, MD5/AO options, PAWS, simultaneous open, RST in TIME_WAIT.

### Priority 4: IP Options from Real Network
PC sends crafted packets with malformed IP options to PS5 LAN IP. Reaches input-side ip_dooptions without output validation.

### Priority 5: Deep Sony Syscall Investigation
Syscall 620 also alive (ret=0). Need targeted investigation of the full 540-700 range with proper argument structures, not just null args.

### Priority 6: SCTP / ip_reass Deeper
SCTP socket creation untested. ip_reass queue exhaustion, timeout races still open.
6. **ktimer abuse** — arm a timer with SIGEV_SIGNAL + signo for an ignored/blocked signal and observe delivery; settime on one timer while another fires (no threads, but signal handlers are reentrant).
