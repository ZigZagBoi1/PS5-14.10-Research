# PS5 Firmware 14.10 Kernel Exploitation Research

## From Userland Code Execution to the Edge of Kernel Memory

**Target:** PlayStation 5, Firmware 14.10  
**Kernel:** FreeBSD r230171 (Sep 28 2026)  
**Status:** Userland primitives confirmed. KASLR defeat in progress.  
**Repository:** https://github.com/ZigZagBoi1/PS5-14.10-Research

---

## Abstract

This paper documents systematic kernel exploit research on the PlayStation 5 running firmware 14.10. Starting from a Lua 5.1 code execution primitive obtained through a modified save file, we developed a complete set of userland exploitation primitives: arbitrary syscall access via a sandbox bypass, a heap read/write primitive spanning 256+ memory pages through GPU mmap adjacency, full ASLR defeat across all 39 loaded modules, and a confirmed ROP chain hijack with writable function pointer and argument slots. Over 80 probes were executed across 10 research phases, mapping the kernel attack surface and eliminating dead ends. The remaining barrier is KASLR defeat - once the kernel base address is known, the existing primitives are sufficient for kernel read/write. We present our methodology, findings, and 16 untested probes designed to cross that threshold.

---

## 1. Introduction

The PlayStation 5 runs a heavily customized FreeBSD kernel with multiple layers of security: W^X memory enforcement, execute-only memory (XOM) on system libraries, per-connection address space layout randomization, a syscall sandbox, and a security level of 1024 (a PS5-specific value far above standard FreeBSD's maximum of 2). Breaking through these protections requires a methodical approach - testing each attack surface, cataloging what works and what doesn't, and building exploitation primitives one at a time.

This research began with a known userland entry point: the Artemis visual novel engine embeds a Lua 5.1 interpreter, and a modified save file can inject a TCP listener that accepts arbitrary Lua scripts. From there, we systematically explored what the kernel exposes to a sandboxed game process on firmware 14.10.

The exploit chain target is:

```
Userland Code Exec -> Kernel R/W -> Hypervisor Bypass
```

This paper covers the first arrow in detail and documents our progress toward the second.

### 1.1 Related Work

This research builds on several prior efforts in the PS5 homebrew scene:

- **shahrilnet/remote_lua_loader** - The original Lua loader that provides our userland code execution primitive
- **hammer-83/ps5-jar-loader** - Kernel symbol offsets for firmware versions 1.00 through 10.01 (not available for 14.10)
- **The Relapse exploit (fw 7.00-13.60)** - Demonstrated AF_ROUTE socket KASLR defeat and AIO race condition exploitation on earlier firmware. Key techniques from Relapse inform our probe 43o (AF_ROUTE KASLR) and 43p (AIO bypass)
- **GoldHEN** - PS4 jailbreak framework by SiSTRo, required for our save file preparation chain
- **Apollo Save Tool** - Save file decryption/encryption tool by bucanero, used in the save file chain

---

## 2. Target Environment

| Property | Value |
|----------|-------|
| Console | PlayStation 5 (disc/digital) |
| Firmware | 14.10 |
| Kernel | FreeBSD r230171 (Sep 28 2026) |
| Architecture | AMD64 (Zen 2), 8 cores / 16 threads |
| Page size | 16 KB (0x4000) |
| Security level | 1024 (PS5-specific) |
| Loaded modules | 39 (all bases randomized per connection) |
| ASLR | Per-connection (fresh process per TCP connection) |
| W^X | Strictly enforced (no RWX regions exist) |
| XOM | System library .text is execute-only; eboot .text is RX |

The PS5's kernel is based on FreeBSD but diverges significantly. The security level of 1024 is unique to the PS5 - standard FreeBSD tops out at 2. The 16KB page size (vs FreeBSD's default 4KB) affects all memory layout calculations. The kernel build string `r230171` corresponds to a Sony-internal FreeBSD fork.

### 2.1 Process Sandbox

The game process runs in a PS4 backwards-compatibility sandbox. This sandbox restricts:

- **Syscalls:** A Lua-side filter (`syscall.resolve()`) blocks many syscalls by name. A critical finding of this research is that this filter is bypassable (Section 4.1).
- **File system:** Most paths are inaccessible. `/dev/dmem0` opens but only exposes GPU memory. `/dev/hid` opens successfully.
- **Network:** TCP/UDP/RAW sockets work. Port binding restricted to 1024-32767. Outbound connections work.
- **Memory:** mmap with RW permissions works. PROT_EXEC is always stripped. MAP_FIXED works for page-aligned remapping.
- **Threading:** All process creation and threading syscalls are blocked (fork, rfork, thr_new).

### 2.2 Per-Connection ASLR

Every TCP connection to the Lua loader on port 9026 spawns a fresh process with a completely new address space. This means:

- All addresses must be re-derived every run
- No state persists between probe executions
- Module bases change completely (but can be leaked via `dynlib_get_info`)
- Heap layout changes (but the GPU mmap anchor provides relative stability)
- The `0x9FE5` prefix in `fn_addr` is constant across sessions, indicating reduced ASLR entropy in the upper bits of certain allocations

---

## 3. Userland Entry

### 3.1 The Game

The entry point is **Hamidashi Creative** (はみだしクリエイティブ) by Madosoft, a Japanese visual novel running on the **Artemis engine**. The Artemis engine embeds a Lua interpreter that processes scripts stored in save data. A free demo is available on the Japanese PSN store.

The loader supports 14 Artemis-engine games total. Game identification works by checking the last nibble of `luaB_auxwrap` in the eboot, with a CRC32 tiebreaker on the first 0xFF bytes of libc for games with identical eboots. Each game has different ROP gadget offsets. For Hamidashi Creative, the stack pivot (`pop rsp; ret`) is at eboot+0x9A2.

### 3.2 The Save File Chain

Getting code execution requires a multi-step save file modification process:

1. Create a save file on the PS5 by playing the game briefly
2. Export the save to USB
3. On a **jailbroken PS4** running GoldHEN, use Apollo Save Tool to activate a profile with the **same PSN Account ID** as the PS5's Japanese account (this is critical - the PS5 cryptographically binds saves to account IDs)
4. Import and decrypt the save on the PS4
5. Transfer the decrypted save to a PC and embed the Lua loader payload
6. Re-encrypt the save on the PS4 under the matched profile
7. Import the modified save back to the PS5
8. Launch the game - the screen goes black and a notification appears: "lua loader is loaded" with the console's IP and port

The loader then listens on TCP port 9026 and accepts Lua scripts using a simple protocol: an 8-byte little-endian length prefix followed by the raw Lua source.

### 3.3 The Loader

Based on shahrilnet's remote_lua_loader, the loader provides:

- **`memory.*` API** - Read/write arbitrary process memory (read_byte, read_dword, read_qword, write_*, alloc)
- **`syscall.*` API** - Invoke syscalls via `syscall.resolve()` (filtered) or `make_syscall(N)` (unfiltered)
- **ROP chain** - A 0x300-byte structure with function target, argument slots, and stack pivot
- **TCP protocol** - 8-byte LE length prefix + raw Lua source, one connection per probe execution

---

## 4. Confirmed Exploitation Primitives

### 4.1 Sandbox Bypass via make_syscall()

**This is the single most important finding of this research.**

The Lua loader's `syscall.resolve()` function contains a filter that blocks many syscalls by name. Early probes (phases 1-6) reported numerous syscalls as "blocked." However, the `make_syscall(N)` function constructs a raw syscall object by copying the internal state of an existing syscall (`syscall.pipe`) and overwriting the syscall number:

```lua
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
```

This object goes straight to the kernel, bypassing the `resolve()` filter entirely. The bypass was proven when **sysctl (syscall 202)** - reported as "blocked" by `resolve()` - worked perfectly via `make_syscall(202)`. This discovery invalidated dozens of earlier "blocked" verdicts and opened the kernel's full syscall interface for testing.

The key insight: the sandbox filter exists only in the Lua loader's JavaScript, not in the kernel. Any syscall that the kernel itself permits will work through `make_syscall()`.

### 4.2 Heap Read/Write Primitive

GPU memory mapping via `mmap` (syscall 477) with protection flags 0x33 (CPU_RW + GPU_RW) allocates pages with **no guard pages** between allocations. This means consecutive allocations land contiguously in the virtual address space.

**Parameters:**
- addr: 0 (kernel chooses)
- size: 512 * 0x4000 (8 MB, 512 pages)
- prot: 0x33 (PROT_READ | PROT_WRITE | GPU flags)
- flags: 0x1002 (MAP_PRIVATE | MAP_ANON)
- fd: 0xFFFFFFFF (-1, anonymous)
- offset: 0

**Confirmed capabilities (probes 41c-41e):**
- 256+ pages readable before the allocation base (backward scan)
- All backward pages are writable (tested at 9 offsets from -0x1000 to -0x80000)
- Cross-allocation writes confirmed: write to alloc1+PAGE, read from alloc2
- Use-after-free writes confirmed: freed page retains written data after reallocation
- 90+ non-zero pages found in backward scans, containing heap metadata and object data

The heap contains categorized data: heap self-pointers (0x3_1xxxxxxx range), heap cross-pointers, fill patterns (0xAFAFAFAF for freed memory), small values, and ASCII strings. Critically, **zero kernel pointers** were found across exhaustive scans of 10,240+ qwords.

### 4.3 ASLR Bypass

The `dynlib_get_info` syscall (number 593) leaks the text and data segment base addresses for every loaded module. By iterating over all module handles (0 through ~40), we recover all 39 module bases in a single probe execution.

```lua
local info = memory.alloc(0x200)
safe_wd(info, 0x160)  -- struct size
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
```

This completely defeats userland ASLR. Every module's code and data locations are known, enabling gadget address computation for ROP chains. The libkernel handle is consistently 0x2001 (8193).

Example module bases from a single run:
- Eboot: `0x054660000`
- libkernel: `0x8281F0000` (text), syscall stub at libkernel+0xB57

### 4.4 ROP Chain Architecture

The loader's ROP chain was fully reverse-engineered in probes 41v and 42i. It is a 0x300-byte (768-byte) structure in heap memory that implements a function call primitive:

**Chain structure:**
1. Stack pivot: `pop rsp; ret` at eboot+0x9A2 redirects execution into the chain
2. Gadget sequence: `pop rax` -> `mov rax,[rax]` (dereference) -> `pop rdi` -> `mov [rdi],rax` (write)
3. Register loading: The chain loads rdi, rsi, rdx, rcx, and r8 from 13 argument slots in heap memory
4. Function call: The chain jumps to `fn_addr`, which points to the syscall stub at libkernel+0xB57
5. Return: Control returns through the chain back to Lua

**Gadget catalog (extracted from RX eboot, probes 41r-41t):**

| Gadget | Location | Bytes |
|--------|----------|-------|
| pop rdi; ret | eboot+0xC9DFE | 5F C3 |
| pop rsi; ret | eboot+0xD77D | 5E C3 |
| pop rdx; ret | eboot+0x420E6D | 5A C3 |
| pop rax; ret | eboot+0x992 | 58 C3 |
| pop rcx; ret | eboot+0xE64 | 59 C3 |
| pop r8; ret | eboot+0x991 | 41 58 C3 |
| pop rsp; ret | eboot+0x9A2 | 5C C3 |
| jmp rax | eboot+0x84C | FF E0 |
| mov rax,[rax]; ret | eboot+0x7EEBB | 48 8B 00 C3 |
| mov [rdi],rax; ret | eboot+0x6F2C67 | 48 89 07 C3 |
| leave; ret | eboot+0x37FDE0 | C9 C3 |

Notably, **no `syscall; ret` gadget exists anywhere in the eboot's 4.6 MB of text**. The syscall instruction is only available through libkernel's text segment, which is execute-only (XO) and cannot be read. The loader solves this by using `fn_addr` to point to the syscall stub in libkernel.

### 4.5 ROP Chain Hijack

Probe 41z confirmed the complete hijack capability. The ROP chain, `fn_addr`, and all argument slots reside in heap memory reachable from the GPU mmap primitive:

- **ROP chain distance from GPU mmap:** ~146 pages (~2.3 MB)
- **Chain read confirmed:** First gadget reads as eboot+0x42 (ret), matching expected value
- **Chain write confirmed:** Wrote 0x4141414142424242, read back correctly, restored original
- **fn_addr write confirmed:** Original value 0x9FE510810130, write/restore cycle successful
- **All 13 argument slots writable:** Full control over rdi, rsi, rdx, rcx, r8 register values
- **Post-hijack stability:** getpid() returns correctly after all read/write/restore operations

This means we can:
1. Point `fn_addr` at any address (currently the syscall stub, but could be any function)
2. Set all 5 argument registers to arbitrary values
3. Execute the next `make_syscall()` call, which will call whatever function fn_addr points to with our controlled arguments
4. The process remains stable for subsequent operations

Combined with KASLR defeat, this primitive would enable direct kernel function calls with controlled arguments - the bridge from userland to kernel.

---

## 5. Attack Surface Analysis

### 5.1 Working Syscalls

Over 80 probes mapped the syscall attack surface. The following syscalls are confirmed working (either directly or via `make_syscall`):

**Networking (fully open):**
- socket(97), bind(104), connect(98), listen(106), shutdown(134)
- read(3), write(4), readv(120), writev(121)
- sendmsg(28), recvmsg(27) with MSG_DONTWAIT(0x80)
- socketpair(135) for AF_UNIX
- poll(209) with correct POLLIN/POLLHUP/POLLNVAL semantics
- getsockopt(118), setsockopt(105) (limited options)
- getsockname(32)
- RAW sockets with IP_HDRINCL (crafted packets reach kernel ip_input via loopback)

**Memory:**
- mmap(477) - RW only, MAP_FIXED works
- munmap(73), madvise(75), mlock(203)
- mincore - works as memory residency oracle

**System identification:**
- getpid(20), thr_self - returns real TID (e.g., 101819)
- sysctl(202) via make_syscall - kern.version, kern.securelevel, hw.pagesize, etc.
- dynlib_get_info(593) - all 39 module bases

**Kernel objects:**
- ktimer_create(235) - clocks 0 (REALTIME) and 4 (MONOTONIC), cap at 27 timers
- ktimer_settime(236) - validation correct
- ktimer_getoverrun(239) - works
- sigaction(416) - SIG_IGN/SIG_DFL/custom handlers

**PS5-specific:**
- sceKernelMtypeprotect(585) - returns 1 (the only Sony syscall returning positive)
- sceKernelGetCpuUsage(617) - returns 0 (success)

### 5.2 Blocked Syscalls

These are confirmed blocked at the kernel level (not just the Lua filter):

- **Threading:** fork(2), rfork(251), thr_new(455) - all return -1
- **fd manipulation:** dup(41), dup2(90), fstat(189), pipe(42), pipe2(542)
- **ioctl(54)** - blocked via resolve(), untested via make_syscall
- **AIO:** All aio_* syscalls (255, 256, 314-317) - sandbox-killed
- **mprotect(74)** - PROT_EXEC always denied
- **kevent(363)** - always returns -1 (kqueue fd allocates but is useless)
- **Obscure sysctls:** kern.proc.vmmap, kern.proc.filedesc, kern.proc.kstack, kern.file, kern.proc.auxv, net.inet.tcp.pcblist, security.mac - all blocked
- **procctl:** ASLR_STATUS, ASLR_CTL, STACKGAP_STATUS, NO_NEW_PRIVS_STATUS - all blocked

### 5.3 Instant-Kill Syscalls

These terminate the process immediately, even through pcall():

- **minherit(250)** - identified as the killer in probe 30
- **msync(226)** - confirmed in probe 42b
- **kenv(390)** - confirmed in probe 42g2

These cannot be used in any probe and must be avoided.

### 5.4 The make_syscall Question

The critical open question: **which "blocked" syscalls actually work via make_syscall?**

We know sysctl(202) is blocked by `resolve()` but works via `make_syscall()`. Probe 43e is designed to test thr_new(455), ioctl(54), dup(41), dup2(90), fstat(189), and pipe2(542) through the bypass. If threading or ioctl works, entirely new attack vectors open up.

Probe 43p tests whether AIO's "sandbox kill" is a `resolve()`-side mechanism or kernel-side enforcement. If AIO works via `make_syscall()`, the entire async I/O subsystem becomes available, enabling kernel race conditions without threading - the same bug class that the Relapse exploit used on earlier firmware.

---

## 6. KASLR Defeat Attempts

Nine dedicated probes (42b-42j) attempted to leak kernel addresses from userland. All failed. This section documents what was tried and why it didn't work, to save future researchers from repeating these dead ends.

### 6.1 Sysctl Information Leaks

Multiple sysctl queries were tested for kernel pointer leaks:

- **kinfo_proc (kern.proc.pid):** Returns 1096 bytes. Field at +0x060 contains 0xFFFFFFFF00000000, which appears to be a kernel pointer but is actually a bitmask/sentinel. No real kernel pointers found in the entire structure.
- **kern.msgbuf:** Returns 8 bytes with value 0x7EF710000 - a userland stack-area address, not a kernel pointer. A full 64KB read (probe 43j) may contain more data.
- **kern.proc.vmmap, kern.proc.filedesc, kern.proc.kstack:** All return -1 (blocked by sandbox).
- **Sysctl tree walking:** The entire MIB tree enumeration returns 0 OIDs - heavily sandboxed.
- **machdep, debug, security.bsd, net.inet, kern.smp:** All return -1.

### 6.2 Thread Control Block (TCB)

The FS base register (TCB pointer) was read via the crash handler's ASLR oracle. The value is in the 0x88xxxxxxxx range - strictly userland. TCB dump shows all entries are userland addresses. This is not a viable KASLR vector.

### 6.3 Physical Memory via /dev/dmem0

The device opens successfully (fd=24) but only exposes the GPU GDDR6 aperture:
- Physical offset 0x0 returns GPU hardware register 0x80000000_C0012800
- Physical offsets beyond 4GB are all zeros
- All ioctl operations (DMEM_TOTAL, DMEM_AVAIL, allocate_direct_memory) fail
- No CPU DRAM or kernel memory is accessible through this device

### 6.4 Heap Scanning

An exhaustive scan of 10,240+ qwords in the userland heap found zero kernel pointers. All values in the 0xFFFFFFFF_xxxxxxxx range are bitmasks or sentinels, not real kernel addresses. Valid kernel pointers would be in the 0xFFFF8xxx_xxxxxxxx range.

### 6.5 libkernel Data Segment

The libkernel data segment was scanned for kernel pointers. None found in the first 1KB. The data segment contains only userland addresses.

### 6.6 fstat Values

fstat on fd 0 returns successfully. Field at +0x068 contains 0xFFFFFFFFFFFFFFFF - all-ones sentinel, not a kernel pointer.

### 6.7 Crash Handler as ASLR Oracle

When the process crashes (e.g., reading XOM pages), the crash handler leaks module base addresses with a magic value of 0x13371337. This provides userland ASLR defeat but no kernel address information.

---

## 7. Untested Attack Vectors

Based on the research so far, 16 probes are ready to send targeting the remaining attack surface. These are organized by priority:

### 7.1 Tier S+ - Scene-Proven Techniques

**Probe 43o: AF_ROUTE Socket KASLR Defeat**

The Relapse exploit (fw 7.00-13.60) defeated KASLR by reading kernel virtual addresses from AF_ROUTE socket routing messages. The routing table contains `rt_entry` structs with kernel function pointers. Sony patched the specific `aio_multi_wait` UAF that Relapse used, but may not have patched the information leak through routing structures.

The probe creates an AF_ROUTE (PF_ROUTE=17) raw socket, sends RTM_GET messages for various route targets (default route, loopback, gateway, self, broadcast, DNS), and scans every qword in the response for kernel pointers. Falls back to sysctl NET_RT_DUMP if the socket fails.

**Probe 43p: AIO via make_syscall**

AIO was only ever tested via `resolve()` (probes 19-19g), where it was sandbox-killed. The make_syscall bypass may allow AIO to survive, since the same pattern held for sysctl. Tests all 10 FreeBSD AIO syscalls in order from safest (aio_error) to most dangerous (aio_write), with post-test canary checks. Also sweeps syscalls 532-700 for undocumented Sony AIO-like syscalls (the Relapse exploit used a Sony-custom `aio_multi_wait`).

### 7.2 Tier S - Direct KASLR Defeat

**Probe 43a: kldstat**

On standard FreeBSD, `kldstat` (syscall 308) returns a `kld_file_stat` struct containing the kernel's load address at offset +0x50. For fileid=1 (the kernel itself), this would be the kernel base - KASLR defeated in one call. Also tests syscall 367 (mapped in an earlier sweep). Previous attempts used the wrong syscall number (306 is `kldfind`, not `kldstat`).

**Probe 43b: kldsym**

`kldsym` (syscall 337) resolves kernel symbols by name. If it works, we can look up any kernel function address directly (e.g., `printf`, `copyin`, `copyout`), completely bypassing KASLR.

**Probe 43d: Full kinfo_proc Dump**

A byte-by-byte scan of the complete 1096-byte kinfo_proc structure plus the filedesc structure. Previous scans checked at qword alignment; this probe reads every byte offset looking for kernel pointers that might span non-aligned boundaries.

### 7.3 Tier A - Bypass Testing

**Probe 43e: Blocked Syscall Bypass**

Tests thr_new(455), ioctl(54), dup(41), dup2(90), fstat(189), and pipe2(542) via make_syscall. If thr_new works, threading becomes available and race condition attacks are possible. If ioctl works, device driver attack surfaces open up.

**Probe 43c: sysarch GET_GSBASE**

The GS base register on FreeBSD often points to the kernel's `curthread` structure. `sysarch` with operation 130 (AMD64_GET_GSBASE) may leak this value. Previous attempts used operation 129, which is SET_FSBASE and crashed with a zero argument.

**Probe 43h: sceKernelMtypeprotect W^X Bypass**

Sony's `sceKernelMtypeprotect` (syscall 585) returned 1 (success?) in earlier testing. If this syscall can change memory protection types, it might bypass the W^X enforcement that blocks mprotect(EXEC).

### 7.4 Tier B - Exploitation Primitives

**Probe 43j:** Full kern.msgbuf read (up to 64KB) - boot messages may contain kernel addresses  
**Probe 43k:** sceKernelGetCpuUsage deep probe with proper buffers  
**Probe 43l:** mincore() as a KASLR side-channel oracle  
**Probe 43m:** PS5 socket option buffer overflow (256-byte buffers for 4-byte flags)  
**Probe 43n:** /dev/hid + ioctl via make_syscall  
**Probe 43f:** sysctl write paths (lower securelevel, enable coredump)  
**Probe 43g:** Sony syscall sweep (540-700 range)  
**Probe 43i:** ROP chain fn_addr redirect test  

---

## 8. Hard Constraints

These constraints have been thoroughly tested and represent real walls, not untested assumptions:

1. **W^X is absolute.** mmap(RWX) silently gives RW. mprotect(EXEC) always fails. No RWX regions exist in the process's memory map (309 VMAs scanned, 42 executable regions, all r-x or --x). There is no known bypass through standard FreeBSD memory management.

2. **Execute-only memory (XOM) kills past pcall.** System library .text segments are mapped --x (execute-only). Reading them causes SIGBUS that terminates the process instantly, even inside pcall(). Only the eboot's .text is mapped r-x (readable + executable). This means the `syscall; ret` gadget in libkernel cannot be read or located by scanning - we must use the existing fn_addr mechanism.

3. **No threading.** fork(2), rfork(251), and thr_new(455) all return -1 via resolve(). This blocks traditional race condition primitives. However, these are untested via make_syscall (probe 43e).

4. **Per-connection ASLR.** Each connection spawns a new process. All addresses must be re-derived. The ASLR bypass via dynlib_get_info makes this manageable for userland, but kernel ASLR is independent.

5. **No kernel pointers leak to userland.** 10,240+ qwords scanned in the heap, plus kinfo_proc, fstat, TCB, libkernel data, sysctl outputs - all clean. Every 0xFFFFFFFF_xxxxxxxx value is a sentinel or bitmask.

6. **Instant-kill syscalls exist.** minherit(250), msync(226), and kenv(390) terminate the process immediately with no recovery. These must be avoided in all probes.

---

## 9. Methodology

### 9.1 Probe Design

Each probe is a self-contained Lua 5.1 script designed for a single research question. Probes follow a strict template:

- **Crash classification** (LOW / MODERATE / HIGH / RISKY) declared at the top
- **Standard helper functions** included in every probe: `to_num()`, `make_syscall()`, `safe_rd()`, `safe_rq()`, `safe_wd()`, `safe_wq()`, `get_hi_lo()`
- **pcall wrapping** around all risky memory operations
- **No hardcoded addresses** - everything derived from dynlib_get_info or parsed from loader state
- **uint64 for all 64-bit values** - Lua 5.1 numbers are IEEE 754 doubles, which lose precision above 2^53
- **Progress printing** to keep the TCP connection alive (30-second per-read timeout)
- **Canary checks** after dangerous operations to verify process integrity

### 9.2 Execution Environment

Probes are sent via `tools/send_probe.py`:
```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua
```

The tool connects to 10.0.0.96:9026, sends the Lua source with an 8-byte LE length prefix, and captures the response. Results are saved to `results/<phase>/<name>_<timestamp>.txt`.

### 9.3 Research Phases

The research progressed through 10 phases over the course of October 2026:

| Phase | Focus | Probes | Key Result |
|-------|-------|--------|------------|
| 1 | Identity & Layout | 01-08 | Firmware ID, ~40 working syscalls mapped |
| 2 | Kernel Objects | 09-21 | Threading blocked, AIO killed, UMTX mapped |
| 3 | Signals & Code Exec | 22-26 | W^X confirmed, XOM confirmed, sigaltstack dead |
| 4 | IPC & Network | 27-31 | writev works, SCM_RIGHTS works, TCP_INFO no leaks |
| 5 | Buffer I/O | 32-33 | F_SETFL is cosmetic, MSG_DONTWAIT is real nonblocking |
| 6 | Raw Packets | 34-39 | RAW sockets work, ip_reass correct, port policy mapped |
| 7 | Heap Exploitation | 40-41 | GPU mmap R/W, ASLR bypass, ROP chain hijack |
| 8 | Live Network | 42 | TCP connect-back, ktimer, kernel info via sysctl |
| 9 | KASLR Defeat | 42b-42j | All attempts failed (9 probes, 0 kernel pointers) |
| 10 | Untested Theories | 43a-43p | 16 probes ready, informed by Relapse intelligence |

### 9.4 Dead End Catalog

The following approaches were fully explored and confirmed as dead ends:

| Approach | Why It Failed |
|----------|--------------|
| sigaltstack kernel write | copyout() validates destination addresses |
| mprotect(EXEC) | Always denied, hard W^X enforcement |
| XOM gadget scanning | Reading execute-only pages kills past pcall |
| Threading via resolve() | fork/rfork/thr_new all return -1 |
| AIO via resolve() | Sandbox-killed instantly |
| kqueue kevent | fd allocates but kevent always returns -1 |
| ioctl via resolve() | All blocked |
| Sysctl kernel pointer leaks | All scanned values are sentinels |
| TCP_INFO | 236 bytes, no kernel pointers |
| minherit / msync | Instant-kill syscalls |
| memfd_create | Stub, returns fake fd=1 |
| /dev/dmem0 physical memory | GPU aperture only, no CPU/kernel DRAM |
| kenv | Sandbox kill |
| TCB (FS base) | Userland only (0x88xxxxxxxx) |
| libkernel data segment | No kernel pointers |
| Vtable corruption triggers | Lua GC doesn't dereference through [+00] |
| pipe via make_syscall | Returns fds 0,0 (dead) |
| kldstat at syscall 306 | 306 is kldfind, not kldstat (crashed) |
| sysarch command 129 | 129 is SET_FSBASE, not GET_GSBASE (crashed) |
| F_SETFL O_NONBLOCK | Cosmetic only, kernel ignores it |
| SOCK_NONBLOCK flag | Crashes socketpair |
| sendto/recvfrom via resolve() | Crashes the resolver |
| PS5 custom socket options | Boolean flags, not exploitable |
| Heap vtable redirect | 8 trigger attempts, none caused dereference |
| Sysctl tree enumeration | Returns 0 OIDs, fully sandboxed |

---

## 10. The Path Forward

The exploitation primitives are complete. The only remaining barrier is KASLR defeat. Once the kernel base address is known:

1. **Kernel symbol resolution becomes possible.** Using hammer-83's offset methodology (adapted for fw 14.10), we can locate kernel functions like `copyin`, `copyout`, `kernel_map`, etc.

2. **fn_addr redirect enables kernel function calls.** Point fn_addr at any kernel function, set arguments via the ROP chain slots, and call `make_syscall()`. This gives arbitrary kernel function invocation with controlled arguments.

3. **Kernel R/W follows directly.** Call `copyin`/`copyout` with controlled arguments to read/write arbitrary kernel memory.

4. **Hypervisor bypass is the final target.** With kernel R/W, hypervisor data structures become accessible for analysis and modification.

The 16 probes in phase 10 are designed to find that kernel base address. The most promising are:

- **43o (AF_ROUTE)** - Worked on PS5 in the wild via the Relapse exploit
- **43a (kldstat)** - Standard FreeBSD kernel address disclosure
- **43b (kldsym)** - Direct kernel symbol resolution
- **43p (AIO bypass)** - If AIO works via make_syscall, race conditions reopen
- **43e (blocked syscall bypass)** - If thr_new works, threading becomes available

---

## 11. Conclusion

This research demonstrates that the PS5's userland security on firmware 14.10, while significantly hardened compared to earlier firmware, can be systematically analyzed and partially defeated. We achieved:

- **Complete sandbox bypass** through the make_syscall technique
- **Full heap R/W** through GPU mmap adjacency
- **Total userland ASLR defeat** across all 39 loaded modules
- **Confirmed ROP chain hijack** with writable function pointer and all argument slots

The kernel's defenses remain intact - KASLR has not been defeated, and no kernel pointers have leaked to userland despite exhaustive searching. However, 16 targeted probes informed by both FreeBSD kernel internals and proven PS5 exploitation techniques (Relapse) are ready to test.

The gap between our current position and kernel R/W is exactly one piece of information: the kernel base address. Every other primitive needed for the full chain is confirmed working.

All research data, probe scripts, result logs, and analysis are available in the repository for community contribution and independent verification.

---

## Appendix A: Statistics

| Metric | Value |
|--------|-------|
| Total probes executed | 80+ |
| Successful probes | ~55 |
| Crashed probes | ~12 |
| Killed probes | 2 |
| Hung probes | 4 |
| Result files | 121 |
| Working syscalls confirmed | 40+ |
| Blocked syscalls confirmed | 17+ |
| Instant-kill syscalls | 3 |
| Dead ends cataloged | 24 |
| Untested probes ready | 16 |
| Kernel pointers found | 0 |

## Appendix B: VM Map Summary

From probe 03, the process memory layout:

| Region | Address Range | Size | Permissions | Notes |
|--------|--------------|------|-------------|-------|
| Eboot text | 0x10BBC000-0x11050000 | 4.6 MB | r-x | Readable, gadget source |
| GPU/heap | 0x2006E0000-0x3106E0000 | ~4.3 GB | rw- | GPU mmap area, heap R/W primitive |
| System libs | 0x800000000-0x83FC60000 | ~1 GB | --x / r-- / rw- | XOM .text, readable .rodata/.data |
| TLS/TCB | 0x880550000-0x881600000 | ~16 MB | rw- | Userland only |
| Stack | 0x7EF1D4000-0x7EF2A8000 | 64 KB | rw- | Per-thread with 16KB guard pages |
| GPU registers | 0xFE0000000-0xFE0400000 | 4 MB | mixed | Hardware register space |

Total VMAs: 309. Executable regions: 42. **RWX regions: 0.**
