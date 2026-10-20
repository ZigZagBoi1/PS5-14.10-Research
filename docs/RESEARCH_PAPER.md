# PS5 Firmware 14.10 Kernel Exploitation Research

> **Evidence scope (2026-10-18):** The 45c controls concern selected syscall-object metadata mutations, not every loader path. Later 56c/56f captures record selected CClosure redirects to existing Lua C functions with returned values and restoration. Those userland results do not establish arbitrary native calling conventions, a working ROP chain, injected-page execution, kernel R/W, or KASLR defeat. See [the evidence ledger guide](RESEARCH_EVIDENCE.md) and Findings 79/82.

> **Historical scope:** The narrative below preserves the earlier 43–53 research state; its unrun/open labels and broad execution conclusions are not current status. Later research remains in the probe index and Findings 79–82. The 2026-10-17 audits are dated snapshots, not summaries of every later result.

> **Evidence status update (2026-10-18):** This paper preserves earlier hypotheses and interpretations. Read the evidence audit and probe index for current adjudications. Probe 45c recorded tested syscall results persisting after selected fn_addr and chain mutations; this contradicts the earlier dependency model for those calls but does not identify dispatch implementation. Probe 43o did not deliver its RTM_GET request; 43p contains no AIO result; 43a/43b are header-only; and 47b omitted CClosure offset +0. The paper's original probe set does not establish a 14.10 kernel exploit, kernel read/write, or native execution through fn_addr; later selected CClosure results are outside this narrative cutoff.

## From Userland Code Execution to the Edge of Kernel Memory

**Target:** PlayStation 5, Firmware 14.10  
**Kernel:** FreeBSD r230171 (Sep 28 2026)  
**Status:** Userland Lua execution, heap access, module-base disclosure, and tested raw syscall invocation are documented. Kernel read/write, KASLR defeat, and native code execution are not demonstrated.
**Repository:** https://github.com/ZigZagBoi1/PS5-14.10-Research

---

## Abstract

This paper records exploratory work on a PlayStation 5 running firmware 14.10 through a Lua 5.1 loader. The evidence supports userland memory access, module-base disclosure, and invocation of tested syscall numbers through the loader. Probe 45c recorded tested calls continuing after selected fn_addr and chain mutations, which contradicts the earlier dependency model for those calls; it does not identify the complete dispatch implementation. No function-call primitive is established through the tested fn_addr metadata. The paper's original probe set does not demonstrate kernel read/write, KASLR defeat, or native code execution. Several older probe interpretations were overstated or based on incomplete captures; the linked evidence audit records the corrected claims, contradictions, and remaining tests.

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

### 4.1 Lua Resolver Filter and Tested Raw Syscall Calls

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

The saved probes show that selected syscall numbers produce results through make_syscall() even when the Lua resolver filter blocks their names. This establishes behavior for those calls and arguments only; it does not establish unrestricted kernel syscall access or bypass kernel-side policy.

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

### 4.4 Historical ROP-shaped Metadata Interpretation — Not an Established Call Path

Probes 41v and 42i mapped ROP-shaped metadata in the heap and a candidate gadget sequence. The original interpretation treated this structure as an active function-call primitive; probe 45c later recorded tested syscall results persisting after selected metadata mutations, so that execution role is not established.

**Observed metadata and limits:**

- Probes 41v/42i mapped a ROP-shaped heap structure and catalogued candidate eboot gadget bytes.
- Probe 41z reported that the metadata, argument slots, and selected chain entries could be read and written from the userland heap.
- These observations established writable data and gadget bytes, not a working control-flow path.
- Probe 45c later recorded tested syscall results persisting after selected fn_addr changes and corruption of chain entries 0–7. This contradicts the earlier dependency model for those calls; the complete dispatch implementation remains unknown.

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

The earlier hypothesis assumed a syscall; ret gadget in execute-only libkernel text had to be invoked through fn_addr. Probe 45c's mutation results contradict that dependency for the tested calls; how dispatch works is unresolved.

### 4.5 Historical ROP Chain Hijack Hypothesis — Not Demonstrated

Probe 41z reported that the ROP-shaped metadata was approximately 146 pages from the GPU-mapped region and that selected metadata and argument slots could be changed and restored. These are userland heap observations.

The earlier interpretation proposed redirecting fn_addr and using the next make_syscall() call to invoke an arbitrary function. Probe 45c recorded sysctl/getpid results persisting after selected fn_addr mutations and corruption of chain entries 0–7. The expected redirection effect was not demonstrated. The dispatch implementation, and whether these fields affect any other path, remain unknown.

**Current conclusion:** No arbitrary function-call primitive, native code execution, or kernel read/write is established by these observations. Treat the historical redirect recipe as an unvalidated hypothesis, not a current procedure.

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
- **AIO:** Older resolver-based probes reported blocked calls; probe 43p's saved output ends before the first raw-call result, so raw-path status is unresolved.
- **mprotect(74)** - PROT_EXEC always denied
- **kevent(363), timeout-dependent observations:** saved probes 20/21 record successful registration and polling with zero timeouts; probe 30c records `rv=-1` for combined add+poll with a 100ms timeout. This is not a generally blocked syscall, and timeout causality remains unproven. See [the evidence reconciliation](KEVENT_TIMEOUT_VARIABLE.md).
- **Obscure sysctls:** kern.proc.vmmap, kern.proc.filedesc, kern.proc.kstack, kern.file, kern.proc.auxv, net.inet.tcp.pcblist, security.mac - all blocked
- **procctl:** ASLR_STATUS, ASLR_CTL, STACKGAP_STATUS, NO_NEW_PRIVS_STATUS - all blocked

### 5.3 Abrupt-Termination Reports and Capture Limits

Older notes attribute abrupt process termination to these calls. A truncated network capture alone cannot distinguish a kernel termination from a Lua error, connection loss, or capture truncation:

- **minherit(250)** - historical termination attribution is unverified; probe 38 ends at its minherit section header without a result
- **msync(226)** - probe 42b ends after its msync region address; no result or termination cause is recorded
- **kenv(390)** - unresolved: 42a and 42g2 end at the call header without a result or kill record

Do not infer a sandbox or kernel kill from an absent output tail. Use the per-call markers and record independent console-side signals for future tests.

### 5.4 The make_syscall Question

The critical open question: **which "blocked" syscalls actually work via make_syscall?**

We know sysctl(202) is blocked by `resolve()` but works via `make_syscall()`. Probe 43e is designed to test thr_new(455), ioctl(54), dup(41), dup2(90), fstat(189), and pipe2(542) through the bypass. If threading or ioctl works, entirely new attack vectors open up.

Probe 43p was designed to test whether AIO calls survive through `make_syscall()`, but its saved output ends immediately before the first call result (`aio_error`, syscall 317). The planned later Sony scan, including syscall 663, is not recorded as reached. Thus the current log provides no raw-path AIO outcome on 14.10; see `docs/SECONDARY_EXPLOIT_AUDIT_13.60.md`.

---

## 6. KASLR Defeat Attempts

Probes 42b–42j examined several possible disclosures. No validated kernel address was identified in the reviewed outputs, but not every candidate path was validly exercised: 43o failed to deliver its AF_ROUTE request, 43a/43b contain only headers, and other captures are partial. This section records the bounded observations and their limitations.

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

An examined scan of more than 10,240 qwords in the userland heap found zero kernel pointers in that scanned region. Values in the `0xFFFFFFFF_xxxxxxxx` range observed in the cited structures were sentinels or bitmasks. This does not establish that every information-disclosure path was tested: successful AF_ROUTE delivery was not established, the KLD logs are header-only, and the CClosure `+0` field remains untested.

### 6.5 libkernel Data Segment

The libkernel data segment was scanned for kernel pointers. None found in the first 1KB. The data segment contains only userland addresses.

### 6.6 fstat Values

fstat on fd 0 returns successfully. Field at +0x068 contains 0xFFFFFFFFFFFFFFFF - all-ones sentinel, not a kernel pointer.

### 6.7 Crash Handler as ASLR Oracle

When the process crashes (e.g., reading XOM pages), the crash handler leaks module base addresses with a magic value of 0x13371337. This provides userland ASLR defeat but no kernel address information.

---

## 7. Untested Attack Vectors

The 43a–43p probe sources were sent previously, but several resulting captures are incomplete. Four evidence gaps have dedicated retests (53a–53d); they have not yet produced new console results. The older descriptions below are historical probe rationale, not current results:

### 7.1 Tier S+ - Scene-Proven Techniques

**Probe 43o: AF_ROUTE Socket KASLR Defeat**

The earlier AF_ROUTE hypothesis was based on public Relapse research for fw 7.00–13.60. The local 43o run did not test the disclosure: its RTM_GET write returned `-1`, and the read returned 108 bytes with zero detected pointers and unresolved attribution. Neither a 14.10 leak nor a 14.10 patch is established; retest 53b is prepared and unrun.

The probe creates an AF_ROUTE (PF_ROUTE=17) raw socket, sends RTM_GET messages for various route targets (default route, loopback, gateway, self, broadcast, DNS), and scans every qword in the response for kernel pointers. Falls back to sysctl NET_RT_DUMP if the socket fails.

**Probe 43p: AIO via make_syscall**

The historical probes 19–19g used `resolve()` and their summaries report tested calls blocked, but the exact per-call raw records should govern their scope. Probe 43p planned to test 10 FreeBSD AIO calls via `make_syscall()` and later scan syscalls 532–700 for Sony AIO-like calls; its saved output ends before the first result (`aio_error`, syscall 317). Thus neither its raw AIO outcome nor Sony syscall 663 was observed in that saved run.

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

2. **Execute-only memory (XOM) kills past pcall.** System library .text segments are mapped --x (execute-only). Reading them causes SIGBUS that terminates the process instantly, even inside pcall(). Only the eboot's .text is mapped r-x (readable + executable). This means the `syscall; ret` gadget in libkernel cannot be read or located by scanning - the earlier proposal to use fn_addr remains unsupported by the 45c controls.

3. **No threading.** fork(2), rfork(251), and thr_new(455) all return -1 via resolve(). This blocks traditional race condition primitives. However, these are untested via make_syscall (probe 43e).

4. **Per-connection ASLR.** Each connection spawns a new process. All addresses must be re-derived. The ASLR bypass via dynlib_get_info makes this manageable for userland, but kernel ASLR is independent.

5. **No kernel pointers were observed in the examined valid outputs.** The 10,240+ qword heap scan and the cited kinfo_proc, fstat, TCB, libkernel, and sysctl scans showed no validated kernel pointer. AF_ROUTE did not deliver its request, KLD logs are header-only, and CClosure `+0` remains untested.

6. **Some calls were associated with abrupt loader exits.** Available captures do not establish the mechanism for every reported exit; in particular, kenv(390) has no captured call result or kill record.

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
| 2 | Kernel Objects | 09-21 | Threading blocked; historical AIO probes limited; UMTX mapped |
| 3 | Signals & Code Exec | 22-26 | W^X confirmed, XOM confirmed, sigaltstack dead |
| 4 | IPC & Network | 27-31 | writev works, SCM_RIGHTS works, TCP_INFO no leaks |
| 5 | Buffer I/O | 32-33 | F_SETFL is cosmetic, MSG_DONTWAIT is real nonblocking |
| 6 | Raw Packets | 34-39 | RAW sockets work, ip_reass correct, port policy mapped |
| 7 | Heap Exploitation | 40-41 | GPU mmap R/W, ASLR bypass, ROP chain hijack |
| 8 | Live Network | 42 | TCP connect-back, ktimer, kernel info via sysctl |
| 9 | KASLR Defeat | 42b-42j | All attempts failed (9 probes, 0 kernel pointers) |
| 10 | Evidence-audit retests | 53a-53d | Four focused probes prepared; not yet run |

### 9.4 Dead End Catalog

The following catalog includes failed approaches and unresolved or scope-limited observations; it is not proof that each interface is generally unavailable:

| Approach | Why It Failed |
|----------|--------------|
| sigaltstack kernel write | copyout() validates destination addresses |
| mprotect(EXEC) | Always denied, hard W^X enforcement |
| XOM gadget scanning | Reading execute-only pages kills past pcall |
| Threading via resolve() | fork/rfork/thr_new all return -1 |
| AIO via resolve() | Historical probe summaries report tested calls blocked; see raw records for exact scope |
| kqueue kevent | Not a general dead end: zero-timeout registration/polling worked in probes 20/21; combined add+poll returned -1 with a 100ms timeout in 30c. Cause unresolved; see [the reconciliation](KEVENT_TIMEOUT_VARIABLE.md). |
| ioctl via resolve() | All blocked |
| Sysctl kernel pointer leaks | All scanned values are sentinels |
| TCP_INFO | 236 bytes, no kernel pointers |
| minherit / msync | Incomplete captures: 38 stops at the minherit section header; 42b after the msync region address. Outcomes and cause unresolved. |
| memfd_create | Stub, returns fake fd=1 |
| /dev/dmem0 physical memory | GPU aperture only, no CPU/kernel DRAM |
| kenv | Unresolved: 42a/42g2 captures stop at the call header without result or kill record |
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

## 10. Evidence-Guided Next Work

The current evidence does not establish an exploitation chain or a demonstrated kernel primitive. In probe 45c, tested syscall results persisted after selected `fn_addr` values and chain entries were changed. This contradicts the earlier dependency model for those tested calls, but it does not identify the complete dispatch implementation or establish how every syscall path behaves. The earlier chain from KASLR defeat to kernel access is withdrawn.

The immediate work is bounded evidence collection, not exploitation:

1. Run prepared probes 53a–53d individually, preserving source hashes, full raw output, firmware banner, and console restart state as specified in `docs/RETEST_PLAN_53.md`.
2. Rerun 42g only if its high-physical scan remains relevant; the earlier scan stopped at an undefined `MB`. Rerun 46a only if the incomplete neighbor sweep matters.
3. Complete partial syscall-survey coverage only for concrete questions; keep 51a/51c's untested ranges explicitly untested.
4. Treat any positive address-shaped value as a candidate until it is validated against authenticated 14.10 evidence and an independent source.

These steps can resolve specific observations. They do not presume that any result will yield a vulnerability, KASLR defeat, kernel read/write, or native execution.

---

## 11. Conclusion

The current evidence documents several userland behaviors on firmware 14.10:

- Lua execution and tested syscall invocation through `make_syscall()`
- Heap read/write across adjacent GPU-mapped pages
- Module-base disclosure for the examined process modules
- Writable ROP-shaped metadata; probe 45c's selected mutations contradict the earlier dependency model for tested calls, but its dispatch role remains unknown

No kernel read/write, KASLR defeat, or native code execution is established. Several earlier claims about AIO termination, AF_ROUTE patch status, KLD syscall termination, and CClosure writability exceeded the available logs. Probes 53a–53d are prepared to resolve those evidence gaps; they have not yet been run.

The path from these userland observations to kernel read/write remains open. A kernel address alone would not supply the missing, demonstrated kernel read/write or native execution primitive.

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
| Syscalls historically described as instant-kill | Several; claims vary in evidentiary support and are not a verified kernel-kill count |
| Dead ends cataloged | 24 |
| Prepared evidence-audit probes | 4 (53a–53d; not run) |
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
