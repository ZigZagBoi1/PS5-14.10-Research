# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Critical Context

## Current Evidence Correction — 2026-10-18

This section supersedes older, more confident statements that remain in the historical notes below.

- Probe 45c recorded sysctl/getpid results persisting after selected fn_addr changes and corruption of chain entries 0–7 in one run. This contradicts the earlier dependency model for those tested calls; it does not identify the complete dispatch implementation or establish that every path ignores those fields.
- Probe 46b reports a shared C-function __call address, but its log is truncated and does not establish the function's implementation or a redirection primitive.
- Probes 54o and 54p are incomplete: 54o stops immediately after writing the candidate `+0x20` field, while 54p stops after printing the `xor eax,eax;ret` gadget address. The captures contain no post-call marker, restore confirmation, or returned Lua value. A timeout/reset is a transport outcome and does not establish native code execution.
- Native code execution, a 14.10 kernel vulnerability, kernel read/write, and KASLR defeat are not demonstrated.
- Probes 43o, 43p, 43a/43b, and 47b have evidence gaps. Retest 53d established qword writability/restoration across the tested CClosure offsets; 54o/54p remain incomplete redirect experiments. Scripts 52a/52b have no saved outputs.
- The captures labeled 13.60 are fixed ranges, not complete kernel sections; acquisition authenticity remains unresolved; no verified 14.10 kernel image is present in this repository.


### The Environment
- **Target:** PS5 at YOUR_PS5_IP:9026, firmware 14.10
- **Kernel:** FreeBSD r230171 (Sep 28 2026), 16KB pages
- **Entry:** Lua 5.1 scripts sent over TCP (8-byte LE length prefix + raw source)
- **Tool:** `python tools/send_probe.py --save probes/<path>.lua` (writes a JSON run record; `tools/run_probe_batch.py` provides bounded sequential execution)
- **Per-connection ASLR:** Fresh process spawns for every TCP connection. All addresses must be re-derived each run.

### What We Have (Confirmed Working)
| Primitive | How |
|-----------|-----|
| Tested raw syscall invocation | make_syscall(N) bypasses the Lua syscall.resolve() filter for tested numbers; kernel-side restrictions still apply |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages |
| Userland module-base discovery | dynlib_get_info(593) returned base information for 39 userland modules; kernel ASLR is separate |
| eboot gadget catalog | Gadget bytes were read from RX eboot; no working execution path has been established |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |
| sys 649 module member query | Returns userland addresses for member types 1-4, 7, 8 across module handles (no kernel pointers). Probe 54k, 2026-10-18 |

### What's Blocked (Hard Walls)
- **Native code execution is not demonstrated** — 45c results persisted after selected metadata mutations; this undermines the earlier execution interpretation but leaves dispatch implementation unknown
- **W^X enforced** — `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails; mtypeprotect may change perms but no jump path exists
- **Execute-only memory (XOM)** — system lib .text is XO (reading crashes); eboot is RX
- **No threading** — `fork`, `rfork`, `thr_new` all blocked (confirmed via both resolve() and make_syscall)
- **AIO 661-670 — confirmed hard wall** — sys 661 instantly kills the process on 14.10. Tested via probes 54c and 54f section G (2026-10-18). The earlier 43p inconclusive status is resolved: AIO event syscalls are lethal.
- **No kernel pointers found** — extensive scanning has found none. AF_ROUTE retest 53b confirmed kernel sanitizes route messages (zero kernel pointers). kldstat/kldsym (43a/43b) retest 53c never ran (connection refused). No KASLR defeat path identified.
- **ROP-shaped metadata role is unknown** — tested calls persisted after selected fn_addr and chain mutations; do not treat the fields as a function-call primitive

### Tested raw syscall behavior
The Lua loader's resolver filter blocks some syscall names. Selected calls still returned results through make_syscall(); this bypasses the Lua-side filter only for those tested calls, and kernel-side restrictions remain. The full dispatch implementation is unknown.

## How to Write Probes

### Probe Template
```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE XX: one-line description
--
-- Context: what we know, what we're testing, why

print("=== PROBE XX: TITLE ===")
print("")

-- Standard helpers (ALWAYS include these)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
```

### Lua 5.1 Constraints (MUST follow)
1. **uint64 for all addresses >32 bits:** `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall everything risky:** `pcall(function() return memory.read_qword(addr) end)`
3. **No `goto`/labels** — Lua 5.1 doesn't have them. Use `repeat...until true` + `break`
4. **XO pages kill past pcall** — reading execute-only memory terminates the process. Never read system lib .text sections. Eboot .text is RX and safe to read.
5. **Fresh ASLR every connection** — never hardcode addresses. Always re-derive from `dynlib_get_info` or `tostring(syscall.pipe)`.
6. **memory.alloc(N)** for heap buffers. Always zero them before use.
7. **Kernel pointer detection:** `h >= 0xFFFF8000` where `h, l = get_hi_lo(val)`. Values like `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are bitmasks/sentinels, NOT real kernel pointers.

### How make_syscall Works
```lua
local sc = make_syscall(202)  -- sysctl
local ret = sc(arg1, arg2, arg3, arg4, arg5, arg6)
-- Arguments are uint64 values
-- Returns: the syscall return value
```
Historical hypothesis only: the heap contains writable ROP-shaped metadata and argument slots. Probe 45c recorded tested calls continuing after selected mutations, so this does not establish that the loader calls fn_addr or executes the chain.

### Getting Key Addresses
```lua
-- Userland module-base discovery; this does not defeat kernel ASLR
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

-- Historical metadata addresses; not established as execution controls
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

-- GPU mmap (heap R/W primitive)
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
```

### Sysctl Pattern
```lua
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
local ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
```

## Repository Layout

```
probes/
  phase1_identity_layout/    # 01-08: system ID, syscalls, memory
  phase2_kernel_objects/     # 09-21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/    # 22-26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/        # 27-31: threading, fd passing, sockets
  phase5_buffer_io/          # 32-33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/        # 34-39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/  # 40-41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/       # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/       # 42b-42j: KASLR attempts (mostly failed)
  phase10_untested_theories/ # 43a+: theory-driven probes (results recorded; 2026-10-17 audit)
  phase11_network_attacks/   # 48a-50d: SCTP, IPv6, TCP inject, exotic protocols
  phase12_kernel_analysis/   # 51a+: kernel dump sysent analysis, Sony syscall survey
  phase13_52batch/           # 52a+: Sony syscall survey 627-676 + 624 oracle (written, queued)
phase13_53batch/           # 53a-53d: evidence-audit retests (AIO, AF_ROUTE, kldstat, CClosure)
results/                     # Output logs (same phase structure)
tools/                       # send_probe.py, run_session40.py, tcp_fuzz_server.py
docs/
  ATTACK_SURFACE.md          # Complete syscall status map
  FINDINGS.md                # Detailed technical findings
  PROBE_INDEX.md             # Every probe with status and key result
  STRATEGY.md                # Exploit strategy and dead ends
  UNTESTED_THEORIES.md       # 17 theories ranked by priority
```

## Known Dead Ends (Don't Repeat These)

> Note (2026-10-17 evidence audit): entries marked inconclusive / "not established" reflect claim downgrades — see docs/EVIDENCE_AUDIT_2026-10-17.md.

- **sigaltstack kernel write** — copyout() validates destinations
- **mprotect(EXEC)** — always fails, hard W^X
- **XOM gadget scan** — reading XO pages crashes past pcall
- **Threading via resolve()** — fork/rfork/thr_new all -1
- **AIO** — **CONFIRMED DEAD**: sys 661 instantly kills the process on 14.10 (probes 54c/54f, 2026-10-18). Previous 43p inconclusive status resolved.
- **kqueue** — fd allocates but kevent returns -1
- **ioctl via resolve()** — all blocked (untested via make_syscall)
- **sysctl kernel pointer leaks** — all scanned pointers are sentinels (0xFFFFFFFF_*)
- **TCP_INFO** — 236 bytes, no kernel pointers
- **minherit/msync** — outcomes unresolved: probe 38 ends at the minherit section header; 42b ends after the msync section prints its region address. Neither log records a call result or establishes a termination cause.
- **memfd_create** — stub, does nothing
- **/dev/dmem0** — opens but all operations fail (GPU partition only)
- **kenv** — outcome unverified: 42a/42g2 captures stop at the kenv header without a call result or kill record
- **TCB (FS base)** — userland only (0x88xxxxxxxx)
- **libkernel data segment scan** — no kernel pointers
- **kldstat at syscall 306** — 306 is `kldfind` (crashed on bad arg). Real FreeBSD `kldstat` is 308; sweep 02 had 367. Probe 43a tests both.
- **sysarch command confusion** — 129 is `SET_FSBASE` (calling with 0 crashes userland). Real `GET_GSBASE` is 130.
- **/dev/dmem0 physical memory** — GPU aperture only; phys 0 = GPU HW reg `0x80000000_C0012800`, 4GB+ unmapped/zeros.
- **pipe(42) via make_syscall** — returns fds 0,0 (dead)
- **ROP chain hijack / fn_addr redirect** — 45c observed tested calls returning normally after selected metadata mutations; no arbitrary function-call primitive is established and the full dispatch path is unknown
- **W^X bypass via mtypeprotect + fn_addr** — earlier code-execution claim is unsupported; mtypeprotect returns did not prove code-page execution, and 45c undermines the proposed dependency for tested calls
- **Shellcode execution via fn_addr** — proposed writes did not land and results do not establish shellcode execution; the evidence does not prove every path is incapable of executing code
- **AF_ROUTE KASLR (Relapse technique)** — **CONFIRMED DEAD**: retest 53b delivered RTM_GET (hdr=152, write ret=168), received valid 136-byte response (version=5, type=4, pid=112), but all payload is zeroed sockaddr structures — zero kernel pointers. Kernel sanitizes route messages on 14.10. (probes 43o, 53b retest 2026-10-18)
- **AIO via make_syscall** — **CONFIRMED**: sys 661 instantly kills process. "Instant kill" IS established (probes 54c/54f, 2026-10-18).
- **kldstat/kldsym via make_syscall** — inconclusive: 43a/43b logs are header-only (145 B / 116 B), no output and no kill record (retest 53c pending; 2026-10-17 audit).
- **kinfo_proc kernel pointers** — full 1096B dump: only sentinels, no real kernel pointers.
- **kern.proc.filedesc/vmmap** — blocked (ret=-1)
- **sysctl operations (43f)** — the write labeled `kern.securelevel` returned -1. Reads labeled `kern.coredump`, `security.bsd.unprivileged_proc_debug` and `kern.maxproc` returned -1, so their conditional writes were not reached. `kern.somaxconn` read returned 0/value 1024; no write was attempted. See `results/43f_sysctl_write_20261016_180756.txt`; these labels follow the probe's assumed MIB mappings.
- **sysarch GET_GSBASE** — returns 0, no kernel pointer
- **ioctl via make_syscall** — returns -1 for all tested codes
- **dup/dup2 via make_syscall** — returns -1
- **thr_new via make_syscall** — crashes process
- **kern.msgbuf** — returns only 8 bytes (filtered)
- **mincore KASLR oracle** — all kernel VA probes return -1
- **sockopt overflow** — kernel clamps copy length, not exploitable
- **/dev/hid ioctl** — Sony error 0x80740004 on all codes
- **Syscall 557** — saved 46a/47a tests show argument-dependent returns, including a linear version pattern for tested positive versions in 47a and a special version-zero result. No kernel pointer or exploit was demonstrated; full semantics and exploitability remain unresolved.
- **Syscall 620** — the saved 46a re-run returns 0 for its tested inputs; sentinel checks report no changes in their monitored windows. The zero-struct dump used the same incorrect baseline as 557 and is not write evidence. Full semantics remain unresolved; see `docs/SYSCALL_557_14_10_EVIDENCE.md`.
- **CClosure C function pointer redirect** — retest 53d confirmed ALL 7 offsets (+0x00 through +0x30) are writable with successful restore. +0x30 was observed holding an eboot-range pointer, but the field consumed by dispatch is unresolved. Probes 54o/54p tested a `+0x20` candidate and stopped before a returned value or restore marker; no execution redirect is established.
- **SCTP chunk fuzzing** — 39 variants via loopback raw socket, zero crashes (probe 48b)
- **IPv6 extension header fuzzing** — 83 variants, zero crashes (probe 48c)
- **TCP state machine injection** — 182 crafted segments; the saved run reached COMPLETE. RST injection left the observed state ESTABLISHED, which does not by itself confirm RFC 5961 challenge ACK behavior. (probe 49a)
- **IPv6 fragment reassembly** — 280 fragments; the saved run reached COMPLETE. This does not establish RFC 5722 compliance. (probe 49b)
- **Exotic protocols (IGMP/GRE/ESP/AH/PIM/OSPF/VRRP)** — 86 packets, zero crashes (probe 50a)
- **Sony syscall info leak** — 11 accessible syscalls deep-tested with output buffers, no kernel pointers in any output (probes 51a, 51b)
- **TCP state machine injection** — 182 crafted segments into ESTABLISHED loopback connection (RST, SACK, PAWS, option parser len=0/255, URG, zero-window, ACK storm, SYN flood). The saved run reached COMPLETE. TCP_INFO values at +108/+112 tracked sequence numbers in that run; this does not establish TCP hardening or RFC compliance. (probe 49a)
- **IPv6 fragment reassembly attacks** — 280 fragments targeting ip6_reass() (overlapping/teardrop, queue exhaustion 50+101-bomb, huge totals 65535+, atomic frags, interleaving, ext hdr combos, nested frag-in-frag). The saved run reached COMPLETE; fragment-drop behavior and RFC 5722 compliance were not independently established. (probe 49b)
- **Port binding ≥40000** — bind() returns -1 for ports ≥40000. Use 1024-32767 range.
- **sys 572 VM info query** — returns -1 for (addr, outbuf, size) layout; returns 0 but empty buffers for (outbuf, cmd, size) layout across cmds 0-5. No useful VM metadata extracted. (probes 54i, 2026-10-18)
- **sys 626 RDMSR precise (cmd=1 + cmd=4)** — cmd=1 returns -1 for all 16 PMC indices (MSR 0xC0010231+); cmds 1-6 all return -1 for idx=0; narg sensitivity 0-8 all -1. cmd=4 returns 0 but output is all zeros (counters not running). WRMSR (cmd=2) returns -1. No MSR data accessible. (probe 54a2, 2026-10-18)
- **sys 629 jail bypass** — all arg patterns (direct values, pointer-to-value for arg1/arg2) return -1. No fast path. Process crashed on kld* retests. (probe 54b, 2026-10-18)
- **AIO 661-670 via make_syscall** — sys 661 instantly kills process. Confirmed hard wall on 14.10, resolving the 2026-10-17 inconclusive status. (probes 54c, 54f section G, 2026-10-18)
- **sys 626 RDMSR** — returns -1 for all 11 MSR indices (TSC, APIC_BASE, SYSENTER_EIP, EFER, STAR, LSTAR, CSTAR, SFMASK, FS_BASE, GS_BASE, KERNEL_GS_BASE) across 3 arg layouts. Blocked on 14.10. (probes 54k, 2026-10-18)
- **sys 567 RDMSR read** — returns -1 for all MSR indices with both flat and struct arg layouts. (probe 54k, 2026-10-18)
- **sys 612** — returns -1 for all tested member values 0-8. (probe 54k, 2026-10-18)
- **sys 598 dynlib context** — returns -1 for all arg patterns tested. (probe 54f section A, 2026-10-18)
- **sys 639/638 memory region** — returns -1 for all address ranges including zero, low, heap, module, libkernel, and kernel VA. (probe 54f section C, 2026-10-18)
- **net.route.iflistl kernel pointer scan** — returned 6536 bytes but all values are sockaddr/MAC/interface structures, no kernel pointers. (probe 54f section D, 2026-10-18)
- **sys 593 deep struct scan (+0x148/+0x150)** — values across all 39 modules are NID hashes/fingerprints (random high bits but not in kernel VA range 0xFFFF8xxx), not kernel pointers. (probe 54f section F, 2026-10-18)
- **sys 643 chicken switches** — all 32 bits accepted (ret=0 for each), 0xFFFFFFFF OR'd into process+0xa34. No observable effect: mprotect(RWX) still fails, fork still blocked, kldstat still blocked. Field does not control W^X, sandbox, or syscall filtering. (probe 55a, 2026-10-18)
- **sys 548 batch VM ops** — all operation codes (0, 2, 3) and arg layouts return ret=-1, processed=0. Dead on 14.10. (probe 55b, 2026-10-18)
- **sys 622 device control** — every command (0x100-0x520, 400+ commands) returns ret=0 with buf[0]=0x800E0001 (Sony error "no device context"). No crashes, no variation, no kernel pointers. Process lacks initialized GPU device context. (probe 55c, 2026-10-18)
- **sys 548 batch VM ops** — all operation codes (0=new mapping, 2=protection update, 3=anonymous mapping) return ret=-1, processed=0. Different code path from mprotect but equally blocked. W^X not bypassable via this route. (probe 55b, 2026-10-18)
- **sys 622 device control multiplexer** — all 400+ commands across ranges 0x100-0x520 return ret=0 with buf[0]=0x800E0001 (Sony error: no device context). Every arg1 value tested gives same result. Process lacks GPU/display context so all commands early-exit. No data, no crashes, no kernel pointers. (probes 55b/55c, 2026-10-18)
- **sys 601 process control multiplexer** — most commands return -1 (no init state). cmd 0x00 ret=0 buf=0x100, cmds 0x07/0x09/0x0d/0x13/0x14/0x19 ret=0 with empty buffers. "Backdoor" cmd 0x0c returns -1 for all auth patterns. "Write" cmd 0x12 returns -1. Kernel page copyout cmd 0x10 returns -1. Process lacks initialization. Game crashed during full scan. (probe 55d, 2026-10-18)
- **sys 674 VM map kernel pointer search** — 317 regions enumerated with full 72-byte records. All addresses are userland VA (max 0xF_E0400000). Zero kernel pointers found at any offset. Record layout decoded: +0x00 start addr, +0x08 end addr, +0x18 protection, +0x20 name string. GPU/device regions at 0x8-0xF range are userland device-mapped memory. (probes 55e/55f, 2026-10-18)
- **sys 672 dynlinker library list** — ret=-1 (predicate gate failed). Dead. (probe 55e, 2026-10-18)
- **sys 676 CPU mode update** — ret=-1 (process+0xc81 gate). Dead. (probe 55e, 2026-10-18)
- **sys 673 page remap** — ret=-1. GPU mmap backing object isn't type 11 required by the handler. (probe 55e, 2026-10-18)
- **sys 675 reset global state** — ret=0, resets 3 globals. mprotect(RWX) still fails after reset. Does not control W^X. (probe 55e, 2026-10-18)
- **sys 587 credential metadata** — ret=0, returns 0x88 bytes. Only +0x0C = 0x20000000 (single capability bit). No kernel pointers. (probe 55e, 2026-10-18)
- **sys 671 resource class query** — sel=-1 mode=1: A=6144, B=3948. mode=2: A=2560, B=2014. Explicit selectors 0-10 all failed (needs credential bit 62). Memory budget values only. (probe 55e, 2026-10-18)

## Sending Probes

```bash
# Via Python (if installed):
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# Via native PowerShell (no Python required):
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save

# For TCP connect-back fuzzing:
python tools/run_session40.py --ps5-ip YOUR_PS5_IP --fake-ip YOUR_TEST_HOST_IP
```

Results are saved to `results/<phase>/<name>_<timestamp>.txt`.

## Current Attack Priority (Updated 2026-10-18 — post-55g)

**Evidence update:** Phase 14 (54a–55g) exhaustively tested KASLR candidates, Sony syscalls, and device control paths. All conventional KASLR defeat paths are dead (AF_ROUTE sanitized, RDMSR blocked, no kernel pointers in sys 674 VM map, sys 649 module members, kinfo_proc, or net.route.iflistl). AIO is confirmed lethal. sys 622/601/548 are dead.

**★★ CClosure +0x20 write HANG (probe 54q):** Writing a different value to type()'s CClosure+0x20 caused a 15-second timeout (IDLE_TIMEOUT). The write itself blocked — not the redirected call. Writing the same value back (no-op) succeeded instantly. This is the most anomalous signal observed and is the top investigation priority. Probe 55g is a diagnostic to narrow the cause.

**REMAINING PRIMITIVES:**
- Arbitrary syscall via `make_syscall(N)` (C-level wrapper, confirmed working)
- Heap R/W via GPU mmap (256+ pages)
- Userland ASLR bypass via `dynlib_get_info(593)`
- Full process VM map via sys 674 (317 named regions with protections)
- Network packet injection (RAW socket + IP_HDRINCL, TCP connect-back)
- **CClosure redirect characterization (ACTIVE LEAD)** — 54q's +0x20 write hung for 15s. 55g diagnostic probe written. The dispatch mechanism and which field it consumes remain uncharacterized.
- **Syscall 624 observation** — values differ by one across two saved processes; no controlled VM-map test result exists to establish a live counter or side channel
- **11 accessible Sony syscalls** — 596, 585, 572, 624, 563-566, 606, 643, 640

**NEXT PROBES TO RUN:**
1. **55g CClosure write hang diagnostic** — narrow down what causes the +0x20 write to block (WRITTEN, READY)
2. **52a Sony syscall survey 627-676** — written, never run
3. **52b Syscall 624 heap oracle** — written, never run
4. **54r CClosure target bytes** — read-only inspection of +0x20 targets for multiple C functions (WRITTEN, READY)
6. **Loader internals** — find the C-level syscall dispatch, check for writable function pointers
7. **Evidence-audit retests (53b–53d)** — fixed AF_ROUTE RTM_GET, kldstat/kldsym, CClosure +0 write test (53a AIO retest no longer needed — confirmed dead)

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** ZigZagBoi1 <marwantech2004@gmail.com>
- **No AI attribution** in commits, PRs, or code.
- Commit messages should be short and descriptive of what changed.
