# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Critical Context

## Current Evidence Correction — 2026-10-18

This section scopes the current claims; older notes describe their cited probe sets. See [the ledger guide](docs/RESEARCH_EVIDENCE.md). A writable pointer, a truncated write, a returned Lua value, and an identified dispatcher implementation are different evidence.

- Probe 45c recorded sysctl/getpid results persisting after selected fn_addr changes and corruption of chain entries 0–7 in one run. This contradicts the earlier dependency model for those tested calls; it does not identify the complete dispatch implementation or establish that every path ignores those fields.
- Probe 46b reports a shared C-function __call address, but its log is truncated and does not establish the function's implementation or a redirection primitive.
- Probes 54o and 54p are incomplete: 54o stops immediately after writing the candidate `+0x20` field, while 54p stops after printing the `xor eax,eax;ret` gadget address. The captures contain no post-call marker, restore confirmation, or returned Lua value. Probe 55g changes to binary output after its write marker, and 54r reads target bytes; neither alone identifies executed instructions. The 54q timeout has no returned-call evidence. Later 56c supplies discriminating output after selected +0x20 target changes.
- **Selected userland CClosure redirects are supported** (56c/56f, 2026-10-18): 56c records rawequal→rawget and rawget→type with distinguishing outputs and restoration; its tostring targets print 42 without a return-type check. 56f adds string.len/math.abs target-like values. General executable-target support, native-register argument control and internal calls to type() remain unverified. A 14.10 kernel vulnerability, kernel read/write, and KASLR defeat are not demonstrated.
- Probes 43o, 43p, 43a/43b, and 47b have evidence gaps. Retest 53d established qword writability/restoration across the tested CClosure offsets; 54o/54p remain incomplete redirect experiments. The older audit predates the saved 52a/52b outputs noted next.
- Scripts 52a/52b now have saved outputs (2026-10-18): 52a crashed at sys 631 (627-630 PCALL-FAIL); 52b confirmed sys 624 as a VM operation counter (+5 per mmap, zero jitter).
- **thr_create(430) kernel panic root cause identified** (PRs #30/#31, 2026-10-19): 13.60 Ghidra decompile of 22 functions shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK` (0x3). CS=0 from zeroed context → `ISPL(0)=0` → kernel-mode fault path → `pcb_onfault==NULL` → `trap_fatal` → panic. Fix hypothesis: CS=0x43/SS=0x3B should produce a user-mode thread. This is a 13.60 analysis; behavioral match with 14.10 panic (rv=0, TID returned, delayed panic, entry point irrelevant) is strong but identical code is not proven. Probe 80a tests the CS=0x43 fix on 14.10. **Probe 189a (2026-10-20) contradicts the missing-mask reading for 14.10**: CS=0x40 (same index, RPL 0) produced a live thread with no panic, so this firmware forces or replaces the selector; the defect is panic-only and cannot raise CPL.
- **The "umtx" probes called syscall 557, not `_umtx_op(454)** (2026-10-19): phase-1/2 probes 04/10-13 and the first revision of 82a bound `sc_umtx_op` to 557 (namedobj_create in the 13.60 capture). 56i2's section [F] is the only saved 454 execution (ops 5/21 ret=0, op 5 wrote a TID-shaped owner word). UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never exercised on 454, and FreeBSD 11 reads their key/params pointer from uaddr1. Do not treat probe 10's SHM/robust findings as umtx evidence. Probe 110a prepared; see docs/UMTX_454_EVIDENCE.md.
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
| eboot gadget catalog | Readable candidate bytes; 56e records nil gadget-test returns, but no working general ROP chain is established |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |
| sys 649 module member query | Returns userland addresses for member types 1-4, 7, 8 across module handles (no kernel pointers). Probe 54k, 2026-10-18 |
| CClosure function redirect | Selected existing Lua C targets produced target-like outputs and restore checks (56c/56f); arbitrary target/ABI and ROP support remain unverified |
| native.fcall_with_rax | Arbitrary userland function calls: getpid=0x22a, socket=0x16, close=0x0 confirmed (probe 129b) |
| C11 threading (Thrd_create) | 5+ concurrent threads with join; Atomic_fetch_add_8 as thread entry verified (probes 126g/126h) |
| UMTX_OP functional (op 5/21) | UMTX_OP_WAIT blocks correctly on value match; NWAKE_PRIVATE returns 0; MUTEX_LOCK writes owner TID (probes 56i2, 152k) |

### What's Blocked (Hard Walls)
- **fn_addr/ROP execution is not demonstrated** — 45c undermines that earlier model for tested calls. Later selected CClosure redirects are separate userland evidence; neither identifies the complete syscall dispatcher
- **W^X enforced** — `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails; mtypeprotect returns do not prove execute permissions or execution of the allocated test page
- **Execute-only memory (XOM)** — system lib .text is XO (reading crashes); eboot is RX
- **Threading works via `thr_create(430)`** — `fork`, `rfork`, `thr_new` stay blocked, but `thr_create(430)` starts a second userland thread when the context carries the handler's three gates (`+0x108 = 0x480`, `+0x0d0 <= 7`, `+0x110 = 0x10000`) plus `CS = 0x43` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8`, `SS = 0x3b` at `+0x100`; GP registers come from `+0x048..+0x0b8`. Probes 156c/156d: `rv = 0`, `thr_kill(tid, 0) = 0`, and the child executed `mov [rdi], rax; ret` in eboot and wrote `0xdeadbeefcafe` into a mapped page. The `+0x90..+0xb0` offsets used by 80a are not the fields the handler reads; that context is rejected at `+0x108` (`rv = -1`) with a TID written before validation. `thr_suspend(442)` returns -1 for the child, so a spinning thread outlives the probe; no kernel primitive and no TLS inside the child yet. See `docs/THREADING_ALIVE_14_10.md`.
- **A kill does not prove the slot is absent** (2026-10-20). It did, by the 173a reading: `make_syscall(4095)` kills and 4095 cannot have a handler. But 622 `ipmimgr_call` kills on six zeros and returned `ret=0` to a real request in 55c, so a present handler that faults on the arguments dies the same way, and a kernel that kills on a forbidden call would look identical. A kill is a result about the call, never about the handler. The range 661-670: 662, 663, 664, 666, 667, 669 return `-1` (present, rejecting zeros), 670 returns `0`, and 661/665/668 kill on zeros and need a real aiocb before anything can be concluded. See `docs/SYSCALL_ABSENT_VS_LETHAL.md` and `docs/AIO_RANGE_14_10_EVIDENCE.md`.
- **The measured sysent ends at 676** (2026-10-20): 677 through 707 each killed the process, thirty-one consecutive numbers including the five `nosys` slots, which reads as past-the-end rather than thirty-one hostile handlers. The 13.60 capture has 735 entries and names the tail (`wait6`, `pipe2`, `ppoll`, `get_phys_page_size`, `ioreq`, `mmap2`, `virtual_query_by_pid`), so either 14.10 dropped it or the tables number differently; it cannot be settled without a 14.10 image. Names above 676 are unverified and unreachable. See `docs/SYSENT_PRESENCE_14_10.md`.
- **No kernel pointers found** — extensive scanning has found none. AF_ROUTE retest 53b confirmed kernel sanitizes route messages (zero kernel pointers). kldstat/kldnext/kldsym all terminate the process on 14.10 (56k4/56k5, 171a). No KASLR defeat path identified.
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
- **Threading via resolve()** — fork/rfork/thr_new all -1. `thr_create(430)` via make_syscall starts a real thread once the gates and the `CS`/`RIP`/`RSP`/`SS` offsets are right (156c/156d); a zeroed ucontext still panics. See `docs/THREADING_ALIVE_14_10.md`.
- **AIO (sys 661)** — instantly kills the process on 14.10 for the two tested argument shapes (probes 54c/54f, 2026-10-18). Scope correction: both captures terminate at 661, so 662-670 were never reached; the earlier range-wide verdict is unsupported. Use `tools/syscall_isolation_sweep.py` for one-connection-per-number measurement. See `docs/AIO_RANGE_14_10_EVIDENCE.md`.
- **kqueue** — fd allocates; kevent works with zero timeout (split and combined calls, probes 20/21), only the 100ms-timeout call returns -1 (probe 30c). See `docs/KEVENT_TIMEOUT_VARIABLE.md`.
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
- **/dev/dmem0 physical memory** — GPU aperture only; phys 0 = GPU HW reg `0x80000000_C0012800`, 4GB+ unmapped/zeros. Retested 2026-10-21 with the working shape (`O_RDWR`, `PROT_READ`, `MAP_SHARED`): `dmem0` and `dmem1` both map and both read all-zero above offset 0, `dmem2` refuses every shape, and `PROT_READ|PROT_WRITE` is rejected unless the open used `O_RDWR` (probes 262a/263a).
- **pipe(42) via make_syscall** — returns fds 0,0 (dead)
- **ROP chain hijack / fn_addr redirect** — 45c observed tested calls returning normally after selected metadata mutations; no arbitrary function-call primitive is established and the full dispatch path is unknown
- **W^X bypass via mtypeprotect + fn_addr** — earlier code-execution claim is unsupported; mtypeprotect returns did not prove code-page execution, and 45c undermines the proposed dependency for tested calls
- **Shellcode execution via fn_addr** — proposed writes did not land and results do not establish shellcode execution; the evidence does not prove every path is incapable of executing code
- **AF_ROUTE KASLR (Relapse technique)** — **CONFIRMED DEAD**: retest 53b delivered RTM_GET (hdr=152, write ret=168), received valid 136-byte response (version=5, type=4, pid=112), but all payload is zeroed sockaddr structures — zero kernel pointers. Kernel sanitizes route messages on 14.10. (probes 43o, 53b retest 2026-10-18)
- **The whole `kld*` family plus `sysctlbyname`** — 307 (`kldnext`), 308 (`kldstat`), 337 (`kldsym`) and 570 (`sysctlbyname`) all kill the process on 14.10 (56k4/56k5, 171a, 172a). These are host-only syscalls in a console kernel and the kill is at touch, so no handler is reachable; 622's counterexample means the kill alone does not prove absence, but there is no argument shape that would make a console kernel implement `kldstat`. `docs/SYSCALL_ABSENT_VS_LETHAL.md`.
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
- **CClosure C function pointer redirect (pre-55g)** — retest 53d confirmed ALL 7 offsets (+0x00 through +0x30) are writable with successful restore. 55g records a boundary after the +0x20 write; 54r records target bytes. These do not identify the crash instruction or a successful 54q redirect. Later 56c/56f returned target-like results for selected existing Lua C targets; broader execution support remains unverified.
- **SCTP chunk fuzzing** — 39 variants via loopback raw socket, zero crashes (probe 48b)
- **IPv6 extension header fuzzing** — 83 variants, zero crashes (probe 48c)
- **TCP state machine injection** — 182 crafted segments into ESTABLISHED loopback connection (RST, SACK, PAWS, option parser len=0/255, URG, zero-window, ACK storm, SYN flood). The saved run reached COMPLETE. TCP_INFO values at +108/+112 tracked sequence numbers in that run; this does not establish TCP hardening or RFC compliance. (probe 49a)
- **IPv6 fragment reassembly attacks** — 280 fragments targeting ip6_reass() (overlapping/teardrop, queue exhaustion 50+101-bomb, huge totals 65535+, atomic frags, interleaving, ext hdr combos, nested frag-in-frag). The saved run reached COMPLETE; fragment-drop behavior and RFC 5722 compliance were not independently established. (probe 49b)
- **Exotic protocols (IGMP/GRE/ESP/AH/PIM/OSPF/VRRP)** — 86 packets, zero crashes (probe 50a)
- **Sony syscall info leak** — 11 accessible syscalls deep-tested with output buffers, no kernel pointers in any output (probes 51a, 51b)
- **Port binding ≥40000** — bind() returns -1 for ports ≥40000. Use 1024-32767 range.
- **sys 572 VM info query** — returns -1 for (addr, outbuf, size) layout; returns 0 but empty buffers for (outbuf, cmd, size) layout across cmds 0-5. No useful VM metadata extracted. (probes 54i, 2026-10-18)
- **sys 626 RDMSR precise (cmd=1 + cmd=4)** — cmd=1 returns -1 for all 16 PMC indices (MSR 0xC0010231+); cmds 1-6 all return -1 for idx=0; narg sensitivity 0-8 all -1. cmd=4 returns 0 but output is all zeros (counters not running). WRMSR (cmd=2) returns -1. No MSR data accessible. (probe 54a2, 2026-10-18)
- **sys 629 jail bypass** — all arg patterns (direct values, pointer-to-value for arg1/arg2) return -1. No fast path. Process crashed on kld* retests. (probe 54b, 2026-10-18)
- **sys 626 RDMSR** — returns -1 for all 11 MSR indices (TSC, APIC_BASE, SYSENTER_EIP, EFER, STAR, LSTAR, CSTAR, SFMASK, FS_BASE, GS_BASE, KERNEL_GS_BASE) across 3 arg layouts. Blocked on 14.10. (probes 54k, 2026-10-18)
- **sys 567 RDMSR read** — returns -1 for all MSR indices with both flat and struct arg layouts. (probe 54k, 2026-10-18)
- **sys 612** — returns -1 for all tested member values 0-8. (probe 54k, 2026-10-18)
- **sys 598 dynlib context** — returns -1 for all arg patterns tested. (probe 54f section A, 2026-10-18)
- **sys 639/638 memory region** — returns -1 for all address ranges including zero, low, heap, module, libkernel, and kernel VA. (probe 54f section C, 2026-10-18)
- **net.route.iflistl kernel pointer scan** — returned 6536 bytes but all values are sockaddr/MAC/interface structures, no kernel pointers. (probe 54f section D, 2026-10-18)
- **sys 593 deep struct scan (+0x148/+0x150)** — values across all 39 modules are NID hashes/fingerprints (random high bits but not in kernel VA range 0xFFFF8xxx), not kernel pointers. (probe 54f section F, 2026-10-18)
- **sys 643 chicken switches** — all 32 bits accepted (ret=0 for each), 0xFFFFFFFF OR'd into process+0xa34. No observable effect: mprotect(RWX) still fails, fork still blocked, kldstat still blocked. Field does not control W^X, sandbox, or syscall filtering. (probe 55a, 2026-10-18)
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
- **sys 631** — instantly kills process. Lethal on 14.10. (probe 52a, 2026-10-18)
- **sys 627-630** — all return PCALL-FAIL (exception/crash caught by pcall). (probe 52a, 2026-10-18)
- **sys 677** — instantly kills process AND crashes the game (loader stops accepting connections). LETHAL + GAME CRASH. (syscall_isolation_sweep, 2026-10-20)
- **sys 678** — instantly kills process AND crashes the game. Same behavior as 677. LETHAL + GAME CRASH. (syscall_isolation_sweep, 2026-10-20)
- **UMTX_OP_SHM (op 25 on syscall 454)** — **CONFIRMED STUB**: all sub-ops (create=1, destroy=4, alive=8) return 0 for any valid mapped address, -1 for unmapped addresses. Invalid sub-ops (0, 16) also return 0. Zero VM ops (sys 624 delta=0). alive() returns 0 even for never-created keys. No fd allocation, no vm_object creation, no slab allocation. Sony stubbed out the SHM subsystem. **CVE-2024-43102 is NOT exploitable** on 14.10 — the vulnerable umtx_shm_create_reg/unref_reg race path is unreachable. (probes 151a–152k, 2026-10-20)
- **fstat(189) via make_syscall** — kills process immediately. (probe 152j, 2026-10-20)

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

## Current Attack Priority (Updated 2026-10-18 — post-55g results)

**Evidence update:** Phase 14 (54a–55g) examined KASLR candidates, Sony syscalls, and device control paths. The examined paths have not established a kernel base, including the tested AF_ROUTE, RDMSR, sys 674 VM map, sys 649 module member, kinfo_proc and net.route.iflistl paths. These results do not establish that every possible KASLR technique is unavailable. Sys 661 kills; the rest of 662-670 is unmeasured. sys 622/601/548 are dead.

**CClosure +0x20: target bytes, write boundaries and later returned effects:**
- 55g wrote +1 to type()'s +0x20 low dword; output changes to binary after the write marker. The executed instruction and termination cause are not identified by that capture. Section D records same-value/no-op writes at +0x00, +0x08, +0x10, +0x18, +0x28 and +0x30. Sections E/F record different-value writes only at +0x18 and +0x00, followed by restoration; those operations returned without a recorded behavioral change.
- 54r read the first 64 bytes at each function's +0x20 target: all seven decode as `push rbp; mov rbp, rsp` (0x55 0x48 0x89 0xE5) — real x86-64 C function prologues in eboot's RX .text.
- 54q stops before its post-write marker. A successful tonumber redirect/loop is an interpretation without a recorded returned effect.
- **Scope:** later 56c/56f support selected existing Lua C targets with output and restore checks. Arbitrary target/ABI support, injected-page execution and a working general ROP chain remain unverified. The recorded region protection is userland metadata, not kernel access.

**REMAINING PRIMITIVES:**
- **CClosure +0x20 function redirect (selected targets)** — Lua arguments, target-like output and restore checks are recorded for rawequal/rawget/select changes (56c/56f); machine-register arguments and general native targets are not established.
- Tested syscall invocation via `make_syscall(N)`; the exact C-level dispatcher implementation is unidentified
- Heap R/W via GPU mmap (256+ pages)
- Userland ASLR bypass via `dynlib_get_info(593)`
- Full process VM map via sys 674 (317 named regions with protections)
- Network packet injection (RAW socket + IP_HDRINCL, TCP connect-back)
- **Syscall 624** — confirmed VM operation counter: +5 per mmap, stable (zero jitter over 100 samples), monotonic. Useful as side channel for counting kernel VM ops. (probe 52b)
- **11 accessible Sony syscalls** — 596, 585, 572, 624, 563-566, 606, 643, 640

**NEXT STEPS:**
1. **UMTX_OP mutex/rwlock/PI races (op 5/6/22 on 454)** — UMTX_OP_WAIT/WAKE/MUTEX are functional (56i2, 152k). The PI-mutex ops allocate `umtx_pi` objects and have had historical UAF/race bugs. Exercise the full op matrix (0-26) beyond 5/21.
2. **56d ROP via CClosure** — redirect +0x20 to eboot gadgets (ret, pop rdi;ret, etc.) to build a gadget chain. Redirect rawequal/rawget to gadget addresses, call them, observe register/stack effects.
3. **Loader internals** — find the C-level syscall dispatch, check for writable function pointers
4. **Threaded UMTX races** — Thrd_create works; use threads to race UMTX_OP_MUTEX_LOCK/UNLOCK for refcount or state corruption
5. **Sysent 679-734 survey** — unexplored Sony syscall range beyond the lethal 677/678

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** commit as the contributor doing the work (Rithik Janarthanan
  <janarthananrithik@gmail.com>), never as the repository owner
- **No AI attribution** in commits, PRs, or code.
|Device inventory|34 of 76 `/dev` nodes open from a game process (`gc`, `dce`, `ajm`, `dmem0`-`2`, `camera`, `usb`, `hid`, `bt`, `rng`, `gic`, `notification*`, HMD sets); `ioctl` reaches the drivers and they return `-1` for unprobed commands. Probes 259a-263a, 2026-10-21|
- Commit messages should be short and descriptive of what changed.
