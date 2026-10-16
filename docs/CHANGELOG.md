# Changelog — PS5 14.10 Kernel Research

## 2026-10-16: Probes 44a-44d — W^X DEFEATED

### ★★★ BREAKTHROUGH: Native Code Execution (44a)
- `sceKernelMtypeprotect(585)` with `PROT_READ|PROT_WRITE|PROT_EXEC` grants execute permission on mmap'd pages
- NOP sled, `mov eax` shellcode, and direct `syscall` instruction all execute from the page
- Combined with fn_addr redirect (43i), we have arbitrary native x86-64 code execution
- **W^X was the hardest wall in PS5 exploitation. It is now broken.**

### Other Results
- Syscall 557 (44b): returns 0x4205 as process type/sandbox query, no kernel pointers
- Sockopt heap corruption (44c): not exploitable, kernel clamps copy length
- Creative KASLR (44d): NET_RT_IFLISTL returns 6.5KB (no kptrs), kern.usrstack readable, all other paths blocked

### Status
**KASLR defeat is now the sole remaining blocker.** With native code execution, we can write shellcode that probes kernel memory directly. Next: write shellcode-based KASLR probes that use timing side channels or scan kernel memory via native syscall instructions.

---

## 2026-10-16: Phase 10 Full Probe Sweep (43a-43p)

Sent all 16 Phase 10 probes. Eliminated nearly all direct KASLR defeat vectors.

### Critical Finding
- **fn_addr + slot0 writes persist** (43i) — the ROP chain does NOT rebuild fn_addr or slot0 after syscall calls. We have a confirmed arbitrary function call primitive with 6 controlled arguments. This is the key exploitation building block — we just need a kernel address to target.

### Promising Leads
- **Syscall 557 returns 16901** (43g) — live Sony-custom syscall, unknown function. Needs targeted investigation.
- **mtypeprotect returns 1 for RWX** (43h, 43k) — potential W^X bypass. Execution test not performed yet.
- **Syscall 620 returns 0** (43k) — another live Sony syscall.

### Confirmed Dead Ends (16 paths eliminated)
- AF_ROUTE KASLR (43o): socket opens, zero kernel pointers — Relapse info leak patched
- AIO via make_syscall (43p): instant kill — sandbox is kernel-level
- kldstat (43a): sandbox kill
- kldsym (43b): sandbox kill
- kinfo_proc full dump (43d): only sentinel values, no kernel pointers
- kern.proc.filedesc (43d): blocked
- kern.proc.vmmap (43d): blocked even with 256K buffers
- sysctl writes (43f): all paths blocked
- sysarch GET_GSBASE (43c): returns 0
- ioctl via make_syscall (43e): returns -1
- dup/dup2 (43e): returns -1
- thr_new (43e): crashes process
- kern.msgbuf (43j): returns 8 bytes only (filtered)
- mincore KASLR oracle (43l): kernel VA probes all -1
- sockopt overflow (43m): kernel clamps copy, not exploitable
- /dev/hid ioctl (43n): Sony error 0x80740004

### Other Findings
- fstat works via make_syscall (43e) — no kernel pointers but confirms stat struct access
- kinfo_proc process name is "boot.bin" (43d)
- kern.boottime readable: 0x6AD29A84 (43j)
- /dev/null, /dev/zero, /dev/urandom all open (43n)
- 32GB address (0x800000000) mapped in process VA space (43l)

### Status
**Blocker: KASLR defeat.** We have the function call primitive (43i) but no kernel address to call. All direct info leak paths are dead. Remaining vectors: Sony syscall 557/620 investigation, mtypeprotect exec test, network-side attacks (TCP/IP options from real network).
