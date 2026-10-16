# Changelog — PS5 14.10 Kernel Research

## 2026-10-16: Probes 47a + 46a re-run — Syscall 557 Dead, CClosure Test Pending

### Key Findings
- **Syscall 557 is a formula-based metric** (47a + 46a re-run): returns `base + ver` where base varies per connection (517, 1038, etc.). Not exploitable.
- **Syscall 620 is a no-op** — always returns 0, doesn't modify buffers.
- **47a Section C (CClosure write test) SKIPPED** — address parse bug, `__call` string has no `0x` prefix. THIS IS THE HIGHEST-PRIORITY FIX — if CClosure+32 is writable, we have code execution.
- SCM_RIGHTS over socketpair: sendmsg/recvmsg succeed but cmsg data is zeros.
- LOCAL_PEERCRED: uid=1, gid=1, pid=0 (sandbox).

### Critical Next Step
Fix the CClosure address parsing in the next probe. The `__call` C function at `0x3108dbaa0` needs its struct scanned for a writable function pointer. Also: jmpbuf at `0x3109b8130` and recover_from_call at `0x3109b8100` are potentially writable targets.

---

## 2026-10-16: Probes 46a-46d — Loader Internals + Socket Bypass

### Key Findings
- **Syscall 557 is version-dependent** (46a): `{ver=1,size=0x200}` returns 518 vs 16901. Kernel writes back to struct buffer. Probe crashed on format bug before full sweep.
- **__call C dispatcher confirmed** (46b): All syscall objects share `__call` at `0x311023aa0`. ROP chain exists as metatable data but is never executed. Both resolve() and make_syscall() go through same C function.
- **socketpair works** (46d): `socketpair(AF_LOCAL, SOCK_STREAM)` returns fd pair via make_syscall. Not in resolve() namespace. New IPC primitive.
- Socket creation identical between make_syscall and resolve — no hidden bypass
- SCTP still dead (-1)

### Status
Network-side attacks (TCP from PC) are the top priority. Need to run `tcp_fuzz_server_v2.py` on PC and send 46b_tcp_enhanced_listener.lua.

---

## 2026-10-16: Probe 45c — ROP Chain Model INVALIDATED

### ★★★ CRITICAL: make_syscall() Bypasses ROP Chain Entirely
- Probe 45c proved definitively that `make_syscall().__call` uses a **C-level syscall wrapper**, NOT the ROP chain
- fn_addr is NEVER called as code: ud2, null, unmapped address = no crash
- ROP chain corruption (writing 0x41414141) has zero effect on syscall behavior
- Sysctl returns valid data even when fn_addr points to NOP+ret
- fn_addr value `0x9FE5_11100130` is NOT in any loaded module's text range

### Retracted Findings
- **W^X "defeat" (44a) was a false positive** — our code page was never executed; the chain just doesn't call fn_addr
- **fn_addr/slot0 "arbitrary function call primitive" (43i) is dead** — writes persist but have no effect on execution
- **Entire ROP chain exploitation model (Tier 5) invalidated**

### Remaining Attack Surface
- Syscalls via make_syscall() (C wrapper)
- Heap R/W via GPU mmap
- Network-side packet injection (TCP/IP from PC)
- Sony syscall investigation (557/620)
- Loader internals reverse engineering

---

## 2026-10-16: Probes 45a-45b — Shellcode Execution Doubts

- 45a: Shellcode appears to execute (no crash) but all buffer writes return sentinel values
- 45b: Return value is ALWAYS pid regardless of eax. `xor eax,eax; ret` returns pid=128 (impossible if executing). All memory writes from shellcode fail. Raised first suspicion that shellcode isn't running.

---

## 2026-10-16: Probes 44a-44d — W^X DEFEATED (RETRACTED — see 45c above)

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
