# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## ★★★ PRIORITY 0 — KERNEL PANIC VIA thr_create(430) — ROOT CAUSE IDENTIFIED

**STATUS: ROOT CAUSE FOUND (13.60 decompile, PRs #30 + #31).**
The panic happens because `set_mcontext()` copies CS=0 from the zeroed ucontext into tf_cs. `ISPL(0) = 0` makes the kernel treat the child thread's fault as a KERNEL-MODE fault → `pcb_onfault == NULL` → `trap_fatal()` → `panic("page fault")`.

**THE FIX: Set `ctx+0xC0 = 0x43` (user CS) and `ctx+0x100 = 0x3B` (user SS).** This makes the kernel treat the fault as user-mode → SIGSEGV → clean kill instead of panic. With valid RIP/RSP + correct CS/SS, the child thread should ACTUALLY RUN — giving us THREADING on 14.10.

**Analysis by:** @Unkown607 (PR #31, 13.60 Ghidra decompile of 22 functions) and @cobrajet302gt (PR #30, independent iretq hypothesis + probes)

- [ ] ★★★ **Run probe 80a section 1 on console** — thr_create with CS=0x43/SS=0x3B + RIP=0. DECISIVE: no panic = CS=0x43 prevents it. Standalone (no dependency on 79a). HIGH crash class.
- [ ] ★★★ **Run probe seg/79a on console** — getmcontext(78) layout harvest. ZERO crash risk. Returns Sony's real mcontext field offsets + live CS/SS/RFLAGS values. Validates 80a's hardcoded offsets.
- [ ] ★★★ **Run probe seg/79b on console** — thr_create with real CS=0x43/SS=0x3B from 79a. DECISIVE: rv=0 + no panic = threading works. rv=0 + panic = hypothesis dead.
- [ ] ★★★ **Run probe 80a sections 2-4** — if section 1 survives: test ret gadget execution (2), controlled RSP via GPU mmap (3), ret-sled busy loop with thr_suspend interaction (4).
- [ ] ★★ **Run probe race/79c on console** — AIO race ingredients (Relapse prereqs). Zero crash risk.
- [ ] ★ **Run probe 77a on console** — thr_create panic boundary map. NOTE: cobrajet302gt says 77a will panic in ALL sections because it carries CS=0/SS=0. Needs rebasing on 79a's real selectors.
- [x] ~~**Write probe 78c**~~ — thr_create controlled RSP → GPU mmap (WRITTEN).
- [x] ~~**Write probe 78b**~~ — thr_create heap spray (WRITTEN).
- [ ] ★ **Run probe 78c on console** — controlled RSP trap frame. Check GPU pages for kernel-written signal frame data.
- [x] ~~**Analyze the panic path**~~ — ROOT CAUSE IDENTIFIED: CS=0 → kernel-mode fault → no pcb_onfault → trap_fatal → panic. See `docs/THR_CREATE_PANIC_PATH_13.60.md` and `docs/ANALYSIS_thr_create_panic_2026-10-19.md`.

## ★★★ PRIORITY 0.3 — SYS 532 GPU COMMAND DISPATCH — 9 UNPRIVILEGED COMMANDS (2026-10-19)

**CRITICAL DISCOVERY:** sys 532 is the PRIMARY Sony GPU/compute dispatch syscall (~70+ sub-operations, ~16KB handler). Decompiled analysis reveals **commands 0x18-0x1E, 0x20, and 0x2F BYPASS priv_check(td, 682)**. These ~9 GPU resource management commands are accessible to our unprivileged process. sys 532 has NEVER been tested.

**7 vulnerability classes identified:**
- V2: TOCTOU in handle validation — no locking between lookup and permission check (MEDIUM-HIGH)
- V5: Missing auth check on deinit/reinit path — tear down GPU subsystem without privilege (MEDIUM)
- V1: Integer overflow in size validation (MEDIUM)
- V4: Unchecked object pointer from pool lookup (MEDIUM)
- V3/V6/V7: Registration table, worker thread, and rate-limiting issues

- [x] ~~**Write probe 87a**~~ — sys 532 GPU dispatch unprivileged commands (WRITTEN). 4 sections: A=reachability sweep all 9 unprivileged cmds + privileged rejection check, B=cmd 0x20 config query (48-byte output, kernel pointer scan — potential KASLR), C=deep probe cmds 0x18-0x1E with sub-command/size variations, D=deinit vulnerability + handle probing + version query.
- [ ] ★★★ **Run probe 87a section A** — reachability of 9 unprivileged GPU commands. If any return 0: GPU command execution without privilege!
- [ ] ★★★ **Run probe 87a section B** — cmd 0x20 copies 48 bytes of config. Scan for kernel pointers = instant KASLR defeat.
- [ ] ★★ **Run probe 87a section C** — deep probe GPU resource commands. These manage memory mapping, buffer ops, resource creation. Could expose W^X bypass.
- [ ] ★★ **Run probe 87a section D** — test deinit trigger + handle fingerprinting + version query.

## ★★★ PRIORITY 0.4 — SYS 601 DECOMPILED VULNERABILITIES (2026-10-19)

**NEW VECTOR:** 13.60 decompiled sys_601 handler (`results/kernel_handlers/analysis/sys_601_deep.md`) reveals CRITICAL structural bugs:
- **Cmd 0x0c:** Hardcoded auth backdoor — XOR bytes 0xCD/0x41 pass authentication
- **Cmd 0x12:** Unchecked process structure write to proc+0x578/+0x580 — zero credential checks, these are kfree'd kernel heap ptrs → arbitrary kfree primitive
- **Cmd 0x10:** 0x1000-byte kernel page copyout without zeroing → kernel info leak
- **Ring buffer:** Signed comparison bypass at handler+0x2288 → heap underflow write

Probe 55d tested but got -1 on critical commands ("process lacks initialization"). Cmd 0x00 DID return 0. The re-probe needs proper init sequencing + exact decompiled auth bytes.

- [x] ~~**Write probe 83a**~~ — sys 601 deep retest (WRITTEN). 4 sections: A=systematic init+survey, B=hardcoded backdoor with exact 0xCD/0x41 bytes, C=unchecked process write (arbitrary kfree), D=device name matching+config write.
- [ ] ★★★ **Run probe 83a section A** — init survey: which commands succeed after cmd 0x00? Scan all outputs for kernel pointers. MODERATE crash risk.
- [ ] ★★★ **Run probe 83a section B** — backdoor auth with exact decompiled bytes + offset variations. If accepted: kernel access via cmd 0x10/0x12.
- [ ] ★★ **Run probe 83a section C** — process structure write test. If ret=0: arbitrary kfree primitive confirmed.
- [x] ~~**Write probe 84a**~~ — sys 653 GPU PTE modifier reachability (WRITTEN). 3 sections: A=basic reachability (arg0 values, struct pointer, GPU addr), B=sys 630 mount enumeration (info leak), C=GPU PTE attribute modification on mmap pages.
- [ ] ★★★ **Run probe 84a section A** — sys 653 has NO priv_check: test reachability. If ret=0: potential W^X bypass via GPU PTE modification!
- [ ] ★★★ **Run probe 84a section B** — sys 630 mount enumeration: zero auth on ALL read functions. List all kernel mount points, cross-PID lookup. Info leak minimum.
- [ ] ★★ **Run probe 84a section C** — if A succeeds: try PTE attribute changes on GPU mmap pages (protection modification).
- [x] ~~**Write probe 98a**~~ — GPU PTE W^X bypass COMBINED CHAIN (WRITTEN). 4 sections: A=sys 547 VM region query on GPU mmap pages (discover object type + protection), B=sys 653 reachability with various arg0 values and param structs, C=PTE attribute sweep (try to change protection on GPU pages, verify before/after via sys 547), D=full W^X bypass attempt (modify attrs → write shellcode to GPU page → CClosure redirect → execute).
- [ ] ★★★ **Run probe 98a section A** — sys 547 VM region query on GPU mmap. Reveals object type (need 0xb for sys 653 eligibility) and protection bits. Compare GPU pages vs heap vs eboot.
- [ ] ★★★ **Run probe 98a section B** — sys 653 reachability. NO priv_check in entry. If ret=0 for any arg0: GPU PTE modification is LIVE.
- [ ] ★★★ **Run probe 98a section C** — PTE attribute modification attempt. Verify protection changes via sys 547 before/after. If protection changes: W^X bypass path CONFIRMED.
- [ ] ★★★ **Run probe 98a section D** — DECISIVE: write ret/xor-eax-eax/mov-eax-0x42 to GPU page, redirect CClosure +0x20, call. If returns value: ARBITRARY CODE EXECUTION on 14.10.
- [x] ~~**Write probe 85a**~~ — dispatch function reverse + return_addr hijack + sys 560 global unlock (WRITTEN). 3 sections: A=read __call dispatch function bytes from eboot, B=return_addr writability test (NEVER tested on console!), C=sys 560 global setter + blocked syscall retest.
- [ ] ★★★ **Run probe 85a section A** — read the SYSCALL DISPATCH FUNCTION code. __call +0x20 IS the dispatcher. Reading its x86-64 bytes reveals the mechanism.
- [ ] ★★★ **Run probe 85a section B** — return_addr writability test. fn_addr+0x10 was never tested. If writable + used by dispatch: post-syscall return hijack.
- [ ] ★★ **Run probe 85a section C** — sys 560 sets kernel global (NO auth). Test if it unlocks fork/mprotect/kldstat.

## ★★★ PRIORITY 0.42 — HANDLE NAMESPACE CONFUSION — 5 SUBSYSTEMS, ZERO CREDENTIAL CHECKS (2026-10-19)

**CRITICAL DISCOVERY:** Decompiled handler analysis reveals FIVE subsystems share process+0xc48 handle namespace with NO credential/privilege checks:
- **Event flags (type 0x110):** sys 538-546 — create/open/signal/wait/poll/clear/cancel. No credential gate.
- **Semaphores (type 0x120):** sys 549-556 — create/open/wait/post/cancel. No credential gate.
- **Generic objects (type arg|0x1000):** sys 557 — creates 0x18-byte records with ANY caller-chosen type. No credential gate.
- **Handle deletion:** sys 558 — deletes any object by handle+type from the same namespace. No credential gate.
- **AIO subsystem:** sys 662-670 — also uses process+0xc48 domain.

**Attack chains:**
- **Type confusion:** sys 557 creates 0x18-byte objects. If event flag/semaphore ops look up by type and find the undersized object, they read/write past its 0x18-byte allocation into adjacent heap memory.
- **Cross-subsystem UAF:** Create event flag → delete via sys 539 → spray semaphores (0x60 bytes) over freed memory → signal stale event flag handle → writes into semaphore structure at wrong offsets.
- **Handle recycling:** Rapid create/delete cycles may recycle handle slots, allowing stale handles to resolve to new objects.

- [x] ~~**Write probe 88a**~~ — handle namespace confusion (WRITTEN). 4 sections: A=event flag + semaphore reachability (create/signal/poll/delete/handle-reuse tracking), B=sys 557/558 generic object create/delete + handle recycling + fake event-flag-type creation, C=cross-subsystem confusion chain (create EF→delete→spray sems→signal stale handle→scan for kernel pointers), D=sys 648 GPU display OR-gate privilege probe (4-way OR priv_check, any 1 of 4 suffices).
- [ ] ★★★ **Run probe 88a section A** — event flag + semaphore reachability. If sys 538/549 return 0: IPC primitives ALIVE. Track handle values for recycling patterns.
- [ ] ★★★ **Run probe 88a section B** — sys 557/558 generic objects. Test type values including 0x110 (event) and 0x120 (semaphore). Then try sys 540 (ef_open) on a sys-557-created "event" name.
- [ ] ★★★ **Run probe 88a section C** — cross-subsystem UAF chain. If stale signal succeeds (ret=0): the freed memory was reclaimed and we're writing into another subsystem's object. Scan for kernel pointer leaks.
- [ ] ★★ **Run probe 88a section D** — sys 648 GPU display OR-gate. If ret != 1: we passed at least 1 of 4 privilege checks and have GPU display pipeline access.

## ★★★ PRIORITY 0.43 — SYS 625 AMD MSR CONTROLLER — 23 COMMANDS, NO CREDENTIAL CHECK (2026-10-19)

**CRITICAL DISCOVERY:** Decompiled handler analysis reveals sys 625 is a 23-command AMD Performance Monitoring Counter (PMC) / MSR controller with **NO credential predicate in the handler body**. This is COMPLETELY DIFFERENT from sys 626 (which returned -1 for all MSR indices). Sys 625 takes 4 args: `command32 (1-23), domain32 (0-3), index32 (0-7), value64`.

**Direct hardware MSR writes confirmed in decompile:**
- `wrmsr` to AMD PMC MSRs 0xc0010230-0xc001023b (performance counters)
- Counter MSRs 0xc0010241+2*index accept raw 64-bit caller values
- Event select MSRs 0xc0010240+2*index accept filtered values (mask 0xe7fffff0ffff0000 rejected)
- Bit 22 enable/disable for PMC operation
- CPU cluster migration (domain 1-3 = different CPU groups)
- Full sweep: clear/reconfigure, enable, indexed write, raw write, init paths

**Why this matters:** If accessible, MSR writes give us:
- PMC-based side channel for KASLR defeat (count kernel instructions between syscalls)
- Hardware performance counter manipulation → potential PMI triggers
- Direct hardware register access from unprivileged process

- [x] ~~**Write probe 89a**~~ — sys 625 MSR controller (WRITTEN). 4 sections: A=reachability sweep all 23 cmds with safe zero args + domain/index sensitivity, B=PMC enable + counter observation via sys 624 baseline, C=direct MSR value writes + timing verification, D=full command×domain matrix + index=-1 all-counter write + KASLR side channel attempt.
- [ ] ★★★ **Run probe 89a section A** — reachability of 23 MSR commands. If ANY return 0: hardware MSR access without privilege! Compare against sys 626 which was blocked.
- [ ] ★★★ **Run probe 89a section B** — PMC enable + counter observation. If enables succeed: timing side channel via instruction counting.
- [ ] ★★ **Run probe 89a section C** — direct MSR value writes. Test counter manipulation.
- [ ] ★★ **Run probe 89a section D** — full matrix + KASLR side channel attempt.

## ★★★ PRIORITY 0.44 — SYS 563-566 PMU CREDENTIAL BYPASS + HARDWARE SIDE CHANNEL (2026-10-19)

**CRITICAL DISCOVERY:** Handler analysis reveals sys 563-566 are a complete AMD Performance Monitoring Unit (PMU) control family. **The selector=0 path (current process/thread) has NO credential gate on ALL four syscalls.** The process-selector path requires `cred+0x58 == 0x4800000000010003`, but selector=0 bypasses this entirely.

**The four PMU syscalls:**
- **sys 563:** Enable per-thread monitoring — sets bit 22 in 6 event-control MSRs at PCB+0x160-0x188
- **sys 564:** Disable per-thread monitoring — clears bit 22
- **sys 565:** Configure event selectors — writes to MSRs 0xc0010200-0xc001020a (even), rejects bits 0xfffffff0007b0000
- **sys 566:** Write counter values — writes to MSRs 0xc0010201-0xc001020b (odd), index 0xFFFFFFFF writes ALL 6 counters

**Combined with sys 625 (L2 PMC bank, also no credential check):**
- Core PMC bank: MSRs 0xc0010200-0xc001020b (via sys 563-566)
- L2 PMC bank: MSRs 0xc0010230-0xc001023b (via sys 625)
- = Complete write access to BOTH AMD PMC hardware banks from unprivileged process

**KASLR defeat via PMC overflow side channel:**
1. Configure counter to count retired instructions (event 0xC0)
2. Set counter near MAX_UINT48 (overflow threshold)
3. Execute target syscall → counter overflows → PMI interrupt
4. Different KASLR slides = different kernel instruction counts = different overflow points
5. Binary search initial counter values → fingerprint exact kernel code path length → KASLR slide

- [x] ~~**Write probe 92a**~~ — PMU hardware exploitation (WRITTEN). 4 sections: A=reachability of all 4 PMU syscalls with selector=0 vs selector=1 (confirm credential bypass), B=PMU enable + 5 event configurations (retired instructions, cycles, cache misses) + counter writes, C=timing measurement with PMU on vs off + sys 624 side channel baseline, D=combined sys 563-566 + sys 625 cross-bank PMC control + workload measurement.
- [ ] ★★★ **Run probe 92a section A** — PMU reachability. If sys 563-566 return 0 with selector=0: HARDWARE PMC ACCESS without credential check! Compare selector=1 (should fail with ESRCH/EPERM).
- [ ] ★★★ **Run probe 92a section B** — PMU enable + event configuration. If configure succeeds: we can count retired instructions, cache misses, etc. Hardware side channel LIVE.
- [ ] ★★ **Run probe 92a section C** — timing measurement. Detect PMU overhead in wallclock time. If measurable: confirms hardware counters are actually running.
- [ ] ★★ **Run probe 92a section D** — combined core + L2 PMC banks. 12 hardware counter channels for side channel attacks.

### SYS 567 PMU COUNTER READ — COMPLETES THE PMU CHAIN (2026-10-19)

**CRITICAL CORRECTION:** The dead-end entry "sys 567 RDMSR read — returns -1" (probe 54k) tested with **WRONG arguments** (MSR addresses as arg0). Handler analysis reveals sys 567 is a **PMU counter READ**, NOT an arbitrary MSR read:
- **Args:** thread_id(uint32), counter_index(0-5), output_pointer(uint64*)
- **Returns:** One uint64 saved counter value via copyout
- **No explicit priv_check** in the handler
- Resolves thread via lookup(tid, current_pid) — only reads own threads

**This COMPLETES the PMU read/write chain:**
1. sys 563: Enable PMU (selector=0 = no credential)
2. sys 565: Configure event (retired instructions = 0xC0)
3. sys 566: Zero counter
4. Execute target syscall (workload)
5. **sys 567: READ counter** ← NOW AVAILABLE
6. = Exact hardware instruction count = KASLR fingerprint

- [x] ~~**Write probe 94a**~~ — sys 567 PMU counter read with correct args (WRITTEN). 3 sections: A=sys 567 reachability with TID+index+output_ptr (correct layout, TID=0/self/invalid tests), B=full PMU cycle (enable→configure→zero→workload→read, linear scaling test), C=KASLR fingerprinting (instruction counts per syscall, jitter measurement, 7 target syscalls).
- [ ] ★★★ **Run probe 94a section A** — sys 567 with correct arg layout. If ret=0 and counter value written: PMU READ WORKS! The dead-end was a wrong-args test.
- [ ] ★★★ **Run probe 94a section B** — full PMU cycle. If counter increases after workload and scales linearly: HARDWARE INSTRUCTION COUNTING IS LIVE.
- [ ] ★★★ **Run probe 94a section C** — KASLR fingerprinting. Measure instruction counts for 7 different syscalls. If deterministic (zero jitter): KASLR defeat via instruction counting is viable.

## ★★★ PRIORITY 0.44a — SYS 654/655/657 GPU VM RANGE OPS — NO CREDENTIAL CHECK (2026-10-19)

**CRITICAL DISCOVERY:** Three related VM page management syscalls operate on TYPE-11 objects (GPU mmap backing objects) with **NO credential predicate**. These are DIFFERENT from sys 548 (which targeted regular VM objects and returned -1). Since our GPU mmap creates type-11 objects, these should work directly on our pages.

**The three syscalls:**
- **sys 654 (narg=5):** Single range operation. Args: address, length, operation(0-20), flags(bits 0x33), reserved=0. 64KB alignment. Modifies per-page metadata. Operations 0/3/10 have special route; 11-20 bounded route. No credential predicate.
- **sys 655 (narg=3):** Range reset companion. Args: address, length, reserved=0. Resets per-page state. No credential predicate.
- **sys 657 (narg=4):** Batched memory commands. Args: record_ptr(0x20-byte records), count, processed_out, flags=0. Opcodes 1-5 via jump table. Protection bits limited to 0x33. No credential predicate.

**All three require:** entry flag `+0x60 &2` clear, object type `+0x9d == 11` (matches GPU mmap).

**Why this matters:** If operations can modify page protection metadata on GPU-mapped pages, this is a potential **W^X bypass** path. Combined with our 256+ page GPU heap R/W primitive, changing RW→RWX would enable shellcode execution.

- [x] ~~**Write probe 93a**~~ — GPU VM range operations (WRITTEN). 4 sections: A=reachability of 654/655/657 on GPU mmap pages (ops 0-15, reset, batch opcodes 1-5), B=sys 654 full operation sweep (ops 0-20 + flag combos + length + alignment), C=sys 657 batched commands deep probe (opcode x protection matrix + multi-record + count sensitivity), D=protection modification + W^X test (exec flags + VM map verification + sys 624 delta).
- [ ] ★★★ **Run probe 93a section A** — reachability on GPU pages. If ANY operation returns 0: VM page management WITHOUT privilege on our GPU mmap! Compare against sys 548 (returned -1).
- [ ] ★★★ **Run probe 93a section B** — full operation sweep. 20+ operations to try. Find which modify page metadata.
- [ ] ★★★ **Run probe 93a section D** — W^X bypass test. If operation + exec flag succeeds AND VM map shows protection change: W^X is BROKEN.
- [ ] ★★ **Run probe 93a section C** — batched commands. 5 opcodes with protection control. Test if batch can set RWX.

## ★★★ PRIORITY 0.44b — SYS 622 DEVICE CONTEXT BYPASS + KASLR INFO LEAK (2026-10-19)

**CRITICAL DISCOVERY:** Deep analysis of sys 622 (24KB device control multiplexer, 6194 lines) reveals 9 exploitable vulnerabilities. The handler has **300+ commands with ZERO privilege checks** across 4 jump table ranges (0x200-0x270, 0x302-0x320, 0x400-0x493, bitmap-selected 0x100-0x133). Probe 55c tested 400+ commands but all returned 0x800E0001 ("no device context").

**Key vulnerabilities from decompile:**
- **V6 KASLR:** Info leak at 0x3E30 — device name copy ALWAYS copies 25 bytes regardless of actual name length → leaks uninitialized kernel heap memory to userspace
- **V7 WRITE PRIMITIVE:** Callback registration at 0x55A0 — stores function pointer to 8 global slots (0x32582B0-0x32582E8) with NO validation → write-what-where for kernel globals
- **V2 HEAP OVERFLOW:** Integer underflow at 0x444C — if buffer_limit < 0x18, subtraction wraps to ~0xFFFFFFFFFFFFFFE8 → arbitrary-length kernel heap copy
- **V3 UAF:** TOCTOU in device list iteration (0xEC0) — device freed between unlock and use

**Context-bypass paths (NOT device-dependent):**
- 6.16 Linked List Scanner (0x4F90): iterates GLOBAL list from [0x1D60D68+0x38], not device-specific
- 6.17 Initialization (0x5060): CREATES device entries via device_create — could establish context
- 6.19 Bulk Enumeration (0x5140): enumerates ALL device types (0x8001/0x8002/0x8004/0x8008)

- [x] ~~**Write probe 90a**~~ — sys 622 context bypass (WRITTEN). 4 sections: A=error code mapping across all no-auth cmd ranges (find non-0x800E0001 responses), B=sub-cmd sensitivity sweep + semaphore type sub-cmds + copyin_src buffer + size=0 bypass, C=initialization trigger search (find 0x800E0040 init failure code, 0x302-0x320 init range, arg6 sweep, device struct), D=info leak harvest from output buffers + callback test + broad device mask.
- [ ] ★★★ **Run probe 90a section A** — error code mapping. Any non-0x800E0001 error = we bypassed the device context gate on that command. Look especially for 0x800E0040 (init failure).
- [ ] ★★★ **Run probe 90a section B** — sub-cmd sensitivity. 55c only tested cmd values; the handler dispatches on sub-cmd too. Semaphore type values (0x8001/0x8002/0x8004/0x8008) as sub-cmd could select different device types.
- [ ] ★★ **Run probe 90a section C** — initialization trigger. If ANY command returns 0x800E0040: we reached the init path. If init succeeds: ALL 300+ unauth commands become exploitable.
- [ ] ★★ **Run probe 90a section D** — info leak scan + callback registration. If V6 reached: kernel heap bytes in output → KASLR defeat. If V7 reached: function pointer write to kernel globals.

## ★★★ PRIORITY 0.46 — SYS 630 MOUNT ENUMERATION + CROSS-PROCESS LOOKUP (2026-10-19)

**CRITICAL DISCOVERY:** Deep analysis of sys 630 (12KB jail/mount companion, narg=1) reveals ALL enumeration functions have **ZERO privilege checks**:
- Mount tree enumerator (0x0d0): list ALL kernel mount points
- Mount tree lookup (0x1f0): read 0x420 bytes of any mount's data
- Filesystem entry scanner (0x310): list ALL filesystem directory entries (type=0x10 filter)
- Cross-process mount lookup (0x450): takes ARBITRARY PID, returns mount names+handles+serials, NO relationship check
- Mount info query (0x7a0): returns page_count * 0x4000, raw count, mount flags

**Unprotected ioctl interface (0x1630):** 3 commands (0xc0305201/0xc0305202/0xc0305203), up to 1MB user data, NO credential check. Config stored and processed every 20s by kernel timer with full privilege.

**Exploitation potential:**
- Mount structure data may contain kernel pointers → KASLR defeat
- Cross-process mount lookup reveals other process topology by PID
- Ioctl config injection → kernel timer processes attacker data every 20s

- [x] ~~**Write probe 91a**~~ — sys 630 mount enumeration (WRITTEN). 4 sections: A=basic reachability (constants, zeroed buf, path strings, common mounts, module init), B=command structure exploration (cmd codes, ioctl codes, two-pointer layout, mount types), C=mount data harvest (large buffer, path+params, return value survey on 15 paths), D=cross-process mount lookup by PID + mount info query + mount ID table.
- [ ] ★★★ **Run probe 91a section A** — basic reachability of sys 630. If ret=0 with path strings: mount enumeration is LIVE.
- [ ] ★★★ **Run probe 91a section C** — mount data harvest. Scan output for kernel pointers = KASLR defeat. 0x420 bytes per mount lookup = large kernel data exposure.
- [ ] ★★ **Run probe 91a section D** — cross-process mount lookup by PID. If any output: inter-process data exposure without privilege.
- [ ] ★★ **Run probe 91a section B** — command structure exploration. Find internal dispatch for ioctl-like operations.

## ★★★ PRIORITY 0.45 — AIO HARD WALL IS FAKE (2026-10-19)

**CRITICAL DISCOVERY:** Decompiled handler analysis (sys_662 function inventory) proves only 661/665/668 are 5-instruction DISABLED KILL STUBS. Handlers 662 (batch delete, 525-instr), 663 (multi-wait, 801-instr!), 664 (cancel, 388-instr), 666, 667, 669 (submit), 670 (init) are REAL implementations with substantial code.

**Key bugs found in decompile:**
- **sys 669 STALE HANDLE:** identifier copyout occurs BEFORE queue setup finishes → error leaves user-visible handle to freed object (UAF setup)
- **sys 670 PARTIAL UPDATE:** invalid group can return error after earlier groups already written (non-atomic config)
- **sys 662 NON-ATOMIC DELETE:** failed final output copy doesn't roll back already-applied deletions

- [x] ~~**Write probe 86a**~~ — AIO real handler exploitation chain (WRITTEN). 3 sections: A=AIO init+reachability sweep (670 first, then 662-669 individually, skip kill stubs), B=AIO submit+stale handle (669 with valid/invalid FDs), C=AIO delete+wait+cancel (662/663/664/666/667).
- [ ] ★★★ **Run probe 86a section A** — AIO init (sys 670) + reachability of REAL handlers. If 670 returns 0: AIO subsystem is LIVE. Also tests sys 659 (module handle list, no credential check).
- [ ] ★★★ **Run probe 86a section B** — AIO submit with stale handle trigger. Invalid FD should fail AFTER identifier copyout → user-visible handle to freed memory.
- [ ] ★★ **Run probe 86a section C** — batch delete/multi-wait/cancel on initialized AIO. 663 has 801 instructions — massive attack surface for race conditions.

### PROBE 95a — AIO LIFECYCLE DEEP TEST (2026-10-19, deep handler analysis)

**NEW from deep analysis (sys_669_deep.md, sys_670_deep.md, sys_662-668.md):**
- sys 669 (_aio_submit_cmd): 5 args — cmd(1=read/2=write), 0x28-byte request descriptors, count(1-128), queue_class(1-3), output_ids. Uses file capability constants 0x400000000000080/0x20000000000000d. Worker performs actual file R/W via uio/iovec callbacks.
- sys 670 (__aio_init): 4 args — config_ptr(0x3c bytes, 3 groups of 5 uint32), config_len, reserved=0, reserved=0. **Partial-update confirmed:** group 0 written before group 1 validated; no rollback on error.
- sys 664 (_aio_multi_poll): 3 args — **MODIFIES kernel state** on first observation (sets byte+0xc); repeated polls return state|0x10000. Not read-only.
- sys 662 (_aio_multi_delete): Non-atomic — failed final copyout doesn't rollback already-applied deletions.
- sys 667: REQUIRES bit 62 credential — dead for us. Process/thread enumeration with 40-byte records.
- sys 665, 668: Disabled nosys stubs (return 78).

- [x] ~~**Write probe 95a**~~ — AIO subsystem lifecycle (WRITTEN). 4 sections: A=sys 670 init (null config default, config struct mode 0/1, reserved-arg rejection, wrong-length rejection), B=sys 669 submit (init context + socket fd + 0x28-byte descriptors for read/write/per-item-IDs + boundary tests), C=sys 664 poll + 662 delete + 666 cancel (first-observation flag check, cancel then delete, invalid/bogus ID handling), D=sys 670 partial-update bug (valid group 0 + invalid group 1 → partial write without rollback, mode=2 invalid, mode=1 zero chunk_size).
- [ ] ★★★ **Run probe 95a section A** — AIO init reachability. If ret=0 or ret=16: AIO context works. Test config acceptance with exact struct layout from decompile.
- [ ] ★★★ **Run probe 95a section B** — AIO submit with socket fds. If ret=0 + id written: kernel AIO objects created. The handle publication-before-queue-setup race is testable here.
- [ ] ★★ **Run probe 95a section C** — poll/delete/cancel lifecycle. Test first-observation flag (0x10000 bit), non-atomic delete, and cancel-then-delete sequencing.
- [ ] ★★ **Run probe 95a section D** — partial-update bug exploitation. If group 0 written + group 1 rejected: inconsistent AIO context state. Then test if default init works on that partial state.

## ★★★ PRIORITY 0.47 — HANDLE NAMESPACE UAF VIA SYS 558 + AIO RACE (2026-10-19)

**CRITICAL DISCOVERY:** sys 558 deep analysis reveals it is a **GENERIC handle deletion syscall** — takes ID + 16-bit type selector, OR's type with 0x1000, looks up in process+0xc48 namespace, frees object. **NO visible priv_check** in handler body.

**Kernel UAF attack (NO THREADING REQUIRED):**
1. sys 670: init AIO context → creates worker threads (SceAIO, SceFsstAIO)
2. sys 669: submit AIO write → kernel PUBLISHES handle ID BEFORE worker queue setup (offset 0x569-0x587)
3. sys 558: delete that handle by ID + type 0x160 → frees the 0x160-type object
4. Kernel AIO worker: tries to dereference freed handle → **KERNEL USE-AFTER-FREE**

This is a single-threaded race against a KERNEL worker thread — no userland threading needed!

**Cross-type confusion attack:**
- Create semaphore (type 0x120) → delete via sys 558 with type 0x160 → type check bypass?
- Create via sys 557 (generic 0x18-byte object) → delete via subsystem-specific ops → size mismatch

- [x] ~~**Write probe 96a**~~ — handle namespace UAF (WRITTEN). 4 sections: A=sys 558 reachability with various types/IDs, B=cross-type confusion (create sem→delete as AIO type), C=AIO init+submit+delete-via-558+poll-on-freed (UAF test), D=AIO submit+immediate delete race loop (20 rounds).
- [ ] ★★★ **Run probe 96a section A** — sys 558 reachability. Establish return codes for invalid handles (expect 3=not found).
- [ ] ★★★ **Run probe 96a section B** — cross-type confusion. If sem handle deleted with wrong type: type isolation is broken.
- [ ] ★★★ **Run probe 96a section C** — AIO lifecycle + delete via 558. If poll returns 0 on deleted handle: UAF CONFIRMED.
- [ ] ★★★ **Run probe 96a section D** — race loop. 20 rounds of submit+immediate-delete. If process survives all rounds but any round shows inconsistent state: race window exists.

## ★★★ PRIORITY 0.48 — SYS 532 UNPRIVILEGED GPU COMMANDS — NEVER TESTED (2026-10-19)

**UPDATES probe 87a with CORRECT argument layout from deep analysis.** sys 532 takes 5 args: cmd(dword), subcmd(dword), output_ptr(qword), input_ptr(qword), size(qword). The 9 unprivileged commands (0x18-0x1E, 0x20, 0x2F) copyin user data to a 0x818-byte kernel stack buffer.

**Integer truncation vulnerability:** Size arg is QWORD but truncated to DWORD in some code paths. Size 0x100000018 might pass the QWORD comparison (`< 0x819`) but truncate to 0x18 in the actual copyin — a stack buffer overflow in the kernel.

- [x] ~~**Write probe 97a**~~ — sys 532 unprivileged GPU dispatch (WRITTEN). 3 sections: A=enumerate all 9 commands with subcmd sweep, B=cmd 0x20 config query (kernel pointer scan), C=integer truncation test on cmds 0x1A-0x1D.
- [ ] ★★★ **Run probe 97a section A** — enumerate all 9 unprivileged commands. First-ever test of sys 532.
- [ ] ★★★ **Run probe 97a section B** — cmd 0x20 config query output. Scan for kernel pointers = KASLR defeat.
- [ ] ★★ **Run probe 97a section C** — integer truncation test. If size 0x100000018 is accepted: kernel stack buffer overflow.

## ★★ PRIORITY 0.5 — NEW GOLD VECTORS (Offline Analysis 2026-10-19)

See full write-up: `docs/GOLD_VECTORS_2026-10-19.md` — 12 ranked untested vectors.

- [x] ~~**Write probe 78a**~~ — thr_create + thr_suspend race (WRITTEN). 5 sections: suspend, thr_kill(SIGSTOP), suspend_ucontext, get_ucontext.
- [x] ~~**Write probe 78d**~~ — kevent EVFILT_PROC on thr_create fault (WRITTEN). 2 sections: EVFILT_PROC + EVFILT_SIGNAL.
- [x] ~~**Write probe 79a**~~ — /dev/dsp + pipe2 + procctl (WRITTEN). 3 sections: CVE-2026-49417 prereq, pipe2(542), procctl(544) with ASLR_CTL.
- [x] ~~**Write probe 79b**~~ — AIO isolation sweep sys 662-670 (WRITTEN). One syscall per run, 4 arg patterns.
- [x] ~~**Write probe 79c**~~ — ktimer signal reentrancy (WRITTEN). 2 sections: SIGEV_SIGNAL basic + rapid create/delete race.
- [x] ~~**Write probe 82a**~~ — umtx_op exploitation vectors (WRITTEN). 5 sections: NWAKE overflow, ROBUST_LISTS info leak, RW lock first test, SHM UAF via thr_create, NWAKE kernel oracle.
- [ ] ★★ **Run probe 82a section A** — NWAKE_PRIVATE integer overflow boundary testing. MODERATE crash risk.
- [ ] ★★ **Run probe 82a section C** — RW lock ops NEVER TESTED before. First coverage of ops 12/13/14.
- [ ] ★★ **Run probe 82a section D** — SHM UAF setup (single-threaded); full race needs 80a threading.
- [ ] ★ **Debug probe 50d** — persistent loader crash. Isolate which packet/section kills the loader ACROSS connections. Binary search of sections. This is cross-process kernel corruption.
- [ ] ★ **Run probes 78a-78d, 79a-79c on console** — all written, waiting for PS5 access

## ★★★ PRIORITY 0.8 — SROP (Sigreturn-Oriented Programming)

**NEW VECTOR (2026-10-19):** sigreturn(417) resolved OK in probe 22 but was NEVER CALLED. getcontext(421) and setcontext(422) exist in 13.60 sysent but have ZERO probe coverage.

If set_mcontext() doesn't force SEL_RPL_MASK, sigreturn/setcontext give: controlled RIP, RSP, and all GPRs. This is a one-shot path to ROP without the chain infrastructure.

- [x] ~~**Write probe 81a**~~ — SROP probe (WRITTEN). 5 sections: A=getcontext harvest, B=layout comparison, C=setcontext identity, D=sigreturn crafted frame, E=full SROP via setcontext + GPU mmap.
- [ ] ★★★ **Run probe 81a section A** — getcontext(421) register harvest. ZERO crash risk. Returns live CS/SS/RFLAGS + determines correct mcontext layout.
- [ ] ★★★ **Run probe 81a section B** — compare getcontext output against 3 layout hypotheses (vanilla FreeBSD, Sony 13.60, probe 80a). Determines correct offsets.
- [ ] ★★ **Run probe 81a sections C-E** — actual SROP execution tests. HIGH crash risk.

## PRIORITY 1 — Exploit the CClosure Redirect Primitive

- [ ] **Write and run probe 56d** — ROP via CClosure +0x20 redirect to eboot gadgets
- [ ] **Expand CClosure redirect to gadget chains** — chain gadgets for ROP primitive
- [ ] **Test CClosure redirect with machine-register arguments** — control rdi/rsi/rdx

## PRIORITY 2 — Run These Probes on Console (CRITICAL BACKLOG)

- [x] ~~**Run probe 58e** (`thr_create_ucontext`)~~ — **CONFIRMED: rv=0, real TID, KERNEL PANIC**
- [ ] ★ **Run probe 59b** (`thr_family_survey`) — 11 thr_* syscalls, CRITICAL for panic exploitation
- [ ] ★ **Run probe 58a** (`msync_reachability`) — CVE-2026-49418 device pager UAF
- [ ] ★ **Run probe 57c** (`kldsym_direct`) — instant KASLR defeat if alive
- [ ] **Run probe 59a** (`linux_abi_detection`) — Linuxulator presence for KASLR defeat
- [ ] **Run probe 58d** (`shm_sendfile_reachability`) — CVE-2026-49427/49428 path
- [ ] **Run probe 57e** (`jail_reachability`) — CVE-2026-49419 jail refcount
- [ ] **Run probe 57a** (`native_survey_677_734`) — 58 untested native syscalls
- [ ] **Measure sys 662-670** — use `tools/syscall_isolation_sweep.py`, one connection per number

## PRIORITY 3 — Evidence-Audit Retests

- [ ] **Retest 53c** — kldstat/kldsym for KASLR defeat
- [ ] **Analyze 55e/55f VM map data** — cross-reference 317 regions for RWX, device-mapped, or code-adjacent targets

## PRIORITY 4 — Conditional Follow-Ups

- [ ] **If 58a Section E returns 0:** Write msync double-free trigger (CVE-2026-49418)
- [ ] **If 59a detects Linuxulator:** Write Linux waitid(260) KASLR leak
- [ ] **If 58d shm_open works:** Write sendfile + fspacectl for CVE-2026-49427/49428
- [ ] **If 59b thr_suspend works:** Write thr_set_ucontext register injection probe

## PRIORITY 5 — Research & Analysis

- [ ] **Find the C-level syscall dispatch** — may reveal writable function pointers
- [ ] **Syscall 624 as side channel** — VM operation counter, heap-state oracle
- [ ] PC-coordinated network attacks from external host
- [ ] **sys 596/606/640 deep probing** — all return 0 but tested with trivial args only

## PRIORITY 6 — Prepared Probes Not Yet Run

- [ ] Run probe 57b/57d — deep tests, loader dispatch
- [ ] Run probe 56l (`corrected_mib_probe`) / 50e (`ipv6_msfilter_reach`)

## PRIORITY 7 — Documentation Housekeeping

- [ ] Update ATTACK_SURFACE.md with thr_* syscalls
- [ ] Update STRATEGY.md — thr_create kernel panic is now #1 exploit candidate
- [ ] Cross-reference CVE assessment docs against FINDINGS.md

---

## Contributors

| GitHub | Contribution |
|--------|-------------|
| @ZigZagBoi1 | Lead researcher, all probes 01-79f, findings, tooling |
| @Unkown607 | thr_create panic root-cause analysis (13.60 Ghidra decompile, PR #31) |
| @cobrajet302gt | CS=0/iretq hypothesis, probes seg/79a-79b, race/79c, Ghidra scripts (PR #30) |

---

*Last updated: 2026-10-19 — thr_create root cause IDENTIFIED: CS=0 → kernel-mode fault (PRs #30, #31)*
