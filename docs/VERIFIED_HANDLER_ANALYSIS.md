# PS5 13.60 Kernel Dump — Cross-Validated Handler Analysis

Deep reverse engineering of 97 Sony-specific syscall handlers (532-676) from the firmware 13.60 kernel memory dump in `docs/dumps_13.60/`. All vulnerability claims verified adversarially against raw x86-64 disassembly — refuted claims are listed at the bottom.

**Source**: `docs/dumps_13.60/` (extracted via Relapse + Byepervisor)
**Kernel base**: 0xffffffff8a9c0000 | **Arch**: AMD Zen 2 x86-64 | **Pages**: 16KB

Complements the existing [KERNEL_DUMP_ANALYSIS.md](KERNEL_DUMP_ANALYSIS.md) which covers sysent table structure and handler sizing. This document adds per-handler vulnerability analysis.

---

## Verification Summary

| Subsystem | Claims | Confirmed | Partial | Refuted |
|-----------|--------|-----------|---------|---------|
| Dynlib/Module | 5 | **5** | 0 | 0 |
| Network/IPC/Event | 5 | **5** | 0 | 0 |
| Complex/Sysent/Data | 7 | **7** | 0 | 0 |
| Memory/VM | 6 | 4 | **2** | 0 |
| Security/Credential | 5 | 2 | 1 | **2** |
| **Total** | **28** | **23** | **3** | **2** |

---

## TIER 1: Confirmed Critical Vulnerabilities

### 1. Userspace ASLR Bypass — sys 593/608/660 dynlib_get_info_ex [CONFIRMED DEFINITIVE]

`dynlib_get_info_ex` (0x1a8-byte struct) copies module layout to userspace WITHOUT privilege check:

```
+0x110: mapbase (module+0x78)        — UNCONDITIONAL
+0x118: text_size (module+0x80)      — UNCONDITIONAL
+0x11c: data_base_off (module+0x88)  — UNCONDITIONAL
+0x148: init_proc_addr (module+0xf8) — UNCONDITIONAL
+0x150: fini_proc_addr (module+0x108)— UNCONDITIONAL
+0x158: eh_frame_hdr (module+0x100)  — UNCONDITIONAL
```

Verified: priv_check at 0x7dd only gates module NAME. priv_check at 0x895 only gates TLS/old-style segments. Between them (0x7f4-0x883): unconditional MOVs copy all critical addresses. THREE duplicate syscalls (593, 608, 660) expose the same data.

**Exploitation**: Enumerate module handles → call get_info_ex → extract mapbase + text_size for every loaded PRX → build ROP chain from known gadget offsets.

**14.10 survivability**: STRUCTURAL — the info struct layout is baked into the ABI. Sony would need to add a priv_check gate without breaking userland.

### 2. KASLR Bypass via Pointer Obfuscation — sys 661/662/668 [CONFIRMED DEFINITIVE]

Event subsystem copies kernel heap pointer to userland with trivially reversible transform:

```asm
mov    0x10(%r13),%rax    ; load kernel pointer from event object
sar    $0x4,%rcx          ; arithmetic shift right by 4
xor    %rax,%rcx          ; XOR original with shifted
mov    %rcx,(%rdx)        ; write to user output buffer
```

Transform `f(x) = x ^ (x >> 4)` inverted in O(16) nibble operations. Pattern confirmed byte-identical in all three handlers (661:0x46f, 662:0x45f, 668:0x47f).

**14.10 survivability**: STRUCTURAL — the obfuscation algorithm is the "fix." Unless they change to a real MAC/encryption, the leak persists.

### 3. Stack Clash via Integer Overflow — sys 661/662 [CONFIRMED DEFINITIVE]

32-bit vs 64-bit arithmetic mismatch in stack allocation:

```asm
lea 0xf(,%r15,4),%eax    ; 32-BIT — stack size (overflows)
...
lea 0x0(,%r13,4),%r12    ; 64-BIT — copyin size (doesn't overflow)
```

With count=0x40000001: allocates ~19 bytes on stack, copyin writes ~4GB. Bounds check allows counts up to ~0xFFFFFF00. Stack canaries present but overflow is massive.

**14.10 survivability**: Likely PATCHED if Sony audited integer widths. But these patterns are common in game console kernels.

### 4. sys 622 Unchecked Device Control — 95% of Commands [CONFIRMED, WORSE THAN CLAIMED]

Sony Device Control Multiplexer (6 args). Original analysis said ~80% unchecked; verification found **95%** (534 unchecked vs 27 checked). Entire 0x000-0x0FF range (256 commands) bypasses credentials via unsigned underflow in bitmask index.

**14.10 survivability**: STRUCTURAL — the dispatch table architecture has the bug.

### 5. sys 588 DMEM Page Attribute Modify — NO Permission Check [CONFIRMED DEFINITIVE]

Full handler trace: NO priv_check, NO ucred access, NO auth ID check. Only vm_map bounds validation. A conditional sub-call treats EACCES as "proceed anyway."

If the underlying function allows W^X flip, this is a direct kernel memory protection bypass.

**14.10 survivability**: STRUCTURAL — the missing check is a design oversight, not a specific bug.

### 6. sys 639/638 Memory Region Info — NO Permission Check [CONFIRMED DEFINITIVE]

Returns kernel memory region base/size/offset to ANY caller. Binary search on global kernel table, copies out directly. If table contains kernel VAs → direct KASLR bypass.

### 7. sys 626 Direct RDMSR — Performance Counter Read [CONFIRMED WITH CORRECTION]

Executes `RDMSR` (opcode 0F 32) reading AMD PMC MSRs:
- 0xC0010241 + (2*index): event select registers
- 0xC0010189 + (2*index): L3 performance counters (corrected formula)

6+ RDMSR sites confirmed. No permission check. Enables microarchitectural side-channel attacks.

### 8. sys 629 Jail Bypass via arg0=1 Fast Path [CONFIRMED DEFINITIVE]

`cmpq $0x1,(%rsi); je 0xb8` sends arg0=1 directly to internal mount function, completely skipping: buffer allocation, path copyin, path validation, credential check (0xcecc90), hardcoded path comparison.

---

## TIER 2: Confirmed High-Value Findings

### 9. Module Member Leak — sys 612/649 get_obj_member [CONFIRMED DEFINITIVE]

Jump table returns mapbase (0x78), init_proc (0xf8), fini_proc (0x108) with ZERO priv_check calls in entire handler file. TLS fields (0xe8, 0xf0) gated by flag 0x10 at module+0x11d. Provides targeted per-module extraction alternative to sys 593.

### 10. sys 675 Global State Reset — No Auth [CONFIRMED DEFINITIVE]

40-byte function. Three global writes, zero calls, zero checks:
```c
*(int*)(RIP+0x17c2bf0) = 1;     // global flag
*(int64_t*)(RIP+0x2a8dfd8) = -1; // sentinel
*(int64_t*)(RIP+0x2a8c918) = 0;  // counter
```

### 11. sys 598 Entry 0x000 Info Leak [CONFIRMED DEFINITIVE]

Two 8-byte values from dynlib_context+0xc8/+0xd0 returned without privilege check. Zero priv_check calls in entire handler file. If these contain kernel pointers → zero-cost KASLR bypass.

### 12. Cross-Process Event Manipulation — sys 670 [CONFIRMED DEFINITIVE]

Second handler at offset 0x480: PID-based process lookup → direct access to target_proc->0xc48 event table. Only validation: slot_index <= target_proc->event_max. No privilege check, no credential comparison.

### 13. Non-Atomic Refcount in Event Signal — sys 664/665/666 [CONFIRMED MEDIUM-HIGH]

`decl (%rax)` WITHOUT LOCK prefix at multiple offsets. Zero lock-prefixed instructions in entire file. Exploitability depends on whether outer mutex serializes access (cannot determine statically).

### 14. sys 565/566 PTE Manipulation [CONFIRMED WITH CORRECTION]

Both handle indices 0-5 (not split ranges as originally claimed). Write to different module offsets: 0x160+i*8 (sys 565) vs 0x190+i*8 (sys 566) — low/high PTE halves. Value mask 0xfffffff0007b0000, ucred gate confirmed.

### 15. sys 548 Sony mmap TOCTOU [CONFIRMED]

Per-entry 0x20-byte copyin in processing loop. Userland array can be modified between iterations. Type 2 operation chaining uses previous result. Sandbox flag derivation confirmed.

---

## TIER 3: Structural Findings

### 16. Sysent Table: Zero Audit Coverage [CONFIRMED DEFINITIVE]

All 115 real Sony syscalls: au_event=0, no DTrace probes, no Capsicum flags. Complete invisibility to FreeBSD security monitoring.

### 17. Sony ACM Credential System

Sony replaced FreeBSD priv_check with proprietary ACM functions in security handlers. BUT standard priv_check IS still used in dynlib handlers (591-593). Hybrid model.

### 18. ucred Sony Extensions [CONFIRMED WITH BYTE-ORDER CORRECTION]

```
+0x58: cr_sceAuthId = 0x4800000000000007
+0x60: cr_sceCaps[0] = 0x40ff1cffffffffff (corrected byte order)
+0x68: cr_sceCaps[1] = 0xffffffffffffffff (max privileges)
```

### 19. Module Structure Map [18/18 OFFSETS CONFIRMED]

Cross-validated across 3-4 handlers each:
```
+0x00: next pointer    +0x28: handle ID     +0x70: TLS/SDK version
+0x78: mapbase         +0x80: text_size     +0x88: data_base_off
+0x90: data_size       +0xe8: TLS init addr +0xf0: TLS init size
+0xf8: init_proc addr  +0x100: eh_frame_hdr +0x108: fini_proc addr
+0x110: eh_frame_size  +0x11d: flags byte   +0x168: additional info
```

### 20. Auth ID Hierarchy

```
proc+0x5d4 (non-sandboxed) / proc+0x5d8 (sandboxed):
>= 0x3000000: Extended DMEM operations
>= 0x5000000: VM query extensions, GPU frequency control
```

### 21. Kernel Data Strings

Build path `W:/Build/J03950001/sys/freebsd/...` confirmed. 50+ dynlib strings, budget system strings, `mp4_mDbg_test_context_read_write_process_memory_rw` debug functions, `sceSblAuthMgr` auth infrastructure.

### 22. sys 640 Disabled 8-Arg Stub

`push rbp; mov rsp,rbp; xor eax,eax; pop rbp; ret` — returns 0. Vestigial narg=8 in sysent. Original code nearby (initialization, ring buffer management).

---

## REFUTED Claims

1. **sys 585 "complex VM operations"** — REFUTED. Main handler is a trivial 20-instruction boolean check (reads proc->0x48->0x10, compares against global, returns 0 or 1). Complex code exists in sub-functions but was misattributed to the syscall entry point.

2. **sys 565/566 "different index ranges"** — REFUTED. Both handle indices 0-5, writing to different offsets (low/high PTE halves).

---

## Exploitation Chain (13.60 → potential 14.10)

```
Step 1: KASLR Defeat
  sys 593 dynlib_get_info_ex → mapbase of every loaded module
  OR sys 661/662 event query → deobfuscate heap pointer
  OR sys 639 memory region query → kernel layout table
  OR sys 626 RDMSR → PMC side-channel

Step 2: Primitive Building
  sys 661 stack clash → massive stack overflow → ROP
  OR sys 588 DMEM page attr → W^X bypass (if allows flip)
  OR sys 565/566 PTE manipulation → physical memory mapping (needs ucred)

Step 3: Privilege Escalation
  sys 622 device control → 95% unchecked commands
  sys 629 arg0=1 → jail bypass
  sys 670 cross-process events → manipulate system daemons
  sys 675 global reset → clear module validation state

Step 4: Persistence
  Modify ucred cr_sceCaps → max privileges
  OR sys 565/566 remap kernel pages → persistent patches
```

---

## Recommended Next Steps for 14.10

1. **PRIORITY 1**: Probe sys 593 `dynlib_get_info_ex` on 14.10 — does mapbase still leak without priv_check?
2. **PRIORITY 2**: Probe sys 639/638 — does the memory region table contain kernel VAs?
3. **PRIORITY 3**: Probe sys 598 Entry 0x000 — what values are at dynlib_context+0xc8/+0xd0?
4. **PRIORITY 4**: Probe sys 588 — what page attributes are modifiable without auth?
5. **PRIORITY 5**: Probe sys 622 — enumerate accessible unchecked command codes

All probes are callable from the Lua loader (ZigZagBoi1's entry vector) or from WebKit (user's entry vector) once arbitrary syscall calling is achieved.

---

*Analysis by [@Arn0Stride7](https://x.com/Arn0Stride7) using multi-model RE pipeline (Opus 4.6 analysis + Opus 4.6 adversarial verification). 23/28 claims confirmed, 3 partially confirmed, 2 refuted. Zero hallucinated vulnerabilities survived verification.*
