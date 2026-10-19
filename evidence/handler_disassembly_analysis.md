# Handler Disassembly Analysis — 11 Accessible Sony Syscalls

**Source:** kernel_text.bin + kernel_data.bin from 13.60 dumps  
**Base:** 0xffffffff8a9c0000  
**Date:** 2026-10-18  
**Method:** Capstone x86-64 disassembly of JMP thunk targets from sysent_index.json

## Executive Summary

All 11 Sony syscalls that returned non-error values on firmware 14.10 were disassembled from the 13.60 kernel binary. Key findings:

1. **sys 565 has RDMSR + copyout** — reads 6 AMD PMC MSRs and copies 667 bytes to userspace. This is the highest-priority exploit candidate.
2. **sys 572 traverses kernel page tables** — potential PTE read/modify capability.
3. **sys 563/564 enable/disable PMC** — prerequisite for sys 565 data collection.
4. **sys 643 sets "chicken switches"** — process flag manipulation, may unlock capabilities.
5. **sys 640 is a no-op** — the handler returns 0 immediately; a secondary init function fills a dispatch table but is not reachable via syscall.

## Exploit Priority

| Priority | Syscall | Capability | Why |
|----------|---------|-----------|-----|
| 1 | 565 | RDMSR + 667-byte copyout | Kernel state leak, PMC MSR values, possible KASLR data |
| 2 | 572 | PTE traversal + copyout | Page table read/modify → potential W^X bypass |
| 3 | 563/564 | PMC enable/disable | Required to activate 565's data collection |
| 4 | 643 | Process flag OR | "chicken_switches" may unlock blocked syscalls |
| 5 | 606 | Process value read | Simple info leak (1 dword) |
| 6 | 624 | Metric scalar read | Already known to differ by 1 across processes |

---

## sys 563 — orbis_pmc (narg=1)

**Handler VA:** See sysent_index.json  
**Source reference:** orbis_pmc.c  
**Instructions:** ~417, **Calls:** 36

### Argument Layout
- arg1 (dword): handle/process ID, range-checked `cmp eax, 0x1869e`

### Behavior
1. Looks up kernel object via call to 0x53c170 (object table lookup)
2. Policy check via 0x609890
3. On success: ORs 0x400000 into 6 fields at object offsets:
   - +0x160, +0x168, +0x170, +0x178, +0x180, +0x188
4. Sets object+0x380 to 1 (enable flag)

### Exploit Relevance
**PMC enabler.** Must be called before sys 565 to activate performance monitoring counters. The 6 fields at +0x160..+0x188 correspond to PMC configuration registers. The enable flag at +0x380 gates the RDMSR path in sys 565.

---

## sys 564 — process control 2 (narg=1)

Similar structure to sys 563, also references orbis_pmc.c. Likely the disable/read counterpart.

---

## sys 565 — PTE manipulation 1 / PMC read (narg=3) ★ CRITICAL

**Instructions:** ~300+, **Calls:** Multiple  
**Key features:** 6 RDMSR, copyout of 0x29B (667) bytes

### Argument Layout
- arg1 (dword @ [rsi+0]): handle, range-checked < 0x1869e
- arg2 (dword @ [rsi+8]): command/flags, validated < 6
- arg3 (qword @ [rsi+0x10]): output buffer pointer or address

### RDMSR Details
Reads 6 AMD Performance Monitor Counter MSRs:
| MSR | Name | Offset in Object |
|-----|------|-------------------|
| 0xC0010201 | PerfEvtSel0 | +0x190 |
| 0xC0010203 | PerfEvtSel1 | +0x198 |
| 0xC0010205 | PerfEvtSel2 | +0x1a0 |
| 0xC0010207 | PerfEvtSel3 | +0x1a8 |
| 0xC0010209 | PerfEvtSel4 | +0x1b0 |
| 0xC001020B | PerfEvtSel5 | +0x1b8 |

### Copyout
Copies 0x29B (667) bytes from the kernel object to userspace. This 667-byte blob includes the PMC MSR values at offsets +0x190..+0x1b8 relative to the object base.

### Validation
- Address mask: `movabs rcx, 0xfffffff0007b0000`
- Command range: `cmp r12, 6` (must be < 6)
- Spin-wait loop: `pause` + `test byte [r15+0x380], 6` — waits for PMC operation to complete

### Call Chain
1. 0x4c78b0 — validation
2. 0x609890 — policy check
3. 0xb92420 — object lookup
4. RDMSR x6
5. copyout

### Exploit Strategy
Call sys 563 first to enable PMC (set +0x380=1), then sys 565 with commands 0-5 to trigger copyout. The 667-byte output may contain:
- PMC counter values (timing side-channel)
- Kernel object fields that include pointers
- Process state useful for KASLR defeat

---

## sys 566 — PTE manipulation 2 (narg=3)

Similar structure to sys 565 with different operations on the same object. Likely write/configure counterpart to 565's read.

---

## sys 572 — VM syscall (narg=4) ★ HIGH PRIORITY

**Instructions:** ~380, **Calls:** Multiple  
**Key features:** Page table traversal, copyout, context-dependent validation

### Argument Layout
- arg1: virtual address (page-aligned, `and r12, 0xffffffffffffc000` = 16KB alignment)
- arg2: flags/command (bitmask validated)
- arg3: output buffer or value
- arg4: count/length

### Validation Paths
- Reads context byte at [rax+0xc81]
- If nonzero: full mask check `test ecx, 0xfffcfffe` (allows bits 0, 16-17)
- If zero: masks to single bit only

### Key Operations
- Bounds check against [r14+0x28] (VM map end)
- Permission check via 0xb2bb00 (GS-linked object, bitmask test)
- Page table traversal via 0x782a80 (called multiple times)
- Lock/unlock pairs: 0x2c6820/0x2c6870

### Exploit Relevance
If this reads PTEs, we can discover physical addresses of our pages. If it modifies PTEs, we can potentially change page permissions (RW → RWX) to bypass W^X enforcement. The page table traversal is the strongest indicator of PTE manipulation capability.

---

## sys 585 — mtype_protect (narg=0)

**Instructions:** 94  
**Behavior:** Simple boolean check.

1. Reads [rax+0x48] (process struct field)
2. Compares field at [r15+0x10] against a global value
3. `setne` → stores 0 or 1 to [rbx+0x408] (return value)

Not directly exploitable. Returns a single bit indicating some protection state.

---

## sys 596 — dynlib info (narg=?)

No priv_check found in handler. Already used for userland module-base discovery (39 modules). No kernel ASLR information.

---

## sys 606 — process value read (narg=0)

**Source reference:** sys_process.c  
**Instructions:** ~30

1. Calls 0xacc9a0 (reads process struct)
2. Sign-extends result (cdqe)
3. Stores to [rbx+0x408]
4. Returns 0

Very simple — reads one process-level dword value. Low exploit value.

---

## sys 624 — metric scalar read (narg=0)

**String reference:** "[KERNEL] nonsecure WebCore process can't map DMEM."

1. Lock via 0x2c6820
2. Read dword at [r14+0x1c4]
3. Store to [rbx+0x408]
4. Unlock via 0x2c6870
5. Return 0

The value at +0x1c4 is what was observed to differ by 1 across processes (probe 51a). This is a per-process counter or metric, not a kernel pointer.

---

## sys 640 — dispatch table init (narg=8)

**Handler:** `xor eax, eax; ret` — **pure no-op**

A secondary function at handler+0x10 contains one-time initialization logic:
- `lock cmpxchg` guard (runs once)
- Fills a global table with ~20+ function pointers via RIP-relative LEAs
- Writes to kernel data section at RIP+0x3165aXX offsets

Not exploitable via syscall — the handler itself does nothing. The init function is likely called during kernel boot, not from userspace.

---

## sys 643 — process flag OR / chicken switches (narg=1)

**String reference:** "set_chicken_switches(%x)"  
**Instructions:** ~277, **Calls:** 20

Also references PPFS (Sony protected filesystem):
- "PPFS inode"
- "PPFS dinode32"
- "ppr_pfs_mount"

### Exploit Relevance
"Chicken switches" are debug/feature flags. If we can set the right bits, we might:
- Enable debug features
- Bypass security checks
- Unlock blocked syscalls
- Disable sandbox restrictions

The PPFS references suggest this interacts with the filesystem protection layer.

---

## Cross-Handler Patterns

### Common Call Targets
| Address | Function | Used By |
|---------|----------|---------|
| 0x2c6820 | mutex_lock | 572, 624 |
| 0x2c6870 | mutex_unlock | 572, 624 |
| 0x609890 | policy_check | 563, 565 |
| 0x53c170 | object_lookup | 563 |
| 0xb92420 | object_lookup_2 | 565 |
| 0xb2bb00 | permission_check | 572 |

### Object Structure (shared by 563/565/566)
| Offset | Field | Set By | Read By |
|--------|-------|--------|---------|
| +0x160..+0x188 | PMC config (6 qwords) | 563 | 565 |
| +0x190..+0x1b8 | PMC MSR values (6 qwords) | 565 (RDMSR) | 565 (copyout) |
| +0x380 | Enable flag | 563 | 565 (spin-wait) |

---

## Testing Priority

1. **Probe 54i** — sys 565 RDMSR+copyout with all command values 0-5, after enabling PMC via 563
2. **Probe 54j** — sys 572 PTE read with page-aligned heap and GPU addresses
3. **Probe 54f section H** — sys 563-566 comprehensive test (already written)
4. **Probe 54b** — sys 629 jail bypass + blocked syscall retry
5. **Probe 54c** — AIO 661-670 full attack
