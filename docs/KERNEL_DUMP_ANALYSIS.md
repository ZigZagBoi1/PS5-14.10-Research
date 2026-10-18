# PS5 13.60 Kernel Dump Analysis

Analysis of the live RAM capture from PS5 firmware 13.60 (FreeBSD r230171).

## Dump Source
- Repository: `zigzagboi1/ps5-13.60-kernel-dump` on GitHub
- File: `kernel-13.60-live.bin` (103,546,880 bytes)
- SHA-256: `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`

## Memory Layout
| Region | File Offset | Size | Virtual Address |
|--------|------------|------|-----------------|
| Kernel TEXT | `0x0` | 13,369,344 (12.75 MB) | `0xffffffff9e3f0000` |
| Kernel DATA | `0xcc0000` | 90,177,536 (85.97 MB) | `0xffffffff9f0b0000` |

688 unmapped data pages (zero-filled).

## Sysent Table

**Location:** File offset `0xe6e5c0`, VA `0xffffffff9f25e5c0`  
**Structure:** stride=48 bytes, `sy_narg` at +0 (int32), `sy_call` at +8 (ptr64)  
**Entries:** 679 total (308 implemented, 371 nosys)  
**Nosys handler:** `0xffffffff9e9520e0` (TEXT+0x5620e0)

### Jump Stub Table
427 entries at TEXT+0x2663f0. Each stub is 8 bytes: `e9 XX XX XX XX cc cc cc` (jmp rel32 + INT3 padding). Sysent entries point to these stubs, which redirect to actual handlers.

## Sony Custom Syscalls (532-676)

**115 non-`nosys` handlers among syscall numbers 532–676.** The raw table has 145 entries in this range, including 30 `nosys` stubs. The earlier name map and aggregate counts require reconciliation; see [the evidence audit](EVIDENCE_AUDIT_2026-10-17.md).

### Largest Handlers (Most Complex / Most Attack Surface)
| Syscall | narg | Handler | Size | Notes |
|---------|------|---------|------|-------|
| 622 | 6 | TEXT+0x7dcd40 | 20,795B | Largest handler |
| 668 | 2 | TEXT+0x3af8e0 | — | nosys dispatcher |
| 661 | 4 | TEXT+0x3af8f0 | — | nosys dispatcher |
| 662 | 3 | TEXT+0x3af900 | — | wrapper to TEXT+0x3af920 |
| 663 | 5 | TEXT+0x3b01f0 | — | wrapper to TEXT+0x3b0210; Sony AIO multi-wait candidate |
| 664 | 3 | TEXT+0x3b0fb0 | — | wrapper to TEXT+0x3b0fd0 |
| 665 | 2 | TEXT+0x3b1670 | — | nosys dispatcher |
| 666 | 3 | TEXT+0x3b1680 | — | wrapper to TEXT+0x3b16a0 |
| 669 | 5 | TEXT+0x3b2060 | 10,288B | dynlib region |
| 601 | 3 | TEXT+0xca0630 | 10,285B | Complex operation |

### Tiny Wrappers (Minimal Validation)
| Syscall | narg | Handler | Size | Notes |
|---------|------|---------|------|-------|
| 560 | 1 | TEXT+0x4f5e60 | 38B | Reads global, compares arg |
| 585 | 0 | TEXT+0x8fc610 | 87B | No-arg |
| 606 | 0 | TEXT+0xa36b90 | 34B | No-arg |
| 617 | 1 | TEXT+0x8d2570 | 35B | |
| 640 | 8 | TEXT+0xa90e10 | 8B | Just a jump stub |
| 675 | 2 | TEXT+0x2d36f0 | 40B | |
| 676 | 0 | TEXT+0x6f92e0 | 72B | |

### Known Syscalls
| Syscall | narg | Handler | Size | ID |
|---------|------|---------|------|----|
| 557 | 3 | TEXT+0xac7240 | 1,678B | Returns formula-based metric |
| 593 | 2 | TEXT+0x34b7b0 | 2,870B | dynlib_get_info |
| 620 | 0 | TEXT+0xabd430 | 258B | Always returns 0 |
| 522 | 6 | TEXT+0x4ed3c0 | 7,873B | Near mmap handlers |

## Sandbox Enforcement

### Securelevel Check (TEXT+0xb078d0)
- Called by 12 syscall handlers
- Reads global at `0xffffffff9fcd446c` (DATA+0xc2446c)
- Value in dump: **1** (normal operation)
- Returns EPERM when value == 3, passes when value == 4
- **Not the primary sandbox** — securelevel is already permissive

### Primary Privilege Check (TEXT+0xc08b50)
- Called by **70** syscall handlers
- ~1,270 bytes — complex privilege/capability check
- Returns EPERM under certain conditions
- 7 `gs:` thread-local accesses, 28 sub-function calls
- Reads capability flags bitmask `0x11b1` from DATA+0x1c08c0
- Two sandbox level globals (both value=4) at DATA+0xF3C000 and DATA+0xF3BE10
- `cmp ebp, 64` checks specific FreeBSD privilege number (PRIV_PROC_SETLOGIN range)
- First call is to TEXT+0xc1a3e0 (process state validator) — early-out if invalid
- Also calls itself recursively at +0x4b0

### Process State Validator (TEXT+0xc1a3e0)
- Called by **241** syscall handlers — the MOST called function
- ~607 bytes
- Checks field at offset +0x138 in argument
- Likely validates process/thread state (not a deny function)

### Mutex Lock/Unlock Manager (TEXT+0x4c6fa0)
- Called by **187** syscall handlers
- ~2,219 bytes
- Starts with `gs:` segment prefix (thread-local storage)
- **Actually a mutex management function** (mtx_lock/mtx_unlock), NOT a credential check
- String references: `__mtx_unlock_flags`, `spin lock`, `td_locks`, `mtx_trylock in interrupt context`
- 10 thread-local accesses for getting current thread's lock count

### Copyin/Copyout Wrapper (TEXT+0x6fd6b0)
- Called by **181** syscall handlers
- ~371 bytes
- Called from ALL key syscalls (read, write, open, close, socket, sendmsg, sysctl, mmap)
- Validates user↔kernel data copies

## Cross-Firmware Research Implications for 14.10

### What We Now Know
1. **The captured 13.60 sysent** uses 48-byte entries with `sy_call` at +8. This is a useful parsing hypothesis for 14.10, not a verified 14.10 layout.
2. **The 13.60 Sony range** includes 115 active handlers and 30 stubs. Name assignments and aggregate counts must be validated against the raw table.
3. **Syscalls 661–670** are an AIO-family cluster, not a dynlib region. Entry stubs/wrappers must be followed to their real targets; 661, 665 and 668 dispatch to `nosys` in this capture, while 662–664 and 666–670 have implementations. This is static classification only, not a claim that untested 14.10 calls are safe or reachable.
4. **Syscall 622** has a six-argument, large handler. Its complexity makes it a static-analysis target, not an exploit candidate absent a demonstrated input path.
5. **Tiny handlers** such as 640 can be stubs. A successful return may simply reflect a no-op wrapper; inspect machine code before inferring functionality.

### Evidence-Based Leads
The repository’s saved 14.10 survey output is partial. Among logged calls, 563–566, 572, 596, 624, 585, 606, 640 and 643 produced non-error returns for tested argument patterns. Static analysis shows that 624 reads a scalar field from a VM-related object, 640 is a zero-return stub, and 643 updates a process field with the supplied bitmask. These observations motivate targeted semantic mapping; they do not establish kernel disclosure or corruption. See [cross-firmware pattern research](CROSS_FIRMWARE_PATTERN_RESEARCH.md).

Prior 14.10 assumptions that fn_addr enables arbitrary kernel calls or that writable ROP metadata yields kernel R/W are not established. Probe 45c recorded tested calls persisting after selected metadata mutations, contradicting the earlier dependency model for those calls without identifying the full dispatch implementation. Probe 43o did not deliver its AF_ROUTE request, and 43p's saved output contains no raw AIO result. Those artifacts do not demonstrate the Relapse prerequisites. Do not present KASLR defeat or credential modification as an available chain.

### 13.60 Offset Reference (Not a 14.10 Translation)
These offsets are relative to the 13.60 kernel TEXT base. They are 13.60-only observations; no authenticated 14.10 kernel image is available here to verify whether any offset or layout carries over:

| What | 13.60 Offset | Notes |
|------|-------------|-------|
| Sysent table | DATA+0x1a85c0 | In data segment |
| Jump stub table | TEXT+0x2663f0 | In text segment |
| Securelevel global | DATA+0xc2446c | |
| nosys handler | TEXT+0x5620e0 | |
| Main priv_check | TEXT+0xc08b50 | 70 callers |
| Mutex manager | TEXT+0x4c6fa0 | 187 callers (mtx_lock/unlock) |
| copyin/copyout | TEXT+0x6fd6b0 | 181 callers |

**WARNING:** These offsets are for 13.60 only. Do not apply them to firmware 14.10. A verified 14.10 kernel image and independent address derivation are required before making any cross-firmware mapping.

## AIO Handler Follow-up

The public 13.60 dump is a live kernel TEXT/DATA reconstruction; it is sufficient to inspect the AIO entry stubs and code, but it does not by itself prove a vulnerability. In the local 13.60 sysent, syscall 663 has five arguments and its table target at TEXT+`0x3b01f0` is an ABI wrapper that jumps to the implementation at TEXT+`0x3b0210`. Syscalls 662, 664, 666, 667, 669 and 670 likewise resolve to implementations; 661, 665 and 668 route to the common `nosys` dispatcher.

The saved 14.10 probe `43p` terminates after printing its first standard FreeBSD AIO call, `aio_error` (317). It never reaches the later Sony-range scan where 663 appears. Accordingly, the repository has no 14.10 result for Sony syscall 663, and no conclusion that this specific handler is blocked can be drawn from 43p. See [the secondary exploit audit](SECONDARY_EXPLOIT_AUDIT_13.60.md) for the corrected probe evidence and bounded follow-up plan.
