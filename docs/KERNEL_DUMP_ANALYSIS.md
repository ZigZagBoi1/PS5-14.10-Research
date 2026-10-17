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

**115 implemented Sony-specific syscalls.** Key ones:

### Largest Handlers (Most Complex / Most Attack Surface)
| Syscall | narg | Handler | Size | Notes |
|---------|------|---------|------|-------|
| 622 | 6 | TEXT+0x7dcd40 | 20,795B | Largest handler |
| 668 | 2 | TEXT+0x3af8e0 | 20,400B | dynlib region |
| 661 | 4 | TEXT+0x3af8f0 | 20,384B | dynlib region |
| 662 | 3 | TEXT+0x3af900 | 20,368B | dynlib region |
| 663 | 5 | TEXT+0x3b01f0 | 18,080B | dynlib region |
| 664 | 3 | TEXT+0x3b0fb0 | 14,560B | dynlib region |
| 665 | 2 | TEXT+0x3b1670 | 12,832B | dynlib region |
| 666 | 3 | TEXT+0x3b1680 | 12,816B | dynlib region |
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
- Likely checks process credentials (ucred/prison flags)

### Process State Validator (TEXT+0xc1a3e0)
- Called by **241** syscall handlers — the MOST called function
- ~607 bytes
- Checks field at offset +0x138 in argument
- Likely validates process/thread state (not a deny function)

### Thread-Local Credential Check (TEXT+0x4c6fa0)
- Called by **187** syscall handlers
- ~2,219 bytes
- Starts with `gs:` segment prefix (thread-local storage)
- Gets current thread, then checks credential fields
- This is likely the function that reads process ucred and checks sandbox flags

### Copyin/Copyout Wrapper (TEXT+0x6fd6b0)
- Called by **181** syscall handlers
- ~371 bytes
- Called from ALL key syscalls (read, write, open, close, socket, sendmsg, sysctl, mmap)
- Validates user↔kernel data copies

## Exploitation Implications for 14.10

### What We Now Know
1. **Sysent structure** is stride=48, sy_call at +8 — same structure applies to 14.10
2. **115 Sony custom syscalls** exist in 532-676 range — many untested on 14.10
3. **Syscalls 661-670** are massive handlers (10-20KB each) in the dynlib code region — high complexity = higher bug probability
4. **Syscall 622** is the largest at 20KB with narg=6 — complex operations with many arguments
5. **Tiny syscalls** (560, 585, 606, 640) have minimal code and may bypass normal validation

### Key Attack Vectors
1. **Untested Sony syscalls via make_syscall()**: We've only tested 557, 593, 620 on 14.10. There are 112 more Sony customs to probe.
2. **Large complex handlers (622, 661-670, 601)**: Most likely to contain exploitable bugs due to code complexity.
3. **Heap R/W + KASLR defeat → kernel write**: If we defeat KASLR, we know exactly where the sandbox globals and sysent table are relative to the kernel base. One write = sandbox bypass.
4. **The sandbox is credential-based** (TEXT+0x4c6fa0 checks thread-local creds) — modifying the process ucred structure in kernel memory would bypass it.

### Offset Table (13.60 → 14.10 Translation)
These offsets are relative to kernel TEXT base. They will be at the same relative offset on 14.10 if Sony didn't reorganize the kernel:

| What | 13.60 Offset | Notes |
|------|-------------|-------|
| Sysent table | DATA+0x1a85c0 | In data segment |
| Jump stub table | TEXT+0x2663f0 | In text segment |
| Securelevel global | DATA+0xc2446c | |
| nosys handler | TEXT+0x5620e0 | |
| Main priv_check | TEXT+0xc08b50 | 70 callers |
| Thread cred check | TEXT+0x4c6fa0 | 187 callers |
| copyin/copyout | TEXT+0x6fd6b0 | 181 callers |

**WARNING:** These offsets are for 13.60. Sony may have recompiled with different optimizations for 14.10, shifting everything. The structure and approach remain valid but exact offsets need re-derivation on 14.10.
