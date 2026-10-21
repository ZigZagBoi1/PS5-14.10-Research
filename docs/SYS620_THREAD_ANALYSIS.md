# sys 620 VM Self-Modification — Thread-Based Targeting Analysis

## Background

`sys 620` is a zero-argument syscall with **no credential check**. Its kernel handler:

1. Reads the saved RIP from `td->trapframe + 0x100` (the syscall return address)
2. Computes `(saved_address - 0x80) & ~0x3fff` → a **16KB-aligned code page**
3. Calls a kernel VM operation with **mode 5** on that page

The "saved RIP" is the instruction after the `syscall` instruction that entered the kernel — i.e., wherever the calling thread was running.

## Thread Targeting Insight

On PS5 14.10, `thr_create(430)` with CS=0x43 / SS=0x3B creates a functional child thread (confirmed PR #60). Each thread has its **own trapframe**, so `td->trapframe + 0x100` returns a *different address* depending on which thread calls sys 620.

| Caller | Saved RIP location | Derived 16KB page |
|--------|--------------------|--------------------|
| Main thread (Lua loader) | Inside **eboot** dispatcher | An eboot .text page |
| Child thread (157a-style) | Inside **libkernel** (`gettimeofday+7` wrapper) | A libkernel .text page |

This means sys 620 can be pointed at **different VM objects** without any argument control — just by calling it from different threads.

## Why This Matters

If mode 5 is a **page attribute modification** (e.g., changing protection bits, clearing execute-only, or toggling write permissions):

- **From main thread:** targets eboot's code page. Eboot is mapped as execute-only (XO) by the loader, so the VM object likely has strict protections. A mode-5 change here could reveal eboot bytes (defeating XO) or enable writes (defeating W^X).

- **From child thread:** targets libkernel's code page. Libkernel is the kernel's own userland shim — its VM object may have *different* protection semantics. If mode 5 changes page attributes on a libkernel page and that change is observable via `mprotect` or `sys 547` (VM region query), it indicates that VM attribute operations are reachable from userland.

## Combined with sys 617

`sys 617` writes a byte to a hardware register (MMIO base+0x25310) with no credential check. The written byte is translated through a lookup table at 0xbd79ee0. Hardware registers can control GPU state, display pipeline, power management, and potentially security configuration.

If the hardware register that sys 617 writes controls a **global predicate or permission flag**, then the sequence:

```
sys 617(byte_value)  →  sys 620()  →  mprotect(page, RWX)
```

could unlock W^X enforcement by first setting hardware state, then having the kernel VM operation see a different permission landscape.

## Probe 99b Design

| Section | What it does | Expected outcome |
|---------|-------------|-----------------|
| A | sys 620 reachability + VM region query before/after | Confirms sys 620 returns without crash; VM counter delta shows if kernel performed an operation |
| B | sys 620 → mprotect(RWX) retest | If page attributes changed, mprotect that previously failed may now succeed |
| C | Launch child thread (gettimeofday loop in libkernel) → sys 620 from main → check BOTH eboot and libkernel regions | Proves different target page; if libkernel region changes, mode 5 affects the derived page |
| D | Full sys 617 byte sweep (0-255) combined with sys 620 + mprotect check | Brute-force search for a hardware state that enables the VM attribute change |

## Risk Assessment

- **Crash class: MODERATE.** sys 620 modifies kernel VM state. If mode 5 triggers an unexpected VM operation (e.g., page fault on a kernel-owned page), it could panic. The child thread in section C adds crash risk from thr_kill (kills the whole process on this kernel).
- **Sections A-B:** Low risk — main thread only, well-tested syscall patterns.
- **Section C:** Moderate — child thread creation + concurrent sys 620.
- **Section D:** Moderate — 256 hardware register writes. Unknown side effects possible.

## References

- `probes/phase17_new_vectors/99a_hw_write_vm_selfmod.lua` — original single-threaded probe
- `probes/phase17_new_vectors/157a_syscall_loop_thread.lua` — child thread syscall loop proof
- `docs/THR_CREATE_430_CONTEXT.md` — ucontext field offsets
- `docs/THR_CREATE_PANIC_PATH_13.60.md` — panic root cause (CS=0)
