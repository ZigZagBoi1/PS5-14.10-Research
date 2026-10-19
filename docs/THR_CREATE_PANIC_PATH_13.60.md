# thr_create(430) kernel panic — static root-cause analysis (13.60)

> Scope: **13.60 only.** Decompiled from a full post-HV-defeat kernel TEXT dump
> (16,391-symbol Ghidra project). No 14.10 kernel image exists; behavioral
> differences on 14.10 are possible. No console was contacted for this analysis.

## 1. Summary

`thr_create(430)` on the PS5 creates a new user thread by copying a `ucontext_t`
from userspace. When the context specifies invalid register values (e.g. RIP=0),
the new thread is scheduled, faults immediately, and the kernel's trap handler
reaches `trap_fatal()` → `panic()` instead of delivering a signal to the process.

The root cause is a **missing `pcb_onfault` recovery path** in the new thread's
first fault. The parent thread has `pcb_onfault` set (it was doing `copyin()`
when it called `thr_create`), but the child thread inherits a **zeroed PCB**
from `cpu_copy_thread()` → `pcb_onfault = NULL`. When the child faults at
RIP=0, `trap_pfault()` sees `pcb_onfault == NULL` in kernel-mode context
(during the thread's first return-to-userspace transition) and falls through
to `trap_fatal()`.

## 2. The crash chain

```
thr_create(430)
  ↓ copyin(uap->ctx, stack, 0x500)
  ↓ shared_worker(td, 0, ops=0x265fc8, ctx, 0)     [0x437f30]
      ↓ thread_alloc()                               [0x6ad450]  → newtd
      ↓ cpu_copy_thread(newtd, td)                   → copies PCB, BUT:
      ↓ bzero(newtd->td_startzero, range)            → zeroes td_startzero..td_endzero
      ↓ (*ops)(newtd, ctx)                            [0x437d90]
          ↓ suword(id_ptr, newtd->td_tid)            → TID copyout (id oracle)
          ↓ set_mcontext(newtd, ctx+0x40)             [0xa0ac60]
              ↓ validates: magic==0x480, flags<=7, type∈{0x10000,0x10002}
              ↓ copies register block → newtd->trapframe   [td+0x460]
              ↓ RIP=0, RSP=0, all GPRs=0 (from zeroed ucontext)
      ↓ return 0 (success)
  ↓ thread_link(newtd, proc)
  ↓ sched_fork_thread(td, newtd)
  ↓ TD_SET_CAN_RUN(newtd)
  ↓ sched_add(newtd, SRQ_BORING)                    → newtd is RUNNABLE
  ↓ return 0 to userspace                           → parent thread continues

                    ═══ scheduler picks up newtd ═══

newtd starts executing:
  ↓ CPU fetches instruction at RIP=0 (user mode, cs=0x43 → SEL_UPL)
  ↓ page fault: VA=0, tf_err = PGEX_U | PGEX_I (user + instruction fetch)
  ↓ IDT → exception.S → trap_check()                [0x4ee0e0]

trap_check():                                        [case 0xc = T_PAGEFLT]
  ↓ ISPL(tf_cs) check:  (tf_cs & 3) → distinguishes kernel/user mode
  ↓ TWO BRANCHES depending on trap origin:
      Branch A: (~tf_cs & 3) != 0  → kernel-mode fault handler  [line 80]
      Branch B: (~tf_cs & 3) == 0  → user-mode fault handler    [line 147+]

  ↓ For newtd: tf_cs was set by set_mcontext from user's ctx
  ↓ If ctx+0xC0 (mapped to tf_cs) was ZEROED → tf_cs=0 → ISPL=0 → KERNEL MODE!
  ↓ Falls into Branch A (kernel-mode handler)

Branch A, case 0xc:
  ↓ calls trap_pfault(frame, 0)                      [0x4eeff0]  ← usermode=FALSE

trap_pfault(frame, usermode=0):                       [the critical function]
  ↓ va = frame->tf_rip (= 0x0)
  ↓ va < VM_MIN_KERNEL_ADDRESS → user-space address
  ↓ BUT usermode=0 (kernel context) AND:
      td->td_intr_nesting_level == 0
      curpcb->pcb_onfault == NULL       ← NO FAULT RECOVERY HANDLER
  ↓ → goto trap_fatal(frame, va)                     [0x4eeb00]

trap_fatal():
  ↓ printf("Fatal trap 12: page fault while in kernel mode")
  ↓ panic("page fault")                              → KERNEL PANIC → PS5 SHUTS DOWN
```

## 3. Root cause: tf_cs=0 makes a user fault look like a kernel fault

The `set_mcontext()` consumer at `0xa0ac60` copies the register block from the
user-supplied `ucontext_t` into the new thread's trapframe at `td+0x460`.

The trapframe layout (from the register-copy loop at `0xa0af00`–`0xa0afbc`):
```
ctx+0x48 → tf+0x00   ctx+0x50 → tf+0x08   ctx+0x58 → tf+0x10
ctx+0x60 → tf+0x18   ctx+0x68 → tf+0x20   ctx+0x70 → tf+0x28
ctx+0x78 → tf+0x30   ctx+0x80 → tf+0x38   ctx+0x88 → tf+0x40
ctx+0x90 → tf+0x48   ctx+0x98 → tf+0x50   ctx+0xA0 → tf+0x58
ctx+0xA8 → tf+0x60   ctx+0xB0 → tf+0x68   ctx+0xB8 → tf+0x70
ctx+0xE0 → tf+0xE8 (RIP)
ctx+0xF8 → tf+0x100 (RSP)
ctx+0x100→ tf+0x108 (SS)
```

**The critical field: `ctx+0xC0` → `tf+0xF0` = the CS (code segment) register.**

In vanilla FreeBSD, `set_mcontext()` in `sys/amd64/amd64/machdep.c` does:
```c
tp->tf_cs = mcp->mc_cs | SEL_RPL_MASK;  // ALWAYS forces ring-3 bits
tp->tf_ss = mcp->mc_ss | SEL_RPL_MASK;
```
This ensures the new thread ALWAYS runs in user mode regardless of what the
caller passes.

**In the PS5 13.60 `set_mcontext()`** at `0xa0ac60`, the register-copy loop at
`0xa0af00`–`0xa0afbc` copies the raw value from the user context without
OR-ing `SEL_RPL_MASK`. This means:
- If the user passes `ctx+0xC0 = 0` → `tf_cs = 0` → `ISPL(0) = 0` = **kernel mode**
- The trap handler thinks it's handling a kernel-mode fault
- `trap_pfault` is called with `usermode=0`
- `pcb_onfault` is NULL (new thread) → `trap_fatal()` → panic

## 4. Why vanilla FreeBSD doesn't panic

In vanilla FreeBSD 11.0.0 (`sys/amd64/amd64/machdep.c:453`):
```c
int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
    struct trapframe *tp;
    // ...
    tp = td->td_frame;
    // ...
    tp->tf_cs = mcp->mc_cs | SEL_RPL_MASK;  // ← forces user-mode bits
    tp->tf_ss = mcp->mc_ss | SEL_RPL_MASK;
    // ...
}
```

`SEL_RPL_MASK` is `0x3` — it forces the two least-significant bits of CS to
`11` (ring 3 = user mode). This means no matter what the user passes for CS,
the thread always starts in ring 3.

When the thread then faults at RIP=0:
- `trap()` sees `ISPL(tf_cs) == SEL_UPL` (3) → user-mode fault
- `trap_pfault()` is called with `usermode=1`
- `vm_fault()` fails (VA 0 unmapped)
- Returns `SIGSEGV` to the process → clean process kill, **no kernel panic**

## 5. Is this exploitable? Two scenarios

### Scenario A: tf_cs=0 (current crash)

When tf_cs=0, the CPU will NOT actually execute in ring 0 — the IRETQ that
returns to userspace will #GP because CS=0 is not a valid segment selector.
This #GP is itself a kernel-mode trap, which may cascade to a double fault.
The kernel panic is real but the thread never actually executes user code.

**Exploit value: low for code execution, but high as a denial-of-service
(kernel panic from sandbox).**

### Scenario B: tf_cs=0x43 (user mode with controlled registers)

If the user passes `ctx+0xC0 = 0x43` (the normal user CS), then:
- The thread starts properly in user mode
- RIP and RSP are user-controlled from the ucontext
- The fault at RIP=0 goes through the normal user-mode path
- `trapsignal()` delivers SIGSEGV → process dies (clean, no panic)

**This scenario does NOT panic** — but it gives the attacker a second thread
in the process, which is a **race condition primitive** (TOCTOU, UAF-via-race).

### Scenario C: tf_cs=0x43, RIP=valid userland address

If the user sets RIP to a valid mapped address (e.g. a Lua C function, eboot
gadget, or GPU mmap region) and RSP to a valid stack:
- The child thread runs real user code
- Two threads race against each other
- This enables all threading-dependent exploit classes (race conditions, UAFs)

**This is the highest-value path** — and it was previously believed impossible
on 14.10 because `thr_new` (455) was blocked and `thr_create` (430) was
undocumented.

## 6. The actual 14.10 crash

The crash observed on 14.10 matches Scenario A exactly:
- Zeroed ucontext → tf_cs=0 → kernel thinks it's a kernel fault → panic
- Entry point doesn't matter (RIP=0, longjmp, thr_exit) because the panic
  is in the CS check, not in the user code

## 7. Concrete next steps for probes

### 7a. Stop the panic: set CS=0x43 in the ucontext

The immediate fix for the panic is to set `ctx+0xC0 = 0x43` (user code segment)
and `ctx+0x100 = 0x3B` (user stack segment). This makes the trap handler take
the correct user-mode path → SIGSEGV → clean process kill instead of panic.

### 7b. Get a second thread running

Set the ucontext to:
```
ctx+0xC0  = 0x43    (CS = user mode)
ctx+0x100 = 0x3B    (SS = user stack segment)
ctx+0xE0  = <RIP>   (valid userland address — e.g. eboot entry, Lua fn, thr_exit)
ctx+0xF8  = <RSP>   (valid stack — GPU mmap region or stack clone)
```

If the child thread starts and runs for even one instruction before faulting,
it proves multi-threading from the sandbox — which unlocks race-condition
exploit classes.

### 7c. Race condition exploitation

With two threads:
1. Thread A calls `aio_submit` or another kernel operation that holds a reference
2. Thread B races to free/modify the referenced object
3. UAF or TOCTOU in the kernel → kernel R/W

This is the standard threading-to-kernel-R/W escalation used by every modern
kernel exploit chain.

## 8. Function address table (13.60)

All addresses are absolute VAs (KASLR'd for this dump; subtract `0xffffffffdf100000`
for RVA).

| Function | VA | RVA | Size | Role |
|----------|-----|-----|------|------|
| `thr_create` entry | `0xdf537cf0` | `0x437cf0` | 157 | copyin(0x500) + call worker |
| `thr_create` ops | `0xdf537d90` | `0x437d90` | 70 | TID copyout + set_mcontext |
| shared worker | `0xdf537f30` | `0x437f30` | 846 | thread_alloc + CFI + sched_add |
| `set_mcontext` | `0xdfa0ac60` | `0xa0ac60` | 10742 | validate magic/flags + copy regs |
| `trap_check` (dispatcher) | `0xdf4ee0e0` | `0x3ee0e0` | 2577 | switch on trapno |
| `trap_pfault` | `0xdf4eeff0` | `0x3eeff0` | 576 | vm_fault or trap_fatal |
| `trap_fatal` | `0xdf4eeb00` | `0x3eeb00` | 1256 | print diagnostics + panic |
| `thread_exit` | `0xdfc90cf0` | `0xb90cf0` | 802 | thread teardown |
| `thread_dtor` | `0xdf6f9c00` | `0x5f9c00` | — | thread destructor |
| `userret` | `0xdf5ea110` | `0x4ea110` | 482 | return to userspace |

## 9. Provenance

- Decompiled via Ghidra 12.1.4 headless batch from `corpus/kernel/ghidra_project/ps5_kernel_1360`
- Cross-referenced against FreeBSD 11.0.0 source (`refs/freebsd-11.0.0/sys/`)
- Key files: `kern/kern_thr.c` (thread_create), `amd64/amd64/machdep.c` (set_mcontext),
  `amd64/amd64/trap.c` (trap, trap_pfault, trap_fatal)
- 16 kernel functions decompiled; 6 trap-chain functions decompiled
- All decompiles in `corpus/kernel/decompiled/thr_create_chain/`

## 10. Limits

- **13.60 only.** Sony may have modified `set_mcontext`, `trap_pfault`, or the
  sandbox threading policy on 14.10. The behavioral match (panic on zeroed
  ucontext, delayed crash, entry point irrelevant) is strong but not proof
  of identical code.
- **The `SEL_RPL_MASK` omission is inferred from the decompiled register-copy
  loop**, not from a diff of Sony's `set_mcontext` source against vanilla. The
  decompiler may miss a mask operation hidden in complex control flow. The
  14.10 crash behavior is consistent with the inference.
- **Exploitability on 14.10 is not established.** Scenario B/C require that
  `thr_create` with CS=0x43 produces a running child thread, which has not
  been tested.
