# Children can issue arbitrary syscalls, and poll+close survives 60 raced closes

Measured 2026-11-05 (probe 1234a, pid 80).

## 1. The ucontext GPR block, verified functionally

1229a mapped the layout by reading a suspended child's context back. This run proves the *write* side:
a child created with

```
ctx+0x48 = fd      (rdi)
ctx+0x78 = 6       (rax, close)
ctx+0xE0 = syscall stub
ctx+0xF8 = stack top (qword at top = jmp $)
```

really executed `close(fd)` - the parent's `fstat(fd)` afterwards returns **EBADF**. The mapping is
therefore the FreeBSD order, with the fifteen GPRs starting at `+0x48`:

| slot | register | slot | register |
|---|---|---|---|
| +0x48 | rdi | +0x80 | rbx |
| +0x50 | rsi | +0x88 | rbp |
| +0x58 | rdx | +0x90 | r10 |
| +0x60 | rcx | +0x98 | r11 |
| +0x68 | r8 | +0xA0 | r12 |
| +0x70 | r9 | +0xA8 | r13 |
| +0x78 | rax | +0xB0 | r14 |
| | | +0xB8 | r15 |

That is the capability the earlier thread work did not have: **a child thread can issue any syscall with
chosen arguments**, not just spin. Every two-thread experiment in the plan can now put a *specific*
syscall on the child side, with the parent free to race it.

## 2. poll + close: 60 raced closes, no corruption

Upstream's open row O11 calls CVE-2026-45251 ("poll+close on non-procdesc descriptors") untested and
explicitly different from the kevent+close work they exhausted.

Design: for each iteration a fresh socketpair; a child created with `rax = 209 (poll)`, `rdi = &pollfd`
pointing at the read end, `rsi = 1`, `rdx = 3000 ms`; 2 ms later the parent `close`es that descriptor
while the child is parked; both ends are then closed and the loop continues.

| metric | value |
|---|---|
| iterations | 60 |
| children created | 60/60 (`rv = 0` every time) |
| closes issued while a poll was outstanding | 60 |
| process alive at the end | yes (`pid_end = 80`) |
| crash, hang, or corrupted return | none |

So at this shape the poll registration holds a reference that survives the close, exactly like
`kevent`+close, and the wake path does not touch freed memory. 60 iterations cannot prove the race
absent - the corpus's own standard is thousands - but it is the first measurement of this path and it
behaves like the refcounted one.

## 3. What the child-syscall capability changes

The races that previously needed a parent-side syscall and a lucky window can now be built as:

* child parked *inside* the kernel on the vulnerable call (poll, aio wait, read, kevent);
* parent performs the mutation (close, delete, rewrite) with a controlled delay;
* optionally a second child issuing the third syscall of a three-way race.

Combined with 632/633 suspend/resume, the only remaining nondeterminism is the kernel's own scheduling.


## 4. The cost of a spinning child: 1234a starved the loader

Every child in 1234a was built with `jmp $` as its return address, so after the poll returned (the parent
had closed the descriptor) the child did **not** exit - it spun on its own core forever. 60 of them
accumulated in one process. The next probe (1234b) received **zero bytes**: the connection was
accepted and the loader never answered, and `port_witness` reports **LOADER-STUCK**.

So a spinning child is not free. Consequences, and the rule that follows:

* a probe that spawns N children must assume every one of them is still running when the probe ends;
* children must **exit** after their work. The documented confinement from 999a is the right one: let
  the child fault on an unmapped return address so the loader's SIGSEGV chain runs `thr_exit(431)`,
  which ends that thread and leaves the process alive with the same pid;
* if a probe must keep a child parked (a poll, a blocking read, an aio wait), it should park exactly
  one and close/complete the object it waits on so the child returns and exits.

1234b itself (fd-number reuse against a blocked read) never ran; it is written and correct, but it was
sent to a starved loader. Its design stands: park one child in `read(fd0)`, close fd0, take the same
descriptor number with a new socketpair, write to the new peer, and check whether the child's buffer
receives the bytes. `0x4B4B4B4B` in the buffer would mean the blocked read followed the descriptor
number rather than the file it was opened on - an fd ABA. The expected answer is "no", because `read`
holds a reference from `fget`, but it has not been measured.
