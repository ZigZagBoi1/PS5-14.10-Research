# The ucontext family works on 14.10: 430, 632, 634 and 633 all return 0

Measured 2026-11-05 (probes 1228a, 1228b, 1228c; session pid 87). This is the first time 632, 634
and 633 have been called in this corpus, and the first time the get is known to copy.

## 1. The context offsets decide everything

| probe | context layout | 430 result |
|---|---|---|
| 1228a | 156a layout: CS/RIP/RSP/SS at ctx+0x98/0x90/0xA8/0xB0, magic at +0x118 | **-1 EINVAL**, TID written but not a thread |
| 1228b | same, plus zeroed context and gates at +0x0d0/+0x110 | -1 EINVAL |
| 1228c | 156c layout: **CS +0xc0, RIP +0xe0, RSP +0xf8, SS +0x100, magic +0x108 = 0x480, flags +0x0d0 = 0, type +0x110 = 0x10000** | **0**, TID 0x18E3D, `thr_kill(tid,0)` = 0 |

`PROBE_INDEX` row 80a already recorded that 156a's offsets are the rejected ones; this run is the
behavioural confirmation, and it cost three probes because the wrong recipe was read first.

## 2. 632 / 634 / 633

With a live, spinning child (RIP = `jmp $`, RSP = mmap'd 64 KB stack page):

| call | result |
|---|---|
| `632(tid)` thr_suspend_ucontext | **0** |
| `634(tid, buf)` thr_get_ucontext | **0**, and the 0x600-byte buffer that was prefilled with 0xA5A5A5A5 has its first dwords **zeroed** |
| `633(tid)` thr_resume_ucontext | **0** |
| `433(tid,0)` after resume | 0 - the thread is alive |

So the kernel does copy into the caller's buffer. The earlier EINVAL in 1227b was the "thread is
running" path at `0x4391d7` (`cmp dword [thread+0xe4],0 ; jns error`), exactly as the body
predicted: **a thread must be suspended before its ucontext can be read**.

## 3. No kernel pointer in the copy

A scan of the full 0x4c0 bytes for qwords in the supervisor range found **zero**, and the surviving
tail of the 0xA5 fill (beyond the copied length) was untouched. For a user thread suspended at
`jmp $` the saved context is user state only: CS 0x43, RIP in eboot, RSP in our stack page, and the
GPR block we passed at create time. That is the expected result and it closes the "634 leaks the
kernel thread structure" hypothesis before anyone spends more runs on it.

## 4. What is still worth one probe

1. **Dump the copied context in full** (0x4c0 bytes, 16 rows of hex) and confirm the layout: the
   fields at +0xc0/+0xe0/+0xf8/+0x100 should come back as 0x43, the `jmp $` address and our stack
   pointer. If they do, the getter is a faithful mirror and `635 thr_set_ucontext` becomes the
   interesting half: it is the inverse write direction, and the same field table decides what a
   caller can install into a suspended thread.
2. **`635` on the suspended child**: write a context whose RIP points at a second gadget and see
   whether the resumed thread executes it. That is a kernel-mediated register install path, and it
   has never been exercised.
3. The thread family is otherwise now proven end to end, which matters for every race in the plan
   (a suspended-and-resumed thread is a deterministic scheduler lever the earlier probes did not
   have).


## 5. 635 thr_set_ucontext does not exist, and the context layout is now mapped

### 5.1 635 is an ENOSYS stub

Body at `0x4393A0` is four instructions:

```
4393a0 push rbp
4393a1 mov rbp,rsp
4393a4 mov eax,0x4e        ; 78 = ENOSYS
4393a9 pop rbp
4393aa ret
```

The corpus already records `635` as an ENOSYS stub (the `78` trampoline family with 619 and 620), so
the "inverse direction" - installing a caller context into a suspended thread, and with it the idea of
smuggling a kernel `CS` selector through the setter - **does not exist on this firmware**. Reading the
body first saved a run; this is the second time this session that a static read prevented a duplicate
probe.

### 5.2 Empirical ucontext layout (probe 1229a)

Created a child whose fifteen GPR slots at `+0x48..+0xB8` carried a marker, suspended it with 632,
read it back with 634:

| offset | value seen | meaning |
|---|---|---|
| +0x048 .. +0x0B8 | 0x1111000000000000 (all fifteen) | the GPR block is preserved verbatim |
| +0x0C0 | 0x1B001300000000 | kernel-computed selector blob; a caller write here does **not** survive |
| +0x0D0 | 0x3B003B00000000 | two 0x3B selectors |
| +0x0E0 | 0x206D5481 | **RIP** (our `jmp $`) |
| +0x0E8 | 0x43 | **CS** |
| +0x0F0 | 0x202 | **RFLAGS** |
| +0x0F8 | 0x3113BBF00 | **RSP** (our stack top) |
| +0x100 | 0x3B | **SS** |
| +0x108 | 0x480 | the magic 430 validates |
| +0x110 / +0x118 | 0x10002 / 0x20002 | type / subtype, normalised by the kernel |
| +0x140 | 0x37F | small state field |
| +0x158 | 0x2FFFF00009FC0 | packed small values |
| +0x340 | 3 | |
| +0x480 | 0x881FFC080 | user-range pointer (TLS/FPU area) |

Two corrections to the working recipe follow from this:

* the field the create path reads is **CS at +0x0E8**, not +0x0C0 as 156c's comment suggests; +0x0C0 is
  overwritten by the kernel on the way out. The create call still succeeds because the kernel derives
  CS from the type/subtype pair, and the 0x43 the earlier probes wrote at +0xc0 was never the input.
* the kernel **normalises** `+0x110 = 0x10000` to `0x10002` and `+0x118 = 0` to `0x20002`, which is
  why the "type in {0x10000,0x10002}" note in `THR_CREATE_430_CONTEXT.md` is a read-back range and
  not a write requirement.

### 5.3 What the family is good for, and what it is not

* **Not** a leak: every value in the 0x4c0 bytes is user state or a normalised small constant; there is
  no supervisor-range qword, and suspension appears to take effect at the user-return boundary, so a
  thread cannot be frozen *inside* a syscall and read there.
* **Is** a deterministic scheduling lever: a thread can be created, verified alive (`433(tid,0)=0`),
  suspended (`632=0`) and resumed (`633=0`) at will, which turns every two-thread gate in the plan
  from a timing guess into a controlled sequence.

### 5.4 Correction: a thread *can* be frozen inside a syscall, and the context it exports is still the user frame (probe 1237c)

Section 5.3 asserted that "suspension appears to take effect at the user-return boundary, so a thread
cannot be frozen *inside* a syscall and read there". Half of that was reasoning and half of it was
wrong, and 1237c separates the two.

Method: one child created with the working recipe, `rax = 209` (poll), `rdi = struct pollfd *`,
`rsi = 1`, `rdx = 6000`, `RIP = syscall stub`, stack return slot holding 1. After 150 ms the child
is inside `poll` with a 6 s timeout and no data on the socketpair. Then:

| call | result |
|---|---|
| 433(tid,0) | 0 (the tid resolves while the thread is in-kernel) |
| 632(tid) | **0 - the suspend is accepted while the thread is inside poll** |
| 634(tid,buf) | **0 - the context is copied** |
| 633(tid) | 0 |

So the scheduling claim in 5.3 is refuted: an in-syscall thread *can* be frozen and resumed at will.

The leak claim survives, and this is the measurement that had been missing. The copied frame for that
in-kernel thread (eboot base 0x0C560000, stub 0x0818858B57):

| offset | value | reading |
|---|---|---|
| +0x048 | 0x31069DA40 | rdi, the `struct pollfd *` we passed |
| +0x050 | 1 | rsi, nfds |
| +0x058 | 0x1770 | rdx, the 6000 ms timeout - preserved verbatim |
| +0x078 | 0xD1 | rax, 209 - the syscall number is still in the frame |
| +0x090 | 0x515CA11 | continuation pointer, user range |
| +0x0E0 | 0x0818858B5C | RIP, which is **stub + 5** - the instruction after `syscall` |
| +0x0E8 | 0x43 | CS |
| +0x0F0 | 0x202 | RFLAGS |
| +0x0F8 | 0x31070BF00 | RSP, our stack |

Scan of the full 0x500-byte copy: **160 qwords, 0 supervisor-range, 0 with hi32 >= 0xFFFF0000.** The
frame the kernel hands back is the *user* trap frame at the syscall boundary - the argument registers
intact, RIP already advanced past the `syscall` instruction. Nothing on the kernel stack, no frame
pointer, no return address into the kernel, no per-thread kernel pointer.

Two secondary observations:

* ~~634 wrote the 16-bit value 0x0400 at buffer+0 on a failed call (1237b, ESRCH path).~~
  **RETRACTED 2026-11-05 (probe 1238a).** That was a Lua numeric-precision artifact, not a kernel
  write. `0xA5A5A5A5A5A5A5A5` is not representable as a double; `uint64:tonumber()` rounds it, and
  the probe compared the rounded value with the exact one, so every qword read as "changed". A
  38-call sweep with the same fill pattern shows the buffer **untouched** on both the EINVAL and the
  ESRCH path: 634 writes nothing at all before it refuses. Do not read the first bytes of that buffer
  as an output header.
* Both 1237b and 1237c took the loader process down a few hundred milliseconds after a **suspended**
  child was resumed, allowed to finish its syscall and then returned to unmapped address 1. The
  connection received a 0x80-byte binary record (the fault blob) and then closed with no `=== DONE`.
  A child parked with `jmp $` and never resumed only starves the loader (1234a); a child that is
  suspended, resumed and then faults appears to kill it. Record this as a deployment hazard: any probe
  that combines 632/633 with a faulting exit needs the child to be released by allowing its syscall to
  complete and to spin briefly, not to fault, or the loader has to be relaunched afterwards.

Primitive worth keeping: **632 on a thread inside a syscall is a controllable in-kernel pause.** A
thread can be stopped mid-syscall, the parent can run an arbitrary sequence of other syscalls, and
then 633 releases it. Every two-thread gate that previously needed a sleep can be made deterministic.
No in-kernel state is readable through the pause itself.

