# The Sony debug syscalls in the 13.60 sysent: 619, 620, 634, 635

Status: **static, from `docs/dumps_13.60/kernel_text.bin`** (base `0xffffffff8a9c0000`, file offset == RVA).
Handler bodies resolved from `docs/dumps_13.60/sysent_index.json` (sy_call is a hex-string full VA; RVA =
`int(v,16) - 0xffffffff8a9c0000`; each points at a 5-byte `e9 rel32` thunk).

These four numbers carry the most promising *names* in the Sony range — `test_debug_rwmem`,
`free_stack`, `thr_get_ucontext`, `thr_set_ucontext` — and the 14.10 sweep
(`results/phase15_native_sent/syscall_isolation_sweep_20261020_194148.txt`) only recorded `-1` for each
of them with six zero arguments. The point of this note is that two of the four are **hard-coded
`ENOSYS`** in the kernel itself, so their `-1` was never a missing-argument problem.

## 619 `test_debug_rwmem` — hard-coded ENOSYS

```
a37650: push rbp ; mov rbp,rsp
a37654: mov eax, 0x4e        ; 78 = ENOSYS
a37659: pop rbp ; ret
```

The whole body is nine bytes. `narg = 5` in the sysent entry, so the wrapper will happily forward five
arguments, and the body ignores all of them. **There is no implementation to reach on 13.60, and the
14.10 build would have to have added one.** This closes the most attractive name in the range.

## 635 `thr_set_ucontext` — hard-coded ENOSYS

```
4393a0: push rbp ; mov rbp,rsp
4393a4: mov eax, 0x4e
4393a9: pop rbp ; ret
```

Same nine-byte stub. Any theory that needs "write a ucontext into another thread" is closed at the
kernel side on 13.60; only 634 is implemented.

## 620 `free_stack` — real, and it unmaps the caller's own stack

Body `0xabd430`, `narg = 0`:

```
abd44f: rax = [rdi+8]            ; td_proc
abd453: rcx = [rdi+0x460]        ; td_pcb (or the pcb pointer field)
abd45a: r14 = [rcx+0x100]        ; pcb_spare / stack top
abd461: rbx = [rax+0x200]        ; proc->p_vmspace -> vm_map
abd468: r14 -= 0x80
abd46f: r14 &= ~0x3fff
abd476: call 0x8ac86820          ; vm map lock
abd47b: rdx = &[rbp-0x28]
abd485: call 0x8ac86c40          ; vm_map_lookup(map, start, &entry)
abd48e: rax = [rbp-0x28]
abd492: r14 = (r14 - [rax+0x20]) >> 14
abd49f: rsi = [rax+0x58] >> 14
abd4a3: rdi = [rax+0x50]
abd4b3: rdx = r14 & 0x7fffffff
abd4ae: ecx = 5
abd4ba: call 0x8ae23610          ; vm_map_remove(map, start, end, flags=5)
```

So it takes a pointer derived from the *calling thread's own* pcb, aligns it down to 16 KB, looks it up
in the *calling process's* vm_map and removes the pages. `0x8ae23610` is the body that is absent from
every dump (the residual noted in `docs/COPYOUT_CLASS_CLOSED.md`), so the fourth argument (5) can only
be read as a removal flag.

Consequence: the operation is confined to our own address space by construction (`proc->p_vmspace`),
and the address it removes comes from our own pcb. There is no argument, so nothing to steer. The
`0` the sweep recorded is the success return of a call that unmapped pages we then kept running on.

## 634 `thr_get_ucontext` — real, gated, and it copyout's 0x4c0 bytes

Body `0x439150`, `narg = 2`. `rsi` is the uap:

1. `lookup(uap->dword0, [td_proc+0xbc])` — `(tid, own pid)` via `0x8b552420`. The pid is hard-coded to
   our own process, so a foreign process's thread cannot be named.
2. Gate at `0x4391c2`: `td+0x529 & 1` (the same TDF bit that gates 601's second stage) **or**
   `thr+0xe8 & 0x20` **or** `thr+0xe4 < 0`. Otherwise `0x43930f` unlocks and returns `0x16` EINVAL.
3. With the gate passed: `[thr+0x400]` must be 2..5 (a suspend state), then
   `0x8b3cbb60(thr, rbp-0x4f0, 0)` builds the ucontext on the stack, and `0x4392fd`:
   `copyout(rbp-0x530, uap->qword1, 0x4c0)`.

The copyout source is a **stack buffer**, so this is the closed pattern, not a kernel-read primitive. The
only interesting part is the gate: it is the same `td+0x529` bit that 1195a showed to be clear for our
thread, and the extra `thr+0xe4 < 0` condition means an ordinary thread does not qualify either.

## What this changes

Nothing in the 619/620/634/635 group is a route. It removes four names from the "unprobed Sony
surface" list and one of them (`test_debug_rwmem`) was the single most attractive name in the range.
The useful residue is the second independent sighting of `td+0x529 & 1`: it gates 601's second stage
*and* 634's ucontext copyout, so it is a process-wide debug privilege bit that our process does not
hold. Any future route that depends on it needs a way to set a `td` flag first.
