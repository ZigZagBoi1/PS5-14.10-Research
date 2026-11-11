# The thread family is process-scoped: resolver 0xb92420 decoded, and why it cannot be pointed at a
# kernel thread

Status: static decode of the 13.60 image plus one runtime sweep (probe 1238a, 2026-11-05). Written
after the mcontext installer result, because the obvious next question was whether the *other* half
of the thr_* family - suspend, resume, get-context - can be aimed at a thread that is not ours.

## 1. The idea being tested

634 copies a 0x4c0-byte thread context to user memory and was measured to contain nothing but the
calling thread's own user trap frame. If the handler resolved its first argument in the *global*
thread hash, then `634(kernel_tid, buf)` would copy the context of a **kernel thread**: a thread whose
saved pcb holds a kernel RIP, a kernel RSP and a kernel stack pointer. That is a supervisor-address
leak for the price of one syscall, and with 632/633 in the same family it would also be a
cross-process suspend primitive.

## 2. The resolver, decoded

All three handlers call the same helper, RVA **0xb92420**, with `edi = <id from the caller>` and
`esi = [curproc + 0xbc]`. The helper:

```
b9242b  mov   r14d, edi                    ; arg1
b92435  mov   ebx, esi                     ; arg2
b9243e  call  0x7d50c0                     ; lock (arg = global at rip+0x31ef9e3)
b92443  movsxd rcx, r14d
b92446  and    rcx, [rip + 0x31ef9a3]      ; bucket mask
b9244d  mov    rax, [rip + 0x31ef9a4]      ; table base
b92454  mov    rax, [rax + rcx*8]          ; bucket head
b9245b  je     0xb9252b                    ; empty -> NULL
b92470  cmp    dword [rax + 0x9c], r14d    ; <- exact match on a 32-bit id
b92477  je     0xb9248a
b92479  mov    rax, [rax + 0x50]           ; chain
b9248a  mov    rdi, [rax + 8]              ; td_proc
b9248e  cmp    ebx, -1                     ; -1 skips the process filter
b92493  cmp    dword [rdi + 0xbc], ebx     ; <- p_pid must equal arg2
b92499  jne    0xb9250c                    ; otherwise keep walking the chain
```

So the table is the kernel's **global thread hash**, keyed by a 32-bit thread id, and the returned
thread is filtered on `td_proc->p_pid` against the second argument. The `-1` escape at `0xb9248e`
would disable that filter - and no handler in this family ever passes `-1`.

| handler | body | arg1 as read | arg2 passed |
|---|---|---|---|
| 632 thr_suspend_ucontext | 0x438e30 | **qword** `mov rdi,[rsi]` | `[curproc+0xbc]` |
| 633 thr_resume_ucontext | 0x439070 | **qword** `mov rdi,[rsi]` | `[curproc+0xbc]` |
| 634 thr_get_ucontext | 0x439150 | **dword** `mov edi,[rsi]` | `[curproc+0xbc]` |

where `curproc` is reached as `[curthread+8]` and `curthread` is `gs:[0]`.

## 3. The 632 self-check mismatch, and why it is not a primitive

632 and 633 open with a short-circuit for a self-reference:

```
438e41  mov    rdi, qword ptr [rsi]        ; full 64-bit argument
438e49  movsxd rax, dword ptr [r12 + 0x9c] ; td_tid, sign-extended from 32 bits
438e51  cmp    rdi, rax
438e54  je     0x439014                    ; self -> error
```

Passing `tid | 0x100000000` defeats that comparison, because the resolver then truncates to `edi`
(`mov r14d, edi`) and finds the calling thread anyway. What the caller wins is the removal of the
self-check: 632 then takes the thread lock, sets `or dword [td+0xe4], 0x80000800` and
`mov dword [td+0x400], 4`, and enters the settle loop at `0x438ef0` waiting for the *same* thread it
is running on to reach state 3 or 4. That thread is the caller. The result is an in-kernel spin, not a
suspend, and the loader wedges. 634 does the argument read as a dword, so it does not have the
mismatch at all - which is exactly what probe 1238a measured (`self+2^32` behaves like `self`).

## 4. The 634 state gate, restated

```
4391c2  test byte [curthread + 0x529], 1   ; a debugger-ish flag on the caller skips the gate
4391cd  test byte [td + 0xe8], 0x20         ; target suspended -> proceed
4391d7  cmp  dword [td + 0xe4], 0
4391df  jns  0x43930f                      ; not suspended -> EINVAL
4391e5  mov  eax, [td + 0x400]              ; thread state
4391f2  jae  0x439253                       ; states 2/3/4 take the settle-and-retry path
439253  cmp  eax, 1
439256  je   0x439297                       ; <- the only path that reaches the copyout
```

The copyout at `0x439297` therefore requires `[td+0x400] == 1` **and** a suspended target. That is
consistent with 1237c, where the target was a child parked inside `poll()`.

## 5. Probe 1238a: measured

One connection, pid **96**, `thr_self` = **0x18E9F** (102,047 - the id space is global and sparse).
Thirty-eight calls, buffer filled with `0xA5`, every call scanned for supervisor-range qwords.

| argument | return | errno | buffer |
|---|---|---|---|
| own tid 0x18E9F | -1 | 22 EINVAL | untouched |
| own tid + 2^32 | -1 | 22 EINVAL | untouched (the dword read truncates) |
| 1,2,3,4,5,6,7,8,9,10,11,12,16,20,24,32,40,48,64,80,96,128,160,192,256,512,1024,4096 | -1 | 3 ESRCH | untouched |
| 0x7FFFFFFF, 0xFFFFFFFF, 0x1_0000_0000 | -1 | 3 ESRCH | untouched |

Zero supervisor-range qwords in every run. **A thread that does not belong to the calling process is
indistinguishable from a thread that does not exist**, which is exactly what the `p_pid` filter in
§2 predicts. The cross-process and kernel-thread form of 632/633/634 is closed.

## 6. Correction this probe forced

Probe 1237b had reported that 634 writes the 16-bit value `0x0400` at `buffer+0` on the ESRCH path,
and `UCONTEXT_FAMILY_14_10.md` §5.4 recorded it as an "output header written even on failure".
That was **an artifact of the probe, not a kernel write.** `0xA5A5A5A5A5A5A5A5` is not representable
as an IEEE double; `uint64:tonumber()` rounds it to `0xA5A5A5A5A5A5A800`, and the probe compared that
rounded value against the exact constant, so all 152 qwords "changed" on every call. 1238a uses the
same fill pattern and shows the same phantom change, and shows that the *only* difference between
the buffer before and after is the rounding: on both the EINVAL and the ESRCH path 634 writes
nothing at all. The section has been retracted in place.

Standing rule for every probe that fills a buffer with a 64-bit pattern and compares it: fill with a
value below 2^53 (e.g. `0x0000A5A5A5A5A5A5`), or compare the *rounded* pattern, or scan for
supervisor-range values only instead of testing equality.

## 7. What this leaves

* The thr_* family is process-scoped by construction and cannot reach a thread whose `p_pid` differs.
* 634's copy is gated on a suspended target in state 1, and the copy is the caller's own user trap
  frame - no kernel stack, no kernel RIP/RSP (the mcontext installer result in
  `MCONTEXT_INSTALL_14_10.md` explains why: the exported frame is built from `td_pcb`, and the pcb
  slots hold user values).
* 632's qword/dword mismatch is real but self-destructive: it only removes the self-check and turns
  the call into an in-kernel spin on the calling thread.

## 8. Reproduce

`probes/phase17_new_vectors/1238a_tid_space_pid_filter.lua`;
`results/phase17_new_vectors/1238a_tid_space_pid_filter_20261105_130709.txt`;
`.local/dis_634b.py` (634 body + resolver), `.local/dis_632.py` (632 and 633 bodies).
