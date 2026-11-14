# 637 `set_phys_fmem_limit`: an unprivileged kernel qword store that lands, and why it is still inert

**Status:** static, complete, over `docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`,
file offset == RVA). Probe 1241a is written but not yet run. This document exists because
`docs/PROC_LOCK_WEDGE_637_14_10.md` asserted that the store at `+0x280` was unreachable and blamed the
wedge on a mutex deadlock; both readings are wrong, and the true one is more interesting.

## 1. The body, in full

Thunk `0x265f08` -> body `0xabd930`, `narg = 2`: `uap[0]` = pid (dword), `uap[8]` = value (qword).

    00abd93e  48837e0811        cmp  qword [rsi + 8], 0x11      ; value < 17 -> EINVAL 22
    00abd949  0f8c31010000      jl   0xabda80
    00abd94f  8b06              mov  eax, [rsi]                 ; pid
    00abd954  85c0              test eax, eax
    00abd956  7419              je   0xabd971                  ; pid == 0 -> self
    00abd965  3b81bc000000      cmp  eax, [rcx + 0xbc]          ; == p_pid ?
    00abd96b  0f8521010000      jne  0xabda92                  ; else capability path
    00abd971  65488b042500000000 mov rax, gs:[0]               ; curthread
    00abd97a  488b5808          mov  rbx, [rax + 8]             ; curproc
    00abd984  488dbb48010000    lea  rdi, [rbx + 0x148]
    00abd98b  e87090a0ff        call 0x4c6a00                  ; mtx_lock(&proc->p_mtx)
    00abd990  8b83b0000000      mov  eax, [rbx + 0xb0]          ; p_flag
    00abd996  a900220000        test eax, 0x2200
    00abd99b  0f85c1000000      jne  0xabda62                  ; -> 3 EPERM-ish
    00abd9a1  83bbb800000001    cmp  dword [rbx + 0xb8], 1      ; p_state == 1
    00abd9a8  0f85b4000000      jne  0xabda62
    00abd9ae  ff8358030000      inc  dword [rbx + 0x358]        ; refcount
    00abd9b4  a900000010        test eax, 0x10000000
    00abd9b9  7508              jne  0xabd9c3                  ; flag set -> skip the assert
    00abd9be  e84dd0a7ff        call 0x53aa10                  ; see section 2
    00abd9d6  e8c595a0ff        call 0x4c6fa0                  ; mtx_unlock(&proc->p_mtx)
    00abd9db  4c8ba300020000    mov  r12, [rbx + 0x200]         ; p_vmspace
    00abd9e2  4d85e4            test r12, r12
    00abd9e5  743a              je   0xabda21
    00abd9e7  498dbc2478020000  lea  rdi, [r12 + 0x278]
    00abd9f9  e80290a0ff        call 0x4c6a00                  ; mtx_lock(vmspace + 0x278)
    00abd9fe  498b4508          mov  rax, [r13 + 8]             ; the caller's qword, verbatim
    00abda0c  4989842480020000  mov  qword [r12 + 0x280], rax    ; <<< THE STORE
    00abda14  e88795a0ff        call 0x4c6fa0                  ; mtx_unlock
    00abda19  4c89e7            mov  rdi, r12
    00abda1c  e84f42bdff        call 0x691c70                  ; fmem enforcement
    00abda2f  0fb68bb1000000    movzx ecx, byte [rbx + 0xb1]    ; refcount-drop tail
    00abda36  8b8358030000      mov  eax, [rbx + 0x358]
    00abda3c  c0e905            shr  cl, 5
    00abda3f  ffc8              dec  eax
    00abda44  898358030000      mov  [rbx + 0x358], eax
    00abda4c  80fa01            cmp  dl, 1
    00abda5b  e8b08e1400        call 0xc06910                   ; wakeup when the count hit zero

Return value: `r14d` is 0 on the store path (`00abd9ca xor r14d, r14d`), 3 on either gate,
1 on the capability check at `0xabda92`, 22 on the `value < 17` guard.

## 2. `0x53aa10` is a fatal assert, not a worker

    f687b300000010  test byte [rdi + 0xb3], 0x10
    7401            je   0x53aa1a
    c3              ret
    ... at 0x53aa1a: push rbp; mov rbp, rsp; call 0x7f1950; lea rdi, [rip - 0x10];
        call 0x7f1810; lea rsi, [rip + 0xd4736b]; mov edi, 7; xor eax, eax;
        call 0xc9aa10; ud2

Nine bytes of check, a `ret`, and a `printf(fmt); ud2` death path. Six earlier probes observed 637
returning 0 for large values, and that is only possible if `[proc + 0xb3] & 0x10` is **set**, so this
function executes its `ret` and nothing else. It cannot be the wedge.

## 3. Where the value is read: `0x6918a0`, the fmem reclaim loop

    006918cd  85db            test ebx, ebx                   ; ebx = 1 from 0x691c70
    006918cf  b8ffffff7f      mov  eax, 0x7fffffff
    006918d4  b90a000000      mov  ecx, 0xa                   ; slice = 10 or 0x7fffffff
    006918e7  0f45c8          cmovne ecx, eax
    00691900  498b86d8010000  mov  rax, [r14 + 0x1d8]         ; accounting object
    00691907  498b8e30020000  mov  rcx, [r14 + 0x230]         ; bytes in use
    0069190e  488b4050        mov  rax, [rax + 0x50]          ; capacity, bytes
    00691912  48c1f90e        sar  rcx, 0xe                   ; >> 14, 16 KiB pages
    00691916  4829c8          sub  rax, rcx
    00691919  49398680020000  cmp  qword [r14 + 0x280], rax   ; <<< the stored value
    00691920  0f8f0f030000    jg   0x691c35                   ; limit above available -> done

Otherwise it walks the vm_map circular list (`mov rax, [r14 + 8]; cmp rax, r14;` next at
`[rax + 8]`), skips entries by protection (`test dword [rax + 0x60], 0x40102`) and by object type
(`movzx ecx, byte [r15 + 0x9d]; cmp ecx, 8; bt 0x187, ecx`), computes per-entry page counts with a
second `sar ..., 0xe`, and calls the pageout path (`0x461b20`, `0xb897f0`, `0x8ea110`) until the
comparison is satisfied.

**The value is in 16 KiB pages.** 17 is the smallest legal value, and 17 pages (272 KiB) is not
reachable by a process that is already running, so the loop has no exit condition it can ever meet.
That is the wedge: an unbounded reclaim under a held mutex, not a self-deadlock. It is a signed
compare, so a value with bit 63 set loops exactly the same way.

## 4. So is it a primitive?

The store is real, verbatim, capability-free, repeatable and does not disturb the process:
`637(0, V)` with `V >= 0x40000000` writes `V` to `[p_vmspace + 0x280]` and returns 0. It is the
first unprivileged kernel qword store this corpus has confirmed on 14.10 by both disassembly and a
return value that only the store path can produce.

It is also inert, for a reason that will not change with a better probe: the field is a page count.
A 252-instruction census of every `[reg + 0x280]` reference in the image, classified by operand role,
finds the qword form read in exactly one place - the comparison at `0x691919` - and never
dereferenced, never used as an index, never copied out. Writing it changes only how hard the reclaim
loop tries.

Value for the objective (kernel R/W): none directly. Value as evidence: it separates "the store is
unreachable" from "the store lands and the field is uninteresting", which is the distinction that
matters if a future bug or a later firmware exposes `+0x280` to a different reader.

## 5. What would have made it a primitive

Any one of these would have converted it: `+0x280` used as a length for a copyout, used as an index,
or dereferenced as a pointer. The census in section 4 rules all three out for this image. The one
residual question is whether a *32-bit* reader exists - the field is written as a qword and the
comparison is a qword, but several dozen `dword [reg + 0x280]` reads exist elsewhere in the image.
They are all on unrelated structures (their base registers are stack frames or objects loaded from
other offsets) and none is reachable from `p_vmspace`, so the answer is no.

## 6. Reproduce

* `python .local/dis_637_full.py` - the body, annotated by hand in section 1.
* `python .local/dis_637_helpers.py` - `0x53aa10` and `0x691c70`.
* `python .local/d6918a0.py` - the enforcement routine.
* `python .local/scan_280c.py` - the `[reg + 0x280]` census (252 sites, read/write classified).

**The A/B experiment listed as item 4 of `docs/STATE_AND_PLAN_2026_11_05.md` is withdrawn.** It was
"allocate 64 MiB chunks until one fails, call `637(0, size)`, retry". Section 3 shows every value
that could change an allocation ceiling is below `capacity - usage`, which is exactly the set that
enters the reclaim loop. A value large enough to skip the loop is large enough to have no effect, and
a value small enough to have an effect wedges the console. There is no third case, so the experiment
can only produce a relaunch or a null result, and the store is already proved by the six recorded
`return 0` calls.