# The mcontext installer: why the iret-to-CPL0 route is structurally closed on 14.10

Status: static analysis of the 13.60 image plus one runtime measurement (probe 1237c). Written
2026-11-05.

## 1. Why this mattered

The highest-value idea left after the copy-primitive audits was that the kernel installs a
**caller-supplied** machine context and then `iretq`s into it. If the CS field of that context reached
the PCB unchanged, a thread could be created - or a signal frame restored - with `CS = <kernel code
selector>` and `RIP = <kernel address>`, and `iretq` at CPL0 to a kernel code segment is legal. That
is plain ring-0 execution, which the fault oracle's kernel base would make immediately usable.

Probe 189a had already reported that `CS = 0x40` produced a live thread with no panic, which read as
"the firmware forces or replaces the selector". That was a *behavioural* answer to a question with a
static one. This note answers it statically and closes the whole family - thr_create, sigreturn,
setcontext, swapcontext - in one stroke.

## 2. The call graph

`syscall 430` -> sysent thunk at RVA `0x265c10` (`e9 db 20 1d 00`, jmp) -> handler RVA **0x437cf0**.

The handler is short and does the important thing immediately:

```
437d31  lea      rsi, [rbp - 0x540]      ; kernel stack buffer
437d38  mov      edx, 0x500             ; fixed length
437d3d  mov      rdi, r15               ; r15 = [uap] = caller's context pointer
437d40  call     0x259280               ; copyin
437d45  test     eax, eax
437d47  jne      0x437d6c               ; bail on a bad pointer
```

So the entire user context (0x500 bytes) lands on the kernel stack in one bounded copy - there is no
length arithmetic and therefore no stack-overflow shape here.

It then calls `0x437f30`, which reaches `0x437d90`, which tail-jumps to **0xa0ac60** with
`rdi = td` and `rsi = ctx + 0x40`. That is the installer. The CFI check in front of it
(`lea rax,[rip - 0x1d10a6]; sub rax,r13; ror rax,3; cmp rax,0x3a5`) is the same `ror rax,3` whitelist
pattern already recorded for 29.2% of the corpus's indirect calls.

## 3. The installer's gates (RVA 0xa0ac60)

With `rsi = mcontext base` (`= user ctx + 0x40`) and `rdi = td`:

```
a0ac8c  cmp  qword [rsi + 0xc8], 0x480   ; magic - must be exactly 0x480
a0ac9d  mov  r10d, [rsi + 0x90]          ; flags dword
a0aca4  cmp  r10d, 7                     ; flags must be <= 7
a0acae  mov  r12, [rdi + 0x460]          ; r12 = td->td_pcb
a0acb5  mov  rdx, [rdi + 8]              ; td_proc
a0acd6  cmp  byte [rdx + 0xc81], 0       ; proc->...c81: native vs backwards-compat mode
```

`proc+0xc81 != 0` takes a second path that additionally caps flags at 3 and memcpy's 0x140 bytes from
`ctx+0x300` to the stack. `proc+0xc81 == 0` (our mode) continues. Both then require
`ctx+0xd0` (the type field) to be `0x10000` or `0x10002`; the 0x10002 branch further requires
`ctx+0xd8` (subtype) in {0x20000, 0x20001, 0x20002, 0x20003} and hands off to `0x7318f0` or `0xa07230`
for the two subtype families. Anything else returns 0x16 (EINVAL).

Then the **complete** list of loads out of the caller's context, which is the whole answer to the
question:

```
a0ae9e  mov  rax,[rsi + 0x78]  ->  [r12 + 0x70]
a0aeb1  mov  rax,[rsi + 0x70]  ->  [r12 + 0x68]
a0aeba  mov  rax,[rsi + 0x68]  ->  [r12 + 0x60]
a0aec3  mov  rax,[rsi + 0x60]  ->  [r12 + 0x58]
a0aecc  mov  rax,[rsi + 0x58]  ->  [r12 + 0x50]
a0aed5  mov  rax,[rsi + 0x50]  ->  [r12 + 0x48]
a0aede  mov  rax,[rsi + 0x30]  ->  [r12 + 0x28]
a0aee7  mov  rax,[rsi + 0x28]  ->  [r12 + 0x20]
a0aef0  mov  rax,[rsi + 0x08]  ->  [r12 + 0x00]
a0aef8  mov  rax,[rsi + 0x10]  ->  [r12 + 0x08]
a0af01  mov  rax,[rsi + 0x48]  ->  [r12 + 0x40]
a0af0a  mov  rax,[rsi + 0x40]  ->  [r12 + 0x38]
a0af13  mov  rax,[rsi + 0x18]  ->  [r12 + 0x10]
a0af1c  mov  rax,[rsi + 0x20]  ->  [r12 + 0x18]
a0af25  mov  rax,[rsi + 0x38]  ->  [r12 + 0x30]
a0af2e  mov  rax,[rsi + 0xa0]  ->  [r12 + 0xe8]    ; pcb_rip
a0af45  mov  rax,[rsi + 0xb8]  ->  [r12 + 0x100]   ; pcb_rsp
a0af54  mov  rax,[rsi + 0xc0]  ->  [r12 + 0x108]   ; pcb_ss
a0af3d  mov  [r12 + 0xf8], r15                     ; pcb_rflags =
        r15 = ([r12+0xf8] & 0xffffffffffdab22a) | ([rsi+0xb0] & 0x254dd5)
```

Plus, gated on flag bits: the 16-bit segment fields at `[rsi+0x94/0x96]` and `[rsi+0x84/0x86]`, two
qwords from `[rsi+0x440/0x448]` into `[r8+0x40/0x48]` where `r8 = [rdi+0x3f8]`, and
`or dword [r8+0x100], 1`.

**The CS field is `mcontext + 0xa8`, and nothing in this function ever loads it.** It is not in the
list above, it is not copied anywhere, and there is no comparison against it. The piece of state that
decides the privilege level of the `iretq` is simply not caller-controlled.

## 4. The same installer is the sigreturn path

Full-image scan for direct callers of `0xa0ac60`:

| call site | enclosing body | syscall |
|---|---|---|
| 0x437dd1 | 0x437cf0 | 430 thr_create |
| 0xc379d2 | 0xc37970 | 422 sigreturn |
| 0xc37b4c | 0xc37a20 | 423 sigreturn (other ABI) |

The getter `0xa0bb60` has exactly one caller, `0x4392b7`, inside 634. So a forged signal frame is
not a second route to the same idea: it converges on the identical function and the identical
omission.

This is consistent with 189a's runtime observation that `CS = 0x40` was harmless - a value that is
never read cannot cause a fault, and the earlier reading that "the firmware forces the selector" was
right about the outcome and wrong about the mechanism.

## 5. What 634 actually copies (body 0x439150)

`narg = 2`: argument 1 is the tid as a **dword** (`mov edi,[rsi]`), argument 2 is the output buffer
(`mov rbx,[rsi+8]`). There is no third argument, so the size is not caller-controlled:

```
439297  lea  r15, [rbp - 0x530]
43929e  mov  esi, 0x500
4392a3  mov  rdi, r15
4392a6  call 0x258ff0          ; bzero(0x500) - leak hygiene
4392ab  lea  rsi, [rbp - 0x4f0]
4392b2  mov  rdi, r14          ; thread
4392b7  call 0xa0bb60          ; fill mcontext at buf+0x40
4392fd  mov  edx, 0x4c0        ; constant length
439308  call 0x2591d0          ; copyout(r15, user_buf, 0x4c0)
```

Three consequences worth recording:

1. The copy is a **fixed 0x4c0**, and the source is a zeroed 0x500-byte stack buffer. No length
   control, no uninitialised stack in the copyout.
2. The mcontext begins at `buf+0x40`, which is exactly why the empirical field map in
   `UCONTEXT_FAMILY_14_10.md` §5.2 has the GPR block at `+0x48` - that is `mcontext+0x08`.
3. The state gates on this handler are `[thread+0xe8] & 0x20` and `[thread+0xe4] < 0`, matching the
   corpus's `cmp dword [thread+0xe4],0 ; jns error` reading for the suspend/get pair.

## 6. Standing conclusions

* **Ring-0 via iret is closed by construction on this build.** thr_create, sigreturn and the two
  ABI variants all install the frame through `0xa0ac60`, which never reads `mcontext+0xa8`. No
  user-controlled CS exists anywhere in that path.
* Probe 189a's `CS = 0x40` result is explained: the field is dead input.
* 430's user-context copy is a fixed 0x500-byte `copyin` into a 0x520-byte frame - no overflow.
* 634's copyout is a fixed 0x4c0 from a zeroed buffer - no leak, no length control.
* The remaining attacker-controlled writes into kernel state in this family are the pcb register
  slots, `pcb_rip`, `pcb_rsp` and `pcb_ss`, and the two qwords at `[r8+0x40/0x48]` where
  `r8 = [td+0x3f8]`. All of them target the new thread's own pcb or its own frame; none of them is
  an address the caller chooses.

## 7. Reproduce

`.local/thr430c.py` .. `.local/thr430i.py` disassemble the handler, the installer and its gates;
`.local/thr_uc.py` and `.local/thr_uc2.py` disassemble 632/633/634; `.local/callers_ac.py` does the
full-image caller scan for the setter and getter; `.local/attr_sites.py` attributes a call site to a
sysent body.
