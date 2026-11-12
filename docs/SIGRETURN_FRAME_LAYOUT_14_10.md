# The 14.10 trapframe, sigreturn (417) and setcontext (422): the layout, and why CPL cannot move

Written 2026-11-04 after the console was relaunched. Everything below is read out of
`docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, 15,132,096 bytes) with capstone 5.0.7;
no probe was run for it. It retires probe `1166a` before it ever produced a number, and it corrects
the offsets every frame probe in this repo has been using.

## The trapframe layout, from explicit constants

`td+0x460` is a pointer to the current thread's trapframe. Function `0xffffffff8b3c7690` builds one
for the upcall path and names every slot:

```
ffffffff8b3c769e  mov  r13, qword ptr [rdi + 0x3f8]
ffffffff8b3c76a5  mov  r14, qword ptr [rdi + 0x460]      ; r14 = trapframe
ffffffff8b3c7701  mov  esi, 0x110                        ; the frame is 0x110 bytes
ffffffff8b3c7709  and  dword ptr [r13 + 0x100], 0xffffffbf
ffffffff8b3c7723  call 0xffffffff8ac18ff0                ; bzero(frame, 0x110)
ffffffff8b3c772f  mov  edx, 0x43                         ; *** the user CS constant ***
ffffffff8b3c7734  mov  qword ptr [r14 + 0xe8], rax       ; tf_rip
ffffffff8b3c7747  mov  qword ptr [r14 + 0x100], rax      ; tf_rsp
ffffffff8b3c775d  or   rax, 0x202
ffffffff8b3c7763  mov  qword ptr [r14 + 0xf8], rax       ; tf_rflags = 0x202 | (old & 0x100)
ffffffff8b3c7771  mov  qword ptr [r14 + 0x108], rax      ; tf_ss  (from a global)
ffffffff8b3c777f  cmove rdx, rcx
ffffffff8b3c7783  mov  qword ptr [r14 + 0xf0], rdx       ; tf_cs  = 0x43, or 0
ffffffff8b3c778a  mov  word ptr [r14 + 0x8e], ax
ffffffff8b3c7799  mov  word ptr [r14 + 0x8c], ax
ffffffff8b3c77a8  mov  word ptr [r14 + 0x7c], ax        ; segment selector slots
ffffffff8b3c77b4  mov  word ptr [r14 + 0x7e], ax
```

| slot | offset | source in this builder |
|---|---|---|
| tf_rip | `+0xe8` | computed |
| **tf_cs** | **`+0xf0`** | hard-coded `0x43` (or `0`) |
| tf_rflags | `+0xf8` | `0x202` merged with bit 8 of the old value |
| tf_rsp | `+0x100` | computed |
| tf_ss | `+0x108` | a global |
| frame size | `0x110` | `bzero` length |

That ladder also settles what the RFLAGS mask test in 417 is reading: `sys_sigreturn` compares the
record's flags field against `[frame+0xf8]` under mask `0xFFFFFFFFFFDAB22A`, which is only coherent
if `+0xf8` is the flags slot. The earlier docs' `+0xf8 = RSP` is the *thr_create record*, not the
frame.

## setcontext (422) writes every slot except CS

`sys 422` = stub `0xffffffff8ac25bf8` → body `0xffffffff8b5f7970`. It calls the installer
`0xffffffff8b3cac60` at `0x8b5f79d2` and `0x8b5f7b4c`; those two sites are the **only** callers of
that function in the entire 15.1 MB text (byte scan for `e8 rel32` targeting it). The installer's
complete set of writes into the frame (`r12`) is:

```
ffffffff8b3caef4  mov qword ptr [r12],       rax   ; +0x00  tf_rdi
ffffffff8b3caefc  mov qword ptr [r12 + 0x08], rax
ffffffff8b3caf17  mov qword ptr [r12 + 0x10], rax
ffffffff8b3caf20  mov qword ptr [r12 + 0x18], rax
ffffffff8b3caeeb  mov qword ptr [r12 + 0x20], rax
ffffffff8b3caee2  mov qword ptr [r12 + 0x28], rax
ffffffff8b3caf29  mov qword ptr [r12 + 0x30], rax
ffffffff8b3caf0e  mov qword ptr [r12 + 0x38], rax
ffffffff8b3caf05  mov qword ptr [r12 + 0x40], rax
ffffffff8b3caed9  mov qword ptr [r12 + 0x48], rax
ffffffff8b3caed0  mov qword ptr [r12 + 0x50], rax   ; ... 15 GPRs in total, +0x00..+0x70
ffffffff8b3caf8f  mov word  ptr [r12 + 0x8e], ax    ; segment slots
ffffffff8b3caf9f  mov word  ptr [r12 + 0x8c], ax
ffffffff8b3cafaf  mov word  ptr [r12 + 0x7c], ax
ffffffff8b3cafbc  mov word  ptr [r12 + 0x7e], ax
ffffffff8b3caf35  mov qword ptr [r12 + 0xe8], rax   ; tf_rip      <- record +0xa0
ffffffff8b3caf3d  mov qword ptr [r12 + 0xf8], r15   ; tf_rflags   <- masked merge
ffffffff8b3caf4c  mov qword ptr [r12 + 0x100], rax  ; tf_rsp      <- record +0xb8
ffffffff8b3caf5b  mov qword ptr [r12 + 0x108], rax  ; tf_ss       <- record +0xc0
```

**There is no write to `[r12+0xf0]` anywhere in the installer.** The CS slot keeps whatever the
syscall entry path put there, which is `0x43`. RIP, RSP, SS and (masked) RFLAGS are all
attacker-chosen; the one field that decides the privilege level is not reachable.

The gates are the ones already measured: `[frame? no — record +0xd0] < 8` (`cmp ecx,8 / jae` at
`0x8b3c7314`), and the RFLAGS mask test `test rdx,-0x254dd6` at `0x8b3c7337`.

## sigreturn (417) has no frame write of its own

`sys 417` = stub `0xffffffff8ac25be8` → body `0xffffffff8b3c7280`. What it does, in order:

```
ffffffff8b3c72b1  mov r15, qword ptr [rsi]        ; args[0] = user record pointer
ffffffff8b3c72b4  mov r13, qword ptr [rdi + 0x3f8]
ffffffff8b3c72bf  mov rdi, qword ptr gs:[0]       ; curthread
ffffffff8b3c72db  lea rsi, [rbx + 0xa0]
ffffffff8b3c72db  mov edx, 0x500
ffffffff8b3c72e3  call 0xffffffff8ac19280        ; copyin(user, rbx+0xa0, 0x500)
ffffffff8b3c72aa  mov qword ptr [rbx + 0x5a0], rax  ; stack canary, one past the buffer
ffffffff8b3c7314  mov ecx, dword ptr [rbx + 0x170]  ; record +0xd0
ffffffff8b3c731a  cmp ecx, 8
ffffffff8b3c731d  jae 0xffffffff8b3c7365           ; reject
ffffffff8b3c731f  mov r15, qword ptr [r14 + 0x460]  ; the frame
ffffffff8b3c7326  mov rax, qword ptr [rbx + 0x190]  ; record +0xf0 = our RFLAGS
ffffffff8b3c732d  mov rdx, qword ptr [r15 + 0xf8]
ffffffff8b3c7334  xor rdx, rax
ffffffff8b3c7337  test rdx, -0x254dd6              ; masked bits must be identical
ffffffff8b3c733e  je  0xffffffff8b3c73b0
```

A scan of the body for any store whose base is `r15` (the frame) finds **none**, and the body
contains no `iret`/`sysret`. `417` therefore never installs a context itself; it validates the record
and hands the work to the trap-return path, which uses the frame the kernel already owns.

At `0x8b3c73b0` it reads `record+0xe8` and requires its low two bits to be `3` (`mov edx,eax / not edx /
test dl,3 / jne reject`) — a user-selector sanity check on a field that, by the installer's mapping,
is **not** the one copied into `tf_cs`.

## What this closes

* **CPL cannot change through 417 or 422.** The only writable privilege-bearing slot is `tf_cs`, and
  no user-controlled value reaches it on either path. Combined with the earlier measurement that
  `417` masks RFLAGS (IOPL rejected, `docs/FINDINGS.md` Finding 104) the "sigreturn to CPL0" family is
  closed **statically**, not by argument.
* Probe `1166a` is withdrawn. It wrote CS at `+0xE8` and SS at `+0x100` of a `421` record on the
  assumption that the record mirrors the frame; the frame's `+0xE8` is `tf_rip`, and the record's own
  `+0xe8` is a selector-shaped field that only has its low two bits checked. Its one run printed nothing,
  so nothing was ever measured; nothing is lost by dropping it.
* **New hazard note.** `tf_ss` *is* written from the record (`+0xc0` → `+0x108`) with no validation.
  A non-DPL-3 selector there would `#GP` on the return and panic the console. Do not probe SS.
* The frame layout table above is what future frame work should use:
  `rip +0xe8, cs +0xf0, rflags +0xf8, rsp +0x100, ss +0x108, size 0x110`.

## Residual

* 417's remainder (`0x8b3c7416`-`0x8b3c7680`) calls `0x8b0f18f0`, three `0x8ac19be0` sites and
  `0x8b3c7640` (a `copyin` wrapper with an SDT probe). None of them receives the record pointer and
  the frame pointer together, but the enumeration is by no means exhaustive proof for the whole
  signal-delivery call graph — only for the two syscall bodies and the one installer they reach.
* `0xffffffff8b3c7230`, the routine both paths call, is an FPU/scheduler leave: it clears bits 3-4 of
  `[[gs:0]+0x3f8]+0x100` and tail-calls `0xffffffff8b062650`. It touches a *different* structure at
  `+0x100`, which is why an earlier reading mistook it for a frame write.
