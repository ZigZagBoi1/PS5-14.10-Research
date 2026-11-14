# 637 `set_phys_fmem_limit` at the bottom of its range wedges the process — and the loader with it

**Status:** measured on 14.10 (probe 1162a, 2026-11-04), and it reproduces a
silent hang first hit on 2026-10-22 by probe 339a.

## The measurement

`637(pid=0, value=17)` never returns. The probe's capture stops between the
`value=16` line (`EINVAL`, as expected) and the `value=17` line, and the console
then answers `LOADER-STUCK: accepted, no reply` to `tools/port_witness.py` — the
listening socket still completes TCP handshakes (so the kernel is alive) but the
Lua loader never services them again. The session only recovers with a manual
relaunch, i.e. the calling thread never leaves the kernel.

The same call ended probe 339a on 2026-10-22 the same way, in the same place:

    339a_637_598_659_20261022_124747.txt
      1| === PROBE 339a: 637 / 598 / 659 ===
      2|
      3| [A] 637 value sweep with id = 0
      4|   637(0, 0x10) = -1          <- value 16, EINVAL
                                   <- value 17 was the next iteration; never printed

That capture was never diagnosed: the "637 returns 0 for self" claim in
`docs/ATTACK_SURFACE.md` comes from later probes (340a, 343a, 344a, 345a, 887a,
890a) which all used values of `0x40000000` and above. The wedge sits in the
value range nobody had retried: the first value that clears the `value < 17`
check.

## Measured value map, 14.10, self (`pid = 0`)

| value | result |
|---|---|
| 0, 1, 16 | `-1`, `errno = 22 EINVAL` (the `value < 17` guard) |
| **17** | **never returns; process wedged, loader wedged, needs relaunch** |
| `0x40000000`, `0x7FFFFFFF`, `0xFFFFFFFF`, `0x10000000`, `0x200000000`, 4 GiB, 64 MiB | `0` (340a/343a/344a/345a/887a/890a) |
| foreign pid (`0x40000000`) | `-1` (887a/888a) |

The exact lower edge of the wedge window between 17 and `0x40000000` is
**unmeasured** and is not worth measuring with a wedging console: every attempt
costs a manual relaunch.

## Why it wedges (static, 13.60 body `0xffffffff8b47d930`)

`results/kernel_handlers/decompiled/sys_637.c`:

    } else sub_ffffffff8ae86a00((char *)p+0x148,0,0,0);   // lock parent
    flags = U32(p,0xb0);
    if ((flags & 0x2200) || U32(p,0xb8) != 1) { unlock; return 3; }
    ++U32(p,0x358);                                        // refcount
    if (!(flags & 0x10000000)) sub_ffffffff8aefaa10(p);     // <-- called under the lock
    sub_ffffffff8ae86fa0((char *)p+0x148,0,0,0);            // unlock

The flags/state check passed, so execution reached the refcount bump and the
`0xffffffff8aefaa10(p)` call **while holding the process lock at `p+0x148`**, and
nothing after that line was observed. Two consistent explanations, both static:

1. `0xffffffff8aefaa10` itself takes `p+0x148` (a non-recursive mutex) — a
   self-deadlock that is invisible from outside;
2. `0xffffffff8aefaa10` spins/waits on a condition that a 17-byte limit makes
   unsatisfiable, so the lock is never released.

Either way the lock is left held forever. That the *loader* stops answering too —
and not only the wedged child process — is the important part: the listener and
the probe process share that same parent process object, so the held lock takes
the whole session with it. A one-call, unprivileged (`uid 1`, no bit 62),
permanent denial of the loader on 14.10.

## Consequences for this research

* **Never call 637 with a value in `[17, 0x40000000)`.** It is the only syscall in
  this corpus that has cost a console session without a panic, and the cost is a
  manual relaunch every time.
* 637's interesting surface — `U64(vmspace, 0x280) = value`, a caller-chosen qword
  written into the current process's vmspace with **no capability check** on
  the self path — **is reachable and has been measured returning 0** (see the
  correction at the end of this document). What makes it inert is that the field
  is the fmem page limit, read only as a loop comparison.
* The cross-process path is bit-62 gated (`0xffffffff8afc8f90` = bit 62 of
  `cred+0x60`), so foreign pids are out of reach by the same predicate as
  everything else.

## Note for the next probe that touches 637

Keep it a single call, and if the loader goes silent, do not retry: witness the
port once, tell the operator, and treat the session as lost. The stored-value
hypothesis cannot be settled from the current primitives.

## Correction, 2026-11-05: neither explanation above is right

Full disassembly of the body and of both callees (capstone over
`docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`) replaces the guess above.

**`0x53aa10` is not the worker.** It is nine bytes and it is an invariant check that ends in a
fatal stop:

    0053aa10  f687b300000010   test byte ptr [rdi + 0xb3], 0x10
    0053aa17  7401             je   0x53aa1a
    0053aa19  c3               ret
    ...
    0053aa1a  55               push rbp
    0053aa1b  4889e5           mov  rbp, rsp
    0053aa1e  e82d6f2b00       call 0x7f1950
    0053aa23  488d3df0ffffff   lea  rdi, [rip - 0x10]
    0053aa2a  e8e16d2b00       call 0x7f1810
    0053aa2f  488d356b73d400   lea  rsi, [rip + 0xd4736b]
    0053aa36  bf07000000       mov  edi, 7
    0053aa3b  31c0             xor  eax, eax
    0053aa3d  e8ceff7500       call 0xc9aa10
    0053aa42  0f0b             ud2

That is the `printf(fmt, ...); ud2` shape of a fatal assert, not a lock. For 637 to return 0 at all
(which it does for every large value) the flag has to be **set**, so `0x53aa10` executes only its
`ret` and has nothing to do with the hang.

**The wedge is the reclaim loop in the post-store callee `0x691c70 -> 0x6918a0`.** `0x6918a0` is
the fmem enforcement routine and it is where the stored value is read:

    00691900  498b86d8010000   mov  rax, [r14 + 0x1d8]      ; the accounting object
    00691907  498b8e30020000   mov  rcx, [r14 + 0x230]      ; bytes in use
    0069190e  488b4050         mov  rax, [rax + 0x50]       ; capacity in bytes
    00691912  48c1f90e         sar  rcx, 0xe                ; >> 14  -> 16 KiB pages
    00691916  4829c8           sub  rax, rcx
    00691919  49398680020000   cmp  qword [r14 + 0x280], rax   ; <-- the value 637 stored
    00691920  0f8f0f030000     jg   0x691c35                ; limit above what is available -> done

If the test fails it walks the vm_map entry list (`rax = [r14 + 8]`, `cmp rax, r14`, next at
`[rax + 8]`), skips entries by protection (`test dword [rax + 0x60], 0x40102`) and object type
(`movzx ecx, byte [r15 + 0x9d]; cmp ecx, 8; bt 0x187, ecx`), and calls the pageout path
(`0x461b20`, `0xb897f0`, `0x8ea110`) until the accounting satisfies the comparison. A limit of
17 pages is **unreachable** for a live process, so the loop has no exit — an unbounded reclaim, not
a mutex deadlock. It is a signed comparison (`jg`), so a negative value loops just as hard.

**The interesting surface is not unreachable after all.** The store runs before that callee:

    00abd9db  4c8ba300020000   mov  r12, [rbx + 0x200]      ; vmspace
    00abd9e7  498dbc2478020000 lea  rdi, [r12 + 0x278]
    00abd9f9  e80290a0ff       call 0x4c6a00                ; mtx_lock(vmspace + 0x278)
    00abd9fe  498b4508         mov  rax, [r13 + 8]          ; the caller's qword, verbatim
    00abda0c  4989842480020000 mov  qword [r12 + 0x280], rax
    00abda14  e88795a0ff       call 0x4c6fa0                ; mtx_unlock
    00abda19  4c89e7           mov  rdi, r12
    00abda1c  e84f42bdff       call 0x691c70

So **637 with any value >= 0x40000000 is a working, unprivileged, repeatable 8-byte kernel store
of a caller-chosen qword at `[curproc->p_vmspace + 0x280]`** — it returns 0, and that is what the
six earlier probes measured without knowing it. What makes it inert is the field's meaning, not its
reachability: a 252-site scan of the image for `[reg + 0x280]` finds the 16 KiB-page limit read only
as the comparison target above. It is a scalar, it is never dereferenced and never copied out, so
the primitive writes a number that only one loop can observe. Recorded in
`docs/FMEM_LIMIT_637_14_10.md`.

The operational conclusion is unchanged and now has a mechanism: never pass 637 a value in
`[17, 0x40000000)`.
