# Unexplored Attack Surface Audit

**Date:** 2026-10-25
**Source:** Agent 8 -- Unexplored attack vectors (max effort)

## Priority 1: sys 591 `dynlib_dlsym` (KASLR Defeat Candidate)

The 13.60 offline decode (`docs/OFFLINE_HANDLER_DECODE_2026-10-23.md`) shows this handler has **NO authid gate** and **NO bit-62 gate**. It takes `(handle, name_ptr, &out_addr)` and calls `copyout(&addr, arg3, 8)` on success.

The 14.10 `-1` came from passing six zeros (handle 0 fails with error 3, not a privilege gate). With a real module handle from the `593` handle space plus a known NID string, this could resolve a kernel symbol address in one call.

**If 14.10 kept the 13.60 body, this is a single-call KASLR defeat.**

- Effort: one probe, low risk
- Probability x impact: **HIGHEST**

## Priority 2: AIO Double-Free Heap Spray (Kernel R/W)

The double-free is confirmed (65l, 13.5% hit rate) but exploitation has not succeeded. The gap is identifying the freed object's slab zone size. The 13.60 Ghidra decompile traces the `662` handler's sub-object free.

Once reclaimed, a dangling-pointer read leaks a kernel address (if the original object had a back-pointer), and a write through the stale reference gives kernel R/W. The `624` VM-op counter provides a side channel.

- Effort: medium (offline analysis + 2-3 probes)
- Probability x impact: **VERY HIGH**

## Priority 3: sys 660 `dynlib_get_info2` with Real Args

The 13.60 decode labels this "NO gate" with a different struct filler than `593`. Only tested with zeros (which fail on handle validation). With a real module handle and a `0x160`-byte sentinel-filled buffer, it may return fields `593` omits.

A full byte-diff against `593`'s output could surface a kernel pointer in a field `593` doesn't populate.

- Effort: one probe
- Probability x impact: **MEDIUM-HIGH**

## Priority 4: UMTX ROBUST_LISTS Oversized Struct (op 26)

Probe 110a found that `_umtx_op(0, 26, 4096, params, 0)` was accepted despite the expected struct being 24 bytes. On FreeBSD, robust-lists cause the kernel to walk a user-controlled linked list at thread exit (`thr_exit`). If the copyin does not bound the size, it overflows a kernel stack buffer. If the list walk follows user pointers, a crafted list could redirect kernel execution at thread exit.

The child-thread infrastructure (`thr_new` + `thr_exit` ROP) is already in place.

- Effort: one focused probe
- Probability x impact: **MEDIUM**

## Priority 5: sys 599 `dynlib_process_needed_and_relocate` with Real Args

Ungated at the handler top, reaches two `copyout` sites at depth 4-5 through the dynamic linker. Never tested with valid arguments (handle + flags from the `593`/`594` space). The relocation machinery processes module metadata and could copy kernel-internal pointers into the output.

- Effort: one probe, moderate crash risk
- Probability x impact: **MEDIUM**

## Priority 6: errno Capture for All -1 Returns

The offline decode reveals that SCE error codes (1 = authid gate, 3 = invalid handle, 0x16 = size gate, 0x4e = invalid command) are the actual return values, turned to `-1` by the dispatch wrapper.

Currently no probe captures `errno` after a `-1`. A systematic sweep with errno read (via `__error()` or the TCB errno slot) across all present-but-rejecting Sony syscalls would reveal which ones fail on handles (fixable) vs credentials (permanent).

This is a cheap multiplier for every other vector.

- Effort: one sweep probe
- Probability x impact: **MEDIUM**

## Priority 7: sys 572 `virtual_query` Arg Shape

Returns 0 but writes nothing. The 13.60 decode shows 2 copyout sites with no gate. The current arg layout `(addr, outbuf, size)` may be wrong; the handler likely takes `(outbuf, cmd, addr, size, flags)` based on the 5-arg narg count. Different `cmd` values (0-10) may produce VM metadata output.

- Effort: one probe
- Probability x impact: **LOW-MEDIUM**

## Bottom Line

**sys 591 is the single most promising untested vector for KASLR defeat.** The AIO double-free heap spray is the most promising path to kernel R/W. Both should be probed before anything else.
