# Does any handler read past the argument block the kernel copied?

Measured/static 2026-11-04. Dump 13.60, base 0xffffffff8a9c0000, offset == RVA.

## Why this is interesting

The kernel copies exactly `narg * 8` bytes of user registers into a stack buffer and hands the
handler a pointer to it. A handler that indexes past `narg * 8` reads **kernel stack that the
kernel did not initialise for this call**. If such a value were then used as a length, a pointer,
or copied back to userland, it would be a leak or a type confusion bought for free.

## Method, and the two bugs that had to be fixed first

1. Resolve every sysent entry to a handler body (thunk `e9 rel32` -> body).
2. Decode linearly, maintaining the exact set of registers that still hold the uap pointer
   (`rsi` at entry; propagated by `mov`/`lea`, destroyed by any other write).
3. Record the largest displacement ever reached through a holder.

First pass decoded a fixed 0x400 bytes per body and **walked into the next function**, so it
reported 29 hits; every one of the interesting ones (sys 253 "uap+0x118", sys 210/220 "uap+0x2c")
was a neighbour's code. Second pass stopped at `ret`/`ud2` followed by padding but not at a tail
`jmp`, leaving 5. Third pass also stops at an unconditional tail `jmp`. Result: **3**.

## The three real ones

| sys | body | narg | reads | what it does with it |
|---|---|---|---|---|
| 668 | 0x3af900 | 2 | `[uap+0x10]` | `rax=[uap]; edx=[uap+8]; rcx=[uap+0x10]; rsi=rax; jmp 0xad6f920` |
| 665 | 0x3b1680 | 2 | `[uap+0x10]` | identical shape, `jmp 0xad716a0` |
| 113 | 0x52fae0 | 4 | `[uap+0x20]` | `r14d=[uap+0x20]`; `cmp r14d,1` ANDed with `(proc+0xc81 != 0)` |

665/668 are wrappers that want three arguments, but their sysent rows declare two, so the third
comes from the stack slot immediately after the copied argument block. 113 reads a fifth argument
the same way and folds it into a single boolean.

## Why it is not a primitive

The buffer lives inside `syscall()`'s frame at a fixed depth, and the only thing that ever writes
to it is the `memcpy` of our own registers. Calling a six-argument syscall first and a two-argument
one second primes the tail with values **we supplied ourselves**. There is no kernel-authored data
in that region, so the over-read yields nothing we did not already know.

Additionally, the only consumer this reaches is a boolean that is already forced false for our
process (`proc+0xc81 == 0`).

**Verdict: three real over-reads, zero exploitable value. Class closed.**

## Lesson for the next scan

Any "function summary" scan over this image must terminate at a tail `jmp` as well as at `ret`,
otherwise every small wrapper inherits its callee's accesses and the result is fiction. Both
mistakes here produced plausible-looking findings that dissolved on inspection.
