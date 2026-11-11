# Descriptor lifetime against a blocked read, 14.10

Probe `938d_fd_race_fixed_base.lua`, capture
`results/phase17_new_vectors/938d_fd_race_fixed_base_20261029_235042.txt`.

The loader serialises TCP connections, but `thr_create` children really run in
parallel, so a child blocked in a syscall is the one place a descriptor race can
be set up from userland. The question is narrow: when one thread is blocked in
`read()` on a socketpair end, what does `close()` from another thread do to it?

## Result

| section | action while the child is blocked | child's `read()` |
|---|---|---|
| A | none (control, `getpid` instead of `read`) | returned 270, the pid |
| B | parent closes the peer end | returned `0` — EOF |
| C | parent closes the descriptor the child is reading | **still blocked**, sentinel `0xAAAAAAAA` unchanged |

So `close()` on the descriptor being read does not abort the read on 14.10; only
closing the peer delivers EOF. The process survived all three sections, and no
use-after-free was observed: the read stays queued on the file object rather than
on the descriptor number.

That is the expected FreeBSD behaviour (the descriptor table entry is released,
the `struct file` is not, because the in-flight read holds a reference) and it
removes the "close the fd under a blocked reader" shape from the race list.

## Harness note, and why 938a-c are void

The first three attempts at this probe reported nothing usable. Cause: the
`dynlib_get_info` (593) record was never zeroed, so the module base was read from
uninitialised memory, `find_pat` returned an *offset* and every child chain
jumped to an unmapped address. `938b`'s printed "gadgets" (`41535890`,
`42134631`) are offsets, not addresses; a real chain is `base + 0x992` for
`pop rax; ret`, `base + 0xC9DFE` for `pop rdi; ret`, `base + 0x92C67` for
`mov [rdi],rax; ret` and `base + 0x1A0BA9` for `mov [rsi],rax; ret`.

Two rules that follow:

1. zero the 593 record and take `base = dword[+0x108] | dword[+0x10C] << 32`,
   `size = dword[+0x110]`; refuse to build a chain when `base < 0x100000`;
2. store the child's result through `RSI` with `mov [rsi],rax; ret`
   (`docs/THREADING_ALIVE_14_10.md:243`): the `mov [rdi],rax` shape returns `1`
   for every call, and the first control of `938d` faulted because `RSI` was
   zero, so the store wrote to address 0.
