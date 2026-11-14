# arg2 / arg3 pointer classes on 14.10, and the calls that write into them

`docs/ARG1_CLASSES_14_10.md` varied only the first argument, so a handler that
validates arg1 and then dereferences arg2 rated identical to a credential gate.
This page holds arg1 mapped and compares arg2 and arg3, then looks at the pages
afterwards to see which calls the kernel actually writes into, and finally repeats
the comparison for arguments four to six, which every earlier sweep left at zero.

## Method

Three 16 KB pages, each filled with `0x4141414141414141` (dword `0x41414141`)
plus a `0x42424242` checkpoint in the last eight bytes, then

| phase | arg1 | arg2 | arg3 |
|---|---|---|---|
| A | U1 | U2 | U3 |
| B | U1 | absent | U3 |
| C | U1 | U2 | absent |

`SIGSYS` is ignored first (`sigaction(12, SIG_IGN)` returns 0), so an absent
handler answers `ENOSYS` instead of terminating the caller — the correction from
1342a run 3. Absent is `0x00007FFF00000000`. 131 numbers ran, the same skip list
as the arg1 sweep (561, 562, 570, 571, 573, 609, 614, 621, 622, 631, 650, 651,
668, 673).

## Which calls read arg2 or arg3

B or C differing from A means the handler dereferenced that pointer.

| sys | A (all mapped) | B (arg2 absent) | C (arg3 absent) |
|---|---|---|---|
| 538 | -1, EINVAL | **518** | -1, EINVAL |
| 547 | **0** | -1, EFAULT | 0 |
| 548 | -1, EINVAL | **0** (EFAULT) | -1, EINVAL |
| 553 | -1, ESRCH | -1, EINVAL | -1, EFAULT |
| 554 | -1, ESRCH | -1, EINVAL | -1, ESRCH |
| 555 | -1, ESRCH | -1, EINVAL | -1, ESRCH |
| 557 | **16901** | **519** | **520** |
| 566 | -1, EINVAL | -1, ESRCH | -1, EINVAL |
| 567 | -1, EINVAL | -1, ESRCH | -1, EINVAL |
| 588 | **0** | -1, EINVAL | -1, EFAULT |
| 591 | -1, ESRCH | -1, EFAULT | -1, ESRCH |
| 592 | **0** | 0 (EFAULT) | **0** |
| 593 | -1, EINVAL | -1, EFAULT | -1, EINVAL |
| 594 | -1, EINVAL | -1, ENOENT | -1, EINVAL |
| 598 | **0** | -1, EFAULT | 0 |
| 608 | -1, EINVAL | -1, EINVAL | -1, EFAULT |
| 628 | -1, EINVAL | -1, EINVAL | -1, EBUSY |
| 638 | **0** | -1, EFAULT | -1, EFAULT |
| 639 | **0** | 0 (EFAULT) | -1, EFAULT |
| 640 | **0** | 0 (EFAULT) | 0 (EFAULT) |
| 657 | -1, EINVAL | **0** (EPERM) | -1, EINVAL |
| 659 | **0** (EBADF) | **0** (EBADF) | -1, EFAULT |
| 660 | -1, EINVAL | -1, EFAULT | -1, EINVAL |

Twenty-one numbers change their answer with arg2 and ten with arg3, but only ten
of the arg2 group answer `EFAULT` for an unmapped pointer, and that is the only
direct evidence of a dereference: 547, 548, 591, 592, 593, 598, 638, 639, 640 and
660. The rest read the value rather than the memory behind it — 538 mints `518`
for an absent arg2, 557 returns a different id for every value (`16901`, `519`,
`520`), 566/567 answer `ESRCH` for both absent and supervisor, and 594 answers
`ENOENT`. On the arg3 side nine answer `EFAULT` (553, 588, 592, 608, 638, 639,
640, 659, 660) and 628 answers `EBUSY`.

## The calls that write into the pages

The scorer poisons all three pages, calls, then reports every dword that is no
longer the poison, plus the end checkpoint. Seven numbers wrote, and every one of
them has a contract that `docs/ATTACK_SURFACE.md` already names in its recovered
handler table, so the value here is the argument position, not the existence:

| sys | name | return | page | dwords changed | first bytes (offset = value) |
|---|---|---|---|---|---|
| 547 | region record | 0 | arg2 | 6 | `{start_lo, start_hi, end_lo, end_hi, prot, flags}` — the protection is dword 4 (+0x10), corrected 2026-11-09 from a whole-record dump (1362a); the earlier `0=U1 4=3 8=U2 c=3` reading (start, prot, end, prot of the containing mapping) mistook the high dwords of the two 64-bit addresses for protections |
| 592 | `dynlib_get_list` | 0 | arg1 | 39 | `0=0 4=0x2001 8=2 c=0x11` — the handle list |
| 592 | | 0 | arg3 | 2 | `0=0x27 4=0` — the count, 39 |
| 598 | `dynlib_get_proc_param` | 0 | arg1 | 2 | `0=0xCFE8000 4=0` |
| 598 | | 0 | arg2 | 2 | `0=0x60 4=0` — the size |
| 638 | `utc_to_localtime` | 0 | arg2 | 2 | `0=U1 4=3` |
| 638 | | 0 | arg3 | 4 | `0=0xF615DB90` |
| 639 | `localtime_to_utc` | 0 | arg3 | 2 | `0=U1 4=3` |
| 657 | `blockpool_batch` | -1, EINVAL | arg3 | 1 | `0=0` |
| 659 | `dynlib_get_list2` | 0, EBADF | arg1 | 3 | `0=0 4=0xD 8=0xE` |
| 659 | | 0, EBADF | arg3 | 2 | `0=3 4=0` |

**No kernel pointer appeared in any of them.** The two largest values are
`0xCFE8000` (598's arg1) and `0xF615DB90` (638's arg3); both are userland-range
addresses, and everything else is a small integer, a protection word, an echo of
our own pointer, or the module count. The write sizes are fixed: 547 writes six
dwords (its documented 0x18-byte record), 592 writes the 39-dword list its dword
count agrees with, and the end checkpoint at 0x3FF8 was intact in every case, so
no write ran off the page.

547 is the one that gains a shape from this: its record is `{start_lo, start_hi, end_lo,
end_hi, prot, flags}` for the mapping containing arg1, written into arg2, and an absent arg2
gives EFAULT. That is a region reporter, and it is why 547 works as the read-back
oracle in `docs/ATTACK_SURFACE.md`'s W^X section.

## What is still open

Every one of these is an output pointer that the kernel fills with *userland*
data. The question a kernel read needs is whether any of them can be pointed at a
kernel address. 1344a passes the boot's image base (`0xFFFFFFFFC1000000`) in arg2
and then in arg3 of the same 131 numbers: **every handler that touches the pointer
answers `EFAULT`** — 21 changes in the arg2 phase and 10 in the arg3 phase, all of
them `14 Bad address` or `EINVAL`/`ESRCH`, and not one returns `0` while writing.
That closes the raw-pointer hypothesis for this range: the class check is the
copyout (`copyin` for inputs), and none of these handlers writes through a
pointer it never validated.

## Arguments four to six

Every sweep in this project so far passed zeros for args 4-6, so a handler that
needs a fourth pointer was indistinguishable from a credential gate. 1345a holds
args 1-3 mapped and runs the same 131 numbers four times: all six mapped, then
arg4 zero, then arg5 zero, then arg6 zero.

**Nothing differs.** Of 131 numbers, exactly two change between phases, and both
are per-call counters rather than pointer handling: 557 (`namedobj_create`) mints
the next object id on every call, `525`/`526`/`527`/`528`, and 624 returns the VM
operation counter, `3480`/`3481`/`3482`/`3483`. Every other number answers exactly
what the presence table recorded for the zero shape. So no handler in 532-676
dereferences arg4, arg5 or arg6 — the fourth-to-sixth positions are scalars
everywhere in this range, which is why the AIO and blockpool families only ever
answered from their count and status words.

The blind spot this design has: a handler that treats zero as "optional pointer,
skip it" and a mapped pointer as "dereference it" can succeed in both phases, so
the difference would not show. What the run does establish is that no handler
*requires* a fourth-to-sixth pointer and none faults when handed one.

## Captures

| probe | result | capture |
|---|---|---|
| 1343a | 131 numbers x 3 phases, 20 read arg2, 10 read arg3, process alive | `results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt` |
| 1343b | 7 writers, no kernel pointer, all end checkpoints intact | `results/phase35_dead_end_reruns/1343b_outpage_scorer_20261109_101855.txt` |
| 1344a | arg2 / arg3 = kernel image base: 21 and 10 changed answers, every one EFAULT/EINVAL/ESRCH, none wrote | `results/phase35_dead_end_reruns/1344a_arg23_kernel_class_20261109_102818.txt` |
| 1345a | args 4-6 mapped vs zero: no difference except 557's object id and 624's counter, so no handler in 532-676 dereferences them | `results/phase35_dead_end_reruns/1345a_arg456_classes_20261109_102955.txt` |
