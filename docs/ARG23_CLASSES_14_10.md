# arg2 / arg3 pointer classes on 14.10, and the calls that write into them

`docs/ARG1_CLASSES_14_10.md` varied only the first argument, so a handler that
validates arg1 and then dereferences arg2 rated identical to a credential gate.
This page holds arg1 mapped and compares arg2 and arg3, then looks at the pages
afterwards to see which calls the kernel actually writes into.

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

Twenty numbers read arg2 and ten read arg3; 557 is the only one that changes a
*returned handle* for both (`16901`, `519`, `520` — three different ids from the
same call, so arg2 and arg3 both feed the object it creates). 538 mints `518` only
when arg2 is **absent**, and 657 returns `0` in the same direction.

## The calls that write into the pages

The scorer poisons all three pages, calls, then reports every dword that is no
longer the poison, plus the end checkpoint. Seven numbers wrote, and every one of
them has a contract that `docs/ATTACK_SURFACE.md` already names in its recovered
handler table, so the value here is the argument position, not the existence:

| sys | name | return | page | dwords changed | first bytes (offset = value) |
|---|---|---|---|---|---|
| 547 | region record | 0 | arg2 | 6 | `0=U1 4=3 8=U2 c=3` — start, prot, end, prot of the containing mapping |
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

547 is the one that gains a shape from this: its record is `{start, prot, end,
prot}` for the mapping containing arg1, written into arg2, and an absent arg2
gives EFAULT. That is a region reporter, and it is why 547 works as the read-back
oracle in `docs/ATTACK_SURFACE.md`'s W^X section.

## What is still open

Every one of these is an output pointer that the kernel fills with *userland*
data. The question a kernel read needs is whether any of them can be pointed at a
kernel address; the arg1 K pass says the class check happens at the entry for the
eleven handlers tested there, and copyout enforces it everywhere else, so the
prize has to come from a handler that *skips* copyout and writes through a raw
pointer. None of the seven above does: each refuses at least one absent destination with
EFAULT, which is what a copyout check looks like.

## Captures

| probe | result | capture |
|---|---|---|
| 1343a | 131 numbers x 3 phases, 20 read arg2, 10 read arg3, process alive | `results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt` |
| 1343b | 7 writers, no kernel pointer, all end checkpoints intact | `results/phase35_dead_end_reruns/1343b_outpage_scorer_20261109_101855.txt` |
