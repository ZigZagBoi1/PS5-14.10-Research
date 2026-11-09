# arg1 pointer classes on 14.10 (532-676)

Every Sony syscall in the measured range takes a pointer in its first argument.
This page records what each handler does when that pointer is (a) a mapped,
readable user page, (b) an absent user address, and (c) a mapped but
supervisor-only kernel address. The point is to find the handler that copies
something back from a pointer it does not own: a class that answers differently
because it mapped the address is the only shape a kernel read can take here.

## Method

The call is always `sys(n)(arg1, 0, 0, 0, 0, 0)` through `make_syscall(n)`, so
only arg1 varies. The three pointers:

| class | address | what it is |
|---|---|---|
| U | a 16 KB page from `mmap` syscall 477, filled with `0x41` | mapped user memory |
| N | `0x00007FFF00000000` | unmapped user address |
| K | the kernel image base, measured per boot with `.local/1331a.lua` | mapped, supervisor |

**SIGSYS must be ignored first.** Without `sigaction(12, SIG_IGN)` the shared
`nosys` trampoline raises signal 12, whose default action terminates the caller,
so a stub is indistinguishable from a hostile handler. 1342a run 3 made the
difference visible: with the disposition installed, the numbers that had
terminated three earlier sweeps (`568 U`, `569 U`, `589 U`) all answer `ENOSYS`.
The restore is never needed, because the process ends when the connection does.

Each run is one connection and one process: userland ASLR changes per
connection, the kernel base only on a console reboot. Runs that died left the
console's game process dead, so the capture is also the only record of how far
the sweep got.

## The table

`K` is blank where that number was not in the eleven-handler K pass. `differs`
marks a number whose answer depends on which class arg1 is, which means the
handler read it.

| sys | N (absent) | U (mapped) | K (supervisor) | differs |
|---|---|---|---|---|
| 532 | EPERM | EPERM | — |  |
| 533 | EPERM | EPERM | — |  |
| 534 | EPERM | EPERM | — |  |
| 535 | EPERM | EPERM | — |  |
| 536 | EPERM | EPERM | — |  |
| 537 | ENOSYS | ENOSYS | — |  |
| 538 | EFAULT | ENOSYS, 16903 | EFAULT | yes |
| 539 | ESRCH | ESRCH | — |  |
| 540 | EFAULT | ESRCH | EFAULT | yes |
| 541 | ESRCH | ESRCH | — |  |
| 542 | EINVAL | EINVAL | — |  |
| 543 | EINVAL | EINVAL | — |  |
| 544 | ESRCH | ESRCH | — |  |
| 545 | ESRCH | ESRCH | — |  |
| 546 | ESRCH | ESRCH | — |  |
| 547 | EACCES | EFAULT | EINVAL | yes |
| 548 | 0 | 0 | — |  |
| 549 | EINVAL | EINVAL | — |  |
| 550 | ESRCH | ESRCH | — |  |
| 551 | EFAULT | ESRCH | EFAULT | yes |
| 552 | ESRCH | ESRCH | — |  |
| 553 | EINVAL | EINVAL | — |  |
| 554 | EINVAL | EINVAL | — |  |
| 555 | EINVAL | EINVAL | — |  |
| 556 | ESRCH | ESRCH | — |  |
| 557 | EFAULT | ESRCH, 520 | EFAULT | yes |
| 558 | ESRCH | ESRCH | — |  |
| 559 | EPERM | EINVAL | EINVAL | yes |
| 560 | EBUSY | EBUSY | — |  |
| 561 | — | — | — | — |
| 562 | — | — | — | — |
| 563 | 0 | ESRCH | ESRCH | yes |
| 564 | 0 | ESRCH | ESRCH | yes |
| 565 | 0 | ESRCH | ESRCH | yes |
| 566 | 0 | ESRCH | ESRCH | yes |
| 567 | ESRCH | ESRCH | — |  |
| 568 | ENOSYS | ENOSYS | — |  |
| 569 | ENOSYS | ENOSYS | — |  |
| 570 | — | — | — | — |
| 571 | — | — | — | — |
| 572 | EACCES | 0 | — | yes |
| 573 | — | — | — | — |
| 574 | ENOSYS | ENOSYS | — |  |
| 575 | ENOSYS | ENOSYS | — |  |
| 576 | ENOSYS | ENOSYS | — |  |
| 577 | ENOSYS | ENOSYS | — |  |
| 578 | ENOSYS | ENOSYS | — |  |
| 579 | ENOSYS | ENOSYS | — |  |
| 580 | ENOSYS | ENOSYS | — |  |
| 581 | ENOSYS | ENOSYS | — |  |
| 582 | ENOSYS | ENOSYS | — |  |
| 583 | ENOSYS | ENOSYS | — |  |
| 584 | ENOSYS | ENOSYS | — |  |
| 585 | ENOSYS, 1 | ENOSYS, 1 | — |  |
| 586 | EPERM | EPERM | — |  |
| 587 | EPERM | ESRCH | ESRCH | yes |
| 588 | EFAULT | EFAULT | — |  |
| 589 | ENOSYS | ENOSYS | — |  |
| 590 | ENOSYS | ENOSYS | — |  |
| 591 | EFAULT | EFAULT | — |  |
| 592 | ENOMEM | ENOMEM | — |  |
| 593 | EFAULT | EFAULT | — |  |
| 594 | EFAULT | ENOENT | — | yes |
| 595 | ESRCH | ESRCH | — |  |
| 596 | 0 | 0 | — |  |
| 597 | ENOSYS | ENOSYS | — |  |
| 598 | EFAULT | EFAULT | — |  |
| 599 | EPERM | EPERM | — |  |
| 600 | EPERM | EPERM | — |  |
| 601 | EFAULT | ENOSYS | — | yes |
| 602 | EPERM | EPERM | — |  |
| 603 | EPERM | EPERM | — |  |
| 604 | EPERM | EPERM | — |  |
| 605 | EINVAL | EINVAL | — |  |
| 606 | 0 | 0 | — |  |
| 607 | EFAULT | ENOENT | — | yes |
| 608 | EFAULT | EFAULT | — |  |
| 609 | — | — | — | — |
| 610 | ENOSYS | ENOSYS | — |  |
| 611 | EPERM | EPERM | — |  |
| 612 | EFAULT | EINVAL | — | yes |
| 613 | EPERM | EPERM | — |  |
| 614 | — | — | — | — |
| 615 | EFAULT | EPERM | — | yes |
| 616 | ESRCH | ESRCH | — |  |
| 617 | 0 | 0 | — |  |
| 618 | EPERM | EPERM | — |  |
| 619 | ENOSYS | ENOSYS | — |  |
| 620 | 0 | 0 | — |  |
| 621 | — | — | — | — |
| 622 | — | — | — | — |
| 623 | EPERM | EPERM | — |  |
| 624 | EPERM, 3384 | EPERM, 3384 | — |  |
| 625 | EINVAL | EINVAL | — |  |
| 626 | EINVAL | EINVAL | — |  |
| 627 | ENOSYS | ENOSYS | — |  |
| 628 | EINVAL | EINVAL | — |  |
| 629 | EFAULT | EINVAL | — | yes |
| 630 | EFAULT | ENOENT | — | yes |
| 631 | — | — | — | — |
| 632 | ESRCH | ESRCH | — |  |
| 633 | ESRCH | ESRCH | — |  |
| 634 | ESRCH | ESRCH | — |  |
| 635 | ENOSYS | ENOSYS | — |  |
| 636 | EPERM | EPERM | — |  |
| 637 | EINVAL | EINVAL | — |  |
| 638 | 0 | 0 | — |  |
| 639 | 0 | 0 | — |  |
| 640 | 0 | 0 | — |  |
| 641 | ENOSYS | ENOSYS | — |  |
| 642 | EPERM | EPERM | — |  |
| 643 | 0 | 0 | — |  |
| 644 | ENOSYS | ENOSYS | — |  |
| 645 | ENOSYS | ENOSYS | — |  |
| 646 | EPERM | EPERM | — |  |
| 647 | EPERM | EPERM | — |  |
| 648 | EPERM | EPERM | — |  |
| 649 | EINVAL | ESRCH | — | yes |
| 650 | — | — | — | — |
| 651 | — | — | — | — |
| 652 | EPERM | EPERM | — |  |
| 653 | EPERM, 22 | EINVAL | — | yes |
| 654 | EINVAL | EINVAL | — |  |
| 655 | EINVAL | EINVAL | — |  |
| 656 | EPERM | EPERM | — |  |
| 657 | 0 | 0 | — |  |
| 658 | ENOTBLK | EBADF | — | yes |
| 659 | ENOMEM | ENOMEM | — |  |
| 660 | EFAULT | EFAULT | — |  |
| 661 | ENOSYS | ENOSYS | — |  |
| 662 | EINVAL | EINVAL | — |  |
| 663 | EINVAL | EINVAL | — |  |
| 664 | EINVAL | EINVAL | — |  |
| 665 | ENOSYS | ENOSYS | — |  |
| 666 | EINVAL | EINVAL | — |  |
| 667 | ENOSYS | ENOSYS | — |  |
| 668 | — | — | — | — |
| 669 | EINVAL | EINVAL | — |  |
| 670 | EBUSY | EBUSY | — |  |
| 671 | EPERM | EPERM | — |  |
| 672 | EPERM | EPERM | — |  |
| 673 | — | — | — | — |
| 674 | EINVAL | EINVAL | — |  |
| 675 | 0 | 0 | — |  |
| 676 | EINVAL | EINVAL | — |  |
## What the table says

- **No kernel read exists in this range.** Not one call returns data after being
  handed a supervisor address: the K column is a rejection (`EFAULT`, `EINVAL`,
  `ESRCH`) or absent. Where K differs from N it moves toward the unmapped-path
  answer, never toward a `0` with a filled buffer.
- **Eight numbers change their return value with the pointer class**, so those
  are the handlers that actually branch on arg1: **538** (`-1`/`EFAULT` on an
  absent page, `16903` on a mapped one), **557** (`-1`/`EFAULT` vs a handle,
  `520`), **563, 564, 565, 566** (`0` on an absent page, `-1`/`ESRCH` on a
  mapped one — the inverted direction), **572** (`-1`/`EACCES` vs `0`) and
  **653** (`22` vs `-1`/`EINVAL`). 538 and 557 are the only two that mint
  something for a readable page, and neither takes a supervisor address.
- **Fourteen numbers change only the errno** while returning `-1` in both
  classes: 540, 547, 551, 559, 587, 594, 601, 607, 612, 615, 629, 630, 649, 658.
  547 is the sharpest pair — `EFAULT` when the address *is* readable and
  `EACCES` when it is not, which is what a VM lookup that rejects unmapped
  ranges looks like; 587 gives `ESRCH` for a mapped page and `EPERM` for an
  absent one; 601 gives `EFAULT` for a mapped page and `ENOSYS` for an absent
  one.
- **27 numbers are deliberate stubs** and answer `ENOSYS` with `-1` on both
  user classes: 537, 568, 569, 574-584, 589, 590, 597, 610, 619, 627, 635, 641,
  644, 645, 661, 665, 667. 585 is a stub that returns `1`. Cite this list before
  anyone claims a handler exists at one of those numbers.
- **109 of the 131 pairs are identical**, 27 of them the stubs above; for the
  rest, an identical answer is what a credential gate, an argument validator or
  a call that never touches arg1 looks like. The 532-536, 539-546, 549-556, 558, 560-562 and 567-573
  blocks sit here, as do the `EPERM` Sony families.
- **Ten calls return `0` regardless of arg1**: 596, 606, 617, 620, 638, 639,
  640, 643, 657, 675. 624 belongs with them and returns the VM operation counter
  (`3384` in this run), the side channel 52b described.
- **The errno column is only meaningful when the return value is `-1`.**
  `get_error_string()` reads the thread's errno, which is stale after a
  successful call, so `585`'s `1`/`ENOSYS`, `624`'s `3384`/`EPERM` and the
  `0`/`ENOSYS` pairs are successes carrying an old errno, not errors.
- **`622` is the only number in 568-676 that dies on a bad argument** instead of
  rejecting it, which is why the sweep skips it; its size gate and credential
  predicate are documented on the syscall contract page.

## The next argument

This page holds arg2 and arg3 at zero for every call, so it cannot see a handler
that validates arg1 and then dereferences arg2. That measurement, and the calls
that turn out to write into the pages they are given, are on
[ARG23_CLASSES_14_10.md](ARG23_CLASSES_14_10.md): 20 numbers read arg2, 10 read
arg3, and seven of them write into a mapped destination without any of the
writes carrying a kernel pointer.

## What it does not say

A rejection means that *this* argument shape was refused, not that the handler
is absent: `docs/SYSENT_PRESENCE_14_10.md` already warns that the `-1` column is
not a verdict. The U column is one page of `0x41` with five zero arguments; a
handler that validates arg2 first never reaches arg1, which is exactly why the
`differs` column is the interesting one and the identical one is not evidence
of absence.

## Captures

| probe | boot | coverage | capture |
|---|---|---|---|
| 1334a | 2026-11-06, kernel base `0xFFFFFFFFCD400000` | U and N for 532-567 | `results/1334a_20261106_144023.txt` |
| 1334c | 2026-11-06 | U and N for 574-588 | `results/1334c_20261106_145045.txt` |
| 1342a run 3 | 2026-11-09, base `0xFFFFFFFFC1000000` | N for 568-620, SIG_IGN installed; died at 622 | `results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101208.txt` |
| 1342a run 4 | 2026-11-09 | N for 623-676, U for 568-676, K for eleven | `results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt` |

Skipped in every run as measured lethal or measured elsewhere: 561, 562, 570,
571, 573, 609, 614, 621, 622, 631, 650, 651, 668, 673.
