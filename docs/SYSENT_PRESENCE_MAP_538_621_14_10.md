# Sysent presence map, 538-621, measured with the SIG_IGN oracle (probe 1255a, 2026-11-05)

## Why this exists

Every earlier presence table in this repository was built from a kill/no-kill column: a number
that terminated the process was recorded as "lethal", a number that returned was "present".
Probe 1253a showed that a kill is only the default SIGSYS disposition, and that with `SIG_IGN`
installed an absent slot answers `-1 / ENOSYS(78)` and the process survives. This probe walks
the Sony block in one connection with that oracle, so presence is read directly instead of
inferred, and each present handler also yields its own errno for zeroed arguments.

Capture: `results/phase17_new_vectors/1255a_presence_map_538_676_20261105_210306.txt`
(pid 80, 8.8 s, stopped at 622 — see the hazard section).

## Result

**53 present, 26 absent in 538-621.**

- **Present:** 538-560, 567, 572, 586-588, 591-596, 598-608, 611-613, 615-618, 620
- **Absent:** 561-562, 568-571, 573-584, 589-590, 597, 609-610, 614, 619, 621

Two of the absent runs are structural rather than accidental:

- **573-584 is twelve consecutive absent slots.** A whole family was removed, the same shape as
  the earlier 561/562 `suspend_process`/`resume_process` and 568-571 `budget_*` removals.
  Twelve in a row is a deliberate feature deletion, not damage.
- **561-562 and 568-571 confirm the earlier reading** that Sony removed the process-control and
  budget calls; they are absent, not merely gated.

## Per-number errno with zeroed arguments

Present handlers return their validation errno, which is the first clean reading for most of
these numbers. EPERM/EACCES at 547, 559, 572, 586, 587, 599, 600, 603, 604, 611, 613, 618 is
the capability gate refusing zeros, not absence; `ret=0` rows (548, 560, 596, 602, 606, 617,
620) are handlers that accept a zero argument and are the ones worth revisiting with real
arguments.

| n | ret | errno | text | verdict |
|---|---|---|---|---|
| 538 | -1 | 22 | Invalid argument | present |
| 539 | -1 | 3 | No such process | present |
| 540 | -1 | 14 | Bad address | present |
| 541 | -1 | 3 | No such process | present |
| 542 | -1 | 22 | Invalid argument | present |
| 543 | -1 | 22 | Invalid argument | present |
| 544 | -1 | 3 | No such process | present |
| 545 | -1 | 3 | No such process | present |
| 546 | -1 | 3 | No such process | present |
| 547 | -1 | 13 | Permission denied | present |
| 548 | 0 | 13 | Permission denied | present |
| 549 | -1 | 22 | Invalid argument | present |
| 550 | -1 | 3 | No such process | present |
| 551 | -1 | 14 | Bad address | present |
| 552 | -1 | 3 | No such process | present |
| 553 | -1 | 22 | Invalid argument | present |
| 554 | -1 | 22 | Invalid argument | present |
| 555 | -1 | 22 | Invalid argument | present |
| 556 | -1 | 3 | No such process | present |
| 557 | -1 | 22 | Invalid argument | present |
| 558 | -1 | 3 | No such process | present |
| 559 | -1 | 1 | Operation not permitted | present |
| 560 | 0 | 1 | Operation not permitted | present |
| 561 | -1 | 78 | Function not implemented | absent |
| 562 | -1 | 78 | Function not implemented | absent |
| 567 | -1 | 3 | No such process | present |
| 568 | -1 | 78 | Function not implemented | absent |
| 569 | -1 | 78 | Function not implemented | absent |
| 570 | -1 | 78 | Function not implemented | absent |
| 571 | -1 | 78 | Function not implemented | absent |
| 572 | -1 | 13 | Permission denied | present |
| 573 | -1 | 78 | Function not implemented | absent |
| 574 | -1 | 78 | Function not implemented | absent |
| 575 | -1 | 78 | Function not implemented | absent |
| 576 | -1 | 78 | Function not implemented | absent |
| 577 | -1 | 78 | Function not implemented | absent |
| 578 | -1 | 78 | Function not implemented | absent |
| 579 | -1 | 78 | Function not implemented | absent |
| 580 | -1 | 78 | Function not implemented | absent |
| 581 | -1 | 78 | Function not implemented | absent |
| 582 | -1 | 78 | Function not implemented | absent |
| 583 | -1 | 78 | Function not implemented | absent |
| 584 | -1 | 78 | Function not implemented | absent |
| 586 | -1 | 1 | Operation not permitted | present |
| 587 | -1 | 1 | Operation not permitted | present |
| 588 | -1 | 22 | Invalid argument | present |
| 589 | -1 | 78 | Function not implemented | absent |
| 590 | -1 | 78 | Function not implemented | absent |
| 591 | -1 | 14 | Bad address | present |
| 592 | -1 | 12 | Cannot allocate memory | present |
| 593 | -1 | 14 | Bad address | present |
| 594 | -1 | 14 | Bad address | present |
| 595 | -1 | 3 | No such process | present |
| 596 | 0 | 3 | No such process | present |
| 597 | -1 | 78 | Function not implemented | absent |
| 598 | -1 | 14 | Bad address | present |
| 599 | -1 | 1 | Operation not permitted | present |
| 600 | -1 | 1 | Operation not permitted | present |
| 601 | -1 | 14 | Bad address | present |
| 602 | 0 | 14 | Bad address | present |
| 603 | -1 | 1 | Operation not permitted | present |
| 604 | -1 | 1 | Operation not permitted | present |
| 605 | -1 | 22 | Invalid argument | present |
| 606 | 0 | 22 | Invalid argument | present |
| 607 | -1 | 14 | Bad address | present |
| 608 | -1 | 14 | Bad address | present |
| 609 | -1 | 78 | Function not implemented | absent |
| 610 | -1 | 78 | Function not implemented | absent |
| 611 | -1 | 1 | Operation not permitted | present |
| 612 | -1 | 14 | Bad address | present |
| 613 | -1 | 1 | Operation not permitted | present |
| 614 | -1 | 78 | Function not implemented | absent |
| 615 | -1 | 14 | Bad address | present |
| 616 | -1 | 3 | No such process | present |
| 617 | 0 | 3 | No such process | present |
| 618 | -1 | 1 | Operation not permitted | present |
| 619 | -1 | 78 | Function not implemented | absent |
| 620 | 0 | 78 | Function not implemented | present |
| 621 | -1 | 78 | Function not implemented | absent |

## The 622 hazard — a real handler that faults on a NULL first argument

The sweep stopped at 622. 1255a passed `622(0, 0, ...)`; 1256a retested with a valid zeroed
0x4000 buffer in arg2 and `622(0, buf, ...)`, and **both killed the process under SIG_IGN**.
So 622 is a genuine handler whose first argument is dereferenced in a way that a zero value
makes fatal — it is not a `nosys` slot. Its earlier 55b/55c results (400+ commands in
0x100-0x520 each returning 0 with `0x800E0001` in the buffer) never exercised arg1 = 0, and 55c
is **void** besides: every call passed `0x100` in the size field and was stopped at the entry
check, so only 55b (which used `0x40`) reached the dispatch path.

Practical consequence: 622 must always be called with a non-zero first argument. It stays
classified present from 55b and `1335a` (55c is void - entry-check reject, no dispatch); the map
simply cannot include it in a zero-argument sweep.

## Caveats

- A handler that deliberately returns ENOSYS is indistinguishable from an absent slot. The
  claim is "no code is implemented behind this number", which is the operationally useful form.
- Zeroed arguments reach the validation path, not the granted path. A present handler here is
  proven to exist, not proven to be reachable.
- 563-566, 585, 643 and 675 were excluded from the sweep on purpose: they have process-local
  side effects (`opmc_*` state, the sandbox boolean at `td+0x408`, the chicken-switch word at
  `proc+0xa34`, the three-global reset) and are already classified elsewhere.

## What this changes

The 14.10 attack surface is now enumerated rather than inferred for the Sony block: 53 live
handlers between 538 and 621, of which the ones returning `0` for zeroed arguments are the only
candidates that reach real code without a valid argument shape.
