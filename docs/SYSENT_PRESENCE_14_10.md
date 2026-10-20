# Sysent presence map (14.10)

A kill means the slot is absent (`docs/SYSCALL_ABSENT_VS_LETHAL.md`), so a sweep that
records the return value also records which handlers exist. `-1` is a positive result: the
handler ran and rejected six zero arguments.

Names come from the 13.60 sysent capture (`docs/sysent-names-13.60.csv`) and are labels for
the slot, not proof that 14.10 ships the same handler body. Every presence and return value
below is measured on 14.10 by `tools/syscall_isolation_sweep.py`: six zero `uint64`
arguments, one connection per number.

## Measured slots

| syscall | 13.60 name | return | status |
|---|---|---|---|
| 538 | `evf_create` | `-1` | present |
| 539 | `evf_delete` | `-1` | present |
| 540 | `evf_open` | `-1` | present |
| 541 | `evf_close` | `-1` | present |
| 542 | `evf_wait` | `-1` | present |
| 543 | `evf_trywait` | `-1` | present |
| 544 | `evf_set` | `-1` | present |
| 545 | `evf_clear` | `-1` | present |
| 546 | `evf_cancel` | `-1` | present |
| 547 | `query_memory_protection` | `-1` | present |
| 548 | `batch_map` | `0` | present |
| 549 | `osem_create` | `-1` | present |
| 550 | `osem_delete` | `-1` | present |
| 551 | `osem_open` | `-1` | present |
| 552 | `osem_close` | `-1` | present |
| 553 | `osem_wait` | `-1` | present |
| 554 | `osem_trywait` | `-1` | present |
| 555 | `osem_post` | `-1` | present |
| 556 | `osem_cancel` | `-1` | present |
| 557 | `namedobj_create` | `-1` | present |
| 558 | `namedobj_delete` | `-1` | present |
| 559 | `set_vm_container` | `-1` | present |
| 560 | `debug_init` | `-1` | present |
| 561 | `suspend_process` | absent (kills) | |
| 562 | `resume_process` | absent (kills) | |
| 563 | `opmc_enable` | `0` | present |
| 564 | `opmc_disable` | `0` | present |
| 565 | `opmc_set_ctl` | `0` | present |
| 566 | `opmc_set_ctr` | `0` | present |
| 567 | `opmc_get_ctr` | `-1` | present |
| 568 | `budget_create` | absent (kills) | |
| 569 | `budget_delete` | absent (kills) | |
| 570 | `budget_get` | absent (kills) | |
| 571 | `budget_set` | absent (kills) | |
| 572 | `virtual_query` | absent (kills) | |
| 573 | `mdbg_call` | absent (kills) | |
| 574 | `obs_sblock_create` | absent (kills) | |
| 575 | `obs_sblock_delete` | absent (kills) | |
| 661 | `aio_submit` | absent (kills) | |
| 662 | `aio_multi_delete` | `-1` | present |
| 663 | `aio_multi_wait` | `-1` | present |
| 664 | `aio_multi_poll` | `-1` | present |
| 665 | `aio_get_data` | absent (kills) | |
| 666 | `aio_multi_cancel` | `-1` | present |
| 667 | `get_bio_usage_all` | `-1` | present |
| 668 | `aio_create` | absent (kills) | |
| 669 | `aio_submit_cmd` | `-1` | present |
| 670 | `aio_init` | `0` | present |

## What the names explain

- **561 `suspend_process`, 562 `resume_process`, 568-571 `budget_*` are gone.** Sony removed
  the process-control and budget calls; four of them are consecutive, so the holes are the
  deliberate removal of a family, not damage.
- **563-566 return `0`: `opmc_enable`, `opmc_disable`, `opmc_set_ctl`, `opmc_set_ctr`.**
  Probed in 177b-177d: argument one must be 0, argument two is ignored (enable/disable) or
  range-checked to `{0..4}` (set_ctl/set_ctr), no call keeps state (enable answers `0` on four
  consecutive calls) and none writes a buffer. That is the silent-success stub shape, not a
  reachable MSR path.
- **567 `opmc_get_ctr` returns `-1`** for all 12 argument layouts tried, including buffered and
  size-and-version header shapes, and has never written a byte. The block has no read path.
- **661 `aio_submit`, 665 `aio_get_data`, 668 `aio_create` are absent.** The rest of the AIO
  block exists but rejects every layout (`docs/AIO_RANGE_14_10_EVIDENCE.md`): the context
  they need can only be made by 661, so the range is unreachable by construction.
- Host facilities `307 kldnext`, `308 kldstat`, `337 kldsym`, `570 sysctlbyname` are absent,
  which is why those probes died rather than returning errors.

## Cost model

An absent number costs one game relaunch, because the kill takes the whole process -
including when the call is made from a `thr_create` child (176a). Sweep in ascending order
and stop at the first kill keeps that to one relaunch per absent slot.

Captures: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_185359.txt`
(538-560), `..._185415.txt` (561), `..._190003.txt` (562), `..._190202.txt` (568),
`..._190649.txt` (569), `..._190943.txt` (571).
