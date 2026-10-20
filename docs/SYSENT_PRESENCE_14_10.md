# Sysent presence map (14.10)

A returned value proves the slot exists. `-1` is a positive result: the handler ran and
rejected six zero arguments. A kill proves less than it first appeared to: an absent slot
kills (`173a`, syscall 4095), but so does a present handler that faults or refuses the call -
622 `ipmimgr_call` kills on six zeros and still returns `0` to a well-formed request (`55c`).
So a "kills" row means *not callable with zeros*, and the slot needs a second probe with
plausible arguments before it can be written off. See `docs/SYSCALL_ABSENT_VS_LETHAL.md`.

Names come from the 13.60 sysent capture (`docs/sysent-names-13.60.csv`) and are labels for
the slot, not proof that 14.10 ships the same handler body. Every presence and return value
below is measured on 14.10 by `tools/syscall_isolation_sweep.py`: six zero `uint64`
arguments, one connection per number.

## Measured slots

<!-- presence-table:start -->
| syscall | 13.60 name | return | status |
|---|---|---|---|
| 1 | `exit` | - | kills |
| 2 | `fork` | `-1` | present |
| 3 | `read` | `0` | present |
| 4 | `write` | `-1` | present |
| 5 | `open` | `-1` | present |
| 6 | `close` | `-1` | present |
| 7 | `wait4` | `-1` | present |
| 8 | `compat.creat` | - | kills |
| 9 | `link` | ? | CONNECT_FAILED |
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
| 561 | `suspend_process` | - | kills |
| 562 | `resume_process` | - | kills |
| 563 | `opmc_enable` | `0` | present |
| 564 | `opmc_disable` | `0` | present |
| 565 | `opmc_set_ctl` | `0` | present |
| 566 | `opmc_set_ctr` | `0` | present |
| 567 | `opmc_get_ctr` | `-1` | present |
| 568 | `budget_create` | - | kills |
| 569 | `budget_delete` | - | kills |
| 570 | `budget_get` | ? | CONNECT_FAILED |
| 571 | `budget_set` | - | kills |
| 572 | `virtual_query` | `-1` | present |
| 573 | `mdbg_call` | - | kills |
| 574 | `obs_sblock_create` | `-1` | present |
| 575 | `obs_sblock_delete` | `-1` | present |
| 576 | `obs_sblock_enter` | `-1` | present |
| 577 | `obs_sblock_exit` | `-1` | present |
| 578 | `obs_sblock_xenter` | `-1` | present |
| 579 | `obs_sblock_xexit` | `-1` | present |
| 580 | `obs_eport_create` | `-1` | present |
| 581 | `obs_eport_delete` | `-1` | present |
| 582 | `obs_eport_trigger` | `-1` | present |
| 583 | `obs_eport_open` | `-1` | present |
| 584 | `obs_eport_close` | `-1` | present |
| 585 | `is_in_sandbox` | `1` | present |
| 586 | `dmem_container` | `-1` | present |
| 587 | `get_authinfo` | `-1` | present |
| 588 | `mname` | `-1` | present |
| 589 | `dynlib_dlopen` | - | kills |
| 590 | `dynlib_dlclose` | - | kills |
| 591 | `dynlib_dlsym` | `-1` | present |
| 592 | `dynlib_get_list` | `-1` | present |
| 593 | `dynlib_get_info` | `-1` | present |
| 594 | `dynlib_load_prx` | `-1` | present |
| 595 | `dynlib_unload_prx` | `-1` | present |
| 596 | `dynlib_do_copy_relocations` | `0` | present |
| 597 | `dynlib_prepare_dlclose` | - | kills |
| 598 | `dynlib_get_proc_param` | `-1` | present |
| 599 | `dynlib_process_needed_and_relocate` | `-1` | present |
| 600 | `sandbox_path` | `-1` | present |
| 601 | `mdbg_service` | `-1` | present |
| 602 | `randomized_path` | `0` | present |
| 603 | `rdup` | `-1` | present |
| 604 | `dl_get_metadata` | `-1` | present |
| 605 | `workaround8849` | `-1` | present |
| 606 | `is_development_mode` | `0` | present |
| 607 | `get_self_auth_info` | `-1` | present |
| 608 | `dynlib_get_info_ex` | `-1` | present |
| 609 | `budget_getid` | - | kills |
| 610 | `budget_get_ptype` | `-1` | present |
| 611 | `get_paging_stats_of_all_threads` | `-1` | present |
| 612 | `get_proc_type_info` | `-1` | present |
| 613 | `get_resident_count` | `-1` | present |
| 614 | `prepare_to_suspend_process` | - | kills |
| 615 | `get_resident_fmem_count` | `-1` | present |
| 616 | `thr_get_name` | `-1` | present |
| 617 | `set_gpo` | `0` | present |
| 618 | `get_paging_stats_of_all_objects` | `-1` | present |
| 619 | `test_debug_rwmem` | `-1` | present |
| 620 | `free_stack` | `0` | present |
| 621 | `suspend_system` | - | kills |
| 622 | `ipmimgr_call` | - | kills |
| 623 | `get_gpo` | `-1` | present |
| 624 | `get_vm_map_timestamp` | `3377` | present |
| 625 | `opmc_set_hw` | `-1` | present |
| 626 | `opmc_get_hw` | `-1` | present |
| 627 | `get_cpu_usage_all` | `-1` | present |
| 628 | `mmap_dmem` | `-1` | present |
| 629 | `physhm_open` | `-1` | present |
| 630 | `physhm_unlink` | `-1` | present |
| 631 | `resume_internal_hdd` | - | kills |
| 632 | `thr_suspend_ucontext` | `-1` | present |
| 633 | `thr_resume_ucontext` | `-1` | present |
| 634 | `thr_get_ucontext` | `-1` | present |
| 635 | `thr_set_ucontext` | `-1` | present |
| 636 | `set_timezone_info` | `-1` | present |
| 637 | `set_phys_fmem_limit` | `-1` | present |
| 638 | `utc_to_localtime` | `0` | present |
| 639 | `localtime_to_utc` | `0` | present |
| 640 | `set_uevt` | `0` | present |
| 641 | `get_cpu_usage_proc` | `-1` | present |
| 642 | `get_map_statistics` | `-1` | present |
| 643 | `set_chicken_switches` | `0` | present |
| 644 | `#644` | `-1` | present |
| 645 | `#645` | `-1` | present |
| 646 | `get_kernel_mem_statistics` | `-1` | present |
| 647 | `get_sdk_compiled_version` | `-1` | present |
| 648 | `app_state_change` | `-1` | present |
| 649 | `dynlib_get_obj_member` | `-1` | present |
| 650 | `budget_get_ptype_of_budget` | - | kills |
| 651 | `prepare_to_resume_process` | - | kills |
| 652 | `process_terminate` | `-1` | present |
| 653 | `blockpool_open` | `22` | present |
| 654 | `blockpool_map` | `-1` | present |
| 655 | `blockpool_unmap` | `-1` | present |
| 656 | `dynlib_get_info_for_libdbg` | `-1` | present |
| 657 | `blockpool_batch` | `0` | present |
| 658 | `fdatasync` | `-1` | present |
| 659 | `dynlib_get_list2` | `-1` | present |
| 660 | `dynlib_get_info2` | `-1` | present |
| 662 | `aio_multi_delete` | `-1` | present |
| 663 | `aio_multi_wait` | `-1` | present |
| 664 | `aio_multi_poll` | `-1` | present |
| 665 | `aio_get_data` | - | kills |
| 666 | `aio_multi_cancel` | `-1` | present |
| 667 | `get_bio_usage_all` | `-1` | present |
| 668 | `aio_create` | - | kills |
| 669 | `aio_submit_cmd` | `-1` | present |
| 670 | `aio_init` | `0` | present |
| 677 | `wait6` | - | kills |
| 678 | `cap_rights_limit` | - | kills |
| 679 | `cap_ioctls_limit` | - | kills |
| 680 | `cap_ioctls_get` | - | kills |
| 681 | `cap_fcntls_limit` | - | kills |
| 682 | `cap_fcntls_get` | - | kills |
| 683 | `bindat` | - | kills |
| 684 | `connectat` | - | kills |
| 685 | `chflagsat` | - | kills |
| 686 | `accept4` | - | kills |
| 687 | `pipe2` | - | kills |
| 688 | `aio_mlock` | - | kills |
| 689 | `procctl` | - | kills |
| 690 | `ppoll` | - | kills |
| 691 | `futimens` | - | kills |
| 692 | `utimensat` | - | kills |
| 693 | `numa_getaffinity` | - | kills |
| 694 | `numa_setaffinity` | - | kills |
| 695 | `#695` | - | kills |
| 696 | `#696` | - | kills |
| 697 | `#697` | - | kills |
| 698 | `#698` | - | kills |
| 699 | `#699` | - | kills |
| 700 | `apr_submit` | - | kills |
| 701 | `apr_resolve` | - | kills |
| 702 | `apr_stat` | - | kills |
| 703 | `apr_wait` | - | kills |
| 704 | `apr_ctrl` | - | kills |
| 705 | `get_phys_page_size` | - | kills |
| 706 | `begin_app_mount` | - | kills |
| 707 | `end_app_mount` | - | kills |
| 708 | `fsc2h_ctrl` | ? | CONNECT_FAILED |
<!-- presence-table:end -->

## The table ends at 676 (2026-10-20)

The sweep of 677-734 killed the process on all 31 numbers it reached (677-707) before the
loader needed more than two minutes to come back; every one of them is out of range, in the
same way 4095 is. So the measured sysent ends at 676 on 14.10 and the slots above it do not
exist to be called. Capture:
`results/phase15_native_sent/syscall_isolation_sweep_20261020_200248.txt`.

This conflicts with the 13.60 capture, whose table has 735 entries and names 677 `wait6`,
687 `pipe2`, 690 `ppoll`, 705 `get_phys_page_size`, 715 `ioreq`, 725 `mmap2` and 728
`virtual_query_by_pid`. Either 13.60 shipped 58 slots that 14.10 does not, or the capture and
this firmware number their tables differently. Resolving it needs a 14.10 image, which the
repository does not have; until then the names above 676 are recorded as unverified and
unreachable rather than as targets. Five of the 13.60 slots in that tail (695-699) are the
`nosys` stub at `0x265760`, which is what an unimplemented slot looks like in a capture.

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

An absent number kills the whole process, including from a `thr_create` child (176a), but the
game restarts the loader by itself about nine seconds later with a new pid and module base. So
a sweep costs time, not a human: `--wait-for-loader` waits out the recovery and carries on. The
earlier sweeps aborted on the first `CONNECT_FAILED` and never sat long enough to see it.

Captures: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_185359.txt`
(538-560), `..._185415.txt` (561), `..._190003.txt` (562), `..._190202.txt` (568),
`..._190649.txt` (569), `..._190943.txt` (571).
