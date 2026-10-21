# Sony AIO Family — 13.60 Handler Decode (Syscalls 661-670)

> **Date:** 2026-10-21. Source: `docs/dumps_13.60` text capture (13.60-labeled).
> Motivation: the Relapse exploit (fw <= 13.60) raced `aio_multi_wait` (663,
> node free) against `aio_submit_cmd` (669, spray); 14.00 reportedly closed
> the race, but the patch location is unknown and probe 79c never ran. The
> 14.10 isolation sweep shows 662-664/666/669 present (-1 on zeros) and
> **670 aio_init returning 0 on zeros**.

## Slot status (13.60 capture)

| syscall | name | status | shape |
|---|---|---|---|
| 661 | aio_submit | **nosys stub** | — |
| 668 | aio_create | **nosys stub** | — |
| 662 | aio_multi_delete | real @0x3af900 | (ids_ptr, count u32, ptr) |
| 663 | aio_multi_wait | real @0x3b01f0 | (ids_ptr, count u32, states_ptr, mode u32, timeout_ptr) |
| 664 | aio_multi_poll | real @0x3b0fb0 | (ids_ptr, count, states_ptr, mode) |
| 665 | aio_get_data | real @0x3b1670 | kills on 14.10 zeros |
| 666 | aio_multi_cancel | real @0x3b1680 | (ids_ptr, count, ptr) |
| 669 | aio_submit_cmd | real @0x3b2060 | see below |
| 670 | aio_init | real @0x3b28d0 | (config_ptr, version, NULL, 0) |

## aio_submit_cmd(669) validation (rva 0x3b2060)

- `cmd` (arg0): `cmd & 0xFFF` must be **1 or 2** (`lea eax,[rcx-1]; cmp eax,1; ja reject`).
- arg2 (u32 size): must be **>= 0x81** (129 bytes minimum command buffer).
- arg3 (u32 type): must be **1, 2, or 3** (`dec eax; cmp eax,3; jae reject`).
- Runs through the aio context from `proc+0xc48` (shared handle namespace) and
  the same version negotiator as aio_init (0x8b3b81c0, negotiated version
  <= 0xFFFFFF).

## aio_init(670)

- version arg <= 0xFFFFFF; version 0x3C takes a config-struct parse path
  (0x8ad73f10); arg2 must be NULL and arg3 zero or EINVAL (0x131f/0x1324).
- Zeros are accepted (matches the 14.10 sweep's ret 0).

## Probe

`probes/phase17_new_vectors/276a_aio_lifecycle.lua` (CRASH_CLASS MODERATE):
init zeros + 0x3C, accepted-cmd submit shapes, 1-usec-bounded wait, matching
delete/poll/cancel. First-contact question: does any submission get ACCEPTED
(ret 0) on 14.10? If yes, the node lifecycle is live and the wait-vs-submit
race is schedulable with the proven thr_create threading (276b).
