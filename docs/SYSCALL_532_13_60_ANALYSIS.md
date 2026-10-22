# Syscall 532 — 13.60 Handler Analysis

> **Date:** 2026-10-21. Source: `docs/dumps_13.60` (13.60-labeled capture;
> acquisition authenticity unresolved). Closes the measurement gap noted in
> PR #72 (syscalls 530-532/537) offline; 14.10 behavior still needs probe
> 272a.

## Slot status from the sysent dump

| Syscall | Status |
|---|---|
| 528, 529, 530, 531, 537 | **nosys** — same handler target as sysent[0] (rva 0x5620e0) |
| 532 | real, narg 5 (implemented) |

## Handler shape (rva 0xaf0040, followed through two thunk levels)

- Arguments: `(u32 type, u32 id, ptr a3, ptr a4, ptr a5)` — args read as
  `[rsi]`, `[rsi+8]` dwords and `[rsi+0x10]`, `[rsi+0x18]`, `[rsi+0x20]` qwords.
- Locks `curproc+0x148` (proc mutex) and reads the `proc+0xc81` gate byte
  (same field that gates syscall 676 on 14.10).
- Calls the sandbox permission checker `[td+0x140]`-cred path with id
  **0x2aa (682)**: `gate(td, 0x2aa)` at rva 0xadfa30. Gate-fail paths still
  allow limited types; gate-pass requires a credential check to return 1.
- Type argument must be in one of:
  - `0x18..0x1E` (range check `type-0x18 < 7`), `0x20`, `0x2f`
  - bitmask `0x800003d4` for `type <= 0x20` → types {2,3,4,5,6,7,31}
  - bitmask `0x2a` → types {1,3,5} (plus further masks deeper in the body)
- With a valid type it walks a global table of `0x28`-byte entries comparing
  `id` (arg1) against `entry+0x18`, including computed sub-ids
  `base + i*(1<<shift)` from `entry+0x15/+0x16`. Lookup miss returns Sony
  error `0x800d0203`; the three pointer args look like in/out buffers.

## Probe

`probes/phase17_new_vectors/272a_sys532_survey.lua` (CRASH_CLASS LOW): one
call per accepted type with id 0 and three zeroed 0x100 buffers, then a small
id sweep for type 1. Records raw returns and the first written dword.
