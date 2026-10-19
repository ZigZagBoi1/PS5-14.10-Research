# 13.60 syscall name map + sysent capture identification

> Supplied by cross-referencing the local `dumps_13.60/sysent_index.json` against a **full
> 13.60 kernel dump** (post-HV-defeat, complete TEXT + DATA, 16,391-symbol database,
> FreeBSD 11.0.0 signature matching). All handler addresses are expressed as **RVAs
> relative to the kernel text base** — the same `sy_call_off` convention already used in
> `sysent_index.json` — so they are KASLR-independent.

## 1. Artifacts added

| File | ABI | Entries | `nosys` stubs (rva `0x265760`) | Non-`nosys` entries |
|------|-----|---------|-------------------------------|---------------------|
| `sysent-names-13.60.csv` | native (ELF64) | 735 | 239 | 496 |
| `sysent-compat-names-13.60.csv` | compat (ELF32 / FreeBSD32) | 677 | 368 | 309 |

Columns: `number,name,handler_rva`.

## 2. Finding 1 — `dumps_13.60/sysent_index.json` is the **compat** table

The existing `sysent_index.json` (679 entries) matches the **32-bit compat sysent table**,
not the native 64-bit table.

Evidence (entry-by-entry cross-check):

- **0** RVA mismatches against the compat table for syscall numbers 0–676 (entries 677–678
  are the two already-flagged malformed trailing entries).
- **138** RVA mismatches against the native table. All 138 are standard FreeBSD syscalls
  that the compat ABI stubs to `nosys` while the native ABI implements them — e.g. `link`,
  `mount`, `chown`, `unmount`, `ptrace`, `symlink`, `readlink`, `umask`, `chroot`, `vfork`,
  `sbrk`, `sstk`, `getpgrp`, `setpgid`, `swapon`, `fchown`, `mkfifo`.

Consequence: the "311 non-nosys entries" figure used in the README is a compat-table count
and does not match either table (compat = 309 non-`nosys`, native = 496). This is
significant if the survey's syscall-availability conclusions are to be interpreted per-ABI,
because a PS4-backcompat process and a native process dispatch through **different** tables.

## 3. Finding 2 — the AIO family 661–670 has no `nosys` members

`sysent_index.json` itself already shows every member of 661–670 as a real handler; the
full dump supplies the names:

| num | `handler_rva` | name | notes |
|-----|---------------|------|-------|
| 661 | `0x265710` | `aio_submit` | real handler, **not** `nosys` |
| 662 | `0x265718` | `aio_multi_delete` | |
| 663 | `0x265720` | `aio_multi_wait` | 5 args; Relapse UAF target |
| 664 | `0x265728` | `aio_multi_poll` | |
| 665 | `0x265730` | `aio_get_data` | real handler, **not** `nosys` |
| 666 | `0x265738` | `aio_multi_cancel` | |
| 667 | `0x265f88` | `get_bio_usage_all` | |
| 668 | `0x265708` | `aio_create` | real handler, **not** `nosys` |
| 669 | `0x265740` | `aio_submit_cmd` | |
| 670 | `0x265748` | `aio_init` | |

`nosys` is rva `0x265760`; none of 661–670 resolve to it.

## 4. Finding 3 — an internal inconsistency to reconcile

Several docs state that `661, 665 and 668 dispatch/route to nosys` and that `663`'s table
target is `TEXT+0x3b01f0`:

- `KERNEL_DUMP_ANALYSIS.md` (AIO Handler Follow-up + Cross-Firmware implications)
- `SECONDARY_EXPLOIT_AUDIT_13.60.md` (Corrected AIO coverage and mapping)
- `CROSS_FIRMWARE_PATTERN_RESEARCH.md` (Strongest cross-firmware signals, row 6)

This contradicts the published `dumps_13.60/sysent_index.json`, which places 661/665/668 at
`0x265710`/`0x265730`/`0x265708` (real handlers) and 663 at `0x265720`, not `0x3b01f0`.
The `TEXT+0x3b01f0` offset appears to come from the separate `terrafirma2021` live capture
(`kernel-13.60-live.bin`), which is a different artifact from the local
`dumps_13.60/sysent_index.json`. This PR does **not** re-audit the terrafirma capture;
it flags the discrepancy so the two sources can be reconciled against their raw tables.

## 5. Provenance & method

- Source: full 13.60 kernel dump with native sysent at data offset `0x1b6e54` (735 entries)
  and compat sysent at data offset `0x1ae5c4` (677 entries), both 48-byte stride.
- Names assigned via FreeBSD 11.0.0 syscall numbering + `__func__`/sysent string refs,
  cross-validated against `getpid` (#20), `stat` (#188), `lstat` (#190) and the
  `aio_multi_wait` (#663) Relapse identity.
- `handler_rva` = `handler_va - 0xffffffffdf100000` (the text base of the source dump), so
  every value is directly comparable to `syscall_index.json`'s `sy_call_off`.

## 6. Limits

These are **13.60 identities only**. They do not establish 14.10 handler names, layout,
reachability, or behavior — exactly the boundary the existing docs already draw.
