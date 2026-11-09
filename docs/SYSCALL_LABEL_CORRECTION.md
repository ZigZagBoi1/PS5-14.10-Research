# The 13.60 syscall label table was shifted, and two claims inherited it

Status: **correction.** `tools/ghidra_label_syscalls.py` carried a
hand-maintained `SYSCALL_NAMES` dict that was a *compact list*, not a
number-keyed table. Unimplemented slots had been dropped from the list without
renumbering, so from roughly syscall 300 onward each entry named a slot
1–16 numbers below its own. The committed capture disagreed with it on 153
entries. Two published results — the jail assessment and probe 57e — used the
wrong numbers as a result.

## 1. What the table said and what the capture says

Cross-checking the dict against `docs/sysent-names-13.60.csv` (735 entries,
native) and `docs/sysent-compat-names-13.60.csv` (677 entries, the table that
`sysent_index.json` matches):

| number | stale label | capture label | capture `narg` |
|---|---|---|---|
| 429 | `jail_attach` | `sigwait` | 2 |
| 430 | `extattr_list_fd` | `thr_create` | 3 |
| 431 | `extattr_list_file` | `thr_exit` | 1 |
| 432 | `extattr_list_link` | `thr_self` | 1 |
| 433 | `ksem_timedwait` | `thr_kill` | 2 |
| 436 | `kldunloadf` | `obs_{` (unimplemented) | 0 |
| 442 | `setaudit` | `thr_suspend` | 1 |
| 443 | `getaudit_addr` | `thr_wake` | 1 |
| 444 | `setaudit_addr` | `kldunloadf` | 2 |
| 454 | `kmq_unlink` | `_umtx_op` | 6 |
| 455 | `abort2` | `thr_new` | 2 |
| 456 | `thr_set_name` | `sigqueue` | 3 |

The capture is right, three ways:

1. **Arity.** `thr_create` takes three arguments and slot 430 records
   `narg=3`; `extattr_list_fd` takes four. `thr_new` takes two and slot 455
   records `narg=2`; `abort2` takes three. `sigqueue` takes three and 456
   records three.
2. **Handler shape.** 430's body at `0x437cf0` opens with a `0x500`-byte
   `copyin` from arg0 — the size of a `ucontext_t`, not an extattr buffer.
   454's body at `0x37ec40` bounds `[rsi+8]` at `0x1b` and indexes a jump
   table: dispatch on an operation code, which is `_umtx_op` and not
   `kmq_unlink`.
3. **FreeBSD 9 numbering.** `jail_attach` is 436, `thr_create` is 430,
   `sigwait` is 429 in `stable/9/sys/kern/syscalls.master`, matching the
   capture exactly. The PS5 kernel reports `r230171`, a FreeBSD 9-era
   revision.

## 2. Why it happened

The dict's own comment said "FreeBSD 9-era sysent" and its entries are in the
right *order*, but entries with no implementation (`UNIMPL`, `COMPAT10`,
`NOSTD`) were omitted when the list was written down. Dropping an entry
without adjusting the numbers shifts every later entry by one; by syscall 470
the drift reaches sixteen. Nothing validated the dict against the capture, so
the shift was invisible.

## 3. What it broke

- **The jail assessment** (`docs/CVE-2026-49419-PS5-14.10.md`) claimed 429 was
  `jail_attach` with a real body at `0x55deb0`, and that 496/497 were
  `jail_get`/`jail_set`. In fact 429 is `sigwait`, 496 is `mkdirat`, and 497 is
  `mkfifoat`. The corrected conclusion is stronger than the original: searching
  both name captures for `jail` returns **zero rows**, and the slots that
  would carry jail syscalls (338, 436, 506, 507) are unimplemented
  (`obs_{`, `narg=0`, nosys at `0x265760`) in 13.60.
- **Probe 57e** would have called `sigwait` with a NULL set and `mkdirat` with
  a zeroed buffer, answering a different question entirely. It now calls 338,
  436, 506 and 507, with 429 kept only as a dispatch control.

## 4. The fix

`tools/gen_syscall_labels.py` regenerates the table from
`docs/sysent-names-13.60.csv` between explicit begin/end markers in the Ghidra
script, mapping the capture's unnamed-slot marker to no label at all (the
script already handles nosys by address). `--check` exits non-zero on drift, so
the table cannot silently diverge again. `tools/test_syscall_labels.py` pins
the generated block to the capture, pins the twelve identities above, and
cross-checks the capture's `narg` against each named prototype.

The table now has 375 labels rather than 449. The 74 missing entries are slots
that were previously *named but wrong* and carry no symbol in the capture;
they fall through to the script's `syscall_N` fallback instead of acquiring a
borrowed name.

## 5. What this does not establish

- Nothing here changes a 14.10 observation. The labels describe the 13.60
  capture; 14.10 dispatch is unmeasured for every number above.
- Correct numbering does not make any handler reachable. A `sigwait` identity
  does not imply the syscall succeeds, and a jail slot being unimplemented in
  13.60 does not prove it is unimplemented in 14.10.
- Probes that used the affected numbers for a *different* purpose are not
  re-examined here; only the jail path and its probe were audited.
