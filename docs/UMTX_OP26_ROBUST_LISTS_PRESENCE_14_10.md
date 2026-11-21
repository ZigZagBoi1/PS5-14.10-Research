# `_umtx_op` op 26 (ROBUST_LISTS) presence on PS5 14.10

**Finding: PRESENT handler, registration refused [M].** `UMTX_OP_ROBUST_LISTS` (op 26
on syscall 454) has been issued on 14.10 in at least three saved captures, all
predating `docs/FREEBSD_CVE_TRIAGE_14_10.md` (2026-11-04). All shapes returned `-1`
with the caller alive. This corrects that document's claim that op 26 "was never
issued" and its §3 / S4 `UNKNOWN` status.

## Evidence [M]

| Capture | Date | Call shape | Result |
|---------|------|-----------|--------|
| `results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt` | 2026-10-19 | `454(0, 26, size, params, 0)` — correct FreeBSD 11 layout, params in `uaddr1` | size=24: -1; size=32: -1; size=0: -1; canary OK, probe COMPLETE |
| `results/phase17_new_vectors/541a_umtx_op_matrix_20261024_152151.txt` | 2026-10-24 | op matrix 0-26 | `op 26 ROBUST_LISTS ret=-1 word=1` |
| `results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_235900.txt` | 2026-11-03 | `uaddr1 = head, uaddr2 = len` | len=0/24/4096/0: all rv=-1; alive pid printed |

The 110a probe header (`probes/phase19_umtx_454/110a_umtx_shm_reachability.lua`)
explicitly states its purpose was to issue SHM(25) and ROBUST_LISTS(26) against 454
with the FreeBSD 11 layout (params in `uaddr1`, size in `val`) that the earlier
phase-1/2 probes (which bound to 557) could not reach. Section D of the capture
confirms the call was made with that correct layout: `umtx_op(0, OP_ROBUST_LISTS, 24,
params, 0)` with a zeroed 24-byte params buffer.

## Interpretation (per docs/SYSCALL_ABSENT_VS_LETHAL.md)

- **`-1` with a live caller = present handler.** An absent slot terminates the
  caller; a stub returns `ENOSYS`. Op 26 returned `-1` and the process completed
  with its canary intact, so the handler exists and is reachable — it is not an
  absent slot, and it is on the live syscall surface.
- **No successful registration was observed.** A successful
  `__umtx_op_robust_lists` registration returns `0`. Every tested shape — including
  the correct size=24 case — returned `-1`, so the `umtx_robust_lists` object was
  never created in these runs. With no kmalloc'd object linked to `td`, the
  two-thread UAF (register vs thread-exit free) did not occur.

## Scope of this finding

This closes the `UNKNOWN` / "never issued" status, but it does **not** fully resolve
whether op 26 can ever register. The triage doc's S4 reachability ladder proposed a
specific shape not tried in these captures: `454(26, buf, 0, 0, 0)` with a
non-zero robust-list-head field (`rdl = 1`). The captures above used a zeroed params
buffer (110a) or a head/len layout (1065a). Whether a non-zero list head changes the
return from `-1` to `0` is **untested and requires a console run**. If registration
succeeds with that shape, S4's race becomes live; if it still returns `-1`, the op
is a stub/gate and S4 is cut.

So the honest status is: **issued, present, registration refused with every shape
tested so far**; one proposed shape remains open.

## Ledger

Recorded in `results/INDEX.md` at grade **M**, with the 110a capture attached. Note
the three captures already had `?`-grade seed rows; this row supersedes them for the
op-26 presence question.

## References

- [`probes/phase19_umtx_454/110a_umtx_shm_reachability.lua`](../probes/phase19_umtx_454/110a_umtx_shm_reachability.lua) — Section D
- [`results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt`](../results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt)
- [`results/phase17_new_vectors/541a_umtx_op_matrix_20261024_152151.txt`](../results/phase17_new_vectors/541a_umtx_op_matrix_20261024_152151.txt)
- [`results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_235900.txt`](../results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_235900.txt)
- [`docs/FREEBSD_CVE_TRIAGE_14_10.md`](FREEBSD_CVE_TRIAGE_14_10.md) §3 / S4
- [`docs/SYSCALL_ABSENT_VS_LETHAL.md`](SYSCALL_ABSENT_VS_LETHAL.md)
