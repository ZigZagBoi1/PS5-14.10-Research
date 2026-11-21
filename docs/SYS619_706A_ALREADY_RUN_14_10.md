# sys 619 test_debug_rwmem — probe 706a was already run

**Finding:** `docs/FREEBSD_CVE_TRIAGE_14_10.md` S5 says to "read the result of
`probes/phase17_new_vectors/706a_sys619_slot.lua` first — if unrun, run it."
The probe **was already run** on 2026-10-25 (two captures, both predating the
2026-11-04 triage doc). The first attempt hit a script error; the second ran to
completion and showed all shapes return -1 with the buffer unchanged. The S5
open question (stub vs gated) is not fully closed — 706a did not include the
timing / arg1-validation discriminator S5 proposes — but the "if unrun, run it"
instruction is void and its observed results can be read now.

## Evidence [M]

- `results/phase17_new_vectors/706a_sys619_slot_20261025_091322.txt` — first
  attempt failed to load: `error loading script: ...:56: cannot use '...' outside
  a vararg function near '...'`.
- `results/phase17_new_vectors/706a_sys619_slot_20261025_091336.txt` — second
  attempt ran under the SIGSYS shield. Selected output:

```
[S] sigaction(12, SIG_IGN) ok=true
[*] sys 619 (buf, 0x100, 0, 0, 0)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 619 (0, buf, 0x100, 0, 0)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 619 (buf, 0x100, 0, 0, 1)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 619 (0, 0, buf, 0x100, 0)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 652 (buf, 0x100, 0, 0, 0)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 652 (0, buf, 0x100, 0, 0)
    ret=0xffffffffffffffffffffffff  buf[0]=DEADBEEF buf[4]=DEADBEEF
[*] sys 4095 (0,0,0,0,0)
```

(The capture truncates after the 4095 line; the 619/652 shapes above are complete.)

Related captures already cited by S5: `179a_debug_rwmem_args` (15 shapes, all -1)
and `447a_debug_rwmem` / `892a_sys619_sweep` (more all-(-1) shapes, buffer
unchanged). So a substantial argument matrix already returns -1 with no write.

## Interpretation

Per `docs/SYSCALL_ABSENT_VS_LETHAL.md`, -1 with a live caller means the slot is
present and rejecting these arguments. Every 619 shape tried — in 706a, 179a,
447a and 892a — returned -1 and left the sentinel buffer bytes untouched. This
is consistent with either a stub or a gated handler, exactly as S5 describes.

**What 706a does settle:** its result exists and can be read; S5's "if unrun, run
it" condition is false.

**What 706a does not settle:** it varies the argument *positions* but does not
compare `619(getpid(), ...)` vs `619(0x7fffffff, ...)` vs `619(0, ...)` with a
timing sample, which is S5's stated discriminator for stub-vs-gated. That
comparison remains an open console task.

## Scope of this finding

Corrects one factual claim in S5 ("if unrun, run it") and records the already-run
probe's result. No change to the stub-vs-gated verdict; no escalation or kernel
R/W claimed.

## Ledger

Recorded in `results/INDEX.md` at grade **M**, with the successful 706a capture
attached.

## References

- [`results/phase17_new_vectors/706a_sys619_slot_20261025_091336.txt`](../results/phase17_new_vectors/706a_sys619_slot_20261025_091336.txt) — successful run
- [`results/phase17_new_vectors/706a_sys619_slot_20261025_091322.txt`](../results/phase17_new_vectors/706a_sys619_slot_20261025_091322.txt) — failed load
- [`probes/phase17_new_vectors/706a_sys619_slot.lua`](../probes/phase17_new_vectors/706a_sys619_slot.lua)
- [`docs/FREEBSD_CVE_TRIAGE_14_10.md`](FREEBSD_CVE_TRIAGE_14_10.md) S5
