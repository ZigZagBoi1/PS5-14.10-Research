# sys 596 dynlib_do_copy_relocations — non-zero argument shapes on 14.10

**Finding:** `docs/FREEBSD_CVE_TRIAGE_14_10.md` S6 says the handler "has only ever
been called with zeros." That is incorrect. Capture 548a (2026-10-26), which
predates the triage doc (2026-11-04), called syscall 596 with several non-zero
argument shapes. All returned 0 with no observable effect. The S6 *conclusion*
(the handler is a no-op for these shapes) is unchanged; the claim about what was
tested is corrected.

## Evidence [M]

`results/phase31_sony_leak/548a_sony_leak_hunt_20261026_143900.txt`, section `[A]`:

```
libkernel .text: 0x000000082D6E8000
libkernel .data: 0x000000082D750000
Snapped 32 qwords from libkernel .data
596(): ret=0x00000000_00000000
.data changes: 0
Sentinel: OK

596 with args (may be ignored):
  596(0): ret=0x00000000_00000000
  596(1): ret=0x00000000_00000000
  596(2): ret=0x00000000_00000000
  596(8193): ret=0x00000000_00000000
  596(147): ret=0x00000000_00000000
  [596(buf,0x200) output]
    (all zero)
```

Also `results/phase17_new_vectors/501a_struct_pointer_follow_20261024_122357.txt`
(2026-10-24): `sys 596 A ret=0x0 kern=0 dirty=128` and `sys 596 B ret=0x0 kern=0
dirty=128` — pointer-follow shapes, both return 0 with no kernel pointer.

## Interpretation

Syscall 596 was exercised with six distinct shapes: no args, four distinct scalar
values in the first argument position (0/1/2/8193/147, some > small-handle range),
a `(buf, 0x200)` buffer+length pair, and the 501a struct-pointer-follow shapes.
Every shape returned 0. In 548a the driver snapped 32 qwords of `libkernel .data`
before the call and found 0 changes afterward with the sentinel intact, and the
`596(buf,0x200)` output buffer was all zero — no relocation was written through a
caller pointer.

Per `docs/SYSCALL_ABSENT_VS_LETHAL.md`, a return of 0 means the handler exists and
accepted these argument shapes. This is consistent with 596 being a no-op / empty
relocation loop, not an absent slot. It does **not** prove a gated implementation
is absent (the S6 discriminator — a real module handle from 593/649 with a
populated relocation buffer — was never tried), but it does establish that 596 is
reachable and has been called with more than zeros.

## Scope of this finding

Corrects one factual claim in S6 ("only ever called with zeros"). The S6 open
question — whether 596 can perform an 8-byte write with a real module handle —
remains open and requires a console run. No escalation or kernel R/W is claimed.

## Ledger

Recorded in `results/INDEX.md` at grade **M**, with the 548a capture attached.

## References

- [`results/phase31_sony_leak/548a_sony_leak_hunt_20261026_143900.txt`](../results/phase31_sony_leak/548a_sony_leak_hunt_20261026_143900.txt) — section [A]
- [`results/phase17_new_vectors/501a_struct_pointer_follow_20261024_122357.txt`](../results/phase17_new_vectors/501a_struct_pointer_follow_20261024_122357.txt)
- [`docs/FREEBSD_CVE_TRIAGE_14_10.md`](FREEBSD_CVE_TRIAGE_14_10.md) S6
