# sys 620 VM self-modification — probe 99a Section B was run

**Finding:** `docs/MICROARCH_FEASIBILITY_14_10.md` §8 says "Probe 99a sections B/C
were written but never run" and calls sys 620 "the cheapest route to native exec."
Section **B was run** on 2026-10-20, well before the MICROARCH memo (2026-11-11).
It returned 0 but produced no observable VM operation. Section C (mprotect retest)
remains unrun. This corrects the "never run" claim and the framing of sys 620 as an
unmeasured lead.

## Evidence [M]

`results/99a_B_20261020_152730.txt` (probe `probes/phase17_new_vectors/99a_hw_write_vm_selfmod.lua`, Section B):

```
--- Section B: sys 620 VM self-modification ---
  0 args. NO credential check.
  Derives 16KB page from saved RIP, calls VM op mode 5
[B1] eboot base: unknown
[B3] VM counter BEFORE: 0xE73
[B4] Calling sys 620:
  ret=0x0
[B5] VM counter AFTER: 0xE73
  (no change — operation may have failed silently)
[B7] Rapid sys 620 x5:
  call 1-5: ret=0x0
  VM counter final: 0xE73
[DONE] Section B complete
```

Section A (`results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261020_152717.txt`)
was also run: sys 617 (MMIO byte writer) returns 0 for all byte/full-width arguments
with the VM counter unchanged (0xE73) and PID stable — no observable effect.

## Interpretation

- **Sys 620 reachability:** the handler exists and accepts zero arguments (ret=0,
  caller alive) — per `docs/SYSCALL_ABSENT_VS_LETHAL.md`, a present, reachable slot.
  `docs/ATTACK_SURFACE.md:323` already lists `620 | free_stack | 0`, consistent.
- **No observable effect:** the sys 624 VM operation counter (a monotonic counter
  that increments +5 per mmap, per probe 52b) did not move across six sys 620 calls
  (0xE73 before, 0xE73 after). The probe itself notes "operation may have failed
  silently." So the W^X-bypass premise (VM op on the saved-RIP page) produced no
  measured page-attribute change in Section B.
- **The ATTACK_SURFACE vs TODO contradiction** the MICROARCH memo flagged is
  therefore partly resolved by measurement: sys 620 returns 0 (matching
  ATTACK_SURFACE), and the "MODE 5 self-modification / W^X bypass" hypothesis has
  so far shown no VM activity. It is not confirmed.

## Scope of this finding

- **Corrects** "written but never run" for Section B (it was run, 2026-10-20).
- **Section C is still unrun** — the mprotect-retest that would check whether page
  attributes changed after sys 620 has no capture. The MICROARCH memo's call for a
  run is still valid for Section C.
- Section B did not print the eboot base (`[B1] eboot base: unknown`), so it could
  not query protection on the saved-RIP page — a limitation of that run. A decisive
  W^X test would need the eboot base resolved and Section C's mprotect retest.
- No native exec, W^X bypass, or kernel write is claimed.

## Ledger

Recorded in `results/INDEX.md` at grade **M**, with the 99a Section B capture
attached (superseding its `?` seed row).

## References

- [`results/99a_B_20261020_152730.txt`](../results/99a_B_20261020_152730.txt) — Section B
- [`results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261020_152717.txt`](../results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261020_152717.txt) — Section A
- [`probes/phase17_new_vectors/99a_hw_write_vm_selfmod.lua`](../probes/phase17_new_vectors/99a_hw_write_vm_selfmod.lua)
- [`docs/MICROARCH_FEASIBILITY_14_10.md`](MICROARCH_FEASIBILITY_14_10.md) §8
- [`docs/ATTACK_SURFACE.md`](ATTACK_SURFACE.md) line 323
