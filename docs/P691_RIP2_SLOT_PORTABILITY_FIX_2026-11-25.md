# p691 RIP2 slot portability fix — 2026-11-25

Issue: #282.

## Root cause

`probes/phase13_webkit/p691-walk-forge-fixed.html` had two independent defects:

1. `PK` was parsed but never read. Every run filled all 16 forged vtable slots with the same `G_TRY`, so `pk=4`, `pk=9`, and the default were identical. The documented poison arm did not exist.
2. The default fill was `S0 - goff` with `goff=7`, while the nearby `G_RET` beacon advertised `S0 - 1` as a `ret` without checking the byte. Independent benches measured `*(S0-1) == 0x00`, and some builds map `.text` execute-only, so neither the assumption nor a read-back scan is portable.

## Fix

The probe now separates the safe default from explicit experiments:

| Query | Behavior |
|---|---|
| `pk=-1` (default) | Fill every slot with `R6`, the known returning `ref()` slot already used as the safe value by p690. |
| `pk=0..15` | Fill every slot with `R6` except the selected slot, which receives `0x4141414141414141`. |
| `pk=16` | Poison all 16 slots. |
| `goff=-1` (default) | Use the safe fill. |
| `goff=N` | Explicit byte-probe override: fill with `S0 - N`. This is never selected implicitly. |

The hardcoded `G_RET`/`G_TRY` path and its misleading `GADGET-ret=...` beacon were removed. `RIP2-SLOTS` now records the safe address, actual fill, offset, and `pk`; `LAY-OK` records the actual fill.

## Offline validation

`tools/test_p691_rip2_slots.py` extracts the real helper functions from the HTML with brace matching and executes them under Node. It covers:

- default safe-slot selection;
- default `pk=-1` and `goff=-1`;
- single-slot poison isolation;
- `pk=16` all-slot poison;
- explicit `goff=N` override;
- integration guard proving the slot loop calls the poison helper and no longer contains the hardcoded `S0-1` expression.

The integration guard was also run against `origin/master` and failed there as expected. The modified probe is included in the classic-script parse check.

No console run was performed. The change is logic-only and still needs an on-console safe/poison comparison before any dispatch claim is upgraded.

## Variant sweep

Changed:

- `probes/phase13_webkit/p691-walk-forge-fixed.html`

Inspected and intentionally unchanged:

- `probes/phase13_webkit/adapted-guide-entry/p691b-direct-vp-read.html`
- `probes/phase13_webkit/adapted-guide-entry/p691c-oracle-fix.html`
- `probes/phase13_webkit/adapted-guide-entry/p691d-self-scan.html`
- `probes/phase13_webkit/p691-structureid-prediction.html`

Those four do not contain the RIP2 forged-vtable fill path. `p690-walk-forge-oracle.html`, `p693-coop-vp-dispatch.html`, and `p672-iterateclients-callback-dispatch.html` already implement a `PK` poison arm and do not use the p691 `S0-1` default, so they were not modified.
