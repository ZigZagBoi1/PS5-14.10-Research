# Issue #155 - Cross-Firmware FontFace UAF Analysis (14.00 <-> 14.10)

**Date:** 2026-10-31
**Source:** GitHub Issue #155 - "ps5 14.00 webkit: fontfaceset type confusion & memory offset mapping (part 2)"
**Participants:** lunarshe11 (14.00), cobrajet302gt (14.10), vincenzoiacovone (14.10)

## Executive Summary

An extraordinary cross-firmware collaborative research effort on the FontFaceSet::load() UAF.
Three independent benches (two on 14.10, one on 14.00) converged on identical findings through
systematic A/B testing, establishing the exploit as a reproducible, scripted oracle rather than
a probabilistic coin-flip.

Key verdict: The FontFace UAF is confirmed exploitable on BOTH 14.00 and 14.10. The `void A.loaded`
trigger is mandatory on both firmwares. The per-boot window model (not per-load coin) explains all
previously anomalous data. The m_stateStack forge via Canvas UAF is dead on both firmwares.
The read-only stale pointer strategy is the new direction.

## Critical Findings

### 1. The `void A.loaded` Trigger is Firmware-Independent and Mandatory

14.00 (lunarshe11):
- Without `void A.loaded`: 100% clean scans (survivable miss). Engine cleanly rejects fake object.
- With `void A.loaded`: Reliable hits after cold boot. 2/3 completed scans hit.

14.10 (cobrajet302gt, Campaign 6):
- Arm A (with `void A.loaded`): 20 loads -> 18 HIT, 2 SEGV-miss. 0 clean.
- Arm B (without `void A.loaded`): 16 loads -> 16x NOSCAN-fired-0. Mechanism never arms.

Verdict: This is a cross-firmware law, not a bench artifact. The `.loaded` pilot-cycle kick is
what vincenzo described as the mechanism that arms the window. Without it, the miss face is not
a clean scan - it's no participation.

### 2. Per-Boot Window Model (Not Per-Load Coin)

cobrajet302gt's 30/30 farm on 14.10 (boots 13-22, 3 cold reboots each):
- Load-1 p58 = 0x10001cb0d0 on ALL 10 boots (byte-identical, 15/15 overall).
- Load-position curve: Boot 31 (arm A, crash-reentry x9): loads 1-9 ALL HIT, load 10 died.
- The window survived at least nine consecutive fresh processes in one boot.
- Death at position 10 - expect the cliff somewhere at/after 10, not at 4.
- The earlier "dies after ~4 loads" was an artifact of churned sessions.

### 3. Forge-Spray A/B/C is Closed

| Spray Content | Outcome |
|---------------|---------|
| Zeros (default) | Hit 42/42, SEGV deaths = post-scan derefs of zeroed region |
| Refcnt + forged pointers | SEGV pre-scan, 15/15 |
| Refcnt only (+0x00 = 1) | Alive 15/15 |

Consequences:
1. The sprayed bytes are not adjacent to the freed struct - they ARE the struct's memory.
2. The m_clients walk proceeds even from NULL (+0x58=0) without faulting.
3. The walk faults on arbitrary VAs (short-circuited on NULL-derived chains).
4. The only dereferenceable m_clients value is one the engine itself wrote in this process.
5. Refcount-only forge is a free, crash-safe oracle - 100% survivable.

### 4. Canvas m_stateStack Forge is Dead on Both Firmwares

14.00 (lunarshe11): "no crash, len=0" - ArrayBuffer(7424) did not land on freed m_stateStack.
14.10 (vincenzoiacovone): "nothing payload-shaped ever becomes readable through the pending alias."

Both firmwares agree: The stateStack reclaim is a dead end. Neither side needs to re-test it.

### 5. The Read-Only Stale Pointer Strategy is the New Direction

vincenzoiacovone (14.10): "What we're pursuing instead is a different route through the same alias:
rather than filling the freed slot with a payload, we keep it empty and read through the stale field
while the window is open - the freed context's internal pointer is still resident, and reading
through it doesn't depend on anything of ours taking the slot. Read the right field and you're
reading engine memory with zero bytes written anywhere."

lunarshe11 (14.00): "The 'read-only stale pointer' strategy is brilliant. It completely sidesteps
the libpas allocation lottery. If you can read from the freed context's internal pointer while the
window is open, that's the cleanest ASLR/R-chain path possible."

### 6. p68 is the Invariant; p58 is the Boot-Varying One

p68 band (all three benches):
- 14.00 (lunarshe11): 0x1000_7d-e (e.g., 0x10007e9040, 0x10007e9660)
- 14.10 (cobrajet): 0x1000_7dd-7e7 (30/30 inside one ~0x8000 region)
- 14.10 (vincenzo): 0x100016-0x1000eb (13/13 outside 0x7d-7e on their form)

p58: Thrashes per-boot/per-process on all benches. No cross-bench portability.

Consequence: A boot-reproducible constant is only usable after it has been leaked once on that
console+form. The leak is not bypassable even where the value is stable.

### 7. The `+0x4000` Page-Stride is Deterministic Across Respawns

cobrajet302gt (14.10): p58 values cycle through a two-value set {0x8a0010, 0x8a4010, 0x8a8010 page-stride}.
lunarshe11 (14.00) confirmed: The +0x4000 stride transfers to 14.00.

### 8. The Network TTF Wall

lunarshe11 (14.00): 0/55 hits with a network TTF. async font loading prevented sync getter free.
cobrajet302gt (14.10): "async TTF caching preventing the sync getter free is why our ttf-based arms
were 0/34 too."

Resolution: Switch to `local(Helvetica)` + `local(Arial)` with `unicodeRange` split.

## Implications for Our 14.10 Chain

### p574 (FontFace vtable forge behavior)

1. Forge +0x58 to a foreign VA -> SEGV.
2. Forge +0x58 to NULL -> survives (short-circuited).
3. Forge +0x58 to the leaked +0x58 value -> survives (p564 already proved this).
4. Forge +0x58 to the ArrayBuffer data address -> unknown (not yet tested).

The m_clients walk is short-circuited on NULL-derived chains. The engine checks if the pointer
is in the WebProcess heap range. If it is, the walk proceeds. If it isn't, it faults.

### p575 (Combined FontFace leak + Canvas write primitive)

The community's Canvas m_stateStack forge is dead, but our p553 Canvas UAF write primitive is
separate. The combined chain should pivot to the read-only stale pointer strategy:
- Keep the freed Canvas context slot empty.
- Read through the stale field while the window is open.
- "Read the right field and you're reading engine memory with zero bytes written anywhere."

### Next Steps

1. Run p574 on PS5 14.10 - FontFace vtable forge behavior analysis.
2. Run p575 on PS5 14.10 - Combined FontFace leak + Canvas write primitive.
3. Pivot to the read-only stale pointer strategy if p575's m_stateStack forge fails.
4. Forge the m_clients pointer using the read-only stale pointer strategy.
5. Build the chain on +0x68, treat +0x58 as the boot-varying one.
