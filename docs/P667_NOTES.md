# P667 NOTES — keep-spray-alive (2026-11-11 20:45)

## Device findings from p666 (logs `beacons_d8faf68b`, `beacons_ec2486dc`)

**#sp24 (free + 24-lane spray, lanes dropped each round):**
18 STARTs; 9 loads beaconed R0 — **all 9 died inside the R1 window** (only
R0+R0LATE ever escaped; the R1 analysis beacon never fired once). R0 always
`hit=2`, T=`0x10001cbe90` first-generation ×8, then a drifted
`0x10008c87e0` after a WebProcess restart, W in the usual
`0x10007e6xxx-0x10007e7xxx` band, rc=101, opc=0, st82=0, dump static.

**#nosp (free, NO spray at all):**
8/8 beaconed runs survived **R0 and R1 complete** — `R0 gf=0`, `R0LATE`,
`R1 gf=1`, `R1LATE`, all alive — then **died entering R2's window** (last
beacon R1LATE, next event is the user's reload START ~2.3 s later). One extra
load (20:43:33) died pre-R0; a later rapid-reload storm (20:43:34-20:43:59,
~12 STARTs with no beacons) matches the known die-before-R0 phenotype, not a
new mechanism.

## Conclusions (verified against both logs)

1. **Stale engine writes into freed memory are harmless** for at least two
   rounds (nosp: freed face chunk never reclaimed by us, page fully alive
   through R1LATE). A write into a freed-but-unreused 192B chunk poisons
   nothing by itself.
2. **The spray accelerates death by exactly one round** (sp24: death at R1
   window; nosp: death at R2 window). The one behavioral difference the spray
   introduces — beyond the reclaim itself — is that the NEXT round's getter
   executes `spray = []`, dropping the previous round's lanes while the engine
   still holds a reference into old lane 2's backing store (rc=101 every
   round). Freed backing store + dangling engine ref, then the next round's
   allocations reuse it ⇒ lethal corruption of a live object at the next
   engine write.
3. Faces were already protected (`__facesAlive`); **buffers were not**. p667
   protects exactly the buffers.

## p667 hypothesis table (`probes/phase13_webkit/p667-keepspray.html`)

| Outcome | Verdict | Next step |
|---|---|---|
| Survives all 8 rounds, hits each round (T drift dataset R0-R7) | Keep-alive law confirmed: freed backing store was the killer; multi-round leak unlocked in one WebProcess | p668: 8+ rounds of T/lane/rc telemetry per load — the groom-distance dataset p663 wanted; then forge p669 (controlled table) on top |
| Survives but R1+ = MISS (parity law persists) | Keep-alive works; miss-rounds structural (allocation parity), not fatal by themselves | Instrument per-lane marker ordering across kept rounds to map the freelist sequence |
| Dies at R2 anyway (same as nosp) | Freed-buffer hypothesis REFUTED for the R2 death; killer is engine-side accumulation (stale ref count grows per round regardless of our buffers) | Audit which engine-side per-round object accumulates (FontFaceSet? CSSFontSelector client set?) — beacon per-round heap-pressure proxy |
| Dies at R1 (sp24 phenotype returns) | Keep-alive insufficient; the spray itself (fresh reclaim each round into NEW lanes) still lethal | Bisect: #sp12 (halve pressure) vs one-shot spray (spray only on round 0) |

## Decision tree

```
Run / (=#sp24 keep-alive) x10 loads:
├─ ALIVE end-r8 (SUMMARY beacon present)
│    ├─ R-lines all hit ....... keep-alive law CONFIRMED -> p668 multi-round
│    │                          telemetry (groom-distance dataset unlocked)
│    └─ R1+ MISS .............. law holds for survival, parity persists ->
│                               map freelist order via kept-lane markers
├─ death at R2 window (R1LATE last beacon)
│    └─ buffers were NOT the killer -> engine-side accumulation; audit
│       per-round engine refs (client set growth) before more probes
└─ death at R1 window (R0LATE last beacon)
     └─ fresh-reclaim-per-round is itself lethal -> #sp12 and one-shot-spray
        variants to decouple reclaim count from round count
```

## Run protocol

1. Restart serve.py (routes are read at import). `/` and `/p667` serve
   p667-keepspray.html.
2. 10 loads of `https://192.168.50.45/` (default #sp24, ROUNDS=8 — wait ≥32 s
   per load before reloading: 8 × 3.75 s ≈ 30 s + summary).
3. Optional: 6 loads of `https://192.168.50.45/#sp12`.
4. Grep the new beacon log for: `P667-START`, `R0 hit` (T anchor), `R1`
   (beacon presence = survival past r1 — the datum sp24 never delivered),
   `DUMP2`/`changed=YES` (would be new late-write signal), `SUMMARY`/`ALIVE
   end-r8` (full survival), and last-beacon-before-silence per load.
