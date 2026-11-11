# External Research Audit — 2026-11-11

## 1. V674 Contradiction (pastawithpesto APNG claim)

**What was checked:** pastawithpesto's V674 claimed "1651 heap pointers" leaked via APNG decoder overread on PS5. Our probe p657 tested 7 malformed APNG variants on 14.10.

**What was found:**
- `docs/ATTACK_PRIORITY_REFERENCE.md:129` — ALL 7 variants returned expected red pixels or zeros. Zero heap residue, zero leaked pointers.
- `results/phase13_webkit/v674_canvas_api_info_leak_20261029.txt` — on-device capture confirms API-level reads return zeros.
- `docs/WEBKIT_FINDINGS.md` — "API-level canvas reads all return zeros (V674)"
- `docs/FONTFACE_HEAP_LEAK_TECHNIQUE.md` documents a separate contradiction: pastawithpesto classified FontFace UAF as "DoS-only" (tested write side), but our team found the read side leaks heap pointers. This is the reverse of V674 — here pastawithpesto was too pessimistic.

**Verdict: CONSISTENT** — Internal evidence consistently contradicts V674's "1651 heap pointers" claim on 14.10. The probe, capture, and three independent docs all agree. This may be a firmware-version difference (their target vs 14.10) or methodology issue on their end. Our FontFace finding correctly extends beyond their DoS-only classification.

---

## 2. WebProcess RVA Dispute

**What was checked:** p807 claimed RVA = `0x724DB28` and "SOLVED" status. Corrected per cobrajet302gt's PR #243/#244 review (2026-11-10).

**What was found:**
- `docs/PROBE_INDEX.md:358` — p807 entry now reads "RVA [I], SOLVED banner retracted". The committed corpus has zero `P807-BASE=`/`RVA=`/`SCAN`/`HIT` beacons. The only p807 data is 19 `NOLEAK` rows inside the p804 capture.
- `docs/EXPLOITATION_STATUS.md` — retraction applied in PR #246 cherry-pick (2026-11-11).
- `docs/CAPABILITY_GRAPH.md:203` — Row 17 grades RVA as **I** with "OVERCLAIM RETRACTED".
- `docs/CHANGELOG.md:24` — "p807 'text base SOLVED' overclaim retracted"
- `docs/AUTONOMOUS_RESEARCH_STATE.md:33` — "WebKit info leak (text base) | BLOCKED"

Both terminal scan branches in p807 bypass the probe's own ELF-magic discriminator, which would be required to verify an actual base address. The `0x724DB28` value is plausible (VP mod 0x4000 = 0x1B28 consistently across 17 measurements) but unverified.

**Verdict: CONSISTENT** — All documentation now correctly reflects [I] grade. The retraction was applied across 12 files in the PR #246 cherry-pick. No residual "SOLVED" claims found for RVA.

---

## 3. Kernel Address Consistency

**What was checked:** STATE.md kernel addresses against all docs, results, and captures.

| Address | Claimed In | Corroborated By |
|---------|-----------|-----------------|
| kernel_text `0xFFFFFFFFD5000000` | STATE.md (probe 1199b, 2026-11-10) | INDEX.md:3462-3463 (two runs), ALL_RESULTS.md:4163+4686 ([T340] marker), results/1331a (two captures), CAPABILITY_GRAPH.md:42, hypotheses.json |
| kernel_data `0xFFFFFFFFD5CE0000` | STATE.md (TEXT + 0xCE0000, SDK v0.45) | INDEX.md:3462, CAPABILITY_GRAPH.md:124 |
| allproc `0xFFFFFFFFD85B9EA0` | STATE.md | INDEX.md:3462, CAPABILITY_GRAPH.md:124 |
| security_flags `0xFFFFFFFFD6A84064` | STATE.md | CAPABILITY_GRAPH.md:124 only (SDK-derived, not independently measured) |
| rootvnode `0xFFFFFFFFD8E3B510` | STATE.md | CAPABILITY_GRAPH.md:124 only (SDK-derived, not independently measured) |

The kernel_text base is well-corroborated: measured in two independent 1199b runs, confirmed in two 1331a captures, and the "[T340]" marker in ALL_RESULTS.md provides independent capture evidence. The slide value `+0x55000000` is arithmetically correct (`0xD5000000 - 0x80000000 = 0x55000000`).

The kernel_data, allproc values appear in INDEX.md from the same measurement session.

**security_flags and rootvnode** are SDK-derived (kernel_data + constant offset), not independently measured on device. CAPABILITY_GRAPH correctly notes "Derived offsets: 1/25 confirmed (constant drain)".

**Caveat:** All addresses are boot-specific. STATE.md correctly notes "all kernel addresses valid this boot only; if rebooted re-measure with fault oracle first."

**Verdict: CONSISTENT** — Measured addresses corroborated across 4+ independent sources. SDK-derived addresses correctly flagged as unverified.

---

## 4. Evidence Grade Consistency

**What was checked:** CAPABILITY_GRAPH.md evidence quality table (17 rows) against PROBE_INDEX.md, FINDINGS docs, and INDEX.md.

| Cap# | Graph Grade | Cross-ref Grade | Match? | Notes |
|------|------------|----------------|--------|-------|
| 1 | M | — | ✓ | Every probe proves userland exec |
| 2 | M | INDEX.md M on 1199b rows | ✓ | |
| 3 | M | DEAD_ENDS.md documents 262a/263a limitation | ✓ | Graph correctly notes "GPU bus space" caveat |
| 4 | M | PROBE_INDEX p691 notes 39 modules | ✓ | |
| 5 | M | INDEX.md M grades on 271g/272a | ✓ | |
| 6 | M | INDEX.md M grades on 156c/156d | ✓ | |
| 7 | S | No M-grade run in INDEX.md | ✓ | Correctly S — source-read only, not device-confirmed |
| 8 | M | INDEX.md M on 129b | ✓ | |
| 9 | M | INDEX.md M on 48a-50d | ✓ | Graph notes "DEAD as attack vector" |
| 10 | M | PROBE_INDEX p553 OK | ✓ | |
| 11 | M (VP) / I (RVA) | PROBE_INDEX p691 OK, p807 retracted | ✓ | Split grade correctly reflects evidence |
| 12 | M | PROBE_INDEX p580/p581 | ✓ | |
| 13 | M | PROBE_INDEX p656 | ✓ | "Write is BLIND" caveat matches |
| 14 | M | PROBE_INDEX p599 | ✓ | |
| 15 | M/S | STATE.md measured + SDK derived | ✓ | Split grade correct |
| 16 | M | INDEX.md M on 417/421 | ✓ | |
| 17 | **I** | PROBE_INDEX p807 retracted | ✓ | Correctly downgraded |

**Verdict: CONSISTENT** — All 17 capability grades match their evidence. No mismatches found. The M/I split on capability 11 and the M/S split on capability 15 correctly reflect the mixed evidence levels.

---

## Summary

| Audit Item | Verdict | Action Needed |
|-----------|---------|---------------|
| V674 (pastawithpesto APNG) | CONSISTENT | None — contradiction is documented |
| WebProcess RVA (p807) | CONSISTENT | None — retraction applied across all docs |
| Kernel addresses | CONSISTENT | None — boot-specific caveat in place |
| Evidence grades | CONSISTENT | None — all 17 match cross-references |

**Overall evidence integrity: GOOD.** No contradictions, no stale overclaims, no grade mismatches found. The p807 retraction (the most significant correction this session) was applied consistently across 12 files. SDK-derived kernel offsets are correctly flagged as unverified.
