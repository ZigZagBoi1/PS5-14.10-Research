# PR #240 (p691/p710 vtable-pointer leak) — independent evidence review

Date: 2026-11-10. Reviewer lane: offline desk review (beacon logs + committed sources + arithmetic only;
no console). Method matches the PR #236 receipt-checks: every claimed number re-derived from the
committed artifacts, and claims separated into beacon-observed vs self-reported.

## Verdict summary

The core result — a 4-read FontFace UAF walk chain leaking a CSSFontFaceSet vtable pointer (VP)
and 9 vtable slots from the WebProcess code segment — is **supported by the committed beacon log
for one boot** (run UHOGII, 2026-11-09 23:54 UTC-3). All spot-checked arithmetic closes.
The p710 .text/.rodata boundary measurement is internally consistent and its arithmetic checks out.

However, the PR as it stands **cannot be merged** and parts of its headline are overstated:

- The PR deletes 100+ files that landed on master after its branch point (upstream's p704-p802
  info-leak queue, tools/jailbreak-host, docs/DEBUG_SETTINGS_CHAIN_14_10.md,
  docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md, docs/NEW_CVE_CANDIDATES_2026_11.md and
  others). Merging would silently wipe the entire autonomous WebKit queue. GitHub already reports
  the PR as CONFLICTING.
- CLAUDE.md regressions: the branch reverts the upstream `DFG OFF per cmake` correction back to
  "DFG tier confirmed", and reverts the issue #178 corrections (rc=2 "BOUNDED, not permanent"
  back to "PERMANENT"; destructor "reachable via GC after unpin" back to "unreachable").
- Claim-vs-evidence mismatches: "0xB28 across 5 boots" (p691) is 1 boot in committed data;
  "7 boots" (p710) is log-only — the cited beacon log
  (`beacons_02263713-58d7-4a65-88a6-cb6209c45aeb.log`, 12704 lines) is NOT committed anywhere
  in the branch; 7 of the 43 committed beacon_logs files in the PR are 0 bytes
  (beacons_20261109_042804/042813/042816/042854/042859/043205/043208).
- Reviewer follow-ups already requested on the PR (cobrajet302gt's p804 delta-invariance and
  Arm-1 s2/s4 byte-compare tests) have committed probes but no committed runs.

## What was verified (closes arithmetic)

p691 run UHOGII — `results/phase13_webkit/p691_walk_forge_fixed_20261109_235425.log` (947 lines,
host 192.168.1.37, the second contributing bench) carries the complete beacon chain in order:

  P691-L1-0x10008a5ff0 → P691-L2-0x1000164140 → FORGED-1 → FAMILY-OK → ADD-OK →
  SELF-0x1000384480 → IHT-ok-160 → VTAB-0x1000384100-j0 → W3-MID →
  WALK-IM=0x10009e0140,FO=0x1000160770,VP=0x80f4b9b28 → WALK-ok=true →
  VT-s0=0x80dda8fb0,s1=0x80dda8fe0,s2=0x80c26d750 → VT-s3..s5 → VT-s6..s8 (s8=0x0)

- The committed probe source (`p691-walk-forge-fixed.html`) can emit every beacon stage observed
  in the log (IHT/W2/W3/W3-MID/W4/VT): no provenance gap, unlike p682 v4-v12. The VP threshold
  fix is present at line 434 (`if(VP>0x100000000n)`), matching the PR description's bug-fix claim.
- Inter-slot deltas (boot 5) recompute exactly as the (corrected) values:
  s0 0x1710B78, s1 0x1710B48, s2 0x324C3D8, s3 0x1710478, s6 0x1ABA728, s7 0x1710318.
- s2 = s4 = s5 (three slots one implementation) is visible in the beacon lines themselves.
- s1 = s0 + 0x30: 0x80dda8fe0 - 0x80dda8fb0 = 0x30. Correct.
- Echo check: VP and the slot values are not little-endian encodings of any planted marker
  (no 31337.31337/1.0/10.0-style constants are planted in the walk path; the only 0x4141414141414141
  sentinel sits in the later lay-forge step, gated on ?ivp=1 which defaults 0). The p682
  echo-verdict failure mode does not apply here.

p710 boundary run — `results/phase13_webkit/p710_base_discovery_20261110_013236.txt`:

- 0x808D95B28 - 0x76DB28 = 0x808628000, page-aligned (low 14 bits zero). Consistent.
- boundary - s2 = 0x808628000 - 0x805B49750 = 0x2ADE8B0 = 42.87 MB. Consistent.
- VP - s2 = 0x324C3D8, matching the p691 boot-5 slot delta — cross-run coherence.
- RVA & 0x3FFF = 0x1B28 follows from VP & 0x3FFF = 0x1B28 since the rodata-start is page-aligned.
- The scan-log section lists 15 boots with per-boot VP values; those are txt-log self-report
  (no beacon lines committed for any of them).

## Overstated or unverifiable claims

1. "VP ends in 0xB28 across 5 boots" / "7 boots" (PR body, CLAUDE.md row, PROBE_INDEX row).
   Committed evidence carries exactly ONE VP value (0x80f4b9b28, run UHOGII). The other four
   p691 VPs and all fifteen p710 VPs appear only in the result .txt files. The CLAUDE.md row's
   own "1 boot confirmed in committed beacon data" phrasing is the accurate one — but the
   PROBE_INDEX row then says "0xB28 across 5 boots" in its result column and the ledger row in
   results/INDEX.md repeats "(0xB28 across 5 boots)". Those should be downgraded to n=1 with the
   rest marked [I] pending the missing beacon log.
2. "HARD BLOCKER #1 is solved" (result txt) — overstated twice over: the RVA is undetermined
   (a link-time fact; the fork is WebKit 616 internally per the UA-string correction, so a
   605.1.15 source RVA cannot simply be assumed), and VP is single-boot. The PR body's own
   phrasing ("pending static RVA determination") is the correct grade.
3. "HARD BLOCKER #5 also solved" (SELF via FO+0x10 back-pointer) — beacon-observed for the one
   run (SELF-0x1000384480 + WALK-h3 line in the .txt timeline; the log carries
   P691-SELF-0x1000384480). Single-run; should be graded like the rest.
4. The empty beacon_logs files: beacons_20261109_042804 through 043208 (7 files, 0 bytes each).
   Either truncated captures or placeholders; as committed they carry no evidence and should be
   dropped or completed.
5. The p691 result .txt "TIMELINE" lists WALK-h2/h3/h4 lines (23:54:29.671-29.997) that do NOT
   appear in the committed .log — the log jumps WALK-IM/FO/VP (29.630) → WALK-ok (30.068) → VT
   lines. Minor, but the txt's per-step h2/h3/h4 contents are log-only.

## Regression list (must be fixed before merge)

1. Restore all master-side files the branch deletes: the p704-p802 probe queue
   (probes/phase13_webkit/p7*-*.html, p8*-*.html), tools/jailbreak-host/ (whole tree),
   docs/DEBUG_SETTINGS_CHAIN_14_10.md, docs/HARDWARE_SESSION_RUNBOOK_13_60.md,
   docs/NEW_CVE_CANDIDATES_2026_11.md, docs/VP_SLOT_DELTAS_CORRECTED.md,
   docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md, probes/phase14_final_push/1400a_auxv_procfs.lua,
   probes/phase13_webkit/p692-auxv-base-probe.html, p693-delta-invariance.html
   (the 3562c57a "rename colliding IDs" commit resolved the collision by deleting the master's
   files and keeping its own — wrong direction; the master files were there first and the
   incoming duplicates should have been renamed instead).
2. CLAUDE.md: keep upstream's "LLInt + baseline only (DFG OFF)" row (fa834434, cobrajet302gt
   issue #181 correction) and the issue #178 rc=2/destructor corrections; add the p691/p710 rows
   on top rather than reverting to the branch-point text.
3. PROBE_INDEX/ledger phrasing: "1 boot confirmed in committed beacon data" for VP; mark the
   4 extra p691 boots and all p710 boots [I] until beacons_02263713-....log is committed.
4. probe-ID bookkeeping: the PR adds p685-fontface-walk-dispatch.html and p686-fontface-impl-bisect.html
   while master already has p685-range-selection-uaf.html and p686-svg-animation-uaf.html —
   two NEW collisions beyond the p692/p693 pair, not resolved by 3562c57a.
5. serve.py + tools/browser_runner/server.log (0-byte) changes should be split or justified.

## Suggested acceptance path

- Rebase/merge master into the branch (resolves CONFLICTING), restoring everything in
  regression item 1; rename the PR's duplicate p685/p686/p692/p693 files (e.g. -walk suffixes).
- Commit the p710 beacon log or downgrade p710 to "log-only [I]".
- Run and commit p804 (delta invariance across a fresh slide + s2/s4 XO byte-compare): one boot
  of that output upgrades VP from n=1 to cross-slide-confirmed and is the cheapest possible
  corroboration now that the walk chain is repeatable.
- Keep the CLAUDE.md hard-blocker text at "VP leaked, RVA undetermined, base not yet computable".

None of this contradicts the headline: the walk chain working even once, with a code-segment
pointer recovered and arithmetic this clean, is the strongest WebKit result the repo has. The
fixes above are about keeping the evidence ledger honest, not about disputing the result.
