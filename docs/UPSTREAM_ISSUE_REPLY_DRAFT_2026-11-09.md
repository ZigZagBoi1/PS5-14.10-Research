# Posted reply — issue #216 (ZigZagBoi1/PS5-14.10-Research), cross-ref #184
# Status: this file mirrors the comment posted to #216 on 2026-11-09 (items
# 1-8). The #184 comment carries items 1-4 + the v918 row (see the cross-post
# block at the end).

---

@cobrajet302gt @4TheDoctor — closing our side of the 14.22 lane for this era and answering your open asks in board order. Grades: [S] = source/file:line re-verified today; [M] = attributed device rows on our 14.22 bench, logs cited; [I] = model. Bench cold after this post.

**1. L6/L7 adopted; our v911 sweep conforms to the return channel — and we are self-reporting that it proves less than its size suggests. [M]**

Our v911 is the pre-registered two-arm differential instrumented per your decode: `V911-SURV` fires on ANY returned forge read, value recorded bit-exact (Float64Array round-trip, no arithmetic — DAZ-safe), so zero SURV = zero return-channel events, not a value-channel miss. The forge sets {m_buffer @+112, cap @+120, size @+124}; the read consumes exactly your touch set {+112, +124, T+0x30}. Arm B (size=64/cap=64 → T+63×448+0x30 ≈ T+27.6KB) is gated on an arm-A survive and therefore never fired — per the crash/crash-adds-no-information pre-registration.

Grid closed end-to-end on 14.22: bands 0–5, ~6300 targets (3072 @4MB 1G–4G; 2048 @8MB 4G–32G; 17 @2MB wp14; 1024 @256KB stack; 129 @256KB SceLibcHeap±16M; 9 loaderEboot), zero SURV / PAIR / RECON / DONE, close-out timestamps 10:13:40 → 10:53:01, terminal loop after band 5 (probe defect, recorded, not patched). Result row: `results/phase13_webkit/v911_full_grid_close_14_22_20261109.txt`.

**2. Self-reported confound — the grid's zero is attribution-blind. [I → resolved mechanically by item 3]**

v905 already retired the +112 forge "until a positive control exists"; v911 re-ran it at grid scale anyway. The grid argues against itself: band 3 (stack) samples guaranteed-mapped pages, so a landing forge must return there — zero SURV across 1024 stack targets is inconsistent with a working forge and consistent with all ~6300 reads dying at null+0x30 on an unconsumed/zeroed ctx chunk. We grade our own grid as **attribution-blind** — same grade you assigned the 21-survive corpus — and retract any implication that it settles regions. Combined cross-firmware scoreboard (~5400 yours + ~6300 ours): zero attributed. (Your L10 re-pricing of the stack-band argument is accepted; the self-regrade below stands on the stronger mechanical argument of item 3.)

**3. The positive control: corpse route refuted → forge written but NOT consumed → lane closed. [M]**

Three device steps, each with logs:

- **v914 (corpse route) — refuted by design.** 4 cycles, zero variance: `lw1=1014` after refs-dropped + GC churn and no change after a 2160-AB ladder prove the JS wrapper strong-refs the impl — the read handle and the free are mutually exclusive; no corpse is producible outside the trigger free. Rows banked: zero-at-free on 14.22 is trigger-path-specific (the GC-path dangle produces no corpse at all), and our v904 consumption claim is withdrawn (v904's own file says "crash before READ" — AB-fill-as-m_buffer consumption was never proven).
- **v915 run-1/run-2 (forge control inside the trigger construction).** Run-1 is void by disclosure: our default T constant was non-canonical (0x7fffffffffffe000, 16-digit; the BOOT beacon proves it) — matrix zero. One board-grade observation stands [M]: **async image-GET PRE beacons are lost in the crash race** (2 of 3 READ-PREs never reached the server; gaps match the crash+reload cadence); we propose as a channel-law refinement that PRE markers are position-proof only when sync-XHR, which is what our bench now does. Run-2 with T = 0x00007fffffffc000 (mapped stack page, L10-conformant — see item 8) and sync PREs on every attempt: fill died at the read (expected, non-discriminating), forge died at the read 3/3 with position-proof PREs. T mapped ⇒ a consumed read cannot crash ⇒ **the forge cell at +112 is written but never consumed**.
- **v916 (cell-everywhere) — the lane closes.** A valid Vector cell {T, cap=1, size=1} written at every 16-byte position of the AB (48 at()-safe cells), both 8-byte alignments, then a 9-size AB ladder (512..1024 step 64), 200 ABs each: 11 reads, 11 deaths at the read site (sync position-proof), zero returns. **No attacker cell in AB data is ever consumed by the read path after the trigger free.** Your row-2 pre-registration (b) is the verdict we publish: the v904-construction landing/consumption is null on 14.22 — not offsets, not regions.

**4. Your open era-posture cell: we cannot close it either, and we regrade v909. [M, correction]**

Our "zero-at-free 14.22" row (v909: 6/6 crashes at the first read, no reclaim) is observer-grade, not byte-grade — same class as your p641 v2 — and we withdraw the byte-grade wording our 11-06 synthesis gave it. With L8's retirement of the 14.10 side, the FW-delta pin in our CHANGELOG is withdrawn as well: canvas-class null@+112 after free is two-bench device-grade on 14.10 and observer-grade on 14.22 — no FW delta claimed on that cell. The face-class 192B stays byte-open on both benches from our side too: on 14.22 the FontFace lane is doubly dead (reclaim of the freed CSSFontFace by 13 AB classes: 38/38 no-reclaim [v913]; and the AB(192)-carrier route kills the engine's own post-free walk before any write [v912]). No byte-grade unreclaimed readout exists on either bench, either class — your open decider stands.

**5. Luac0re/ps2emu dump (lf6-5):** nothing to add to your identification — kernel stage ≤ 12.00, upstream frozen pre-14.22, runtime-derived rows are per-boot. Adopting your page-form caveat into our docs: WebProcess heap physics run on 4 KiB pages; emu PAGE_SIZE=0x4000 is a different form; +0x4000 heap strides are allocator size-class granularity, never 16 KiB pages.

**6. Cross-bench port — WITHDRAWN per your point 4.**

Our original offer (run v911 on 14.10 for a firmware contrast) is withdrawn: your p647-p655 family shows the same sweep construction never observed landing on 14.10 either, so a v911 null there separates nothing. On our bench the p635-class equivalent IS the same-type canvas-alias construction (landing + consumption proven by v904/v651 on 14.22 — the stale wrapper reads and writes the live reclaiming context every load), and the AB forge into the freed chunk is dead per item 3's v916 row. The relocation verdict your pre-registration (b) anticipated is therefore already published with device rows.

**7. Request: upstream's verbatim V674 APNG probe.**

With v916 closing the ctx-chunk forge lane, our 14.22 scoreboard is: live = the same-type canvas alias with full bidirectional R/W and the v651 state channels; dead = every forge and leak lane we and the board have tried. The alias is control-channel-only (p629) and pointers cannot cross the value channel (L6), so **we have no local attribution instrument on 14.22**.

The only confirmed address-leak instrument on the board is your APNG overread — V674, 1651 heap pointers, CONFIRMED on your 14.10 bench. We verified your public tree at 92780e1 does not contain it (no file matching v674/png/overread in the clone or its history). Our reconstructions now span three eras with zero foreign bytes: v674b (10-29, 14.10: 7 build variants), p610 (11-04: row truncation + palette OOB — the decoder reads OOB but lands on zeroed memory), and today's v918 on 14.22 (the untried classes: dispose_op=PREVIOUS first-frame / small-rect restore / growing chain, fcTL rect fully outside the image, bogus acTL num_frames, fdAT sequence gaps — all decoded, zero crashes, zero pointer candidates; two decoder-behavior rows banked: mixed-rect APNGs silently drop the final frame, and an all-PREVIOUS chain yields an all-zero output). Two asks, either settles attribution for us:

1. The verbatim `v674` probe file (or a pointer to wherever it lives), to run byte-for-byte on 14.22 — the engine string is unchanged (605.1.15/17.0), so the decoder bug is plausibly unpatched.
2. Failing that, the structural minimum of the overread (the PNG structure and the read path that produces the 1651-pointer window), and we rebuild it locally (v918b) and report rows in your format.

**8. L9/L10 conformance — no re-run needed; run-2 and v916 keep full grade.**

- L9 (wrapper→impl is an owning Ref, JSDOMWrapper.h:73-88): accepted — refs-dropped + GC churn can never produce a JS-reachable corpse on any firmware. Our v914 finding is a port fact, not a 14.22 delta, and all corpse routes not riding a trigger-path free are retired bench-wide.
- L10 (the deref lands at T+0x30; USRSTACK = 0x7ffffffff000 under VM_MAXUSER_ADDRESS_LA48): our run-2 and v916 used T = 0x7fffffffc000 — 3 pages below USRSTACK, T+0x30 = 0x7fffffffc030 inside the initial-stack region, not flush-to-ceiling. That conforms to your fix (ii) (T ≥ 2 pages inside the candidate top), so pre-registration (b) applies, not (c): the row-2 verdict "v904-construction forge written but NOT consumed" keeps its grade, and v916's lane closure inherits it.
- Fill arm: retired from all future probes on our bench (your point 3 formalizes our run-1 correction — it carries no discriminating power).
- Band-3 re-pricing accepted: the self-regrade stands on the v916 mechanical argument; the stack-band argument is demoted to supporting color.

v917 (region grid re-run under a positive control) stays blocked until an anchor exists; everything above is banked and cold.

---

# Cross-post block for #184 (pastawithpesto)

Same lane, our bench. Items 1-4 of the #216 reply apply verbatim (the 14.22 grid close, the self-regrade, the control arc, the v909 regrade and FW-delta withdrawal); items 5-8 are board-specific to #216. Added for you: our v913 row (zero reclaim of the freed CSSFontFace across 13 AB classes, 38 trials, corrected p563 form) confirms your Pro-finding on our 14.22 base retail — the pair oracle is unavailable on both — and today's v918 row closes the APNG reconstruction lane on our side (three eras, zero foreign bytes). Full text: `docs/UPSTREAM_ISSUE_REPLY_DRAFT_2026-11-09.md` (or issue #216, this reply).
