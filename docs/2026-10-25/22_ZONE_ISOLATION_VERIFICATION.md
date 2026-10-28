# Verification Report: "Sony Per-Type Zone Isolation" Claim

> **Date:** 2026-10-25 Session 3 — Verification Pass
> **Scope:** Is the claim in 14_ZONE_ISOLATION_PROOF.md that "cross-subsystem spray is structurally impossible" actually proven by the evidence cited?
> **Verdict:** OVERSTATED. The conclusion is plausible but not proven. An alternative explanation — insufficient spray volume — has not been ruled out.

---

## 1. Probe-by-Probe Verification

### Results that match the cited claims:

| Probe | Cited Claim | Actual Output | Verified? |
|-------|-------------|---------------|-----------|
| **65o** | "kqueue + namedobj, 200+200, zero anomalies" | 200 kqueues + 200 namedobjs per iter × 20 iters. smark=0x54545454 (sentinel unchanged). 31 total doubles confirmed. | **YES** — but detection was via sentinel marker only, not raw memory readback |
| **65v** | "EVF + namedobj + AIO, 128+256, zero EVF corruption" | Spray=128 AIO, "namedobj created: 0" (section B failed), EVF sections D/E SKIPPED. Only AIO self-spray ran. | **PARTIALLY** — namedobj spray FAILED, EVF sections SKIPPED. Only AIO self-spray of 128 was tested. The "128+256" count is wrong. |
| **65w** | "namedobj 24/31-char, 64+32+64, zero cross-corruption" | 16+16 namedobj created, 32+64 AIO. no_del=64/64 (all deleted cleanly). | **YES** — but max 80 namedobj total |
| **66c** | "socketpair + setsockopt + AIO, 64+64+32, zero unusual status" | **"only got 0 IDs, skip" × 5 trials.** The race never produced doubles. No spray occurred at all. | **NO — PROBE DID NOT RUN.** Zero IDs means the double-free setup failed entirely. This is NOT evidence of zone isolation. |
| **66e** | "EVF + namedobj + socketpair + AIO, 32+32+32+16, zero anomalies" | 32 evf + 32 namedobj + 32 sockets + 16 AIO. 12 doubles. 0 anomalies. | **YES** — but only 32 of each type |
| **66f** | "Massive AIO self-spray, 256, zero delete errors" | 256 AIO spray, 3 trials, all 256 deleted OK each time. 36-37 doubles per trial. | **YES** — but this is AIO self-spray, not cross-subsystem. It tests same-zone reclaim detection, not zone isolation. |
| **67d** | "AIO self-spray + 663 readback, 128+128, status unchanged" | 128 spray, 64/64 overlap pairs. 663 returns 0x00010003 before AND after reclaim. Wide read: only first dword written, rest sentinel. | **YES** — confirms 663 readback is opaque. But this is about the readback interface, not zone isolation. |
| **67e** | "AIO self-spray, status unchanged" | 128 spray, 64/64 overlap. 624 delta=0 for both delete and reclaim. 663=0x00010003 unchanged after reclaim. | **YES** — same conclusion as 67d. Readback opacity, not zone isolation. |
| **67f** | "namedobj cross-zone, 32, no overlap" | namedobj_lookup BROKEN (`h=0xFFFFFFFFFFFFFFFF`). **Probe aborted in section A.** | **NO — PROBE DID NOT COMPLETE.** Namedobj lookup was broken, so the cross-zone test was never executed. |
| **67k** | "CPU-pinned AIO spray, 80+80, all clean" | 80 spray per CPU. 28 doubles across 8 iters. All deletes OK. Socketpair AIO data flow confirmed. | **YES** — but only 80 objects per CPU |
| **67l** | "socketpair AIO dual spray, 24+24, zero sentinel changes" | 24+24 socketpairs. AIO data flow clean (no cross-contamination). | **YES** — but tests data cross-contamination, not zone reclaim. Only 48 objects total. |

### Summary: Of 10 cited probes:
- **6 verified** (65o, 65w, 66e, 66f, 67k, 67l) — results match claims
- **2 did not run** (66c got zero IDs; 67f aborted with broken namedobj lookup)
- **1 partially wrong** (65v: namedobj created 0, EVF sections skipped; count "128+256" is inaccurate)
- **2 prove readback opacity, not zone isolation** (67d, 67e)

---

## 2. Spray Volume Analysis — The Critical Gap

**Maximum spray counts per object type across ALL probes:**

| Object Type | Max Sprayed | Probe | Needed to Drain Per-CPU Cache |
|-------------|------------|-------|-------------------------------|
| kqueue | 200 | 65o | 4096-16384 (per HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md) |
| namedobj | 64 | 65w | 4096-16384 |
| EVF | 32 | 66e | 4096-16384 |
| socketpair | 64 | 66c (but probe failed) | 4096-16384 |
| setsockopt | 64 | 66c (but probe failed) | 4096-16384 |
| AIO self | 256 | 66f | 4096-16384 |

**No probe sprayed more than 256 objects of any type.** The HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md (written by the same session's agents) states that draining per-CPU bucket caches requires 4096-16384 allocations. The highest spray count (256) is **1.5-6% of the minimum needed** to drain caches.

If the allocator is NOT per-type isolated but instead routes through generic `malloc-N` zones (Architecture C from the addendum), then the freed object sits in the per-CPU bucket cache. A spray of 256 objects goes into the SPRAYING CPU's bucket cache and never reaches the slab layer where the freed object sits. The freed object's bucket drains only when the spraying CPU's bucket is full AND the spraying CPU happens to be the SAME CPU that freed the object.

**The zero-overlap result is equally consistent with "right zone, wrong CPU, insufficient volume" as it is with "wrong zone."**

---

## 3. The Lapse Contradiction

The Lapse exploit (PS5 1.00-10.01) uses **socket options + event flags** to spray into the same zone as the freed AIO objects. From `11_LAPSE_PROLAPSE_IDENTIFICATION.md`:

> "the dangling chunk is reclaimed by 'some socket options,' producing an aliased pair of sockets"

And from `FREEBSD_EXPLOIT_TECHNIQUES.md`:

> "evf_create allocates kernel event flag objects. These are in the Sony handle table (proc+0xc48, type 0x110). **Used by Lapse Stage 2.**"

**If Sony's allocator truly isolates zones per-type, Lapse could not work.** Lapse sprays socket option buffers and EVF objects into a zone freed by AIO — the exact cross-subsystem spray our probes attempted.

Three possible reconciliations:
1. **The allocator changed between firmware 10.01 and 14.10.** Sony tightened zone isolation in later firmware. Possible but unverified — would need a 10.01 binary comparison.
2. **Lapse uses `malloc`-class zones, not Sony custom zones.** If AIO objects on PS4/early-PS5 are allocated via `malloc(M_AIO_*)` (generic zones), but on 14.10 Sony switched to dedicated zones, that would explain both Lapse working AND our probes failing.
3. **Our spray volume is simply too low.** Lapse's actual implementation may spray thousands of objects (the Gistre Blog writeup doesn't specify counts). With sufficient volume, the per-CPU cache drains and the freed slot IS reclaimed by cross-subsystem objects.

**Option 3 is the most likely and is not ruled out by any probe.**

---

## 4. The 13.60 Decompile Argument

The claim rests heavily on the 13.60 decompile showing distinct zone descriptor addresses (`0x1ab5900` etc.). This IS evidence that AIO objects use dedicated zones, but it does NOT prove:

1. That EVF/namedobj/socket objects use DIFFERENT zones — no decompile of those subsystems' allocators was cited
2. That the zone descriptors are UMA-isolated — they could be metadata structures that ultimately feed into the same `malloc-128` backing zone
3. That the allocator on 14.10 matches the 13.60 layout

The AIO zone descriptors prove AIO has its own zone management. They don't prove OTHER subsystems don't share the same backing slab pages.

---

## 5. Verdict

### Claims that HOLD:
- **AIO objects use Sony-custom zone descriptors** — confirmed by 13.60 decompile
- **663/664/666/667 readback returns computed status, not raw memory** — proven by 67d/67e wide-buffer tests (sentinel intact past first dword)
- **AIO self-spray creates handle-level overlaps** — confirmed by 65p, 67d (overlap_pairs=64/64)

### Claims that are OVERSTATED:
- **"Cross-subsystem spray is structurally impossible"** — NOT PROVEN. No probe sprayed enough objects (max 256 vs 4096+ needed) to drain per-CPU caches. The Lapse exploit uses exactly this technique on earlier firmware. The correct statement is: "Cross-subsystem spray at volumes ≤256 showed no overlap."
- **"The allocator is zone-isolated"** — PLAUSIBLE but not discriminated from insufficient volume. The 13.60 decompile shows AIO-specific zone descriptors but doesn't prove they're isolated from other subsystems' zones at the slab page level.
- **"Stop writing cross-type spray probes"** — PREMATURE. A probe spraying 2000-4000 namedobj or EVF objects (close to the per-CPU cache drain threshold) would discriminate between "zone isolation" and "insufficient volume."

### What would discriminate:
1. **High-volume cross-type spray probe:** 2000-4000 namedobj or EVF objects after a confirmed double-free. If still zero overlap → zone isolation is real. If overlap → volume was the problem.
2. **sys 624 slab page boundary test:** As probe 68d section [E] proposes — if 500 namedobj causes a 624 step at the same batch count as 500 AIO submits, they share backing pages.
3. **13.60 decompile of EVF/namedobj allocator:** Check if `evf_create` calls `func_0x00c08b50` with a zone address in the same 0x1ab5xxx range, or uses a different allocator entirely.
