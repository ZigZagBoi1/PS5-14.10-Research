# Contradictions and Inconsistencies Report — All 21 Documents

> **Date:** 2026-10-25 Session 3 (verification pass)
> **Scope:** Cross-document contradiction analysis across docs 01–21

---

## CONTRADICTION 1: Lapse Used Cross-Subsystem Spray vs. Cross-Subsystem Spray Is Structurally Impossible

**Doc 11** (Session 2): "Socket options + event flags are the correct spray technique" and "Lapse specifically adapted evf for the 128B zone." States Lapse used socket+evf spray successfully to reclaim double-freed AIO slots.

**Doc 14** (Session 3): "Sony per-type zone isolation proven structural — cross-subsystem spray is dead. Stop writing cross-type spray probes."

**Doc 12** (Session 2) explicitly flags this: "Is cross-subsystem spray possible? probe-result-mining: proven dead. freebsd-exploit-research: Lapse used socket options + evf."

**Resolution:** This is the **single most important unresolved contradiction** in the entire document set. If Lapse works on PS5 (and Prolapse is announced for 14.10), then EITHER:
- (a) The allocator wraps UMA and shares generic `malloc-N` zones across subsystems (doc 05, doc 19 Architecture C), making our 20 failed spray probes a quantity/technique problem, not a structural one, OR
- (b) Lapse uses a technique we haven't replicated — e.g., IPv6 routing structures, SO_LINGER socket teardown allocations, or a different allocation path that DOES share zones, OR
- (c) Lapse targets a different firmware where the allocator behaved differently.

**Verdict:** Doc 14's "structurally impossible" claim is **too strong**. The 20 failed probes prove that our TESTED spray objects (namedobj, EVF, kqueue, socketpair, setsockopt, shm) don't share AIO zones. They do NOT prove that NO object can. Lapse's existence is a counterexample that must be reconciled. Doc 14 should say "no tested spray reclaims AIO zones" not "structurally impossible."

---

## CONTRADICTION 2: File Refcount UAF Ranked #1 vs. 65r Disproves Refcount Accumulation

**Doc 16** (Session 3): Ranks "File Refcount Double-Decrement → fd UAF → fstat Leak" as **#1 KASLR approach, feasibility HIGH**.

**Doc 18** (Session 3): "fd Refcount Does NOT Accumulate (65r): 100 double-frees on the same fd left it alive. The double-freed object is a per-request AIO tracking structure, NOT the file descriptor itself."

**Doc 21** (Session 3): Lists "Simple file refcount accumulation" as **PROVEN DEAD** (item 3 in "What's Proven Dead").

**Resolution:** Direct self-contradiction within Session 3. Doc 16 ranks the approach #1 with a caveat about 65r, while doc 21 lists the same approach as dead. The issue is that doc 16's chain assumes `entry_dispose` decrements the file refcount (I+0x40 → file object), while doc 18 measured the fd staying alive, which could mean either: (a) the exclusive lock prevents the second `entry_dispose` from running, or (b) the refcount starts higher than expected. Doc 16 acknowledges the caveat but still ranks it #1 with "feasibility: HIGH", which contradicts doc 21's "proven dead."

**Verdict:** Doc 16 should downgrade Rank 1 from "feasibility: HIGH" to "feasibility: CONTESTED." The approach is not proven dead (only 65r's specific test is evidence against it), but it's not HIGH confidence either. Doc 21 is slightly overstated — 65r proves the fd survives 100 races, but doesn't definitively prove the decrement never fires (it could fire and be compensated by other references).

---

## CONTRADICTION 3: Allocator Is UMA vs. Sony Custom

**Doc 01** (Session 1): "`func_0x00c08df0` takes `(pointer, zone)` — this is `uma_zfree()`."
**Doc 05** (Session 1): "All AIO objects are small, so they use **UMA zones**. Confidence: HIGH."
**Doc 09** (Session 1): "AIO objects live in 4 dedicated UMA zones."
**Doc 11** (Session 2): "Queue entries land in the 0x80 (128-byte) UMA zone."

**Doc 13** (Session 2): "Sony-custom allocator zone addresses, not standard UMA zone descriptors."
**Doc 14** (Session 3): "Sony's custom kernel allocator uses per-TYPE zones."
**Doc 15** (Session 3): Names zones as Sony-custom.
**Doc 19** (Session 3): Presents three possible architectures (UMA wrapper / bump pool / malloc wrapper).

**Doc 12** (Session 2) explicitly flags this: "Is the allocator UMA or Sony-custom? freebsd-exploit-research: standard UMA. aio-object-forensics: Sony custom."

**Resolution:** The allocator interface (`func_0x00c08b50(size, zone_ptr, flags)` / `func_0x00c08df0(ptr, zone_ptr)`) is structurally compatible with BOTH a UMA wrapper and a Sony custom allocator. Session 1 docs assume UMA because the interface pattern matches; Session 2-3 docs note the zone descriptors are in Sony's data segment and may not be standard UMA zones.

**Verdict:** Doc 19's three-architecture framework is the most honest representation. Docs 01, 05, 09, 11 are **overstated** in asserting UMA with HIGH confidence. The correct statement is: "the allocator has a UMA-compatible interface but the zone descriptors may be Sony-custom; whether zones are shared across subsystems is unresolved." This connects directly to Contradiction 1.

---

## CONTRADICTION 4: Freed Object Count — 4 vs 5 vs 7

**Doc 01** (Session 1): "frees **four distinct sub-objects** per deleted AIO request."
**Doc 13** (Session 2): "R, I, Q, D" — 4 objects in the diagram.
**Doc 15** (Session 3): Lists 7 freed objects (R, I, Q lock, Q, A, T, D) with steps 4-7 conditional.

**Resolution:** Doc 15 is the most detailed and correct. Steps 4-7 (Q, A, T, D) only fire on last-reference (count==1). For individual submits (count=1, the common case), ALL 7 steps execute. For batch submits with count>1, only R and I are freed per-ID. Doc 01's "four" counts only the unconditional frees and misses the conditional ones. Doc 13's diagram is abbreviated.

**Verdict:** Doc 15 is correct. Docs 01 and 13 are incomplete but not wrong for the batch case. Should be clarified: "4 always-freed + 3 conditionally-freed (on last-ref)."

---

## CONTRADICTION 5: Probe 68a Name Collision

**Three different files share the name `68a`:**
1. `68a_aio_uaf_readback.lua` (Session 2, doc 12's probe queue)
2. `68a_full_gadget_catalog.lua` (Session 1, doc 10)
3. `68a_doublefree_zone_overlap.lua` (Session 3, doc 21's probe queue)

**Impact:** HIGH. These are three completely different probes with the same prefix. The README references "probe 68a" without disambiguating which one. Session 3's synthesis (doc 21) says "Send probe 68a" meaning the zone overlap version, but Session 2 (doc 12) expects 68a to be the UAF readback probe.

**Verdict:** Rename to unique identifiers. Suggested:
- `68a_aio_uaf_readback.lua` → keep (Session 2, first created)
- `68a_full_gadget_catalog.lua` → rename to `68g_full_gadget_catalog.lua`
- `68a_doublefree_zone_overlap.lua` → rename to `68h_doublefree_zone_overlap.lua`

---

## CONTRADICTION 6: sys 591 Is "Highest-Priority KASLR Defeat" vs. CLAUDE.md Says It's Dead

**Doc 04** (Session 1): "sys 591 — Possible Single-Call KASLR (p=HIGH)"
**Doc 08** (Session 2): "**sys 591 is the single most promising untested vector for KASLR defeat.**"
**Doc 09** (Session 1): "sys 591 dynlib_dlsym KASLR shortcut."

**CLAUDE.md dead ends:** "FatGid/setcred (CVE-2026-45250) — syscall 591 is in the Sony range and returns -1 (not crash). setcred was added in FreeBSD 14.3; PS5 kernel is FreeBSD 11-based. Not present."

**13.60 CSV:** Line 592: `591,dynlib_dlsym,0x265570` — 591 IS `dynlib_dlsym`.
**SYSENT_PRESENCE_14_10.md:** `| 591 | dynlib_dlsym | -1 | present |`

**Resolution:** CLAUDE.md's dead-end entry MISLABELS syscall 591 as "FatGid/setcred." The 13.60 CSV confirms 591 is `dynlib_dlsym`. The dead-end tested it with zeros (probe 392a tested it in a CVE-2026-45250 context) and got -1, which is the expected result for handle=0 (error code 3, invalid handle, not a privilege gate). 591 has **never been tested with valid arguments** (a real module handle + NID string).

**Verdict:** The CLAUDE.md dead-end for 591 is a **mislabel and a false closure**. Docs 04/08/09 are correct that 591 is untested with valid arguments. This is genuinely a HIGH-priority untested vector. The CLAUDE.md entry should be corrected to show that 591=dynlib_dlsym, the -1 came from invalid args (zeros), and it needs testing with real module handles.

---

## CONTRADICTION 7: Session 2 Top Actions vs. Session 3 Top Actions

**Session 2 (README):**
1. Replicate Lapse Stage 2 — SO_LINGER spray + evf readback
2. Test sys 665 with valid AIO IDs
3. Socket-level ioctl sweep (SIOC*)

**Session 3 (README):**
1. Send probe 68a (zone overlap)
2. Write + send sys 665 probe
3. Write + send 663 mode parameter sweep

**Neither mentions sys 591 despite docs 04/08/09 calling it the highest-priority KASLR vector.**

**Resolution:** Session 3 dropped the SO_LINGER/evf approach (declaring cross-subsystem spray dead, see Contradiction 1) and replaced it with zone overlap testing. The socket-level ioctl sweep from Session 2 also disappeared without being marked done or dead.

**Verdict:** The action lists are inconsistent. sys 591 should appear in both. Session 3's dismissal of SO_LINGER/evf spray contradicts Session 2's Lapse analysis (Contradiction 1). The socket ioctl sweep should be tracked as still-open or explicitly closed.

---

## CONTRADICTION 8: Sub-Object Size Estimates

**Doc 05** (Session 1): "Best estimate: 0x40-0x80 bytes (64-128), most likely near 0x58 (88 bytes). Confidence: MEDIUM — inferred from field offsets."
**Doc 06** (Session 1): R=0x30, I=0x58. Clear table with zone assignments.
**Doc 09** (Session 1): "Estimated size 128-256 bytes." (for the freed "kernel-side AIO request node")
**Doc 13** (Session 2): R=0x30, I=0x58, Q=0x58. Clear hierarchy with zone addresses.
**Doc 15** (Session 3): Same as doc 13, confirmed by cross-validation.

**Resolution:** Doc 09's "128-256 bytes" is wrong — it conflates the overall object tree with the individually freed sub-objects. The consensus from docs 06/13/15 is R=0x30 and I=0x58.

**Verdict:** Doc 09 should be corrected. The freed sub-objects are 0x30 and 0x58 bytes, not 128-256.

---

## STALE CLAIMS (Later Sessions Superseded)

| Doc | Claim | Superseded By |
|-----|-------|---------------|
| 04 | "#1: AIO Cross-Slab Reclaim + 663/664 Readback (p=20%)" | Doc 18/21: 663/664 returns computed status, not raw memory. Dead. |
| 04 | "#2: Pipe/Socket Buffer Header Type Confusion" | Doc 14: Zone isolation. Dead. (Doc 04 itself marks this "non-viable" inline.) |
| 06 | setsockopt ranked 9/10 for spray | Doc 14: Cross-subsystem spray dead. Zero overlap in 66c. |
| 06 | evf ranked 8/10 for spray | Doc 14: Zero overlap in 65v/66e. (But see Contradiction 1 — Lapse used evf.) |
| 06 | namedobj ranked 8/10 for spray | Doc 14: Zero overlap in 65w/67f. |
| 07 | STRATEGY.md "No threading → no race conditions" | Already contradicted at time of writing — threading works. |
| 09 | "Estimated size 128-256 bytes" | Doc 13/15: 0x30 and 0x58 bytes. |
| 09 | "setsockopt/getsockopt (if 0x30-byte context is in general zone)" | Doc 14: Zone isolation makes this non-viable. |

---

## SUMMARY: Most Critical Issues

1. **Contradiction 1 (Lapse vs Zone Isolation)** — unresolved and determines the entire exploit strategy. Must be reconciled before proceeding.
2. **Contradiction 6 (sys 591 mislabeled as dead)** — a potentially live HIGH-priority KASLR vector dismissed by a mislabel. Should be tested immediately.
3. **Contradiction 5 (three probes named 68a)** — operational hazard. Rename before sending any probe.
4. **Contradiction 2 (file refcount ranked #1 AND listed as dead)** — internal Session 3 inconsistency. Needs a definitive assessment.
5. **Contradiction 3 (UMA vs Sony custom)** — impacts all spray strategy. Should state "unknown, possibly UMA wrapper" not assert either way.
