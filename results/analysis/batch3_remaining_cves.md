# Batch 3: Remaining CVE Cross-References

**Date:** 2026-11-11

---

## CVE-2025-14174 — ANGLE Metal Renderer Memory Corruption

**Local docs:** `WEBKIT_CVE_RESEARCH_2026-11-09.md:14-20`
**Probe:** None. **Run:** No.
**JIT dependency:** N/A — not a WebKit JS engine bug.
**Info leak potential:** None.

**Assessment: DEAD.** This is in Google's ANGLE graphics library (Metal renderer). PS5 WebKit uses a Sony GPU backend, not ANGLE/Metal. The code path does not exist on PS5. Even if it did, patched in WebKit versions far newer than 605.1.15.

- **Previously believed:** Potential memory corruption vector.
- **Evidence establishes:** ANGLE/Metal is not present on PS5. Sony GPU backend is proprietary.
- **Overlooked:** Nothing — correctly identified as inapplicable in existing docs.
- **New capability:** No.
- **Uncertainty:** None. Structurally dead.

---

## CVE-2024-23213 — WebKit Memory Handling (Code Execution)

**Local docs:** Extensive — `WEBKIT_CVE_RESEARCH_2026-11-09.md:34-38, 79-110, 310-332`
**Probes:** p689 (Fetch body lifetime), p690 (TextDecoder streaming) — both WRITTEN, NOT RUN.
**JIT dependency:** **JIT-INDEPENDENT** — Apple describes "improved memory handling", NOT type confusion. The type confusion in Safari 17.3 is CVE-2024-23222 (tested DEAD). This is a separate memory handling issue.
**Info leak potential:** MEDIUM-HIGH — if it's a UAF or buffer error in Fetch/TextDecoder, could expose heap data including code pointers.

**Assessment: HIGH — Probe ready, console needed.**

- **Previously believed:** Initially misclassified as type confusion. Corrected to "memory handling" (CHANGELOG.md:85).
- **Evidence establishes:** Two probes (p689/p690) target the two most likely trigger paths (Fetch body stream lifetime confusion, TextDecoder streaming decode buffer). Neither has been run. Present in Safari 17.0 (our version), patched in 17.3. Bugzilla 266619.
- **Overlooked:** Nothing — classification correction already applied. Two alternative trigger paths designed.
- **New capability:** Not yet — probes unrun.
- **Uncertainty:** Which of the two trigger paths matches. Whether the bug provides a read primitive or just a crash. Console access required.

---

## CVE-2023-41983 — WebKit DoS (Junsung Lee)

**Local docs:** `WEBKIT_CVE_RESEARCH_2026-11-09.md:160` — single table row, classified LOW.
**Probe:** None written. **Run:** No.
**JIT dependency:** Unknown (insufficient data).
**Info leak potential:** None — DoS only per Apple advisory.

**Assessment: LOW.** Apple describes this as a DoS (denial of service), not code execution. Same researcher (Junsung Lee) as CVE-2023-40447 and CVE-2023-41976 (code execution bugs). The DoS classification means no memory corruption — likely a hang or assert failure. No research value for kernel R/W path.

- **Previously believed:** Low priority DoS.
- **Evidence establishes:** DoS only. No probe, no analysis beyond table entry.
- **Overlooked:** Nothing. DoS bugs don't advance the exploitation chain.
- **New capability:** No.
- **Uncertainty:** None meaningful. Even if it were memory corruption, the "DoS" classification means Apple didn't consider it exploitable.

---

## CVE-2026-64783 — DataListButtonElement Use-After-Free

**Local docs:** Extensive — `NEW_CVE_CANDIDATES_2026_11.md:34-42`, `WEBKIT_CVE_REMAINING_2026.md:122-151`, `ALL_PROBES.md` (probes p670, p675).
**Probes:** p670 (feature detection), p675 (UAF trigger) — p670 confirmed `<datalist>` NOT SUPPORTED on PS5.
**JIT dependency:** JIT-independent (DOM UAF).
**Info leak potential:** Would be MEDIUM (vptr read from freed object) IF datalist were available.

**Assessment: DEAD.** Probe p670 confirmed that `<datalist>` element is not supported on PS5 WebKit. The entire UAF trigger depends on `DataListButtonElement` existing in the shadow DOM of `<input>`. Without `<datalist>`, the shadow subtree containing `DataListButtonElement` is never created. The bug is structurally unreachable.

The `NEW_CVE_CANDIDATES_2026_11.md:159` summary table already marks this DEAD. The `WEBKIT_CVE_REMAINING_2026.md:122+` analysis is more detailed but reaches the same conclusion.

- **Previously believed:** HIGH priority DOM UAF with vptr leak potential.
- **Evidence establishes:** DEAD — datalist unsupported on PS5 (p670 device-confirmed).
- **Overlooked:** Nothing — correctly killed by device testing.
- **New capability:** No.
- **Uncertainty:** None. Structurally dead.

---

## Summary

| CVE | Rating | Key Finding |
|-----|--------|-------------|
| CVE-2025-14174 | **DEAD** | ANGLE/Metal not on PS5 |
| CVE-2024-23213 | **HIGH** | Memory handling ACE, probes p689/p690 ready, JIT-independent |
| CVE-2023-41983 | **LOW** | DoS only, no memory corruption |
| CVE-2026-64783 | **DEAD** | datalist unsupported on PS5 (p670 confirmed) |

**CVE-2024-23213 is the standout** — it's the second-highest priority unrun probe after CVE-2025-43265 (OOB read). Both are JIT-independent and target Safari 17.x code paths confirmed present on PS5.
