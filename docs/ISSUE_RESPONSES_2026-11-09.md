# Issue Responses - 2026-11-09

Drafted responses for open GitHub issues. Post these as comments, then close the ones marked CLOSE.

---

## #216 - V650-V655 crash oracle (TFujiwara) - KEEP OPEN

> **Response:**
>
> Thanks for the independent 14.22 repro, this is great cross-firmware data. The Canvas2D alias R/W at p553-level working on 14.22 is exactly what we expected given the WebKit 605.1.15 branch point.
>
> For the forged m_stateStack crash oracle: on our 14.10 bench the first HIT consistently lands in the "low" region (0x10001xxxxx range). The forge offsets that survived in our testing are documented in the p599 v4f/v4i series. Key finding from v4i: the 80B spray is unnecessary and actively harmful. Freed bmalloc memory at T1-0x60 is benign (all zeros = empty hash table), so removeClient reads zeros, finds nothing, returns safely. 7/7 runs survived without any 80B spray (100% reliability vs 33% with spray).
>
> The ArrayBuffer(768) reclaim for the freed 768B ctx slot matches our p553/p554d findings. Cross-type reclaim (different bmalloc size classes) is dead though, so the spray must be same-type.
>
> Will share more region data once we run the next bench session.

---

## #184 - 14.20 PS5 Pro feature probe data (elanonimo832) - CLOSE

> **Response:**
>
> This data has been fully incorporated into the research. The 14.20 Pro confirmation of WebKit 605.1.15/Safari 17.0 with identical API surface (FontFace, RAB, structuredClone, no WebAssembly/SharedArrayBuffer) was critical for establishing cross-firmware viability. elanonimo832 also independently confirmed the Canvas2D UAF on 14.20 (3/3 cold boots), which is cited in CLAUDE.md.
>
> Thank you for the contribution. Closing as incorporated.

---

## #181 - FontFace UAF core thread (vincenzoiacovone) - KEEP OPEN

> **Response:**
>
> Status update (2026-11-09):
>
> The chain has progressed significantly since the last summary:
> - Two-phase forge write CONFIRMED (p656): addClient uses forged table pointer, writes WeakPtrImpl* into target bucket, keyCount increments
> - GC destructor path CONFIRMED (p599 v1/v2/v4a): ~FontFace() -> removeClient reads m_table from +0x58 -> deref() decrements rc
> - Null-spray survival 100% (p599 v4i): 80B spray unnecessary, freed memory benign, 7/7 survived
> - rc=2 is PERMANENT: no known path fires additional deref()
>
> The single remaining hard blocker is the WebProcess text base. All 17+ known info-leak routes are dead (p630-p658). We need either a new 605.1.15-era CVE or an indirect leak path. If anyone has access to decrypted 14.00/14.10 WebProcess binaries, one address (any ret gadget or base) unlocks the entire chain.
>
> PR #237 (iterateClients survives on forged client with controlled fontPropertyChanged callback) and PR #238 (argument pointer class measurement) are both merged as of today.

---

## #180 - Probe-ID collision p563/p564 (AstroBot-tech) - CLOSE

> **Response:**
>
> This naming collision is documented in CLAUDE.md next steps (item 10). The FontFace probes should be renamed to p563-html/p564-html to disambiguate from the Canvas probes. This is a bookkeeping fix, not a research blocker. Closing as acknowledged and tracked.

---

## #179 - V88 forge geometry contradictions (AstroBot-tech) - KEEP OPEN

> **Response:**
>
> The forge geometry has been reconciled in `docs/V88_FORGE_GEOMETRY_RECONCILIATION.md` and the exploit chain analysis doc. Key corrections:
> - WeakPtrImpl layout confirmed: `{+0x00: m_refCount(4B), +0x04: m_ownerThread, +0x08: m_areThreadChecks, +0x10: m_ptr, +0x18: m_thread}` with no vtable (CRTP ref/deref)
> - fontStateChanged is at V+0x18 (PS5 fork), not V+0x28 (upstream header)
> - README law "+0x00: vtable" retracted for WeakPtrImpl
>
> If there are remaining contradictions not covered by the reconciliation doc, please flag the specific section numbers.

---

## #178 - m_ranges reader + wrapper free (vincenzoiacovone) - CLOSE

> **Response:**
>
> Both questions are now answered by later probes:
>
> (a) m_ranges is NOT a reader. It requires the face to be alive and in-set, and 3 independent structural locks prevent attacker-bytes + in-set simultaneously. This is documented in CLAUDE.md trap #3.
>
> (b) Wrapper free in-document: `font-display: fallback` (~3.1s to Failure) or `optional` (~0.1s to Failure) triggers `faceFinished()` which releases both GC pin and C++ strong refs. The forge of +0x68 must happen AFTER unpin. This is now documented in the exploit chain analysis.
>
> Closing as resolved by subsequent research.

---

## #174 - WebProcess text base needed (4TheDoctor) - KEEP OPEN

> **Response:**
>
> This remains THE hard blocker for the entire chain. Update:
>
> All known info-leak routes are now exhausted (p630-p658, 17+ routes tested). The CE-108262-9 error codes carry zero fault-type info (confirmed). The crash backtrace route needs a capture that shows module-relative frames, which nobody has produced yet.
>
> With GTA 6 launching this holiday season, a 14.10 jailbreak has never been more in demand. One WebProcess address unlocks everything. If anyone has:
> - A decrypted 14.00 or 14.10 WebProcess binary
> - A crash report with backtrace frames (not just error codes)
> - Any other WebKit code pointer leak technique for 605.1.15
>
> Please share here. The entire exploit chain is waiting on this single piece.

---

## #170 - Cross-check kptr_hunt.py on 13.40 (rooklz) - CLOSE

> **Response:**
>
> Thank you for the independent 13.40 confirmation. The finding that the same syscall families (659, 593, 532, 661-668) produce only userland pointers on 13.40 validates our 14.10 results and confirms this is a deliberate Sony sanitization, not a version-specific behavior. The AIO family closure confirmation is especially valuable.
>
> Closing as incorporated.

---

## #153 - Cold-boot VA-window map (cobrajet302gt) - KEEP OPEN

> **Response:**
>
> This reproducibility data has been critical for the bake approach. The finding that cold-boot VA-window maps are 100% reproducible (3/3 cold starts) while mid-session maps show churn is incorporated into the FontFace T-determinism analysis. Load-1 byte-constant T (16/16 cold boots) relies directly on this observation.
>
> Keeping open as reference data that active research depends on.
