# New WebKit CVE Candidates for PS5 14.10 Info Leak

**Date**: 2026-11-09
**Target**: PS5 14.10, WebKit 605.1.15 / Safari 17.0 era
**Cherry-pick cutoff**: Safari 26.3 (Feb 2026) INCLUDED, Safari 26.4+ NOT included
**Goal**: Find an info leak (address disclosure) to derive WebProcess text base

---

## Selection Criteria

1. Fixed AFTER Safari 26.3 (Feb 2026) = definitely unpatched on PS5
2. In JSC or WebCore, reachable from a web page without Wasm or SharedArrayBuffer
3. Provides info leak / address disclosure (not just crash/DoS)
4. DFG JIT active, FTL likely absent, no WebAssembly on PS5

---

## TIER 1: HIGH CONFIDENCE UNPATCHED (Fixed Safari 26.4+)

### CVE-2026-86922 -- Type Confusion in JSC (Safari 27, Sep 2026)
- **Fixed in**: Safari 27 (Sep 14, 2026)
- **Component**: JSC / B3 ReduceStrength
- **Type**: Type confusion
- **Impact**: Arbitrary code execution
- **Unpatched on PS5**: YES (fixed well after cutoff)
- **Info leak potential**: HIGH -- type confusion in JIT can enable addrof/fakeobj
- **Caveat**: The regression test targets Wasm GC `br_on_cast_fail`, which is absent on PS5. However, the B3 ReduceStrength optimization may also affect non-Wasm code paths through DFG. Needs investigation of whether the same optimization fires on JS-only DFG compilation.
- **Probe strategy**: Test B3 optimization patterns that mirror the Wasm GC cast logic but through JS type checks. Focus on `instanceof` + JIT optimization + type narrowing.
- **Status**: ALREADY ANALYZED in `docs/WEBKIT_CVE_REGRESSION_TESTS_2026.md` -- regression test is Wasm-only. Needs JS-only B3 path investigation.

### CVE-2026-64783 -- DataListButtonElement Use-After-Free (Safari 26.6, Jul 2026)
- **Fixed in**: Safari 26.6 (Jul 27, 2026)
- **Component**: WebCore DOM
- **Type**: Use-after-free
- **Impact**: Safari crash
- **Unpatched on PS5**: YES (fixed after cutoff)
- **Info leak potential**: MEDIUM -- vptr read from freed object could disclose module base
- **Caveat**: Requires `<datalist>` element support. PS5 WebKit may not support `<datalist>` -- probe p670 confirmed datalist is NOT supported. DEAD.
- **Status**: DEAD (p670 confirmed datalist unsupported on PS5)

### CVE-2026-64718 -- WebKit Canvas Use-After-Free (Safari 26.6 + Safari 27)
- **Fixed in**: Safari 26.6 (Jul 27, 2026), also listed in Safari 27
- **Component**: WebKit Canvas
- **Type**: Use-after-free
- **Impact**: Safari crash
- **Unpatched on PS5**: YES (fixed after cutoff)
- **Info leak potential**: MEDIUM-HIGH -- Canvas UAF could expose internal pointers if the freed object contains code pointers and can be read before reclaim
- **Caveat**: We already have Canvas2D UAF (CVE-2026-43720, p635) but it's a CONTROL primitive, not an info leak. This is a DIFFERENT Canvas UAF (Bugzilla 313935). Worth investigating the specific trigger.
- **Probe strategy**: Identify the specific Canvas operation that triggers 313935. Likely involves OffscreenCanvas or canvas context type switching. Test reading properties of the freed context before reclaim.
- **Status**: NEW -- needs probe

### CVE-2026-64757 -- WebKit Memory Corruption (Safari 26.6, Jul 2026)
- **Fixed in**: Safari 26.6 (Jul 27, 2026)
- **Component**: WebKit (unspecified)
- **Type**: Memory corruption
- **Impact**: Safari crash
- **Unpatched on PS5**: YES (fixed after cutoff)
- **Info leak potential**: UNKNOWN -- depends on corruption type
- **Probe strategy**: Look up Bugzilla 315082 for details on the trigger
- **Status**: NEW -- needs investigation

### CVE-2026-64753 -- WebCore Cache Information Disclosure (Safari 27, Sep 2026)
- **Fixed in**: Safari 27 (Sep 14, 2026)
- **Component**: WebCore cache
- **Type**: Permissions issue (vulnerable code removed)
- **Impact**: "May disclose sensitive user information"
- **Unpatched on PS5**: YES (fixed after cutoff)
- **Info leak potential**: LOW for address leak -- likely a privacy/data leak, not a memory address leak
- **Probe strategy**: Test cache-related APIs for information disclosure. May reveal cross-origin data but unlikely to reveal code pointers.
- **Status**: LOW PRIORITY

---

## TIER 2: LIKELY UNPATCHED (Fixed Safari 18.2-18.6, after Nov 2024)

These were fixed in Safari 18.x (Dec 2024 - Jul 2025). PS5 cherry-picks through Safari 26.3 (Feb 2026), so Sony MAY have backported these. Lower confidence.

### CVE-2024-54505 -- Type Confusion in WebKit (Safari 18.2, Dec 2024)
- **Fixed in**: Safari 18.2 (Dec 11, 2024)
- **Component**: WebKit (likely JSC based on "type confusion" + credited to Gary Kwong)
- **Type**: Type confusion
- **Impact**: Memory corruption
- **Unpatched on PS5**: UNCERTAIN -- fixed before cutoff but may not be cherry-picked
- **Info leak potential**: HIGH -- type confusion is the classic addrof/fakeobj primitive
- **Probe strategy**: Gary Kwong's type confusion bugs are typically in JSC object representation. Test property access type speculation with mixed-type arrays, DFG optimization of GetByVal with polymorphic types.
- **Status**: NEW -- needs probe. Priority: test before p680 series if possible.

### CVE-2025-24213 -- Type Confusion with Float Handling (Safari 18.5, May 2025)
- **Fixed in**: Safari 18.5 (May 12, 2025)
- **Component**: WebKit (Google V8 Security Team credit suggests JSC focus)
- **Type**: Type confusion, "improved handling of floats"
- **Impact**: Memory corruption
- **Unpatched on PS5**: UNCERTAIN
- **Info leak potential**: HIGH -- float handling type confusion can expose raw pointer bits through double-to-pointer confusion (the classic NaN-boxing exploit)
- **Probe strategy**: Create DFG-compiled functions that operate on mixed float/object values. Force JIT to speculate float type, then pass object. If speculation check is wrong, the object pointer gets treated as a float and can be read as a double (= address leak).
- **Status**: NEW -- HIGH PRIORITY probe candidate

### CVE-2025-31206 -- Type Confusion with State Handling (Safari 18.5, May 2025)
- **Fixed in**: Safari 18.5 (May 12, 2025)
- **Component**: WebKit
- **Type**: Type confusion, "improved state handling"
- **Impact**: Safari crash
- **Unpatched on PS5**: UNCERTAIN
- **Info leak potential**: MEDIUM -- state confusion could expose internal pointers depending on what state is confused
- **Probe strategy**: Investigate what "state handling" means -- likely involves async state transitions in DOM or JSC. Test Promises, async/await, generator state machines under DFG.
- **Status**: NEW -- needs investigation

### CVE-2025-43265 -- Out-of-Bounds Read (Safari 18.6, Jul 2025)
- **Fixed in**: Safari 18.6 (Jul 30, 2025)
- **Component**: WebKit
- **Type**: Out-of-bounds read ("improved input validation")
- **Impact**: "May disclose internal states of the app"
- **Unpatched on PS5**: UNCERTAIN (late fix, less likely cherry-picked)
- **Info leak potential**: VERY HIGH -- explicitly stated as information disclosure, OOB READ
- **Probe strategy**: This is described as disclosing "internal states" which strongly suggests reading past buffer boundaries. HexRabbit (DEVCORE) is the credit -- look for their writeup. Focus on input validation paths in WebKit rendering or DOM.
- **Status**: NEW -- TOP PRIORITY if a writeup or PoC exists

### CVE-2025-43216 -- Use-After-Free (Safari 18.6, Jul 2025)
- **Fixed in**: Safari 18.6 (Jul 30, 2025)
- **Component**: WebKit
- **Type**: Use-after-free
- **Impact**: Safari crash
- **Unpatched on PS5**: UNCERTAIN
- **Info leak potential**: MEDIUM -- UAF can expose vtable pointers if read before reclaim
- **Probe strategy**: Similar approach to our FontFace/Canvas UAF work. Identify the specific UAF trigger and attempt stale pointer read.
- **Status**: NEW -- needs Bugzilla lookup

### CVE-2025-30427 -- Use-After-Free (Safari 18.4, Mar 2025)
- **Fixed in**: Safari 18.4 (Mar 31, 2025)
- **Component**: WebKit
- **Type**: Use-after-free
- **Impact**: Safari crash
- **Unpatched on PS5**: POSSIBLE (recent enough that cherry-pick may be incomplete)
- **Info leak potential**: MEDIUM
- **Probe strategy**: Look up details from rheza (@ginggilBesel)
- **Status**: NEW -- needs investigation

### CVE-2025-24209 -- Buffer Overflow (Safari 18.4, Mar 2025)
- **Fixed in**: Safari 18.4 (Mar 31, 2025)
- **Component**: WebKit
- **Type**: Buffer overflow
- **Impact**: Process crash
- **Unpatched on PS5**: POSSIBLE
- **Info leak potential**: LOW-MEDIUM -- buffer overflow is typically a write primitive, not a read
- **Probe strategy**: Could be useful for the full exploit chain but not directly for info leak
- **Status**: LOWER PRIORITY for info leak goal

---

## TIER 3: ALREADY TESTED / KNOWN DEAD

| CVE | Status | Notes |
|-----|--------|-------|
| CVE-2024-44308 | DEAD | DFG PutByVal -- Sony patched (p621) |
| CVE-2026-86922 | PARTIAL | Wasm GC only, no JS path found |
| CVE-2026-64783 | DEAD | datalist unsupported on PS5 (p670) |
| CVE-2026-84635 | LIVE but not weaponizable | TypedArray Reflect.set bounds-checked (p661/p662) |
| CVE-2026-28905 | LIVE but not a leak | FTL PhantomNewArrayWithButterfly -- own data, no pointers (p663-p666) |
| CVE-2023-42916 | UNTESTED | DFG OOB read -- TOP PRIORITY, probes p680/p681 queued |
| CVE-2023-42917 | DEAD | DFG flatten race -- Sony patched (p602b) |
| CVE-2023-42890 | UNTESTED | Memory handling -- probe p693 queued |
| CVE-2023-41976 | UNTESTED | SVG animation UAF -- probe p686 queued |
| CVE-2023-42852 | UNTESTED | CSS counter-style OOB -- probe p688 queued |

---

## Recommended Probe Priority

1. **CVE-2025-43265** (OOB read, Safari 18.6) -- explicitly an info disclosure, OOB read
2. **CVE-2025-24213** (type confusion with floats, Safari 18.5) -- classic NaN-boxing exploit path
3. **CVE-2026-64718** (Canvas UAF, Safari 26.6+) -- definitely unpatched, Canvas is our domain
4. **CVE-2024-54505** (type confusion, Safari 18.2) -- Gary Kwong JSC bug
5. **CVE-2023-42916** (DFG OOB read) -- already queued as p680/p681, still top candidate
6. **CVE-2025-31206** (type confusion state handling)
7. **CVE-2025-43216** (UAF, Safari 18.6)
8. **CVE-2026-64757** (memory corruption, Safari 26.6)

---

## Next Steps

- Search for writeups/PoCs for CVE-2025-43265 (HexRabbit/DEVCORE)
- Search for Gary Kwong's JSC type confusion pattern for CVE-2024-54505
- Look up Bugzilla 313935 for CVE-2026-64718 Canvas UAF details
- Write probes for top 3 candidates
- Run p680/p681 (CVE-2023-42916) when PS5 comes online -- still the single most promising candidate
