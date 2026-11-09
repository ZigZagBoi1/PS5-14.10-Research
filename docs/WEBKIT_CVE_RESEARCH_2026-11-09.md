# WebKit CVE Research for Info Leak -- 2026-11-09

> **Goal:** Find a WebKit 605.1.15 / Safari 17.0 era CVE that leaks code pointers
> (WebProcess text base), since all 17+ known routes are dead on PS5 14.10.

## Search Summary

Searched for: WebKit CVEs 2023-2026 with info leak / address disclosure / type confusion
primitives, PS5 jailbreak scene updates, Coruna exploit kit techniques, and JSC
addrof/fakeobj primitives without WebAssembly.

## CVEs Evaluated

### CVE-2025-14174 (ANGLE Metal renderer memory corruption)
- **Patched:** December 2025 (iOS 26.2, macOS Tahoe 26.2)
- **Root cause:** Out-of-bounds memory access in ANGLE's Metal renderer
- **Status:** UNLIKELY TO APPLY. This is in Google's ANGLE graphics library, patched in
  WebKit versions far newer than 605.1.15. The PS5 WebKit port uses a Sony GPU backend,
  not ANGLE/Metal. Even if the code path existed, no public PoC or technique writeup is
  available.

### CVE-2025-43529 (DFG escape analysis StoreBarrier missing)
- **Already tested:** DEAD on PS5 14.10 (CLAUDE.md). Vulnerable code was introduced
  AFTER the 605.1.15 branch point. PS5 has older WebKit.

### CVE-2024-23222 (WebKit type confusion -- actively exploited)
- **Patched:** January 2024 (Safari 17.3, iOS 17.3)
- **Already tested:** DEAD on PS5 14.10 (probes p606/p607). 467 fine-grained DFG race
  attempts, zero type confusion.
- **Note:** Used in the Coruna exploit kit for RCE on iOS 16.6-17.2.1. The addrof
  technique built on top of this bug is NOT public -- no writeup describes the
  info-leak construction.

### CVE-2024-23213 (WebKit memory handling -- code execution)
- **Patched:** January 2024 (Safari 17.3)
- **Status:** NOT TESTED. Apple describes it as "improved memory handling" leading to
  arbitrary code execution. Bug class unspecified. WebKit Bugzilla 266619.
- **Assessment:** Patched in Safari 17.3, which is AFTER the 605.1.15 / Safari 17.0
  branch. **PS5 14.10 may be vulnerable.** This is the most promising untested lead.

### CVE-2024-23206 (WebKit fingerprinting via access issue)
- **Patched:** January 2024 (Safari 17.3)
- **Status:** NOT TESTED. Access-control issue enabling browser fingerprinting. WebKit
  Bugzilla 262699.
- **Assessment:** Fingerprinting != info leak for code pointers. Low priority but could
  reveal side channel information about the WebProcess.

### CVE-2023-43000 (WebKit UAF)
- **Patched:** July 2023 (Safari 16.6, iOS 16.6)
- **Status:** DEAD. Fixed BEFORE the 605.1.15 branch point (Safari 17.0 shipped
  September 2023). PS5 14.10 has the fix.

### CVE-2022-48503 (WebKit memory access -- Coruna chain)
- **Patched:** July 2023 (iOS 16.5.1)
- **Status:** DEAD. Fixed before 605.1.15. Used in Coruna kit for iOS 15.2-15.5.

## Coruna Exploit Kit Analysis

Google TAG reported the Coruna kit in March 2026 with 5 exploit chains and 23 exploits
targeting iOS 13.0-17.2.1. Key observations:

- The WebKit RCE stage uses type confusion (CVE-2024-23222 for iOS 17.x)
- The addrof primitive construction is NOT documented publicly
- PAC bypass is a separate stage (irrelevant to PS5 which has no PAC)
- The kit fingerprints devices before selecting a chain -- no universal technique

## Gezine's 14.10 Demo

Gezine demonstrated Debug Settings on PS5 14.10 on October 19, 2026. Key facts:
- Method is private and undisclosed
- NOT the Relapse chain (that was patched in 14.00)
- Shows Debug Settings IS achievable on 14.10
- No game backup execution demonstrated
- Gezine stated "hypervisor exploit may be needed" for full functionality
- No WebKit text base leak technique was disclosed

## Promising Leads

### 1. CVE-2024-23213 (HIGH PRIORITY -- UNTESTED)
Patched in Safari 17.3, meaning it was present in Safari 17.0 (605.1.15). The PS5
ships 605.1.15. Apple credits Wangtaiyu of Zhongfu info. WebKit Bugzilla 266619.
This is the single most promising untested CVE found in this search.

**Next step:** Find the WebKit commit that fixes Bugzilla 266619 and analyze the
vulnerable code path. If it produces a type confusion or UAF, it could provide the
addrof primitive needed for the text base leak.

### 2. Existing CSSFontFace Exploit Chain (ntfargo/CSSFontFace-Exploit)

The community has an existing CSSFontFace UAF exploit chain by Nathan Fargo (ntfargo)
that works on PS4 6.00-13.52 and PS5 1.00-8.60. Key observations:
- Uses m_featureSettings corruption to build addrof/fakeobj from a corrupted array header
- **14.10 redesigned the property handling** that the m_featureSettings primitive relies on
- DeepWiki analysis confirms: "PS5 vtable checks and ASLR block the current chain
  without a separate leak or heap-shaping step"
- ChendoChap's PS5 4.03 work confirms PS5 CFI blocks PS4's vtable-smashing approach

**Conclusion:** The community faces the SAME blocker we do -- the text base leak. Our
FontFace UAF chain uses a different trigger mechanism (cascade rebuild in `.then` trap)
but hits the same wall. The ntfargo chain's addrof/fakeobj construction technique
(corrupted indexing header yields oversized array) may be adaptable to our 192B
ArrayBuffer reclaim if we can leak a single code pointer.

### 3. CVE-2024-23213 (CORRECTED -- "Improved Memory Handling", Not Type Confusion)

**Correction:** Earlier analysis incorrectly classified CVE-2024-23213 as type confusion.
Apple describes it as "improved memory handling" leading to arbitrary code execution.
The TYPE CONFUSION in Safari 17.3 is CVE-2024-23222, which we already tested DEAD
(probes p606/p607). CVE-2024-23213 is a separate memory handling issue that may still
be exploitable. WebKit Bugzilla 266619 (unverified mapping).

### 4. CVE-2023-41976 (UAF -- Safari 17.1 Fix, UNTESTED)

A use-after-free addressed with "improved memory management." Found by Junsung Lee.
Fixed in Safari 17.1 (Oct 25, 2023), meaning it was present in Safari 17.0 (605.1.15).
CVSS 8.8. PS5 14.10 is LIKELY VULNERABLE unless Sony cherry-picked.

This is particularly interesting because:
- UAF is the same vulnerability class as our FontFace/Canvas2D exploits
- If it produces a dangling pointer readable from JS, it could be the info leak
- Safari 17.1 fixes are very close to the 17.0 branch point, making cherry-pick less likely

**Next step:** Identify the WebKit component affected. The Bugzilla ID may be 260173
(unconfirmed). Need to determine if this UAF is in a different component than CSSFontFace
and whether it could produce an info leak rather than code execution.

### 5. StructureID Prediction (MEDIUM PRIORITY -- TECHNIQUE)
Older WebKit builds (pre-2020) lack StructureID randomization. If PS5's 605.1.15
build does not have randomization, StructureIDs can be predicted, enabling fakeobj
construction without a separate info leak. Project Zero's JITSploitation II (2020)
documents this technique.

**Next step:** Test whether StructureIDs are randomized on PS5 14.10. If sequential
or predictable, the fakeobj primitive becomes achievable without an addrof.

### 3. JIT CodeBlock Pointer via Heap Grooming (LOW PRIORITY -- SPECULATIVE)
DFG-compiled functions store CodeBlock pointers on the heap. If the Canvas2D UAF or
FontFace UAF can be aimed at a freed CodeBlock allocation, the code pointer could
be read through the R/W channel.

**Next step:** Measure DFG CodeBlock allocation sizes and check if they fall in
the same bmalloc size class as 192B (FontFace) or 768B (Canvas2D).

### 4. Safari 17.1/17.2 Fixes (MEDIUM PRIORITY -- RESEARCH)
Safari 17.1 (Oct 2023) and 17.2 (Dec 2023) both shipped WebKit security fixes.
Any bug fixed in 17.1+ but present in 17.0 is a candidate. Apple's security notes
for these releases should be checked systematically.

## Safari 17.1 through 17.3 CVE Audit (All Present in 605.1.15)

These were ALL present in Safari 17.0 (605.1.15) and fixed later. PS5 14.10 ships
605.1.15, so these bugs are live unless Sony cherry-picked the fix.

### Safari 17.1 (Oct 25, 2023)
| CVE | Credit | Description | Priority |
|-----|--------|-------------|----------|
| CVE-2023-42852 | Pedro Ribeiro, Vitor Pedreira | "improved checks" - code execution | MEDIUM |
| CVE-2023-40447 | Junsung Lee (Cross Republic) | code execution | MEDIUM |
| CVE-2023-41976 | Junsung Lee | code execution | MEDIUM |
| CVE-2023-41983 | Junsung Lee | DoS | LOW |

### Safari 17.1.2 (Nov 30, 2023)
| CVE | Credit | Description | Priority |
|-----|--------|-------------|----------|
| **CVE-2023-42916** | **Clement Lecigne (Google TAG)** | **OOB READ - actively exploited** | **CRITICAL** |
| CVE-2023-42917 | Clement Lecigne (Google TAG) | memory corruption - actively exploited | TESTED DEAD (p602/p602b) |

### Safari 17.2 (Dec 11, 2023)
| CVE | Credit | Description | Priority |
|-----|--------|-------------|----------|
| CVE-2023-42890 | Pwn2car | code execution | MEDIUM |
| CVE-2023-42950 | Nan Wang (360 VRI) | code execution | MEDIUM |
| CVE-2023-42956 | SungKwon Lee | DoS | LOW |
| CVE-2023-42883 | Zoom Offensive Security Team | DoS | LOW |
| CVE-2023-43010 | Apple | unknown | LOW |

### Safari 17.3 (Jan 22, 2024)
| CVE | Credit | Description | Priority |
|-----|--------|-------------|----------|
| **CVE-2024-23213** | **Wangtaiyu (Zhongfu info)** | **memory handling - code execution** | **HIGH** |
| CVE-2024-23222 | anonymous | type confusion - actively exploited | TESTED DEAD (p606/p607) |
| CVE-2024-23206 | anonymous | fingerprinting | LOW |
| CVE-2024-23271 | James Lee | cross-origin logic issue | LOW |

## CRITICAL FINDING: CVE-2023-42916 (OOB Read -- JIT Related)

**This is the strongest info-leak candidate found in this research.** Key facts:
- **OOB READ** vulnerability in WebKit -- exactly the primitive class needed for a text
  base leak
- **Actively exploited in the wild** (CISA KEV, added 2023-12-04)
- Found by Clement Lecigne of Google TAG (same researcher who found CVE-2023-42917,
  which we already tested for the code execution part)
- Fixed in Safari 17.1.2 (Nov 30, 2023), meaning it was **present in Safari 17.0**
- PS5 14.10 ships WebKit 605.1.15 / Safari 17.0 -- **LIKELY VULNERABLE**
- Apple describes: "An out-of-bounds read was addressed with improved input validation"
- **Red Hat confirms: "related to the JIT code"** -- PS5 has DFG JIT active (p602)
- WebKit Bugzilla: 265041
- CWE-125 (Out-of-bounds Read)
- Used as the **info-leak stage** alongside CVE-2023-42917 (code execution stage) in
  targeted attacks against iOS < 16.7.1
- **Zero public PoCs verified on GitHub** (2026-11-09 search: 0 repos matching
  "CVE-2023-42916"; aggregator's "6 PoC" count is false)
- Impact: "Processing web content may disclose sensitive information" -- this is Apple's
  way of saying it leaks memory contents
- **WebKit Bugzilla 265041 is ACCESS-RESTRICTED** -- cannot view bug details, linked
  commits, or patches without authenticated access
- **Fix commit NOT publicly identifiable** -- Debian/Ubuntu/Red Hat patch trackers all
  bump the WebKitGTK version to 2.42.3 without referencing an upstream commit hash.
  WebKitGTK 2.42.3 release notes list only non-security fixes.

**Red Hat explicitly notes:** "out-of-bounds memory can expose addresses that help
bypass ASLR" and that their builds are unaffected because **JIT is disabled by default
in RHEL WebKitGTK builds** -- this confirms the vulnerability is IN the JIT code path.

**If this OOB read can be triggered from JS on PS5, it could leak heap or code pointers
directly -- exactly the info leak primitive the FontFace/Canvas2D chain needs.**

**Chain integration:**
```
CVE-2023-42916 (OOB read)  -->  WebProcess text base  -->  FontFace UAF forge
       |                              |                          |
  info leak stage               ASLR defeat              code-reuse chain
       |                              |                          |
  "sensitive info"              gadget addresses          kernel exploit entry
```

## Probe Design: CVE-2023-42916 (JIT OOB Read)

The fix commit is inaccessible, so probing must be based on the vulnerability class:
**JIT-related OOB read, fixed with "improved input validation."**

Common DFG JIT OOB read patterns in WebKit 605.1.15:
1. **Range analysis error** -- DFG miscomputes the range of an index, eliminates a
   bounds check, and JIT code reads past the end of an array or buffer
2. **Type confusion in JIT speculation** -- DFG speculates wrong type, accesses a
   structure at the wrong offset, reads adjacent memory
3. **Uninitialized register in OSR exit** -- DFG leaves a register uninitialized
   on a bailout path, and the interpreter reads it as an address
4. **GetByVal on TypedArray with incorrect length** -- JIT caches a stale length
   after resize/detach and reads past the end

Since PS5 has DFG JIT active (p602: 5M loop in 49ms) but NO FTL and NO WebAssembly,
the vulnerable code path must be in the DFG tier. The "input validation" fix suggests
the trigger involves user-controlled input that reaches the JIT without proper bounds
checking -- likely an array index or TypedArray offset.

**Probe strategy (requires console access):**
- p680: DFG array bounds elimination -- force DFG compilation with predictable indices,
  then feed an out-of-range index after compilation to trigger OOB read
- p681: TypedArray resize during DFG -- create ResizableArrayBuffer, DFG-compile a
  hot loop reading it, resize mid-loop to shrink, check if JIT reads past new end
- p682: Structure transition during DFG speculation -- change object shape after DFG
  compiles a property access, check if JIT reads at stale offset
- p683: DFG OSR exit with valueOf -- trigger OSR exit via valueOf callback that
  changes array type, check if post-exit code uses stale register

**Key measurement:** each probe reads BigUint64Array views of ArrayBuffer after the
trigger. Any non-zero value in a freshly-allocated buffer that looks like a code
pointer (not heap, not small integer) is the leak.

## Probe Design: CVE-2023-41976 (UAF -- Safari 17.1)

Apple's description: "A use-after-free issue was addressed with improved memory management."
No public PoC. Credited to Junsung Lee, who also found CVE-2023-40447 and CVE-2023-41983
in the same Safari 17.1 batch. The clustering suggests Junsung Lee found a family of
related issues in the same WebKit component.

Since the exact component is unknown, probes target the most common UAF patterns in
WebKit 605.1.15 that were NOT already tested by our existing campaign:

- **p684: DOM mutation observer UAF** -- create a MutationObserver, trigger a DOM subtree
  removal that frees observed nodes, then access the observer's record list. If the
  records hold stale node pointers, reading them could leak freed-memory content.
- **p685: Range/Selection UAF** -- create a Range spanning a DOM subtree, remove the
  subtree (causing the range's boundary nodes to be freed), then call
  `range.cloneContents()` or `range.toString()`. Stale boundary pointers may dereference
  freed memory.
- **p686: SVG animation UAF** -- SVG `<animate>` elements hold pointers to their target
  elements. Remove the target while the animation is running, then force a repaint.
  The animation's stale target pointer may dereference freed memory.

## Probe Design: CVE-2023-42852 ("Improved Checks" -- Safari 17.1)

Apple's description: "A logic issue was addressed with improved checks." This is the
vaguest possible description, covering anything from bounds checking to type validation.

Most likely vulnerability classes for "improved checks" in WebKit:
1. Missing bounds check on array/buffer access
2. Missing type check before a cast
3. Missing null check before dereference
4. Missing permission/origin check

- **p687: CSS calc() integer overflow** -- `calc()` expressions with deeply nested
  operations can overflow intermediate integer values. If the result is used as a
  length for a buffer allocation or array index without a final bounds check, this
  could produce an undersized allocation or OOB access. Test with
  `width: calc(99999999px * 99999999)` and similar expressions that overflow 32-bit int.
- **p688: CSS counter-style OOB** -- `@counter-style` with a symbols descriptor
  containing an excessive number of entries or with `range` values that overflow.
  The counter formatting code may index past the symbol array bounds.

## Probe Design: CVE-2024-23213 (Memory Handling -- Safari 17.3)

Apple describes "improved memory handling" -- distinct from both "improved memory
management" (usually UAF) and "improved checks" (usually logic). This phrasing often
means a buffer lifetime or ownership error.

- **p689: Fetch API response body lifetime** -- start a fetch(), read the response as
  a ReadableStream, close the stream mid-read, then attempt to access the partially-read
  chunks. The response body buffer may be freed when the stream closes while the chunks
  still reference it.
- **p690: TextDecoder streaming decode** -- create a TextDecoder with `stream: true`,
  feed it partial multi-byte sequences, then decode a final chunk. The internal state
  buffer holding the incomplete sequence may be freed incorrectly between calls.

## Conclusion

**CVE-2023-42916 (OOB read, Safari 17.1.2 fix) is the top-priority research target.**
It is an out-of-bounds READ -- the exact primitive class needed for the WebProcess text
base leak. Combined with the confirmed Canvas2D or FontFace UAF write primitives, an
OOB read providing an addrof or code pointer leak would complete the exploit chain.

**CVE-2024-23213** (memory handling, Safari 17.3 fix) is the second priority -- it could
provide a UAF or buffer error if the OOB read route fails.

**CVE-2023-41976** (UAF, Safari 17.1 fix) is the third priority -- same vulnerability
class as our working FontFace/Canvas2D exploits.

**Five additional untested CVEs** from Safari 17.1/17.2 are potential fallbacks.

The StructureID prediction technique remains the best CVE-independent approach.

**NEXT STEPS (ordered by impact):**
1. **Run CVE-2023-42916 probe battery (p680-p683)** when console is online -- four
   DFG JIT OOB read trigger patterns covering the most likely vulnerability classes.
   Any leaked code pointer solves the WebProcess text base blocker.
2. Research CVE-2024-23213 commit (Bugzilla 266619) and assess exploitability
3. Test StructureID randomization on PS5 14.10
4. Systematically test Safari 17.1/17.2 CVEs that produce code execution
5. Community ask: anyone with WebKit Bugzilla access who can read bug 265041 and
   share the component/files-changed (not the exploit) would unlock targeted probing
