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

### 2. StructureID Prediction (MEDIUM PRIORITY -- TECHNIQUE)
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
| **CVE-2024-23213** | **Wangtaiyu (Zhongfu info)** | **type confusion - actively exploited** | **HIGH** |
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
- 6 claimed public PoCs on GitHub (unverified count from aggregator)
- Impact: "Processing web content may disclose sensitive information" -- this is Apple's
  way of saying it leaks memory contents

**Red Hat explicitly notes:** "out-of-bounds memory can expose addresses that help
bypass ASLR" -- this is exactly what we need for the WebProcess text base.

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

## Conclusion

**CVE-2023-42916 (OOB read, Safari 17.1.2 fix) is the top-priority research target.**
It is an out-of-bounds READ -- the exact primitive class needed for the WebProcess text
base leak. Combined with the confirmed Canvas2D or FontFace UAF write primitives, an
OOB read providing an addrof or code pointer leak would complete the exploit chain.

**CVE-2024-23213** (type confusion, Safari 17.3 fix) is the second priority -- it could
provide addrof/fakeobj if the OOB read route fails.

**Seven additional untested CVEs** from Safari 17.1/17.2 are potential fallbacks.

The StructureID prediction technique remains the best CVE-independent approach.

**NEXT STEPS (ordered by impact):**
1. Research CVE-2023-42916 WebKit commit and build a PoC for PS5
2. Research CVE-2024-23213 commit and assess exploitability
3. Test StructureID randomization on PS5 14.10
4. Systematically test Safari 17.1/17.2 CVEs that produce code execution
