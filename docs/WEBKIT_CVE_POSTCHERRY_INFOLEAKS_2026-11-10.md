# WebKit Post-Cherry-Pick Info Leak CVEs -- PS5 14.10 Candidate Analysis

> **Date:** 2026-11-10
> **Context:** PS5 14.10 build date Sep 28, 2026. Sony cherry-picked WebKit fixes through
> Safari 26.3 (Feb 2026). Fixes from Safari 26.4+ are NOT included (fingerprinted by
> p659-p671 campaign). PS5 WebKit is LLInt-only (no DFG/FTL/JIT).

## The Cherry-Pick Gap

Apple shipped **3 confirmed "disclosure of process memory" WebKit CVEs** after Sony's cutoff:

| CVE | Fixed In | Impact | Bug Class | JIT Required |
|-----|----------|--------|-----------|--------------|
| CVE-2026-43740 | Safari 26.5.2 (Jun 2026) | Process memory disclosure | UAF (CWE-416) | NO |
| CVE-2026-112699 | Safari 27.2 (Oct 2026) | Process memory disclosure | OOB read (CWE-125) | NO |
| CVE-2026-112680 | Safari 27.2 (Oct 2026) | Process memory disclosure | OOB read (CWE-125) | NO |

All three are described as non-JIT bugs (memory handling / bounds checking). All three
are fixed well after the Feb 2026 cherry-pick cutoff. PS5 14.10 almost certainly carries
all of them.

## Priority 1: CVE-2026-43740 (UAF Info Leak)

- **Fixed:** Safari 26.5.2, June 29, 2026
- **Advisory text:** "Processing maliciously crafted web content may result in the
  disclosure of process memory"
- **Fix description:** "The issue was addressed with improved memory handling"
- **Bug class:** Use-after-free (CWE-416 per Red Hat; CWE-119/CWE-200 per NVD)
- **Credited to:** Nathaniel Oh (`@calysteon`), Arni Hardarson
- **WebKit Bugzilla:** 308046

**Why this matters:** A UAF that discloses process memory is exactly the primitive the
FontFace chain needs. If the freed memory contained a vtable pointer or function pointer,
reading it after free (before reclaim) would directly expose the WebProcess text base.

**CONFIRMED DEAD (2026-11-10):** Bugzilla 308046 is public. Title: "Fix incorrect offset
when reading pattern character for Unicode backreference in JIT." Component: JSC/YARR.
Fix commit: 2693828e8d73 (upstream main, 2026-02-18), PR #58848. This IS the YARR JIT
bug that p659 already tested and found PATCHED on PS5 14.10. The advisory's "disclosure
of process memory" description was about this specific YARR regex JIT offset bug.
Sony cherry-picked it despite it being a JIT path -- likely because the fix date
(Feb 2026) falls within their cherry-pick window (through Safari 26.3).

**This CVE is DEAD. Remove from candidate list.**

## ~~Priority 2: CVE-2026-112699 (OOB Read Info Leak)~~ -- DEAD (WebGPU)

- **Fixed:** Safari 27.2, October 26, 2026
- **WebKit Bugzilla:** 323130
- **Commit:** 411a4c9 (mwyrzykowski)
- **Title:** "drawIndexed validation cache not invalidated on sub-global-max writeBuffer
  -> GPU OOB read"
- **Component:** WebGPU (Source/WebGPU/WebGPU/Buffer.h, Buffer.mm, RenderPassEncoder.mm)

**DEAD on PS5 14.10:** This is a WebGPU drawIndexedIndirect bug. WebGPU is NOT available
on PS5 14.10 -- the API does not exist in the 605.1.15 era WebKit build. The "disclosure
of process memory" impact applies to platforms with WebGPU (macOS, iOS with Metal).

## ~~Priority 3: CVE-2026-112680 (OOB Read Info Leak)~~ -- DEAD (WebGPU)

- **Fixed:** Safari 27.2, October 26, 2026
- **WebKit Bugzilla:** 323148
- **Commit:** cb21dfb (mwyrzykowski)
- **Title:** "[WebGPU] drawIndexedValidated promotes an unvalidated whole-payload max
  index as a validated ceiling, causing GPU OOB"
- **Component:** WebGPU (Source/WebGPU/WebGPU/Buffer.h, Buffer.mm)

**DEAD on PS5 14.10:** Same as above. Both OOB read info leaks are in the WebGPU
drawIndexed validation pipeline. PS5 has no WebGPU.

## Additional Candidates (Type Confusion / ACE Class)

| CVE | Fixed In | Impact | Bug Class | Bugzilla |
|-----|----------|--------|-----------|----------|
| CVE-2026-43705 | Safari 26.5.2 (Jun 2026) | Memory corruption | Type confusion | -- |
| CVE-2026-112659 | Safari 27.2 (Oct 2026) | Arbitrary code execution | Type confusion | 321982 |
| CVE-2026-86974 | Safari 27.2 (Oct 2026) | Memory corruption | Type confusion | 321609 |
| CVE-2026-113903 | Safari 27.2 (Oct 2026) | Memory modification | UAF | 321652 |

CVE-2026-112659 is especially interesting: ACE-grade type confusion could skip the info
leak step entirely if it works under LLInt. Credited to OpenAI Codex Security and
Anthropic Research -- likely a high-quality bug report with clear trigger conditions.

## Next Steps

1. **CVE-2026-43740 is DEAD** -- confirmed as the YARR JIT bug (Bugzilla 308046),
   already tested and found patched on PS5 14.10 by p659.
2. **Monitor WebKitGTK advisory releases** -- WSA-2026-0007 will map these Bugzilla
   IDs to public commits when it ships (WSA-2026-0006 is the latest, Sep 2026).
3. **Search WebKit GitHub commit log** for commits referencing 323130, 323148, 321982
   -- commit messages often include the Bugzilla ID even when the bug is restricted.
4. **Build trigger PoCs** once commit diffs are accessible.
5. **Test on PS5 14.10** when console access is available.
6. **Alternative:** search the WebKit git log for "out-of-bounds read" fixes committed
   between Jul-Oct 2026 that are NOT in Sony's cherry-pick set.

## Evidence Grade

All findings are [S] (source-read from Apple security advisories and CVE databases).
No device testing has been performed. The cherry-pick cutoff is [M] (device-confirmed
by p659-p671 campaign). JIT independence is [I] (inferred from advisory descriptions
naming "memory handling" and "bounds checking", not "JIT" or "compiler").
