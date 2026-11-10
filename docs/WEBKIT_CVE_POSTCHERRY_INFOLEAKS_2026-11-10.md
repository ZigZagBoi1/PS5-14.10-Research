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

**Caution (2026-11-10):** p659 tested CVE-2026-43740 as a YARR regex bug and found it
PATCHED on PS5 14.10. However, the Bugzilla ID 308046 needs verification -- it is possible
that p659 tested a different bug with a similar CVE number, or that this specific YARR
path was cherry-picked while the broader UAF was not. The advisory description ("memory
handling", not "regex") suggests a different component than YARR.

**Action:** retrieve the actual WebKit commit for Bugzilla 308046 and verify whether it
is the same YARR fix tested in p659 or a separate bug. If separate, build a trigger.

## Priority 2: CVE-2026-112699 (OOB Read Info Leak)

- **Fixed:** Safari 27.2, October 26, 2026
- **Advisory text:** "Processing maliciously crafted web content may result in the
  disclosure of process memory"
- **Fix description:** "An out-of-bounds read was addressed with improved bounds checking"
- **Bug class:** OOB read (CWE-125)
- **Credited to:** Anonymous researcher
- **WebKit Bugzilla:** 323130

**Why this matters:** An OOB read is a cleaner info-leak primitive than a UAF -- it reads
past an object's boundary into adjacent heap data, which often contains object headers,
tagged pointers, or vtable addresses. No timing or reclaim race needed.

**Action:** retrieve the commit diff for Bugzilla 323130. The fix ("improved bounds
checking") implies a specific array/buffer access path that can be triggered from JS.
Identify the path and build a PoC.

## Priority 3: CVE-2026-112680 (OOB Read Info Leak)

- **Fixed:** Safari 27.2, October 26, 2026
- **Advisory text:** same as CVE-2026-112699
- **Fix description:** same as CVE-2026-112699
- **Bug class:** OOB read (CWE-125)
- **Credited to:** Franz Bettag, Kwak Kiyong, Song Nuri
- **WebKit Bugzilla:** 323148

**Why this matters:** Two independent OOB read info leaks in the same release suggests a
pattern in the codebase -- possibly related subsystems or shared vulnerable code.

**Action:** same as CVE-2026-112699. Compare the two fixes for shared vulnerable paths.

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

1. **Retrieve WebKit commits** for Bugzilla 308046, 323130, 323148, 321982
   - WebKitGTK's WSA-2026-0004 advisory maps Bugzilla IDs to public commits
   - The commit diffs reveal the vulnerable code paths and trigger conditions
2. **Verify CVE-2026-43740 identity** -- is Bugzilla 308046 the YARR bug tested in
   p659, or a separate UAF? If separate, this is the top priority.
3. **Build trigger PoCs** for confirmed candidates
4. **Test on PS5 14.10** when console access is available

## Evidence Grade

All findings are [S] (source-read from Apple security advisories and CVE databases).
No device testing has been performed. The cherry-pick cutoff is [M] (device-confirmed
by p659-p671 campaign). JIT independence is [I] (inferred from advisory descriptions
naming "memory handling" and "bounds checking", not "JIT" or "compiler").
