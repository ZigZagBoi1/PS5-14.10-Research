# VP-Slot Delta Corrections (PR #240 review)

**Source:** cobrajet302gt adjudication comment on PR #240, 2026-11-09
**Status:** corrected arithmetic on committed p691 beacon data

## Background

PR #240's walk chain leaked VP = `0x80f4b9b28` and 8 vtable slots from one
successful capture on 192.168.1.37. The PR's summary published inter-slot
deltas, but the arithmetic contained transcription errors. Corrected values
below are computed from the committed beacon log.

## Committed beacon values (p691, one boot)

| Slot | Value          | Identity (Itanium ABI)             |
|------|----------------|------------------------------------|
| s0   | 0x80dda8fb0    | ~Client() complete destructor      |
| s1   | 0x80dda8fe0    | ~Client() deleting destructor      |
| s2   | 0x80c26d750    | fontLoaded (inherited, no override)|
| s3   | 0x80dda96b0    | fontStateChanged (override at CSSFontFaceSet.cpp:524) |
| s4   | 0x80c26d750    | fontPropertyChanged (*)            |
| s5   | 0x80c26d750    | updateStyleIfNeeded (inline-empty, final, CSSFontFaceSet.h:94) |
| s6   | 0x80d9ff400    | ref                                |
| s7   | 0x80dda9810    | deref                              |
| s8   | 0x0            | past-end (NOT a null terminator)   |
| VP   | 0x80f4b9b28    | CSSFontFace::Client vtable pointer |

## Corrected deltas (VP - slot)

| Delta   | Corrected     | PR #240 published | Slip        |
|---------|---------------|--------------------|-------------|
| VP-s0   | 0x171_0B78    | 0x170_0B78         | -0x10000    |
| VP-s1   | 0x171_0B48    | (not published)    | --          |
| VP-s2   | 0x324_C3D8    | 0x324_C3D8         | matches     |
| VP-s3   | 0x171_0478    | 0x170_0478         | -0x10000    |
| VP-s6   | 0x1AB_A728    | (not published)    | --          |
| VP-s7   | 0x171_0318    | 0x170_0318         | -0x10000    |

**NOTE:** The `0x10000` slip pattern suggests a systematic carry error in the
original subtraction. s2 and s6 were corrected a second time on 2026-11-10:
this doc previously carried VP-s2 = `0x2CE_C3D8` ("matches") and VP-s6 =
`0x14B_A728` ("check"), both wrong against this doc's own slot table
(s2 = `0x80c26d750`, s6 = `0x80d9ff400`, VP = `0x80f4b9b28`). The canonical
six, one frame, buffer-absolute from VP `0x80f4b9b28`:
s0 `0x1710B78` · s1 `0x1710B48` · s2 `0x324C3D8` · s3 `0x1710478` ·
s6 `0x1ABA728` · s7 `0x1710318` — identical to the p804 expected-value
header, so boots may spend against either source. A bench anchoring through
the stale `0x2CEC3D8` lands `0x560000` low and reads its own mapping slip as
a structural negative. (Second-pass correction: cobrajet302gt post-merge
audit, PR #240 comment, 2026-11-10.)

## s2=s4=s5 anomaly

cobrajet302gt's WebKit 616 source drop shows `fontPropertyChanged` (s4) is
NOT empty -- it contains `m_cache.clear()`, faces-table rebuild, and observer
`forEach`. The source predicts s4 != s2, but the beacon shows s4 == s2.

Two explanations:
1. **Fork drift:** the 14.10 fork carries an empty/absent fontPropertyChanged
   override (different from the source drop)
2. **ICF (Identical Code Folding):** the linker merged the function bodies

**Pre-registered arm (cobrajet):** dump 16 bytes at s2 and at s4 addresses.
Byte-identical = one function (fork drift row). Different = s4 mislabel.

## Delta invariance test

The assumption `base = VP - RVA` requires that ALL VP-slot deltas reproduce
exactly under a different ASLR slide. If any delta moves across boots, the
image is not one sliding mapping, and VP anchors a segment, not the base.

**Pre-registered arm (cobrajet):** on next boot, verify all six deltas match
the corrected values exactly.

## Key corrections from cobrajet review

1. **605.1.15 is the UA token, not a tree generation.** The fork internally
   reports MAJOR_VERSION 616 (Configurations/Version.xcconfig). Apple's
   605.1.15 upstream has no libpas, no OptionsPlayStation.cmake. Source
   analysis must target the 616-era fork, not an Apple 605.1.15 tag.

2. **A vtable RVA is a link-time fact, not a source fact.** .rodata placement
   depends on link order, section packing, and ICF. No source drop yields it
   without the link map or binary.

3. **Cheapest anchor if procfs works:** `/proc/<pid>/auxv` gives AT_PHDR,
   then `AT_PHDR - e_phoff = base`, making `RVA = VP - base` a one-syscall
   measurement. No source analysis needed.

4. **Crash-as-instrument (error-history):** generic for WebProcess faults on
   14.10 and 14.22 retail -- zero frames, no free partial base.

5. **s8=0 is past-end, not a null terminator.** C++ vtables are not
   NULL-terminated; s8 is the qword after the last slot (padding or next
   table).

6. **IsoMalloc OFF confirmed.** `USE_ISO_MALLOC PRIVATE OFF` at line 211 of
   OptionsPlayStation.cmake. Reclaim follows bmalloc/libpas size-class
   routing, not IsoHeap free lists.
