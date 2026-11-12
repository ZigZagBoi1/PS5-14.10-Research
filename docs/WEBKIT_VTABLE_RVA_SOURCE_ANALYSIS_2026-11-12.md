# WebKit Vtable RVA — Source-Level Resolution of the s2=s4=s5 Anomaly

**Author:** jsrkamal2002
**Date:** 2026-11-12
**Status:** [S] source-grounded (WebKitGTK 2.42.0 tarball, Safari 17.0-era tree)
**Grade:** S (source read) — resolves one open arm of `docs/VP_SLOT_DELTAS_CORRECTED.md`

## Purpose

cobrajet302gt's PR #240 review (`docs/VP_SLOT_DELTAS_CORRECTED.md`, section
"s2=s4=s5 anomaly") left an open question. The p691 beacon shows three vtable
slots pointing at the SAME address:

| Slot | Identity (per review) | Beacon value |
|------|----------------------|--------------|
| s2   | fontLoaded           | 0x80c26d750  |
| s4   | fontPropertyChanged  | 0x80c26d750  |
| s5   | updateStyleIfNeeded  | 0x80c26d750  |

But cobrajet's WebKit 616 source drop shows `fontPropertyChanged` (s4) is NOT
empty — it contains `m_cache.clear()`, a faces-table rebuild, and an observer
`forEach`. The source predicts s4 != s2, yet the beacon shows s4 == s2. The
review offered two explanations: (1) fork drift, (2) ICF (Identical Code
Folding).

This document resolves the anomaly at source level WITHOUT needing the
pre-registered 16-byte dump arm: **the leaked VP belongs to a vtable whose
class does NOT override `fontPropertyChanged` at all.** The beacon and the
source agree once the correct vtable is identified.

## Finding: two distinct Client implementations

`CSSFontFace::Client` (`Source/WebCore/css/CSSFontFace.h:127`) is an abstract
interface with five virtual callbacks, all with empty default bodies except
the pure `ref()`/`deref()`:

```cpp
class Client : public CanMakeWeakPtr<Client> {
public:
    virtual ~Client() = default;
    virtual void fontLoaded(CSSFontFace&) { }                                  // EMPTY
    virtual void fontStateChanged(CSSFontFace&, Status, Status) { }            // EMPTY
    virtual void fontPropertyChanged(CSSFontFace&, CSSValueList* = nullptr) { }// EMPTY
    virtual void updateStyleIfNeeded(CSSFontFace&) { }                         // EMPTY
    virtual void ref() = 0;
    virtual void deref() = 0;
};
```

There are (at least) two concrete subclasses in the tree:

1. **`CSSFontFaceSet`** (`Source/WebCore/css/CSSFontFaceSet.h:44`):
   `class CSSFontFaceSet final : public RefCounted<CSSFontFaceSet>, public CSSFontFace::Client`.
   It OVERRIDES three of the five callbacks with real bodies:
   - `fontStateChanged(...)` — `final` (CSSFontFaceSet.h:105), real body in .cpp
   - `fontPropertyChanged(...)` — `final` (CSSFontFaceSet.h:106), real body
     (`m_cache.clear()` + `removeFromFacesLookupTable`/`addToFacesLookupTable`
     + observer `forEach`, CSSFontFaceSet.cpp:540)
   - `updateStyleIfNeeded(...)` — `final` but **empty inline**
     (`{ }`, CSSFontFaceSet.h:94)
   It does NOT override `fontLoaded` — inherits the empty `Client::fontLoaded`.

2. **`FontFace`** (`Source/WebCore/css/FontFace.h`) — the wrapper JS holds — is
   also a `CSSFontFace::Client`. (Note: the UAF frees the backing `CSSFontFace`,
   NOT the wrapper — the wrapper stays alive and rooted, holding `m_backing` as
   a dangling strong ref to the freed face slot. See the correction note below.)
   It overrides:
   - `fontStateChanged(...)` — `final` (FontFace.h:92)
   - `ref()`/`deref()` — `final` (FontFace.h:94-95)
   It does **NOT** override `fontLoaded`, `fontPropertyChanged`, or
   `updateStyleIfNeeded` — it inherits all three empty `Client::` bodies.

## Why the beacon shows s2 == s4 == s5

The p691 walk chain read VP out of the freed `CSSFontFace`'s client set, via
the **alive, rooted `FontFace` wrapper** (the 192B ArrayBuffer spray reclaims
the freed face slot; the wrapper is the client registered in that set). The
relevant vtable is the wrapper's secondary `CSSFontFace::Client` table at
FontFace+0x20 (`docs/FONTFACE_ITANIUM_ABI_RESOLUTION.md`).

For `FontFace`'s Client table:
- s2 `fontLoaded`          = `Client::fontLoaded`          (empty, inherited)
- s4 `fontPropertyChanged` = `Client::fontPropertyChanged` (empty, inherited)
- s5 `updateStyleIfNeeded` = `Client::updateStyleIfNeeded` (empty, inherited)

All three are the same empty function body `{ }`. Under the linker, three
identical empty bodies fold to ONE address (Identical Code Folding, or simply
three out-of-line copies of an empty function that the linker coalesces). The
beacon therefore reads the same address at s2, s4, s5 — **exactly as observed
(0x80c26d750)**.

The anomaly dissolves: it is NOT fork drift and NOT a mislabel. The leaked
table is `FontFace`'s Client vtable, in which all three callbacks are the
shared empty `Client::` implementation. cobrajet's source observation
(`fontPropertyChanged` non-empty) describes `CSSFontFaceSet`'s override —
a DIFFERENT vtable that is not the one VP points to.

## Consequence for the pre-registered arms

- The "dump 16 bytes at s2 and s4" arm (`VP_SLOT_DELTAS_CORRECTED.md`) is now
  moot at source level: s2 == s4 is expected, not anomalous. Byte-identical
  dumps would merely re-confirm ICF of two empty bodies.
- The vtable-slot identities for a `FontFace::Client` table are:
  - s0 = ~Client() complete destructor
  - s1 = ~Client() deleting destructor
  - s2 = fontLoaded (empty)
  - s3 = fontStateChanged (FontFace override, REAL body) ← discriminating slot
  - s4 = fontPropertyChanged (empty)
  - s5 = updateStyleIfNeeded (empty)
  - s6 = ref (FontFace override)
  - s7 = deref (FontFace override)

  **s3 (fontStateChanged) is the only callback slot with a real, class-specific
  body.** Its delta VP-s3 = 0x171_0478 (corrected) is the most informative
  single slot for validating the table identity on-device, because it is the
  one slot that is guaranteed NOT to fold to the empty-function address.

## Measured confirmation (companion build, 2026-11-12)

The WebCore-enabled reproduction build (`Build-wc`, same tree and flags as the
text_size build) compiled the two unified sources that carry these classes. The
relocation records and disassembly CONFIRM the source-level model above — this
upgrades the slot-identity claim from [S] to [M-on-reproduction]:

From `objdump -r` on `UnifiedSource-2f84417a-13.cpp.o` (contains `FontFace.cpp`),
the `FontFace` vtable `_ZTVN7WebCore8FontFaceE` (size 0xb8) has its secondary
`CSSFontFace::Client` address point at +0x70, with these slot relocations:

| Offset | Relocation target | Slot | Identity |
|--------|-------------------|------|----------|
| +0x78 | `_ZThn32_N7WebCore8FontFaceD1Ev` | s0 | ~FontFace complete-dtor thunk |
| +0x80 | `_ZThn32_N7WebCore8FontFaceD0Ev` | s1 | ~FontFace deleting-dtor thunk |
| +0x88 | `_ZN7WebCore11CSSFontFace6Client10fontLoadedERS0_` | s2 | Client::fontLoaded (empty) |
| +0x90 | `_ZThn32_N7WebCore8FontFace16fontStateChangedE...` | s3 | FontFace::fontStateChanged thunk (REAL) |
| +0x98 | `_ZN7WebCore11CSSFontFace6Client19fontPropertyChangedE...` | s4 | Client::fontPropertyChanged (empty) |
| +0xa0 | `_ZN7WebCore11CSSFontFace6Client20updateStyleIfNeededE...` | s5 | Client::updateStyleIfNeeded (empty) |
| +0xa8 | `_ZThn32_N7WebCore8FontFace3refEv` | s6 | FontFace::ref thunk |
| +0xb0 | `_ZThn32_N7WebCore8FontFace5derefEv` | s7 | FontFace::deref thunk |

Disassembly of the three base `Client::` virtuals confirms each is a single-byte
empty body (`0xc3 ret`):

  Client::fontLoaded          -> ret
  Client::fontPropertyChanged -> ret
  Client::updateStyleIfNeeded -> ret

Three identical one-byte `ret` bodies fold to one address under link-time ICF —
exactly why the on-device beacon reads the same address at s2, s4, s5
(0x80c26d750). And `FontFace::fontStateChanged` (s3) disassembles to a real
multi-instruction prologue (`push %r15; push %r14; push %r13; ...`), confirming
it is the one non-empty, class-specific callback — the discriminating slot.

This is a reproduction-build measurement, not an on-device one: the GTK build's
ICF coalesces the three empty bodies the same way Sony's link does, so it
validates the MECHANISM. It does not give the PS5's absolute slot addresses.

## Bearing on the RVA blocker

The RVA itself (VP - WebProcess_base) remains open — it is a link-time fact
and cannot be read from source (`VP_SLOT_DELTAS_CORRECTED.md` correction #2).
This document does NOT advance the RVA number. It only fixes WHICH vtable VP
anchors, which is a prerequisite for correctly interpreting any future
slot-delta measurement (e.g., p804's delta-invariance beacon) and for the
link-time reproduction estimate.

## Source basis

- Tree: WebKitGTK 2.42.0 stable tarball (`webkitgtk-2.42.0.tar.xz`, 40,917,832
  bytes, webkitgtk.org). This is the closest public tree to the PS5's
  Safari 17.0-era (616-internal) fork.
- `Source/WebCore/css/CSSFontFace.h:127` — Client interface (all-empty virtuals)
- `Source/WebCore/css/CSSFontFaceSet.h:44,94,105,106` — CSSFontFaceSet overrides
- `Source/WebCore/css/CSSFontFaceSet.cpp:540` — fontPropertyChanged real body
- `Source/WebCore/css/FontFace.h:92,94,95` — FontFace overrides (no
  fontLoaded/fontPropertyChanged/updateStyleIfNeeded)
- PlayStation config confirms `USE_ISO_MALLOC PRIVATE OFF` and all JIT tiers
  OFF (OptionsPlayStation.cmake:160-165), consistent with the on-device LLInt-only
  measurement (p573) and the reclaim model.
