# WebKit text_size Build Estimate — JSC Component (LLInt-only)

**Author:** jsrkamal2002
**Date:** 2026-11-12
**Status:** [M] measured on a local reproduction build (GTK port, JIT-off)
**Grade:** M (measured) for the build; the PS5 inference is [I]

## Purpose

The WebProcess text-base RVA blocker reduces to one unknown: `text_size`
(`docs/VP_SLOT_DELTAS_CORRECTED.md`, `results/phase13_webkit/p710_...txt`).
On-device (p710) we have:

  RVA = text_size + 0x76DB28
  RVA & 0x3FFF = 0x1B28
  RVA > 0x324C3D8          (VP - s2)
  text_size >= 42.87 MB    (from s2, a known .text function)

No public 14.10 WebProcess binary exists, and the RVA is a link-time fact that
source alone cannot yield. This document measures the JavaScriptCore (JSC)
component of `text_size` on a faithful local reproduction build, to bound and
decompose the total.

## Build configuration (matches PS5 14.10 measured config)

Source: WebKitGTK 2.42.0 stable tarball (closest public tree to the PS5's
Safari 17.0-era / 616-internal fork). Port: GTK (the PlayStation port requires
Sony's closed SDK / PlayStationModule CMake helpers and cannot configure on a
plain Linux host). Compiler: GCC 14.3.1, `-DCMAKE_BUILD_TYPE=Release`, Ninja.

Feature flags set to match the on-device p573 measurement and
`OptionsPlayStation.cmake` (all JIT tiers OFF, IsoMalloc OFF):

  ENABLE_JIT = OFF
  ENABLE_DFG_JIT = OFF
  ENABLE_FTL_JIT = OFF
  ENABLE_B3_JIT = OFF (derived: only set when FTL_JIT on, PlatformEnable.h:716)
  USE_ISO_MALLOC = OFF

Verified effective values in the force-included `cmakeconfig.h`
(`-DHAVE_CONFIG_H=1`):

  #define ENABLE_JIT 0
  #define ENABLE_DFG_JIT 0
  #define ENABLE_FTL_JIT 0
  #define ENABLE_WEBASSEMBLY 0
  #define ENABLE_WEBASSEMBLY_B3JIT 0
  #define ENABLE_WEBASSEMBLY_BBQJIT 0
  #define ENABLE_C_LOOP 0   (native x86-64 offlineasm backend, like the PS5)

The 134 dfg / 35 ftl / 123 b3 / 97 wasm .cpp files in Sources.txt are each
wrapped in `#if ENABLE(<tier>)` guards (verified on DFGAbstractValue.cpp,
FTLLowerDFGToB3.cpp, B3BasicBlock.cpp, WasmModule.cpp), so with all tiers OFF
they compile to empty translation units. Residual DFG/FTL/B3/Wasm symbol text
in the linked library totals **8,191 bytes** (measured via `nm --print-size`),
i.e. ~0.008 MB of stub — negligible. This is a genuine LLInt-only build.

## Measurement

Artifact: `lib/libjavascriptcoregtk-4.1.so.0.4.9` (JSC + WTF + bmalloc linked
as a shared object, hidden visibility).

  .text   = 11,913,906 bytes  = 11.36 MB
  .rodata =    885,768 bytes  =  0.84 MB
  Total image = 15,745,253 bytes

`bin/jsc` (the shell, static-thin) .text = 293,133 bytes (shell driver only;
the engine itself lives in the shared lib above).

## Interpretation

The full WebProcess `text_size` (>= 42.87 MB measured on-device) is the sum of:

  text_size = JSC + WebCore + WebKit + PAL + bmalloc + WTF + ICU + support libs

The JSC component measured here (**~11.4 MB .text**) is therefore a FLOOR for
one part of that total. The WebCore component has now been measured on the
companion build (see "WebCore component" below): **55.71 MB .text** — WebCore
alone exceeds the 42.87 MB on-device lower bound, which shows how loose that
bound is (it was measured from s2, not from base).

This does NOT yield the RVA directly. `text_size` is a link-time fact that
depends on Sony's exact link order, section packing, and ICF
(`VP_SLOT_DELTAS_CORRECTED.md` correction #2). A GTK build reproduces the
feature set but NOT the exact link layout, so the absolute `text_size` will
differ from the PS5's. What this measurement provides:

1. A grounded decomposition: JSC ≈ 11.4 MB of the >= 42.87 MB total.
2. Confirmation that a JIT-off build shrinks JSC dramatically (a JIT-on x86-64
   build of the same tree would add DFG/FTL/B3/wasm codegen — several MB more).
   The on-device >= 42.87 MB total is consistent with an LLInt-only engine.
3. A two-component anchor (completed 2026-11-15): JSC + WebCore = 11.36 +
   55.71 = **67.07 MB .text** measured across the two builds. See below.

## Caveats

- GTK port, not PlayStation port. The PlayStation link uses Sony's toolchain,
  `--wrap=mmap`, `sign()`, and module shims (OptionsPlayStation.cmake) that the
  GTK build does not. Absolute `text_size` differs.
- ICU here is system ICU 74.2; the PS5 links Sony's ICU. Different size.
- The 42.87 MB figure is a LOWER bound (measured from s2, not from base), so the
  true `text_size` is somewhat larger than 42.87 MB regardless.

## WebCore component (companion measurement, 2026-11-15)

Build: `Build-wc`, same tree (WebKitGTK 2.42.0), same flags, same compiler.
cmakeconfig.h verified identical on the relevant flags: ENABLE_JIT/DFG/FTL/
WASM all 0, plus USE_ISO_MALLOC 0 and USE_SYSTEM_MALLOC 0 (the PlayStation
port config values, matching the chain-plan corrections of 2026-11-14).

Method: in this tree's GTK port, WebCore is statically linked into
libwebkit2gtk (no libWebCore.so exists), so .text was measured per object
file over the complete `WebCore.dir` object set and summed. All 860 objects
on disk were complete (the earlier full build attempt died only at the
WebKit-layer DMABuf sources — an unrelated upstream bug where SourcesGTK.txt
compiles Accelerated{BackingStore,Surface}DMABuf.cpp unconditionally even
with USE_GBM=OFF; those two files are not in the WebCore target). Object-set
decomposition verified disjoint by construction: 547 unified-source objects
(4,656 .cpp files) + 104 unscanned objects (@no-unify / generated); zero
overlap. Section filter: PROGBITS + SHF_EXECINSTR (.text, .text.unlikely,
etc.), parsed from `readelf -SW`.

  WebCore .text total = 55,710,067 bytes = 55.71 MB
    unified-source objects:   54.65 MB
    unscanned objects:         1.06 MB
    (209 objects carry 0 text — name tables, derived sources)

Two-component anchor:

  JSC (11.36 MB) + WebCore (55.71 MB) = 67.07 MB .text

Interpretation and caveat. WebCore alone (55.71 MB) already exceeds the
on-device >= 42.87 MB lower bound. This does not contradict the on-device
measurement — that bound was taken from s2 (a mid-text function), not from
base — but it does quantify how loose it is: the true on-device text_size is
very likely tens of MB above 42.87 MB. Direction of the GTK-vs-PlayStation
skew: the GTK build INCLUDES code the PlayStation port drops
(cairo/freetype/harfbuzz font stack, gstreamer media, texmap/nicosia
compositing, GTK accessibility), so the PlayStation WebCore component is
likely SMALLER than 55.71 MB; both ports share the same DOM/CSS/layout/render
core that dominates the number. Treat 55.71 MB as the WebCore share anchor
(~80% of a Sony text plausibly in the 45-70 MB range), and note the
consequence for the p809/p810 rodata-backwalk / gadget-scan probes: the
address range to cover from a leaked .rodata pointer back to .text base is
much larger than the 42.87 MB figure suggested.

The FontFace::Client vtable layout cross-check mentioned in the original
next-step was already resolved at source level (see
WEBKIT_VTABLE_RVA_SOURCE_ANALYSIS_2026-11-12.md, "Measured confirmation"
section — the two unified sources carrying these classes compiled fine in
this build).
