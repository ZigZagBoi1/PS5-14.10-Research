# Prolapse — Canvas UAF WebKit Exploit for PS5 14.10

**Author:** @notnotzecoxao (Jose Coixao)
**Status:** Coming to 14.00/14.10
**Previous versions:** FW 11.60–13.60 (repo: [1nk1/PS5-Prolapse](https://github.com/1nk1/PS5-Prolapse))
**Based on:** j0rdy's WebKit exploit

---

## Overview

Prolapse is a WebKit exploit targeting the PS5's built-in browser engine. It uses a Canvas `getContext()` Use-After-Free (UAF) vulnerability to achieve arbitrary read/write, ultimately targeting kernel code execution.

**CVE-2026-43720**: Canvas `getContext()` UAF (WebKit bug 313175) — **CONFIRMED on device** by pastawithpesto on 14.10.

---

## Attack Chain

```
Canvas 2D reentrancy
  -> getContext() UAF
    -> same-type reclaim
      -> bidirectional R/W
        -> info leak (heap pointer as JS number)
          -> arbitrary R/W
            -> kernel exploit
```

### The Sole Blocker

**Reading one raw heap pointer as a JS number (info leak).**

Everything else in the chain is confirmed working. The info leak is the single remaining gap.

---

## Technical Details

### Canvas 2D Slot

- **Size:** 768 bytes
- **Allocator:** FastMalloc
- **Reclamation:** Only by same-type Canvas2D contexts
- **Implication:** The slot is reclaimed when a Canvas2D context is destroyed and another Canvas2D context of the same type is created

### getContext() Reentrancy

The core primitive is `getContext()` reentrancy. When `getContext("2d")` is called while a Canvas2D context is already active, it triggers the UAF. This is the entry point for the entire chain.

### Canvas2D Context Lifecycle

1. `getContext("2d")` creates a Canvas2D context (768B FastMalloc slot)
2. Destroying the context frees the slot
3. Creating another Canvas2D context of the same type reclaims the slot
4. The old context's pointers now point to the new allocation (UAF)

### MetadataTable Overflow (CVE-2026-64784)

- **Type:** JSC (JavaScript Core) integer overflow
- **Status:** Confirmed on device, **UNEXPLOITABLE** (OOM)
- **Details:** stride=112 bytes, N=38,348,816
- **Why unexploitable:** The overflow triggers an out-of-memory condition before exploitation can complete

---

## PS5 14.10 WebKit Environment

### Confirmed Features

| Feature | Status |
|---------|--------|
| IsoHeap | **OFF** |
| Gigacage | **OFF** |
| JIT | **DISABLED** (LLInt only) |
| WebAssembly | **NOT AVAILABLE** |
| SharedArrayBuffer | **NOT AVAILABLE** |
| WebGL | **NOT AVAILABLE** |
| WebContent memory ceiling | **~500MB** |

### Implications

- **IsoHeap OFF**: No per-process heap isolation. Heap pointers are predictable.
- **Gigacage OFF**: No gigabyte-scale cage for heap pointers. Heap pointers are predictable.
- **JIT disabled**: No JIT spray. No JIT-based primitives. Must rely on LLInt-only execution.
- **WebContent ~500MB**: Limited heap space for exploitation. Memory pressure is a factor.

---

## Canvas 2D Slot Layout (768B FastMalloc)

The Canvas 2D slot is a 768-byte FastMalloc class. Key fields:

- Pointer fields: Canvas backing store, rendering context, etc.
- Number fields: Dimensions, pixel data pointers, etc.

**TODO:** Reverse engineer the exact layout of the 768B Canvas2D slot on 14.10 WebKit. This determines what we can leak and what we can corrupt.

---

## Info Leak — The Critical Gap

### Problem Statement

We need to read a raw heap pointer as a JS number. This is the sole blocker preventing the entire Prolapse chain from completing on 14.10.

### Potential Approaches

1. **Canvas pixel data readback** — Can we read canvas pixels that contain a heap pointer?
2. **OffscreenCanvas readback** — OffscreenCanvas may have different behavior than regular Canvas.
3. **ImageBitmap** — ImageBitmap may expose heap pointers through pixel data.
4. **Canvas filter/gradient** — Canvas filter or gradient objects may contain heap pointers.
5. **WebGL texture readback** — WebGL may expose heap pointers through texture data.

### Why This Matters

If we solve the info leak, we inherit the entire WebKit chain:
- Canvas 2D reentrancy -> UAF -> same-type reclaim -> bidirectional R/W
- Bidirectional R/W -> info leak (our solution) -> arbitrary R/W
- Arbitrary R/W -> kernel exploit

---

## Relation to Our Research

### How Prolapse Influences Our Work

1. **Canvas 2D slot analysis** — Our project should profile the Canvas 2D slot on 14.10 WebKit. What's the layout? What fields are pointers vs numbers?
2. **getContext() reentrancy** — Can we trigger getContext() reentrancy from a saved game context? This is the entry point for the entire chain.
3. **Info leak research** — The info leak is the single most important research task. We need to find a path where a heap pointer leaks as a JS number.
4. **WebKit canary tests** — Test the specific WebKit features that Prolapse uses: OffscreenCanvas, ImageBitmap, WebGL2, Canvas2D, pixel storage modes.
5. **IsoHeap / Gigacage verification** — Confirm IsoHeap OFF and Gigacage OFF on 14.10 WebKit. This determines what heap primitives are available.

### Complementary Research

- **pastawithpesto's WebKit research**: Their Canvas UAF PoC confirms the vulnerability exists on 14.10.
- **Our Lua loader research**: The Lua loader provides an alternative entry vector (TCP 9026). If we can combine the Lua loader with the WebKit UAF, we may have a path to the info leak.
- **Our kernel research**: The dynlib probe suite (591, 660, 656, 594) confirms only sys 593 works on 14.10. The kernel exploit path through the WebKit chain may be more viable than the Lua loader path.

---

## TODO

- [ ] Reverse engineer the 768B Canvas2D slot layout on 14.10 WebKit
- [ ] Profile Canvas2D context lifecycle on 14.10
- [ ] Test getContext() reentrancy on 14.10 WebKit
- [ ] Analyze Prolapse PoC from FW 11.60–13.60 for applicable techniques
- [ ] Test Canvas pixel data readback for info leak
- [ ] Test OffscreenCanvas readback for info leak
- [ ] Test ImageBitmap for info leak
- [ ] Confirm IsoHeap OFF and Gigacage OFF on 14.10 WebKit
- [ ] Measure WebContent memory ceiling on 14.10
- [ ] Cross-reference Prolapse techniques with our Canvas 2D slot analysis

---

## References

- [1nk1/PS5-Prolapse](https://github.com/1nk1/PS5-Prolapse) — Prolapse for FW 11.60–13.60
- [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) — 14.10 WebKit research
- [@notnotzecoxao](https://github.com/notnotzecoxao) — Prolapse author
- [CVE-2026-43720](https://webkit.org/blog/16648/) — Canvas getContext() UAF
- [WebKit bug 313175](https://bugs.webkit.org/show_bug.cgi?id=313175) — Canvas getContext() UAF

---

*Last updated: 2026-10-24*
