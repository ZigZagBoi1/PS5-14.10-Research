# WebKit Canvas UAF (CVE-2026-43720) — Exploitation Status

> **Last updated:** 2026-10-31 (probes p568v7–v12)

## Summary

The Canvas UAF is confirmed working on PS5 14.10 WebKit. The free is reliable (100% trigger rate). ArrayBuffer spray (128 × 768B) reliably reclaims the freed slot. **But exploitation is stuck at the info-leak stage** — we cannot read back any useful data from the reclaimed memory.

## What Works

| Primitive | Evidence | Probe |
|-----------|----------|-------|
| UAF trigger | `inner !== outer`, 100% reliable | v7+ |
| ArrayBuffer reclaim | webkitBackingStorePixelRatio returns 1 (C++ getter survives → proves reclaim) | v8 |
| Object.defineProperty shadowing | All 24 getters + 55 methods on prototype are `configurable: true`, can shadow with JS own-properties | v8 |
| Prototype getter replacement | `Object.defineProperty(proto, 'globalAlpha', { get() { return 0.999; } })` works, `this === inner` inside getter | v8 |
| BigUint64Array | Available on PS5 WebKit, bypasses DAZ for integer reads | p567 |
| WeakRef + FinalizationRegistry | Available | p567 |

## What Crashes (Zeroed Spray)

**ALL C++ code paths crash on zeroed ArrayBuffer spray data.** The 768B freed CanvasRenderingContext2D has:
- Offset 0: vtable pointer → zeroed → virtual dispatch crashes
- m_canvas: stored as reference (CanvasBase&) → zeroed → any access crashes
- m_stateStack: Vector<State> → zeroed buffer pointer → `state()` crashes

| Method / Getter | Crash? | Likely cause | Probe |
|-----------------|--------|-------------|-------|
| webkitBackingStorePixelRatio | NO (returns 1) | Constant return, accesses nothing | v8 |
| webkitImageSmoothingEnabled | YES | Reads through m_stateStack | v8 |
| globalAlpha (getter) | YES | Reads through m_stateStack | v9 |
| getContextAttributes() | YES | Accesses m_canvas (for `canvas().hasAlpha()`) | v9 |
| createLinearGradient() | YES | Return value toJS needs scriptExecutionContext via m_canvas, or virtual dispatch | v10 |
| createRadialGradient() | NOT TESTED (crash before it) | Same as above | — |
| createImageData() | NOT TESTED | Same as above | — |
| beginPath() | YES | Accesses m_stateStack via `state()` or m_path, or binding preamble checks canvasBase() | v11 |
| closePath(), moveTo(), lineTo() | NOT TESTED (crash before) | Same as beginPath | — |
| Property setters (globalAlpha=) | NOT TESTED (crash before) | Accesses m_stateStack | — |
| save(), restore() | NOT TESTED | Accesses m_stateStack | — |

## Context-Reclaim Approach (v12) — FAILED

Attempted to reclaim the freed 768B slot with a second live CanvasRenderingContext2D instead of zeroed ArrayBuffers. The second context was created (`CTX2-OK`) but `inner.globalAlpha` still crashed. bmalloc allocated intermediate objects during `canvas2.getContext('2d')` (state stack, path, font cache, etc.) that consumed the freed slot before the context object itself.

## Dead Ends

- **FontFace heap pointer disclosure** — DEAD: even with proper async timing (await Promise.allSettled, FF-STATUS-error=64 confirmed), FF-TOTAL-0 across ALL 9 size classes (96-512B). No heap pointers.
- **String spray** — strings use WTF::StringImpl with header, different size class than 768B C++ objects.
- **ArrayBuffer.resize()** — available but preserves/extends existing (zero) data, doesn't help.
- **WebAssembly** — NOT available on PS5 WebKit.
- **SharedArrayBuffer** — NOT available.
- **OffscreenCanvas** — NOT available.
- **Workers** — alive but postMessage times out (no data transfer possible).
- **ArrayBuffer.transfer()** — NOT available.
- **localStorage crash oracle** — works but PS5 stops auto-restarting after ~8 consecutive crashes.

## The Core Blocker

**Self-address gap:** We can write controlled data to the freed slot (via ArrayBuffer spray), but we cannot:
1. **Read back** — all C++ getters crash on zeroed data
2. **Identify which buffer overlaps** — no way to detect overlap without a readable C++ code path
3. **Construct valid fake state** — need heap pointers for m_canvas, m_stateStack, vtable, but have no address disclosure

## Possible Next Steps (for resumption)

1. **Heap spray with fake pointers** — spray GB-scale ArrayBuffers, write self-referencing pointers at m_stateStack offset. If the spray lands at a predictable address range, the fake pointer might land inside readable memory. Very unreliable with ASLR.

2. **Intermediate-object reclaim** — instead of reclaiming with another context, identify exactly which 768B C++ object is allocated FIRST during `canvas2.getContext('2d')` and see if THAT object's data makes inner's methods work.

3. **Pre-spray then UAF** — allocate ArrayBuffers FIRST, write non-zero patterns, then trigger UAF. If the UAF's free returns the slot to bmalloc and then `getContext` internally allocates something that happens to use that slot, the internal allocation would overwrite our buffer with C++ data. Then read the buffer to see the written C++ data (including pointers).

4. **Different WebKit vulnerability** — search for another PS5 14.10 WebKit bug that leaks heap addresses directly (e.g., uninitialized memory read, type confusion that exposes internal pointers).

5. **CSS/DOM side channels** — explore whether CSS computed styles, DOM measurements, or animation timing can leak address information.

6. **Timing side channel on bmalloc** — measure allocation timing to infer whether a specific address is allocated or free (extremely difficult).

## Float64 Bit Patterns (from v6, still valid)

```
globalAlpha   0.5  = 0x3FE0000000000000
lineWidth     3.14 = 0x40091EB851EB851F  
shadowBlur    7.77 = 0x401F147AE147AE14 (stored as float32 → reads 7.769999980926514)
```

## CanvasRenderingContext2D Prototype

79 properties total: 24 getters, 55 methods (54 non-constructor).
See p568v8 beacon data for full enumeration.
