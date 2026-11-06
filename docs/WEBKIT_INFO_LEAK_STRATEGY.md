# WebKit Info Leak Strategy — PS5 14.10

*Analysis date: 2026-10-31*

## Problem Statement

The sole remaining blocker for the entire 14.10 exploit chain is an info leak:
reading a heap pointer as a JavaScript-accessible value.

Two working WebKit primitives exist:
1. **Canvas UAF bidirectional R/W** (CVE-2026-43720, p553): float64 R/W over a
   768B Canvas2D context through same-type reclaim alias.
2. **FontFace reclaim disclosure** (Finding 13, p563/p564): engine writes two live
   WebProcess heap pointers into a script-controlled 192-byte ArrayBuffer.

Both are blocked from becoming full arbitrary R/W by the same gap: no
JavaScript-visible value carries a raw pointer.

## Why Standard Techniques Are Dead

| Technique | Result | Probe |
|---|---|---|
| Canvas getImageData oversized | Zero-filled (clamped + zeroed) | V674 |
| Canvas createImageData | Zero-initialized | V674 |
| Canvas resize residue | Zero-filled | V674 |
| APNG conforming frame into larger canvas | Clean padding | V674 |
| APNG truncated zlib (decoder-level) | ptrs=0 all phases | V674b |
| WebGL texture readback | NOT AVAILABLE | V674 |
| IPV6_2292PKTOPTIONS | BLOCKED on 14.10 | Prolapse docs |
| Cross-type reclaim (ArrayBuffer→Canvas) | Different bmalloc classes | p554/b/c |
| RAB sort OOB write (resize mid-sort) | Confirmed but JSC catches detach | P560, P561 |
| RAB double-detach | JSC catches, suspects=0 | P562 |
| Relapse stage-1 scope leak | Patched | p160 |
| float64 pointer read via Canvas API | DAZ returns 0.0 for denormals | p553 |

**DAZ (Denormals-Are-Zero)**: MXCSR DAZ is ON. Heap pointers in the
`0x000000100xxxxxxx` range are IEEE754 denormals. Any float64 operation that
touches the FPU reads 0.0 instead of the pointer value. All Canvas2D API
getters (getTransform, lineWidth, etc.) pass through float64 → DAZ kills them.

## What IS Working

### FontFace Reclaim (Finding 13)

Trigger: `FontFaceSet::load()` + `then` getter removes a `<style>`, freeing the
`CSSFontFace`. A 192-byte `ArrayBuffer` takes the freed chunk. The engine
continuation writes:
- `+0x00`: RefCounted counter = 1
- `+0x58`: `WeakHashSet` impl address (heap)
- `+0x68`: `WeakPtr` impl address (heap)

Both addresses move with heap churn and navigation → confirmed live heap
pointers. The control (no `style.remove()`) is byte-clean.

**Key**: ISO_MALLOC is OFF on PS5 (`OptionsPlayStation.cmake`). ArrayBuffer
backing stores share the allocator with engine objects. This is confirmed by
the measurement — a 192-byte buffer landed in the CSSFontFace chunk.

**Constraints**: one successful run per WebProcess, ~50% death rate per
attempt, write arrives 80ms after getter return.

### Canvas UAF R/W (Finding 14)

Trigger: `getContext('2d', {desynchronized: getter})` re-enters `getContext()`.
80-context spray, spray[9] lands in freed 768B slot. Bidirectional alias:
- 6×float64 via setTransform/getTransform
- 7 numeric properties (lineWidth, globalAlpha, etc.)
- save()/restore() functional

Stable, no crash, repeatable.

## Synthesis: The Two-Primitive Chain

The exploit chain requires combining these primitives:

```
FontFace reclaim → 2 engine heap pointers (WebProcess ASLR defeat)
    ↓
Heap grooming + known base → predict self-address
    ↓
Canvas UAF + self-address → arbitrary R/W
    ↓
Arbitrary R/W → kernel exploit
```

### Gap 1: Self-Address

FontFace gives us engine heap addresses but NOT the address of our own
ArrayBuffer. With ISO_MALLOC off, the engine and ArrayBuffer allocations share
the same heap. Adjacent allocations in the same size class are at predictable
offsets.

**Approach A: Relative offset prediction**

1. Allocate N×192-byte ArrayBuffers to fill free-list positions
2. Trigger FontFace reclaim → buffer B takes the freed chunk
3. Engine writes pointer P at B[0x58] — P is a fresh WeakHashSet impl,
   allocated AFTER B, likely at B + sizeof(CSSFontFace) + alignment
4. Our other buffers are in the same heap region
5. Distance from P to our buffers is predictable after heap grooming

**Approach B: Double FontFace disclosure**

1. First FontFace trigger → get P1, P2 (engine addresses)
2. Second FontFace trigger (fresh WebProcess via guide reload) → get P3, P4
3. Template second trigger with P1, P2 → engine dereferences our values
4. If the engine allocates new objects near our template buffer, the NEW
   pointers (P3, P4) have a computable offset from our buffer

**Approach C: FontFace controlled dereference**

p564 showed: a template with engine pointers at +0x58/+0x68 survives.
A template with 0x41... at +0x30/+0x58/+0x68 crashes (dereferenced).

What if we redirect one of these to point to a structure we control?
- Put address X at +0x58 (the `m_clients` field)
- Engine calls `m_clients.contains()` or iterates the WeakHashSet at X
- If the WeakHashSet structure at X is crafted correctly, the engine
  traverses into controlled memory and either returns data or writes
  to a location we specify

This requires reverse-engineering the `WeakHashSet` layout. The implementation
is in `wtf/WeakHashSet.h` — a hash table of `WeakReference<T>` entries. Each
entry contains a pointer to the referent. If we can make the iteration write
a known value to a known location, we get arbitrary write.

### Gap 2: Bypassing DAZ for Pointer Reads

Even with self-address, reading pointers through Canvas getTransform() is
blocked by DAZ. Alternative read channels:

1. **ArrayBuffer via FontFace reclaim**: Already works! The 192-byte buffer
   reads raw bytes including pointers. If we can do this repeatedly...
2. **BigUint64Array**: Operates on BigInt, no FPU involvement. If we can get
   an ArrayBuffer whose contents are engine-written, BigUint64Array reads the
   raw bits. FontFace already does this.
3. **Canvas putImageData + toDataURL**: putImageData writes bytes to the canvas
   pixel backing store, toDataURL reads them back. The pixel store is separate
   from the context numeric fields. But both paths go through the Canvas API,
   which zero-initializes.

## Priority: Viable Next Steps

### P0: FontFace self-address probe (NEW)

Write a probe that:
1. Grooms the heap with known-size ArrayBuffers
2. Triggers FontFace reclaim
3. Computes the offset from leaked pointer to each groomed buffer
4. Validates by writing a marker to the predicted address and checking
   if a groomed buffer's content changed

This is the highest-priority probe. If we can derive self-address from the
FontFace leak, the chain closes.

### P1: APNG decoder-level overread (RETEST)

V674b got 0 pointers. But the original claim was "1651 heap pointers" via a
SPECIFIC malformed APNG (truncated zlib mid-row). The V674b probe may have
tested conforming truncation rather than the exact decoder bug.

**Next**: Craft APNGs with:
- Truncated IDAT mid-row (not at a frame boundary)
- Missing CRC on the truncated chunk
- Missing IEND
- DEFLATE stream that decompresses to fewer bytes than the filter expects

If the decoder's error path doesn't zero-fill, stale heap data leaks through
`getImageData()`.

### P2: pastawithpesto's APNG ASLR defeat (INVESTIGATE)

README.md states pastawithpesto confirmed "APNG-based ASLR defeat" as stage
5/8. Our V674/V674b could not replicate it. The technique may involve the
Canvas UAF:

**Hypothesis**: Draw an APNG onto a UAFed canvas. The decoder writes pixel
data into the canvas backing store, which (through the UAF alias) is the
reclaimed Canvas2D context. The decoder writes raw image bytes into the context
structure's pointer fields, and the alias then reads those bytes back as
float64 values that represent the original pointer.

This reverses the direction: instead of reading pointers OUT, it writes known
byte patterns IN (via the image decoder), and the pointer fields' original
values are displaced into the pixel readback. Needs testing.

### P3: OffscreenCanvas worker readback (UNTESTED)

PS5 14.10 has Workers and Canvas 2D. OffscreenCanvas is untested. If
available, a worker's OffscreenCanvas might:
- Have different zero-initialization behavior
- Have different backing store allocation (might share with engine objects)
- Allow transfer of canvas backing between threads (exposing timing windows)

### P4: Canvas UAF + numeric field as pointer fragment

The Canvas UAF gives us 6×float64 (transform) + 7 properties = 13 float64
values at specific offsets in the 768B context. What if ONE of these offsets
overlaps with a pointer field in the RECLAIMED context?

If `miterLimit` is stored at the same offset as (say) the canvas backing store
pointer in a different Canvas2D sub-state... then writing to miterLimit via
the stale wrapper writes over a pointer in the reclaimed context. This requires
the 768B layout.

**Next**: Reverse-engineer the Canvas2D context layout:
- Write distinct sentinel values to all 13 numeric fields via spray[9]
- Read all 768 bytes of the spray[9] context via a separate UAF chain
  (FontFace-style: free spray[9]'s context, reclaim with ArrayBuffer)
- The sentinel positions in the 768 bytes reveal the field layout
- Check if any pointer field is adjacent to or overlapping with a writable
  numeric field

### P5: FontFace controlled dereference → arbitrary read (SPECULATIVE)

If Approach C works (redirect engine dereference to controlled memory):
1. FontFace leak #1 → get engine pointer P
2. Template the freed chunk with P at +0x58, but with a CRAFTED WeakHashSet
   at address P that we've filled with a target address T
3. Engine iterates the "WeakHashSet" at P, follows our entry pointing to T
4. If the iteration does a copyout or write-to-JS, we read arbitrary memory

This requires:
- Precise WeakHashSet layout knowledge
- A way to place controlled data at the engine address P (only possible if P
  is in the same heap region as our allocations — likely with ISO_MALLOC off)
- Understanding what the iteration callback does with each entry

## Syscall Leads (Lower Priority)

From the offline handler decode, these syscalls have untested paths:

| Syscall | Status | Next Step |
|---|---|---|
| 572 | ret=0 for 3 shapes but no output data | Deep probe with different sentinels and sizes (probe 572a) |
| 591 | All -1 (resolves USERLAND, not kernel) | NID-encoded names with library qualifier |
| 599 | All -1 for all shapes tried | 13.60 decompile shows loader path; try more arg shapes |
| 656 | All -1 (debug-unit gate) | Confirmed blocked on retail |
| 660 | Only size field differs from 593 | Already fully tested |

These are secondary to the WebKit info leak work. Even if 591 resolves a
symbol, it gives a userland address (confirmed by 13.60 decode), which does
not defeat kernel KASLR.

## Recommended Console Session Order

1. **572a probe** — errno capture for all key syscalls + 572 deep (20 min)
2. **FontFace self-address probe** (new, needs to be written) (30 min)
3. **Canvas2D layout probe** — sentinel dump via FontFace reclaim (20 min)
4. **APNG malformed decoder probe** — truncated IDAT variants (30 min)
5. **OffscreenCanvas availability check** (5 min)

## References

- `docs/WEBKIT_FINDINGS.md` — Findings 1-14, full measurement records
- `docs/FONTFACE_RECLAIM_LEAK_14_10.md` — FontFace reclaim details
- `docs/PROLAPSE_CANVAS_UAF.md` — Canvas UAF overview
- `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt`
- `results/phase13_webkit/v674_canvas_api_info_leak_20261029.txt`
- `results/phase13_webkit/v674b_apng_decoder_overread_20261029.txt`
- `results/phase13_webkit/p560_sort_oob_write_20261027.txt`
- pastawithpesto's repo: APNG ASLR defeat (stages 5/8)
