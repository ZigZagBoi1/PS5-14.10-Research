# A freed `CSSFontFace` is reclaimable by script, and the engine writes heap pointers into it (14.10)

Measured on the guide browser of a 14.10 console, 2026-10-29. Probes
`probes/phase13_webkit/p563-fontface-reclaim-leak.html` and
`probes/phase13_webkit/p564-fontface-reclaim-template.html`.

## Result

The `FontFaceSet::load()` use-after-free described in Finding 12 and issue #143 does
not only crash: the freed `CSSFontFace` chunk can be claimed by an `ArrayBuffer`
allocation made from script inside the same `then` getter, and the engine then
**writes two live heap pointers into that buffer**. Script can read them.

This is the first value read out of freed memory on 14.10, and it contradicts the
earlier note in `docs/WEBKIT_FINDINGS.md` that "ArrayBuffer-backed data does not land
in this allocator's size class".

## Trigger

Unchanged from Finding 12:

```js
Object.defineProperty(FontFace.prototype, 'then', { configurable: true, get() {
    styleEl.remove();               // frees the CSSFontFace behind @font-face
    document.fonts.delete(this);
    document.body.offsetHeight;     // force layout so the free is not deferred
    /* reclaim happens here */
    return undefined;
}, set(){} });
document.fonts.load('1em f0, s0', 'AB');
```

`fontShorthand` names both a JS-created face (`f0`) and the style-rule face (`s0`),
so `matchingFacesExcludingPreinstalledFonts()` captures a `reference_wrapper` to the
style-rule face before the getter destroys it.

## Measurement 1: reclaim, and the bytes the engine leaves

Inside the getter, after the free, thirteen size classes (`64 … 2048`) of
`ArrayBuffer` are allocated, eight per class, and kept. A scan 60 ms later reads
every byte.

| run | result |
|---|---|
| p563 (free) | `P563-HIT-b19-s192-o0-n9` — a **192-byte** buffer took the chunk |
| control, identical page without `styleEl.remove()` | `P563-ALL-CLEAN-104` |

The 192-byte buffer read `+0x00 = 1`, `+0x58 = 0x00000010008d8920`,
`+0x68 = 0x00000010007e7060`, and zero everywhere else.

`ArrayBuffer` data is zero-filled at allocation, so those three values were written
**after** the buffer took the chunk, by the continuation of the engine call that
still holds the stale pointer. The control — same allocations, no free — is
byte-clean, so the writes are a property of the dangling object, not of the page.

## Measurement 2: the two qwords are heap addresses

A variant adds 5000 `<span>`s and 2000 arrays before the trigger:

| run | `+0x58` | `+0x68` |
|---|---|---|
| no churn | `0x00000010008d8920` | `0x00000010007e7060` |
| with churn | `0x00001000e66810` | `0x00001000ed1a20` |
| with churn, following navigation | `0x00001000e5e810` | `0x00001000ec9920` |

Both move with the heap and both sit in the WebProcess heap range (`0x10…`), so they
are pointers, not constants. Between the last two rows the base shifted by about
`0x8000`, which is the per-navigation difference observed elsewhere in this project.

## What the fields are

From the shipped tree, `WebKit-1400/WebKit-1400/Source/WebCore/css/CSSFontFace.h`:

```cpp
class CSSFontFace final : public RefCounted<CSSFontFace> {
    const std::variant<Ref<MutableStyleProperties>, Ref<StyleRuleFontFace>> m_propertiesOrCSSConnection;
    RefPtr<CSSValueList> m_families;
    Vector<UnicodeRange> m_ranges;
    FontFeatureSettings m_featureSettings;
    FontLoadingBehavior m_loadingBehavior { FontLoadingBehavior::Auto };
    float m_sizeAdjust { 1.0 };
    Vector<std::unique_ptr<CSSFontFaceSource>, 0, CrashOnOverflow, 0> m_sources;
    WeakHashSet<Client> m_clients;
    WeakPtr<FontFace> m_wrapper;
    FontSelectionSpecifiedCapabilities m_fontSelectionCapabilities;
    Status m_status { Status::Pending };
    /* … flags, Timer m_timeoutTimer */
};
```

Offset 0 is the `RefCounted` counter — the observed `1`. The two written qwords fall
in the `m_sources` / `m_clients` / `m_wrapper` run of members.

`CSSFontFace::addClient(Client&)` is `m_clients.add(client)`, and `WeakHashSet`'s
implementation is allocated on first use, so the continuation allocates a fresh
`WeakHashSet` impl and stores its address into the object we own.
`wrapper()`/`setWrapper()` assign `m_wrapper`; `setStatus()` later walks `m_clients`
to notify every client. The engine therefore both writes an address into our buffer
and subsequently uses the field that holds it.

## Measurement 3: the engine accepts the object back

p564 runs two stages in one load:

1. free a face, reclaim with 192-byte buffers, read the two qwords the engine wrote;
2. create a second face and second style, free it the same way, and refill the
   reclaimed buffers with a template whose `+0x58` and `+0x68` are **those engine
   pointers**, then let the load continue.

Result: `P564-S1-HIT-b2-n9`, `P564-S2-RESOLVED`, `P564-S2-ALIVE-1`. The second load
resolved and the page survived, i.e. the engine accepted our chunk as a live
`CSSFontFace` when its two pointer fields held values it had itself produced.

A template whose fields are zero apart from `0x4141414141414141` at either `+0x30`,
`+0x58` or `+0x68` kills the page after the getter in every case, so those slots are
dereferenced on this path.

## Constraints

- **One successful run per WebProcess.** After a successful reclaim the process
  stops inside `load()` on the next attempt (`SETUP → LOAD-CALLED → nothing`).
  Quitting and reopening the guide restores it. Measurements taken in a process
  that has already run a reclaim are not evidence either way.
- **Long family names change the path.** A 2000-character family name and a
  256-character one both die after the getter even as the first page of a fresh
  process; the two-character names used by p563/p564 work.
- The freed chunk is 192 bytes with the page's own heap state; the size class is
  fixed by `sizeof(CSSFontFace)`, not chosen.

## What this establishes, and what it does not

Established: script can free a `CSSFontFace`, place readable memory in its chunk,
read two live heap pointers out of it, and hand the object back to the engine with
those fields intact. That is a first-stage address disclosure through a JS-only
channel, and it is the missing half of every WebKit chain on this firmware — the
other half being the ability to shape the object.

Not established: any address of our own memory. The leaked values are the engine's
`WeakHashSet` impl (and the neighbouring member), not the address of the buffer that
holds them, so a fake `Client` or fake source table still cannot be aimed. Until a
self-address exists, this is a disclosure, not a corruption primitive.

The earlier claim that this allocator is hermetic does not hold on 14.10. The header
does declare `DECLARE_ALLOCATOR_WITH_HEAP_IDENTIFIER(CSSFontFace)`, but
`Source/cmake/OptionsPlayStation.cmake` sets `USE_ISO_MALLOC` off for this port, and
the measurement is unambiguous: an `ArrayBuffer` backing store took the chunk, and
the same allocation pattern without the free stays clean.

## Repeatability

Two conditions decide whether the disclosure appears at all, and both were missing
from the first write-up.

**The sheet has to die.** `styleEl.remove()` alone does not free the face: the
`CSSStyleSheet` owns its `StyleRuleFontFace`, which owns a `Ref<CSSFontFace>`, so the
object lives as long as the JavaScript variable still references the element. The
pages that hit drop the last reference explicitly (`styleEl.remove()`,
`styleEl.textContent = ''`, `styleEl = null`) before the flush. With the reference kept
(`uaf37`, 64 x 192-byte buffers) the scan reports zero hits every time.

**The write arrives after the getter, not inside it.** The first runs scanned the
buffers immediately after `document.fonts.check()` and reported nothing; the hit
appears at a scan 80 ms later:

```
U38-T80-HIT-s192-b4-nz3
  0:0100000000000000
  58:b08a8c0010000000   -> 0x10008c8ab0
  68:a0707e0010000000   -> 0x10007e70a0
```

Refcount `1` at offset 0, a `WeakHashSet` impl at `+0x58` and the `WeakPtr` impl at
`+0x68`, matching the `CSSFontFace` member order.

**The write needs the dangling continuation.** Freeing a *loaded* face with no
in-flight `load()` (`uaf42`: the rule loads normally, then the sheet is dropped, then
72 buffers are sprayed) produced no write at all, so the two pointers come from the
engine continuing to use the object after the free — not from the free itself.

| control | spray inside the window | outcome |
|---|---|---|
| none | nothing | load resolves normally |
| one 192-byte buffer | 1 buffer | resolves, buffer stays zero |
| `uaf24` | 96 x 192-byte buffers, then `check()` | resolves, buffers stay zero |
| `uaf37` | 64 x 192-byte buffers, sheet reference kept | zero hits |
| `uaf42` | clean free, no in-flight load, 72 buffers | zero hits |
| `uaf38` | 13 classes 64-2048, sheet reference dropped | one hit, then the values above |
| `uaf6` (the page that hit six times) | same shape, zeros | dies inside `load()` in about half the runs |

What that leaves is a measured disclosure with an unstable window: the same page on
the same console either reports the pointers or dies in the continuation, and which
one happens is decided by state we cannot set from JavaScript. Treat a clean scan as
inconclusive and a death as evidence only that a buffer of some small class took a
chunk the continuation was still using.

