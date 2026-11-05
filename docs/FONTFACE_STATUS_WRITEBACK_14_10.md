# The status byte is a *write-back* oracle, not a read-back one

Status: proposal, **device-shaped and run on the console** (2026-11-04, port 14.10). Supersedes
`FONTFACE_STATUS_ORACLE_14_10.md`.
Grades: [S] source, [D] device row, [I] inference.

## 0. What changed, and why the previous oracle could not work

The earlier proposal wrote an invalid status value (`v=66`) into the reclaim lanes and read
`face.status` afterwards, expecting that byte to still be there. It cannot be: in
`CSSFontFace::setStatus` the write

```cpp
m_status = newStatus;                     // CSSFontFace.cpp:595
```

happens **after** `iterateClients(...)` (`:591-593`), i.e. after the JS `then` getter has run. The engine
itself overwrites the byte with `3` (`Status::Success`) on every run. "Write a value, read it back" is
therefore dead; the oracle must be **"did the engine write `3` into our object"**.

Two more corrections, both fatal to the old probe:

- `sizeof(CSSFontFace)` is **192**, not 176: `TimerBase` carries a vtable (`Timer.h:49`, `:75`), so
  `Timer` is 48 bytes and the class is bitfit 192.
- `m_status` is at **+0x82** (layout table below), not +0x82±1.

## 1. The primitive, stated precisely

Inside the `then` getter the victim is **freed** and the slot is reclaimed by attacker-chosen objects;
after the getter returns, the engine performs one store:

| access | type | offset | value |
|---|---|---|---|
| `m_status = newStatus` (`:595`) | **WRITE** 1 byte | `+0x82` | `3` (`Success`), fixed |

Then it *reads* `m_loadingBehavior` / `m_fontLoadTimingOverride` through `fontLoadTiming()` (`:599`) and
`m_heapItem` through `m_timeoutTimer.stop()` (`:625`). Those reads are what kills most carriers.

**The victim is not readable from JS.** `FontFace::m_backing` is a `Ref<CSSFontFace>`
(`FontFace.h:109`); `FontFace::adopt` (`FontFace.cpp:322-329`) repoints it to the **new** face, so every
getter (`style`, `family`, `status`) reaches a live object. The only reference to the freed one is the
C++ stack frame of `setStatus`.

## 2. Trigger shape

1. `@font-face` lives in its own `<style id="fs">` and is **never modified**: `lookUpByCSSConnection`
   matches by `StyleRuleFontFace` pointer (`CSSFontSelector.cpp:222`), and re-parsing the sheet replaces it.
2. A **second** `<style id="ds">` is dirtied inside the getter, then `offsetHeight` forces the rebuild:
   `StyleScope::updateActiveStyleSheets` → `Reconstruct` → `clearResolver` → `createDocumentResolver` →
   `buildCompleted` → `addFontFaceRule` → `remove` + `adopt` → free.
3. `document.body.offsetHeight` on a page whose elements do **not** use the font, then `face.loaded` is
   accessed (this registers the `DeferredPromise`), then `face.load()`.
   `FontFaceSet::load()` keeps a `Vector<reference_wrapper<CSSFontFace>>`; after the free it re-reads
   `status()` and `wrapper()` on the dead object (`FontFaceSet.cpp:195-206`), so the direct
   `face.load()` path avoids that second UAF.

`delete(this)` is a no-op for CSS-connected faces (`FontFaceSet.cpp:136`) and must not be used as the free.

## 3. Carriers

| carrier | class | survives the tail? | why |
|---|---|---|---|
| `ArrayBuffer(192)` | — | no | `ArrayBufferContents::tryAllocate` → `Gigacage::tryMalloc(Primitive)` (`ArrayBuffer.cpp:132`): separate auxiliary heap |
| `StringImpl` LChar, L=172 | 192 | no | payload writes 0 at `+0xB0` = `Timer::m_thread`; `stop()` → `setNextFireTime` hits `RELEASE_ASSERT(canCurrentThreadAccessThreadLocalData(m_thread))` (`Timer.cpp:469`), and `shouldSuppressThreadSafetyCheck()` is `false` off Apple platforms (`Timer.cpp:248-257`) |
| `new FontFace(...)` + `document.fonts.add` | 192 | **yes** | the constructor initialises a valid `Timer` (vtable, `m_thread = Thread::current()`) |

So the only usable carrier is another `CSSFontFace`, and the only readable consequence is `face.status`
on the sprayed face: `'unloaded'` → `'loaded'`.

**Fill before the trigger is load-bearing [D]**: without it the victim's page is nearly empty, gets
decommitted, and the first load of a fresh tab crashes *every time*. 80 sprayed faces before the trigger
keep it green on consecutive first loads (3/3 at the values above). This is not cosmetic.

## 4. Protocol

Fresh tab, first load, one arm per load, `fill=80`, `n=160`.

**Sizing matters [D]**: with `fill=60&n=64` the hit landed at 62/64 and 4 of 5 runs died before it. The slot
is taken late on a cold process; size the spray at least twice the highest index seen. With `fill=80&n=160`
the oracle was green on three consecutive first loads (hits at 44, 44, 44).

| arm | expected | reading |
|---|---|---|
| default | `HIT <idx>:loaded:zz<idx>` | the freed slot was reclaimed by spray face `idx` and took the `m_status = 3` store |
| `?ctl=1` | `HIT none`, page alive | no `offsetHeight`, no free, no state change |
| `?swap=1` | same as default, getter sees `st=error` | `font-display: swap` avoids starting a timer; the `TimedOut` status maps to `error`, `Success` still fires |

Positive: a face shows `loaded` while never having been loaded, and its own `family` equals `zz<idx>`.
Negative: with `ctl=1` no face changes state.
Reported rows (device, 2026-11-04): hits at indices 8, 9, 11, 14, 18, 19, 20 — every other face
`unloaded`, `HIT2` identical after 200 ms, `ctl=1` → `none`.

## 5. Layout table used

```
0x00 4 m_refCount            0x58 16 m_clients (WeakHashSet)
0x08 16 variant (index 0x10) 0x68 8 m_wrapper (WeakPtr)
0x18 8 m_families            0x70 18 m_fontSelectionCapabilities
0x20 16 m_ranges             0x82 1 m_status   <- UAF write
0x30 16 m_featureSettings    0x83 1 m_isLocalFallback
0x40 1 m_loadingBehavior     0x87 1 m_fontLoadTimingOverride
0x44 4 m_sizeAdjust          0x90 48 m_timeoutTimer (vtable +0x90, m_thread +0xB0)
0x48 16 m_sources            0xC0 = sizeof -> class 192
```
Page capacity for class 192: `floor((16384-272)/192) = 83`.

## 6. The three traps that still apply

**(a) `reserveCapacity` frees `m_buffer` even when `shouldReallocateBuffer` is false** [S].
`VectorBuffer::shouldReallocateBuffer` requires `min(m_capacity, newCapacity) > inlineCapacity`
(`Vector.h:520-523`); `Vector::reserveCapacity` calls `Base::deallocateBuffer(oldBuffer)` unconditionally
(`Vector.h:1146-1168`). A forged `m_buffer` that is not a malloc block gets `free()`d: keep
`m_buffer = 0, m_capacity = 0` and take the malloc path.

**(b) `m_size` of `Vector<CSSProperty, 4>` is at `+0x58`, not `+0x14`** [S] (`MutableStyleProperties.h:85`,
inline capacity 4). `+0x14` falls inside the inline buffer.

**(c) `font-family` is 8, not 7** [S]: `7` is `display`; the enum is generated in priority-then-name order.

## 7. Limits

- One byte per page, one value (`3`): only `Success` reaches `m_loadedPromise->resolve`, and only
  `resolve` runs the `then` getter (`FontFace.cpp:332-356`); `Failure` rejects.
- The address is chosen by the allocator (slot of the victim), not by the attacker.
- No read of the freed object: `wrapper()` is not on the `face.load()` path, and with a non-face carrier
  the variant discriminant (`+0x10`) is not valid.

## 8. Open question

A class-192 allocation that **does not write `+0xB0`** would keep the stale `m_thread` pointer and let a
byte-controlled carrier survive the tail. Vector buffers over-reserved (capacity 24 with size 17..22 at
8 bytes/element, or capacity 192 with size <= 176 for byte vectors) are the candidates; the variant
discriminant at `+0x10` (must be 0 or 1) stays the harder half.
