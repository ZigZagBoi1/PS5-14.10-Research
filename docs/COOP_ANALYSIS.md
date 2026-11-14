# COOP Analysis — FontFace Vtable-to-Method Mapping

Date: 2026-11-12
Source: WebKit main branch (CSSFontFace.h, FontFace.h, FontFace.cpp, CSSFontFace.cpp)
Reference: LinearFox CSSFontFace-to-ARW writeup (ntfargo/ufm42)

## FontFace Class Hierarchy

```
FontFace final
  ├─ RefCounted<FontFace>          (no vtable, CRTP ref counting)
  ├─ ActiveDOMObject                (primary vtable, offset 0x00)
  │   └─ ContextDestructionObserver (virtual ref/deref, destructor)
  └─ CSSFontFaceClient             (secondary vtable, offset 0x20)
      └─ AbstractRefCountedAndCanMakeWeakPtr
```

offset_to_top for secondary = -32 (0xFFFFFFFFFFFFFFE0) [M from p809]

## Primary Vtable (PV_RVA = 0x724DAC0, 11 slots)

ActiveDOMObject interface. Called when WebKit treats the object through its primary base.

| Slot | RVA       | Likely Method                          | Side Effects                                      |
|------|-----------|----------------------------------------|---------------------------------------------------|
| 0    | 0x412C450 | ~FontFace() D1 (complete destructor)   | m_backing->removeClient(*this)                    |
| 1    | 0x5B3CE20 | ~FontFace() D0 (deleting destructor)   | same + deallocate                                 |
| 2    | 0x5B3CFC0 | FontFace::ref() final                  | ++m_refCount at this+offset                       |
| 3    | 0x5B3D7A0 | FontFace::deref() final                | --m_refCount; if 0 → destroy                      |
| 4    | 0x4001750 | no-op (ActiveDOMObject::suspend)       | returns void                                      |
| 5    | 0x4001750 | no-op (ActiveDOMObject::resume)        | returns void                                      |
| 6    | 0x4001750 | no-op (ActiveDOMObject::stop)          | returns void                                      |
| 7    | 0x5B3D7B0 | virtualHasPendingActivity() const      | reads m_mayLoadedPromiseBeScriptObservable + m_loadedPromise->isFulfilled() |
| 8    | 0x5B3D410 | activeDOMObjectName() const            | returns "FontFace" string literal                 |
| 9    | 0x503EC80 | unknown (unique RVA, different region) | TBD                                               |
| 10   | —         | not dumped (PV+0x50)                   | TBD                                               |

## Secondary Vtable (VP_RVA = 0x724DB28, 8 valid + 2 NULL)

CSSFontFaceClient interface. Called when CSSFontFace notifies its clients.

| Slot | RVA       | Likely Method                              | Side Effects                                              |
|------|-----------|--------------------------------------------|-----------------------------------------------------------|
| 0    | 0x5B3CFB0 | ~CSSFontFaceClient() D1 thunk             | adjust this+32, call ~FontFace D1                         |
| 1    | 0x5B3CFE0 | ~CSSFontFaceClient() D0 thunk             | adjust this+32, call ~FontFace D0                         |
| 2    | 0x4001750 | fontLoaded(CSSFontFace&) — default no-op  | nothing                                                   |
| 3    | 0x5B3D6B0 | fontStateChanged() thunk → FontFace       | m_loadedPromise->resolve(*this) on Success                |
| 4    | 0x4001750 | fontPropertyChanged() — default no-op     | nothing                                                   |
| 5    | 0x4001750 | updateStyleIfNeeded() — default no-op     | nothing                                                   |
| 6    | 0x5793400 | ref() thunk                                | adjust this-32, ++refCount                                |
| 7    | 0x5B3D810 | deref() thunk                              | adjust this-32, --refCount; if 0 → destroy                |

## FontFace Object Layout (measured + source-derived)

```
FontFace base (+0x00 from FontFace*)
  +0x00  primary vtable ptr (PV)
  +0x08  RefCounted m_refCount (uint32) + padding
  +0x10  ContextDestructionObserver m_scriptExecutionContext (ptr)
  +0x18  ActiveDOMObject state / padding
  +0x20  secondary vtable ptr (VP) — CSSFontFaceClient subobject
  +0x28  AbstractRefCountedAndCanMakeWeakPtr state (weak ptr factory)
  +0x30  m_backing : Ref<CSSFontFace> (8B ptr)
  +0x38  m_loadedPromise : UniqueRef<LoadedPromise> (8B ptr)
  +0x40  m_mayLoadedPromiseBeScriptObservable : bool (1B)
  +0x41  m_sourceIsImmediateBuffer : bool (1B)
  +0x42  padding to alignment
  sizeof(FontFace) ≈ 0x48 (72 bytes), bmalloc size class TBD
```

NOTE: offsets after +0x20 are estimates. Need probe verification.

## CSSFontFace Layout (WebKit-1200, from LinearFox)

```
+0x00  vtable ptr (RefCountedAndCanMakeWeakPtr)
+0x08  m_refCount + flags
+0x10  m_propertiesOrCSSConnection (Variant, 16B)
+0x20  m_family (RefPtr<CSSValue>, 8B)
+0x28  m_ranges (Vector<UnicodeRange>)
+0x38  m_featureSettings (FontFeatureSettings)
+0x48  m_loadingBehavior (enum, 4B)
+0x4c  m_sizeAdjust (float, 4B)
+0x50  m_sources (Vector<unique_ptr<CSSFontFaceSource>>)
+0x60  m_clients (WeakHashSet<CSSFontFaceClient>)
+0x70  m_wrapper (WeakPtr<FontFace>)
+0x78  m_fontSelectionCapabilities
+0x8a  m_status (Status enum, 1B)
+0x98  m_timeoutTimer (Timer, embedded)
sizeof(CSSFontFace) ≈ 0xc8
```

## Key COOP Gadget: fontStateChanged (VS-3)

```cpp
void FontFace::fontStateChanged(CSSFontFace& face, Status, Status newState) {
    switch (newState) {
    case Status::Success:
        if (!m_loadedPromise->isFulfilled())
            m_loadedPromise->resolve(*this);  // WRITE: resolve stores *this
        return;
    case Status::Failure:
        if (!m_loadedPromise->isFulfilled())
            m_loadedPromise->reject(exception); // WRITE: reject stores exception
        return;
    }
}
```

If we control m_loadedPromise, the resolve/reject calls write through our pointer.
Requires understanding DOMPromiseProxyWithResolveCallback internals.

## Key COOP Gadget: ~FontFace() (PV-0)

```cpp
FontFace::~FontFace() {
    m_backing->removeClient(*this);
}
```

If we control m_backing, removeClient modifies WeakHashSet at m_backing->m_clients.
Two-level indirection: fake m_backing → fake m_clients → write target.

## LinearFox Approach (NOT COOP)

LinearFox does NOT use COOP. Their chain on PS4:

```
CSSFontFace UAF → ArrayBuffer reclaim → m_featureSettings relative read
→ JS array Butterfly indexing header corruption → oversized array
→ addrof/fakeobj (double/object array pair) → fake DataView → full ARW
```

Key points:
- m_featureSettings read BROKEN on PS5 14.10 (goes through m_propertiesOrCSSConnection)
- PS5 has vtable check at reclaim: `cmp [rdi], rax; jnz fail`
- They DO NOT demonstrate full PS5 exploitation (only "partially")
- Gigacage + IsoHeaps disabled on PS5 → Butterfly in same heap as C++ objects

## Our Position vs LinearFox

| Capability | LinearFox (PS4) | Us (PS5 14.10) |
|-----------|-----------------|-----------------|
| UAF trigger | CSSFontFace font-loading | Canvas2D getContext reentry |
| ASLR defeat | Not demonstrated | DONE (fault oracle) |
| Read primitive | 4-byte m_featureSettings | 16-byte syncRead16 (unlimited) |
| WebProcess base | Unknown | KNOWN (RVA calculations work) |
| Vtable knowledge | Not described | FULL (PV+VP, 19 slots mapped) |
| Write primitive | ArrayBuffer reclaim | ArrayBuffer reclaim (same) |
| Arbitrary write | Butterfly corruption → DataView | **NOT YET** |

## Paths to Arbitrary Write

### Path A: JSC Butterfly Corruption (LinearFox-inspired)
1. Spray JS arrays whose Butterfly size = freed object size class
2. Use syncRead16 to find Butterfly near reclaimed slot
3. Attempt heap shaping to get Butterfly header within write range
4. Corrupt vectorLength → oversized array → addrof/fakeobj → fake DataView → ARW
- **Pro:** Well-understood, no .text reading needed
- **Con:** Requires exact heap feng shui, bmalloc boundaries may prevent overlap

### Path B: addrof-via-READ + single write escalation
1. Use syncRead16 to READ JSC object internals (JSCell → Butterfly → element pointers)
2. Build addrof from READ alone (no write needed for reading object addresses)
3. Find DataView/ArrayBuffer JSCell in memory, read its buffer pointer
4. Need ONE write to DataView's buffer pointer to retarget it → full ARW
5. Use COOP (fontStateChanged or destructor) for that one write
- **Pro:** Leverages our strong read primitive, minimal COOP needed
- **Con:** Still need one controlled write via COOP chain

### Path C: Pure COOP write chain
1. Forge fake FontFace in reclaimed slot with controlled m_backing + m_loadedPromise
2. Trigger fontStateChanged → m_loadedPromise->resolve(*this) writes through fake promise
3. The write lands at a controlled address (DataView buffer pointer)
4. Full ARW from there
- **Pro:** Direct use of vtable knowledge
- **Con:** Need DOMPromiseProxy internals, deep chain

### Path D: Re-trigger UAF for Butterfly overlap
1. Use first UAF for read primitive (keep it running)
2. Trigger SECOND UAF → don't reclaim, let Butterfly fill the slot
3. The Butterfly's indexing header is now exposed through the stale pointer
4. BUT: can't write to stale pointer directly...
- **Pro:** Gets Butterfly and stale pointer to overlap
- **Con:** Can't write to the overlap region without another primitive

## Recommended Next Step: Path B (addrof-via-READ)

Build p811 to:
1. Verify FontFace object layout (exact offsets of m_backing, m_loadedPromise)
2. Build addrof using ONLY syncRead16:
   - Create JS objects, find their JSArray JSCells in heap
   - Read Butterfly pointers, read element values
   - Decode NaN-boxed pointers
3. With addrof, find the target DataView's buffer pointer location
4. Then design the COOP write gadget to corrupt that single pointer
