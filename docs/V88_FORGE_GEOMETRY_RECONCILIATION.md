# V88 Forge Geometry Reconciliation (Settlement of Issue #179)

**Target Firmware:** PS5 14.10 / WebKit 605.1.15 (Safari 17.0 fork)  
**Status:** Canonical layout specification & test suite  
**Related Probes:** `p564`, `p578`, `p579`, `p582`

---

## 1. Executive Summary

Issue #179 highlighted four critical contradictions across the repository regarding the `CSSFontFace` UAF reclaim and the single-lane V88 vtable forge geometry. This document settles these contradictions by cross-referencing on-device measurements on 14.10 (`docs/FONTFACE_RECLAIM_LEAK_14_10.md`), WebKit 605.1.15 source definitions, and the 10 empirical physics laws established in `README.md`.

---

## 2. Settlement of Contradictions

### C1: HashTable Placement & Dereference Chain (+0x58)
* **The Contradiction:** Early diagrams depicted `HashTable` fields (`m_table`, `m_tableSize`, `m_keyCount`) as starting inline at `CSSFontFace + 0x58`, whereas `docs/FONTFACE_RECLAIM_LEAK_14_10.md` proved that both `+0x58` and `+0x68` hold live WebProcess heap pointers.
* **Settlement:** 
  In WebCore Safari 17.0, `WeakHashSet<Client> m_clients` allocates its backing store lazily on first insertion. At `CSSFontFace + 0x58`, the engine stores an **indirect pointer** to the heap-allocated `WeakHashSet` impl struct. The inline metadata model was an unverified hypothesis.
* **Probe Verification:** `p582-table-geometry-discrim.html` tests `geom=impl` vs `geom=entry` to confirm the required dereference depth.

---

### C2: The +0x68 Wrapper Existence-Gate Law
* **The Contradiction:** The theoretical V55 recipe prescribed writing `m_keyCount = 1` into `CSSFontFace + 0x68`, claiming that `iterateClients()` executes before any `m_wrapper` access. However, Law 3 established that writing non-zero garbage to `+0x68` kills the WebProcess (0/12 survival), whereas `+0x68 = 0` survives (57%).
* **Settlement:**
  `CSSFontFace + 0x68` is `WeakPtr<FontFace> m_wrapper`. Because the `FontFace` wrapper is a GC root and load promise tracking retains references, writing integer `1` (`0x0000000000000001`) into `+0x68` produces an immediate unmapped read fault on the wrapper path. Forges must preserve the leaked wrapper pointer or maintain `+0x68 = 0`.
* **Probe Verification:** `p579-wrapper-slot-sweep.html` sweeps `+0x68` across `{0, 1, 0xFFFFFFFF, leaked}` to validate survival.

---

### C3: fontStateChanged Vtable Slot (+0x18 vs +0x28)
* **The Contradiction:** Chain analysis documented `fontStateChanged` at `vtable + 0x18` (Layout A, pre-2024 CRTP RefCounted), while upstream source analysis suggested `vtable + 0x28` (Layout B, post-2024 AbstractRefCounted with virtual ref/deref).
* **Settlement:**
  PS5 14.10 runs a Safari 17.0 fork branched in September 2023, prior to the introduction of `AbstractRefCountedAndCanMakeWeakPtr`. `ref()` and `deref()` remain non-virtual CRTP methods. However, to eliminate ambiguity without reliance on assumptions, probe `p578` fills all 8 vtable slots with distinct tagged sentinels (`0x414141410000 + slot_offset`).
* **Probe Verification:** `p578-vtable-slot-discrimination.html` captures the crash RIP:
  * RIP = `0x414141410018` $\implies$ Slot 3 (+0x18) verified.
  * RIP = `0x414141410028` $\implies$ Slot 5 (+0x28) verified.

---

### C4: WeakPtrImpl Layout
* **The Contradiction:** The README previously noted `{+0x00: vtable, +0x08: refcount, +0x10: m_ptr}`, while the chain doc noted `{+0x00: m_refCount, +0x04: m_ownerThread, +0x08: m_areThreadChecks, +0x10: m_ptr}`.
* **Settlement:**
  `WeakPtrImpl` does not possess a virtual destructor or virtual methods; it inherits `ThreadSafeRefCountedBase`. There is no vtable pointer at `+0x00`.
  The layout under security-assertions-enabled WebCore is:
  ```text
  +0x00: m_refCount          (uint32_t)
  +0x04: m_ownerThread       (uint32_t, RefCountDebugger)
  +0x08: m_areThreadChecks   (bool + padding)
  +0x10: m_ptr               (void*, pointer to CSSFontFaceClient)
  +0x18: m_thread            (uint32_t, WeakPtrImplBase)
  ```
  Therefore, fake `WeakPtrImpl` instances must write refcount at `+0x00` and target client pointer at `+0x10`.

---

## 3. Canonical V88 Single-Lane Forge Map

```text
Reclaimed CSSFontFace Chunk (192 bytes):
  +0x00: 0x00000002          (RefCount = 2, natural refcount law 7)
  +0x04..+0x57: 0x00         (Zero padding)
  +0x58: [qword]             (Pointer to WeakHashSet impl)
  +0x68: [qword]             (Preserved leaked m_wrapper pointer or 0)
  +0x70..+0x81: 0x00         (Zero padding)
  +0x82: 0x03                (Status byte write-back target)
  +0x83..+0xBF: 0x00         (Zero padding)
```
