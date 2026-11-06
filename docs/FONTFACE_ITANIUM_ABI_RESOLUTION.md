# FontFace and CSSFontFace Memory Hierarchy & Itanium C++ ABI Model

**Target:** WebKit 605.1.15 / Safari 17.0 branch point (PS5 14.00, 14.10, 14.20, 14.22)  
**Status:** `[I]` Desk Model & Source-Grounded Architecture (WK-1400 Drop & Itanium ABI) with Pre-Registered `[M-pending]` Device Deciders (Issue #181).

---

## 1. Executive Summary & Class Inheritance Hierarchy

In community discussions (Issue #181), conflicting memory layouts were debated for the `FontFace` wrapper. Analysis against the pinned Safari 17.0 / WK-1400 source drop (`Source/WebCore/css/FontFace.h:46`) resolves the structural inheritance:

```cpp
class FontFace final : public RefCounted<FontFace>,
                       public ActiveDOMObject,
                       public CSSFontFace::Client
```

### Base Subobject Hierarchy & Primary Base Selection

Under the **Itanium C++ ABI** (§2.4: Non-Virtual Base Allocation, §2.5: Primary Base Class Selection):

1. **Non-Polymorphic Base `RefCounted<FontFace>`:**
   - Inherits `RefCountedBase`, which holds scalar `mutable unsigned m_refCount;` (4 bytes).
   - It possesses **no virtual functions** and **no vtable**. It is strictly non-polymorphic and cannot be selected as the primary base.
2. **Polymorphic Base `ActiveDOMObject`:**
   - Inherits `ContextDestructionObserver` (`ActiveDOMObject.h:52`), which declares `virtual ~ContextDestructionObserver();`.
   - `ContextDestructionObserver` is the first dynamic subobject and is selected as the **Primary Base Class** placed at offset **`+0x00`**.
   - Consequently, the primary `vptr` is placed at **`+0x00`**, followed by CDO's `ScriptExecutionContext*` at **`+0x08`**.
3. **Tail of `ActiveDOMObject` (+0x10):**
   - `ActiveDOMObject` appends `uint64_t m_pendingActivityInstanceCount {0}` (`ActiveDOMObject.h:157`) at CDO's tail $\Rightarrow$ **`+0x10`** holds `m_pendingActivityInstanceCount` (reads 0 or 1).
4. **Placement of `m_refCount` (+0x18):**
   - Non-virtual base `RefCounted<FontFace>` is allocated after `ActiveDOMObject`: `m_refCount` resides at **`+0x18`** (+ 4 bytes alignment padding), NOT at `+0x10`.
5. **Secondary Base `CSSFontFace::Client` (+0x20):**
   - Polymorphic client interface defining virtual callbacks $\Rightarrow$ secondary `vptr` resides at **`+0x20`**.
6. **Weak Pointer Factory Tagged Pointer (+0x28):**
   - `FontFace` has no standalone factory member (`m_backing`, `m_loadedPromise`, and `bool` in private block :109-111).
   - The cell at **`+0x28`** is the nested `CanMakeWeakPtr<Client>` factory (`CSSFontFace.h:127`; `wtf/WeakPtr.h:276-299`), typed as `CompactRefPtrTuple<WeakPtrImpl, uint16_t>` (`WeakPtr.h:268`).
   - This is a **tagged qword**: `impl* | (type << 48)`. Forgers must mask the low 48 bits (`ptr & 0x0000FFFFFFFFFFFF`) before evaluating or forging.

---

## 2. Field Offset Map

### `FontFace` Class Layout (Itanium ABI on x86-64 NDEBUG)

| Offset | Member / Subobject | Size | Grade | Description |
|---|---|---|---|---|
| `+0x00` | `ActiveDOMObject` Primary `vptr` | 8 B | `[S]` | Pointer to `vtable for FontFace` (primary table) |
| `+0x08` | `ScriptExecutionContext*` (`Document*`) | 8 B | `[S]` | Member of nested `ContextDestructionObserver` |
| `+0x10` | `m_pendingActivityInstanceCount` | 8 B | `[S]` | `uint64_t` pending activity counter (reads 0 or 1) |
| `+0x18` | `mutable unsigned m_refCount` | 4 B | `[S]` | Scalar refcount from `RefCountedBase` (+ 4 B pad) |
| `+0x20` | `CSSFontFace::Client` Secondary `vptr` | 8 B | `[S]` | Secondary vtable pointer for client dispatch interface |
| `+0x28` | `CompactRefPtrTuple<WeakPtrImpl, uint16_t>` | 8 B | `[S]` | `CanMakeWeakPtr<Client>` tagged pointer (`impl* \| (type<<48)`) |
| `+0x30` | `Ref<CSSFontFace> m_backing` | 8 B | `[S]` | Pointer to backing engine face object |

### `CSSFontFace` Class Layout (Backing Object, 192-byte Size Class)

| Offset | Member | Size | Grade | Description |
|---|---|---|---|---|
| `+0x00` | `m_refCount` | 4 B | `[S]` | Non-polymorphic refcount (`RefCountedBase` + 4 B pad) |
| `+0x08` | `m_propertiesOrCSSConnection` | 8 B | `[S]` | `CSSFontFace.h:184` (non-polymorphic; no class vptr) |
| `+0x58` | `m_clients` (`WeakHashSet<CSSFontFace::Client>`) | 16 B | `[M]` | Client table (engine-written heap pointer during reclaim) |
| `+0x68` | `m_wrapper` / `WeakPtrImpl` | 8 B | `[M]` | Weak wrapper reference (engine-written heap pointer) |
| `+0x90` | `Timer m_timeoutTimer` (`vptr`) | 8 B | `[S]` | Timer vtable pointer (`WebCore::Timer` shared vtable) |

*Note on polymorphism and tail geometry:* `CSSFontFace` itself inherits strictly from `RefCounted<CSSFontFace>` (`CSSFontFace.h:60`) and contains **zero virtual functions** (virtual interfaces exist solely in nested `Client` :127-135). The only vtable pointer in the structure resides at `+0x90` and belongs to the `m_timeoutTimer` member. Offsets `+0x58` and `+0x68` are device-measured `[M]`. Tail geometry variations under the Sony fork are pre-registered on Issue #181 (branches D1/D1′/D2) and graded `[M-pending]`.

---

## 3. Pre-Registered Device Deciders & Memory Probing

1. **Band Discriminator at `+0x18` (Scalar refCount):**
   - Reads small integer scalar ($m\_refCount \in \{1, 2, \dots\}$).
   - `+0x10` reads small integer ($m\_pendingActivity \in \{0, 1\}$).
2. **Weak Pointer Tag Masking at `+0x28`:**
   - Low 48 bits: `addr = val & 0x0000FFFFFFFFFFFFULL`.
   - Upper 16 bits hold weak pointer type tag (`type << 48`).
3. **Open Device Decider for Fork Verification:**
   - Read `+0x20` through wrapper alias on live console:
     - **Module band (`.data.rel.ro`):** Standard Itanium ABI published map holds.
     - **Heap band:** Sony fork altered subobject ordering.
