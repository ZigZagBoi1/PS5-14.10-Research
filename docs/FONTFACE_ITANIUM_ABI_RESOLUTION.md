# FontFace and CSSFontFace Memory Hierarchy & Itanium C++ ABI Resolution

**Target:** WebKit 605.1.15 / Safari 17.0 branch point (PS5 14.00, 14.10, 14.20, 14.22)  
**Status:** Settles the base class ordering, offset divergence, and vtable positioning debated in Issue #181.

---

## 1. Executive Summary & Root Cause of the Discrepancy

In community discussions (Issue #181), two conflicting object models were proposed for the `FontFace` wrapper:
- **Model A (Proposed by 4TheDoctor):** `+0x00` primary `vptr` · `+0x08` `Document*` · `+0x10` `m_refCount` · `+0x20` `Client vptr` · `+0x30` `m_backing`.
- **Model B (Proposed by cobrajet302gt):** `+0x00` `m_refCount` · `+0x08` `vptr` · `+0x10` `Document*` · `+0x18` `counter` · `+0x20` `m_backing`.

### Compiler & ABI Specification Verdict: Model A is ABI-Mandated

Under the **Itanium C++ ABI** (§2.4: Non-Virtual Base Allocation, §2.5: Primary Base Class Selection) used by Clang and GCC on x86-64 (FreeBSD and PlayStation):

1. **Primary Base Class Rule (§2.5):**
   A dynamic (polymorphic) class inherits its primary vtable pointer (`vptr`) from its **primary base class**.
   A base class can only be selected as the primary base if it is polymorphic (i.e. defines or inherits virtual functions).
2. **Analysis of `FontFace` Class Declaration:**
   ```cpp
   class FontFace final : public RefCounted<FontFace>,
                          public ContextDestructionObserver,
                          public CSSFontFace::Client
   ```
   - `RefCounted<FontFace>` inherits `RefCountedBase`, which holds `unsigned m_refCount;`. It has **no virtual functions** and **no vtable**. It is strictly **non-polymorphic**. Therefore, it is mathematically impossible under Itanium ABI rules for `RefCounted` to be selected as the primary base class or to occupy offset `+0x00`.
   - `ContextDestructionObserver` declares `virtual ~ContextDestructionObserver();`. It is the first dynamic (polymorphic) base encountered in the base specifier list.
   - Therefore, the compiler mandates `ContextDestructionObserver` as the **Primary Base Class** at offset **`+0x00`**, placing the primary `vptr` at offset `+0x00`.

---

## 2. Definitive Field Offset Map

### `FontFace` Class Layout (Itanium ABI on x86-64 NDEBUG)

| Offset | Member / Subobject | Size | Description |
|---|---|---|---|
| `+0x00` | `ContextDestructionObserver` Primary `vptr` | 8 B | Pointer to `vtable for FontFace` (primary table) |
| `+0x08` | `ScriptExecutionContext*` (`Document*`) | 8 B | Inherited member of `ContextDestructionObserver` |
| `+0x10` | `unsigned m_refCount` | 4 B | Non-virtual base `RefCountedBase::m_refCount` |
| `+0x14` | *(padding)* | 4 B | Alignment padding for 8-byte pointer boundary |
| `+0x20` | `CSSFontFace::Client` Secondary `vptr` | 8 B | Secondary vtable pointer for client dispatch interface |
| `+0x28` | `WeakPtrFactory<FontFace>` / internal state | 8 B | Client weak pointer reference block |
| `+0x30` | `Ref<CSSFontFace> m_backing` | 8 B | Pointer to backing engine face object |

### `CSSFontFace` Class Layout (Backing Object, 192-byte Size Class)

| Offset | Member | Size | Description |
|---|---|---|---|
| `+0x00` | `m_refCount` | 4 B | Non-polymorphic refcount (`RefCountedBase`) |
| `+0x04` | *(padding)* | 4 B | Alignment padding |
| `+0x08` | `m_wrapper` (if non-split) | 8 B | Backpointer to JS wrapper |
| `+0x58` | `m_clients` (`WeakHashSet<CSSFontFace::Client>`) | 16 B | Client table (engine-written heap pointer during reclaim) |
| `+0x68` | `m_wrapper` / `WeakPtrImpl` | 8 B | Weak wrapper reference (engine-written heap pointer) |

---

## 3. Practical Implications for In-Document Probing

1. **Resolving the Band Test:**
   - At `+0x00`: Guaranteed to land in the `.data.rel.ro` / executable module segment (WebCore primary vtable).
   - At `+0x08`: Guaranteed to land in the WebProcess heap segment (pointer to live `Document` / `ScriptExecutionContext`).
   - At `+0x10`: Small integer scalar (`m_refCount` ∈ {1, 2, ...}), NOT a pointer.
   - At `+0x20`: Secondary vtable pointer (`vtable for FontFace for CSSFontFace::Client`).
2. **Dispatch Mechanism:**
   Any virtual dispatch directed through `CSSFontFace::Client` (such as `fontStateChanged` or `ref()`) dereferences the secondary `vptr` at offset `+0x20`.
