# CanvasRenderingContext2D State Geometry & Out-of-Line Buffer Architecture

**Target:** WebKit 605.1.15 / Safari 17.0 (PS5 14.00, 14.10, 14.20, 14.22)  
**Status:** Resolves the 16-byte offset error, out-of-line buffer math, and zero-survivor crash behavior debated in Issue #216.

---

## 1. Context & State Struct Layout

In WebKit's `CanvasRenderingContext2D`, state management utilizes a hybrid inline/heap-allocated stack (`m_stateStack`):
- The first state (`State[0]`) is embedded directly inside the context object.
- Out-of-line allocations occur only when consecutive `save()` calls accompanied by non-default property assignments exceed inline capacity.

### Exact Clang Record Layout (64-bit Itanium / NDEBUG)

```
CanvasRenderingContext2D:
  +0x00 .. +0x6F: Base class and context flags (112 bytes)
  +0x70 (+112):   m_stateStack.m_buffer   (8 bytes void*)
  +0x78 (+120):   m_stateStack.m_capacity (4 bytes uint32_t)
  +0x7C (+124):   m_stateStack.m_size     (4 bytes uint32_t)
  +0x80 (+128):   Inline State[0] starts
```

### `CanvasRenderingContext2D::State` Struct (Total Size: 464 bytes = `0x1D0`)

| Offset within State | Context Absolute (Inline) | Field | Type | Description |
|---|---|---|---|---|
| `+0x00` (`+0`) | `+128` | `m_transform` | `AffineTransform` (48 B) | Matrix elements a, b, c, d, e, f (6 doubles) |
| `+0x30` (`+48`) | `+176` | `m_clipList` / styles | 16 B | Clip region and path references |
| `+0x40` (`+64`) | `+192` | **`m_lineWidth`** | `double` (8 B) | Stroke line width (default 1.0) |
| `+0x48` (`+72`) | `+200` | `m_miterLimit` | `double` (8 B) | Miter limit (default 10.0) |
| `+0xB8` (`+184`) | `+312` | **`m_lineDash.m_buffer`** | `double*` (8 B) | Vector buffer pointer for dash segments |
| `+0xC0` (`+192`) | `+320` | `m_lineDash.m_capacity` | `uint32_t` (4 B) | Vector capacity |
| `+0xC4` (`+196`) | `+324` | `m_lineDash.m_size` | `uint32_t` (4 B) | Vector size (number of double elements) |
| `+0xD8` (`+216`) | `+344` | `m_textAlign` | `uint32_t` (4 B) | Alignment enum |

---

## 2. Root Cause of the 14.22 Probing Crashes (Issue #216 & v665)

In prior probes (such as `v630.html`, `v665.html`, and Issue #216 experiments), the memory layout was modeled with two fatal errors:
1. **Underestimated State Size:** `sizeof(State)` was assumed to be **400 bytes** instead of the actual **464 bytes**.
2. **16-Byte Field Misalignment:** `lineWidth` was assumed to be at `State + 48` instead of **`State + 64`**.

### Cumulative Indexing Analysis (NSAVES = 8)

When 8 `save()` operations are executed:
- **Legacy Flawed Calculation:**
  $$\text{Offset} = 8 \times 400 + 48 = 3248 \text{ bytes}$$
- **Actual WebKit Layout:**
  $$\text{State}[8] \text{ start} = 8 \times 464 = 3712 \text{ bytes}$$
  $$\text{State}[8].\text{lineWidth} = 3712 + 64 = 3776 \text{ bytes}$$
- **Discrepancy:**
  $$3776 - 3248 = +528 \text{ bytes}$$

At offset `3248`, the read lands exactly at `7 * 464 = 3248`, which is offset `+0` of `State[7]` (the `AffineTransform.a` double). Attempting to dereference this as an arbitrary pointer or lineDash vector triggers an immediate invalid read or unmapped memory fault.

---

## 3. Buffer Allocation & bmalloc Size Classes

When the state stack expands out-of-line:
$$\text{Allocation Size} = 16 \times \text{sizeof}(\text{State}) = 16 \times 464 = 7424 \text{ bytes}$$

In WebKit's `bmalloc` allocator:
- An allocation of `6400` bytes falls into the **6400 / 6656** bucket.
- The true allocation of `7424` bytes falls into the **7680 / 8192** bucket.
- Attempting to reclaim a freed state buffer using `ArrayBuffer(6400)` will never land in the freed 7424-byte slot because the buckets are strictly segregated. Reclaim arrays must be sized at **7424 bytes**.
