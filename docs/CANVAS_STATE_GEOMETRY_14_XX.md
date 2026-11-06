# CanvasRenderingContext2D State Geometry & Out-of-Line Buffer Architecture

**Target:** WebKit 605.1.15 / Safari 17.0 (PS5 14.00, 14.10, 14.20, 14.22)  
**Status:** `[I]` Desk Model & Vector Sizing Ladder (WK-1400 Drop & bmalloc) with `[M-pending]` Device Deciders (Issue #216).

---

## 1. Context Frame Architecture & Vector Header [S-Verified]

In WebKit's `CanvasRenderingContext2D`, state management utilizes a hybrid inline/heap-allocated stack:
```cpp
Vector<State, 1> m_stateStack; // CanvasRenderingContext2DBase.h:436
```

Under this era's `Vector` header (`wtf/Vector.h:396-397`), the layout places capacity before size:
```
CanvasRenderingContext2D:
  +0x00 .. +0x6F: Base class and context flags (112 bytes)
  +0x70 (+112):   m_stateStack.m_buffer   (8 bytes void*)
  +0x78 (+120):   m_stateStack.m_capacity (4 bytes uint32_t)
  +0x7C (+124):   m_stateStack.m_size     (4 bytes uint32_t)
  +0x80 (+128):   Inline State[0] starts
```

### Self-Pointing Discriminator
On a fresh 2D context prior to out-of-line migration:
$$\text{m\_stateStack.m\_buffer} = \text{ctxVA} + 128$$
This provides a direct, heap-free discriminator to verify context base address.

---

## 2. Lazy Save Semantics & Vector Growth Mathematics

1. **Lazy Saves (`m_unrealizedSaveCount`):**
   - Bare `save()` calls do NOT immediately allocate or grow the vector; they increment `m_unrealizedSaveCount` (`CanvasRenderingContext2DBase.h:438`).
   - The vector only realizes and pushes states when a property setter invokes `modifiableState()` (:313).
2. **Vector Growth Mathematics & Capacity Steps (`wtf/Vector.h:1152`):**
   The exact WebKit expansion formula is:
   $$\text{newCapacity} = \text{capacity} + \left\lfloor\frac{\text{capacity}}{4}\right\rfloor + 1$$
   Progression from inline capacity 1:
   - Initial inline: $\text{cap} = 1$
   - Realized save 1 ($\text{size}=2$): $1 + 0 + 1 = 2$
   - Realized save 2 ($\text{size}=3$): $2 + 0 + 1 = 3$
   - Realized save 3 ($\text{size}=4$): $3 + 0 + 1 = 4$
   - Realized save 4 ($\text{size}=5$): $4 + 1 + 1 = 6$
   - Realized save 6 ($\text{size}=7$): $6 + 1 + 1 = 8$
   - Realized save 8 ($\text{size}=9$): $8 + 2 + 1 = \mathbf{11}$

   *(Note: Under strict integer $1.25\times$ scaling without the $+1$ bias, the step yields $8 + 2 = \mathbf{10}$).*

   - **For 10 states:** $10 \times (\approx 376 - 408\text{ B}) \approx 3760 - 4080\text{ B} \implies$ lands in bmalloc bucket **3840** or **4096**.
   - **For 11 states:** $11 \times (\approx 376 - 408\text{ B}) \approx 4136 - 4488\text{ B} \implies$ lands in bmalloc bucket **4352** (or 4096).

   Critically, **both capacity 10 and capacity 11 fall squarely within the pre-registered bmalloc ladder $\{3328, 3584, 3840, 4096, 4352\}$**, and both are $\approx 40-50\%$ below the legacy 7424-byte overestimate.

---

## 3. State-Internal Member Map (WK-1400 Drop: `BASE.h:267-295`)

The layout opens with style strings and stroke variants:

| Offset within State | Field | Size | Grade | Description |
|---|---|---|---|---|
| `+0x00` (`+0`) | `unparsedStrokeColor` | 8 B | `[S]` | `String` |
| `+0x08` (`+8`) | `unparsedFillColor` | 8 B | `[S]` | `String` |
| `+0x10` (`+16`) | `strokeStyle` | 16 B | `[S]` | `CanvasStyle` (`std::variant` 16 B) |
| `+0x20` (`+32`) | `fillStyle` | 16 B | `[S]` | `CanvasStyle` (`std::variant` 16 B) |
| `+0x30` (`+48`) | **`lineWidth`** | 8 B | `[S]` | `double` (stroke width, default 1.0) |
| `+0x38` (`+56`) | *(padding)* | 8 B | `[S]` | Alignment padding |
| `+0x40` (`+64`) | `miterLimit` | 8 B | `[S]` | `double` (default 10.0) |
| `+0x48` (`+72`) | `shadowOffset` | 8 B | `[S]` | `FloatSize` (2 floats) |
| `+0x58` (`+88`) | `shadowColor` | 8 B | `[S]` | `Color` (uint64_t) |
| `+0x60` (`+96`) | `globalAlpha` | 4 B | `[S]` | `float` (+ 4 B pad) |
| `+0x70` (`+112`)| `transform` | 128 B | `[S]` | `TransformationMatrix` (`Matrix4[4][4]` 16 doubles) |
| `+0xF8` (`+248`)| **`lineDash`** | 16 B | `[S]` | `Vector<double>` (`{buffer*, cap, size}`) |
| `+0x108` (`+264`)| `lineDashOffset` | 8 B | `[S]` | `double` |
| `+0x118` (`+280`)| `textAlign` | 4 B | `[S]` | Enum (+ 4 B pad) |
| `+0x128` (`+296`)| `unparsedFont` | 8 B | `[S]` | `String` |
| `+0x130` (`+304`)| `font` | $\approx 72-104$ B | `[S]` | `FontProxy` / `FontCascade` footprint |

**Total Drop Footprint:** $\approx 376 - 408$ bytes.
The legacy 464-byte figure is $\ge +14\%$ over the drop ceiling, representing an unverified fork hypothesis `[M-pending]`.

---

## 4. bmalloc Allocation Ladder & Reclaim Sizing

In this port, `IsoMalloc` is OFF (`OptionsPlayStation.cmake:211`) and `libpas` is OFF (:284/:286). All allocations use standard `bmalloc` pools.

### Allocation Sizing
$$\text{Allocation Size} = 10 \times \text{sizeof}(\text{State}) \approx 3760 - 4080 \text{ bytes}$$

Reclaim arrays sized at 7424 bytes land in the **7680 / 8192** bucket, completely bypassing the actual state buffer bucket.

### Pre-Registered A/B Ladder Deciders for Device Runs
To decisively pin the state buffer size class without blind assumptions, consoles should execute single-size-per-cold-load sprays across the bmalloc bucket ladder:
$$\{ 3328,\; 3584,\; 3840,\; 4096,\; 4352 \}$$

- **Landings in $\{3840, 4096\}$:** Confirms the WK-1400 drop footprint ($10 \times \approx 384\text{ B}$).
- **Clean misses across ladder + landings $\ge 7168$:** Proves a Sony fork-fattened State structure (where $\text{sizeof}(\text{State}) \ge \text{lowest landing bucket} / 10$).
