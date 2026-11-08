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

   The mathematically derived capacity for 8 realized saves (9 total states) is **11 states**.  
   *(Note: Informal $1.25\times$ scaling without the $+1$ bias, i.e. $\text{cap} + \text{cap}/4$, would yield $8 + 2 = 10$, but the engine implementation explicitly evaluates to 11).*

   - **Primary Model (11 states):**
     $$11 \times (\approx 376 - 408\text{ B}) \approx 4136 - 4488\text{ B}$$
     In bmalloc, size classes double their step size with magnitude (`Sizes.h:56-118`). Specifically, in the range $[4096, 8192)$, the size class step is **512 bytes**, producing classes:
     $$\{ 4096,\; 4608,\; 5120,\; 5632,\; 6144,\; 6656,\; 7168,\; 7680,\; 8192 \}$$
     Therefore, `4352` is NOT a bmalloc size class ($4096 + 256$ exists only below 4096).
     Any allocation in the range $(4096, 4608]$ rounds strictly up to **`4608`**.
     Consequently, the entire derived range $4136 - 4488\text{ B}$ maps to the **single, monolithic bmalloc class 4608**.

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

## 4. bmalloc Allocation Sizing & Pre-Registered Deciders

In this port, `IsoMalloc` is OFF (`OptionsPlayStation.cmake:211`) and `libpas` is OFF (:284/:286). All allocations use standard `bmalloc` pools (`Sizes.h:56-118`).

### bmalloc Size Class Calculation
- Class step doubles with magnitude:
  - $[512, 1024)$: step 64
  - $[1024, 2048)$: step 128
  - $[2048, 4096)$: step 256 $\to \{ 2304, \dots, 3840, 4096 \}$
  - $[4096, 8192)$: step **512** $\to \{ 4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192 \}$

### Allocation Sizing (Primary Model: 11 States)
$$\text{Allocation Size} = 11 \times \text{sizeof}(\text{State}) \approx 4136 - 4488 \text{ bytes}$$

Because every value in $[4136, 4488]$ satisfies $4096 < \text{size} \le 4608$, the entire state buffer allocation maps exclusively to class **4608**. Reclaim arrays sized at the legacy 7424 bytes land in class **7680**, completely missing the active buffer slot.

### Pre-Registered A/B Ladder Deciders for Device Runs
Consoles should execute single-size-per-cold-load sprays across the genuine bmalloc size classes:
$$\{ 3840,\; 4096,\; 4608,\; 5120 \}$$

- **Landing at 4608:** Confirms the primary WK-1400 drop expansion model ($11 \times \approx 384\text{ B}$, buffer $4136-4488\text{ B}$).
- **Landing at 3840 or 4096:** Effective capacity 10 ($11 \times \text{State}$ cannot reach $\le 4096$ under the drop floor of $376\text{ B}$) $\implies$ fork growth law differs from drop.
- **Landing at 5120:** $\text{sizeof}(\text{State}) \in [419, 465\text{ B}] \implies$ fork-fattened State (fork floor $= 5120 / 11 = 465\text{ B}$).
- **Clean misses across $\{3840 \dots 5120\}$ + first landings $\ge 7168$:** Unexplained buffer layout; attribute elsewhere before adopting.
