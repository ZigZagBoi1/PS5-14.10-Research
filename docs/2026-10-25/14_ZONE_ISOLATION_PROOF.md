# Finding 14: Sony Per-Type Zone Isolation — Why Cross-Subsystem Spray Is Dead

> **Date:** 2026-10-25 Session 3
> **Agents:** cross-subsystem-spray, probe-result-mining, freebsd-exploit-research
> **Confidence:** HIGH (confirmed by 20+ failed probes)

---

## The Finding

Sony's custom kernel allocator uses **per-TYPE zones**, not per-SIZE zones. Each kernel subsystem (AIO, EVF, namedobj, sockets, etc.) allocates from its own dedicated zone descriptor, even when the object sizes are identical. This makes cross-subsystem heap spray structurally impossible.

## Evidence

### 13.60 Decompile
Five AIO zone descriptors are contiguous in kernel data, 0x70 bytes apart:
```
0x1ab5890 — A (payload, 0x30B)
0x1ab5900 — I (queue entry, 0x58B)
0x1ab5970 — Q (completion, 0x58B)
0x1ab59e0 — R (metadata, 0x30B)
0x1ab5a50 — T/D (table/desc)
```

The allocator interface `func_0x00c08b50(size, zone_ptr, flags)` routes allocations by zone descriptor address, not by size. Different subsystems pass different zone pointers.

### 20+ Failed Live Probes (65o–67m)
| Probe | Spray Type | Count | Result |
|-------|-----------|-------|--------|
| 65o | kqueue + namedobj | 200+200 | Zero anomalies |
| 65v | EVF + namedobj + AIO | 128+256 | Zero EVF corruption |
| 65w | namedobj 24/31-char | 64+32+64 | Zero cross-corruption |
| 66c | socketpair + setsockopt + AIO | 64+64+32 | Zero unusual status |
| 66e | EVF + namedobj + socketpair + AIO | 32+32+32+16 | Zero anomalies |
| 66f | Massive AIO self-spray | 256 | Zero delete errors |
| 67d-67e | AIO self-spray + 663 readback | 128+128 | Status unchanged |
| 67f | namedobj cross-zone | 32 | No overlap |
| 67k | CPU-pinned AIO spray | 80+80 | All clean |
| 67l | socketpair AIO dual spray | 24+24 | Zero sentinel changes |

Zero overlap detected across ALL cross-subsystem combinations. AIO self-spray creates handle-level overlaps but the readback interface returns computed status, not raw memory.

## Implications

1. **Stop writing cross-type spray probes.** namedobj, EVF, kqueue, socketpair, setsockopt — none can reclaim AIO zones.
2. **AIO self-spray is guaranteed same-zone** but the 663/664/666/667 readback is opaque (computed status words, not raw object bytes).
3. **The exploit must attack through a different interface** — either the file refcount double-decrement (entry_dispose at I+0x40), or submit-during-delete to hit live objects, or read back through socket/evf/fstat rather than AIO queries.

## What CAN Cross the Zone Boundary

The `entry_dispose` function at I+0x40 does `lock xadd [*(I+0x40)+0x28], -1`. This atomic decrement targets the **file object** (struct file), which lives in a DIFFERENT zone (general-purpose). If the double-free's second pass operates on a reclaimed I object whose +0x40 field contains a controlled address, the decrement lands at `controlled_addr + 0x28` — crossing zone boundaries through pointer dereference, not allocation.
