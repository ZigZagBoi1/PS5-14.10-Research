# P816v2 Diagnostic Results — CSSFontFace Layout + Oracle Reads

Date: 2026-11-12
Probe: p816-diag.html (v2, no backptr scan)
Console: 192.168.1.37
Grade: M (measured, 3 independent runs)

## CSSFontFace Layout on PS5 WebKit 605.x (192-byte bmalloc class)

```
+0x00: refcount (spray→0, WebKit increments to 1)
        Run 1 buf=11: 0x100b80000001  (k=11 marker + refcount inc)
        Run 2 buf=23: 0x101780000001  (k=23 marker + refcount inc)
+0x08 to +0x50: ALL ZEROS (WebKit wrote nothing here)
+0x58: L1 — heap pointer WRITTEN BY WEBKIT post-spray
+0x60: 0x0
+0x68: L2 — heap pointer WRITTEN BY WEBKIT post-spray
+0x70: 0x0
+0x78: 0x0
+0x80: 0x30000 (m_status byte at +0x82 = 3 = our spray)
+0x88 to +0xB8: ALL ZEROS
```

3/3 runs confirm: ONLY +0x00, +0x58, +0x68 are modified by WebKit. Everything else stays as sprayed.

## L1/L2 Pointer Values (per run)

| Run | Try | zi | buf | L1 (+0x58)     | L2 (+0x68)     | Refcount         |
|-----|-----|----|-----|----------------|----------------|------------------|
| 1   | 1   | 0  | 11  | 0x100070d910   | 0x100081c080   | 0x100b80000001   |
| 2   | 4   | 1  | 23  | 0x1000882770   | 0x10007a6af0   | 0x101780000001   |
| 3   | 7   | 1  | 23  | 0x1000886770   | 0x10007a69e0   | 0x101780000001   |

## Oracle Reads (boundary() — max 0x10FFFF, 21-bit values only)

### Run 1 (zi=0, L1=0x100070d910, L2=0x100081c080, t1=0x10FFFF)

| Target | +0x0 | +0x4 | +0x8 | +0xC | +0x10 | +0x14 | +0x18 | +0x1C |
|--------|------|------|------|------|-------|-------|-------|-------|
| L1     | -1   | -1   | 0    | 0    | 0     | 0x10FFFF | -1 | -1   |
| L2     | -1   | 0x10FFFF | -1 | -1 | -1   | -1    | -1    | -1   |

### Run 2 (zi=1, L1=0x1000882770, L2=0x10007a6af0, t1=0x10C890)

| Target | +0x0 | +0x4 | +0x8 | +0xC | +0x10 | +0x14 | +0x18 | +0x1C |
|--------|------|------|------|------|-------|-------|-------|-------|
| L1     | 0    | 0    | 0    | 0    | 0     | 0     | 0     | 0x10FFFF |
| L2     | -1   | 0x10C890 | -1 | -1 | -1   | -1    | -1    | -1   |

### Run 3 (zi=1, L1=0x1000886770, L2=0x10007a69e0, t1=0x10C890)

| Target | +0x0 | +0x4 | +0x8 | +0xC | +0x10 | +0x14 | +0x18 | +0x1C |
|--------|------|------|------|------|-------|-------|-------|-------|
| L1     | 0    | 0x10FFFF | -1 | -1 | 0   | 0x10FFFF | -1 | -1   |
| L2     | -1   | 0x10C890 | -1 | -1 | -1   | -1    | -1    | -1   |

## Property Access (PROP phase)

The UAF face's JS properties read from C++ backing memory:
- UAF face shows family="normal" (CSS initial, not our rename)
- UAF face shows unicodeRange="U+0-10FFFF" (full range, from zero buffer)
- Legitimate face shows correct values (e.g. family="zz1", unicodeRange="U+41")

This confirms JS property getters access C++ CSSFontFace fields, not JS-cached values.

## LOAD-TEST Results

**document.fonts.load() on UAF face CRASHES 100% (3/3 runs)**

| Run | Time to crash | Notes |
|-----|---------------|-------|
| 1   | ~55s (13:49:09 → 13:50:04 next PAD) | Normal recovery |
| 2   | ~3s (13:50:18 → 13:50:21 next PAD) | Fast retry |
| 3   | ~12min (13:50:35 → 14:02:43 REDIRECT) | Hard crash, long recovery |

Crash root cause: load() likely dereferences null pointers in our zeroed buffer (+0x08 to +0x50 are all zero). This is exploitable if we populate those fields with controlled values.

## Interpretation

### L1 (+0x58) object analysis
- Contains unicode range data at varying offsets (0x10FFFF appears)
- When zi=0: data at +0x00 is non-zero (pointer/large value)
- When zi=1: data is mostly zeros with 0x10FFFF at different offset per run
- L1 varies between runs — possibly allocated at different offsets depending on heap state

### L2 (+0x68) object analysis  
- Very consistent: L2+0 always -1, L2+4 always readable
- L2+4 = 0x10FFFF when zi=0, L2+4 = 0x10C890 when zi=1
- 0x10C890 = 1,099,920 — not a standard Unicode value, possibly struct field
- All other L2 offsets (+0x8 through +0x1C) consistently -1

### Critical insight: L1 and L2 are FRESH allocations
Our spray zeros +0x58 and +0x68. WebKit WRITES heap pointers there after spray.
This means these are objects WebKit creates when it accesses our fake CSSFontFace.
Refcount byte[0] changes 0→1 confirms WebKit ref()'s our buffer.

## Next Steps

1. **Determine load() crash field**: Fill buffer fields one-by-one with L1 or L2 pointers to prevent null deref — find which field load() needs
2. **Explore wrapper repopulation**: +0x68 might be m_wrapper; if WebKit creates fresh FontFace wrapper, that's a controlled alloc
3. **Use load() crash as controlled crash**: If we know which field crashes, we can redirect that call with a controlled pointer
4. **Investigate 0x10C890**: This non-standard value in L2 might leak size/offset information useful for exploitation
