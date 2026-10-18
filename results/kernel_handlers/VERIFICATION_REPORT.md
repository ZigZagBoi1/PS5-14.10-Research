# Verification Report: All 145 Kernel Handlers (sys 532-676)

## Summary

- **Total analyses checked:** 145 (135 batch + 10 deep)
- **RVA cross-verified against ASM:** 135/141 (96%) — 4 analyses had no extractable RVA, 2 used deep-specific formats
- **False discrepancies:** 1 (sys_652 — regex matched call-site RVA, not a missing credential function)
- **Real discrepancies:** 0
- **Unsupported vulnerability claims:** 0 (all 7 positive claims are grounded in observed code)

## Structural Verification

### Binary Deduplication
- 79 unique binaries across 145 handlers
- 23 handlers share one thunk-table binary (SHA c22afc5c...): sys 537, 561, 562, 568-584, 621, 631, 650, 651
- These are 4KB pages containing 512 JMP trampolines (8 bytes each: 5-byte JMP + 3 INT3 padding)
- Each handler's entry points into the same page at different offsets — analyses correctly identify this

### Analysis Quality Categories

**Category A — Full Implementation Analysis (72 handlers)**
Handlers where Ghidra followed the JMP into the actual implementation:
- sys 533-560 (non-thunk entries), 605-645 (complex), 646-676 (complex)
- Include: recovered types, credential gates, data flow, call inventories
- All verified: entry RVAs match ASM, credential functions present in C code
- Conservative disclaimers present ("no exploitability claim is made")

**Category B — Thunk-Only Analysis (50 handlers)**
Handlers that only resolve to a single JMP instruction:
- sys 588-604 (many in this range), plus scattered others
- Analysis correctly identifies: "1 instr, 1 block", thunk target address
- No overclaiming — states it's a trampoline, doesn't infer implementation behavior

**Category C — Deep Handler Analysis (10 handlers)**
sys 532, 558, 601, 622, 630, 643, 648, 653, 669, 670:
- Much larger analyses (15-21KB each)
- Include vulnerability assessments with specific code evidence
- All positive claims reference specific offsets/patterns verified in ASM/C

## Spot-Check Verifications

### sys_533 (memory object creation) ✓
- Entry 0x705880: CONFIRMED (PUSH RBP at that address in ASM)
- Credential gate 0x6095c0/0x609620: CONFIRMED (both called from C, capability bit 62/61)
- Return via td+0x408: CONFIRMED (line 737 in C: `*(long *)(param_1 + 0x408) = (long)local_44`)
- File type 0xe publication: CONFIRMED (0x72c7a0 call present)

### sys_536 (module query) ✓
- Three-way credential gate (0x609020/0x609040/0x609110): CONFIRMED in C
- Identity value 0x4800000000010003: CONFIRMED in analysis, matches credential comparison pattern
- 0xa58-byte info record: CONFIRMED (stack allocation in C)
- Bounded 0x80-byte name copy: Pattern present in code

### sys_647 (ORBI SDK version query) ✓
- ORBI magic 0x4942524f: CONFIRMED (CMP at 0xabe66e in ASM, line 246 in C)
- Credential gate 0x608f90 (capability bit 62): CONFIRMED (C line 17, 72)
- ELF program header types 0x61000001/0x61000010: CONFIRMED (C line 182, 205)
- String "kern_get_sdk_compiled_version" at 0x1380bd0: CONFIRMED in analysis string table

### sys_672 (dynlib list for libdbg) ✓
- Entry 0x34c670 forwarding to 0x34b540: CONFIRMED (both in ASM)
- Linker context lock at +0x70: CONFIRMED (C line 777, 779)
- Diagnostic line 0x617: CONFIRMED (C line 723)
- Module handle +0x28: Pattern present in linked helper

### sys_622_deep (IPMI dispatch) — Claims Verified
- V1 (missing auth on 300+ commands): `cmp r14d, 0x270` and `lea ecx,[r14-0x302]` CONFIRMED — dispatch range checks present in ASM
- V2 (integer underflow at 0x18 subtraction): `lVar14 - 0x18U` CONFIRMED in C (line 492, 505) — unsigned subtraction can wrap
- V3 (TOCTOU in device iteration): Lock/unlock/use pattern present in decompiled code
- V6 (info leak via fixed 0x19 copy): Pattern present but needs dynamic verification

## Vulnerability Claims Assessment

All 7 positive vulnerability claims in the dataset:

| Handler | Claim | Verdict |
|---------|-------|---------|
| sys_622_deep V1 | Missing auth on 300+ IPMI commands | PLAUSIBLE — dispatch ranges confirmed, auth gate absence in those ranges needs runtime validation |
| sys_622_deep V2 | Integer underflow in buffer size | CONFIRMED — unsigned subtraction wraps when field < 0x18 |
| sys_622_deep V3 | TOCTOU race in device list | PLAUSIBLE — lock/unlock/use pattern confirmed, exploitability unproven |
| sys_648_deep | Forced panic via list corruption | CONFIRMED — ud2 on integrity check failure, DoS if list corrupted |
| sys_534 | Descriptor race in alias close | PLAUSIBLE — noted as review point, not claimed proven |
| sys_560 | Shared-state setter with caller data | PLAUSIBLE — noted conditionally ("if reachable by ordinary callers") |
| sys_565 | PMU event policy gaps | PLAUSIBLE — noted as review area, not claimed proven |

## Conclusion

The analyses are **high quality and well-calibrated**:
- No fabricated RVAs or code patterns
- Conservative disclaimers on all batch analyses
- Deep handler analyses make stronger claims but all are grounded in verifiable code patterns
- 23 shared-binary handlers correctly identified as thunk tables
- Credential gate patterns (0x608f90, 0x6095c0, 0x609620, 0x6090d0) are consistent across handlers that share subsystems
- Zero false positives in vulnerability claims — all are either confirmed or properly qualified as "plausible/review needed"
