# Agent B — Kernel Image Audit (2026-10-23)

Independent audit of the PS5 14.10 kernel extraction and 13.60 comparison material.

## 1. 14.10 kernel candidate: verdict

**No plaintext 14.10 kernel image exists.** The extraction pipeline completed outer PUP decryption but the inner kernel payload remains opaque.

| Property | Value | Source |
|----------|-------|--------|
| Candidate file | `5_kernel.bin` (on remote server) | `docs/PUP14_EXTRACTION_ANALYSIS_2026-10-21.md` |
| Size | 32,689,664 bytes | Extraction report |
| SHA-256 | `8cb90195948273cd0cf3bf2cb69897be190304c6dbf1d23b2da9879c15c91905` | `tools/pup14/verify_kernel_candidate.py` |
| Whole-file entropy | 7.999994 bits/byte | Same |
| Zero-byte percentage | 0.3889% (random expectation: 0.3906%) | Same |
| ELF magic (`\x7fELF`) | 0 occurrences | Same |
| `FreeBSD` string | 0 occurrences | Same |
| `SceKernel` string | 0 occurrences | Same |

**Assessment:** The entropy is indistinguishable from random data. The zero-byte distribution matches the binomial expectation for uniform random bytes. No structural markers of any known executable format are present. This file is encrypted or compressed with a scheme that produces near-perfect entropy. It is not a plaintext kernel.

### Local PUP artifacts

| File | Size | SHA-256 | Entropy | Notes |
|------|------|---------|---------|-------|
| `515_block141.bin` | 100,372 B | `3304DD33...D6C15A2E` | 7.998 bits/byte | High entropy, no signatures, encrypted nested block |
| `515_block141_source.bin` | 100,372 B | `F24CB47C...8435E816` | — | Different hash from `515_block141.bin` despite same size — one is pre-decryption, one post |
| `515_table.img` | 36,640 B | `F2AE90FC...45BA257F` | 7.790 bits/byte | 6.43% zeros, slightly lower entropy suggests some structure, but no recognizable headers |

The `515_block141_source.bin` and `515_block141.bin` are the same size but have different SHA-256 hashes, confirming one is the pre-outer-decryption and one is post-outer-decryption form. Both remain opaque — the outer decryption transforms the bytes but does not yield plaintext.

The `515_table.img` (36,640 bytes) does not align to standard sector (512) or page (4096) boundaries. Its slightly lower entropy (7.790 vs 7.998) and higher zero percentage (6.43%) hint at structured metadata, but no block table, partition table, or PUP segment header is recognizable at 512-byte boundaries.

### Unpacker crash

The `pup_unpacker_linux` (pinned from `zecoxao/ps5-pup-unpacker` commit `005cccc`) returned SIGSEGV while processing PUP entry 1's nested `515_ssd0.system_b` image. The upstream source explicitly labels `ssd0.system_b` and `ssd0.system_ex_b` as requiring keys the unpacker does not possess. The crash is consistent with the unpacker attempting to decompress an encrypted block as zlib data and dereferencing invalid memory. The `check_nested_blocks.py` tool confirms: sampled blocks of segments 30 (system_b), 32 (system_ex_b), and 10 (preinst) fail zlib/gzip header checks after outer decryption.

### Why the kernel is opaque

The 14.10 recovery PUP has (at least) two encryption layers:

1. **Outer PUP entry encryption** — successfully removed by the 13.60 console's `/dev/pup_update0` device. The `.dec` files are the result.
2. **Inner payload encryption** — the kernel segment (index 16, ID 5) within the decrypted PUP entry remains encrypted. The PUP decryptor README states system/system_ex/wlan require same-family firmware; kernel is not explicitly listed, but the bytes prove it is also protected. The per-segment key derivation likely uses firmware-version-specific material that the 13.60 console cannot supply for a 14.10 payload.

No transformation was applied to the kernel candidate beyond extracting it from the PUP segment table. The `verify_kernel_candidate.py` script confirms the extracted bytes match the PUP segment byte-for-byte (SHA-256 match). The opacity is inherent, not an extraction artifact.

## 2. 13.60 kernel dumps: what's actually usable

### kernel_text.bin — verified x86-64 kernel code

| Property | Value |
|----------|-------|
| Size | 15,132,096 bytes (0xE6E5C0) |
| SHA-256 | `406AB210236D4123E06495BCC8DA82D8F89DAC07266558DC8C0F80CC6CF55CF1` |
| Failmap | 924/924 chunks successful (100% coverage, zero failed reads) |
| Function prologues (`55 48 89 E5`) | 25,890 |
| INT3 padding (0xCC) | 2,472,882 bytes (16.34%) |
| Zero bytes | 1,892,402 bytes (12.51%) |
| Kernel base (session) | `0xFFFFFFFF8A9C0000` |
| File spans | RVA `+0x0` through `+0xE6E5C0` (ends exactly at sysent table) |

**Code layout:**

| Offset range | Entropy (64KB sample) | Character |
|-------------|----------------------|-----------|
| `0x000000` | 0.034 bits/byte | Nearly empty — startup trampoline + padding |
| `0x100000` | 0.000 bits/byte | All zeros |
| `0x250000+` | Dense code begins | First substantial non-zero/CC region |
| `0x400000` | 6.390 bits/byte | Dense x86-64 code |
| `0x800000` | 6.474 bits/byte | Dense x86-64 code |
| `0xC00000` | 6.640 bits/byte | Slightly higher entropy, still code |

The file does NOT contain:
- An ELF header (the dump starts at kernel base, not at the ELF file header)
- Readable kernel strings (`FreeBSD`, `panic`, `malloc`, `sysctl` — all zero hits)
- A `.rodata` section (string tables are elsewhere in the kernel address space)

The four "SCE" matches are x86-64 instructions that happen to encode "SCEI" (`0x53 0x43 0x45 0x49`) and "SCEVENT" (`0x53 0x43 0x45 0x45 0x56 0x45 0x4E 0x54`) as immediate operands, at offsets `0x607A74`, `0x6085DE`, `0xB96C5E`, `0xB9728F`. These are `mov` instructions storing Sony-specific magic constants.

The high ASCII "string" count (393,139 runs of 8+ printable chars) is misleading — these are code byte sequences that happen to fall in the printable ASCII range, not actual text strings.

### kernel_data.bin — partial data section

| Property | Value |
|----------|-------|
| Size | 4,194,304 bytes (4 MiB) |
| SHA-256 | `E46B98AA2155B29D33DE3B11582A31051900F192058ACAA10517E934DC2C5E46` |
| Failmap | 256/256 chunks successful (100% coverage) |
| Starts at RVA | `+0x1000000` |
| First 64KB entropy | 0.000 bits/byte (all zeros) |

The first 64KB is entirely zero. The dump starts at a fixed RVA (+0x1000000) that falls partway into the kernel's data section. The `.text` section ends around RVA `+0xCC0000` per the README, so `kernel_text.bin` (which goes to `+0xE6E5C0`) actually contains ~2.7 MiB of data-section material after the code. The `kernel_data.bin` starts ~3.4 MiB further into data.

### sysent_area.bin — verified sysent table

| Property | Value |
|----------|-------|
| Size | 65,536 bytes (64 KiB) |
| Starts at RVA | `+0xE6D5C0` (0x1000 before sysent) |
| Sysent at | `+0x1000` within file = RVA `+0xE6E5C0` |
| Entry stride | 48 bytes |
| Entries | 679 |
| Progress | 4/4 chunks, 0 zero-filled |

First sysent entry at +0x1000: `sy_call = 0xFFFFFFFF8AC25760` = kernel base + `0x265760` = the nosys handler. Matches the documented nosys RVA.

### Handler bins (532–676) — jump trampolines

Each `handler_NNN.bin` is 4,096 bytes at the resolved `sy_call` address. The first bytes of handler 570 (nosys stub) and handler 532 both show **relative jump trampolines** (`E9 xx xx xx xx CC CC CC`), not direct function prologues. These are jump stubs that redirect to the actual handler body elsewhere in `.text`. The 25,890 prologues in `kernel_text.bin` are the real function bodies; the handler bins are the sysent dispatch stubs.

This means: to find the actual handler code for a given syscall, one must resolve the `E9` relative jump from the handler bin's starting address to compute the target address within `kernel_text.bin`.

## 3. Coverage map

### What is analyzed and verified

| Artifact | Status | Confidence |
|----------|--------|------------|
| 14.10 `5_kernel.bin` hash and entropy | ✅ Verified encrypted | HIGH — entropy indistinguishable from random |
| 14.10 PUP segment extraction correctness | ✅ Verified (SHA-256 match to PUP segment) | HIGH |
| 14.10 inner encryption layer | ✅ Diagnosed (per-version keying) | MEDIUM — mechanism inferred, not proven |
| 13.60 `kernel_text.bin` code validity | ✅ 25,890 prologues, real x86-64 | HIGH |
| 13.60 failmap coverage | ✅ 100% for all three regions | HIGH |
| 13.60 sysent nosys RVA cross-check | ✅ Matches documented `+0x265760` | HIGH |
| Handler bin structure (jump trampolines) | ✅ Characterized | HIGH |

### Gaps

| Gap | Impact | Notes |
|-----|--------|-------|
| No 14.10 kernel code at all | CRITICAL | Cannot do any 14.10 static analysis or cross-firmware diff |
| 13.60 `.rodata`/string table not dumped | HIGH | Cannot resolve string references, identify panic messages, or match symbol names |
| 13.60 dump between `+0xCC0000` and `+0xE6D5C0` is code+data mix | MEDIUM | The file labeled `kernel_text.bin` crosses into data — section boundaries not independently verified |
| 13.60 data dump starts at `+0x1000000`, skips `+0xCC0000`–`+0x1000000` | MEDIUM | ~3.4 MiB gap in data section coverage |
| No 13.60 module list or symbol table | MEDIUM | Only sysent-based handler identification available |
| Handler bin jump targets not resolved | LOW | Computable from existing data but not yet done |

## 4. Ranked areas requiring live 14.10 validation

1. **Kernel memory dump via live exploit** — the only path to a 14.10 kernel image. Requires kernel R/W, which is the unsolved problem. Catch-22.
2. **Sysent table location on 14.10** — the 13.60 RVA `+0xE6E5C0` is not proven to match. If KASLR were defeated, the sysent could be read directly.
3. **Handler body comparison** — every behavioral claim about 14.10 handlers (from probes) should be validated against actual code once an image is available.
4. **W^X enforcement mechanism** — whether this is kernel-level (PTE manipulation) or hypervisor-level (second-stage page tables). The probe evidence (sys 588 returns 0 but protection unchanged) suggests HV enforcement.
5. **Credential structure and authid gates** — the `cred+0x58` comparisons in syscalls 535/536/563-566 need code-level verification of what values they check.
6. **Thread context validation** — the `set_mcontext` CS/SS handling (13.60 analysis in `docs/THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md`) needs 14.10 code comparison.

## 5. Recommendations

### Immediate (no new capabilities needed)

1. **Resolve handler jump targets** — parse each `handler_NNN.bin`'s `E9` relative jump to compute the target RVA within `kernel_text.bin`. This creates a sysent→code-offset map for 13.60 that can be used for targeted comparison when a 14.10 image becomes available.
2. **Disassemble high-value 13.60 handlers** — use the jump-resolved offsets to extract and disassemble the actual handler bodies from `kernel_text.bin` for the syscalls of research interest (especially 622, 637, 588, 674, 547, 548).

### Requires new capabilities

3. **Alternative kernel image source** — investigate whether a 14.10-to-14.10 decryption path exists (same-version PUP on a 14.10 console, if one with kernel access becomes available).
4. **13.60 rodata/BSS dump** — a second dump run on the 13.60 console targeting the `.rodata` section would fill the string-table gap and dramatically improve static analysis.
5. **Live 14.10 handler body sampling** — if a partial kernel read primitive emerges (even a few hundred bytes at a known offset), targeted reads at sysent+handler offsets would be the highest-value use.

## 6. Discrepancy notes for Agent A

- The `515_block141.bin` and `515_block141_source.bin` are NOT identical despite being the same size. The "source" version has SHA-256 `F24CB47C...` while the processed version has `3304DD33...`. This confirms a transformation occurred but both remain encrypted.
- The 13.60 handler bins are **not direct function code** — they are jump trampolines. Any analysis treating offset 0 of a handler bin as the function entry is analyzing the wrong bytes. The actual code is at `handler_addr + 5 + int32_le(handler_bin[1:5])`.
- The "393K strings" in `kernel_text.bin` are code fragments, not text. The dump contains zero actual kernel-domain strings. String-based analysis requires the `.rodata` section, which was not captured.
- `dump_progress.json` records only the `sysent_area.bin` region. The `kernel_text.bin` and `kernel_data.bin` failmaps exist separately and show 100% coverage, but the progress file does not track them.
