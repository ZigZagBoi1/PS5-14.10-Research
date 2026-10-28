# Agent A — 14.10 Kernel Candidate: Corrected Evidence Report (2026-10-23)

Source: `R:\lib\ps5-research\pup-runs\manual-sdk-updaterid-20261020\`

This report separates observed bytes from inferences. Sections labeled **OBSERVED** contain only directly measured facts. Sections labeled **INFERRED** state the reasoning basis and confidence.

---

## 1. Verified File Inventory

| File | Size (bytes) | SHA-256 | Observed format |
|------|-------------|---------|-----------------|
| `PS5_1410_PS5UPDATE1.PUP.dec` | 1,261,406,781 | `158be2d3...` | PUP container (magic `54 14 F5 EE` at byte 0) |
| `PS5_1410_PS5UPDATE2.PUP.dec` | 157,481,653 | `efd08dfe...` | PUP container (same magic) |
| `5_kernel.bin` | 32,689,664 | `8cb90195948273cd0cf3bf2cb69897be190304c6dbf1d23b2da9879c15c91905` | Opaque (no recognized format; see §3) |
| `2_updatemode.self` | 11,772,452 | `194c22bb...` | Sony SELF (magic `54 14 F5 EE`, structured header, ELF at +0xE0) |
| `12_version_name.xml` | 134 | — | Plaintext XML: `<prefix_version>26.06</prefix_version>` |
| `15_bd_firm_info.json` | — | — | Plaintext JSON (begins `{`) |
| `4_mbr.bin` | 512 | `90634f07...` | Plaintext partition table (`SonyInteractiveEntertainmentLLC`) |
| `tables/16_for_5.img` | 2,016 | `dd251512...` | 63 × 32-byte entries, high-entropy |

## 2. Decryption Log — OBSERVED

`PS5_1410_RESEARCH.log` (200,555 bytes) records:

| Fact | Evidence |
|------|----------|
| `/dev/pup_update0` opened successfully | Log line `pup_update0 stat=0` |
| `updater_identity=1` set before processing | Log line `RESEARCH IDENTITY 1` |
| BLS header verified (ioctl `0xC0104401`) | Log line `Verifying Bls Header...` succeeded |
| PUP header decrypted (ioctl `0xC0184402`, type=1) | Log line `Decrypting header...` succeeded |
| All segment verifications passed | No verification failure lines |
| Kernel table decrypted (ioctl `0xC0184405`, index=15) | `Decrypting table #15 for segment #16` |
| All 63 kernel blocks decrypted (ioctl `0xC0284406`, index=16) | `Decrypting block 0/63` through `62/63`, no error lines |
| Process completed | `RESEARCH EXTRACTION SUCCESS` |

**Every ioctl returned 0 (success).** No decryption error was logged for any segment.

## 3. Kernel Binary — OBSERVED Properties

### 3a. Statistical measurements

| Property | Value | Method |
|----------|-------|--------|
| Entropy (per 4KB sample) | 7.9438 – 7.9620 bits/byte | Shannon entropy on 32 aligned samples |
| Zero-byte fraction | 0.27% – 0.56% per 4KB sample | Byte counting |
| Chi-squared (1MB, 255 df) | 216.79 | Byte frequency distribution |
| AES-ECB repeated 16B blocks | 0 in first 1MB (65,536 blocks) | Exact comparison |
| AES-ECB repeated 512B blocks | 0 in first 4MB (8,192 blocks) | Exact comparison |

### 3b. Format signature scan

Full 32MB scanned at every 4-byte-aligned offset for: SELF (`4F 15 3D 1D`, `54 14 F5 EE`), ELF (`7F 45 4C 46`), SCE (`53 43 45 00`), PFS (`50 46 53 43`). **Zero matches.**

### 3c. Structural uniformity

No low-entropy region found at any 512KB boundary. No header, footer, or metadata region distinguishable from the body.

### 3d. What these measurements establish and do NOT establish

**Established:** The file has no recognizable container format from byte 0 through byte 32,689,663. Its byte distribution is inconsistent with plaintext x86-64 code (which has ~6.0–6.5 bits/byte entropy, frequent `0x00`/`0xCC` bytes, and recurring prologue patterns). It is also inconsistent with standard compression formats (which have format headers). Zero repeated 16-byte blocks rules out AES-ECB mode specifically.

**NOT established:**
- The exact cipher (AES-CBC, AES-CTR, AES-XTS, ChaCha, or other)
- The key source (SAMU hardware, PUP header derivation, console-specific fuse, or other)
- Whether the opacity is firmware-version-specific (as opposed to key-specific, device-specific, or a processing error)
- Whether there are additional processing steps not performed by this extraction tool
- That a live kernel dump is the only possible path to plaintext

## 4. Cross-Component Comparison — OBSERVED

### Critical experiment: original PUP bytes vs decrypted output

| Component | PUP offset | Bytes compared | Bytes differing | Output format |
|-----------|-----------|---------------|-----------------|---------------|
| **5_kernel.bin** (block 0) | `0x400 + 0x1726C95` | 512 | 511 | High-entropy, no structure |
| **2_updatemode.self** | `0x4B2F9000 + 0xABBD11` | 256 | 256 | SELF magic `54 14 F5 EE` (**correct plaintext**) |

**Kernel:** First 16 bytes at PUP source offset:
```
4C AC 2E 44 A8 85 39 AA 93 90 BB E9 4D E0 90 F3
```
First 16 bytes of decrypted output:
```
37 63 BD 98 A4 8C 91 95 A1 33 FE AA 8F 09 FC 99
```
511 of 512 bytes differ. The ioctl **transformed the data** — this was not a no-op. But the output contains no recognizable format.

**updatemode.self:** First 16 bytes at PUP source offset:
```
0A A1 A4 39 69 4C 0F 27 44 3F C5 A6 B9 8D 58 32
```
First 16 bytes of decrypted output:
```
54 14 F5 EE 10 01 01 32 01 07 00 10 B0 02 F0 03
```
256 of 256 bytes differ. Output begins with SELF magic — **correct plaintext produced**.

### Other plaintext components

| Component | Format in `.dec` | Evidence |
|-----------|-----------------|----------|
| `12_version_name.xml` | Plaintext XML `<?xml...>` | First 4 bytes: `3C 3F 78 6D` |
| `15_bd_firm_info.json` | Plaintext JSON `{` | First 4 bytes: `7B 0D 0A 20` |
| `4_mbr.bin` | Plaintext ASCII | Readable string `SonyInteractiveEntertainmentLLC` |

### PUP header comparison

First 16 bytes of PUP entry 1 are **identical** in original BLS and `.dec`:
```
54 14 F5 EE 10 01 01 32 04 00 00 00 B0 05 E0 0D
```
Bytes 16+ differ (header decryption transformed the segment table region, not the file magic).

### What this comparison establishes

1. The PUP block decryption ioctl (`0xC0284406`) **did transform** kernel bytes — not a passthrough.
2. The **same device and code path** on the **same 13.60 console** produced correct plaintext for updatemode.self.
3. Multiple non-kernel components (XML, JSON, MBR) are also correctly decrypted plaintext.
4. The kernel is the only large component whose decrypted output has no recognizable format.

## 5. PUP Segment Table — OBSERVED

33 segments in PUP entry 1. Key entries for this analysis:

| Idx | Flags | ID | Type | Notes |
|-----|-------|----|------|-------|
| 1 | `0x00230007` | 2 | TABLE | Table for updatemode.self (segment 8) |
| 8 | `0x00207C06` | 2 | DATA+BLK | updatemode.self — 23 blocks, not compressed |
| 14 | `0x00400006` | 4 | DATA | MBR — single segment, not blocked |
| 15 | `0x01010007` | 16 | TABLE | Table for kernel (segment 16) |
| 16 | `0x00507806` | 5 | DATA+BLK | **Kernel** — 63 blocks, not compressed, block factor 7 (512KB) |

Segment flags decode:
- Bit 0 (`0x1`): table segment
- Bit 1 (`0x2`): encrypted
- Bit 3 (`0x8`): compressed
- Bit 11 (`0x800`): blocked (split into block_size chunks)
- Bits 12-15 (`0xF000`): block size factor → `1 << (factor + 12)` bytes per block
- Bits 20+: component ID

**Kernel flags `0x00507806`:** encrypted (bit 1), blocked (bit 11), block factor 7 → 524,288 bytes/block, component ID 5. compressed_size = uncompressed_size = `0x1F2CE00` (32,689,152) — **not compressed**.

**updatemode.self flags `0x00207C06`:** encrypted, blocked, block factor 7, component ID 2. Also not compressed.

Both the kernel and updatemode.self have identical flag patterns (encrypted, blocked, not compressed, same block factor). The decryption code path is the same for both. **The only operational difference is the segment index passed to the SAMU ioctls (16 vs 8).**

## 6. Processing Stage Diagram — Component ID 5 (Kernel)

```
STAGE 1: BLS Container (outer)
┌──────────────────────────────────────────────────────────────┐
│ PS5UPDATE_14.10_RECOVERY.PUP                                │
│ Magic: SLB2                                                  │
│ Entry 0: PS5UPDATE1.PUP at BLS offset 0x400                 │
│ Entry 1: PS5UPDATE2.PUP at BLS offset 0x4B2F9000            │
│                                                              │
│ ioctl 0xC0104401: verify BLS header → PASSED                │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
STAGE 2: PUP Header Decrypt
┌──────────────────────────────────────────────────────────────┐
│ PS5UPDATE1.PUP header                                        │
│ Magic: 54 14 F5 EE (preserved; not encrypted)                │
│ 33 segments in segment table                                 │
│                                                              │
│ ioctl 0xC0184402 (type=1): decrypt header → PASSED           │
│ Result: segment table bytes transformed (offsets, flags,     │
│         sizes now readable)                                   │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
STAGE 3: Segment Verification (two passes)
┌──────────────────────────────────────────────────────────────┐
│ Pass 1: 0xE0000000-flagged segments (additional signatures)  │
│   ioctl 0xC0184403 per segment → ALL PASSED                 │
│ Pass 2: 0xF0000000-flagged segments (watermarks)             │
│   ioctl 0xC0184404 per segment → ALL PASSED                 │
│                                                              │
│ ⚠ Verification operates on encrypted data — passing does    │
│   NOT prove the decryption key is correct for this console   │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
STAGE 4a: Kernel Table Decrypt (segment 15, ID=16)
┌──────────────────────────────────────────────────────────────┐
│ Table segment for kernel: 2016 bytes (63 × 32B entries)      │
│                                                              │
│ ioctl 0xC0184405 (index=15): decrypt table → ret=0           │
│ Saved as: tables/16_for_5.img                                │
│ Output: high-entropy 32-byte entries (0.45% zeros)           │
│                                                              │
│ ⚠ Table output is high-entropy. Whether this is correct      │
│   (verification tags are inherently high-entropy) or wrong   │
│   (garbled by wrong key) is unknown                          │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
STAGE 4b: Kernel Block Decrypt (segment 16, 63 blocks × 512KB)
┌──────────────────────────────────────────────────────────────┐
│ For each block i = 0..62:                                    │
│   Read 524,288 bytes from PUP at segment offset + i*512KB    │
│   ioctl 0xC0284406(entry_index=16, block_index=i,           │
│                     block_buf, 524288, table_buf, 2016)      │
│   → ALL 63 returned 0                                        │
│   Write transformed block to output                          │
│                                                              │
│ ⚠ The ioctl receives: segment index, block index, block      │
│   data, and the decrypted table. Key derivation details      │
│   (what inputs → key) are inside the SAMU and unobservable.  │
│   ret=0 confirms the SAMU accepted the operation, NOT that   │
│   the output is correct plaintext.                           │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
STAGE 5 (output): 5_kernel.bin
┌──────────────────────────────────────────────────────────────┐
│ 32,689,664 bytes (32,689,152 from blocks + 512 tail)         │
│ SHA-256: 8cb90195...c15c91905                                │
│ Entropy: 7.94-7.96 bits/byte (uniform)                       │
│ Format signatures: none found                                │
│                                                              │
│ Status: OPAQUE — not recognizable as code, ELF, SELF,        │
│         or any known container                                │
└──────────────────────────────────────────────────────────────┘

        ═══════════════════════════════════════════════════
        COMPARISON: Same pipeline, different segment
        ═══════════════════════════════════════════════════

STAGE 4': updatemode.self (segment 8, table at segment 1)
┌──────────────────────────────────────────────────────────────┐
│ Same code path, same console, same ioctls                    │
│ ioctl 0xC0184405 (index=1): decrypt table                    │
│ ioctl 0xC0284406 (entry_index=8, block_index=i): per block   │
│                                                              │
│ Output: SELF magic at byte 0, structured header, ELF at +0xE0│
│ → CORRECT PLAINTEXT                                          │
└──────────────────────────────────────────────────────────────┘
```

**The only code-level difference between the kernel and updatemode.self paths is the segment index passed to the SAMU.** Same device fd, same ioctl numbers, same buffer handling, same console.

## 7. STAGE ??? — What Happens AFTER PUP Block Decryption

**OBSERVED:** The extraction tool performs NO processing after `encsrv_decrypt_segment_block()`. Blocks are written directly to the output file.

**UNKNOWN:** On a real PS5 performing a system update, what happens to the kernel after PUP block decryption?

The extraction tool was written to capture PUP-decrypted data. A real PS5 update would be performed by `updatemode.self` (the updater program), which:
1. Receives PUP-decrypted segments
2. Installs them to the SSD
3. The kernel is loaded from the SSD at boot

There may be additional processing between PUP extraction and SSD installation that this tool does not perform. Alternatively, the kernel may be stored encrypted on the SSD and decrypted by boot-stage hardware (SAMU/EAP KBL) at load time.

The 13.60 kernel was obtained via `kernel_copyout()` — reading from kernel virtual memory **after boot**. Whatever decryption occurs during the boot process would have already been applied.

## 8. Inferences — Explicitly Separated

### INFERENCE 1: The SAMU applied a wrong or incompatible key to the kernel blocks

**Basis:**
- The same code path produced correct plaintext for updatemode.self (segment 8) but opaque output for kernel (segment 16)
- The only operational difference is the segment index passed to the SAMU
- The SAMU returned success (ret=0) for both, so it does not signal key mismatches
- Non-kernel components (XML, JSON, MBR, updatemode.self) all produced correct plaintext

**Confidence:** MEDIUM. This is the simplest explanation but alternatives exist (see §8.2, §8.3).

**What would confirm it:** Re-running the same extraction on a 14.10 console. If the output becomes recognizable code, the key was firmware-version-specific.

### INFERENCE 2 (alternative): Correct PUP decryption, but an additional boot-time decryption layer exists

**Basis:**
- The PS5 boot chain includes SAMU and EAP KBL stages before the kernel runs
- The kernel is a higher-security component than user-mode executables
- SELF-format binaries (like updatemode.self) have their own encryption in ELF segments separate from PUP encryption — the kernel could have an analogous second layer without the SELF wrapper

**Confidence:** LOW-MEDIUM. No direct evidence for or against. The absence of any format header in the output is consistent with either wrong-key decryption or correct PUP decryption of a still-encrypted inner payload.

### INFERENCE 3 (alternative): Processing step missing from the extraction tool

**Basis:**
- The tool performs block decryption then writes directly — no decompression, no format conversion
- The PUP flags say `compressed=0` for the kernel, so the tool correctly skips decompression
- But the flags could describe PUP-level compression separately from kernel-level encoding
- The `flags2` field (`0x00000000` for kernel) and `block_info` structures are not fully decoded

**Confidence:** LOW. The tool handles all flag combinations documented in the PUP format. But unknown flags or post-processing steps could exist.

## 9. Remaining Unknowns

| # | Unknown | Impact | What would resolve it |
|---|---------|--------|----------------------|
| 1 | **Whether the SAMU key is firmware-version-specific for kernel segments** | CRITICAL — determines if the 13.60 console can ever produce kernel plaintext | Decrypt the same PUP on a 14.10 console, OR find documentation of the SAMU key hierarchy |
| 2 | **Whether an additional decryption layer exists between PUP extraction and boot** | CRITICAL — if yes, the PUP output might be correctly decrypted but still needs a second pass | Analyze `updatemode.self`'s ELF code for kernel installation logic, OR compare PUP output to what's on the SSD of a running system |
| 3 | **The exact key derivation inputs used by the SAMU for ioctl `0xC0284406`** | HIGH — determines which parameters (segment index, PUP header fields, console fuses) select the key | SAMU firmware reverse engineering or side-channel analysis |
| 4 | **What the 32-byte table entries encode** | MEDIUM — whether they are correctly-decrypted verification tags or garbled output from wrong-key table decryption | Compare to updatemode.self's table entries (`8_for_2.img`); if those are also high-entropy AND updatemode.self decrypted correctly, then high entropy in tables is normal |
| 5 | **The 512-byte tail of `5_kernel.bin`** | LOW — file is 512 bytes larger than the PUP segment's declared `compressed_size` (32,689,664 vs 32,689,152) | Check extraction tool's write accounting; may be block-alignment padding |
| 6 | **Whether the "pasted key list" mentioned by the user exists in the repo** | MEDIUM — could contain keys with purpose labels that narrow the decryption model | No key list file found in the repo; user may need to provide it |
| 7 | **Whether `flags2` or undocumented PUP fields control additional processing** | LOW-MEDIUM — `flags2=0` for kernel, but field semantics are not fully decoded | PUP format specification or comparative analysis across firmware versions |

## 10. Experiments — Completed and Proposed

### Experiment 1: Table entropy comparison — COMPLETED (OFFLINE)

**Hypothesis:** If updatemode.self's block table is also high-entropy, then high entropy in table entries is normal (inherently random verification tags), and the kernel table was correctly decrypted.

**Result:**

| Table | Entropy | Zero % | Entries | Compressed? | Correct plaintext produced? |
|-------|---------|--------|---------|-------------|---------------------------|
| `16_for_5.img` (kernel) | 7.8905 | 0.45% | 63 | No | **No** — kernel is opaque |
| `8_for_2.img` (updatemode) | 7.7171 | 0.00% | 23 | No | **Yes** — SELF magic in output |
| `6_for_22.img` (seg 6) | 7.1985 | 12.14% | 26 | Yes | (not checked) |
| `22_for_11.img` (seg 22) | 7.5771 | 8.41% | 51 | Yes | (not checked) |

**Conclusion:** The updatemode table is high-entropy (7.72 bits/byte) AND its data decrypted correctly. Tables for compressed segments have lower entropy because they include structured `pup_block_info` metadata alongside the 32-byte tags; uncompressed segments have only the tags.

**Table entropy is inherently high for uncompressed segments. The kernel table's entropy is normal.** The table decryption is consistent with being correct, narrowing the problem to the block-level decryption (ioctl `0xC0284406`).

### Experiment 2: updatemode.self inner analysis — COMPLETED (OFFLINE)

**Hypothesis:** `updatemode.self` contains code that processes the kernel during installation. Its ELF structure might reveal additional decryption steps.

**Result:** SELF header parsed:
- Magic: `0xEEF51454`, header size 688, 6 SELF entries
- ELF at +0xE0: x86-64, type `0xFE00` (Sony SELF), entry `0x400080`
- 3 LOAD segments: .text (RX, 645KB at vaddr 0x400000), .rodata (R, 590KB at 0x4A0000), .data+bss (RW, ~10MB at 0x534000)

**Limitation:** ELF segments are SELF-encrypted. Only headers are plaintext. Without SELF segment decryption keys, the updater's kernel-handling code cannot be examined offline.

**Conclusion:** This experiment is blocked. The updater's code is behind SELF encryption. A live 13.60 console could potentially load this binary for analysis, but that requires a SELF loader, which is outside current capabilities.

### Experiment 3 — PROPOSED: Modified segment index (REQUIRES 13.60 console)

**Hypothesis:** The SAMU's key selection depends on the segment index. If we modify the extraction tool to pass segment index 8 (updatemode's index) when decrypting kernel blocks, the output would change — proving the key is index-dependent.

**Steps:**
1. Modify `sdk_decrypt.c` line 274: change `index` to `8` for the kernel segment only
2. Run extraction for just the kernel segment
3. Compare output to original `5_kernel.bin`

**What the result means:**
- Output changes → SAMU key depends on segment index (confirms Inference 1)
- Output identical → key does NOT depend on segment index; other factors control it

**Risk:** LOW — reads from the same PUP, writes to a different output file, only changes one parameter.

### Experiment 4 — PROPOSED: Decrypt 13.60 kernel from its own PUP (REQUIRES 13.60 console + 13.60 PUP)

**Hypothesis:** If the same extraction tool decrypts the 13.60 PUP's kernel segment on the 13.60 console, the output should be recognizable x86-64 code (matching `kernel_text.bin`). This would confirm the extraction tool works correctly for same-version PUPs, proving the 14.10 opacity is a cross-version key mismatch, not a tool bug.

**What the result means:**
- 13.60 kernel decrypts to recognizable code → tool is correct, cross-version key mismatch confirmed
- 13.60 kernel also opaque → tool has a bug, or kernel requires additional processing regardless of version

**Prerequisite:** A 13.60 recovery PUP file.

**Recommendation:** Experiment 3 is the strongest discriminator and requires only a code change + re-run on the existing 13.60 console. It directly tests whether the segment index controls the key.

## 11. Coverage Table

### Verified Facts

| Fact | Evidence | Confidence |
|------|----------|------------|
| `5_kernel.bin` bytes extracted from PUP segment 16 | SHA-256 match, byte comparison | HIGH |
| PUP block decryption transformed kernel bytes (not a no-op) | 511/512 bytes differ at offset 0 | HIGH |
| Same code path produced correct plaintext for updatemode.self | SELF magic in decrypted output | HIGH |
| Same console produced correct plaintext for XML/JSON/MBR | Readable content in `.dec` components | HIGH |
| The only code-level difference between kernel and updatemode paths is segment index | Source code review of `sdk_decrypt.c` | HIGH |
| All 63 kernel block ioctls returned 0 | Research log, no error lines | HIGH |
| Kernel has no SELF wrapper or format header | 32MB magic scan, zero hits | HIGH |
| Kernel entropy is 7.94–7.96 bits/byte, uniform across file | Statistical measurement | HIGH |
| No AES-ECB repeated blocks in first 1MB | 65,536 16-byte block comparison | HIGH |

### Inferences

| Inference | Basis | Confidence |
|-----------|-------|------------|
| The SAMU applied wrong/incompatible key to kernel blocks | Same path works for other segments; only index differs; table entropy normal (Exp 1) | MEDIUM |
| An additional decryption layer may exist for kernel | Boot chain architecture; kernel obtained post-boot in 13.60 | LOW-MEDIUM |
| Tables are verification tags (high entropy is normal) | **CONFIRMED by Experiment 1** — updatemode table is equally high-entropy and its data decrypted correctly | HIGH |

### Unknowns

| Unknown | Status |
|---------|--------|
| Exact cipher algorithm and mode | Unknown (ECB excluded) |
| SAMU key derivation inputs | Unknown |
| Whether the opacity is firmware-version-specific | Unknown (not tested cross-version) |
| Whether additional boot-time decryption exists | Unknown |
| Key list referenced by user | Not found in repo |
| Purpose of 512-byte file size excess | Unknown |
