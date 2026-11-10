# 13.60 Hardware Session Runbook

> **Purpose:** maximize data extraction from the next jailbroken 13.60 console session.
> Every payload here is pre-built and tested for syntax. Run them in priority order.
> Stop only when the console needs a reboot or the session ends.

## Prerequisites

- PS5 on firmware 13.60 with kernel R/W (etaHEN/Relapse + Byepervisor Reborn)
- LAN connection: PS5 at known IP, host at 10.0.0.80
- etaHEN payload loader accepting ELF or Lua payloads on TCP
- USB drive formatted exFAT (for large dumps)

## Priority 1: Vtable RVA Extraction

**Why:** the 14.10 FontFace UAF chain is hard-blocked on the WebProcess text base.
VP = 0x80f4b9b28 (leaked on 14.10). If we extract the CSSFontFaceSet vtable RVA from
the 13.60 binary, then: `14.10_WebProcess_base = VP - RVA` (assuming shared WebKit build).

**Payload:** `tools/jailbreak-host/research_payloads/06_vtable_rva_extract.lua`

**What it does:**
1. Enumerates all processes via sysctl KERN_PROC_ALL
2. Identifies WebProcess / SceShellCore PIDs
3. Tests kernel read capability (reads known kernel addresses)
4. If kernel read works: dumps WebProcess text section, scans for vtable at page offset 0xB28
5. Validates: 8 function pointers matching CSSFontFace::Client ABI (2 dtors, fontLoaded,
   fontStateChanged, fontPropertyChanged, updateStyleIfNeeded, ref, deref)

**Expected output:**
- Process list with WebProcess PID
- Kernel read confirmation (or fallback instructions)
- Vtable RVA value (hex offset from WebProcess text base)

**Capture:** save the full output. The RVA is the single most valuable number.

## Priority 2: Kernel Segment Offsets

**Why:** the 14.10 Debug Settings enablement needs 3 kernel byte writes at known offsets
from DATA_BASE. The 13.60 kernel gives us the offset table to validate against.

**Payload:** `tools/jailbreak-host/research_payloads/07_kernel_segment_offsets.lua`

**What it does:**
1. Reads kernel text base (from etaHEN or known address)
2. Reads segment headers to find DATA segment base and size
3. Extracts key offsets: allproc, security_flags, qa_flags, sysent table
4. Dumps first 256 bytes of each critical structure for pattern matching

**Expected output:**
- Kernel text base, data base, data size
- Offset table for critical structures
- Raw hex dumps for cross-reference with 14.10 fault oracle data

## Priority 3: Full Sysent Table Dump

**Why:** the 14.10 sysent map has gaps (677-734 kill zone). The 13.60 table gives ground
truth for handler addresses, argument counts, and which slots are real vs nosys stubs.

**Payload:** `tools/jailbreak-host/research_payloads/03_sysent_dump.lua`

**What it does:**
1. Locates sysent array from kernel base + known offset
2. Reads all entries (up to 735): handler address, narg, flags
3. Identifies nosys stubs, real handlers, and Sony custom range (532-676)
4. Cross-references with the 14.10 behavioral map

**Expected output:**
- Complete sysent table with handler addresses
- nosys identification
- Sony custom syscall signatures

## Priority 4: WebProcess Binary Dump

**Why:** the WebKit binary contains every vtable, gadget, and offset we need for the
14.10 exploit chain. Even if the builds differ between 13.60 and 14.10, the structure
gives us a template for all code-reuse chains.

**What to dump:**
1. WebProcess .text section (code, RX)
2. WebProcess .rodata section (vtables, constants)
3. WebProcess .data section (writable globals)
4. Module info: base addresses, segment sizes, protections

**Method:** use kernel R/W to read the WebProcess address space.
The process can be identified by name from the allproc list.

**Size warning:** WebProcess .text alone could be 50-100 MB. Use USB for storage
or stream over network in chunks.

## Priority 5: PUP Key Extraction (if time permits)

**Why:** decrypting the 14.10 PUP gives us the exact binaries without needing to
dump them from a running process. See issue #239 for full context.

**Payload:** `ps5_key_extractV4.elf` from TitaniaPy project

**Note:** cobrajet302gt's audit (issue #239) confirms the payload is read-only
(no kernel/flash/NVS writes). It reads CCP key slots and security processor registers.
The container key is necessary but not sufficient -- kernel text needs at least one
further decryption layer. Still worth running: the key serves all firmware versions.

## Session Protocol

### Before connecting:
1. Verify console is on 13.60 with kernel R/W active
2. Run `python tools/state.py check --ip <console>` from the host
3. Prepare USB drive if dumping large binaries
4. Have `tools/jailbreak-host/orchestrator.py` ready

### During the session:
1. Run payloads in priority order (P1 through P5)
2. Save every output immediately -- do not rely on console state persisting
3. If a payload crashes the process, reconnect and continue with the next priority
4. After each payload: `python tools/state.py row <probe> --claim "..." --result "..." --grade M`

### After the session:
1. Verify all captures are saved and readable
2. If vtable RVA was extracted: compute 14.10 WebProcess base = 0x80f4b9b28 - RVA
3. If kernel offsets were extracted: update `docs/DEBUG_SETTINGS_CHAIN_14_10.md`
4. If sysent was dumped: update `docs/SYSENT_PRESENCE_14_10.md` kill-zone analysis
5. Commit everything and push to GitHub
6. Update issue #239 with results

## What Success Looks Like

**Best case (all 5 priorities complete):**
- Vtable RVA extracted, 14.10 WebProcess base computable from any VP leak
- Kernel offset table for Debug Settings byte writes validated
- Complete sysent map resolves the 677-734 kill zone
- WebProcess binary available for gadget search
- PUP key extracted for future firmware analysis

**Minimum viable session (P1 only):**
- Vtable RVA number extracted and validated
- This single number unblocks the entire 14.10 FontFace exploit chain

**If kernel read does not work:**
- The fallback in payload 06 documents exactly what kernel offsets are needed
- Process enumeration still gives WebProcess PID and module layout
- This narrows the problem for the next attempt
