# Ghidra reference workflow: executed validation

2026-10-18. **13.60-labeled; acquisition authenticity unresolved.** This is
offline implementation analysis, not a 14.10 kernel test or vulnerability finding.

Implemented and ran [the reusable workflow](../tools/ghidra/README.md) using the
already-installed Ghidra 12.1.4. The imported original files were read as data;
no imported code, console command or payload was executed. No software was installed.

## Actual outputs

- Prepared 679 reference records from the retained range-family index.
- Created and read back **679 labels at 301 distinct recorded targets**. These
  are aliases, including shared entry targets, not an implementation count.
- Retained the recorded argument counts as annotations; assigned no prototypes.
- Imported `kernel_text.bin` at analytical address zero and the separate
  `kernel_data.bin` at recorded relative coordinate `0x1000000`, length `0x400000`.
  Uncaptured gaps remain unmapped. This is not an ELF reconstruction or a claim
  about actual section boundaries or kernel permissions.
- Exported Ghidra pseudocode for selected offsets `0x3b0210` (AIO-associated body),
  `0xabd4f0` (scalar reader) and `0x2c6480` (write-lock-associated helper).

Published outputs are in
[`evidence/2026-10-18-ghidra-reference`](../evidence/2026-10-18-ghidra-reference).
The actual local project is
`C:/Users/marwa/Documents/PS5-Static-Analysis/20261018/Retained1360.gpr`.
The large project/database is kept outside Git; the scripts recreate it.
Original dumps, earlier evidence and previous commits were not rewritten.

The first attempt used a project directory under `.codex`; Ghidra rejected the
dot-prefixed path before import. A normal Documents directory resolved that
tool limitation. The REA Windows provider accepts native PE targets; direct
Ghidra headless raw import was used for this explicitly requested static task.

## Interpretation

The scalar reader's pseudocode reproduces the observed object chain and a
zero-extended 32-bit read at `+0x1c4`. The write-lock helper reproduces the
unit increment at that field after its lock path. This corroborates the earlier
instruction review; it is not independent firmware-authentication evidence.

The AIO output includes **type-propagation and overlapping-global warnings**.
They remain intact. Function boundaries, parameter types and unknown callees
are Ghidra analysis results, not original C declarations. Whole-image automatic
analysis was disabled; only explicitly selected function starts were recovered
and decompiled. Reading this partial output does not establish an ownership
defect, exploitability or patch state.

Input identities are the previously retained range-family files and index in
`docs/dumps_13.60/`, source revision
`7e25a1174b5a3086b7e90d860d85f8ab7bad7a70`. Prior provenance/hash qualifications
remain unchanged; no prior whole-file comparison was repeated. Export-file
SHA-256 values identify the new generated outputs only.

## Tests and live-test disposition

Four Python unit tests passed: shared-target/count preservation, coordinate
conflict rejection, repeated-selector rejection and invalid-offset rejection.
Both Java scripts compiled and ran in actual Ghidra. Data-window import and
label readback succeeded; all three selected decompilations completed and the
project save succeeded. This verifies the tooling, not console behavior.

The requested “627–676 untouched” premise is inaccurate: the completed saved
51b log already records returns for 628, 632–634, 637, 640, 643, 646–648, 652 and
676. A return is not necessarily a valid ABI test. The independent audit did
reopen AIO, AF_ROUTE and module-query questions; that did not validate the
prepared 53x argument layouts or error collection.

The focused reassessment identified inherited selector/prototype assumptions,
guessed routing header sizes, a stale echo attribution, and no verified native
`errno` capture. A prior bounded live Lua metadata check found no errno accessor
under the named entries examined. That absence is not universal proof that an
accessor cannot exist. No 53x retest was executed in this Ghidra task.

No GPU DMA test was run. A GPU buffer or API alone does not demonstrate access
outside its authorized mappings. There is no new evidence here of GPU kernel
reads, kernel read/write, a bypass, or a 14.10 sysent implementation.
