# Retained 13.60 Ghidra reference workflow

This imports retained bytes into a **separate offline Ghidra project** and applies
reference labels from `docs/dumps_13.60/sysent_index.json`. Every label/comment is
**13.60-labeled; acquisition authenticity unresolved**. No offsets, layouts,
handler names or patch status transfer to 14.10. These scripts never contact a
console, execute imported code or modify the original dumps.

679 table records are not 679 distinct functions. Shared targets receive multiple
`sc_ref_NNN` labels at the same address. The current index produces 301 distinct
recorded targets; this is not an implemented-syscall count. Recorded `narg` values
are comments only, including implausible values. No prototypes are assigned.
Stub labels remain at the recorded targets; the script does not reinterpret the
compatibility map or repeat the prior branch/table comparisons.

## Prepare and test

Use Python 3 and a local Ghidra installation with its supported Java runtime.
No dependency installation or console connection is required.

```powershell
python -m unittest discover -s tools/ghidra -p 'test_*.py' -v
python tools/ghidra/prepare_sysent_map.py docs/dumps_13.60/sysent_index.json C:/PS5-Analysis/sysent-reference.tsv
```

Create the output parent first; the TSV is created exclusively to protect earlier
analysis. Coordinate disagreements, negative offsets and repeated selectors are
rejected rather than silently reconciled. This is annotation-input validation,
not another raw table comparison or firmware-authentication check.

## Import into a new project

Choose a **new project name** and an output directory outside all source checkouts.
Ghidra rejects project paths containing dot-prefixed components such as `.codex`;
use a normal directory such as `C:/PS5-Analysis/projects`. Do not use `-overwrite`.
The example uses file-relative addresses starting at zero, an analytical
coordinate choice rather than an authenticated kernel base.

```powershell
& 'C:/Tools/ghidra/support/analyzeHeadless.bat' C:/PS5-Analysis/projects Retained1360 `
  -import F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin `
  -loader BinaryLoader -loader-baseAddr 0 -processor x86:LE:64:default -cspec gcc `
  -noanalysis -max-cpu 2 -scriptPath F:/PS5-14.10-Research/tools/ghidra `
  -postScript LabelRetainedSysent.java C:/PS5-Analysis/sysent-reference.tsv C:/PS5-Analysis/decompiled 0 0x3b0210 0xabd4f0 0x2c6480
```

`TEXT_FILE_ORIGIN` (the `0` argument) must match where text file offset zero was
imported. The optional final offsets select specific already-reviewed function
locations for disassembly/function recovery and decompiler export. They are not
new verified symbols. Omit them for annotation-only operation. The export
directory must not already exist. Label readback is checked and recorded.
Existing primary names are retained; aliases do not overwrite curated symbols.

Open the resulting `.gpr` in Ghidra to browse labels. Default whole-image
auto-analysis is disabled in this minimal workflow: selected functions are
disassembled and decompiled, while unexamined calls/types remain unresolved.
You may run ordinary static analysis in that separate project as needed.

## Add the recorded data window

The retained manifest records data at relative `0x1000000`. Its mapping is a
capture annotation, not an authenticated section boundary. Load only the
matching range-family data file; do not combine browser or compatibility-map
families. For the example project:

```powershell
& 'C:/Tools/ghidra/support/analyzeHeadless.bat' C:/PS5-Analysis/projects Retained1360 `
  -process kernel_text.bin -noanalysis -scriptPath F:/PS5-14.10-Research/tools/ghidra `
  -postScript ImportRetainedData.java F:/PS5-14.10-Research/docs/dumps_13.60/kernel_data.bin 0x1000000
```

The importer rejects overlap. Its read-only/non-executable analysis flags do not
establish original kernel permissions. Uncaptured gaps stay unmapped, not zero
filled. This is a partial requested-range reconstruction, not a complete kernel
ELF or hypervisor dump.

## Interpretation and validation limits

Decompiler C is **pseudocode**, not recovered original C. Undefined types,
calling-convention assumptions, unknown callees and warnings must be retained.
`LOCK()`/`UNLOCK()` emitted for atomic instructions do not by themselves identify
subsystem lock ownership. Review against instruction bytes and earlier ledgers.

Tested on installed Ghidra 12.1.4: raw-image import, all 679 aliases, three selected
decompilations, label readback and data-window import. See
`docs/GHIDRA_REFERENCE_VALIDATION_2026-10-18.md` for the actual run and limitations.

No GPU DMA probe or 14.10 kernel retest is included. A GPU interface or mapped
buffer alone does not establish access to kernel memory. The existing 53x
retests still have the interface/error-capture limitations recorded in the
focused reassessment; static script compilation is not console validation.
