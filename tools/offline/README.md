# Offline analysis tooling (13.60 capture)

Tools for decoding the retained 13.60 kernel capture in `docs/dumps_13.60/`
without a console. Python scripts run under the repo venv
(`uv venv .venv && uv pip install capstone pyelftools`); Java scripts run as
Ghidra headless post-scripts.

## Python (capstone)

- `handler_extract.py` — resolve the sysent thunk table (`e9 rel32 + int3`)
  to real handler RVAs inside `kernel_text.bin`; dump per-syscall inventory
  or disassembly. `python tools/offline/handler_extract.py 604 636`
- `dis_rva.py` — disassemble an arbitrary RVA range.
- `kptr_hunt.py` — classify every copyout/copyin call site in the 145 Sony
  handlers by source provenance (object deref / stack scalar / register
  chain); object-sourced copyouts are the leak candidates.

## Ghidra (headless)

Project setup (one-time):

```bash
~/tools/ghidra_12.2_PUBLIC/support/analyzeHeadless ~/tools/ghidra_proj ps5kernel \
  -import docs/dumps_13.60/kernel_text.bin \
  -processor "x86:LE:64:default" -loader BinaryLoader \
  -loader-baseAddr 0xffffffff8a9c0000 -cspec gcc
```

Then per-run (`-noanalysis` reuses the analyzed program):

```bash
~/tools/ghidra_12.2_PUBLIC/support/analyzeHeadless ~/tools/ghidra_proj ps5kernel \
  -process kernel_text.bin -noanalysis -scriptPath tools/offline \
  -postScript DecompileList.java <addr_file> <out_dir>       # lines: <abs_addr> <name>
~/tools/ghidra_12.2_PUBLIC/support/analyzeHeadless ~/tools/ghidra_proj ps5kernel \
  -process kernel_text.bin -noanalysis -scriptPath tools/offline \
  -postScript CopyoutReach.java <thunk_file> <out_file>      # lines: <num> <thunk_rva>
```

Notes: addresses are absolute (`0xffffffff8a9c0000 + RVA`); the program's
image-base metadata is 0 — scripts use the memory-block start. Thunks are not
disassembled by default; `CopyoutReach` forces them.
