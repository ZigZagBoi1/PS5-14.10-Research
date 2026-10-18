# PS5 13.60 Kernel Reverse Engineering Tools

## Files

| Tool | Path | Purpose |
|------|------|---------|
| Ghidra syscall labeler | `tools/ghidra_label_syscalls.py` | Labels all 679 syscall handlers in Ghidra |
| Capstone disassembler | `tools/disasm_handlers.py` | Analyzes 145 Sony handler .bin dumps |
| Sysent index | `docs/dumps_13.60/sysent_index.json` | All 679 sysent entries with addresses |
| Handler dumps | `docs/dumps_13.60/handler_NNN.bin` | 4KB raw code dumps per Sony syscall |

## Prerequisites

- **Ghidra script:** Ghidra 10.x+ with the PS5 13.60 kernel ELF loaded
- **Capstone script:** Python 3.8+, `pip install capstone`

## Ghidra Script: ghidra_label_syscalls.py

### What it does

1. Reads `sysent_index.json` (679 syscall entries)
2. Auto-rebases addresses if Ghidra's image base differs from the dump's `0xffffffff8a9c0000`
3. Creates a `Syscalls` namespace with labels for every handler:
   - Standard FreeBSD: `sys_read`, `sys_write`, `sys_mmap`, etc. (0-531)
   - Sony proprietary: `sony_syscall_532` through `sony_syscall_676`
   - nosys stubs: `nosys_NNN`
4. Adds plate comments: `Syscall #NNN | narg=N`
5. Creates functions at unlabeled addresses

### Setup

Copy `sysent_index.json` next to the script, or edit `SYSENT_JSON` at the top of the file.

### Running

1. Open the kernel ELF in Ghidra
2. Script Manager -> Run Script -> select `ghidra_label_syscalls.py`
3. Check the console for: `Done: 679 syscalls labeled`

### After labeling

- Window -> Symbol Table -> filter by namespace `Syscalls`
- Sony handlers: filter for `sony_syscall_`
- Navigate to any handler by double-clicking its label
- Cross-reference: right-click a function -> References -> Find references to

## Capstone Script: disasm_handlers.py

### Basic usage

```bash
# Default analysis (top 20 most interesting handlers)
python tools/disasm_handlers.py

# Save report to file
python tools/disasm_handlers.py --out docs/research/handler_report.txt

# Full disassembly of specific handlers
python tools/disasm_handlers.py --full 572 --full 596 --full 624

# Show top 50 handlers
python tools/disasm_handlers.py --top 50

# Custom paths
python tools/disasm_handlers.py --dir /path/to/bins --json /path/to/sysent_index.json
```

### Output sections

1. **Handler summary** - All 145 handlers ranked by thunk count with entry RVA and first target RVA
2. **Categories** - Breakdown of nosys stubs vs real handlers
3. **Shared implementation targets** - Kernel functions referenced by ALL handlers (common infrastructure: copyin, malloc, priv_check etc.)
4. **Top referenced targets** - Hot kernel function addresses for Ghidra labeling
5. **Unique-target handlers** - Handlers with dedicated implementations (most interesting)
6. **Nosys vs real** - Which syscalls point to null/nosys

### Key discovery: thunk table architecture

The handler .bin dumps are NOT inline code. Each is a 4KB page of 8-byte JMP thunk entries (5-byte `jmp rel32` + 3 `int3` padding). All 145 handlers have exactly 512 thunk entries each.

The first thunk is the syscall's actual handler implementation. The remaining ~500+ thunks are shared kernel utility functions (copyin, copyout, malloc, etc.) that the handler calls. This is a PLT-like structure.

Handlers sharing the same first target (e.g., `+0x5620e0`) likely share the same implementation -- often a nosys/null stub.

### Cross-referencing with Ghidra

1. The **first target RVA** of each handler is where the real implementation lives in the kernel. Navigate to `kernel_base + first_target_RVA` in Ghidra.
2. Targets referenced by ALL 145 handlers are common kernel functions. Label these in Ghidra (copyin, copyout, priv_check, etc.) by analyzing their code.
3. Handlers whose first target is unique to them have dedicated Sony implementations -- these are the most interesting for vulnerability research.

## Workflow

1. Run `disasm_handlers.py` to identify the most interesting Sony syscalls
2. Load the kernel ELF in Ghidra, run `ghidra_label_syscalls.py`
3. Navigate to the top-scored handlers in Ghidra for full analysis
4. Identify shared call targets (copyin/copyout/priv_check)
5. Write probes (in `probes/`) targeting the most promising handlers
6. Test on the live PS5 via `make_syscall(NNN)`

## Key numbers

- Kernel base (13.60 dump): `0xffffffff8a9c0000`
- nosys stub RVA: `+0x265760`
- sysent stride: 48 bytes
- Total entries: 679 (311 active, 368 nosys)
- Sony range: 532-676 (145 entries, ~115 with real handlers)
- Handler dumps: 4096 bytes each (may contain padding past the real function end)
