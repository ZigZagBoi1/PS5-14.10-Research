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

1. **Top N ranking** - Handlers scored by exploit potential (calls, branches, memory writes, size)
2. **Category summary** - Counts of trivial, large, complex, multi-call handlers
3. **Exploit candidates** - Detailed breakdown of high-scoring handlers with call targets and CMP values
4. **Shared call targets** - Kernel functions called by multiple handlers (copyin/copyout candidates)

### Scoring criteria

| Factor | Points | Why |
|--------|--------|-----|
| Each CALL instruction | 3 | More calls = more attack surface |
| Each conditional branch | 2 | Complex logic = more bug potential |
| Function size per 64 bytes | 1 | Larger = more opportunity |
| Each memory write | 2 | Write primitives matter |
| RIP-relative LEA | 1 | Data structure references |
| CMP immediates | 1 | Switch/case dispatch |

Trivial stubs (<=5 instructions) score 0.

### Cross-referencing with Ghidra

The shared call targets section shows kernel function addresses called by multiple Sony handlers. In Ghidra (after running the labeler), navigate to these addresses to identify copyin, copyout, malloc, priv_check, etc. These are the functions whose callers are most interesting for exploitation.

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
