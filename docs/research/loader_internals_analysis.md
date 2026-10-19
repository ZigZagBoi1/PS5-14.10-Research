# Loader Internals Analysis — Probe 52a Design Notes

> **Historical design hypotheses:** These notes predate 53d/56c/56f. Read [the ledger guide](../RESEARCH_EVIDENCE.md) and Findings 79/82 for selected CClosure results. The syscall dispatcher has not been identified from exact-build source/disassembly.

## Background

The Lua loader running inside "Hamidashi Creative" (Artemis engine) on PS5 14.10 provides memory R/W, syscall access via `make_syscall(N)`, and writable ROP-shaped metadata. Probe 45c recorded tested calls persisting after selected mutations; this contradicts the earlier dependency model for those calls, without proving universal non-use or a particular C implementation. Probe 47b attempted to find writable code pointers in CClosure structs but had two critical flaws.

## Gaps in Previous Probes

### 1. CClosure +0 Was Never Write-Tested (47b Bug)

Probe 47b's write test covered offsets +16, +24, +32, +40, +48 — but **not +0**. The summary says "C func ptr writable: false" referring to offset +0, but this was based on the redirect test failing (Section F), not an actual write test. The DeepSeek audit correctly identified this gap.

In Lua 5.1's standard CClosure layout on x86-64:
- +0: `GCObject *next` (GC linked list)
- +8: `lu_byte tt, marked` (type tag, GC mark bits)
- +16: `GCObject *gclist`
- +24: `Table *env`
- +32: `lua_CFunction f` ← the C function pointer
- +40+: upvalues

However, probe 47b showed +0 = `00000003_105AF820` and the "code bytes" read at that address were clearly struct data, not x86 instructions. This means either:
- The struct layout is non-standard (Sony/Artemis modified Lua)
- +0 is indeed GCObject.next (another Lua object pointer)
- The actual C dispatch is indirect

### 2. Module Matching Bug in 47b

47b's `find_module()` matched heap addresses (h=0x3, l=0x1XXXXXXX) to "mod0.text" because the text range check used 32-bit arithmetic that wrapped around. Address `0x00000003_105AF820` is a **heap pointer**, not in any module's text section. The eboot text base is around `0x00000000_7F478000` (from the ROP gadget offsets in probe results).

Probe 52a fixes this by comparing the full hi:lo pair against module ranges.

### 3. The C Dispatch Mechanism Is Unknown

make_syscall() creates a table with `syscall_no`, copies properties from `syscall.pipe`, and sets the same metatable. When called (Lua `__call` metamethod), the C function at CClosure.f is invoked. A historical hypothesis was that the C function reads syscall_no, marshals arguments and issues a syscall instruction. None of those internal steps is identified by the 45c log; they require exact-build source/disassembly. The tested mutations do not prove that every path bypasses fn_addr/ROP.

The C function itself may be in the eboot's .text (RX), in a system library .text (XO — unreadable), or in a custom loader page. If it's readable (eboot), we can disassemble it. If it's XO, we can only probe behavior.

## What Probe 52a Tests

### A. Full Module Map
Maps all dynlib text and data sections with correct hi:lo comparison. This is needed for accurate pointer classification.

### B. CClosure +0 Write Test
Tests writability of **every** offset 0 through 56 in the CClosure struct. If +0 is writable, it's just GCObject.next (GC chain, not exploitable). If +32 is writable and points to actual code, that's the target.

### C. C Function Dispatch Search
For each qword in the CClosure that could be a pointer, reads 16 bytes at the target to check for x86-64 function prologues (push rbp, sub rsp, endbr64, mov rbp rsp). Also follows indirect pointers (ptr → *ptr) to find code through one level of indirection.

### D. Eboot Data Section Scan
Scans the eboot's .data section for qwords that point into eboot .text. These are vtable entries, callback pointers, or dispatch tables. Tests each for writability. A writable function pointer in the data section that gets called during normal execution = code execution primitive.

### E. Pipe Object Neighborhood
Scans around the pipe object address for code pointers, testing each for writability. The C dispatch function's address may be stored near the pipe struct.

### F. fn_addr Structure
Although selected tested calls persisted after fn_addr mutations, the wider structure around it may contain the actual dispatch pointer or a recovery/longjmp address that IS used.

### G. All Metatable CClosures +0
Tests +0 writability on every function in the syscall.pipe metatable. If any metatable function's CClosure is writable at the C function pointer offset, we can redirect it.

### H. Global C Functions
Scans _G and standard library tables for C functions, testing their CClosure +0 writability. Even if syscall-related functions are protected, a string/math/io C function might be writable and redirectable.

### I. Longjmp/Return Path
The historical candidate layout ends with longjmp and labels a return_addr slot. Whether the dispatcher reads that slot, uses this chain, or exposes a controllable return path is unverified. Writability alone does not establish a hijack.

## Expected Outcomes

**Best case:** A writable code pointer (CClosure.f, vtable entry, or return_addr) that is called during normal execution, giving us arbitrary code execution.

**Likely case:** The C function pointer at +32 in CClosure is either read-only (protected page) or points to heap (not directly callable code). The eboot data section may have writable function pointers but they may not be called from our code path.

**Worst case:** All code pointers are in read-only pages or XO memory. The C dispatch is fully hardened with no writable indirection.

## Follow-up Probes

Based on 52a results:
- **52b**: If writable code pointers found, controlled redirect test (point to RET gadget, then to syscall gadgets)
- **52c**: If eboot data has writable vtables, find which ones are called and when
- **52d**: Scan the Lua VM state (L pointer) for dispatch tables — the Lua interpreter loop has a function dispatch table that may be writable
- **52e**: If the C function is readable, disassemble it to understand the exact syscall dispatch path and look for bugs (integer overflow in syscall_no validation, etc.)
