# UMTX Op Map — 13.60 Capture, Syscall 454

> **Date:** 2026-10-21. Source: `docs/dumps_13.60` (13.60-labeled; acquisition
> authenticity unresolved). Extracted from the syscall 454 handler's 27-entry
> jump table (table rva 0xe6baa0, dispatcher rva 0x37ec40, bound check
> `cmp rax, 0x1b`). All targets resolve inside the captured text. Extends
> `docs/UMTX_454_EVIDENCE.md`.

## Op handlers

| op | handler rva | shape | note |
|----|-------------|-------|------|
| 0, 1 | 0x37fa90 | stub `mov eax, 0x2d; ret` | WAIT/WAKE return 45 (EOPNOTSUPP) |
| 2 | 0x37faa0 | full (owner-flag mask 0xf000000000000000) | mutex-family |
| 3 | 0x37fbc0 | full, dl=0x3f | |
| 4 | 0x37fc70 | tail `mov rsi,[rsi]; ecx=1` | try-lock shape |
| 5 | 0x37fc90 | full | 14.10-measured: writes owner TID (56i2) |
| 6 | 0x37fd70 | tail `mov rsi,[rsi]` | unlock shape |
| 7 | 0x37fd80 | full | |
| 8-15 | 0x380260-0x381900 | full | CV/PP family |
| 16 | 0x3819f0 | reads [rsi] and [rsi+0x10] | two-arg op |
| 17-24 | 0x381a10-0x383120 | full | sem/rw family |
| 21 | 0x382480 | full | 14.10-measured: ret 0 (56i2) |
| 25 | 0x3835b0 | full | SHM (stubbed semantics on 14.10, probes 151a-152k) |
| 26 | 0x3837f0 | stub `mov eax, 0x4e; ret` | returns 78 |

Ops 0 and 1 being stubs means phase-1/2-style `WAIT/WAKE` semantics never
existed on syscall 454 for this firmware line; blocking behavior has to come
from ops 2/5/8+.

## Dispatcher detail

- The op table is indirect through the L1 thunk table (rva 0x265608-0x2656d0),
  so every op resolves through two jmp levels.
- The dispatcher verifies each target against a base pointer with
  `sub rax, rcx; ror rax, 3; cmp rax, 0x3a5` before `jmp rcx` — a CFI-style
  range check around the jump table.
- Out-of-range op (>= 0x1c) returns 0x16 (EINVAL) directly.

## Probe

`probes/phase17_new_vectors/273a_umtx_waiter_vs_remap.lua` (CRASH_CLASS HIGH):
main locks a umtx word with op 5, a 158c-style child (RIP = syscall tail,
RAX = 454, RDI = word, RSI = 5) blocks on it, then the main thread replaces
the mapping with `mmap MAP_FIXED` and attempts unlock; a munmap control runs
on an unwaited page. A panic on wake = kernel bug; clean revalidation bounds
the waiter-vs-vm surface.
