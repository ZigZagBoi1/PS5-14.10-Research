# The 30-bit error oracle, applied to syscalls 600-609

Run 2026-11-04 22:23, probe `1208a`, capture
`results/phase17_new_vectors/1208a_sony_range_branch_oracle_20261104_222301.txt`. The probe calls
each syscall in seven argument shapes and prints `get_error_string()` per shape; a shape-dependent
code means the handler validates its arguments and we are watching **which guard fires**.

Shapes: `Z` all zero; `a0`..`a3` one 0x1000-byte zeroed malloc'd buffer in that argument slot;
`one` arg0 = 1; `0x1_2` arg1 = 1, arg3 = 0x1000.

## Measured

| sys | Z | a0 | a1 | a2 | a3 | one | 0x1_2 | reading |
|---|---|---|---|---|---|---|---|---|
| 602 | 22 EINVAL | 1 EPERM | 1 EPERM | 1 EPERM | 1 EPERM | 1 EPERM | 1 EPERM | arg0 must be non-NULL, and then a privilege check refuses every other shape |
| 603 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | uniform refusal |
| 604 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | uniform refusal |
| 605 | 22 | 22 | 22 | 22 | 22 | 22 | 22 | the magic whitelist; none of these shapes is a magic |
| 606 | 22 | 22 | 22 | 22 | 22 | 22 | 22 | same front door |
| 607 | 14 EFAULT | **2 ENOENT** | 14 | 14 | 14 | 14 | 14 | arg0 is dereferenced as a NUL-terminated string; an empty buffer is a name that does not exist |
| 608 | 14 | 14 | 14 | **22 EINVAL** | 14 | 14 | 14 | the third argument is a required pointer |
| 609 | **connects, prints nothing, connection dies** | | | | | | | LETHAL |

## Static confirmation of each reading

- **602** body 0xa368e0, narg 3: `a36909 mov rax,[rsi]; test rax,rax; je EINVAL` then
  `a36912 mov esi,0x2af; call 0x8b49fa30` — a named privilege check. EPERM 1 is that check
  refusing, not a missing capability of the syscall.
- **607** body 0xabc710, narg 2: `abc744 mov r12,[rsi]` — argument 0 is a pointer, loaded once and
  handed to a lookup. Empty string -> ENOENT, null pointer -> EFAULT.
- **608** body 0x34bdc0, narg 3: `34be0c mov r14,[rsi+0x10]` (argument 2 as a pointer) and the
  NULL case is rejected before any copyout. This is `dynlib_get_info_ex`, already documented.
- **609** resolves to body **0x5620e0**, the stub shared by 368 syscalls: it takes
  `mtx_init(proc+0x148, ...)`, zeroes a 0x70-byte frame, and then continues into code that our
  process cannot survive. It is not a per-syscall handler at all, which is why its sysent row says
  narg 0 and why nothing about the call shape mattered.

## Why this instrument is worth keeping

Three of these eight calls produced **shape-dependent codes**, and each difference is a branch we
can now name without reading a single byte of kernel text. The previous instrument (rv) reported
0 for every one of these calls.

## Status

Sweep stopped at 609: the payload process died, and this time the listener did too
(`port_witness` -> `LOADER-DEAD connect refused`). The sweep resumes at 610 (probe `1208b`,
already written, 609 added to the skip set) once the loader is back.
