# Syscall 601 dispatch audit: 13.60 capture and 14.10 gate

The earlier descriptions of syscall 601 commands `0x05`, `0x06`, `0x0c`,
`0x10`, and `0x12` in `VERIFIED_HANDLER_ANALYSIS.md` and probe 83a do not
match the retained 13.60 instruction bytes. Do not use the probe's auth or
process-write sections as evidence for a privilege bypass.

## Artifact and mapping

- Raw text: `docs/dumps_13.60/kernel_text.bin`, SHA-256
  `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`.
- ELF carrier containing matching bytes at the cited text RVAs:
  `ps5_1360_live_memory_analysis.elf`, SHA-256
  `f1c10593d8f1954179a53a749bbc455f53d690b53f7b2b5ef1b6385ee796ea1b`.
- The 13.60 sysent entry 601 points to the thunk at text RVA `0x265e18`,
  which jumps to RVA `0xca0630`. The handler reads a command from the first
  syscall argument slot and dispatches values `0x00`–`0x27` through a signed
  32-bit relative jump table at RVA `0x1a51160` in the retained data.

Selected table entries, decoded from the retained bytes:

| Command | Target RVA | Observed entry behavior |
|---|---:|---|
| `0x05` | `0xca221c` | Common return, with entry-initialized `r14d=0x4e` |
| `0x06` | `0xca221c` | Same common return |
| `0x0c` | `0xca0e7d` | Reads `proc+0x568`, then a state field; no `copyin` from the supplied auth buffer on this path |
| `0x10` | `0xca15df` | Checks argument slots and accepts only subvalues 1 or 2 before internal calls; not an unconditional page copyout |
| `0x11` | `0xca0f58` | With arg2 zero, copies a 0x18-byte request from arg3, allocates 0x480 bytes, copies user data into that allocation, and attaches it to process state with a `0x400` flag |
| `0x12` | `0xca1032` | Requires the second argument slot to be zero, then copies 0x18 bytes from the third argument slot and checks copied fields; not an unchecked 16-byte process write |
| `0x24`, `0x25` | `0xca067f` | Shared path copies 0x10 bytes from the second argument slot and branches on command value |

The dispatch-table mapping is a static observation of this **13.60-labeled**
capture. The capture's acquisition authenticity and the 14.10 implementation
remain unverified. It does, however, directly contradict the proposed 13.60
`0x05` info-leak, `0x06` process-write, and `0x0c` two-byte auth labels.

Further disassembly of `0x12` at RVAs `0xca1032`–`0xca10d6` and
`0xca1b2c`–`0xca1ba2` shows a conditional **copyout**: after finding the
`0x400` process flag, it reads the process's existing `+0x578` buffer,
copies up to `0x480` bytes to the user pointer in the request, frees the
buffer, and clears that process pointer. The routine at `0x2591d0` validates
the second argument as a user destination; the routine at `0x259280` validates
the first argument as a user source. This is a paired buffer-store/read path,
not evidence that command `0x12` assigns arbitrary user qwords to
`proc+0x578/+0x580`. The `0x11` path also writes other process fields; its
authorization and cleanup behavior on 14.10 have not been established.

## Live 14.10 result

`results/phase17_new_vectors/83a_sys601_deep_retest_20261022_200903.txt`
records PID 192 and a live canary. Command `0x00` returned 0; `0x01`,
`0x05`, and `0x10` returned -1; `0x07`, `0x09`, and `0x0d` returned 0 but
their inspected output buffers remained zero. No kernel pointer or memory
read/write primitive was demonstrated. The meaning of those zero returns
requires more work; they cannot be interpreted from the stale probe labels.

The corrected read-only probe `83c_sys601_arg2_copyout.lua` recorded
`cmd0_rv=0`, `arg2_after=0x00000000_00000100`, and an unchanged sentinel in
arg3. With arg2 null and arg3 valid, the same command returned `-1` and did
not modify arg3. PID and canary both remained 192. Capture:
`results/phase17_new_vectors/83c_sys601_arg2_copyout_20261022_201232.txt`.
This validates the output argument on 14.10 and rules out a kernel pointer
from this particular command response.

## Next gate

For syscall 601, obtain a trustworthy 14.10 implementation or design a
probe around one command whose argument layout is established from static
bytes and whose output can be checked against controls. The current 83a
sections B–D should remain unrun until their command semantics are corrected.
