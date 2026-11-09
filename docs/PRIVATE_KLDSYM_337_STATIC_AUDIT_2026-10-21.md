# 13.60 `kldsym(337)` static gate audit — 2026-10-21

The retained 13.60 `docs/dumps_13.60/kernel_text.bin` (SHA-256 recorded in `PRIVATE_KERNEL_PRIMITIVE_TRIAGE_2026-10-21.md`) maps syscall slot 337 to stub RVA `0x2661f0`. Its bytes are `jmp 0x552d10`. Disassembly of that target shows:

1. `call 0xb07920` at RVA `0x552d1d`.
2. If the helper returns zero, return `0x4e` at RVA `0x552d35`–`0x552d3e`.
3. Otherwise, tail-jump to RVA `0x27bc0` at RVA `0x552d26`–`0x552d30`.

The helper at RVA `0xb07920` compares one kernel global with `4` and returns a Boolean. The saved text bytes at RVA `0x27bc0` begin with `INT3` (`0xcc`) throughout the inspected 0x80-byte window; the kernel-text failmap contains no failed chunk at that address. This suggests a state-dependent or unresolved module path, not a simple unprivileged symbol lookup. The 13.60 global value and any dynamic remapping of `0x27bc0` are unknown from the retained dump, and the 14.10 implementation has not been observed.

The 14.10 `results/phase15_native_sysent/57c_kldsym_direct_20261019_194850.txt` capture ends after `Trying kldsym for: prison0` with no return or output bytes. It does not prove the syscall reached the symbol lookup, returned a kernel address, or that `INT3` caused termination. Repeating that same unbounded six-symbol probe would add no justified evidence and can terminate the loader. A future test would require a version-matched handler or isolated evidence of a safe enabled path. No kernel pointer or kernel R/W is established.
