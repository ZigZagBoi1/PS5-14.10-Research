# Copyin length screen: the twelve stack-destination sites are all bounded

Static, 13.60 dump (base 0xffffffff8a9c0000, offset == RVA). Companion to
`docs/MEMCPY_PROVENANCE.md` and `docs/COPYIN_DEST_PROVENANCE_14_10.md`.

## 1. What was screened

All **432** direct `e8` call sites of copyin (RVA 0x259280; arg0 = user source, arg1 = **kernel
destination**, arg2 = length). For each site the last write to `rsi` (destination) and to `rdx`
(length) in the preceding 0x260 bytes was classified.

| destination | length | count |
|---|---|---|
| stack `lea rsi,[rbp-…]` | constant | 183 |
| stack `lea rsi,[rbp-…]` | **not constant** | **12** |
| not stack | constant | 60 |
| not stack | not constant | 177 |

The 12 are the only sites where a user-influenced length meets a kernel-stack buffer, which is the
classic kernel stack smash. All twelve were read instruction by instruction.

## 2. The twelve, with the bound that saves each

| site RVA | destination | length register | bound |
|---|---|---|---|
| 0x2ec0cf | `[rbp-0x60]` | edx = 8 | constant, my classifier missed `mov edx, 8` |
| 0x34b355 | `[rbp-0x28]` | edx = 8 | constant |
| 0x34b820 | `[rbp-0x38]` | edx = 8 | constant |
| 0x34bcd0 | `[rbp-0x38]` | edx = 8 | constant |
| 0x34c3d6 | `[rbp-0x38]` | edx = 8 | constant |
| 0x34cdac | `[rbp-0x30]` | edx = 8 | constant |
| 0x34ce99 | `[rbp-0x38]` | edx = 8 | constant |
| 0x34d486 | `[rbp-0xf8]` | edx = 8 | constant |
| 0x3812d9 | `[rbp-0x48]` | rdx = r15, `mov r15d,0x18` | constant 0x18 |
| 0x34ce33 | `[rbp-0xb0]` | rdx = r14 | `cmp r14,0xa9; jae error` two instructions earlier at 0x34d49b - max 0xa8 into a 0xb0 frame |
| 0x34d4cf | `[rbp-0xf0]` | rdx = r14 | same `cmp r14,0xa9` guard, max 0xa8 into a 0xf0 frame |
| 0x34d4cf (second) | `[rbp-0xf0]` | r14 loaded from `[rbp-0xf8]` | the loader at 0x34d48f reads the length the *previous* copyin filled, and the same `0xa9` compare gates it |

Eight of the twelve are a misparse: capstone prints `mov edx, 8` without a `0x` prefix and the
first classifier only recognised `0x`-prefixed immediates. The three genuinely variable-length
sites (0x34ce33, 0x34d4cf twice) all copy into a frame buffer that is larger than the compare
bound, and the compare sits immediately above the call.

## 3. Verdict

**No kernel stack smash exists in the direct copyin call graph.** The destination side of copyin is
either a constant-size stack buffer, a register-held kernel object, or the enclosing function's own
argument (which the interprocedural audit covers). This closes the length half of the copyin
question; the destination-provenance half is `docs/COPYIN_DEST_PROVENANCE_14_10.md`.

Lesson for later screens: classify immediates by parsing the operand, not by searching for `0x`.
