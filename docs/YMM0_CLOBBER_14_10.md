# The ymm0 clobber hypothesis (H1): measured, and negative

Written 2026-11-04 (sixth boot). Probes: 1187a, 1188a, 1189a, 1190a, 1191a. Supersedes the
"open, not refuted" wording of the 1187a/1188a rows in `docs/PROBE_INDEX.md`.

## 1. The hypothesis

`docs/MICROARCH_FEASIBILITY_14_10.md` H1: the kernel is compiled with AVX enabled (it is - see §5) and
runs AVX code on syscall paths without `vzeroupper`; the upper 128 bits of the caller's ymm0-ymm15
therefore survive **kernel** data between the `syscall` and the `ret`. If a userland gadget then does
`vmovups [rsi], ymm0`, the kernel's register residue is written to user memory: a kernel register read.

Requirements: (a) a usable `vmovups [rsi], ymm0 ; ret` gadget in readable user code, (b) a way to issue a
raw syscall with a controlled rax while keeping ymm0 alive across it, (c) a kernel path that actually
touches ymm0 between entry and exit.

## 2. (a) The gadget - found, and callable two ways

``.local/dumps/eboot_chunk0.bin`` (1,048,576 bytes of eboot, reassembled from 1186a) disassembled with
capstone 5.0.7 (`skipdata=True` or it yields zero instructions): 289,483 instructions, 92 that move ymm0
to or from memory, and exactly two clean stores that return:

| RVA | Bytes | Instruction |
|---|---|---|
| `eboot+0xF7CB7` | `c5 fc 11 06 c3` | `vmovups ymmword ptr [rsi], ymm0 ; ret` |
| `eboot+0xD4144` | `c4 c1 7c 11 02 b8 06 00 00 00 c3` | `vmovups [r10], ymm0 ; mov eax, 6 ; ret` |

1188a proved the `[rsi]` gadget executes, but the value was **all zero**: `memcpy(dst=buf, src=eboot, 16)`
in the same process returned `2f 6c 69 62 65 78 65 63 2f 6c 64 2d 65 6c 66 2e` = `"/libexec/ld-elf."`, so
`native.fcall_with_rax`'s slot mapping (3=fn, 4=rax, 5=rdi, 6=rsi, 7=rdx, 8=rcx, 9=r8, 10=r9;
`.local/loader_payload/native.lua:209-222`) and the path are correct, yet the gadget wrote 32 zero bytes.
That is expected: the fcall path is a fresh `Thrd_create` thread whose XSAVE area starts zeroed (§4).

## 3. (b) The raw-syscall handoff - verified in-chain

`syscall.syscall_address` (`.local/loader_payload/syscall.lua:27-28`) = `*libc_gettimeofday_import + 7`,
i.e. the tail of the loader's own wrapper: `mov rax, imm32 ; syscall ; ret`. Pushing it as a plain chain
slot is enough to perform a syscall because the chain has already loaded rax
(`chain:push_set_rax(n)`) and rdi/rsi/rdx/rcx/r8/r9 (`push_set_rXX`, `.local/loader_payload/ropchain.lua:167-209`).

1190a verified the handoff with five chain shapes, each ending
`push(SC) -> push_store_rax_into_memory -> push_set_rsi(BUF) -> push(eboot+0xF7CB7)`:

| Case | syscall | rax after | buffer |
|---|---|---|---|
| C0 | none | 0x1 | 32 zeros |
| C1 | getpid (20) | 0xB1 | 32 zeros |
| C2 | 196 (0, BUF2, 0, 0) | -1 | 32 zeros |
| C3 | 638 (1000000000, BUF2, 0, 0) | 0 | 32 zeros, BUF2 = 0x3B9AD810 (echo) |
| C4 | 638 (1,2,3,4) | -1 | 32 zeros |

So the in-chain `syscall; ret` **does** perform the syscall with our registers, and the store after it always
runs. 1189a's two "store did not happen" cases ([G] and [T]) were an artefact of loading rsi *before* the
syscall: the kernel owns rsi on the way out of some handlers, so the store landed elsewhere. Order matters:
**reload rsi after the syscall**.
(1190a capture: `results/phase17_new_vectors/1190a_ymm_store_after_syscalls_20261104_170402.txt`, COMPLETE,
0.032 s, `[Z] alive`.)

## 4. What zero actually means

A fresh `Thrd_create` thread starts with a zeroed FPU/XSAVE area, and 1190a's C0 case (no syscall at all)
also writes zeros, so "zeros after a syscall" cannot distinguish "the kernel did not clobber" from "the
thread never had a non-zero ymm0". The experiment needs a **poison** step: load a known 32-byte pattern
into ymm0 *in user mode, in the same chain*, then make one syscall, then store.

## 5. The poison experiment (1191a) - the answer is negative

Poison gadget, from the same capstone pass - `eboot+0xDB597`:

```
vmovups ymm0, [rdi+0x28]      ; 32-byte marker -> ymm0
vmovups [rsi+0xc8], ymm0      ; proof it really executed (scratch copy)
mov     [rsi+0xe8], al
xor     eax, eax
ret
```

Chain per case: `push_set_rsi(SCR) -> push_set_rdi(MARK-0x28) -> push(LOAD) -> [one syscall] ->
push_store_rax_into_memory -> push_set_rsi(BUF) -> push(STORE=eboot+0xF7CB7)`. Marker = four qwords
`0xDEADBEEF00000001..04` (printed as `00000000efbeadde` x4). The scratch writes at SCR+0xc8 and SCR+0xe8
prove the poison ran and ymm0 was loaded.

| Case | syscall | rax | BUF (spilled ymm0) | marker |
|---|---|---|---|---|
| P0 | none | 0 | all zero | MARKER-INTACT |
| P1 | getpid (20) | 0xB1 | all zero | MARKER-INTACT |
| P2 | 638 (1e9, VO, 0, 0) | 0 | all zero | MARKER-INTACT |
| P3 | 196 (0, VO, 0, 0) | -1 | all zero | MARKER-INTACT |
| P4 | clock_gettime (232) (0, VO) | 0 | all zero | MARKER-INTACT |

**ymm0 is preserved bit-for-bit across every syscall measured.** H1 as stated is dead for the syscall
surface: on 14.10 the kernel either never touches the vector registers on these paths, or it does
`xsave`/`xrstor` (kernel_fpu_begin/end) around the code that does. Note that this does **not** contradict
§6 - the AVX code in the kernel image is real, it is just not on any path we can reach.

(1191a capture: `results/phase17_new_vectors/1191a_ymm0_poison_spill_20261104_170531.txt`, COMPLETE,
0.031 s, `[Z] alive`.)

## 6. Why the kernel's own AVX does not help

Static scan of `docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, 15,132,096 bytes): 2,452
`c5`-prefixed bytes with L=1 (i.e. 256-bit capable VEX). Hotspots by 64 KB bucket: RVA `0x870000` = 850,
`0x600000` = 162, `0x8F0000` = 83, `0xB90000` = 68, `0x6D0000` = 54, `0xC50000` = 42. Disassembly at
`0x876870` shows scalar float math (`vcvtsi2ss`, `vdivss`, `vbroadcastss`, `vmaxss`, `vcmpltss`) -
VEX-128 encodings of SSE operations, not 256-bit work. 238 `call rel32` sites target the `0x87xxxx`
region (e.g. `0x27DD22 -> 0x870060`, `0x331DE9 -> 0x8761B5`, `0x409196 -> 0x8709C0`); **none** of them
resolves within 0x2000 of any of the 735 sysent handler RVAs. No handler body reaches the AVX-dense code.

Scripts: `.local/scan_avx.py`, `.local/scan_avx2.py`, `.local/scan_ymm_load.py`.

## 7. Verdict and what is left

- H1 (kernel ymm clobber -> userland kernel read): **negative** for getpid, 638, 196 and 232. Not worth a
  further sweep: the clobber would have to come from a handler that runs VEX code without saving, and no
  handler is near the AVX code.
- The negative result is still useful: it tells us the kernel's FPU discipline is intact, so any future
  register-residue idea must look at *scalar* registers instead. Those we already control: the chain sets
  every argument register, and a handler's leftovers in rax are what `push_store_rax_into_memory` reads.
- The one residue channel that is still open in principle is the **kernel stack**: `syscall` does not switch
  stacks on this kernel (no KPTI, CPL3 only - `docs/ATTACK_SURFACE.md`), so a return value left on the
  thread's kernel stack by a previous, deeper handler could be read by a shallow handler that copies out
  an uninitialised stack buffer. `docs/COPYOUT_PARTIAL_STACK_AUDIT.md` closed the 15 known
  `call 0xffffffff8ac191d0` sites on the copy-out side (0/15 partially initialised, 0/15 caller length);
  the remaining target is the body at `0xffffffff8ac190b0` (73 call sites, absent from all dumps).
