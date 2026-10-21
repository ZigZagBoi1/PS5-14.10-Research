# thr_create set_mcontext copy map — 13.60 capture re-read

> **Date:** 2026-10-21. Source: `docs/dumps_13.60/kernel_text.bin` (13.60
> labeled; acquisition authenticity unresolved). This corrects the PR #30/#31
> reading cited in `docs/ANALYSIS_thr_create_panic_2026-10-19.md` and
> `docs/THR_CREATE_PANIC_PATH_13.60.md`, and resolves the 189a contradiction.

## Chain, verified in the capture

- `sysent[430]` thunk -> real `sys_thr_create` at rva 0x437cf0
- it calls the shared worker, which calls ops via the 0x265fc8 thunk ->
  **ops at rva 0x437d90**
- ops tail-jumps to the mcontext consumer at **rva 0xa0ac60** with
  `rsi = ctx + 0x40` (also the target of the `0x480`/flags/type validation)

## Copy map (rva 0xa0ac60, set path)

| ctx offset | field | trapframe offset | mask |
|---|---|---|---|
| +0x48..+0xB8 | 15 GPRs (rdi..r15) | tf+0x00..0x70 | none |
| +0xE0 | RIP | tf+0xE8 | none |
| +0xF0 | rflags source | tf+0xF8 (preserved value) | AND 0x254dd5, OR'd |
| +0xF8 | RSP | tf+0x100 | none |
| +0x100 | **SS** | tf+0x108 | **none (raw)** |
| +0x440/+0x448/+0x458 | fpstate | pcb | flags bit 1; length-checked |
| **+0xC0** | **CS** | **never read** | — |

The full function range was swept: `[rsi + 0x80]` (ctx+0xC0, the CS field) is
written twice in the get path and **read zero times**. `tf_cs` comes from the
parent frame copied by `cpu_copy_thread`, not from the user context.

## Consequences

1. **The "set_mcontext copies CS without OR-ing SEL_RPL_MASK" claim is wrong
   for 13.60.** CS is not copied at all.
2. **Probe 189a (CS=0x40 -> live thread) is not a 14.10 divergence.** The copy
   map predicts it: the context CS field is ignored, tf_cs is inherited.
   The behavioral match between firmwares is stronger than the old model
   suggested.
3. The zeroed-context panic is better explained by **SS=0 copied raw into
   tf_ss** (iretq -> #SS -> double fault -> trap_fatal) or by RIP=0/RSP=0
   itself, not by CS=0. A context with CS=0 but SS=0x3B and valid RIP/RSP
   should behave identically to CS=0x43; that is a cheap discriminating probe
   (call it 274a).
4. Because SS is copied raw with no validation, SS=0 remains the suspected
   panic trigger; there is no CPL-raising primitive either way (RIP/RSP/SS all
   land in a ring-3 frame).
