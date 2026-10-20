# 13.60 kernel target evidence review (2026-10-20)

This review checks whether the retained artifacts support new findings in the UMTX registry, `set_mcontext`, and Sony syscall handlers 557–676. It uses repository evidence only. It does not establish a new vulnerability or a 14.10 patch state.

## Evidence available

- The published Ghidra reference has three decompiled functions: `0x3b0210` (AIO-associated), `0xabd4f0` (scalar reader), and `0x2c6480` (write-lock-associated helper). Neither UMTX registry function nor `set_mcontext` is among these exports. The reference README says acquisition authenticity remains unresolved and function recovery was partial.
- `docs/dumps_13.60/` has short `handler_NNN.bin` ranges for 145 numbers between 532 and 676. A handler prefix cannot establish the complete call graph or all cleanup paths.
- The documented full 13.60 Ghidra project and live kernel capture are outside this checkout. The documented project location was unavailable in this workspace during this review.
- There is no verified 14.10 kernel image here. Runtime results cannot be interpreted as a binary diff.

## Target assessment

| Target | Supported observation | Finding status |
|---|---|---|
| `umtx_shm_create_reg` / `umtx_shm_unref_reg` | The repository does not contain decompilation of these functions. The older phase-1/2 UMTX probes actually invoked syscall 557, not `_umtx_op` 454. The saved corrected 14.10 SHM probe reached 454 but every SHM operation returned `-1`; errno was not captured. | The registry lifetime and any CVE-2024-43102 analogue are **unverified**. No race window or refcount defect can be inferred from these artifacts. |
| `set_mcontext` | `docs/THR_CREATE_PANIC_PATH_13.60.md` records an assembly-derived register-copy loop and a CS selector concern. It also lists RSP, RIP, and SS destinations. The full function decompilation, validation branches, and surrounding dataflow are not present in the published Ghidra exports. | The prior CS analysis is a documented hypothesis/observation; other unsanitized security-relevant fields have **not been established** by this review. A copied field alone does not prove missing validation. |
| Sony syscall handlers 557–676 | The available evidence includes syscall maps, short handler ranges, one AIO-associated Ghidra export, and saved live probes. The maps mix distinct capture families and contain a documented native/compat and address discrepancy. | No new memory corruption, information leak, or missing-check finding is supported across the requested range. A complete handler and helper review remains necessary. |

## Evidence corrections that matter

1. `_umtx_op` is syscall 454 in the 13.60 map; syscall 557 is labeled `namedobj_create`. Earlier UMTX success claims based on 557 do not demonstrate UMTX behavior. See `docs/UMTX_454_EVIDENCE.md`.
2. In `results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt`, the corrected SHM calls all returned `-1`, including creation, and the log contains no errno. This shows no successful SHM registry lifecycle in that run. The result does not distinguish unsupported operation, privilege rejection, argument mismatch, or another error.
3. `docs/SYSCALL_NAME_MAP_13.60.md` documents incompatible native/compat and capture-coordinate interpretations for the AIO family. Resolve raw artifact identity before attributing any decompiled body to a syscall entry.

## What would make a finding reviewable

For UMTX, obtain provenance-checked full function bodies plus callers and cleanup helpers, then document reference acquisition, lock scope, release, and object free for every exit path. For `set_mcontext`, preserve the full validation and assignment control flow and distinguish intentionally user-controlled registers from privilege-sensitive selectors and flags. For Sony handlers, resolve each table entry to a complete implementation and trace user-copy, size arithmetic, ownership, and error cleanup through helper calls. Record artifact hash, firmware, address base, and confidence with each claim. Any 14.10 applicability claim requires 14.10 code evidence or a narrowly interpreted runtime observation.

## Source records

- `evidence/2026-10-18-ghidra-reference/README.md` and `decompiled/`
- `docs/GHIDRA_REFERENCE_VALIDATION_2026-10-18.md`
- `docs/UMTX_454_EVIDENCE.md`
- `results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt`
- `docs/THR_CREATE_PANIC_PATH_13.60.md`
- `docs/SYSCALL_NAME_MAP_13.60.md`
