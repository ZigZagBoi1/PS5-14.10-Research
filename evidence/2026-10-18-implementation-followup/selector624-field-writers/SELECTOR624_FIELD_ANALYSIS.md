# Selector 624: field-writer analysis

2026-10-18. **New result:** in the retained 13.60-labeled range-family bytes, the scalar read by the previously mapped 624 body is strongly associated with cumulative map write-lock activity. It is not supported as a resident-page, mapped-byte or available-memory measurement. Exact source-level naming and 14.10 implementation equivalence remain unknown.

## Inputs and scope

Original source: `F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin` and `kernel_data.bin`; revision at this pass `7e25a1174b5a3086b7e90d860d85f8ab7bad7a70`. **13.60-labeled; acquisition authenticity unresolved.** Only the 8a9c… range family's code is examined. Browser-table and compatibility-map records remain separate. All locations below are text-file offsets, not authenticated VAs. Data references use the manifest's recorded relative mapping: data file offset plus `0x1000000`.

Inherited text SHA-256: `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`; data: `e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46`. Source and limitations inherited from `../implementation-research/IMPLEMENTATION_RESEARCH_REPORT.md`, its selected windows and source manifests. No whole-artifact hash or table comparison was repeated.

New checks: existing Capstone 5.0.7 static decoding; focused displacement-use discovery; manual review of selected writers/initialization and matching lock/object relationships. Scripts and assembly exports are preserved beside this report. No target contact, allocation experiment, repository-code execution or original-file changes occurred. No new public-source search was performed.

## Direct observations

| Evidence | Instructions | Observation / confidence |
|---|---|---|
| Scalar reader | `metric_reader.asm.txt:0xabd4f7–0xabd526` | Loads object through input context `+8`, then related object `+0x200`; calls `0x2c6820`, reads 32-bit `+0x1c4`, writes zero-extended scalar to return-area `+0x408`, calls `0x2c6870`. High decoded-instruction confidence. No human-readable field name is present. |
| Shared/read-side entry | `read_enter.asm.txt:0x2c6824–0x2c6862` | Tests object flag `+0x244`, acquires through `+0x170` with shared-lock-associated helper `0xc4b350`, or mutex word `+0x1a8` via `0x4c6a00`. No `+0x1c4` increment in this bounded routine. High. Lock modes corroborated by prior ownership analysis, not imported upstream layouts. |
| Write-side entry | `write_enter.asm.txt:0x2c6486–0x2c64e0` | Uses the **same object flag and lock locations**, but calls exclusive-lock-associated `0xc4bb20` or the same mutex. After acquire, increments `+0x1c0`, then executes `lock add dword ptr [object+0x1c4],1` at `0x2c64d2`, before returning. High effect; write-lock-entry role strongly inferred. No allocation size or page count is used to compute the increment. |
| Upgrade/reacquire path | `upgrade.asm.txt:0x2c69b7–0x2c6a58` | Saves `+0x1c0`, drops shared lock, reacquires exclusive lock, compares saved value with current `+0x1c0`; successful path increments that field and atomically increments **separate** `+0x1c4` by one at `0x2c6a38`. Failure returns through a different unlock/status path. High. Do not conflate the generation-like `+0x1c0` with the exposed `+0x1c4`. |
| Initialization | `map_initializer.asm.txt:0x2c6fa0–0x2c709b` | Initializes list-like links, range fields and locks. Qword store of zero at `+0x1c0` (`0x2c6ffb`) also clears the adjacent 32-bit field at `+0x1c4`. Initializes the same mutex/read-write lock locations, with diagnostic strings `system map` and `user map` at data offsets `0x344403` / `0x2bcdaf`. High instruction effects; VM-map identity strongly inferred from combined evidence. |
| Explicit object-chain corroboration | `0x2d3920.asm.txt:0x2d3950`, `0x2d3a8e–0x2d3a98` | Caller loads object from `[rsi+0x200]`, keeps it in rbx, passes it to `0x2c6480`. This corroborates the reader's `+0x200` relationship; it is stronger than matching a displacement alone. High instruction/data-flow observation; exact rsi type provisional. |
| Inlined write-side pattern | `0x2c6b10.asm.txt:0x2c6bca–0x2c6c1b` | Reacquires through the same lock offsets, increments `+0x1c0`, then atomically adds one to `+0x1c4` at `0x2c6c12`. High within reviewed branch. Other candidate increment sites are discovery leads, not all independently typed. |

### What the units most likely are

The directly recovered unit is **one increment per execution of the identified write-side acquisition/upgrade path**. This supports an activity/acquisition count. It does not necessarily count successful map changes: a caller can acquire the write lock before deciding whether any mapping changes. Initialization shows zero start for this constructor; 32-bit additions imply modular arithmetic if they wrap. This pass does not prove wrap occurs, identify all reset paths, or establish a global monotonicity guarantee.

“Cumulative map write-lock activity counter” is a **strong interpretation**, not an original symbol, API name or proof of exact Sony source equivalence. `+0x1c0` appears generation-like because callers save and compare it across a lock handoff; the exposed field is `+0x1c4`, not that saved generation field.

## Why this changes the planned live interpretation

`docs/CROSS_FIRMWARE_PATTERN_RESEARCH.md:17,33` and prepared `probes/phase13_52batch/52b_624_oracle.lua` entertained memory-accounting interpretations. Those are hypotheses, not primary evidence. The new writers weaken a direct pages/budget interpretation **for these retained 13.60 bytes**.

Even if a future 14.10 allocation operation correlates with selector 624, that correlation would not distinguish page accounting from write-lock activity: mapping-related operations can acquire locks. A larger change need not mean more pages; an unchanged value need not mean no allocation. Therefore the proposed map/touch experiment is not presently a discriminating semantic test, and was not run.

The six already saved 14.10-context wrapper-visible returns (`0xD31`) remain in `F:/PS5-14.10-Research/evidence/2026-10-18-selector624/{baseline,wrapper-followup}/response.raw`, with session metadata, original scripts and hashes. No repeat calls were made. They establish short-session stability only, with unauthenticated firmware identity and unverified native dispatch. The 13.60 interpretation is not assigned to those results.

## Discovery coverage and negative-evidence limits

`FIELD_DISPLACEMENT_CANDIDATES.json` locates literal little-endian displacement `0x1c4` and tests linear x86-64 decoding from a nearby prologue pattern. It includes unrelated objects using the same offset. It is **not** an exhaustive list of this object's accesses, a valid global CFG or proof that every listed instruction executes. It misses base-adjusted pointers, alternate displacement forms, indirect writes, bulk initialization and functions outside the retained prefix. Assembly exports beginning with an offset cover windows and can include neighboring functions/data; no symbols are invented from their filenames.

The focused exports in `FOCUSED_WINDOWS.json` and the reviewed caller in `DIRECT_CALL_CANDIDATES.json` narrow the argument to identified lock/initialization paths. In particular, constructor zeroing is a qword write at `+0x1c0`; a search only for `+0x1c4` would miss it. No universal absence of decrements/resets is claimed.

## Interface decision and remaining questions

Existing local compatibility metadata `/syscalls/624` (key context as stored in `docs/ps5_13.60_sysent.json`) records an empty name and zero arguments for the 13.60-labeled entry. The prior static body matches that reference mapping; it is not a Sony 14.10 prototype. The historical loader code constructs a callable by copying a Lua table and changing `syscall_no`; the native C-function dispatch has not been identified. Lua fields and returned h/l types do not independently prove which native syscall executed.

**No independently established 14.10 interface was identified in these bounded existing records for a controlled mapping comparison.** This is a limitation of the reviewed sources, not a claim that such an interface cannot exist.

Next offline tasks, in order:

1. Recover attributable loader native dispatch source/binary identity and follow the callable implementation. This can establish whether selector annotations select an actual syscall and how zero-argument returns are propagated. Existing sender transport code alone cannot resolve it.
2. Confirm this object's field meaning through additional attributable symbols/source or remaining retained constructor/counter consumers. Existing bytes can strengthen the behavioral interpretation; unavailable symbol/build evidence must remain unavailable.
3. Only then design a minimal semantic comparison that distinguishes competing hypotheses. Do not use allocation deltas alone as proof of a page counter, kernel disclosure or an oracle.

No exploitability, firmware transfer, authenticated 14.10 layout, patch difference or kernel-access capability follows from this work. Repository and prior evidence were left unchanged. New-output hashes are in OUTPUT_MANIFEST.json; these identify analysis files, not historical firmware acquisition.
