# Implementation and loader follow-up findings

Published 2026-10-18 from the preserved analysis packages. This publication adds
no console tests and does not rerun prior table/hash comparisons. Original
reports, raw records, dumps and source checkouts are unchanged.

## Findings and evidence strength

| Finding | What the evidence supports | What remains unresolved |
|---|---|---|
| Retained scalar-reader field | The 13.60-labeled field at object-relative `+0x1c4` is zeroed by initialization and incremented by write-lock-associated paths. A cumulative map write-lock activity counter is the strongest interpretation. | Exact original symbol/contract, all writers/resets and its relationship to the 14.10-context selector-624 return. It is not established as resident pages or a heap oracle. |
| AIO ownership | Separate aggregate locks and a local mutex protect observed registration, notification and cleanup paths; descriptor-associated locks persist through waiter use. | Complete lifetime guarantees, exceptional callees and mode-dependent association invariants. No defect is demonstrated. |
| AIO branch representation | Some branches publish the current waiter record; another publishes the array base. Cleanup remains element-indexed. Construction supports both shared and per-element aggregates. | A cross-call contract explaining every admitted representation and reachable state. No trigger or vulnerability-transfer claim follows. |
| Present-day loader source | Five named userland Lua files were received through bounded read-only file collection, with exact raw receipts and current hashes. | Historical execution identity, loaded-file byte equality, upstream revision and firmware/build authentication. |
| Active Lua dispatch | Runtime metadata identifies `fcall.__call` as Lua; the pipe metatable equals the class. Serialized loaded functions structurally support selector consumption and native/fallback paths. | Native machine-code identity, actual historical branch selection and authoritative Sony ABI. A printed function identity alone did not establish C code. |
| Error capture/retest readiness | The prepared 53a–53c sources contain unverified ABI/layout assumptions and lack verified native errno capture. A bounded named-metadata check did not find an errno accessor under the entries examined. | A reliable error accessor and typed, attributable requests. No 53x kernel retest was executed in these packages. |

All implementation findings from kernel bytes mean **13.60-labeled; acquisition
authenticity unresolved**. Present-day loader receipts are not authenticated
14.10 kernel artifacts. Historical acquisition and 14.10 sysent location,
stride, handler identity, patch state and vulnerability applicability remain
unresolved. The six previously published selector-624 returns establish only
short-session stability.

## Published reports

The [publication package](../../evidence/2026-10-18-implementation-followup/README.md)
contains the unchanged reports and selected supporting evidence:

- [Implementation research report](../../evidence/2026-10-18-implementation-followup/implementation-research/IMPLEMENTATION_RESEARCH_REPORT.md)
- [AIO ownership](../../evidence/2026-10-18-implementation-followup/aio-ownership/AIO_OWNERSHIP_ANALYSIS.md),
  [mode ledger](../../evidence/2026-10-18-implementation-followup/aio-mode-ledger/AIO_MODE_LEDGER.md)
  and [construction analysis](../../evidence/2026-10-18-implementation-followup/aio-construction/AIO_CONSTRUCTION_ANALYSIS.md)
- [Selector-624 field analysis](../../evidence/2026-10-18-implementation-followup/selector624-field-writers/SELECTOR624_FIELD_ANALYSIS.md)
- [Loader source findings](../../evidence/2026-10-18-implementation-followup/loader-source-receipt/LOADER_SOURCE_FINDINGS.md),
  [runtime metadata](../../evidence/2026-10-18-implementation-followup/loader-runtime-metadata/RUNTIME_METADATA_FINDINGS.md)
  and [loaded-bytecode findings](../../evidence/2026-10-18-implementation-followup/loader-loaded-chunks/LOADED_CHUNK_FINDINGS.md)
- [Retest reassessment](../../evidence/2026-10-18-implementation-followup/retest-readiness/RETEST_REASSESSMENT.md)
  and [627–676 coverage register](../../evidence/2026-10-18-implementation-followup/retest-readiness/COVERAGE_627_676.json)

The original source-findings report contains approximate syscall.lua line
references; the later runtime-metadata report explicitly corrects the resolver
range to **67–81**. Preserve both instead of silently changing the earlier report.
The loaded-bytecode parser's initial stock-format assumption failed; its observed
duplicate-instruction-vector handling and limitations are documented in the
loaded-bytecode findings. No serialized chunk was executed offline.

Original diagnostic/collection scripts and frames remain in their named local
packages; this publication includes findings and evidence, not another live
probe suite. Inherited manifests can name files outside this selected publication.
The publication manifest is the authoritative list of files copied here.

## Next evidence boundary

Continue offline queue/publication and teardown analysis against retained bytes.
For the loader, matching native registration/module evidence is still missing.
Neither repeated baseline calls, guessed selector sweeps nor GPU buffer access
would establish those missing facts. No GPU DMA/kernel-memory test is included.
