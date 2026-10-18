# Implementation research: five unresolved questions

2026-10-18. Offline static analysis; local source revision `0ccf250603b8b448045ec6405abfaf0346b88504`. Original files and prior reports are unchanged.

The most valuable question is **what ownership and synchronization contract protects the AIO wait body's registered objects through completion and cleanup**. New decoding identifies the relevant entry layers, allocation sites, locks and cleanup paths. It supplies a concrete basis for ownership analysis, but does not establish a lifetime violation. Four additional questions below address real implementation uncertainty rather than repeating table comparisons.

## Scope, evidence and method

All binary findings below mean **13.60-labeled; acquisition authenticity unresolved**. They describe retained bytes and decoded control flow, not independently authenticated Sony release behavior. Addresses below are hexadecimal **file offsets in `docs/dumps_13.60/kernel_text.bin`**, also recorded relative coordinates under the retained manifest. They are not authenticated virtual addresses. For `kernel_data.bin`, string references use file offsets; its recorded relative mapping adds `0x1000000`.

| Material | What is available and what it establishes |
|---|---|
| Range family R, recorded base `0xffffffff8a9c0000` | `docs/dumps_13.60/kernel_text.bin`, 15,132,096 bytes; `kernel_data.bin`, 4,194,304 bytes; manifest, raw table/index and handler samples. Text is a retained prefix, not a demonstrated complete executable section. Only this family's code is decoded here. |
| Browser family B, recorded base `0xffffffff94480000` | Previously recovered raw table/index under `/var/lib/ps5-research/dumps/a2e91480-9fbf-4d0c-89b7-22d3da46387c/`. No browser-family handler bodies are established by this analysis. Its different bytes remain separate. |
| Compatibility map M | `docs/ps5_13.60_sysent.json`: annotation/offset source, not an independent authenticated capture. Numerical disagreements remain recorded in the completed three-way report. |
| Existing RE notes | `docs/KERNEL_DUMP_ANALYSIS.md`, `docs/SECONDARY_EXPLOIT_AUDIT_13.60.md`, `docs/CROSS_FIRMWARE_PATTERN_RESEARCH.md` and historical candidate/evidence audits. These contain interpretations, not original symbols or decompiler proof. No pre-existing disassembly project was identified in the bounded repository filename review. |
| Hypervisor material | Retained `PS5-V13.60-Research/HV-RELAPSE-13.60.md` and `site/release/web/relapse/README.md`, revision `7d0aa623770887901297df5790da5d1fda741c0d`; payload artifacts in the inherited inventory. A payload ELF is not a hypervisor memory image. Delivery records and reported notifications do not independently prove hypervisor execution or expose its implementation. |

Inherited SHA-256 values, **not recomputed this pass**: R text `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`; R data `e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46`. Source: prior `/home/marwanserver/ps5-workspace/evidence/setup-20261018T030304Z/inventory.json`, corresponding artifact paths.

Browser raw table inherited SHA-256: `9867f4ffa0b2b131331d76105196e427586f68fccfecb9d059c1a9dde15df003`. Prior family/index hash conflicts remain in `../compatibility-three-way-comparison/INPUTS.json` and `../retained-1360-reference-map/SOURCE_ARTIFACTS.json`; no conflict was silently resolved here.

Executed checks: read-only x86-64 decoding with Capstone 5.0.7; selected branch following; RIP-relative diagnostic-string resolution against retained data; bounded AIO direct-control-flow traversal. No repository code was imported/executed. No target traffic, executable launch, payload or new capture occurred. REA's available Windows Ghidra provider accepts PE targets rather than this raw flat image; no decompilation is claimed. Assembly windows can cross function boundaries and are explicitly window evidence.

New outputs `SELECTED_BYTE_WINDOWS.json` contain exact raw windows and newly calculated **window** hashes, not repeated whole-artifact checks. `STATIC_WINDOWS.json` records calls/string references. Each named `.asm.txt` supplies instruction-address pointers. `AIO663_CFG.json` records the traversal, not runtime coverage. Original table comparisons and handler-window consistency checks were not rerun.

## New primary-byte findings

**E01 — Entry layers explain selected offset disagreements, without establishing record lineage.** In R code, all ten recorded entry targets for selectors 661–670 begin with direct branches whose destinations equal the previously recorded M offsets. See `AIO_ENTRY_BRANCHES.json`, keyed by `number`. For 663, `0x265720` contains `e9cbaa1400`, branching to `0x3b01f0`; the wrapper there unpacks differently sized argument-block fields and jumps at `0x3b020a` to `0x3b0210`. This is new code-flow evidence, not a repeat numerical table comparison. It supports stub-versus-wrapper layering in these R bytes. It does not establish which historical parser produced a record, complete ABI semantics, or B-family code equivalence.

Additionally, R targets associated with M-omitted entries 515, 619 and 635 reach `0x49b0b0`, `0xa37650` and `0x4393a0`: each short body returns numeric `0x4e`. See `OMITTED_ENTRY_CODE.json`, entries by number. Distinct table targets therefore do not by themselves count substantive implementations. Do not assign that constant a Sony errno meaning from an upstream table. This offers a code-supported distinction relevant to 311-versus-308 counts, not proof of how either count was generated.

**E02 — AIO association has direct string and control-flow support.** The body `0x3b0210–0x3b0fb0` references `_aio_multi_wait` (data file `0x379d7c`), `AIO MWait mutex` (`0x2e78de`), `set_waiter` (`0x2bdac0`) and `aio mwait` (`0x2f1fc8`). These are recovered diagnostic strings, not independently recovered symbol names. Count/mode checks precede stack-buffer preparation; copy-associated calls at `0x3b0468` and `0x3b04f3` check returns. Allocation-associated calls at `0x3b0540` and `0x3b0586` use count-scaled sizes; locks, object-state branches, waiter links and cleanup follow. The bounded CFG contains 801 reachable instructions and 58 call sites not followed. Direct branch destinations stayed within the selected body; indirect/callee behavior and non-returning calls remain outside that result.

**E03 — Earlier helper labels need correction in future reasoning.** `docs/KERNEL_DUMP_ANALYSIS.md:74–102` labels `0xc08b50` as a privilege-check hub and `0x6fd6b0` as copyin/copyout. The bytes do not support those labels. `0xc08b50` references `malloc(M_WAITOK)` at data `0x319f27`, performs size/allocation-related work, and is called for AIO count-scaled allocations. Allocation association is strong; exact source equivalence is unproved. Cleanup entry `0xc08df0` is used by AIO; a nearby diagnostic at `0xc08f11` references a free-address warning (data `0x32ea67`). Adjacent functions must not be merged into one inferred routine.

`0x6fd6b0–0x6fd6d9` references `stack overflow detected; backtrace may be corrupted` (data `0x391dca`) and ends in `ud2`. AIO's canary mismatch path calls it at `0x3b0fa8`; a VM mismatch path calls it at `0xabb2e7`. It is strongly associated with stack-check failure, not an ordinary copy operation. Actual copy-associated R routines `0x259280` and `0x2591d0` contain address/length guards and fault-recovery handling; the latter uses STAC/CLAC. See `aio_copyin_candidate.asm.txt`, `aio_copyout_candidate.asm.txt`, `diag_helper.asm.txt`, and selected E03 windows. These mechanisms are observed; their complete contracts remain inferred.

A second annotation issue (`docs/KERNEL_DUMP_ANALYSIS.md:67–73`): `0xb078d0` returns boolean 1 for recorded global values 3 **and** 4, otherwise 0. AIO uses this query conditionally. Treating it as a demonstrated securelevel permission error contradicts these bytes; the global's meaning is unknown (`aio_context_query.asm.txt`).

## Five prioritized unanswered technical questions

### 1. Which references keep AIO objects alive while waiters are registered and removed?

**Known / strongest evidence:** E01–E02 establish the entry-to-body path, object-list manipulation, state-dependent branches, locking and cleanup. Calls to `0x4c6a00` / `0x4c6fa0` bracket portions of shared-state handling; the latter references `__mtx_unlock_flags` (data `0x366943`). Cleanup includes calls to `0xc08df0` at `0x3b0a87` and `0x3b0f9e`. Already-completed diagnostic paths contradict a simple claim that no state checking exists.

**Uncertain:** object ownership, reference transfers, list invariants, completion/cancellation synchronization and the contracts of untraversed callees. Neither a diagnostic about an already-completed object nor a cleanup call proves use-after-free.

**Next offline task / existing artifact:** build an ownership ledger across the body and its direct state/cleanup callees in R text/data; track acquisitions, link insertion/removal, lock-held regions and releases for every return path. Correlate only verified instruction effects, leaving structure/member names provisional. This would distinguish a protected lifecycle from an actually missing invariant; it advances beyond the former API-name hypothesis. **Assessment: high-priority unresolved; demonstrated defect: no; 14.10 presence: unknown.**

### 2. What are the actual allocation, user-copy and diagnostic contracts?

**Known / strongest evidence:** E03 changes the inferred architecture: an apparent privilege hub is allocation-associated, and a supposed copy hub is stack-failure-associated. R copy routines have concrete bounds/fault-context logic; AIO checks copy-associated returns before proceeding.

**Uncertain:** allocator flags/types, exhaustion behavior, copy helper caller prerequisites and the purpose of the context validator `0xc1a3e0`. Its callers pass operation strings including allocation/copy diagnostics, which does not establish a process authorization predicate. Diagnostic strings alone cannot identify an exact FreeBSD implementation/version.

**Next offline task / existing artifact:** recover bounded helper CFGs and a caller matrix from R text; correlate string/data references and call argument roles without assigning Sony structure names. Separate allocation failure paths, stack protection and user-copy faults. Result: a defensible subsystem vocabulary and error-path model, replacing stale annotations before further security claims. **Assessment: old helper labels weakened; replacement contracts partly supported; 14.10 contracts unknown.**

### 3. What lookup and authorization invariants govern the process-related 563 body?

**Known / strongest evidence:** `proc563_body.asm.txt`, R `0x602fe0–0x603250`, contains an initial numeric range check, object lookups, conditional policy calls, locks, mutations and releases. References at `0x60306d` and `0x60313a` resolve to `W:/Build/J03950001/sys/freebsd/sys/kern/orbis_pmc.c` (data `0x2ab551`). This associates a vendor process-control code area; it is not an authenticated build identifier. Helper `0x609890` tests bits in object fields and invokes further helpers (`proc_policy_callee.asm.txt`).

**Uncertain:** which namespace/object is looked up, caller-versus-target credentials, membership checks, field semantics and release guarantees. A successful lookup or an error return is not an unauthorized process effect.

**Next offline task / existing artifact:** follow lookup candidates `0x53c170` / `0xb92420`, policy helper `0x609890` and cleanup/lock paths. Produce a path-condition and resource ledger before assigning permissions. Result: identify which policy is actually enforced and where unresolved prerequisites enter. **Assessment: policy structure supported; suspected privilege weakness unresolved; 14.10 equivalence unknown.**

### 4. Why does the VM-related 572 body select different validation paths by context?

**Known / strongest evidence:** `vm572_body.asm.txt`, R `0xabac50–0xabb2ec`. The context byte read at `0xabac79` selects full flag-mask validation (`0xabac96`, mask `0xfffcfffe`) or input masking to one bit (`0xabaca4`). Address alignment/bounds checks and a predicate call at `0xabace4` follow. Helper `0xb2bb00` reads a GS-linked object and tests a bitmask; a null branch returns 1 (`permission_callee.asm.txt`). These are concrete conditional checks, not evidence of universal bypass.

**Uncertain:** context-byte meaning and writers, permitted call contexts, mask semantics and predicate authority. Numeric error constants are not independently authenticated Sony errno mappings.

**Next offline task / existing artifact:** identify writers/readers of the context field and recover the predicate's caller contract in R text, preserving uncertain structure types. Result: determine whether the paths intentionally normalize different trusted contexts or leave an unexplained validation gap. **Assessment: conditional validation supported; defect unresolved; 14.10 behavior unknown.**

### 5. What state does the 624 scalar report, and what does its locking guarantee?

**Known / strongest evidence:** `metric624_body.asm.txt`, R `0xabd4f0–0xabd532`, loads a 32-bit field at an object-relative `+0x1c4`, zero-extends it into a return-area slot, and returns zero after paired calls to `0x2c6820` / `0x2c6870`. Those helpers choose lock paths based on object flags; see `metric_enter_helper.asm.txt` and `metric_leave_complete_window.asm.txt`. This supports a protected scalar read, not a kernel pointer or established allocation oracle.

**Uncertain:** metric meaning/units, field writers, aggregation scope, consistency across changes and whether the 14.10 numeric selector reaches a related body.

**Next offline task / existing artifact:** recover the object's construction and field writers plus alternative lock paths, using R code references. Result: explain the scalar's contract rather than infer heap layout from its size. **Assessment: scalar/locking shape supported; oracle claim unresolved; 14.10 implementation identity unknown.**

## Historical claims and 14.10 observations kept separate

The retained Relapse README (B revision above, kernel-stage description) reports an `aio_multi_wait` lifetime race. That historical report motivates question 1; it is not a local reproduction or a patch-state determination. `HV-RELAPSE-13.60.md` distinguishes delivery and reported outcomes from independent execution proof. Retained FreeBSD-derived labels and malloc/copy conventions can guide type recovery, but do not identify Sony source equivalence. `docs/UNTESTED_THEORIES.md:103` invokes CVE-2019-11477 as a networking analogy; this pass establishes neither its platform attribution nor a matching Sony code path. No external advisory verification was attempted during this offline pass. The available evidence establishes **no new confirmed cross-firmware implementation difference**.

Existing 14.10-labeled observations, all at local revision above, are summarized only to delimit applicability. Exact Git blobs and inherited log SHA-256 values remain in `../offline-candidate-triage/READ_LOG_REGISTER.json`, selected by `relative_path`; they were not rehashed here:

- `results/43p_aio_bypass_20261016_180656.txt:9`: last output announces the first AIO selector; no return or later stages observed. The log's own “killer” instruction is an interpretation, not evidence of cause.
- `results/phase2_kernel_objects/19g_aio_debug_20261015_193320.txt:6–8`: records one `rv=-1`, then an alternate-number stage heading; no subsequent result. The firmware banner at line 2 is session-reported identity.
- `results/51c_sony_survey_part2_20261016_215838.txt:7–8`: two `-1` results, then record ends. Printed `DENIED` is a source annotation; later selector outcomes are unobserved.
- `results/51b_accessible_syscall_deep_20261016_214832.txt:17` records numeric selector 624 returning `0x00000000_00000D30`; completion at 67 does not authenticate handler identity or the metric's semantics.
- `results/43f_sysctl_write_20261016_180756.txt:1–25`: specific read/write results only; no universal permission architecture follows.
- `results/45c_execution_reality_check_20261016_192713.txt:1–207`: counterevidence to the old function-address execution interpretation; restored state and completion are recorded at 205–207.

Missing output supplies no panic, sandbox or precise failure attribution. None of these records authenticates the code analyzed here as 14.10. There is no reason to repeat them to answer the static questions above.

The existing fifteen-candidate ranking remains in `../offline-candidate-triage/OFFLINE_CANDIDATE_TRIAGE.md`. This pass deepens implementation evidence for AIO, process/VM policy, copy/allocation architecture and the scalar metric; it does not resurrect retracted function-address claims or upgrade the bounded network observations to defects.

## What changes, and what does not

New primary evidence supports entry-layer mapping for the selected R targets, corrects three misleading helper interpretations, and identifies concrete ownership, policy and scalar-read analysis targets. These are useful implementation findings even while acquisition remains unverified. **No lifetime defect, unauthorized effect, authenticated 14.10 handler, patch difference or exploitability is established.**

The five tasks can proceed against existing bytes without target access. Questions of actual concurrency schedules, exact build attribution, historical execution identity and 14.10 implementation identity remain outside what these artifacts alone establish. A future independently attributable implementation artifact could resolve the last category; a new banner or repeated offset claim could not.


