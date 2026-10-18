# AIO ownership analysis

2026-10-18 — focused offline continuation of `../implementation-research/IMPLEMENTATION_RESEARCH_REPORT.md`.

**Result:** the retained bytes support a substantially recoverable, lock-based lifecycle: a call allocates waiter storage, acquires descriptor-associated read locks through lookup, associates waiter records with pre-existing request aggregates under their locks, waits using a call-local mutex/counters, unlinks associations under aggregate locks, releases descriptor locks, destroys the call-local mutex, and frees waiter storage. Worker and cancellation paths publish results through those same waiter fields. This is more than an unknown contract, but it is not a proof of memory safety: mode-dependent record selection, external deletion, allocator guarantees and indirect sleep-lock callbacks still have explicit gaps.

## Evidence boundary and notation

Every implementation statement here is **13.60-labeled; acquisition authenticity unresolved**. Only range-family R bytes are analyzed; recorded base `0xffffffff8a9c0000`. Browser-family 9448… and compatibility JSON remain separate. No 14.10 implementation or patch-state conclusion changes.

Original source: `F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin` and `kernel_data.bin`, repository revision `0ccf250603b8b448045ec6405abfaf0346b88504`. All code locations below are **text-file offsets**, not authenticated VAs. Data offsets explicitly mean offsets in kernel_data.bin, mapped provisionally by manifest `/regions` offset `0x1000000`. Source manifest: `docs/dumps_13.60/kernel_dump_manifest.json`, Git blob `9a9982c27dceda183c892f3d7ac7f35a369643da` (inherited from `../retained-1360-reference-map/SOURCE_ARTIFACTS.json`). Text/data inherited SHA-256 values respectively:

- `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`
- `e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46`

These identify the previously recorded inputs; no original hashes or completed comparisons were repeated. Prior report, AIO assembly, `SELECTED_BYTE_WINDOWS.json`, `AIO663_CFG.json`, `STATIC_WINDOWS.json`, analysis method and source manifest were read. The prior CFG's 801 instructions/58 untraversed call sites are inherited, not a new CFG result. Entry-layer decoding was reused, not rerun.

New analysis uses existing Capstone 5.0.7 for read-only x86-64 decoding of specifically relevant callee windows and adjacent AIO consumers. New `.asm.txt` files carry exact instruction offsets/bytes. `CALLEE_WINDOWS.json`, `FOLLOWUP_WINDOWS.json`, `OWNERSHIP_HELPER_WINDOWS.json`, `FINAL_TARGETED_WINDOWS.json` and `LOCK_ZERO_WINDOWS.json` identify the selected new windows and their hashes; scripts preserve the decoding procedure. No source or payload was executed. Window names are provisional; windows sometimes include adjacent routines. No dynamic reachability, complete callee coverage or source equivalence is implied.

Confidence: **H** = direct instruction/branch/data-flow observation within a bounded path; **M** = mechanism inferred from several matching instruction effects/callers; **U** = contract not established. “Lock held” below means the normal path after the identified acquire returns and before its matching release, conditional on the helper's normal lock contract. Interrupt/debug/indirect slow paths have not all been proved.

## 1. Recovered lifecycle model

The mnemonic “AIO wait body” refers to retained body `0x3b0210–0x3b0fb0`, supported by recovered `_aio_multi_wait` diagnostic strings in the prior report. It is not an original recovered symbol. This section references prior `../implementation-research/aio663_body.asm.txt` by instruction offset unless another file is named.

| Stage | Instruction locations | Observed operation / confidence |
|---|---|---|
| Prepare frame | `0x3b0232–0x3b0282` | Saves call inputs and retrieves a registry/context pointer through a context object; initializes several frame fields. H. No Sony structure type assigned. |
| Preliminary checks | `0x3b0289–0x3b0382` | Context-dependent helper/global checks precede input-count/mode processing. Some failure paths return before allocating waiter storage. H effects; policy meaning U. |
| Bound count/mode | `0x3b0384–0x3b042c` | Arithmetic/unsigned branches constrain count; rejects mode values at or above 3. Error paths carry numeric `0x16`. H; no upstream errno substitution. |
| Input/result storage | `0x3b03d4–0x3b046f` | Uses count-scaled, aligned stack arrays or small-count frame slots; invokes copy-associated routine and checks its return. H. This storage is distinct from heap waiter records. |
| Optional timeout copy | `0x3b04bd–0x3b0512` | Optional four-byte input goes to frame `+0x108`; a nonzero copy return exits before heap waiter allocation. H. |
| Optional diagnostic array | `0x3b0517–0x3b0548` | Query-gated allocation of count times `0x18`; later used for diagnostic information, distinct from waiter ownership. H size/use; purpose M. |
| Initialize local mutex | `0x3b0555–0x3b0571` | Initializes lock word at frame `+0xf8`, diagnostic `AIO MWait mutex`. `mutex_init_4c7dd0.asm.txt:0x4c7e03–0x4c7e3c` initializes header at lock-word minus `0x18` and word to 4. H. |
| Allocate waiter array | `0x3b0576–0x3b05bc` | Allocates count times `0x38` with flags `0x102`; saves base in frame `+0x40`. No caller-side null branch follows. H. Allocation success/non-return guarantees require allocator contract. |
| Initialize counters | `0x3b0563`, `0x3b058e–0x3b059e` | Primary frame counter `+0x104` starts 0; one mode initializes it to 1 and secondary `+0x10c` to 0. H. |
| Resolve descriptor | `0x3b061e–0x3b0649` | Lookup `0x399ee0` returns payload and outputs descriptor D. On success, stores D into the current W element `+0x28`. Cached lookup reuse is visible. H. This is not an observed refcount increment. |
| Validate selected object | `0x3b064d–0x3b06ea` | Payload count check, descriptor flag helper, indexed pointer lookup and null check precede aggregate access. Invalid entries receive recorded numeric result values and continue. H. |
| Acquire aggregate lock | `0x3b073f–0x3b0788` | Follows indexed object's `+0x20` pointer to aggregate Q, invokes lock manager on Q `+0x20`, operation `0x80000`. H effects; exclusive-lock association M, corroborated below. |
| Associate waiter | `0x3b0798–0x3b096d` | Branches by mode/state; records counter/mutex pointers, updates counters under local mutex, rechecks Q state, links waiter to Q `+0x50` when appropriate. H; exact mode semantics U. |
| End registration | `0x3b0a01–0x3b0a3c` | Releases Q lock via operation `0x100000`, advances input/current waiter and loops. H. |
| Optional diagnostics cleanup | `0x3b0a41–0x3b0a87` | Query-gated diagnostic callback and deallocation of the optional array. H. Not waiter-array free. |
| Decide whether to wait | `0x3b0a8c–0x3b0ac5` | Acquires local mutex; tests primary counter and, for one mode, secondary counter before calling wait routine. H. |
| Wait / timeout accounting | `0x3b0b2d–0x3b0d63` | Calls `0xc06260` with primary-counter address and local mutex header; supports timed/untimed paths and remaining-time accounting. Numeric status translation and looping are visible. H instructions; full scheduler/callback contract U. |
| Leave local mutex | `0x3b0d63–0x3b0d6c` | Releases local mutex before per-aggregate detach. H. Optional timeout copy-out follows; its result is not used in this body at that site. |
| Detach each association | `0x3b0de3–0x3b0eaa` | For each W with nonnull `+0x18`, acquires Q lock, copies result, traverses Q's singly linked waiter list, removes W, clears W `+0x18` on removal, observes/updates Q `+0xc`, releases Q lock. H. The traversal expects membership; no null-termination recovery is visible inside its predecessor-search loop. This is an assumed list invariant, not proof it fails. |
| Release descriptor locks | `0x3b0eaf–0x3b0ed6` | Iterates W `+0x28` values and calls `0x399eb0` for each nonnull D. This happens after association-removal loop. H. |
| Destroy local mutex | `0x3b0ed8–0x3b0edf` | Calls `0x4c7e50` after detach/descriptor release. New helper has `_mtx_destroy` diagnostic and writes lock word 6. H. |
| Postprocessing / result copy | `0x3b0ee4–0x3b0f70` | Calls `0x3b3f50` then copies result array through `0x3b3a40`; status-sensitive handling includes numeric 4. H. Postprocessing is not the primary ownership release; see below. |
| Free waiter array / return | `0x3b0f93–0x3b0fa3`, `0x3b0490–0x3b04b8` | Deallocates saved W base, then shared epilogue returns saved status after stack-canary check. H. No direct free of Q is present in this wait body. |

This order supports a meaningful conditional guarantee: **on the analyzed normal cleanup path, W storage and its referenced stack counter/mutex storage are not retired until the caller has attempted to remove its Q-list associations under Q's lock.** A stronger universal guarantee needs the mode/list and external-destruction contracts below.

## 2. Provisional objects and fields

Names below are analytical aliases only. An offset is relative to the stated object, never a verified Sony structure layout.

| Alias / field | Observable relationship | Evidence |
|---|---|---|
| D: generic descriptor; D `+0` | Pointer to lock used by lookup/release | `lookup_complete.asm.txt:0x39a01e–0x39a028`; `release_399eb0.asm.txt:0x399eb4–0x399ed8` |
| D `+0x10`, `+0x18` | Payload pointer; context/thread tag used in lookup revalidation | `lookup_tail.asm.txt:0x39a0af–0x39a0bd`; `lookup_complete.asm.txt:0x39a003–0x39a03f` |
| D `+0x20/+0x22/+0x26/+0x28` | Type discriminator, flag bit, validity state, generation-related bits respectively | `lookup_complete.asm.txt:0x399fc8–0x399ffb`; `retain_lock_399e20.asm.txt:0x399e24–0x399e2c`. That filename is an early hypothesis: this tiny callee only reads a flag, it does not retain or acquire. |
| A: descriptor payload | Signed word count at `+0`; indexed pointer table at `+0x28` | Prior AIO `0x3b064d–0x3b06e3` |
| I: indexed object | `I+0x20` points to Q | Prior AIO `0x3b073f`; corresponding worker relationship `aio_helpers.asm.txt:0x3b5160` |
| Q: request aggregate | Allocation observed as `0x58` bytes or an array with that stride; total/pending-like counts `+0/+4`, state `+8`, flags `+0xc/+0xd`, lock header `+0x20`, waiter-list head `+0x50` | `aio_following_bodies.asm.txt:0x3b2359–0x3b240f`; initial state 1/head zero are explicit; pending/state interpretation corroborated by worker/cancel, below. |
| W: call-owned waiter record | Array stride `0x38`; `+0` primary-counter pointer; `+8` optional secondary-counter pointer; `+0x10` local mutex-header pointer; `+0x18` associated Q; `+0x20` 32-bit result; `+0x28` D requiring later release; `+0x30` next waiter | Prior AIO `0x3b07c5–0x3b0810`, `0x3b086f–0x3b08c4`, `0x3b0de3–0x3b0ed1`; worker consumer `aio_helpers.asm.txt:0x3b59c5–0x3b5a09` |
| F: local frame | Header `F+0xe0`, mutex word `F+0xf8`, primary `F+0x104`, secondary `F+0x10c`, timeout `F+0x108` | Prior AIO preparation/association/wait sites above; init helper subtracts `0x18` from supplied word pointer. |

**Important mode distinction:** mode-1 and mode-2 branches associate the current W element; the other admitted branch uses the array base for registration (`0x3b0839`, `0x3b0900–0x3b096d`). Cleanup still iterates `0x38`-stride elements (`0x3b0de3`). Do not generalize the independent-per-element model to every branch. The validity invariant for this shared/base-record representation is not recovered; neither an intended API constraint nor a defect is established. No invocation recipe or scheduling procedure is proposed.

Initialization is partly clarified: the call supplies flags `0x102`; the allocator forwards the low flag bits to `0x43b880` on its small-allocation path (prior `allocation_candidate.asm.txt:0xc08c56–0xc08c74`). New `allocator_zero_path.asm.txt:0x43bedc–0x43bef7` tests `0x100` and calls `0x258ff0`; `zero_helper.asm.txt:0x25901a–0x25902e` clears bytes using zero-valued `rep stosq/stosb`. This supports zero-filled W fields on that path, explaining unset optional pointers. Complete allocator alternatives, size-class data and callback contracts remain unproved; a flag name imported from FreeBSD is unnecessary.

## 3. Synchronization and lifetime contracts recovered

### Descriptor lifetime is protected through a held lock, not a demonstrated AIO refcount

Lookup `0x399ee0` locks registry context `+0x218`, checks generation/state/type, records a current-context tag, releases the registry mutex, and acquires a lock through D `+0` (`lookup_complete.asm.txt:0x399f20–0x39a028`). It then reacquires the registry mutex and revalidates the tag/state/payload; failure releases the acquired lock and retries or returns null (`0x39a02d–0x39a0ee`, including `lookup_tail.asm.txt`). Successful return writes D to the caller's output and returns D `+0x10` **without releasing D's lock**.

New `rwlock_enter.asm.txt:0xc4b3a5–0xc4b3b7` uses atomic lock-word increment by `0x10`; `rwlock_leave_A.asm.txt:0xc4c341–0xc4c351` subtracts the same amount. This strongly supports a shared/read-lock pair. Release helper `0x399eb0` chooses this release or owner-aware `0xc4c4b0`; the latter includes recursion/owner handling. These are inferred lock modes, not source-symbol equivalence.

The wait body stores D only when it performs a fresh successful lookup; cached lookups reuse the held lock. It later releases each stored D once. There is no observed AIO-object reference-count increment in this body. Atomic decrements of unrelated file-like objects in postprocessing must not be mistaken for Q lifetime references.

Deletion provides corroboration: `record_notify_area.asm.txt:0x3afe63–0x3afe7c` releases the read-side D lock and obtains another lookup at `0x39a2a0` before disposing objects. `descriptor_exclusive_lookup.asm.txt:0x39a3bf–0x39a3c9` acquires through `0xc4bb20`; its `exclusive_lock_head.asm.txt:0xc4bb73–0xc4bb8c` CASes unlocked word 1 to the current-context pointer, unlike the shared increment. This supports an exclusive-lookup deletion design. The complete destruction contract and all other destroyers are not covered.

### Two nested protection domains

- **Q lock:** registration calls `0xbf1770(Q+0x20, operation 0x80000, ...)`, and releases with operation `0x100000`. The helper's diagnostic string `__lockmgr_args` and its dispatch/atomic owner-word operations corroborate a lock-manager mechanism (`object_lock_dispatch.asm.txt:0xbf1842–0xbf1882`, `0xbf1a22–0xbf1ed8`). The acquire path can install the current context at lock-header `+0x18`; release handles recursion/owner state. Full slow/error paths remain outside the proof. State checks/list insertion and later list removal are bracketed by this same Q lock in the caller.
- **Local mutex:** counter changes during registration occur between `0x4c6a00(F+0xf8)` and `0x4c6fa0(F+0xf8)`, while Q remains held. Waiter links are then installed under Q. A second state check occurs after counter setup, with explicit counter rollback on selected late-state branches (`0x3b07f2–0x3b0810`, `0x3b094f–0x3b09c0`). State-to-counter correspondence across every mode is not proved.

Observed lock order during association and notification is Q then local mutex. The wait phase holds only the local mutex before sleeping; it explicitly releases it before acquiring Q for detach (`0x3b0d63–0x3b0df5`). This avoids treating the two locks as interchangeable. No claim about all subsystem lock orders follows.

### Completion and cancellation consume the same W representation

New `aio_helpers.asm.txt` contains the worker region associated with recovered `aio_worker_entry2` strings (`OWNERSHIP_HELPER_WINDOWS.json:/[name=aio_helpers]/strings`). It loads Q through indexed object `+0x20` at `0x3b5160`, acquires Q's lock at `0x3b517f`, changes Q state 1 to 2 at `0x3b5188–0x3b518f`, then releases it. Later it reacquires that saved Q lock at `0x3b5920`, decrements Q `+4`, records an indexed-object state 3, and when the pending-like count reaches zero writes Q state 3 or 4 according to Q `+0xd` (`0x3b5929–0x3b5981`). These state assignments are observed; human-readable state names remain provisional.

For every W reached through Q `+0x50`, the worker:

1. Copies Q state into W `+0x20` (`0x3b59c5–0x3b59cf`) while Q is held.
2. Acquires the mutex at `W[+0x10]+0x18` (`0x3b59d2–0x3b59da`), matching the call-local header/word relationship.
3. Decrements the primary counter addressed by W `+0`; when it is nonpositive, may decrement the optional secondary and invokes wake helper on the primary address (`0x3b59df–0x3b5a09`).
4. Releases the local mutex and advances through W `+0x30` (`0x3b59a5–0x3b59bf`). Q remains held through traversal and is released on the shared path at `0x3b4c00–0x3b4c1a`.

The `_aio_multi_cancel`-associated body has a matching consumer: acquires Q lock at `0x3b1b63`, handles state/queued-entry branches, writes Q flags/count/state, then traverses W and updates counters/wakes under the same local mutex (`aio_following_bodies.asm.txt:0x3b1ca2–0x3b1d5b`). Its Q release is `0x3b1d71–0x3b1d88`. This is concrete cancellation-notification evidence, not a complete model of every cancellation subcase.

Neither examined notification loop frees W or removes it from Q's list. **The waiting caller owns association removal and W-array deallocation.** A completion notification alone therefore does not retire W. The caller's later acquisition of Q serializes its detach against these examined traversals, conditional on normal lock operation and the list invariant. Writing W's result before acquiring the local mutex is not an unprotected-write finding: Q is the enclosing protection domain, also taken by cleanup.

### Sleep and wake contract: substantial mechanics, remaining indirect boundary

`wait_primitive.asm.txt:0xc0627c–0xc06282` saves the supplied lock header; `0xc062c3–0xc062d5` resolves a lock-class descriptor. The body invokes a class callback at class `+0x30` before waiting (`0xc06403–0xc0642b`), passes the wait identity through queue/wait helpers (`0xc06431–0xc06510`), and conditionally invokes class `+0x20` afterward (`0xc06563–0xc06599`). This supports a release/wait/reacquire design, **not a direct proof of the selected callback's identity or atomic lost-wakeup contract**. Wake helper `0xc06910–0xc0694a` brackets an operation on the same identity with queue helpers and may invoke scheduler follow-up (`wakeup.asm.txt`).

The class table/objects referenced at recorded relative coordinates around `0x25683c0` and `0x1ac9d80/0x1ac9db8` are outside the retained text prefix and data interval `[0x1000000,0x1400000)`. No value was fabricated for those slots. Callback targets might still be inferred from existing initializer code, but are not directly readable as table data here.

## 4. Cleanup, errors and postprocessing

The shared post-allocation cleanup detaches records first, releases all saved descriptors next, destroys the local mutex, invokes postprocessing/result-copy helpers and finally frees W. Early context/validation/copy errors return before W allocation. Registration errors generally become per-entry status values rather than abandoning the allocated array immediately. The array free site is shared by the later success/status paths; no simple “error skips free” finding follows.

`result_3b3a40.asm.txt:0x3b3a4a–0x3b3a7d` is a diagnostic wrapper tail-jumping to the already identified copy-out routine. `finish_3b3f50.asm.txt:0x3b3f73–0x3b4187` conditionally revisits IDs/diagnostic statuses, performs its own lookup/release operations and file-like reference drops. It does not receive the W-array pointer, and the caller passes the saved input array after W's associations and original D holds are already retired. Treating it as the missing primary W destructor is contradicted by its data flow.

`entry_dispose.asm.txt:0x3b3e90–0x3b3efc` disposes a different indexed object and decrements a referenced object's counter before tail-calling deallocation. It must not be conflated with W or Q. The deletion body also contains object/array cleanup and pointer clearing; it is reviewed only enough to establish the read-to-exclusive transition above, not certify every Q destruction path.

## 5. Historical interpretation: what the new evidence changes

Historical retained documentation reports an `aio_multi_wait` lifetime race. It is a motivation, not a fact established by this capture. The original report's attribution and provenance limitations remain authoritative.

**Supporting relevance:** these bytes contain genuine cross-context waiter associations, callback-accessible pointers to a caller's stack counters/mutex, a heap waiter array, completion/cancellation consumers and later deallocation. This identifies the implementation area to investigate, rather than relying on a function-name analogy.

**Contradicting simplistic interpretations:** there are two lock domains, a held descriptor lock, state checks/rechecks, explicit list detach before free, and completion/cancellation traversals protected by Q. A model in which the caller simply frees still-registered waiters without synchronization does not describe the analyzed normal path. No AIO refcount can be inferred from unrelated atomic decrements.

**Unresolved:** the base-record branch's list invariant, all deletion/teardown paths, allocator alternatives, lock error/slow paths and concrete sleep-class callbacks. None is automatically a defect. No invalid access, exploitable schedule, reproduction, historical patch state or 14.10 presence is established. Existing 14.10 logs remain unchanged and do not reach an attributable result for this particular body (previous report's cited `43p` and `19g` stopping points).

## 6. Specific remaining gaps

| Missing fact | Why it matters | Existing artifact / static recoverability |
|---|---|---|
| Valid representation and list invariants for the base-record registration branch | Limits whether per-element detach and counter models generalize to every admitted mode | R text around `0x3b0839–0x3b096d`, callers and notification/list consumers. Likely partially recoverable; intended API constraints require attributable interface documentation. No runtime input campaign is proposed. |
| All transitions that remove/free Q or indexed objects | Descriptor read-side protection is only meaningful if destroyers honor the corresponding exclusive protocol | R deletion `0x3af900–0x3b01f0`, exclusive lookup `0x39a2a0`, dispose helper `0x3b3e90`, existing AIO worker/teardown code. Substantial static progress is possible; not all destroyers identified. |
| Exact selected sleep lock-class callbacks and queue atomicity | Needed to prove that a counter transition cannot be missed during sleep handoff and that the mutex is reacquired on each return | R init and sleep/wake code; class-table bytes are outside retained ranges. Code initializers may resolve callbacks; otherwise requires an already-preserved relevant class-data capture, not a new console capture under this authorization. |
| Allocation initialization, nonnull and failure guarantees on every backend | W optional pointers rely on initialization and caller has no null-result test | R `0xc08b50`, small-backend zero path now recovered, large backend `0x43e080` and allocator callback data. Partly recoverable from code; static global size-class data incomplete. |
| Every mode's counter accounting and late-state rollback | Needed to connect observed list representation with exact waiting/notification policy | Existing AIO body and newly decoded worker/cancellation consumers. Recoverable by a branch-specific symbolic accounting ledger; semantics of externally named wait modes remain unverified. |
| Lock helper exceptional/debug/interrupt/slow-path guarantees | Normal-path lock bracketing alone does not certify every execution context | R lock helper bodies and unexamined callbacks. Direct paths available; some dispatch data outside capture. |
| Actual execution/build identity and concurrent outcomes | Static instruction effects do not show which build ran or demonstrate a defect | Cannot be recovered from these bytes alone; needs independently attributable historical records/implementation evidence. No new target activity is proposed. |

## 7. Next offline investigation

Prioritize **one branch-specific association-and-detach ledger covering the base-record branch and the corresponding completion/cancellation consumers**, then connect it to the deletion helper's exclusive-lock lifetime boundary. The required code is already retained. Record which exact W address is published, which Q list owns it, which counter is addressed, and which cleanup path retires that association; leave unsupported invariants explicit. This is the highest-value remaining static question because most ordinary per-element ownership mechanics are now recovered, whereas a uniform model across all branches would overstate the evidence. Do not turn that work into trigger construction or concurrency scheduling instructions.

Original repositories, dumps, raw logs and earlier reports remain unchanged. This directory contains only new analysis and its manifests. No table comparisons, original-artifact hash checks, entry-layer decoding, probes or target contact were repeated.
