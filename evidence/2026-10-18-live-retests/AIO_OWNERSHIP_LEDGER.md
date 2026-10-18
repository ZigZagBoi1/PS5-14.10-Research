# AIO ownership ledger and bounded live-result note

2026-10-18. This is a focused continuation of the retained AIO analysis. It
does not rerun syscall-table, hash, or entry-decoding work.

## Evidence boundary

All implementation observations below are **13.60-labeled; acquisition
authenticity unresolved**. The analyzed range-family inputs are
`docs/dumps_13.60/kernel_text.bin` (recorded SHA-256
`406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`) and
`kernel_data.bin` (recorded SHA-256
`e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46`), at the
source revision and manifest identified by
`evidence/2026-10-18-implementation-followup/aio-ownership/AIO_OWNERSHIP_ANALYSIS.md`.
The offsets below are retained text/data offsets, not authenticated Sony VAs.
The browser `9448…` family and compatibility JSON are not used as substitutes.

The disassembly is preserved in
`evidence/2026-10-18-implementation-followup/implementation-research/aio663_body.asm.txt`,
`.../aio-ownership/aio_following_bodies.asm.txt`, and
`.../aio-ownership/aio_helpers.asm.txt`. The prior ownership report is the
authoritative detailed analysis; this ledger extracts the ownership and lock
edges needed to locate the unresolved concurrency boundary.

## Provisional records

These names describe observed pointer relationships only. They are not
recovered Sony source-level type names.

| Alias | Observed relationship | Confidence |
|---|---|---|
| `D` | Descriptor held through lookup; payload at `D+0x10`; lock-related word/pointer at `D+0`; saved in `W+0x28` for later release. | H on loads/stores; lock contract M |
| `A` | Descriptor payload with a count at `A+0` and indexed pointer area reached from `A+0x28`. | H |
| `I` | Indexed object whose `I+0x20` points to aggregate `Q`. | H |
| `Q` | Aggregate with state-like `Q+8`, flag-like `Q+0xc/+0xd`, lock header at `Q+0x20`, waiter-list head at `Q+0x50`, and a pending-like count at `Q+4`. | H for fields; names U |
| `W` | Call-owned waiter record, stride `0x38`: primary counter `+0`, optional secondary `+8`, local-mutex header `+0x10`, associated `Q` `+0x18`, result `+0x20`, saved `D` `+0x28`, next pointer `+0x30`. | H |
| `F` | Call-local frame containing mutex word `F+0xf8`, primary/secondary counters `F+0x104`/`F+0x10c`, and timeout state. | H |

## Lifecycle ledger

The state below is the normal path visible in the retained bytes. “Lock held”
means after the identified helper returns and before the matching release; the
helpers’ exceptional and scheduler paths are not fully recovered.

| Phase | Retained location | Direct observation | Ownership implication |
|---|---|---|---|
| Frame preparation and validation | `aio663_body.asm.txt:0x3b0232–0x3b0548` | Inputs, count/mode checks, stack arrays, optional timeout copy, and optional diagnostic allocation occur before waiter-array allocation. | Early copy/validation failures do not yet own `W`; policy meaning of status values is unknown. |
| Local wait state initialization | `aio663_body.asm.txt:0x3b0555–0x3b0571`; `mutex_init_4c7dd0.asm.txt:0x4c7e03–0x4c7e3c` | Initializes the local mutex associated with `F+0xf8`; the helper writes its lock word/header state. | `F` owns the wait counters and mutex for this call. Exact mutex class/callback remains unresolved. |
| `W` allocation and initialization | `aio663_body.asm.txt:0x3b0576–0x3b05bc`, `0x3b058e–0x3b059e`; `allocator_zero_path.asm.txt:0x43bedc–0x43bef7`; `zero_helper.asm.txt:0x25901a–0x25902e` | Allocates `count*0x38` with flags `0x102`; the selected zero path clears bytes. The caller has no visible null-result branch. | `W` is call-owned after allocation. Zeroing is supported for the selected backend only; all allocator alternatives and failure guarantees are unknown. |
| Descriptor lookup/hold | `aio663_body.asm.txt:0x3b061e–0x3b0649`; `lookup_complete.asm.txt:0x399ee0–0x39a0ee`; `release_399eb0.asm.txt` | Lookup validates registry state, acquires the descriptor-associated lock, revalidates, and returns while that hold remains. `D` is saved in `W+0x28`. | The body shows a held descriptor protection edge, not an AIO refcount. A failed lookup follows per-entry status paths. |
| Aggregate lock acquisition | `aio663_body.asm.txt:0x3b073f–0x3b0788` | Resolves `I+0x20` to `Q` and calls `0xbf1770(Q+0x20, 0x80000, ...)`. | Registration/list/state operations that follow are conditionally under `Q`’s lock. The operation’s exact source-level mode is inferred from helper behavior. |
| Association and counter updates | `aio663_body.asm.txt:0x3b0798–0x3b096d`, `0x3b07f2–0x3b0810`, `0x3b094f–0x3b09c0` | Records `W` pointers to counters/mutex/Q, changes counters under the local mutex, rechecks Q state, rolls back selected late-state changes, and links a waiter when the branch permits. | The normal path publishes the association before Q unlock. The admitted base-record branch does not have a fully recovered W-to-list invariant. |
| Registration release | `aio663_body.asm.txt:0x3b0a01–0x3b0a3c` | Calls `0xbf1770(..., 0x100000, ...)`, then advances to the next input/current record. | No `W` free occurs while registration still holds Q. |
| Wait handoff | `aio663_body.asm.txt:0x3b0a8c–0x3b0d63`; `wait_primitive.asm.txt:0xc0627c–0xc06599` | Tests counters under the local mutex, calls `0xc06260` with the primary counter and local mutex header, accounts timeout, then releases the local mutex at `0x3b0d63`. | The local mutex is the wait-domain lock. The callback sequence supports release/wait/reacquire, but the selected class callbacks and lost-wakeup atomicity are not directly identified. |
| Completion notification | `aio_helpers.asm.txt:0x3b5160–0x3b518f`, `0x3b5920–0x3b5a09` | Worker obtains Q, changes observed Q state values, traverses Q’s waiter list while Q is held, copies Q state into `W+0x20`, then takes `W+0x10`’s local mutex, decrements counters, wakes, releases the mutex, and follows `W+0x30`. | Notification does not free or unlink `W` in the inspected path. Q protects the result/list traversal; the local mutex protects counter/wake updates. |
| Cancellation notification | `aio_following_bodies.asm.txt:0x3b1b63–0x3b1d88` | Cancellation takes Q’s lock, changes state/flags/counters, walks W records, updates counters and wakes under the local mutex, then releases Q. | Same ownership direction is observed: notification consumes W but the waiting caller remains responsible for detach/free. Other cancellation subpaths are not covered. |
| Return from wait | `aio663_body.asm.txt:0x3b0d63–0x3b0d6c` | Releases the local mutex before the caller starts per-Q detach. | This creates a scheduling interval before cleanup can reacquire Q; it is a candidate boundary for analysis, not a demonstrated race. W is still allocated and associated during the interval. |
| Association detach | `aio663_body.asm.txt:0x3b0de3–0x3b0eaa` | For each nonnull `W+0x18`, reacquires Q with `0x80000`, copies `W+0x20`, searches Q’s `+0x50` singly linked list, unlinks W, clears `W+0x18`, updates observed Q flags/state, and releases Q with `0x100000`. | Q serializes cleanup against the examined worker/cancel traversals. The predecessor search assumes the W is present; the base-record branch and all external destroyers are not enough to prove that invariant universally. |
| Descriptor release | `aio663_body.asm.txt:0x3b0eaf–0x3b0ed6`; `release_399eb0.asm.txt` | Iterates saved `W+0x28` entries and releases each nonnull descriptor hold. | Descriptor release follows association removal. No AIO-object refcount increment was observed. |
| Mutex destruction and result processing | `aio663_body.asm.txt:0x3b0ed8–0x3b0f70`; `mutex_destroy_4c7e50.asm.txt` | Destroys F’s mutex, then runs postprocessing/result-copy helpers. The postprocessing helper does not receive W’s base. | The primary W ownership release has already occurred logically; postprocessing is not a recovered W destructor. |
| W deallocation and return | `aio663_body.asm.txt:0x3b0f93–0x3b0fa3`, shared epilogue `0x3b0490–0x3b04b8` | Frees the saved W base, then returns the saved status after stack-canary handling. | Normal path evidence supports “detach, release D, destroy local mutex, then free W.” It does not prove every exceptional path or allocator guarantee. |

## Lock order and candidate race boundaries

The strongest recovered lock order is `Q -> local mutex` during association and
notification. The wait path holds the local mutex while deciding to sleep, but
the wait primitive may release/reacquire it internally; the caller explicitly
releases it before cleanup acquires Q. This yields three bounded boundaries:

1. **Registration publication boundary:** Q is held while counters and list
   membership are established, then released at `0x3b0a01`. A worker cannot
   traverse the published Q list concurrently with the registration writes if
   the Q lock helper has its normal contract. The base-record branch
   (`0x3b0839`, `0x3b0900–0x3b096d`) may publish a different W relationship
   than the per-element cleanup assumes; this is the highest-value unresolved
   static question.
2. **Sleep/wake boundary:** `0xc06260` and its indirect lock-class callbacks
   mediate the transition between counter test, unlock/sleep, wake, and
   reacquire. The callback identities and queue atomicity are outside the
   retained class-data window. A lost wake or stale counter cannot be inferred
   from the call alone.
3. **Wake-to-detach boundary:** after `0x3b0d63`, the caller is outside the
   local mutex until it reacquires Q at `0x3b0e10`. During that interval a
   worker/cancel path may update W, but the examined paths retain Q and W
   storage until the caller unlinks the record. The bytes therefore show a
   synchronization boundary, not a proven use-after-free. An external Q
   destroyer that ignores the descriptor/exclusive protocol would change this
   conclusion, but all such destroyers are not recovered.

The actual byte-supported conclusion is conditional: on the analyzed normal
path, completion/cancellation does not retire W; the waiting caller removes
the Q association under Q’s lock and frees W only afterward. The ledger does
not establish a race, memory-safety defect, exploitability, patch state, or
14.10 applicability.

## Relation to the live sessions

The live records are separate runtime evidence and do not validate the static
artifact or its firmware label:

| Session | Exact record | Observation | Limit |
|---|---|---|---|
| Selector check | `aio-661-670-zeroarg/response.raw`, SHA-256 `c618453f09459b473ce299c2578b7320e1bb47e4b230b25711641a5c8dff1104` | 663 returned `table h=-1 l=4294967295`; 661 emitted `BEFORE` and no return was observed. | Zero-argument marshaling and signedness are unverified; missing tail does not identify a kill or cause. |
| 53a | `retest-53a-aio/response.raw`, SHA-256 `8bdce42a4f52aa03171a8df53c4dcec7659e15b5059d33d7c22e15fbe906462b` | Reached the first `aio_error` `BEFORE` marker; no syscall return or completion marker. | No AIO result established. |
| 53b | `retest-53b-afroute/response.raw`, SHA-256 `98e260c75f73b2759f269522b3cafe9eea4a8a3811e44cf28f630573c84a6bbe` | 152-byte variant wrote 168 and received a 136-byte non-echo candidate response; zero pointer-shaped qwords were reported. | This is route-message behavior only; no leak or kernel-address attribution follows. |
| 53c | `retest-53c-kldstat/response.raw`, SHA-256 `d5dc1981441495cb2322d116c71722e0c47337f9bfc3f8634a220323f4c9c064` | Reached the first kldstat `BEFORE` marker; no return or completion marker. | No structured module/symbol result established. |
| 53d | `probes/phase13_53batch/53d_cclosure_retest.lua` | Not sent. | Retained runtime evidence identifies `__call` as a Lua function, while this script mutates guessed CClosure fields. Its premise is unresolved and the write was not authorized by the evidence basis. |

## Remaining static work

The most useful next offline step is a branch-specific symbolic ledger for the
base-record registration path, paired with all retained Q destroy/teardown
consumers. It should account for the exact W address published, the counter
address, Q list membership, late-state rollback, and the point at which each
destroyer takes the descriptor’s exclusive path. The sleep-class initializer
and class-data gap should be resolved only from already retained bytes or an
independently attributable artifact. No race-winning schedule or console
probe follows from this report.
