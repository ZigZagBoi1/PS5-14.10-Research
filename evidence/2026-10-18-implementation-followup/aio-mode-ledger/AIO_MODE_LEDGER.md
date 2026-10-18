# AIO association and detach ledger

2026-10-18. Focused continuation of ../aio-ownership/AIO_OWNERSHIP_ANALYSIS.md. **13.60-labeled; acquisition authenticity unresolved.** No 14.10 implementation applicability is established.

## New conclusion

The ordinary per-element ownership model can be narrowed by branch: two branches publish the current array element, while the remaining admitted branch publishes the array base. The cleanup code remains element-indexed. Thus the earlier conditional lifetime guarantee cannot be generalized to all branches without proving an additional representation/list-membership invariant. This is a concrete static inconsistency to explain, not a demonstrated execution, race, invalid access or vulnerability. No triggering input, schedule or console test is supplied.

## Evidence basis

Only already-decoded records were used: ../implementation-research/aio663_body.asm.txt, AIO663_CFG.json (/instructions keyed by offset), and ../aio-ownership/aio_helpers.asm.txt and aio_following_bodies.asm.txt. Original code is F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin. Source-file offsets below are not authenticated VAs. Original acquisition/hash limits are inherited from the ownership report; no binary decoding, table comparison or original-hash comparison was repeated. Current repository pin is 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70.

Notation: F = current frame base, B = allocated waiter-array base saved at F+0x40, W = current record held in r14, Q = aggregate object, P = primary frame counter at +0x104, S = secondary at +0x10c, L = local mutex word at +0xf8/header +0xe0. These are provisional aliases, not source structures or public ABI names. Branches A/B/C below are analytical labels; no documented wait-mode names are assigned.

## Operation ledger

| Path | Exact instruction references | Published association and counter effects | Confidence / limit |
|---|---|---|---|
| Common preparation | 0x3b0563; 0x3b058e–0x3b05c5 | Initializes P to zero; one branch establishes P=1,S=0. B saved separately from W. | Direct instructions, high. Heap optional-field zeroing remains conditional on allocator contract from prior report. |
| Current-record progression | 0x3b05db–0x3b05ec | Advances W by 0x38 per iteration; B slot is not advanced here. | Direct, high. Distinguishes current element from shared base. |
| A: first branch after mode comparison | 0x3b078c–0x3b0792; 0x3b0798–0x3b0810 | Copies Q state to W+0x20. On pending-state path, acquires L, increments P, stores &P and local header in W, releases L, rechecks Q state, stores previous Q head into W+0x30, Q head=W, W+0x18=Q. | Direct, high. Q lock encloses the sequence under normal helper contract. |
| B: second mode branch | 0x3b0841–0x3b08c4 | Copies state to W; pending path increments S under L, stores &P, &S, local header in W; publishes W through Q head and stores Q in W+0x18. P has the branch-specific sentinel-like initialization above. | Direct effects high; meaning of P/S policy inferred. |
| C: other admitted branch | 0x3b0839; 0x3b08e5–0x3b096d | Uses B loaded from F+0x40, rather than W, for state, counter pointers and list fields. Pending path increments P under L; publishes B through Q head and stores Q in B+0x18. | Direct, high. Cannot replace B with W in pseudocode. Correctness depends on an additional invariant not supplied by the record. |
| Late-state A/C path | 0x3b094f–0x3b09c0; A also 0x3b07f2–0x3b07f7 | Selected state rechecks route to diagnostic and decrement P under L, then set saved numeric status 0x10. | Direct, high. Not universal rollback for every branch. |
| Late-state B path | 0x3b08a7–0x3b08ab; 0x3b09d9–0x3b09fa | Diagnostic and status 0x10; no corresponding S decrement appears in this bounded branch. | Direct absence within this branch only. Does not by itself establish an accounting defect. |
| Immediate-state handling | 0x3b08cd–0x3b08e0; 0x3b09c2–0x3b09d7; 0x3b09fc | Reads/writes aggregate byte +0xc; may add bit 0x10000 to recorded status. C writes its result through B; A/B through W. | Direct effects high; public meanings of flag/status unknown. |
| End of registration | 0x3b0a01–0x3b0a3c | Releases saved Q lock, restores iteration inputs and advances W. | High direct sequence; full exceptional lock behavior unproved. |
| Wait decision | 0x3b0a8c–0x3b0ac5 | Acquires L, checks P; one branch also checks S, with branch-specific skip to exit. | Direct, high. P is not simply a count of all registered records in every branch. |
| Notification consumer | aio_helpers.asm.txt:0x3b5985–0x3b5a0b | Under Q lock, traverses Q head and record+0x30; writes result, takes record's L, decrements addressed P; when nonpositive may decrement addressed S and wake. Does not detach/free record. | Direct, high for bounded worker path; all producers not audited. |
| Cancellation consumer | aio_following_bodies.asm.txt:0x3b1ccb–0x3b1d5b | Matching head/next traversal and local counter/wake operations under Q lock. | Direct, high for examined cancellation path. |
| Cleanup selector | 0x3b0da1–0x3b0df3 | Iterates records using B+i*0x38; loads each record+0x18 as Q. Null Q skips association-detach work. | Direct, high. Not redirected according to mode. |
| Unlink | 0x3b0df5–0x3b0e79 | Acquires selected Q lock, searches its list for current indexed record, removes head or predecessor link, clears that record+0x18. | Direct, high. Search assumes membership; no separate record-to-all-lists directory is recovered. |
| Retirement | 0x3b0eaf–0x3b0edf; 0x3b0f93–0x3b0fa3 | Releases retained descriptors after detach pass, destroys L, later deallocates B. | Direct, high. Descriptor-lock protection of Q cannot alone certify membership bookkeeping. |

## What is now better established

1. A record's +0x18 and +0x30 fields form the caller's only directly recovered association/next bookkeeping in these paths. Descriptor storage at +0x28 serves a separate held-lock cleanup responsibility.
2. Completion and examined cancellation consume list records; caller cleanup retires them. Notification is not ownership transfer or automatic detach.
3. Different Q locks serialize operations on their respective lists; the local mutex serializes the addressed counters. Neither fact alone proves the list representation is valid for every branch.
4. The complete branch model is not “allocate N independent waiters and always publish the ith waiter.” Branch C explicitly uses the base record. Treating the earlier overview that way loses a real instruction-level distinction.
5. P and S have different initialization/update rules. A blanket “one pending counter equals number of waiters” invariant is not supported.

## What remains to resolve

The missing fact is the contract making the base-record representation valid across its admitted uses, including aliasing of Q objects and external interface constraints. The body itself permits count-scaled allocation and advances a current record, but that does not establish every logical path is dynamically attainable with independent objects. No source-level precondition, dynamic outcome or authenticated build provenance has been recovered that settles the issue.

Existing bytes may clarify through callers, object creation/sharing and teardown: the next static work should establish whether indexed objects are constrained to share an aggregate and how that relationship is created. Retained allocator/request setup at ../aio-ownership/aio_following_bodies.asm.txt:0x3b2359–0x3b2498 already shows distinct aggregate-allocation branches. That evidence needs a complete object-construction-to-lookup path rather than an assumed public mode name. Independently attributable interface documentation could also establish preconditions absent from bytes.

Assessment: **a precisely localized representation invariant remains unresolved**. The per-element branches have stronger support for association-aware cleanup; the same confidence cannot be assigned to the base-record branch. The ledger justifies further defensive static review, not a claim of a historical bug, current defect, exploitability or firmware transfer. No trigger construction, concurrency simulation or live AIO invocation is authorized or performed by this analysis.

Original evidence/repositories unchanged. Search of the loader archive remains closed pending a new concrete artifact; it is not reopened by this AIO work.
