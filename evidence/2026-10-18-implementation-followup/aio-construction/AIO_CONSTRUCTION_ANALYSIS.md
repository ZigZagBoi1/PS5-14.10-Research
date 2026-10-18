# AIO construction-to-lookup analysis

2026-10-18. **13.60-labeled; acquisition authenticity unresolved.** Range-family bytes only. No 14.10 layout, vulnerability or live AIO behavior established.

## Result

The constructor visibly supports **both shared and per-index aggregate representations**. The descriptor publication/lookup chain preserves the indexed-object table, and wait subsequently dereferences each indexed object's aggregate pointer. Therefore aggregate sharing cannot be assumed universally to discharge the unresolved base-record waiter invariant. No cross-function contract tying that waiter branch to a restricted representation has been recovered.

This is a refined implementation model, not a demonstrated invalid access or an exploitability result. No console invocation, trigger parameters, scheduling procedure or payload is supplied.

## Sources and method

Reused ../aio-ownership/aio_following_bodies.asm.txt, lookup_complete.asm.txt and lookup_tail.asm.txt; ../implementation-research/aio663_body.asm.txt; ../aio-mode-ledger/AIO_MODE_LEDGER.md. All code locations are **kernel_text.bin file offsets**, not authenticated VAs. Original artifact: F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin; inherited SHA-256 406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1. No original digest/byte comparison repeated.

New narrow Capstone 5.0.7 decoding: descriptor publication at 0x399de0–0x399e20, preserved in descriptor_publish.asm.txt and NEW_WINDOW.json with a selected-window hash. Decoder script is preserved as data/procedure; repository code and original binary were not executed. Current source revision: 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70. Original repositories and evidence unchanged.

## Provisional relationships

D = generic descriptor. A = submitted descriptor payload. T = A's indexed pointer table. I = an indexed object. Q = aggregate holding state, lock and waiter-list head. These are analytical names only, not verified Sony structure names.

Recovered chain: **D+0x10 → A; A+0x28 → T; T[index] → I; I+0x20 → Q**. It is supported by writes in construction and reads in wait/lookup, rather than assigning a type from one displacement.

| Stage | Exact location and source | Observed effect | Confidence / limitation |
|---|---|---|---|
| Construction choice | aio_following_bodies.asm.txt:0x3b2348–0x3b2357 | Saves an input-derived construction choice; branches into shared aggregate or aggregate-array allocation. | High instruction effects. Public flag/prototype meaning unverified; no invocation values prescribed. |
| Shared Q allocation | same:0x3b2359–0x3b23ab | Allocates one 0x58-byte aggregate; initializes two count-like fields from the request count, state to 1, waiter head to zero, then initializes its lock. | High. Allocator assumptions inherited. |
| Per-element Q allocation | same:0x3b23ad–0x3b2411 | Allocates count times 0x58; initializes each aggregate's count-like pair to 1, state 1, head zero and lock; advances the initializer by 0x58. | High. Distinct addresses within the allocated array, conditional on successful allocation. |
| Payload/table construction | same:0x3b2415–0x3b2498 | Allocates 0x30-byte A and count-sized pointer table; stores table at A+0x28, aggregate backing pointer at A+0x10, and branch-dependent word counts. | High. Exact member names unknown. |
| Shared assignment | same:0x3b2518–0x3b2571 | For each allocated I, stores the unchanged Q pointer into I+0x20, writes I into T and advances another per-item buffer. Q itself does not advance in this loop. | High data flow. Multiple indexed objects can share one Q in this representation. |
| Per-element assignment | same:0x3b2573–0x3b25c7 | For each I, stores current Q at I+0x20, writes I into T, then advances Q by 0x58. | High data flow. Indexed objects receive distinct Q addresses in this representation. |
| Descriptor publication | same:0x3b25c9–0x3b25e7; descriptor_publish.asm.txt:0x399de4–0x399df0 | Passes A to helper; helper stores the payload at D+0x10, type word at D+0x20, another pointer at D+8 and clears flag word D+0x22. Caller releases D-associated lock afterward. | High bounded writes. Registry reservation/visibility protocol not fully proved. |
| Lookup result | lookup_complete.asm.txt:0x399fc8–0x39a03f; lookup_tail.asm.txt:0x39a095–0x39a0ee | Checks descriptor generation/state/type; acquires associated lock and rechecks; successful return supplies D and its payload A. | High effects; normal lock semantics supported by prior report, exceptional paths incomplete. |
| Wait-side indexing | aio663_body.asm.txt:0x3b064d–0x3b06e7,0x3b073f | Checks payload count, reads T[index] and then I+0x20 to obtain Q. | High bounded data flow. No normalization to a single Q recovered in this segment. |
| Worker corroboration | ../aio-ownership/aio_helpers.asm.txt:0x3b5160–0x3b5197,0x3b5920–0x3b5985 | Loads Q through I+0x20; changes shared state under its lock; decrements Q pending-like field and traverses Q waiter head at terminal-like state. | High effects; supports the construction model, not universal ownership certification. |

## Consequence for the waiter ledger

The previous ledger correctly distinguishes current-element waiter publication from base-record publication. This pass establishes that object construction itself does not collapse every I to the same Q. Moreover, a shared-Q representation alone does not prove that every waiter-list insertion is idempotent or that its duplicate-membership handling is correct. Those are separate invariants; do not substitute one for the other.

The constructor's branch choice and wait's branch choice occur in different functions and are not shown to be equivalent. Reusing the word mode for both would invent an ABI relationship. The observed request-count checks and per-object state checks do not themselves enforce a cross-call relationship between these choices.

Accordingly, the per-element cleanup proof remains conditional. A universal lifetime guarantee for the base-record branch is **not established**. The alternative conclusion that the branch is necessarily vulnerable is also **not established**: complete interface preconditions, dynamically reachable object states, all callee effects, executable-build identity and fault outcomes are missing.

## What can still be recovered offline

1. Inspect the request publication/queue helper at 0x3b3a90 and descriptor reservation helper 0x3998e0 for any transformation, canonicalization or cross-object contract between creation and consumption. Existing bytes are available; only a bounded portion was previously reviewed. Do not assume a transformation exists.
2. Trace teardown and descriptor-exclusive paths to determine how aggregate ownership is retired for both construction representations. This can strengthen protection/cleanup conclusions independently of any vulnerability claim.
3. Seek already-retained attributable interface/source records that identify valid construction/wait contracts. The loader deployment archive remains missing; no further broad search is justified by this result.

The most useful next static task is the **publication-to-queue transition at 0x3b3a90**, followed by teardown. It directly addresses a remaining implementation boundary, whereas repeating table/handler consistency, selector624 baseline calls or source attribution searches would not.

No new live actions were taken. Acquisition authenticity, exact historical patch state and 14.10 applicability remain unresolved.
