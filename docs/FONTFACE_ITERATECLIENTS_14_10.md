# FontFace `iterateClients`: WeakHashSet requirements, checking-build asserts, controlled callback

`CSSFontFace::iterateClients` on a re-freed face needs three things to survive: the checking-build
`WeakHashSet` fields, a preloaded `RefCounted` base block, and a base address that does not collide with the
table metadata. With them the body runs and the property callback becomes a controlled indirect call.

## Summary

We forge a freed `CSSFontFace` (`self`) and drive `setStyle`, whose body is

```cpp
iterateClients(m_clients, [&](Client& client) { client.fontPropertyChanged(*this); });
```

Three vcalls are expected on the forged `Client` from the source order: `fontPropertyChanged` (4), `ref` (6),
`deref` (7). On the device **at least slots {3,4,5,7,8} are reached and slot 6 (`ref`) is not** — an open
point in itself, see the results table.

Three things had to be fixed before the body ran:

1. `m_clients` is a `WeakHashSet` (32 B on a checking build: `HashTable` 24 B + 2 counters), so the fake
   table needs `m_iterators` (+8) and `m_mutex` (+0x10) or `addIterator` SEGVs in `Lock::lock()`.
2. The build is **checking**: `CHECK_HASHTABLE_ITERATORS` has a single definition site
   (`HashTable.h:60-66`, `#ifdef NDEBUG`) and the `Locker` at `:1466` requires the `=1` side; a second,
   independent witness is the threading byte, which does not exist at all in an `NDEBUG` build
   (`RefCounted.h:163-165`). Note the gate scope: the lifecycle bools and `ref()`/`derefBase()` asserts run
   under `ASSERT_ENABLED || ENABLE(SECURITY_ASSERTIONS)`, and `SECURITY_ASSERTIONS` can be on under `NDEBUG`,
   so only the mutex cell and the threading byte carry the `NDEBUG` inference. The base block has to satisfy
   `m_refCount > 0`, `!m_deletionHasBegun`, `!m_adoptionIsRequired`; the threading comparison is opted out by
   `m_areThreadingChecksEnabled = 0`.
3. The base block must not collide with the table metadata; the clean split puts it on the bucket.

With that the body runs and the callback is dispatchable with a fully controlled `this` (our buffer) and a
controlled target — a RIP-control primitive. The remaining gap is declared below: the base shape itself is
not yet fully reliable (2/3), so the primitive is demonstrated but not yet deterministic.

## Ground (all [M], same build) — every offset is face-absolute from `self`

One frame throughout: `self` is the re-freed `CSSFontFace`. Where a pointer is involved, the absolute offset
is given and the indirection spelled out, so nothing has to be re-based.

* `m_clients` occupies `self+0x58..self+0x77`: `m_table` `self+0x58` -> bucket array at `self+0x98`,
  `m_iterators` `self+0x60`, `m_mutex` `self+0x68` -> a mapped zeroed byte, `opCount` `self+0x70`,
  `maxOp` `self+0x74` (`HashTable.h` checking layout; `WeakHashSet.h` counters after `m_set`).
  `m_wrapper` would be `self+0x78` by layout — not yet witnessed by a read (open row).
* Without `m_iterators`/`m_mutex` the body SEGVs inside `Lock::lock()` from `addIterator`
  (`HashTable.h:1466`); in a local build with real WTF the same forge reproduces it exactly.
* The forged client sits at `self+0xB8`, with the external vtable address at `self+0xB8` itself.
  `m_ptr` (`self+0xA8`) points at `self+0xB8`, so `client−0x20` = `self+0x98` = `bucket[0]`, and the
  `RefCounted` base block *is* that bucket: `refCount` = the bucket value (the impl pointer, never 1), and the
  next bytes are the pointer's high dword, structurally `10 00 00 00`. So `isOwnedByMainThread` (`+4`) reads
  `0x10`, which is fine because `m_areThreadingChecksEnabled` (`+5`) is 0 and **skips** the comparison;
  `deletion`/`adoption` (`+6`/`+7`) are 0. Net: `+4` indifferent, `+5` must stay 0. Measured on the real
  client the base sits at `client−0x20` with `refCount` 2 and `isOwnedByMainThread` 0/unset, which is why the
  byte had to be *measured* rather than assumed.
* Real vtable dump (128 B) confirms the ABI order: 0/1 dtors, 2 `fontLoaded`, 3 `fontStateChanged`,
  4 `fontPropertyChanged`, 5 `updateStyleIfNeeded`, 6 `ref`, 7 `deref`. `FontFace` overrides
  `fontStateChanged` (`FontFace.h:92`) **and** `ref`/`deref` as `final` (`FontFace.h:93`), so `+0x30`/`+0x38`
  hold real code — not base stubs.

## Open row: the fields shift under the checking build [I]

With `m_clients` at 32 B and `WeakPtr<FontFace>` at 16 B (`WeakPtr.h:183-186`), `m_fontSelectionCapabilities`
lands at `self+0x88` and the slope the setter writes covers `self+0x94..0x99` — or `self+0x8C..0x91` if the
`ASSERT_ENABLED` bool is absent from that struct. Both candidates fall on HT metadata: `0x8C` = `keyCount`,
`0x94` = `tableSize`. If it is `keyCount`, the setter itself turns 1 into `0x00003838` = 14392 and
`reserveInitialCapacity` asks for **115 136 B** instead of 8, so `~Vector` frees ~112 KB and in mini-mode races
the 5 ms scavenger — which would be exactly the residual 1-in-3, since every poison kills before that free.

Two consequences already applied here: `0x9C` is the high half of the bucket pointer (`0x10`), not a byte to
preload, and the threading check is skipped because `0x9D` (`m_areThreadingChecksEnabled`, byte 5 of the same
pointer, structurally 0) opts out — so `0x9C` is indifferent and `0x9D` must stay 0.

Experiments queued, both read-only-ish and cheap: `m_ptr=0` with the slope store in play isolates the big
malloc/free with zero vcalls; a sentinel diff over `0x78..0xBF` on a surviving run shows the landing zone of
the property and slope stores. **The row is inference, not measurement, until those run.**

## Known uncertainties (declared, not hidden)

* **The slope landing zone is unmeasured.** The harness presets "slope" bytes at `self+0x7C` and that habit
  predates this analysis, but under the checking layout the slope computes to `self+0x94` (or `0x8C` without
  the `ASSERT_ENABLED` bool in that struct). Both candidates fall on HT metadata, so which one is real changes
  the whole shape. A sentinel diff over `self+0x78..self+0xBF` on a surviving run settles it and is the first
  queued experiment.
* **The threading assert is not the source of the residual 1-in-3.** With the base block on the bucket, the
  byte that would enable the per-object check (`self+0x9D`) is byte 5 of the impl pointer and is `0x00` in
  **125/125** runs that reached `RIP2-GO` (byte 4 is `0x10` in all of them), so the comparison never runs.
  The rate therefore has to come from the address-dependent consequences of the same aliasing — the leading
  candidate is the size the setter makes `computeSize()` ask for, not the assert.
* **`dz`/`0x9C` is provisional.** With the base on the bucket `0x9C` is the pointer's high dword (`0x10`);
  writing 1 there is what this probe currently does and it is probably wrong, but it is only a high dword of
  a pointer that is never dereferenced in these runs. `0x9D` must stay 0.
* **A surviving run does not prove iteration.** The only per-run proof of the loop is a poison on a reached
  slot (4, 5, 7) or a wild vptr; plain base runs are counted as survivors, not as "iterated".
* **`document.fonts.check()` does not drive `iterateClients` on this drop**: `CSSFontFace::updateStyleIfNeeded`
  (`CSSFontFace.cpp:767`) has no callers, and `FontFaceSet::check` only reaches
  `Document::updateStyleIfNeeded`, which does not walk the client set.

## Oracle caveat (methodological, worth knowing)

`navigator.sendBeacon` is asynchronous: on a native crash the queue can be dropped, so the *absence* of a
post-trigger beacon does not prove a crash at that point. The verdict must be emitted with a **synchronous
XHR**. Our first counts were wrong because of this (a run looked dead when the setter had actually returned).

## Results (valid runs only: `RIP2-GO` sent, verdict by synchronous XHR)

| Run | Shape | Result |
|---|---|---|
| base (no poison) | `self+0xB0`, base block at `client−0x20` loaded | **AFTER** 2/3 (1 crash) |
| slot 4 poisoned (property callback) | same | **CRASH** 3/3 |
| slot 5 poisoned (`updateStyleIfNeeded`) | same | **CRASH** 2/2 |
| slot 6 poisoned (`ref` per ABI) | same | alive |
| slot 7 poisoned (`deref`) | same | **CRASH** |
| vptr poisoned (`0x4141…`) | same | **CRASH** 3/3 |

Controls: empty table (`m_table=0`) alive; `keyCount=1` with `m_ptr=0` alive (allocation + skip exercised).

So the body reaches more vcalls than the source order suggests: at least {3,4,5,7,8}; the slot the ABI calls
`ref` (6) is **not** dispatched, which is itself an open data point.

## Open gap (declared)

* The base shape is not yet reliable (2/3). With a wild vptr it crashes 3/3, so the loop always starts, but
  a fraction of runs dies anyway; the two most likely causes are a stale `m_iterators` head and the property
  store rewriting the slope bytes so `setStyle` can return before `iterateClients`.

## Mechanism / where each fix comes from

* `WeakHashSet` iteration = `copyToVectorOf<Ref<Client>>` → `Mapper::map` (specialised) → `computeSize()` →
  `removeNullReferences` → `HashTable::removeIf`, then a range-for that builds `Ref<Client>` (calls `ref`),
  appends, and destroys the vector (`deref`, then `free`). `removeIterator` and the iterator destructors run
  inside `map`, **before** the callbacks.
* Checking build: `RefCounted::ref` and `derefBase` assert on `refCount`/`deletion`/`adoption` and on
  `isOwnedByMainThread`. A fake `this` with zeroed garbage aborts.
* `m_deletionHasBegun` sits at `client−0x1C`; if the base block is placed at `client−0x20` = a table
  metadata byte, `tableSize` and the threading byte fight. Splitting the base onto the bucket removes it.

## Reproduction outline

Attached probe: `probes/phase13_webkit/p672-iterateclients-callback-dispatch.html` — self-contained, with
parameters and runbook in the file header. It is a `p658` lineage file (the header of the harness says so):
**the id to use is `p672`**. It emits `RIP2-GO` before the setter and `RIP2-AFTER` after it, both with a
synchronous XHR.


1. leak + reclaim of a `CSSFontFace`, then forge: `m_clients` table (1 bucket → impl at `self+0xA0`, with
   `m_ptr` = client), client with external vtable `VT+8`;
2. external vtable: 16 entries = the `ref` entry from the real vtable, except the callback slot;
3. base block: `refCount` = the bucket pointer (never 1), `isOwnedByMainThread` = 1, deletion/adoption 0;
4. `setStyle`: beacon `GO`, call it, beacon `AFTER`;
5. gates: class pattern on the leaked vtable, auto-retry on load failure.

## Why it may matter to others

The three requirements above are generic for anyone forging a `WeakHashSet`/`Client` pair on this build:
without them the bench dies inside `Lock::lock()`, then inside the `RefCounted` asserts, and the failure
looks like "the append faults" — it does not.
