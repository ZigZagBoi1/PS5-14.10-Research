# Handle namespaces on 14.10: typed, generation-checked

Status: measured (88a section A, 88b). Three facts, one hypothesis closed.

## The handles are return values, not out-pointers

`probes/phase17_new_vectors/88a_handle_namespace_confusion.lua` section A
created eight event flags with `538(name, flags, pattern, &handle)`. The out
pointer stayed `0` and every later call used handle `0` and got `-1`. The
return value is the handle:

```
538 ef_create ret=525
544 signal    ret=0
546 clear     ret=0
545 wait      ret=0   (timeout 0)
549 sem_create ret=526
555 sem_post  ret=0
554 trywait   ret=-1  (empty)
552 close     ret=-1
```

`probes/phase17_new_vectors/88b_handle_typing.lua` on pid 109. Event flags and
semaphores therefore share one handle space, numbered consecutively (525,
526) — and `557` returned `529` for a name pointer, so the generic objects take
handles from the same space.

## Handles carry a generation

```
create A -> 527
delete A -> 0
create B -> 8719 = 0x220F    (slot 0x20F = 527, generation 2)
```

The freed slot is reused with the generation in the high bits, the same shape
as aio: `handle = slot | generation << 13`, and that `<< 13` is the shift this
document uses everywhere. An early draft inferred `<< 12` from a single sample;
the 96b sweep walked one slot through
`0x2206, 0x4206, 0x6206, 0x8206, 0xA206, 0xC206, 0xE206, 0x206`, i.e. generation
1..7 in bits 13+, wrapping after eight reuses (see the generation section below).
A stale handle is therefore distinguishable from a live one.

## A handle is typed: no cross-subsystem confusion

Every call that addressed an object through the wrong subsystem was refused:

```
ef_signal(544)     on a semaphore handle  -> -1
ef_poll(543)       on a semaphore handle  -> -1
ef_delete(539)     on a semaphore handle  -> -1
sem_post(555)      on an event flag       -> -1
sem_trywait(554)   on an event flag       -> -1
sem_delete(550)    on an event flag       -> -1
```

This closes the "five subsystems share process+0xc48, so a handle can be
retargeted at another type" hypothesis from 88a: sharing the numbering does
not share the type, and each syscall validates it.

## Allocator and generation (96b, 96d)

A handle is `slot | generation << 13`, and the slot table is shared by the
generic objects (557), semaphores (549), event flags (538) and aio ids (669).

- Freed slots form a **LIFO free list**: five creates took `0x207, 0x208, 0x209,
  0x20A, 0x20B`, and after deleting them the next five took `0x20B, 0x20A,
  0x209, 0x208, 0x207`.
- The generation is per slot, **three bits, period eight**, incremented on every
  reuse: `0x2206, 0x4206, 0x6206, 0x8206, 0xA206, 0xC206, 0xE206`, then `0x206`
  again, then `0x2206`. A handle kept from the first cycle is numerically equal
  to one issued eight reuses later (96b section A).
- The counter is shared across families: slot `0x208` went 557 generations 1→2→3
  →4 and then served an aio id at generation 5 (96d section D).

## A generation match does not defeat the type check (96e)

- A live 557 handle passed to the aio calls: `664` returned 0 with element
  status `0x80020003` (ESRCH), `663` returned 0, `662` returned 0 with element
  ESRCH. The aio handler resolves the slot, finds a foreign object and reports
  ESRCH; the 557 object is untouched, which the following `558(handle)` proves
  by deleting it and returning 0.
- A live aio id passed to `558` returned `-1`, while `662` with the ids array
  frees it.

So the wrap is real but contained: the slot number and generation are only the
lookup key, and each handler validates the object it finds. A stale handle can
alias a *new object of the same family* in the same slot (ordinary per-process
aliasing), never another family's object.

## aio delete needs a poll first (96f)

- submit → `664` reports state 3 → `662` returns element status 0 and the element
  is gone (`664` afterwards gives `0x80020003`).
- delete before any poll: `662` returns 0, the element status is
  `0x80020003`, and `664` still answers state 3 — the element survived.

## Still open

- `543` (ef_poll) returned `-1` for `(handle, 0xFFFFFFFF, 0, &pattern)`; the
  argument shape is not established.
- `552` (sem_close) returned `-1` on a handle `549` had just returned, yet
  `550` (sem_delete) works — the close path may need a different first
  argument.
- No race has been attempted on 538-546; they hold refcounts and are now
  reachable, which is the remaining reason to look at them.
