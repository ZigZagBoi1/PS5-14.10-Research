# Stale-handle hunt in the object families: why the Bagagwa mechanism has no 14.10 equivalent

Static and documentary, 2026-11-05. Follows `docs/HANDLE_NAMESPACE_14_10.md` (88a/88b/96b/96d/96e) and the
public 11.40 writeup, whose osem step is the only published double-free in this family.

## 1. What the public exploit needs

Bagagwa's stage 1-3 is: `osem_create` a named semaphore, `osem_open` it **again by name** so the object
carries two references, then `osem_delete` with `attr = 0`, which jumps straight to `free()` without
consulting the refcount at `+0x54`. The open handle now points at freed memory; a later `osem_close`
on it frees the reclaimer, and the double free is in hand.

Two ingredients: **a second reference obtainable by name**, and **a delete path that skips the
refcount**.

## 2. What 14.10 has

Measured in this corpus (`HANDLE_NAMESPACE_14_10.md`, 88a/88b/96b/96d/96e):

* `549 sem_create` returns a handle; `550 sem_delete` frees it; `554 trywait`, `555 post` operate on it.
* there is **no open-by-name call** in the family: the name map gives 549 create, 550 delete, 551/553
  wait/post variants, 552 close, 554 trywait, 555 post, 556 cancel. Nothing increments a reference the
  way `osem_open` does, and 88a measured `552` returning -1 on a live semaphore.
* handles are `slot | generation << 13`, the generation is **three bits with period eight**, the slot
  table is shared by generic objects (557), semaphores (549), event flags (538) and aio ids (669), and
  freed slots are a LIFO free list.
* a handle is **typed**: every cross-subsystem call is refused (544/543/539 on a semaphore, 555/554/550
  on an event flag all return -1), and a generation match does not defeat the type check (96e: a live
  557 handle passed to the aio calls resolves the slot, finds a foreign object and reports ESRCH).

So ingredient one is absent. Without a second reference there is no dangling handle to keep, and the
delete cannot leave one behind by construction.

## 3. The generation wrap is a red herring

The three-bit generation means a handle kept from cycle *N* is numerically equal to one issued eight
reuses later (96b). That is an ABA on the slot, and it is worth being precise about why it is not a
primitive:

* the *old* handle and the *new* handle are the same 64-bit value, so "using the stale handle" and
  "using the new handle" are the same call - there is no way to address the new object *while holding
  a reference the new owner does not also hold*;
* freeing does not advance the generation (the counter advances on **reuse**), so a delete never turns
  a live handle stale mid-flight; it empties the slot, and the next delete on it reports "no object"
  (the aio family returns `0x80020003` ESRCH for exactly that);
* the type byte in the object is checked on every call, so even a wrapped generation cannot retarget a
  handle at another family's object.

A slot ABA with a shared counter is a real oddity - it is the reason a handle from one family can be
*numerically* reused by another - but without a second reference and without a refcount-skipping free
there is nothing to dangle.

## 4. What would have to be true for this route to reopen

1. A call that increments an object's reference count **without** creating a new handle - i.e. an
   osem_open equivalent. None is present in the 549-556 block, and the name map has no candidate.
2. A delete path that frees regardless of the refcount. 550's behaviour on an object with a
   hypothetical second reference has never been testable, because ingredient 1 does not exist.
3. A reclaimer in the same size class that survives the first delete's field writes.

All three are needed; the first is absent by inspection, so the other two cannot be reached.

## 5. Consequence

The stale-handle hunt is **closed at the same place the Bagagwa chain starts**, and that is a
structural answer rather than a failed experiment: 14.10's object families are typed,
generation-checked and single-reference. The remaining object-lifetime surfaces that the corpus has
not exhausted are the ones with an explicit *shared* reference - file descriptors, kqueue knotes, and
the aio request's file reference - where a double close or a knote left on a closed fd is the
analogue of `osem_open`.
