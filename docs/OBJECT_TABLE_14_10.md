# The per-process object table on 14.10

Probes `435a`-`446a`, 2026-10-22/23. Everything here was measured from a game process
through the Lua loader; no capture from this round contains a kernel pointer.

## Why this table matters

Every Sony object handler in the sysent range - events (`538`-`546`), semaphores
(`549`-`556`), named objects (`557`/`558`), blockpools (`653`), AIO requests (`669`) - hands
the caller a small integer and takes that integer back on every later call. If those
integers can be aimed at chosen kernel objects, the handlers become a heap-shaping device;
if they cannot, every object is reachable only through the kernel's own lookup. This round
measured which it is.

## The identifiers are one shared table, generated and typed

- **One namespace, not one per family.** Creating an evf, an osem and a namedobj in
  sequence returned `814`, `815`, `816` (`435a`). Earlier ids like `evf[1] = 16901` are the
  same space with a generation already burned.
- **The id is `generation << 13 | slot`.** `437a`: eight evf creates returned
  `1829 ... 1836`; after deleting four, the next four came back `10021`-`10024`, which
  decode to generation 1 on the same four slots. Repeated reuse climbs the generation
  (`438a` saw `g2`, `g3`, `g4`).
- **Reuse is LIFO and exact.** `437a` deleted `1831, 1829, 1832, 1830` and got the slots
  back in the reverse order of that deletion.
- **Placement is predictable before the object exists.** `438a` wrote its predictions down
  first - `18220` then `18219` - and received exactly those, and a freed evf slot was
  taken by an osem, so the free list is shared across families.

## Lifetimes are reference counted, and the generation check stops double release

- **osem** (`439a`): `549(name, 0x100, 0, 4)` creates; `551(name)` opens the same object
  and returns a second handle. Deleting through the creator removes the name from the
  registry while the opened handle keeps the object usable.
- **Double release is refused** (`440a`): close twice returns `0` then `-1`, delete twice
  returns `0` then `-1`, and post through the dead handle returns `-1`. This is the same
  generation rule the AIO queue applies (`0x80020003`, see `docs/AIO_BATCH_14_10.md`).
- **A registered name holds its object** (`443a`): 1000 named evf objects were created and
  every handle closed, and both the first and the last name still resolved. The registry
  reference is not reachable from the process, so a name keeps its object alive until the
  process exits - or until the family's delete is used.
- **The delete is not the close** (`444a`): for evf, `539` is the delete and `541` is the
  close. `541` refuses the creator's handle and accepts an opened one; `539` on the creator
  removes the name and the opened handle stays valid.

## The two shapes that could have been a hole, and are not

- **Names are bounded and refused, not truncated** (`445a`). Two names identical through
  byte `0x20` and different after it both fail with `-1`, and a 64-byte name fails too. A
  truncation collision would have let a lookup return an object registered under a
  different name; it cannot happen here.
- **The registry key includes the type** (`445a`). Registering one name as an evf and as an
  osem produces two entries, and the two open calls return different handles.

## No gauge, and no aim

`671` was the candidate instrument: a resource query that might report kernel allocations
we cause. It does not - the pair `6144/0` (mode 1) and `2560/0` (mode 2) is identical at
baseline, after 100 objects of each family, and after freeing 200 of them (`435a`). It is
a limit query.

So of the three things an exploit needs from an object table, this process has two:
objects can be **placed** predictably and **held** across calls. What it does not have is a
way to learn where an object lives in the kernel, and every id-based lookup is
generation-checked, so a stale or forged id resolves to nothing rather than to a
neighbouring object.

## What this closes

- Forging a handle to reach another object: refused by the generation (`440a`), and the
  one forged-handle surface that decodes at all - sys 532 (`433a`) - decodes into an empty
  table.
- Type confusion through the registry: refused by the type in the key (`445a`).
- Confusion across families: a handle from one family is refused by another's handlers
  (`347a`), and the shared free list does not share the type.

The remaining use is shaping: allocations are deterministic, so a future test can put N
objects of a chosen family in a chosen order at known slot numbers. That is recorded here
as the one capability this table does give.
