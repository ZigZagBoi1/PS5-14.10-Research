# Handle addenda on 14.10: the wrap period, and containment across families

Status: measured (`96b`-`96f`). Two facts, both narrow.

The handle table itself is already documented: typed families shared by
`538`-`544`/`557` (192a-202a, 213a), 31-byte names (216a), `558` freeing by
handle (254a), and `generation << 13 | slot` with LIFO reuse across families
(437a, 438a). This note only adds the two things those did not measure.

## The generation field is three bits and wraps after eight reuses

`probes/phase17_new_vectors/96b_handle_generation_wrap.lua` creates and deletes
one name twenty times. Each create lands on the same slot and the generation
walks the full ring before repeating:

```
0x2206, 0x4206, 0x6206, 0x8206, 0xA206, 0xC206, 0xE206, 0x206, 0x2206, ...
```

(`slot = 0x206`, `generation = handle >> 13`, period 8.) The consequence is
that a stale handle becomes valid again after eight reuses of its slot - unlike
the aio ids, whose generation is also three bits (`docs/CHANGELOG.md`, `0x8ad59ee0`
compares `[entry+0x28] << 13`) but which are only handed out by a submit that
cannot be raced on this firmware.

`probes/phase17_new_vectors/96d_handle_allocator_order.lua` shows the allocator
is a LIFO free list: five creates take `0x207`-`0x20B`, and after deleting them
the next five take `0x20B, 0x20A, 0x209, 0x208, 0x207`. `96c` is the first
attempt, which assumed lowest-free-first and therefore missed the slot it meant
to reuse.

## A wrapped handle cannot be retargeted at another family

`probes/phase17_new_vectors/96e_handle_cross_family_use.lua` passes a live 557
handle to the aio entries: `664` returns `0` with element status `0x80020003`
(ESRCH), `663` returns `0` with the same element status, `662` returns `0` with
element ESRCH, and a following `558` still deletes the original object and
returns `0` - so the aio calls touched nothing. The reverse direction, `558` on
a live aio id, returns `-1`, while `662` frees it.

The slot number is only the lookup key; each handler validates the family of the
object it finds. A recycled slot can therefore alias a new object of its own
family and nothing else, which is what makes the eight-reuse wrap harmless
without a cross-family type confusion.

## aio delete ordering, measured in the same series

`probes/phase17_new_vectors/96f_aio_delete_semantics.lua`: after `669` submits,
`664` reports state `3`, and `662` returns element status `0` and the element is
gone (`664` then answers `0x80020003`). Deleting *before* any poll returns
element ESRCH and leaves the element alive at state 3, i.e. only a polled
completion is deletable.
