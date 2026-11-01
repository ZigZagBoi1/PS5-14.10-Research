# The freed CSSFontFace is really our chunk: a member map from poisoning

The reclaim was already measured (the engine writes two heap pointers into the buffer
that took the freed `CSSFontFace`). This experiment answers the next question: does
the engine *use* the object we built, and which of its members does the continuation
read?

Method: p565's single-arm trigger (free the face, drop the sheet reference, spray
16 x 192-byte buffers, call `document.fonts.check()`), with one 8-byte poison
(`0xDEADBEEF`) at a single offset of every buffer, and a hit scan 120 ms later.

Why a crash proves the reclaim: memory that we did *not* take still holds the freed
object's original, valid contents, so poisoning it cannot fault. A crash therefore
means the chunk was ours and the engine read the poisoned member.

| offset | outcome |
|---|---|
| `+0x18` | survives, `HIT-4` (engine wrote `+0x58`) |
| `+0x20` | survives, `HIT-4` |
| `+0x28` | dies in the continuation |
| `+0x30` | dies |
| `+0x38` | dies |
| `+0x40` | dies |
| `+0x48` | dies |
| `+0x50` | survives, `HIT-3` |

So the continuation dereferences whatever sits in the 0x28-0x48 run, and only
null-checks (or ignores) `+0x18`, `+0x20` and `+0x50`. That range is consistent with
a container laid out there — a pointer/size/capacity triple followed by a second
pointer — being walked after the getter returns.

Establishing this cost one guide reopen per offset: a death takes the guide with it.
A page that walked several offsets per load was tried and abandoned, because it died
at its first arm irrespective of offset, so its results were meaningless; every
number above comes from the single-arm page.

## What it means

- The engine uses the object we built. This is no longer an inference from a write;
  a poisoned member inside our chunk faults the engine.
- Five qwords of the object are attacker-controlled *and* dereferenced.
- It is still not an exploit: to turn this into a read or a call we need one address
  of memory we control, and the only addresses we have are engine objects the engine
  itself allocated. The next experiment is to place a leaked, valid pointer at
  `+0x28` and see whether the continuation survives — which would show the field is
  followed into engine memory rather than merely requiring a non-null value.

Probes (local only, not published): `results/webkit/corpus/uaf50_18.html`,
`uaf50_20.html`, `uaf54.html`.

## Following the pointer

The poison test says the engine reads `+0x28`, but not whether a *valid* address is
followed into memory. Two loads answer that, using `localStorage` to carry the leaked
value between them (the single-arm page is reliable, so each load runs exactly one
arm):

```
12:29:30  U55-LEAK-HIT-b3-p58-00000010008b8880-stored
12:31:04  U55-TEST-STAGED-00000010008b8880-AT-28
12:31:04  U55-TEST-CHECK-RETURNED
          (die)
```

A real, mapped heap pointer — the `WeakHashSetImpl` the engine itself allocated —
placed at `+0x28` kills the process just as `0xDEADBEEF` does. So the field is not
merely required to be non-null: the continuation follows it and dereferences what it
finds. The address was valid, the *contents* were the wrong type for whatever is
being walked there.

That is the shape of a container member, and it makes the next step concrete: point
`+0x28` at a buffer whose contents we choose. Doing that needs the address of that
buffer, which is the one value this chain has never produced.

## The engine's own allocation does not land in the spray

One route to a self-address would be to make the fresh `WeakHashSetImpl` that
`check()` allocates land in one of our other buffers: its address is the value the
engine writes at `+0x58`, so that buffer would then hold its own address.

`uaf56` scans every byte of all sixteen buffers 150 ms after the check:

```
U56-NZ-b3-n9-head-01000000000000000000000000000000
U56-SCAN-buffers_1_of_16
U56-ALIVE-600
```

Exactly one buffer non-zero — the face chunk, with the refcount and the two pointers —
and the other fifteen untouched. So the engine's allocation came from elsewhere and
this route to a self-address does not open by itself. It would need the spray to be
retimed or enlarged to sit on that allocation's free list as well.

## Controls: the write and the crash both require the free

Two pages, byte-identical to the reclaim page except that nothing is freed — the
sheet stays attached and the face stays registered.

**No free, no poison** (`uaf57`):

```
U57-CHECK-RETURNED
U57-RESOLVED
U57-SCAN-buffers_0_of_16
U57-ALIVE-600
```

Zero buffers touched, and the promise resolved normally. So the two pointers appear
only because the object was destroyed, not because a healthy `CSSFontFace` happened
to be allocated into the spray.

**No free, poison at `+0x28`** (`uaf58`): the process stayed alive (`U58-ALIVE-600`).
The byte counter in that run reports 16 of 16, but that is the poison counting
itself — the informative part is that an untouched poisoned buffer is harmless, so
the crash with a freed object comes from the engine reading the chunk, not from the
spray on its own.

Together with the offset table this makes the claim causal: the engine reads memory
we wrote only when it was first freed.

## `+0x68` is dereferenced, not counted

A PR on the repository models `+0x68` as `m_keyCount` (an integer count) and its
templates write `1` there to "force iteration" of `m_clients`. That was measured
rather than argued: the working page (`p565`'s stage 1, which reclaims on every load)
with one forge line added, scanning the *other* pointer so each load proves its own
reclaim, and liveness beacons to separate a death from a load where the getter never
fired.

| arm | forged field | loads | reached the engine-write beacon |
|---|---|---|---|
| A | `+0x68 = 0` | 14 | 8 |
| B | `+0x68 = 1` | 12 | 0 |
| D | `+0x58 = 1` | 4 | 0 |

Fisher exact, A vs B: p = 0.0019. Writing `1` at `+0x68` is exactly as fatal as
writing `1` at `+0x58`, the field already known to be a `WeakHashSet` impl pointer.
A field read as an integer count would not be dereferenced, so `+0x68` reads as a
pointer slot.

The limit of the result: a load can only be shaped in stage 1, where the leaked
address is not yet known, so the arms forge `0` and `1` blind. That separates
"dereferenced" from "ignored", not "must be a valid pointer" from "must be non-null".
Stage 2 — where a same-page leaked pointer would be available — never reclaims here
(`S2-b` = 0 across every log), so the stronger test is not reachable in that page.

Pages: `results/webkit/corpus/uaf63_0.html` (A), `uaf63_2.html` (`+0x68 = 0x41`),
`uaf63_4.html` (D), generated from `results/webkit/corpus/p565.html`.
