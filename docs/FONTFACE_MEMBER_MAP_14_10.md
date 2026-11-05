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
and the other fifteen untouched.

The first reading of that result, "the engine's allocation came from elsewhere", is
wrong, and the correction matters: the natural client table is
`zeroedMalloc(metadataSize + 8 x 8)` = **80 bytes** (`HashTable.h:1158`,
`minimumTableSize = 8`, `HashTraits.h:52`), a class this spray never requested. A
192-byte lane cannot take an 80-byte block, so the scan says nothing about whether
that allocation was reclaimed. Testing it needs a second lane: `p581` sprays
16 x 192 (the face) followed by 32 x 80 (the table) in the same window and scans
both.

`p581` runs that second lane and the answer is negative:

```
P581-SPRAY-16x192-32x80
P581-CHECK-RETURNED
P581-FACE-T90-b2-58_20938d0010000000-68_d0237e0010000000-rc_1   (0x10008d9320)
```

The face lane lands as always; none of the thirty-two 80-byte buffers receives a
byte. That is not a scheduling accident but the shape of the write: the table is
allocated *inside* `check()` (the consumption that also writes `+0x58`), so anything
sprayed before that call sits on the free list that the allocation then draws from —
it cannot be the block the engine hands to itself. Catching the table would need an
allocation made during the consumption, and there is no synchronous JavaScript hook
there.

The remaining way to make the engine use memory we own is to have `+0x58` in the
reclaimed face already point at a table we control, which is the same missing value:
an address of our own buffer. The 80-byte discovery changes which object that address
has to name, not whether we need one.

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

## Re-entry: the stale object is used exactly once

If the engine walked the freed face again after its first continuation, a page could
read the leaked `m_clients` pointer from the landing, write a derived value into the
same buffer and re-enter — a self-address inside one load. It does not.

`p578` armed `+0x68 = 1` in the landed buffer after the hit and called
`document.fonts.check()` again: the process survived. `p579` did the same with
`document.fonts.load()`: survived too. `p580` proves the poison went into the right
place, so the negative is not a wrong-buffer artefact:

```
P580-PRE-58_80088c0010000000   0x10008c0880   engine WeakHashSet impl
P580-PRE-68_a0147e0010000000   0x10007e14a0   engine WeakPtr impl
P580-POST-68_0100000000000000   poison written into that buffer
P580-ARMED-b2
P580-REENTRY-SURVIVED
```

The object is dereferenced once, inside the in-flight `load()` continuation, and
nothing a page does afterwards reaches it.

## Why a baked address cannot replace that

The obvious fallback is to bake an address from a previous load into the page. Three
consecutive landings in one warm process:

| load | `+0x58` | `+0x68` |
|---|---|---|
| 1 | `0x10008bc880` | `0x10007e14b0` |
| 2 | `0x10008c0880` | `0x10007e14a0` |
| 3 | `0x10008c48d0` | `0x10007e1320` |

`+0x58` moves by `0x4000` and then `0x4050`, so the drift per load is not a constant
and no fixed delta maps a previous load's pointer onto this load's chunk. A blind
sweep would need thousands of loads inside a 64 KiB page, one landing per load,
with a crash for every wrong guess.

So the disclosure stands and the next step needs an address from somewhere else.
