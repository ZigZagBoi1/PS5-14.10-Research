# Syscall 557 is a named-object creator — the "version dispatcher" was a handle

Status: measured (557a, 557b, 557c). This supersedes the open question in
`docs/SYSCALL_557_14_10_EVIDENCE.md`: the first argument of 557 is a pointer to
a name, not a version, and its return value is a handle, not a dispatch result.

## Why the old reading was wrong

46a/47a swept the first argument 0..255 and recorded "valid versions found:
256" with returns like `16901 (0x4205)`, `518 (0x206)`, `772 (0x304)`. Every
one of those numbers is handle-shaped, and they are exactly what this probe
gets from a plain create:

```
557(name_ptr) -> 16901 (0x4205)      first object
557(name_ptr) -> 518   (0x206)      second object, same name
```

The sweep was creating 256 objects, one per "version".

## What the arguments are

```
557(ptr, 0, 0, 0)        -> handle      create, name at ptr
557(ptr, 0x1000, 0, 0)   -> handle      flags accepted
557(ptr, 1, 0, 0)        -> handle
557(0, ptr, 0, 0)        -> -1          the name pointer must be argument 1
557(0, 0, ptr, 0)        -> -1
557(0..8, struct)        -> -1          (46a/47a called these "versions")
```

A zeroed 0x200-byte struct works as a name: offset 0 is the string and an empty
string is legal. The pointer must be readable, and only argument 1 is used.

## What deletes it

```
558(handle)        -> 0     deletes
558(handle, 0)     -> -1
558(handle, 1)     -> -1
558(0, handle)     -> -1
558(handle,0x1000) -> -1
558(0x1000,handle) -> -1
550(handle)        -> -1    semaphore delete refuses it
552(handle)        -> -1
539(handle)        -> -1    event flag delete refuses it
```

So `558(handle)` is a one-argument generic delete that accepts only objects made
by 557; the typed deletes of the other families refuse them (88b).

## The name is not a retained user pointer

557b created an object whose name lived in a page it then unmapped, and died -
but its next statement was the probe's own `memory.read_byte` on the unmapped
page, which this loader cannot survive, so that death is not the kernel's.

557c removed that read and repeated the sequence (pid 116):

```
[1] p=0x310F30000   create ret=16901 (0x4205)
[2] munmap(p) ret=0     (p is never read from userland again)
[3] second create with the same name from a different page -> 518, process alive
[4] 558(16901) -> 0,  558(518) -> 0,  process alive
```

A second create with the same name, and the delete of the object whose name page
was gone, both completed without a fault. The name is therefore copied on
create (or not retained at all); there is no dangling user pointer to reclaim.

## Handles

Same table as event flags and semaphores (88b), so the three families share one
numbering. The value carries a generation in the high bits: after a delete the
same slot is handed out again with a different upper part (`0x213` -> `0x2213`
-> `0x4213` across reuses in 557a, `0x20F` -> `0x220F` in 88b), and a stale
handle is refused.

## Still open

- What the named object is *for*: nothing in this session operated on one
  besides 558. A lookup-by-name from another handle (the shape `551(name)` has
  for semaphores) has not been found for it.
- The second field of 557 (flags: `0`, `1`, `0x1000` all accepted) changes
  nothing observable here.
