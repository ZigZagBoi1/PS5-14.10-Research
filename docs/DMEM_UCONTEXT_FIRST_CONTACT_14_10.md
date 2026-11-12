# dmem container closed by priv_check; thr_self works; thr_get_ucontext rejects a raw buffer

Measured 2026-11-05 (probes 1226a, 1227a, 1227b; session pid 87).

## 1. R2 dmem_container(586) is refused by the privilege check

| call | result |
|---|---|
| `586(0xFFFFFFFF)` query form | rv = **1** (the "already set" predicate answers) |
| `586(0)` .. `586(4)` | -1, **EPERM 1** every index |

The body calls `priv_check(0x2ad)` at `0x3ce18f` before the table walk and the `proc+0x5c4` write
at `0x3ce1bd`. EPERM on all five indices means the check refuses this process, so the container
selector cannot be set and the route ends there. `559` (the `proc+0x5c0` sibling) carries the same
`priv_check(0x2ad)` at `0xabc551`, so R3 is closed by the same measurement without spending a run.

`628 mmap_dmem` without a container answers **EBUSY 16** for prot 3 and prot 0, and EINVAL for
prot 0x33 / 0x1002 (bits outside the 0x9fdf2f mask). That is the shape of a handler that got past its
argument checks and found no container, which is consistent with 586 having been refused.

## 2. thr_self(432) takes a pointer, and it works

`432(&tid)` returns 0 and writes **tid = 0x18D99 (101785)**. The earlier `432()` with no argument
returned -1/EFAULT because FreeBSD's `thr_self(long *id)` writes through the pointer.

## 3. thr_get_ucontext(634) refuses a raw buffer

| call | result |
|---|---|
| `634(-1, ctx)` | -1, **ESRCH 3** (bad tid) |
| `634(0x18D99, ctx)` with a 0x600-byte buffer preset to 0xA5A5A5A5 | -1, **EINVAL 22**, buffer untouched |
| `634(pid, ctx)` | -1, ESRCH 3 |

So the tid lookup is real (ESRCH versus EINVAL separates the two failures), but with a valid tid the
handler still rejects the call before copying anything. The second argument is therefore not a plain
buffer; it is validated against something the 0xA5A5A5A5 fill does not satisfy - most likely a size
or version field, the same pattern as `635 thr_set_ucontext`'s gates (`ctx+0x108 = 0x480`,
`ctx+0x0d0 <= 7`, `ctx+0x110 = 0x10000`). A follow-up should pre-fill the buffer with the 635-shaped
context that is known to be accepted and see whether 634 then copies.

## 4. dynlib records: 659 writes a header before failing

| call | result |
|---|---|
| `660(0, buf)` with `buf[0]=0x160` | -1, EINVAL, nothing written |
| `659(buf, 0x100)` | -1, EFAULT, **but the kernel wrote 0x00000000, 0x00000013, 0x00000014** at +0..+8 |

0x13 = 19 and 0x14 = 20 look like a module count and a capacity, written before the copy failed for
lack of room. A larger buffer is the obvious next call. Neither handler produced a supervisor-range
qword.

## 5. Route state after this batch

| route | state |
|---|---|
| R2 dmem container | **CLOSED** - `priv_check(0x2ad)` refuses 586 |
| R3 vm container (559) | **CLOSED by the same check** |
| R4 thr_get_ucontext | alive; tid obtained, needs the 635-shaped context instead of a raw buffer |
| R6 dynlib 659/660 | 659 needs a bigger buffer; 660 needs a valid id |
