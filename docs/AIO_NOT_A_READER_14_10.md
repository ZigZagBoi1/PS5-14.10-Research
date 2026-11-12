# The aio copy paths are user-validated: cmd=2 is not a kernel reader

Measured 2026-11-05 (probes 1231b, 1232a) after recovering the live image base with the upstream
fault-code oracle (probe 1001a).

## 1. The live kernel image base, this boot

`1001a_kernel_map_sweep.lua` (upstream) ran 512 `thr_create` children, each with `RIP` set to a
candidate address, and the SIGSEGV chain wrote 0x80 bytes of the fault context per attempt. Parsing
`(ctx+0x130 >> 8) & 0xF` for each of the 512 steps:

* 50 mapped, 462 unmapped, 0 other;
* the 2 MB stub at `0xFFFFFFFF80000000`;
* **the image at `0xFFFFFFFF85000000` .. `0xFFFFFFFF8B000000`** - 49 steps, 98 MB.

So the current boot's kernel image base is **`0xFFFFFFFF85000000`**, and `spawned=512 failed=0
alive pid=80` confirms the sweep costs no relaunch.

## 2. aio cmd=2 copies from the caller's pointer

Probe 1231b, user source:

| step | result |
|---|---|
| `669(cmd=0x1002, reqs, 1, class=1, ids)` | 0, id 0x4205 |
| `664` | state **3** |
| `recvfrom(fd1, 32, MSG_DONTWAIT=0x80)` | **0x10 bytes**, and the payload is exactly the marker `40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F` |

So the write path really does read from the address in the request's `+0x10` slot and push it to the
descriptor. FreeBSD's `MSG_DONTWAIT` is 0x80; the earlier 0x40 (`MSG_WAITALL`) is what wedged 1231a.

## 3. The same call with a kernel source copies nothing

Probe 1232a, source = `0xFFFFFFFF85000000` and `0xFFFFFFFF85400000` (both mapped, per the sweep):

| step | result |
|---|---|
| `669(cmd=0x1002, ...)` | **0** - accepted |
| `664` | state **3** - "completed" |
| `recvfrom` | **-1 EAGAIN**, no bytes |

So the request is accepted, runs to completion, and delivers **zero bytes**: the copy rejected the
source. That is the behaviour of the user-range mask the corpus already documented for `copyin`
(`and rdi, 0x7fffffffffff` before the access): `0xFFFFFFFF85000000` becomes
`0x7FFFFFFF85000000`, an unmapped user address, and the copy faults into the "user pointer bad" path
instead of reading kernel memory.

**Conclusion: `aio_submit_cmd` is not a kernel reader.** Both directions go through the validated
user-copy helpers, so the source and destination must be user addresses. The idea is closed, cleanly,
without a panic.

## 4. What this leaves

With the base known and the user-copy paths validated, a reader has to come from a kernel
**dereference** of a pointer we can influence - not from a copy helper. The remaining leak-shaped
surface in the corpus is the OBJECT-sourced copyout set (`docs/INTERPROC_COPYOUT_SOURCES.md`): sites
that copy out of a kernel object field rather than a stack copy. Those are reachable candidates and
none of them has been called with real arguments.
