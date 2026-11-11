# Four route first-contacts: 604 EPERM, 572 silent, 656 EPERM, 560 inert

Measured 2026-11-05 (probe 1225a, fresh session pid 87) with the static follow-up for 560.

## 1. 604 dl_get_metadata - the identity tag is not 07

| call | result |
|---|---|
| `604(0,0,0,0,0)` | -1, EPERM 1 |
| `604(pid, buf, 0x100, 0, 0)` | -1, EPERM 1, buffer untouched |

The body gates on `[ctx+0x58] == 0x4800000000000007` (`0x609110`) after a companion test for
`...0006` (`0x609040`). EPERM on both shapes says this process's tag is **neither 06 nor 07**, so
the whole `dl_get_metadata` path is closed to us and 604 is only useful as a negative oracle.

## 2. 572 virtual_query - it answers, and writes nothing

Owned page at 0x311388000 (mmap RW). Five flag words, including the two that only pass under the
strict mask (`0x10000`, `0x10002`):

| flags | ret | first four output dwords |
|---|---|---|
| 0 | 0 | 0 0 0 0 |
| 1 | 0 | 0 0 0 0 |
| 2 | 0 | 0 0 0 0 |
| 0x10000 | 0 | 0 0 0 0 |
| 0x10002 | 0 | 0 0 0 0 |

So the handler accepts the (va, flags, out) layout and returns success, but every output byte stays
zero. Either the output argument is a different slot, or the lookup branch it takes for a plain
anonymous mapping has nothing to report. This corroborates the earlier "returns 0 with empty
buffers" dead-end entry rather than overturning it.

## 3. 656 dynlib_get_info_for_libdbg - the debug-unit predicates fail

`656(0, buf)` and `656(1, buf)` with `buf[0] = 0x160` both return -1 EPERM, and `buf[0]` is still
0x160 (the kernel did not write). The gate is `0xacce10() != 0 || 0xacce50() != 0`; both predicates
are false for this process, so **the debug unit is not visible** and 672/601-stage-two cannot open
from here. That is a clean answer to upstream's open item.

## 4. 560 debug_init - a real write-once store whose global has no readers

The body is 0x4F5E60, and both displacements resolve to the **same** global, 0x3543A5C:

```
4f5e64 mov ecx,[rsi]              ; uap[0]
4f5e66 mov edx,[rip+0x304dbf0]    ; -> 0x3543A5C
4f5e6c test edx,edx
4f5e6e je 0x4f5e7c                ; zero -> store
4f5e70 xor eax,eax ; 4f5e72 cmp edx,ecx ; 4f5e74 setne al ; 4f5e77 shl eax,4 ; ret
4f5e7c mov [rip+0x304dbda],ecx    ; -> 0x3543A5C   (the store)
4f5e82 xor eax,eax ; ret
```

| call | result |
|---|---|
| `560(0x41)` | 0 - first writer, value stored |
| `560(0x41)` again | 0 - matches |
| `560(0x42)` | -1, **EBUSY 16** - the mismatch answer |

So the store is real, write-once per boot, caller-chosen 32 bits, at a fixed kernel address. The
question that decides whether it is worth anything is who reads it. A full-image sweep
(5,343,048 instructions decoded, no chunking, rip-relative targets resolved arithmetically) finds
**thirteen** references within 16 bytes of that address and **exactly two** to 0x3543A5C itself -
the read and the write inside 560. Everything else touches neighbouring globals (0x3543A50,
0x3543A58, 0x3543A60, 0x3543A68).

**No instruction outside 560 reads the value 560 writes.** It is inert in the same way 643's
`or [proc+0xa34], mask` is inert: a real, unprivileged kernel write with no consumer. That closes
route R5 with a measurement instead of a guess.

## 5. Net effect on the route list

| route | state after this run |
|---|---|
| R5 560 debug_init | **CLOSED** - write works, nothing reads it |
| R7 656 libdbg | **CLOSED** - debug-unit predicates false, 672/601-stage-two unavailable |
| R8 572 virtual_query | alive but unproductive at five flag shapes; needs the correct out-slot |
| R9 604 dl_get_metadata | **CLOSED** - tag is not 06/07, EPERM on every shape |
| R1 blockpool | blocked on the installer; slots are a small consumable table |
