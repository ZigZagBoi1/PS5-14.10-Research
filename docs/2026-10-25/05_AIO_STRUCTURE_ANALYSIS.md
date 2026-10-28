# 13.60 AIO Kernel Structure Analysis

**Date:** 2026-10-25
**Source:** Agent 5 -- 13.60 AIO structure reverse engineering (max effort)

## The Double-Free Target: Sub-Object at I+0x18

From the 13.60 decompilation of the delete body (`record_notify_area.asm.txt`, `0x3afe63` onward), after acquiring an exclusive descriptor lock via `0x39a2a0`, the handler:

1. Reads indexed object I from the pointer table: `r12 = T[index]` at `0x3afea3`
2. Reads the sub-object pointer: `r14 = I+0x18` at `0x3afeb7`
3. If non-null, releases r14's own child at `r14+0x10` via `call 0x2a9670`, then zeros `r14+0x10`
4. **Frees r14 (the sub-object at I+0x18)** via `call 0xc08df0` at `0x3afee8` with zone pointer `[rip + 0x1705af8]`
5. Zeros `I+0x18` at `0x3afef5`
6. Then reads Q from `I+0x20` and conditionally frees it if its total-count field reaches zero

**Thread B reads the pointer in step 2 before thread A's zeroing write in step 5 lands**, so both threads pass step 2 with the same non-null pointer and both execute step 4.

**Confidence: HIGH** -- the instruction flow is unambiguous in the retained assembly.

## Object Hierarchy

The 13.60 construction code at `0x3b2348-0x3b2498` builds:

```
Descriptor (D) -- handle table entry
  └─ D+0x10: Payload (A) -- 0x30 bytes
       ├─ A+0x00: count
       ├─ A+0x10: Q backing
       └─ A+0x28: Table (T) -- count * 8 bytes
            └─ Indexed Object (I) -- >= 0x48 bytes
                 ├─ I+0x10: ptr
                 ├─ I+0x18: ★ SUB-OBJECT (double-freed target) ★
                 │    └─ +0x10: child pointer (released before free)
                 ├─ I+0x20: Aggregate Q -- 0x58 bytes
                 │    ├─ Q+0/4: counts
                 │    ├─ Q+8: state
                 │    ├─ Q+0xc/0xd: flags
                 │    ├─ Q+0x20: lock
                 │    └─ Q+0x50: waiter head
                 ├─ I+0x28: assertion field
                 └─ I+0x40: refcounted obj
```

**Confidence for hierarchy: HIGH** -- traced through construction, lookup, wait, and deletion assembly across 5 decoded files.

## Size of the Freed Object

Direct size evidence is incomplete. Known constraints:

- The sub-object has a field at `+0x10` (minimum 0x18 bytes)
- The `0xc08df0` free function receives a zone pointer, indicating UMA zone allocation
- The copyin helper at `0x3b3f10` copies `0x3c` (60) bytes from userspace per request
- The aggregate Q is explicitly 0x58 bytes, and per-element Q arrays stride by 0x58
- The allocator `0xc08b50` tests `r14` against a size threshold near 0x4000; objects below go through the small/zone path

**Best estimate: 0x40-0x80 bytes (64-128), most likely near 0x58 (88 bytes)**

Copyin of 0x3c bytes plus internal kernel bookkeeping (lock word, state, back-pointers) would land in this range. FreeBSD UMA zones for this size class are typically 64, 80, 96, or 128 bytes.

**Confidence: MEDIUM** -- inferred from field offsets and copyin size, not a directly observed allocation size argument.

## Allocator Identification

The free function `0xc08df0` and allocation function `0xc08b50` are the kernel's general allocator wrapper:
- `0xc08b50` checks bit 2 in flags for thread-safety
- ORs `0x100` for zero-fill
- Routes to UMA zone path (small objects) or large-page path via `0x43e080`
- Zone identified by pointer from `[rip + 0x1705af8]` (static global `uma_zone_t`)

All AIO objects are small, so they use **UMA zones**.

**Confidence: HIGH** for UMA zone; the zone identity pointer's offset cannot be verified on 14.10 without a kernel image.

## Kernel Pointers in the Freed Object

The freed sub-object contains at least one kernel pointer at `+0x10` (a child object pointer released during disposal).

After freeing, UMA zone slabs store a `next` freelist pointer in the first qword of the freed chunk. Therefore:

- **After double-free, the freed chunk on the UMA freelist contains kernel heap pointers in its freelist linkage.** If reclaimed with controlled data and then the freelist is inspected, a kernel address leaks.
- The `+0x10` field holds a kernel pointer during the object's live lifetime but gets zeroed before free in the normal path at `0x3afed6`.

**Confidence: HIGH** for freelist pointer presence; MEDIUM for +0x10 being useful (zeroed before free).

## Summary Table

| Claim | Confidence |
|-------|-----------|
| Double-freed object is the sub-object at I+0x18 | HIGH |
| Freed via UMA zone allocator | HIGH |
| Zone pointer at `[rip + 0x1705af8]` identifies the zone | HIGH |
| Object size 0x40-0x80 bytes | MEDIUM |
| Object contains kernel pointer at +0x10 during lifetime | HIGH |
| Freelist linkage leaks kernel heap address after free | HIGH |
| Same-zone AIO self-spray is the safest first test | HIGH |
| 13.60 analysis applies to 14.10 | MEDIUM |
