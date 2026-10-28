# Generation Check in descriptor_exclusive_lookup — Double-Free Structurally Prevented

**Date:** 2026-10-25 (Session 5)
**Source:** Direct analysis of `descriptor_exclusive_lookup.asm.txt` (RVA 0x0039a2a0)

## Discovery

`func_0x0039a2a0` (`descriptor_exclusive_lookup`) — called at sys_662.c line 631 during the delete re-acquisition step — **re-validates the full AIO ID including its generation counter**. This makes 662-vs-662 double-free structurally impossible.

## ID Format (from asm)

```
AIO ID = 16-bit value
  Bits 12..0 (0x1FFF mask): slot index (line 21: and ebx, 0x1fff)
  Bits 15..13: generation counter (reconstructed at line 63: shl eax, 0xd)
```

Note: This is a 3-bit generation (values 0-7), wrapping every 8 uses of the same slot.

## The Generation Re-Check (lines 62-67)

```asm
0039a36b: mov eax, [r13 + rcx + 0x28]    ; read stored generation from table entry
0039a370: shl eax, 0xd                     ; shift left by 13 (into generation position)
0039a373: movzx eax, ax                    ; mask to 16 bits
0039a376: or eax, ebx                      ; OR with slot index → reconstructed full ID
0039a378: cmp eax, r14d                    ; compare with caller's original ID
0039a37b: jne 0x39a413                     ; MISMATCH → return NULL
```

After the exclusive lock is acquired and the slot is looked up:
1. The stored generation at entry+0x28 is read
2. It's combined with the slot index to reconstruct the full ID
3. This reconstructed ID is compared with the caller's original ID
4. **If they don't match → function returns NULL → no free occurs**

## Impact on All Race Scenarios

### Two-thread 662 race (65l pattern)
```
Thread A: exclusive_lookup(ID_X) → generation=G, matches → free → generation bumps to G+1
Thread B: exclusive_lookup(ID_X) → generation=G+1, original has G → MISMATCH → NULL → status=0
```
**Result: double-SUCCESS, not double-FREE.** This explains 65l perfectly.

### Three-thread submit-during-delete
```
Thread A: delete(ID_X gen=G) → free → slot cleared, gen bumped to G+1
Thread C: submit → new ID_Y at same slot with gen=G+1
Thread B: exclusive_lookup(ID_X gen=G) → entry has gen=G+1 → MISMATCH → NULL
```
**Result: also just double-success.** Thread B never touches Thread C's object.

### Different IDs under same Q
```
Thread A: exclusive_lookup(ID_1 gen=G1) → match → free I_1, decrement Q count
Thread B: exclusive_lookup(ID_2 gen=G2) → match → free I_2, decrement Q count
```
This WORKS (both valid), but they're serialized by the D exclusive lock, so Q count decrements are sequential, not racy.

## Additional Checks in exclusive_lookup

After the generation check passes:
- **State check** (line 69): `entry+0x26 == 3` (must be in completed state)
- **Type check** (line 71-73): `entry+0x20 == 0x160` (AIO type tag)
- **Ownership CAS** (lines 76-95): writes curthread to `entry+0x18`, releases lock, does operation, re-acquires, verifies curthread still there. Retry loop if another thread overwrote.

## What This Means for Exploitation

**662-vs-662 races on same IDs CANNOT produce a double-free.** The generation check is a robust TOCTOU mitigation. All 65l "doubles" are double-success reports where Thread B found nothing to free.

The Lapse/Prolapse exploit IS this bug (confirmed by CVE match). So the actual vulnerability must be one of:
1. A race between 662 and a DIFFERENT syscall (669 submit, 663 wait, 664 poll) that accesses objects without the generation check
2. A race on the Q refcount when deleting DIFFERENT IDs under the same Q, exploiting a non-atomic count operation
3. A race in the 3-bit generation wrap-around (after 8 alloc/free cycles on the same slot, the generation wraps back to the original value)
4. A race in the `0xc4bb20` call at line 88 (between lock release at 83 and re-acquire at 93) where the entry is accessible without the exclusive lock
5. The vulnerability is in `entry_dispose` (0x3b3e90) rather than in the lookup path

### Generation Wrap-Around (Hypothesis #3)

The generation is only 3 bits (0-7). After 8 alloc/free cycles on the same slot, the generation wraps back. If an attacker:
1. Takes ID_X with generation G=0 (slot S)
2. Rapidly submits and deletes 8 more requests on slot S → generation wraps: 0→1→2→3→4→5→6→7→0
3. Now slot S has generation G=0 again
4. Calls 662 on the ORIGINAL ID_X → generation matches → free succeeds
5. But slot S now contains a DIFFERENT object (the one from cycle 8)
→ **FREE OF WRONG OBJECT = UAF**

This is the most promising hypothesis. It requires controlling 8 alloc/free cycles on a specific slot, which with LIFO reuse might be achievable.

### Lock Gap in exclusive_lookup (Hypothesis #4)

Lines 82-93: the exclusive lock is released, an operation is performed, and the lock is re-acquired. Between release and re-acquire, entry+0x18 holds curthread as a "reservation." Another thread could:
1. Enter exclusive_lookup for the same ID
2. Pass the generation check
3. Overwrite entry+0x18 with its own curthread
4. Thread 1's re-check at line 94 fails → retry

This is a liveness issue (retry loop), not a safety issue. The CAS ensures at most one thread succeeds per entry.

## Recommended Next Steps

1. **★ Test generation wrap-around** — submit and delete 8+ requests on the same slot, then try to delete the original ID. If deletion succeeds → confirmed UAF mechanism.
2. **Characterize slot reuse** — confirm LIFO reuse and measure whether the same slot is consistently reassigned.
3. **Check if 3-bit generation is correct** — the `movzx eax, ax` at line 64 masks to 16 bits. With `shl eax, 0xd` (shift by 13) and a 16-bit mask, the generation field is `(16-13) = 3 bits`. Verify this interpretation.
4. **Check 669's internal generation handling** — does submit increment the generation stored at entry+0x28? If so, 8 submits to the same slot wraps it.
