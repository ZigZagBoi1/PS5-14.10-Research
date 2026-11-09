# Finding 22: Session 4 Verification — Decompile-Level Evidence Audit

> **Date:** 2026-10-25 Session 4
> **Method:** Direct reading of 13.60 Ghidra decompile (`results/kernel_handlers/decompiled/sys_662.c`) and entry_dispose assembly (`evidence/2026-10-18-implementation-followup/aio-ownership/entry_dispose.asm.txt`)

---

## CRITICAL FINDING: 65l Produces Double-Success, Not Double-Free

### Evidence

The sys_662 decompile shows a clear serialization mechanism that prevents real double-frees:

**Lock sequence (lines 580-631 of sys_662.c):**
```
1. func_0x00399e20()     → acquire READ lock on descriptor D
2. Validate Q state (3 or 4), acquire Q lock (0x80000)
3. func_0x00bf1770(..., 0x100000) → release Q lock
4. func_0x00399eb0()     → release READ lock on D     ← TOCTOU window opens
5. func_0x0039a2a0(..., 0x160) → acquire EXCLUSIVE on D  ← TOCTOU window closes
```

**If func_0x0039a2a0 returns NULL (line 633-635):**
```c
if (psVar6 == (short *)0x0) {
    local_d8[uVar14] = 0;    // status = SUCCESS
    goto LAB_003afcf3;        // skip free path entirely
}
```

**Delete path when count==1 (lines 639-714):**
```
1. Free R to zone 0x1ab59e0 (line 649)
2. entry_dispose(I) = refcount decrement + free I to zone 0x1ab5900 (line 665/696)
3. Free Q to zone 0x1ab5970 (line 702)
4. Free A to zone 0x1ab5890 (line 705)
5. Free T to zone 0x1ab5a50 (line 708)
6. func_0x00399e30() → DEREGISTER handle (line 714)  ← handle removed from table
7. func_0x00399eb0() → release exclusive lock (line 718)
```

**Race outcome:**
- Thread A wins exclusive → frees all objects → deregisters handle → releases lock
- Thread B then acquires exclusive → func_0x0039a2a0 returns NULL (handle deregistered) → writes status=0 → skips free
- **Both threads report status=0 for the same ID, but only Thread A actually freed**

### Why 65l's 65/480 "doubles" are double-success

The probe checks `stateA[i] == 0 AND stateB[i] == 0` for the same ID. Both conditions CAN be true simultaneously because the NULL path at line 634 also writes 0. This is not a double-free — it's Thread B reporting success for an already-deleted object.

---

## Verified Claims (from 13.60 decompile)

### entry_dispose Atomic Decrement — CONFIRMED

Source: `entry_dispose.asm.txt` lines 13-17:
```asm
003b3eba: mov rax, qword ptr [rbx + 0x40]   ; rax = *(I + 0x40) = file object
003b3ec3: mov ecx, 0xffffffff                ; ecx = -1
003b3ec8: lock xadd dword ptr [rax + 0x28], ecx  ; atomic: *(file+0x28) -= 1
003b3ecd: cmp ecx, 1                          ; was old value 1?
003b3ed2: mov rdi, qword ptr [rbx + 0x40]    ; if last ref → call 0x72b380 (fdrop)
```

- **I+0x40 → file object**: CONFIRMED at asm line 13 (`[rbx + 0x40]`)
- **file+0x28 = refcount**: CONFIRMED at asm line 17 (`[rax + 0x28]`)
- **Atomic decrement via lock xadd**: CONFIRMED at asm line 17
- **fdrop on refcount=1→0**: CONFIRMED at asm lines 19-22 (call 0x72b380)

### Object Zones — CONFIRMED

| Object | Zone (claimed) | Evidence | Verdict |
|--------|---------------|----------|---------|
| I (queue entry) | 0x1ab5900 | entry_dispose tail-call: `lea rsi, [rip+0x1701a0d]` at 0x3b3eec → 0x1ab5900 | **CONFIRMED** |
| R (metadata) | 0x1ab59e0 | sys_662.c line 649: `func_0x00c08df0(lVar5, 0x1ab59e0)` | **CONFIRMED** |
| Q (completion) | 0x1ab5970 | sys_662.c line 702: `func_0x00c08df0(uVar7, 0x1ab5970)` | **CONFIRMED** |
| A (payload) | 0x1ab5890 | sys_662.c line 705: `func_0x00c08df0(uVar7, 0x1ab5890)` | **CONFIRMED** |
| T (ptr table) | 0x1ab5a50 | sys_662.c line 708: `func_0x00c08df0(uVar7, 0x1ab5a50)` | **CONFIRMED** |

All 5 zones are distinct addresses → per-type zone isolation confirmed at source level.

### Object Sizes — MIXED

| Object | Claimed Size | Evidence | Verdict |
|--------|-------------|----------|---------|
| I | 0x58 (88B) | NOT directly stated in decompile. Inferred from field offsets (last field at +0x50 = list links). | **INFERRED, not confirmed** |
| R | 0x30 (48B) | NOT directly stated. Inferred from zone allocation call not passing a size. | **INFERRED, not confirmed** |
| Q | 0x58 (88B) | NOT directly stated. Inferred from last field at +0x50. | **INFERRED, not confirmed** |
| A | 0x30 (48B) | NOT directly stated. Inferred from field offsets. | **INFERRED, not confirmed** |
| T | N×8 | Consistent with pointer table indexing in decompile. | **PLAUSIBLE** |

**None of the object sizes are directly confirmed from the decompile.** They are inferences from field offsets, which could undercount due to padding or trailing fields not accessed in this code path. The actual UMA zone allocation sizes would need either kernel symbols or dynamic measurement.

### Free Sequence — CONFIRMED (count==1 path)

| Order | Object | Decompile Line | Call |
|-------|--------|---------------|------|
| 1 | R | 649 | `func_0x00c08df0(lVar5, 0x1ab59e0)` |
| 2 | I | 665/696 | `func_0x003b3e90()` (entry_dispose) |
| 3 | Q lock | 691 | `func_0x00bf1760(puVar17 + 8)` |
| 4 | Q | 702 | `func_0x00c08df0(uVar7, 0x1ab5970)` |
| 5 | A | 705 | `func_0x00c08df0(uVar7, 0x1ab5890)` |
| 6 | T | 708 | `func_0x00c08df0(uVar7, 0x1ab5a50)` |
| 7 | D | 710 | `func_0x00c08df0(psVar6, 0x1ab5a50)` |

Note: D shares zone 0x1ab5a50 with T. This could mean they're same-type objects, or the decompile is using the same zone for both.

### I+0x40 → File Object — CONFIRMED

entry_dispose.asm.txt line 13: `mov rax, qword ptr [rbx + 0x40]` where rbx = I parameter.

### Handle Deregistration After Free — CONFIRMED

Line 714: `func_0x00399e30(uVar12, uVar18, uVar7)` occurs AFTER all frees (649-710), before lock release (718). This is why Thread B gets NULL.

---

## The Real Attack: Submit-During-Delete

Since the exclusive lock serializes delete operations, the only way to get a real UAF is:

```
Thread A: acquire exclusive → free objects → deregister handle → release lock
Thread C: submit new request → gets assigned SAME handle slot (recycled)
Thread B: acquire exclusive → finds NEW handle (non-NULL) → frees NEW live object → UAF!
```

On 14.10 (no generation revalidation), func_0x0039a2a0 returns the new handle because the slot number matches. The new handle points to live objects that are still in use. Thread B frees them → dangling pointers.

The 14.20 patch adds a generation counter: `func_0x0039a2a0` checks that the handle's generation matches the caller's expected generation. Since Thread B has the OLD generation and the handle slot now has a NEW generation, the lookup returns NULL even though the slot is occupied.

### 14.20 Patch — UNVERIFIED

No 14.20 binary or patch notes exist in this repository. The "generation revalidation" claim appears to be inferred from exploit community knowledge, not from repo evidence. **PLAUSIBLE but unsourced.**

---

## Corrections to Session 3 Documents

1. **Doc 15 (Object Hierarchy):** Object sizes are INFERRED, not confirmed. Should downgrade confidence from "HIGH" to "MEDIUM" for sizes.

2. **Doc 17 (Exploit Chain):** Correctly identifies the double-success issue. The submit-during-delete variant IS the right approach. However, it requires a three-thread race (delete A + submit C + delete B) which is harder to win than the two-thread 65l race.

3. **Doc 21 (Convergence Synthesis):** "Submit-during-delete #1 priority" is CONFIRMED correct by the decompile. The exclusive lock at func_0x0039a2a0 makes simple two-thread double-free impossible.

4. **Doc 18 (Probe Mining):** "65r disproves simple file refcount accumulation" is now explained — only one thread actually decrements the refcount per race, so 100 "double-frees" produce only 100 single decrements (not 200). The fd survives because it was never double-decremented.

5. **Doc 14 (Zone Isolation):** Per-type zones CONFIRMED at source level. All 5 freed objects go to distinct zones (except D and T sharing 0x1ab5a50).

---

## Priority Probe Design: Submit-During-Delete (68g)

The probe needs three coordinated child threads:

```
Thread A: 662(ids, N, statesA)  — starts deleting
Thread C: 669(cmd=1, ...)       — submits new request, reuses slot
Thread B: 662(ids, N, statesB)  — finds C's new handle, frees it
```

Timing is critical: C must submit AFTER A deregisters but BEFORE B acquires exclusive. This is a much tighter window than 65l's two-thread race.

Detection: If B frees C's new request, then:
- Querying C's request via 663 should fail or return garbage
- C's request's file refcount was decremented by B's entry_dispose
- The freed zone memory contains stale data from C's allocation

This is the path to real kernel corruption on 14.10.
