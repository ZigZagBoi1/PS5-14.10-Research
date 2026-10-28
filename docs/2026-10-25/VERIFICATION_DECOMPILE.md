# Decompile Claim Verification Report

**Date:** 2026-10-25
**Scope:** Verify claims from AIO forensics documents against the actual 13.60 Ghidra decompile and assembly.
**Sources checked:** `results/kernel_handlers/decompiled/sys_662.c`, `results/kernel_handlers/asm/sys_662.asm`, `evidence/2026-10-18-implementation-followup/aio-construction/`, `evidence/2026-10-18-implementation-followup/aio-ownership/`

---

## Summary Table

| # | Claim | Source Doc | Verdict | Evidence |
|---|-------|-----------|---------|----------|
| 1 | Five zone addresses exist in sys_662.c | All docs | **CONFIRMED** | Grep hits at alloc/free calls throughout |
| 2 | I=0x58, Q=0x58, R=0x30 allocation sizes | AIO_OBJECT_FORENSICS | **CONFIRMED** | Lines 2607, 2622/2636, 2559/2568 |
| 3 | entry_dispose XADD.LOCK at 0x3b3ec8 | AIO_OBJECT_FORENSICS, 13_FREED | **CONFIRMED** | asm line 4477: `XADD.LOCK dword ptr [RAX + 0x28], ECX` |
| 4 | TOCTOU window between lines 621-631 | AIO_13_60_ANALYSIS | **CONFIRMED** | Lock release at 621, exclusive re-acquire at 631 |
| 5 | R (0x30 bytes) contains kernel thread/process values | AIO_13_60_ANALYSIS | **CONFIRMED** | Lines 2607-2616: R+0x00 from GS:0x390, R+0x08 from GS:0x08 |
| 6 | Free order: R before I | AIO_OBJECT_FORENSICS | **CONFIRMED** | Line 649 frees R, line 696 calls entry_dispose(I) |
| 7 | I+0x10 obfuscated pointer `(val >> 4) ^ val` | AIO_OBJECT_FORENSICS, 05_AIO, 15_HIERARCHY | **CONFIRMED** | Lines 596, 1133, 1799, 2134 |
| 8 | Q waiter-list head at +0x50 | AIO_OBJECT_FORENSICS, 05_AIO, 13_FREED | **CONFIRMED** | Lines 1166-1167, 1213-1214, 1242-1243, 1449-1452 |
| 9 | Q lock at +0x20, ops 0x80000/0x100000 | AIO_OBJECT_FORENSICS, 05_AIO, 13_FREED | **CONFIRMED** | Lines 604/621, 1149/1262, 1447/1476 |
| 10 | D descriptor: D+0x10 payload, D+0x20 type, D+0x22 flag | 05_AIO, AIO_CONSTRUCTION | **CONFIRMED** | descriptor_publish.asm.txt: explicit mov instructions |
| 11 | 670 poisons 662 delete path | AIO_13_60_ANALYSIS, 13_FREED | **PARTIALLY CONFIRMED** | context+0x4a0 flag checked at line 510; mechanism imprecise |
| 12 | entry_dispose.asm.txt is standalone file | Task description (expected NOT to exist) | **EXISTS** | `evidence/.../aio-ownership/entry_dispose.asm.txt` (29 lines) |
| 13 | File refcount double-decrement at *(file+0x28) | AIO_OBJECT_FORENSICS, 13_FREED, 15_HIERARCHY | **CONFIRMED** | Lines 250-252, asm 0x3b3ec8; also inlined at 2769-2771 |
| 14 | Zone 0x1ab5890 = "Queue entry pointer array" (count*8) | AIO_13_60_ANALYSIS table | **INCORRECT** | 0x1ab5890 = copyin buffer (count*0x28); T is in 0x1ab5a50 |
| 15 | A (descriptor payload) in zone 0x1ab5890 | AIO_OBJECT_FORENSICS line 96 | **INCORRECT** | A is allocated from zone 0x1ab5a50 (line 2581) |
| 16 | A+0x20 = "descriptor copy from 0x1a7d800" | 15_OBJECT_HIERARCHY line 28 | **INCORRECT** | A+0x20 is from 0x1ab5890; 0x1a7d800 = temp context in 662 |
| 17 | R+0x10 credential-like reference zeroed before free | AIO_OBJECT_FORENSICS, 05_AIO | **CONFIRMED** | Lines 643-646: zero R+0x10 then free R |
| 18 | R+0x00 and R+0x08 contain kernel thread values | Implicit in all docs | **CONFIRMED but UNDER-DOCUMENTED** | Lines 2609-2610: from GS offsets, NOT zeroed before free |

---

## Detailed Evidence

### 1. I+0x10 Obfuscated Pointer (CONFIRMED)

Four independent code paths compute the same obfuscation on I+0x10:

```c
// sys_662.c line 596 (662 delete handler)
(long)*(ulong *)(lVar8 + 0x10) >> 4 ^ *(ulong *)(lVar8 + 0x10)

// sys_662.c line 1133 (663 wait handler, path A)
(long)*(ulong *)(lVar13 + 0x10) >> 4 ^ *(ulong *)(lVar13 + 0x10)

// sys_662.c line 1799 (663 wait handler, path B)
(long)*(ulong *)(lVar11 + 0x10) >> 4 ^ *(ulong *)(lVar11 + 0x10)

// sys_662.c line 2134 (another handler)
(long)*(ulong *)(lVar23 + 0x10) >> 4 ^ *(ulong *)(lVar23 + 0x10)
```

This is exactly `(val >> 4) ^ val` as claimed. The obfuscated value is written to the per-ID output status area.

### 2. Q Waiter-List Head at +0x50 (CONFIRMED)

Linked-list insertion pattern appears at multiple points:

```c
// sys_662.c lines 1166-1168 (wait handler, waiter registration)
plVar8[6] = *(long *)(local_130 + 0x50);    // new->next = Q->head
*(long **)(local_130 + 0x50) = plVar8;       // Q->head = new
plVar8[3] = local_130;                       // new->parent = Q
```

This is a standard singly-linked prepend. The pattern repeats at lines 1213-1215 and 1242-1244. Traversal and removal at lines 2317-2360 and 5799-5800 further confirm +0x50 as the list head.

### 3. Q Lock at +0x20 with lockmgr Operations (CONFIRMED)

Three independent code paths show the lock at Q+0x20:

**Path A (662 delete handler):**
```c
// Line 600: local_a8 = psVar1 + 0x10  (short* arithmetic: +0x10 * 2 = +0x20 bytes)
// Line 604: func_0x00bf1770(psVar1 + 0x10, 0x80000, ...)  // shared acquire at Q+0x20
// Line 617: psVar1 = local_a8  // psVar1 now = Q+0x20
// Line 621: func_0x00bf1770(psVar1, 0x100000, ...)  // exclusive release at Q+0x20
```

**Path B (663 wait handler):**
```c
// Line 1149: func_0x00bf1770(lVar13 + 0x20, 0x80000, ...)  // shared acquire
// Line 1447: func_0x00bf1770(lVar13 + 0x20, 0x80000, ...)  // shared acquire
// Line 1476: func_0x00bf1770(lVar13 + 0x20, 0x100000, ...)  // exclusive release
```

Operations confirmed: `0x80000` = shared/read acquire, `0x100000` = exclusive release. Both consistently target Q+0x20 bytes.

### 4. D Descriptor Layout (CONFIRMED)

`descriptor_publish.asm.txt` contains two variants of the same publish function:

```asm
; Function at 0x399de0
00399de4: mov word ptr [rdi + 0x20], si      ; D+0x20 = type word (arg2)
00399de8: mov qword ptr [rdi + 0x10], rdx    ; D+0x10 = payload A (arg3)
00399dec: mov qword ptr [rdi + 8], rcx       ; D+0x08 = context (arg4)
00399df0: mov word ptr [rdi + 0x22], 0       ; D+0x22 = flag (cleared)

; Variant at 0x399e00
00399e04: mov word ptr [rdi + 0x20], si      ; D+0x20 = type word
00399e08: mov qword ptr [rdi + 0x10], rdx    ; D+0x10 = payload A
00399e0c: mov qword ptr [rdi + 8], rcx       ; D+0x08 = context
00399e10: mov word ptr [rdi + 0x22], 1       ; D+0x22 = flag (set to 1)
```

The calling site in sys_662.c line 2650 passes type=0x160:
```c
func_0x00399de0(CONCAT44(uStack_6c,local_70), 0x160, puVar12, 0);
```

### 5. 670 Poison Mechanism (PARTIALLY CONFIRMED)

The 662 handler checks a context flag at offset +0x4a0:

```c
// sys_662.c line 510
if ((*(int *)(lVar8 + 0x4a0) == 1) || (iVar3 = adjacent_3b3410(1), iVar3 == 0))
```

The 670 init function also references this flag:
```c
// Line 3015 (inside __aio_init)
if (*(int *)(lVar10 + 0x4a0) != 1) goto LAB_003b2a0a;
```

The flag appears to control initialization state. However, the specific claim that "670 installs a different validation path that rejects deletes" is imprecise. The actual mechanism involves:
- A process-global context pointer selected at lines 480-509 based on AIO state
- The +0x4a0 flag marking whether initialization has run
- Configuration values at offsets +0x174, +0x184, +0x194, +0x1a4, +0x1b4, +0x1bc, +0x19c set by init

The probe observation that "after 670, all deletes return 0x80020010" is confirmed behaviorally. The exact mechanism by which init changes request processing to prevent state 3/4 from being reached (the prerequisite for deletion) cannot be determined from the 662 decompile alone without also analyzing the 669 submit handler under both init states.

### 6. entry_dispose.asm.txt File (EXISTS)

Contrary to the task expectation that the file does NOT exist as standalone, it DOES exist:

```
evidence/2026-10-18-implementation-followup/aio-ownership/entry_dispose.asm.txt
```

This is a 29-line extracted function body covering RVA 0x3b3e90-0x3b3efc. The function body IS ALSO embedded in sys_662.asm at lines 4472-4482 (the XADD.LOCK region). Both sources are consistent and contain the same instructions.

### 7. File Refcount Double-Decrement (CONFIRMED)

Three code paths confirm the pattern `lock xadd [*(I+0x40)+0x28], -1`:

**entry_dispose function (RVA 0x3b3e90):**
```c
// sys_662.c lines 250-252
piVar1 = (int *)(*(long *)(param_1 + 0x40) + 0x28);
iVar2 = *piVar1;
*piVar1 = *piVar1 + -1;
```

```asm
; sys_662.asm line 4477
0x3b3ec8: XADD.LOCK dword ptr [RAX + 0x28], ECX  ; ECX = 0xFFFFFFFF
```

**Inlined in construction cleanup (lines 2767-2771):**
```c
if (*(long *)(lVar10 + 0x40) != 0) {
    LOCK();
    piVar1 = (int *)(*(long *)(lVar10 + 0x40) + 0x28);
    iVar9 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
```

With diagnostic string confirmation at lines 2764-2765:
```c
func_0x0025d410("[0]%s() line=%d Warning !! split info is here\n",
                "free_queue_entry", 0xb35);
```

If the refcount reaches 1 before decrement, a release function is called (0x0072b380), which receives the file object and GS:[0] (current thread).

---

## Issues and Incorrect Claims

### Issue 1: Zone 0x1ab5890 Mislabeled in AIO_13_60_ANALYSIS

**Claimed (AIO_13_60_ANALYSIS line 48):**
```
| 0x1ab5890 | variable (count * 8) | Queue entry pointer array |
```

**Actual code (sys_662.c line 2551):**
```c
lVar21 = func_0x00c08b50(iVar7, 0x1ab5890, 0x102);
// where iVar7 = count * 0x28 — this is the copyin buffer for user request data
```

**Correct:** Zone 0x1ab5890 holds the copyin buffer (`count * 0x28` bytes), not the pointer table. The pointer table T (`count * 8` bytes) is allocated from zone 0x1ab5a50 at line 2583:
```c
uVar16 = func_0x00c08b50(local_c0 * 8, 0x1ab5a50, 0x102);
```

### Issue 2: A (Descriptor Payload) Zone Attribution Error

**Claimed (AIO_OBJECT_FORENSICS line 96):**
```
| A (descriptor payload) | ~0x30+ | 0x1ab5890 |
```

**Actual code (sys_662.c line 2581):**
```c
puVar12 = (undefined2 *)func_0x00c08b50(0x30, 0x1ab5a50, 0x102);
```

**Correct:** A is allocated from zone **0x1ab5a50**, not 0x1ab5890. The object freed to zone 0x1ab5890 in the deletion path (line 705) is the copyin buffer stored at A+0x20 bytes, not A itself. A itself is freed to zone 0x1ab5a50 at line 710.

### Issue 3: 15_OBJECT_HIERARCHY Zone/Size Error at A+0x20

**Claimed (15_OBJECT_HIERARCHY line 28):**
```
+-- +0x20 --> descriptor copy (from 0x1a7d800, count x 0x28 bytes)
```

**Actual:**
- A+0x20 points to the copyin buffer from zone **0x1ab5890** (`count * 0x28` bytes), not 0x1a7d800.
- Zone 0x1a7d800 is used for a **temporary per-ID context** (`count * 0x18` bytes) allocated inside the 662 delete handler at line 548:
```c
psVar6 = (short *)func_0x00c08b50(lVar8, 0x1a7d800, 0x102);
// where lVar8 = local_c8 * 0x18
```

### Issue 4: R+0x00 and R+0x08 Kernel Pointers Survive Free (Under-documented)

The documents correctly note that R+0x10 is zeroed before free (lines 643-646). However, they do not highlight that **R+0x00 and R+0x08 are NOT zeroed and still contain kernel values when R is freed**:

```c
// sys_662.c lines 2607-2610 (R allocation and initialization)
puVar13 = (undefined8 *)func_0x00c08b50(0x30, 0x1ab59e0, 0x102);
lVar10 = *in_GS_OFFSET;                           // GS:[0] = curthread
*puVar13 = *(undefined8 *)(lVar10 + 0x390);        // R+0x00 = curthread+0x390
puVar13[1] = *(undefined8 *)(lVar10 + 0x08);       // R+0x08 = curthread+0x08
```

The deletion path (lines 641-649) only checks and zeroes R+0x10:
```c
lVar5 = *(long *)(lVar8 + 0x18);              // lVar5 = R
if (lVar5 != 0) {
    if (*(long *)(lVar5 + 0x10) != 0) {       // only check +0x10
        func_0x002a9670();                     // release reference
        *(undefined8 *)(lVar5 + 0x10) = 0;    // zero +0x10
    }
    func_0x00c08df0(lVar5, 0x1ab59e0);        // free R — +0x00 and +0x08 intact
```

If the attacker can read back the 0x30-byte R object after double-free reclamation, **R+0x00 and R+0x08 contain stale kernel thread/process addresses** -- a potential KASLR defeat that the documents understate.

### Issue 5: 670 Poison Mechanism Description Is Imprecise

**Claimed (13_FREED_OBJECT_FORENSICS line 94):**
> "The initialization installs a different validation path that rejects deletes."

**Actual:** The mechanism involves a context initialization flag at `context+0x4a0` and context-pointer selection at 662 entry (lines 480-509). The flag does not directly reject deletes -- it determines whether `adjacent_3b3410(1)` is called to initialize the context. The most likely explanation for the observed "all deletes return 0x80020010" is that 670 changes how request state progression works, so requests never reach the terminal state 3/4 required by the deletion check at line 599:
```c
if (*(int *)(psVar1 + 4) - 3U < 2)  // requires Q+0x08 (byte) == 3 or 4
```

### Issue 6: AIO_13_60_ANALYSIS Omits Zone 0x1ab5a50 From Main Table

The zone allocation table (lines 46-52) lists five zones but omits 0x1ab5a50, which is used for:
- A (descriptor payload): 0x30 bytes (line 2581)
- T (pointer table): count * 8 bytes (line 2583)
- W (waiter array): count * 0x38 bytes (line 1080)

Later in the document (lines 72-75), the deletion frees mention 0x1ab5a50, but the main allocation table is incomplete.

---

## Correct Zone Map (From Decompile)

| Zone RVA | Alloc size | Object | Constructor line | Free line |
|----------|-----------|--------|-----------------|-----------|
| 0x1ab59e0 | 0x30 (48B) | R (request metadata) | 2607 | 649 |
| 0x1ab5900 | 0x58 (88B) | I (queue entry) | 2622/2636 | entry_dispose (696) |
| 0x1ab5970 | 0x58 or count*0x58 | Q (aggregate) | 2559/2568 | 702 (last-ref only) |
| 0x1ab5890 | count * 0x28 | Copyin buffer (user request data) | 2551 | 705 (last-ref only) |
| 0x1ab5a50 | 0x30 | A (descriptor payload) | 2581 | 710 (last-ref only) |
| 0x1ab5a50 | count * 8 | T (pointer table) | 2583 | 708 (last-ref only) |
| 0x1a7d800 | count * 0x18 | Temporary per-ID context (662 only) | 548 | 819 |

Note: Zone 0x1ab5a50 is shared by A, T, and W allocations of different sizes. The 662 handler also uses 0x1ab5a50 for waiter storage (line 1080: `count * 0x38`).

---

## Conclusion

Of 18 claims verified, **13 are fully confirmed**, **1 is partially confirmed** (670 mechanism), and **4 are incorrect or imprecise** (three zone attribution errors and an under-documented kernel pointer leak). The core exploitation-relevant claims -- object sizes, zone addresses, the TOCTOU window, the atomic decrement primitive, and the free order -- are all correct. The zone attribution errors in the secondary tables do not affect the exploit path (the double-freed objects R and I are correctly identified in all documents), but they would mislead heap-spray targeting if someone tried to spray into zone 0x1ab5890 expecting to reclaim a pointer table.
