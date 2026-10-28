# Finding 24: Session 4 Final Synthesis — Decompile-Verified Exploit State

> **Date:** 2026-10-25 Session 4
> **Method:** 11 verification agents + direct decompile analysis
> **Status:** 3 agents returned rich findings, 2 returned empty, 1 fork still running, 5 status unknown (pre-compaction)

---

## The One Thing That Changed Everything

**65l's "double deletes" are double-success, not double-frees.** This is now confirmed at decompile level across three independent analyses (doc 22, exploit-chain agent, and the convergence of Session 3's 10 agents).

### The Proof (sys_662.c lines 631-635)

```c
psVar6 = (short *)func_0x0039a2a0(uVar7, uVar18, 0x160, &local_68);
if (psVar6 == (short *)0x0) {
    local_d8[uVar14] = 0;    // status = SUCCESS
    goto LAB_003afcf3;        // skip entire free path
}
```

Thread A acquires exclusive lock, frees all sub-objects, deregisters handle, releases lock. Thread B then acquires exclusive, finds NULL (handle deregistered), writes status=0, skips. Both report success; only one actually freed.

### What This Means

The 65l race window IS real — the TOCTOU between lock release (line 628) and exclusive re-acquisition (line 631) exists. But the exclusive lock serializes the actual free+deregister, so a two-thread delete-only race cannot produce zone-level corruption.

**A real UAF requires three concurrent operations:**
```
Thread A: delete → acquire exclusive → free → deregister → release
Thread C: submit → handle slot recycled (LIFO, no generation check on 14.10)
Thread B: delete → acquire exclusive → finds NEW handle → frees LIVE object → UAF
```

---

## Verified Claims (Decompile Evidence)

| Claim | Verdict | Source |
|-------|---------|--------|
| entry_dispose: `lock xadd [*(I+0x40)+0x28], -1` | **CONFIRMED** | entry_dispose.asm.txt line 17: exact instruction at 0x3b3ec8 |
| I zone = 0x1ab5900 | **CONFIRMED** | entry_dispose.asm.txt line 24: `lea rsi, [rip+0x1701a0d]` → 0x1ab5900 |
| R zone = 0x1ab59e0 | **CONFIRMED** | sys_662.c line 649: `func_0x00c08df0(lVar5, 0x1ab59e0)` |
| Q zone = 0x1ab5970 | **CONFIRMED** | sys_662.c line 702: `func_0x00c08df0(uVar7, 0x1ab5970)` |
| A zone = 0x1ab5890 | **CONFIRMED** | sys_662.c line 705: `func_0x00c08df0(uVar7, 0x1ab5890)` |
| T zone = 0x1ab5a50 | **CONFIRMED** | sys_662.c line 708: `func_0x00c08df0(uVar7, 0x1ab5a50)` |
| D shares zone with T | **CONFIRMED** | sys_662.c line 710: `func_0x00c08df0(psVar6, 0x1ab5a50)` |
| 5 distinct zones (4 unique addresses) | **CONFIRMED** | 0x1ab5890, 0x1ab5900, 0x1ab5970, 0x1ab59e0, 0x1ab5a50 |
| Free order: R → I → Q → A → T → D | **CONFIRMED** | sys_662.c lines 649-710 |
| NULL re-lookup → status=0, skip free | **CONFIRMED** | sys_662.c lines 633-635 |
| Handle deregistration AFTER all frees | **CONFIRMED** | sys_662.c line 714 (func_0x00399e30) after frees at 649-710 |
| Submit-during-delete required for true UAF | **CONFIRMED** | Exclusive lock serializes delete; only handle recycling gives Thread B a live target |
| Per-type zone isolation | **CONFIRMED** | 5 objects freed to 4-5 distinct zones in one delete operation |

## Unverified/Contested Claims

| Claim | Status | Issue |
|-------|--------|-------|
| Object sizes (I=0x58, R=0x30, Q=0x58, A=0x30) | **INFERRED** | Derived from field offsets, not from allocation calls. Could be larger due to padding. |
| 14.20 adds generation revalidation | **UNVERIFIED** | No 14.20 binary in repo. Scene community claim only. |
| Controlling I+0x40 = clean arbitrary decrement | **PARTIALLY CONFIRMED** | Decrement is real, but refcount-zero path (old==1) triggers `func_0x72b380` cleanup — crash hazard on forged target. Doc omits this. |
| Lapse/Prolapse uses this exact bug | **UNVERIFIED** | Scene reporting, no source code analysis in repo. |
| Cross-subsystem spray is structurally dead | **CONFIRMED** | Per-type zones proven at source level. No two different subsystem objects share a zone. |

---

## Probe Audit Findings (68*.lua)

### Critical Issues
1. **Naming collision**: Three files share `68a` prefix (uaf_readback, gadget_catalog, zone_overlap) — result files will overwrite each other
2. **evf delete syscall mismatch**: 68a_aio_uaf_readback uses `mk(541)`, 68a_doublefree_zone_overlap uses `mk(539)` — one is wrong
3. **Missing fake TCB**: zone_overlap probe's child calls `read(3)` without sysarch(SET_FSBASE) — any failing syscall crashes the child
4. **uint64 violation**: gadget_catalog computes 64-bit address as plain Lua float instead of `uint64()`

### Systemic Issues (all 6 probes)
- `native.fcall_with_rax(stub, 20)` never pcall-wrapped
- `mk(5)` for `/dev/zero` open never pcall-wrapped
- `read_624()` function in oracle probe not pcall-wrapped (called ~50 times)

### CRASH_CLASS Corrections
- 68a_aio_uaf_readback: marked MODERATE, should be **HIGH** (section H follows stale pointer)

---

## Updated Priority Queue

### Tier 1: Blocking Questions (Must Answer First)

1. **Write submit-during-delete probe (68g)** — three coordinated child threads: delete-A, submit-C, delete-B. This is the ONLY path to a real UAF on 14.10. Timing is harder than 65l (three threads, not two). Detection: query C's new request via 663 after B frees it — should fail or return garbage.

2. **Test sys 665 with valid AIO IDs** — completely untested readback path. May return raw completion record data that bypasses the opaque 663/664 abstraction.

3. **Resolve evf delete syscall** — test both 539 and 541 empirically before running any evf-dependent probe.

### Tier 2: If Submit-During-Delete Works

4. **Identify which object to target** — the delete frees 5+N objects across 4 zones. The attacker must choose which specific zone to spray into. I (0x58, zone 0x1ab5900) is primary target because entry_dispose gives the atomic decrement primitive.

5. **AIO self-spray for reclaim** — submit new AIO requests to reclaim freed I objects in zone 0x1ab5900. Since AIO objects go to the SAME zone, this bypasses per-type isolation.

6. **KASLR defeat via I+0x40 readback** — if the reclaimed I object's +0x40 field contains a stale file pointer, and we can read it through a query interface, that's a direct kernel address leak.

### Tier 3: Probe Fixes Before Sending

7. **Rename 68a probes** to avoid collision (gadget scan → 68e, zone overlap → 68f)
8. **Add fake TCB** to zone overlap child thread
9. **Add pcall** to all unwrapped calls
10. **Fix uint64** in gadget scan

---

## What the 3 Other Agent Sessions Should Focus On

If the 3 other sessions are running 10 subagents each on the 2026-10-25 folder:

1. **Don't re-verify the decompile** — it's been verified 3 times now, the answer is conclusive
2. **DO write the submit-during-delete probe** — this is the critical next experiment
3. **DO investigate sys 665** — the untested readback gap
4. **DO trace func_0x0039a2a0** (descriptor_exclusive_lookup) to understand handle recycling behavior — specifically: after deregistration, does the next 669 submit immediately reuse the freed slot? What's the LIFO reuse latency?
5. **DO analyze the count>1 path** (sys_662.c lines 726-744) — when count>1, the handle is NOT deregistered but count is decremented. If Thread A decrements count from 2→1, and Thread B then finds count=1, Thread B enters the full deregister path on a partially-freed descriptor. This could be a different UAF vector that doesn't need submit-during-delete.
