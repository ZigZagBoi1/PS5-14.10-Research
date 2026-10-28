# Verification Report: KASLR Defeat Ranking (Finding 16)

> **Date:** 2026-10-25 Session 3 — Verification Pass
> **Scope:** Verify feasibility ratings for all 7 ranked approaches in 16_KASLR_NOVEL_RANKED.md
> **Verdict:** Two ratings are WRONG, one is materially incomplete, one is confirmed sound

---

## RANK 1: File Refcount Double-Decrement → fd UAF → fstat Leak
**Claimed: HIGH | Corrected: LOW-MEDIUM**

### Verification

**65r data (verified):** 50 rounds × 16 AIO per round = 800 AIO requests on the same fd. 100 "double success" reports accumulated. fd survived every round. Section D is the most damning: 50 rounds of repeated double-free on a single fd, 100 cumulative doubles, fd still alive.

**Why the refcount doesn't decrement:** The document's own caveat ("exclusive lock may serialize actual frees") is the answer. From the 13.60 decompile (Finding 15), `entry_dispose` runs AFTER the D exclusive lock is acquired. Thread A acquires the exclusive lock first, runs `entry_dispose` (which decrements the file refcount at `*(I+0x40)+0x28`), deregisters the handle, and releases the lock. Thread B then acquires the exclusive lock, but the handle lookup returns NULL (already deregistered) → Thread B reports success WITHOUT calling `entry_dispose`. So **only one refcount decrement occurs per race**, regardless of how many "double success" events are reported.

**fstat crash risk:** Even if the refcount COULD reach zero, calling `fstat` on a freed `struct file` would follow `file->f_ops->fo_stat()` — a function pointer dereference through freed memory. Without controlling the reclaimed object, this crashes, it doesn't leak. The ranking assumes fstat would cleanly read kernel pointers from the struct fields, but the first thing fstat does is call through a vtable pointer — if that pointer is garbage, the kernel panics.

**Corrected feasibility: LOW-MEDIUM.** The exclusive lock prevents refcount accumulation (proven by 65r with 100 doubles). Even if a submit-during-delete variant could cause a real double-decrement, fstat's vtable dereference makes it a crash, not a leak, without prior type confusion.

---

## RANK 2: sys 665 `aio_get_data` With Valid IDs
**Claimed: HIGH | Corrected: DEAD**

### Verification

**665 is ABSENT on 14.10.** Three independent sources confirm:

1. **SYSENT_PRESENCE_14_10.md line 658:** `| 665 | aio_get_data | - | kills |`
2. **AIO_RANGE_14_10_EVIDENCE.md §"First isolation sweep":** `665 | KILLED_IN_CALL | process terminated inside the call`
3. **AIO_RANGE_14_10_EVIDENCE.md §"Reinterpretation":** "661, 665 and 668 are therefore absent on 14.10 — 665 and 668 are labeled `nosys` stubs in the 13.60 capture, which agrees."
4. **SYSCALL_CONTRACTS_13_60.md line 150:** `| 665 | - | ignored_slots | - | - | - | disabled AIO entry routed to common unsupported-syscall handling |`

**665 was a nosys stub even in 13.60.** The 13.60 contracts describe it as "disabled AIO entry routed to common unsupported-syscall handling." It never had a real handler. It was never a "get_data" function — that name was an analytical label, not a confirmed function. On 14.10, calling it kills the process (absent slot behavior, same as syscall 4095).

**Valid IDs would not help.** The slot is absent. There is no handler to accept any arguments.

**Corrected feasibility: DEAD.** Remove from the ranking entirely.

---

## RANK 3: 663 Mode Parameter Sweep
**Claimed: MEDIUM-HIGH | Corrected: MEDIUM-HIGH (confirmed sound)**

### Verification

**The wait_mode parameter exists.** SYSCALL_CONTRACTS_13_60.md line 148 confirms: `| 663 | - | ids, count, states, wait_mode, timeout_inout | - | - | - | AIO batch wait |`. The fourth argument is `wait_mode`.

**All existing probes use wait_mode=0.** Every 663 call in phase16_kwrite passes `uint64(0)` as arg4 (or omits it, which defaults to 0). No probe has tested wait_mode=1, 2, or any other value.

**This is a genuine untested gap.** The 13.60 handler at RVA 0x3b01f0 takes 5 arguments. Different wait modes may trigger different code paths that copy different fields. This is worth testing.

**One concern:** 663 is `aio_multi_wait`, not `aio_multi_query`. Its purpose is to BLOCK until requests complete. Non-zero wait_mode values may change blocking behavior (e.g., wait for all vs wait for any), not what data is returned. The "states" output might still be the same 4-byte status dword regardless of mode.

**Corrected feasibility: MEDIUM-HIGH.** Rating is justified. Low cost to test, genuine gap, but the return format may be mode-independent.

---

## RANK 4: rdtsc Gadget at Unaligned Offsets
**Claimed: MEDIUM (partial search done) | Corrected: LOW-MEDIUM (search complete, no usable gadget)**

### Verification

**The document claims "Probe 56s searched for 0F 31 C3 — zero hits."** This is MISLEADING. The document implies 56s is the only search. In fact:

1. **56h (rdtsc gadget search)** — found 20 rdtsc (0F 31) hits in eboot at all alignments, 0 rdtscp hits. Found ONE apparent candidate: eboot+0x6A109 with "ret at +3 bytes."
2. **390c (gadget context)** — confirmed `rdtsc;ret (0F 31 C3): 0 hits`. Found the same eboot+0x6A109 with "ret at +3."
3. **390e (rdtsc function finder)** — found 44 rdtsc hits total, identified 7 containing functions, tested calling them via fcall_with_rax.

**The eboot+0x6A109 "rdtsc;ret" is a FALSE GADGET.** The bytes are `0F 31 C0 C3 48...`. The probe's parser found `C3` (ret opcode) 3 bytes after `0F 31` and called it "CALLABLE." But `C0` is the opcode for `Grp2 Eb,Ib` — it consumes `C3` as its ModR/M byte and needs one more byte as the immediate. The actual decode is:
```
0F 31       rdtsc
C0 C3 48    rol bl, 0x48
8D 51 01    lea edx, [rcx+1]
```
There is NO `ret` instruction. The `C3` byte is consumed by the `rol` instruction's ModR/M encoding. 56h even noted "(skipping call — huge rax would crash Lua stack)" — it never actually tested this gadget.

**390c was more rigorous** and searched for the exact 3-byte pattern `0F 31 C3` — correctly found 0 hits.

**390e found 7 functions containing rdtsc** and tried calling them via fcall_with_rax. The result file is corrupted (binary output), so the outcome is unknown. However, the key function at 0x19BBD0 shows `0F 31 C0 48 83 C4 20 5B 41 5C 41 5E 41 5F 5D C3` — rdtsc followed by `xor eax,eax` then stack cleanup and ret. This IS callable but `xor eax,eax` destroys the TSC value before it can be returned. The `eax` (containing TSC low bits) is zeroed. `edx` (containing TSC high bits) is not returned by the calling convention.

**Bottom line:** No usable rdtsc gadget exists in eboot. The entire 4.6MB .text was scanned across three probes. Zero `0F 31 C3` sequences. The one "near hit" at 0x6A109 is a false positive due to ModR/M encoding. Functions containing rdtsc exist but zero their return value.

**Corrected feasibility: LOW-MEDIUM.** The claim of "partial search" is wrong — the search is COMPLETE and negative. A child ROP chain could potentially be constructed to save edx:eax to memory before the function's cleanup code runs, but this requires finding the right jump-into-middle point, which is speculative.

---

## RANK 5: Submit-During-Delete Handle Recycling
**Claimed: MEDIUM | Assessment: MEDIUM-HIGH (should be ranked higher)**

### Verification

This is the approach that every other agent (1, 2, 4, 6, 9) independently ranked as the #1 priority. It's the mechanism that the 14.20 patch explicitly closes. The 65r result (100 doubles, fd alive) strongly suggests the current double-free pattern produces double-success-reporting but NOT double-frees at the zone level. Submit-during-delete is the path to a TRUE UAF.

**Should be ranked HIGHER than the current position.** It's the only approach that addresses the fundamental blocker (exclusive lock preventing double-free) rather than working around it.

---

## RANK 6: errno Oracle
**Claimed: MEDIUM | Assessment: MEDIUM (unchanged)**

No specific verification needed — it's genuinely untested and the reasoning is sound.

---

## RANK 7: Cross-Process Named Object
**Claimed: LOW | Assessment: DEAD**

342a proved objects don't outlive the process. Confirmed dead.

---

## Corrected Ranking

| Rank | Approach | Corrected Feasibility | Change |
|------|----------|----------------------|--------|
| **1** | **Submit-during-delete handle recycling** | **MEDIUM-HIGH** | ↑ from #5; the only approach addressing the fundamental blocker |
| **2** | **663 wait_mode parameter sweep** | **MEDIUM-HIGH** | ↑ from #3; confirmed genuine untested gap, low-cost probe |
| **3** | **errno oracle across Sony syscalls** | **MEDIUM** | ↑ from #6; untested, sound reasoning |
| **4** | **File refcount via fstat** | **LOW-MEDIUM** | ↓ from #1; 65r proves refcount doesn't accumulate; vtable crash risk |
| **5** | **rdtsc timing** | **LOW-MEDIUM** | ↓ from #4; search is COMPLETE, no usable gadget exists |
| ~~6~~ | ~~sys 665 aio_get_data~~ | **DEAD** | ~~was #2~~; 665 is absent on 14.10, was nosys even in 13.60 |
| ~~7~~ | ~~Cross-process named objects~~ | **DEAD** | Confirmed dead by 342a |

## Key Takeaway

**The document's top two approaches are both wrong.** #1 is contradicted by its own cited evidence (65r), and #2 is a dead syscall. The real priority is submit-during-delete (was buried at #5) and 663 mode sweep (correctly identified but underranked).
