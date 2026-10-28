# Verification: KASLR_NOVEL_APPROACHES.md

**Date:** 2026-10-25
**Reviewed:** All 11 approaches in docs/KASLR_NOVEL_APPROACHES.md
**Method:** Cross-referenced claims against probe results, FINDINGS.md, CLAUDE.md dead ends, and FreeBSD semantics

---

## Issue 1: Approach #2 (sys 591 dynlib_dlsym) — Contradictory Rating

**Claim:** Rated ★★★ HIGH feasibility for KASLR defeat.
**Problem:** The document itself says (line 115): "the resolved address from 591 is a *userland* address, not a kernel VA. 591 resolves userland dynamic library symbols, not kernel symbols." Then it immediately rates it HIGH for *kernel* ASLR defeat.

**Verdict: RATING IS WRONG.** If 591 only resolves userland symbols, it cannot defeat kernel ASLR. The document acknowledges this but then keeps the HIGH rating on the basis that "it may resolve symbols from modules not visible in the 593 scan" and "the output address might point to a kernel trampoline." Both are speculative. Userland module bases are already available from sys 593.

**Corrected rating:** ★ LOW for KASLR defeat. Still worth a quick probe to confirm it resolves symbols at all (1 probe, low risk), but it does NOT defeat kernel ASLR unless there's a hidden kernel-resident module — which contradicts everything we know about the userland/kernel split.

---

## Issue 2: Approach #3 (AIO result word as implicit kptr) — Conflates 664 with raw memory read

**Claim:** "664's poll reads the `result` field from memory at a fixed offset. After reclaim by a different object, that offset may now contain [something useful]."
**Evidence from PROBE_RESULT_MINING_65_67.md (Finding #10, probe 67d):** "663/666/667 only return a 4-byte status dword — there is no wider data readback through these syscalls." And Finding #11: "663 vs 666 vs 667 ... None write data to the output buffer."

664 is not mentioned separately in the readback characterization, but the EXPLOIT_CHAIN_DESIGN.md (line 129) says: "664/663 status only." The AIO_13_60_ANALYSIS.md (line 177) says: "664/663 return per-item status words (32-bit Sony error codes), not raw object contents."

**Verdict: CLAIM IS MISLEADING.** 664 returns per-item status words from a lookup table, not from the freed memory. The "result field from memory at a fixed offset" phrasing implies a raw memory read, which is contradicted by all probe results (67a, 67d, 67m). The approach assumes 664 reads through the freed object's fields, but it reads through the AIO handle table.

**Corrected rating:** ★★ MEDIUM (downgraded from ★★★ MEDIUM-HIGH). The status dword IS read from somewhere, and in theory type confusion COULD corrupt it, but 67d's 64-overlap test produced zero status changes. The probability is low.

---

## Issue 3: Approach #5 (Zen 2 timing) — Already tried, unclear what's new

**Claim:** Rated ★★ MEDIUM.
**Problem:** The document acknowledges probes 56h-56i2 already tried mprotect timing with 2000 calls × 5 rounds and saw only scheduling noise. The "new" element is: (a) scan for `rdtsc` gadgets beyond `0F 31 C3`, and (b) use child thread ROP for native-speed timing.

**Verdict: RATING IS GENEROUS.** The core problem is that `mprotect` on kernel addresses returns 0 immediately (early return, no page table walk — probe 56k). No amount of timing precision will extract signal from a function that doesn't touch the page tables. The `rdtsc` gadget idea is technically new, but 18 hits of `0F 05` in 4.6MB of eboot with zero `syscall;ret` sequences suggests `0F 31` is equally sparse or absent.

**Corrected rating:** ★ LOW. The timing approach is dead because the kernel function being timed doesn't vary with the address. A `rdtsc` scan is still worth one probe (trivial, no risk), but shouldn't drive strategy.

---

## Issue 4: Approach #7 (thr_exit status as kptr carrier) — WRONG FreeBSD semantics

**Claim:** "When a child thread calls `thr_exit(status)`, FreeBSD copies the status to the parent's `child_tid` location."
**FreeBSD reality:** `thr_exit(long *state)` takes a **pointer to a long**. The kernel writes the integer `1` to `*state` via `suword()` — it does NOT copy a thread exit status. The parameter is an exit-notification pointer, not a status value. Existing probes confirm this: they use `thr_exit(exit_marker_addr)` and expect the kernel to write `1` there (e.g., probe 160f: `EXIT_A = shared + 0x10 -- thr_exit writes 1 here`).

Additionally, FreeBSD's `thr_exit` does NOT write anything to the `child_tid` field of `struct thr_param`. The `child_tid` pointer in `thr_param` is written by `thr_new` at thread creation time (the child's TID), not at exit time. There is no mechanism for `thr_exit` to deliver an arbitrary value to the parent.

**Verdict: APPROACH IS INVALID.** The proposed chain (call syscall → move return value to rdi → thr_exit writes it to parent) cannot work because `thr_exit` writes `1` to the supplied pointer, it does not copy `rdi` anywhere. The child CAN write an arbitrary value to shared memory via a `mov [rdi], rax; ret` gadget (already proven in 156d), but that's a userland write, not a kernel-mediated transfer.

**Corrected rating:** INVALID — remove from list. The underlying question ("can a child thread capture a kernel pointer from sysarch(GET_GSBASE=130)?") is still worth testing, but the delivery mechanism is a simple `mov [rdi], rax; ret` gadget, not thr_exit.

---

## Issue 5: Approach #10 (SCM_RIGHTS fd leak) — CONTRADICTS DEAD ENDS

**Claim:** "fd leak is confirmed (151d/151e)" rated ★ LOW-MEDIUM.
**CLAUDE.md dead end:** "SCM_RIGHTS — kernel strips fd passing in game jail (56q section B)"
**Finding 83 (FINDINGS.md):** "When receiving with `controllen=0`, the kernel installs the passed fds into the receiver's fd table anyway."

**Reconciliation:** Both are true but describe different things. 56q shows `controllen=0` on recvmsg — the cmsg data IS stripped from the receive buffer. But Finding 83 (151d/151e) shows the kernel still installs the fds into the receiver's fd table silently. So the "leak" is an fd-installation leak, not a data leak. The fds ARE functional, but they're fds the receiver already had access to (self-pass over socketpair).

**Verdict: APPROACH IS VIABLE BUT RATING IS ACCURATE.** The fd leak is real but:
- It doesn't provide any new fd types (self-pass gives you fds you already have)
- It can't surface kernel pointers (the fds are standard socket/file fds)
- It could shape the kernel heap via fd-table growth, but only weakly

**Corrected rating:** ★ LOW (downgraded from LOW-MEDIUM). The fd leak is an fd-exhaustion primitive, not a KASLR primitive. Useful only as an indirect heap-shaping tool for the double-free.

---

## Issue 6: Duplicate of Exhausted Approaches

**Approach #4 (sys 624 VM-op counter):** The "exhaustively ruled out" section lists "sys 624 side channel — no intra-kernel discrimination, all kernel addrs identical (56f)." Approach #4 acknowledges this but proposes using it as a "spray validation oracle" rather than a KASLR oracle. This is a legitimate distinction — 624 as a spray oracle is NOT the same as 624 as a KASLR oracle. No duplication.

**Approach #5 (Zen 2 timing):** Duplicates "Timing KASLR (mprotect batch + stability) — scheduling noise only (56h-56i2)" from the dead list. The document tries to distinguish by proposing native-speed child-thread timing, but the core problem (mprotect early-return) is the same. **Partial duplicate.**

**Approach #11 (AIO completion timing):** Not in the dead list but related to the timing approaches (56h-56i2). Uses a different mechanism (AIO completion vs mprotect) so not a direct duplicate, but faces the same `os.clock()` granularity problem. **Not a duplicate, but faces the same fatal constraint.**

---

## Corrected Feasibility Ratings

| # | Approach | Original | Corrected | Reason |
|---|----------|----------|-----------|--------|
| 1 | AIO double-free → reclaim → readback | ★★★ HIGH | ★★★ HIGH | Correct — this IS the path |
| 2 | sys 591 dynlib_dlsym | ★★★ HIGH | ★ LOW | Resolves userland symbols, not kernel |
| 3 | AIO result word type-punned read | ★★★ MED-HIGH | ★★ MEDIUM | 664 returns status from lookup table, not raw memory |
| 4 | sys 624 as spray oracle | ★★ MEDIUM | ★★ MEDIUM | Correct — legitimate use as validation |
| 5 | Zen 2 timing | ★★ MEDIUM | ★ LOW | mprotect early-return defeats any timing precision |
| 6 | Errno oracle | ★★ MEDIUM | ★★ MEDIUM | Untested, speculative but reasonable |
| 7 | thr_exit kptr carrier | ★★ MEDIUM | ✗ INVALID | FreeBSD thr_exit writes 1, not rdi |
| 8 | AIO UAF controlled write | ★★ MEDIUM | ★★ MEDIUM | Correct — legitimate approach |
| 9 | sys 599 dynlib relocation | ★ LOW-MED | ★ LOW-MED | Untested, high risk of crash |
| 10 | SCM_RIGHTS fd leak | ★ LOW-MED | ★ LOW | fd-exhaustion primitive, not KASLR |
| 11 | AIO completion timing | ★ LOW | ★ LOW | Correct — os.clock() too coarse |

## Summary

3 of 11 approaches have material errors:
- **#2 (sys 591):** Contradicts itself — acknowledges userland-only then rates HIGH for kernel ASLR
- **#7 (thr_exit):** Wrong FreeBSD semantics — thr_exit writes `1`, not the argument value
- **#10 (SCM_RIGHTS):** Overstated — the fd leak is real but the CLAUDE.md dead end is also correct

2 more are misleading:
- **#3 (result word):** Implies raw memory read, but 664 uses a lookup table
- **#5 (timing):** Acknowledged as tried, but doesn't address why it failed (early return)

The remaining 6 approaches are accurately rated. **Approach #1 (AIO readback through reclaim) remains the only HIGH-feasibility path**, consistent with the Lapse exploit's proven technique.
