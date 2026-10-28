# Finding 22: Missed Gaps and Improved Action Plan

> **Date:** 2026-10-25 Session 4
> **Task:** Find opportunities all 30 agents (sessions 1-3) missed; improve the action plan.

---

## Verified Gaps

### Gap A: AIO class parameter — NEVER VARIED

All 30+ AIO probes use `class=1`. The 669 contract accepts class 1-3, and **no probe has ever submitted with class=2 or class=3**. Different classes may:
- Allocate from different kernel zones (class-specific sub-object types)
- Use different completion paths (different fields populated in the status)
- Return different data through 663/664/666/667 readback
- Free different sub-objects in 662 (different double-free targets)

If class=2 or class=3 allocates from a zone that's shared with other subsystems, it bypasses the per-type zone isolation that killed cross-subsystem spray.

**Priority: HIGH** — one-line change in every existing probe. Test class=2 and class=3 with the full submit/poll/delete/readback lifecycle.

---

### Gap B: AIO write (cmd=2) — NEVER USED IN DOUBLE-FREE PROBES

All double-free probes use cmd=1 (read). The 669 contract supports cmd=2 (write). AIO writes may:
- Allocate different internal objects (write buffer vs read buffer)
- Store the source data pointer in different sub-object fields
- Use different locking discipline in the completion path (the TOCTOU may be wider or narrower)
- Make different fields visible through 663/664 readback

67k section E confirmed AIO read moves real data from a socketpair. AIO write to a socketpair would move data the other direction — potentially filling different completion record fields.

**Priority: HIGH** — complements the class parameter gap. Test `669(cmd=2, ...)` with socketpair fds.

---

### Gap C: UMTX_OP_ROBUST_LISTS (op 26) — ALL RETURNS -1 ON REAL 454

Session 1 Doc 08 claimed "oversized robust was ACCEPTED(!)" but this was from the WRONG SYSCALL (557, not 454). The actual 110a result on syscall 454 shows:
```
register size=24: rv=-1
oversized size=32: rv=-1
zero size=0: rv=-1
```
**All three returned -1.** The robust-lists path is dead on 14.10 via syscall 454. No further testing needed.

**Priority: NONE (DEAD)** — corrects a false positive from Session 1.

---

### Gap D: Device fd read/write/mmap beyond ioctl

The ioctl sweep tested command encoding across 34 nodes. But simple read()/write() on device fds was only tested on `/dev/zero`, `/dev/random`, `/dev/null`, `/dev/urandom`. Untested:

- `read(fd, buf, size)` on `/dev/gc`, `/dev/dce`, `/dev/gic`, `/dev/rng`, `/dev/bt`, `/dev/hid`, `/dev/camera`, `/dev/ajm`, `/dev/ajmi`, `/dev/notification0`, `/dev/usbctl`
- `write(fd, data, size)` on same set
- `mmap(addr, size, prot, MAP_SHARED, device_fd, offset)` on non-dmem devices

The GPU device fds (gc, dce) kill on read (376a, 380a), but `rng`, `gic`, `bt`, `hid`, `camera`, `notification*`, `usbctl` are untested for read/write. `/dev/rng` is particularly interesting — it's a cryptographic RNG that should produce output on read.

**Priority: MEDIUM** — unlikely to produce kernel pointers, but read() on `/dev/rng` vs `/dev/random` vs `/dev/urandom` might reveal whether rng is a Sony device with different internals. Write to notification devices might trigger kernel activity observable through 624.

---

### Gap E: sendfile with device fd sources

sendfile(393) works on shm fds (391d). Never tested with:
- Source = `/dev/urandom` fd, destination = socket (kernel copies from device vnode to socket)
- Source = `/dev/zero` fd, destination = socket
- Source = `/dev/rng` fd, destination = socket

sendfile is a zero-copy mechanism that may use a different kernel code path (vnode-to-socket vs file-to-socket). The kernel creates temporary `sf_buf` and `vm_page` objects during the transfer — different from normal read/write. If sendfile on a device fd triggers page allocation visible to 624, it expands the side-channel.

**Priority: LOW-MEDIUM** — worth a quick test but unlikely to produce a primitive.

---

### Gap F: Signal handling in child threads

Child threads created via thr_new(455) inherit the parent's signal disposition. Currently:
- SIGSYS is ignored (sigaction from 353a/353b)
- All other signals have default disposition

Untested:
- Can we install a signal handler (sigaction) that the child will use? If so, when the child's ROP chain faults, instead of dying it would jump to the handler — which could be set to a gadget that writes diagnostic info (like the faulting address) to a shared page.
- Does `sigaltstack` work for child threads? If the child's signal handler runs on an alternate stack we control, we get arbitrary code execution in the signal context (with register state from the fault).

This matters for exploitation: if the entry_dispose arbitrary decrement targets an unmapped address, the child gets SIGSEGV. With a signal handler, the child survives and reports whether the decrement hit a valid address — turning the arbitrary decrement into a **crash oracle for KASLR**.

**Priority: HIGH** — a signal handler in the child thread turns the entry_dispose arbitrary decrement into a safe KASLR oracle. If `*(addr+0x28)` is mapped → decrement succeeds, signal handler runs, child survives. If unmapped → SIGSEGV, handler catches, child writes 0 to shared page.

---

### Gap G: Kernel stack residue after thr_exit

When a child thread exits via `thr_exit(431)`, the kernel deallocates the thread's kernel stack. Questions:
1. Does the kernel zero the stack before deallocation? (FreeBSD 11 does NOT zero kernel stacks)
2. Is the kernel stack page returned to the page allocator or held in a per-CPU cache?
3. If we mmap MAP_FIXED at the same virtual address range, do we get the kernel stack's physical page?

This is NOT testable directly (kernel stacks are in kernel VA), but:
- The 624 VM-op counter might show a delta when a thread exits (kernel stack page deallocation = VM op)
- If kernel stacks are allocated from a zone, rapid thread create/exit could deplete that zone and force cross-zone reuse

**Priority: LOW** — speculative and hard to observe from userland.

---

### Gap H: mlock on GPU mmap pages

CLAUDE.md confirms mlock(203) returns 0 on heap pages. Untested on:
- GPU mmap pages (the `sc_mmap(477)` pages used for heap R/W)
- `/dev/zero` MAP_SHARED pages
- `/dev/dmem0` MAP_SHARED pages

If mlock works on GPU pages, it forces the kernel to wire the physical pages — which creates different vm_map_entry and pmap state than normal pages. This state difference might be observable through 624 or 547.

Probe 110a was prepared to test this but its "vm page manipulation" section either wasn't run or the result wasn't analyzed.

**Priority: LOW-MEDIUM** — check 110a results first.

---

### Gap I: recvmsg with large cmsg buffer and LOCAL_CREDS

Probe 56o tested SCM_CREDS and found clean 40-byte cmsgcred. But:
- Was the cmsg buffer checked for PADDING bytes between cmsgs? FreeBSD aligns cmsgs to `sizeof(long)` and the padding is NOT guaranteed zeroed.
- Was the full allocation (msg_controllen) checked for kernel stack residue, or just the cmsg data?
- Were multiple sends/receives done to see if different kernel stack frames leave different residue?

The 56o probe says "Zero kernel pointers in data or padding" which covers this. **No gap — already done.**

**Priority: NONE**

---

### Gap J: sys 591 dynlib_dlsym — ALREADY TESTED AND DEAD

Session 1 Doc 08 ranked this as Priority 1 ("NO authid gate, possible single-call KASLR defeat"). But the debug-settings Agent 1 already tested it: `dlsym(591)` returns error for ALL handles (0-50) and ALL symbol name formats (C names and NID hashes). The 13.60 "no gate" analysis was correct, but the handler still rejects all inputs from a game process — likely a different gate (process type check, not authid).

**Priority: NONE (DEAD)** — corrects Session 1's top recommendation.

---

### Gap K: sys 660 dynlib_get_info2 with real handles — STATUS UNCLEAR

Session 1 Doc 08 ranked this Priority 3. The ATTACK_SURFACE.md shows it was tested in the 601-660 sweep and returned -1 for zeros. But was it tested with REAL module handles (like the ones 593 accepts)?

**Priority: MEDIUM** — one quick probe. If 660 fills different fields than 593, it might include a kernel pointer 593 omits.

---

### Gap L: Triple child race (3 threads instead of 2)

All double-free probes use exactly 2 child threads. Three threads calling 662 concurrently on the same IDs increases:
- The TOCTOU window (more interleavings)
- The probability that one thread frees while another submits (the submit-during-delete pattern happens naturally)
- The probability of actual zone-level corruption (3 decrements instead of 2 on refcounts)

**Priority: MEDIUM** — easy to implement, increases pressure on the race window.

---

## Corrected Action Plan (Integrating New Gaps)

### Tier 1: Blocking Experiments (do FIRST)

| # | Probe | Gap | Rationale |
|---|-------|-----|-----------|
| 1 | **AIO class=2/3 lifecycle** | A | One-line change; if class 2/3 uses shared zones, it unlocks cross-spray |
| 2 | **AIO cmd=2 (write) double-free** | B | Write path may have wider TOCTOU or different readback fields |
| 3 | **Child signal handler as crash oracle** | F | Turns entry_dispose into safe KASLR brute-force |
| 4 | **68a zone overlap** | — | Existing: determines real double-free vs double-success |
| 5 | **sys 665 valid IDs** | — | Existing: untested readback path |
| 6 | **663 mode sweep** | — | Existing: unexplored parameters |

### Tier 2: Quick Tests (low effort, potentially high reward)

| # | Probe | Gap | Rationale |
|---|-------|-----|-----------|
| 7 | **sys 660 with real handles** | K | One probe; might fill kernel pointer field 593 doesn't |
| 8 | **Triple child race** | L | Easy variant of existing probes |
| 9 | **Device fd read/write sweep** | D | Quick loop over 34 fds with read()/write() |
| 10 | **sendfile with device fds** | E | Quick test: `/dev/urandom` → socket via sendfile |

### Tier 3: If Tier 1 Succeeds

| # | Probe | Rationale |
|---|-------|-----------|
| 11 | **Submit-during-delete** | If 68a confirms no zone corruption, this is the only path |
| 12 | **Heap spray with class=2/3 objects** | If class 2/3 shares zones |
| 13 | **entry_dispose + signal oracle KASLR sweep** | If child signal handler works |

### What To STOP

- Cross-subsystem spray with namedobj/EVF/kqueue/socketpair (proven dead by zone isolation)
- AIO 663/664/666/667 readback for raw memory (returns computed status, not memory)
- sys 591 dlsym (already tested and dead)
- UMTX robust-lists on 454 (all returned -1)
- More AIO read (cmd=1) probes with class=1 (saturated — vary cmd and class instead)

---

## Key Correction Log

| Session | Claim | Reality |
|---------|-------|---------|
| Session 1, Doc 08 | "sys 591 has NO authid gate — possible single-call KASLR defeat" | Tested by debug-settings agent: returns error for ALL handles 0-50 and all symbol formats. DEAD. |
| Session 1, Doc 08 | "UMTX ROBUST_LISTS op 26 oversized struct accepted" | That was syscall 557 (namedobj), not 454. Real 454 test (110a) returned -1 for all sizes. DEAD. |
| Session 3, Finding 16 | "File refcount double-decrement → fd UAF" ranked #1 | 65r showed 100 double-frees left fd alive. Exclusive lock may serialize, so refcount decrement may not accumulate. CONTESTED. |
| All sessions | Every AIO probe uses class=1, cmd=1 | class=2/3 and cmd=2 are completely untested. Major blind spot. |
