# Finding 16: Novel KASLR Defeat Approaches — Ranked After 38+ Dead Ends

> **Date:** 2026-10-25 Session 3
> **Agent:** kaslr-novel
> **Status:** 38+ classic approaches exhausted. These are the remaining candidates.

---

## Ranked Approaches

### Rank 1: File Refcount Double-Decrement -> fd UAF -> fstat Leak
**Feasibility: HIGH** | **Status: UNTESTED**

The entry_dispose `lock xadd [*(I+0x40)+0x28], -1` decrements the file object's refcount. Two frees = two decrements. If refcount hits zero, the fd table retains a dangling pointer to a freed `struct file` (~128 bytes, general-purpose zone).

**Chain:**
1. Open `/dev/zero` (fd=22), refcount ~2
2. Submit 1 AIO request on fd 22 (refcount +1 = ~3)
3. Double-free via 662 → refcount -2 = ~1
4. Close AIO reference → refcount -1 = 0 → file object freed
5. Spray 128-byte objects (kqueue knotes, setsockopt buffers) to reclaim
6. `fstat(189, fd22)` reads through reclaimed object → kernel pointer leak

**Why this bypasses the blocker:** fstat dereferences `file->f_vnode`/`file->f_data` directly — not through the opaque AIO query abstraction.

**Caveat:** Probe 65r showed 100 double-frees left fd alive. The exclusive lock may serialize actual frees, so only one refcount decrement occurs per race iteration. Needs careful refcount accounting.

---

### Rank 2: sys 665 `aio_get_data` With Valid IDs
**Feasibility: HIGH** | **Status: NEVER TESTED WITH VALID IDS**

665 kills on zeros but its name ("get_data") suggests raw per-request data readback. The 67a characterization tested 663/666/667 but **not 665**. If 665 copies completion record bytes to userland, it's the direct leak path.

**Probe:** `665(valid_id, outbuf, size)` for various arg layouts.

---

### Rank 3: 663 Mode Parameter Sweep
**Feasibility: MEDIUM-HIGH** | **Status: UNEXPLORED MODES**

The 13.60 handler for 663 takes a mode parameter (param_5). All existing probes used mode=0. Different modes may copy different fields — potentially raw tracking data with kernel pointers.

**Probe:** `663` with arg4=0..7, arg5=0..3, dump all output bytes per mode.

---

### Rank 4: rdtsc Gadget at Unaligned Offsets
**Feasibility: MEDIUM** | **Status: PARTIAL SEARCH DONE**

Probe 56s searched for `0F 31 C3` (rdtsc;ret) — zero hits. But `rdtsc` (0F 31) and `rdtscp` (0F 01 F9) may exist at unaligned offsets within other instructions. A child thread ROP chain with rdtsc gives **nanosecond** timing — 90,000x better than Lua's os.clock(). Could discriminate valid vs invalid kernel addresses via mprotect timing.

**Probe:** Scan eboot for `0F 31` and `0F 01 F9` at ALL alignments, build child ROP timing chain.

---

### Rank 5: Submit-During-Delete Handle Recycling
**Feasibility: MEDIUM** | **Status: NOT ATTEMPTED**

After Thread A frees and deregisters, if we submit a NEW request before Thread B's re-lookup, Thread B finds a NEW object at the recycled handle slot. Thread B then frees the new object's live sub-objects → UAF on active I/O. The new object's kernel pointers (from current thread, not old) are at known offsets.

**Chain:** Three allocation stages to create a slot where fresh kernel pointers survive into readable fields.

---

### Rank 6: errno Oracle Across Sony Syscalls
**Feasibility: MEDIUM** | **Status: UNTESTED**

Current probes check ret but not errno. With the fake TCB fix (384b), child threads can read errno at `%fs:0`. Sony handlers may return pointer-dependent error codes that leak information.

---

### Rank 7: Cross-Process Named Object Pollution
**Feasibility: LOW** | **Status: 342a showed objects don't outlive process**

Dead unless a handle type persists cross-process.

---

## Priority Action

**Test Ranks 1-3 before anything else.** They are untested, high-feasibility, and attack through interfaces we haven't tried (fstat, sys 665, 663 modes) rather than fighting the proven-opaque AIO query path.
