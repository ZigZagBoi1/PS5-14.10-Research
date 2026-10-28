# Finding 23: Session 4 Probe Audit — 68*.lua Correctness Review

> **Date:** 2026-10-25 Session 4
> **Method:** Static analysis of all 68*.lua probes against Lua 5.1 constraints and project conventions

---

## Summary

6 probe files found matching `68*.lua`. **Zero Lua 5.1 violations** (no goto, no continue, no labels). All syscall numbers correct. All use `make_syscall` correctly. **Five systemic issues** and **one critical naming collision**.

## Per-Probe Results

### 1. 68a_aio_uaf_readback.lua (564 lines)
**Purpose:** UAF readback via 663 after cross-type spray
**CRASH_CLASS:** MODERATE (should be **HIGH** — section H follows stale pointer intentionally)
**Bugs:**
- Line 66: `native.fcall_with_rax(stub, 20)` not pcall-wrapped
- Line 94: `mk(5)` for `/dev/zero` not pcall-wrapped
- Line 549: evf delete uses `mk(541)` — **conflicts with 68a_doublefree_zone_overlap (uses mk(539))**

### 2. 68b_aio_spray_pipes.lua (551 lines)
**Purpose:** Double-free + sendmsg/setsockopt spray + readback
**CRASH_CLASS:** MODERATE — accurate
**Bugs:**
- Lines 66, 93: Unwrapped `native.fcall_with_rax` and `mk(5)`
- Line 329: cmsg_type `0x1234` is nonstandard but acceptable (kernel copies regardless)

### 3. 68c_aio_spray_setsockopt.lua (540 lines)
**Purpose:** Zone-size identification via setsockopt size sweep (16-128B)
**CRASH_CLASS:** MODERATE — accurate
**Bugs:**
- Lines 66, 93: Unwrapped calls (systemic)
- Line 308: `SO_LABEL=0x1009` almost certainly returns -1 on PS5 (design concern, not crash)

### 4. 68a_full_gadget_catalog.lua (196 lines)
**Purpose:** Full eboot ROP gadget scan
**CRASH_CLASS:** LOW — correct (read-only scan of RX pages)
**Bugs:**
- **Line 42**: `base = thi * 0x100000000 + tlo` computes 64-bit address as plain Lua number instead of `uint64()`. Should be `uint64(string.format("0x%X%08X", thi, tlo))` per CLAUDE.md.
- Line 27: Unwrapped `native.fcall_with_rax`

### 5. 68d_624_heap_oracle.lua (666 lines)
**Purpose:** Sys 624 VM-op counter characterization during AIO lifecycle
**CRASH_CLASS:** MODERATE — accurate
**Bugs:**
- Lines 70, 105: Unwrapped calls (systemic)
- **Line 101**: `read_624()` calls `mk(624)` outside pcall — called ~50 times, any failure kills probe

### 6. 68a_doublefree_zone_overlap.lua (848 lines)
**Purpose:** Zone corruption detection via accumulated double-frees
**CRASH_CLASS:** HIGH — accurate (most dangerous probe)
**Bugs:**
- **Lines 64-66**: `put_str` uses `memory.write_byte(p + i - 1, ...)` without `N(p)` wrapper. If `p` is a uint64 table, the `+` operator may not work correctly without the conversion helper. **Potential crash bug.**
- Line 828: evf delete uses `mk(539)` — **conflicts with 68a_aio_uaf_readback (uses mk(541))**
- **Lines 261-264**: Child thread executes syscall 3 (`read`) to wait on gate fd **without a fake TCB**. Per CLAUDE.md: child without TLS crashes on ANY failing syscall. If read fails, child crashes.
- Lines 291-300: thr_param doesn't set `child_tid` at +0x30 (safe but diverges from convention)

---

## Cross-Cutting Issues

### 1. CRITICAL: Naming Collision
Three files share the `68a` prefix:
- `68a_aio_uaf_readback.lua`
- `68a_full_gadget_catalog.lua`
- `68a_doublefree_zone_overlap.lua`

Result files will collide under `results/` (naming convention: `<probename>_<timestamp>.txt`).

### 2. evf Delete Syscall Mismatch
`68a_aio_uaf_readback` uses `mk(541)` for evf delete.
`68a_doublefree_zone_overlap` uses `mk(539)` for evf delete.
**One is wrong.** Needs empirical test with a known valid evf handle.

### 3. Systemic Unwrapped Calls
All 6 probes call `native.fcall_with_rax(stub, 20)` and `mk(5)` for `/dev/zero` without pcall. While getpid and open are unlikely to crash, project convention mandates pcall for all risky calls.

### 4. Missing Fake TCB
`68a_doublefree_zone_overlap` spawns a child that calls `read(3)` without first calling `sysarch(SET_FSBASE=129)`. Any failing syscall in that child will crash on `%fs:0` access for errno.

---

## Recommendations

1. **Rename probes** to avoid the 68a collision: gadget scan → 68e, zone overlap → 68f
2. **Resolve evf delete syscall**: test both 539 and 541 with `mk(N)(handle)` on a known evf
3. **Add pcall** around `native.fcall_with_rax` and initial `mk(5)` in all probes
4. **Add fake TCB** (sysarch preamble) to the child thread in 68a_doublefree_zone_overlap
5. **Fix uint64 in gadget scan**: use `uint64(string.format(...))` instead of float arithmetic
