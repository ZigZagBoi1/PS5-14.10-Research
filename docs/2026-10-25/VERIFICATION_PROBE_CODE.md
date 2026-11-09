# Probe Code Verification Report -- 2026-10-25

Reviewed against CLAUDE.md coding standards: CRASH_CLASS header, standard helpers,
Lua 5.1 compliance, no hardcoded addresses, correct make_syscall, no XO page reads,
and double-free race pattern correctness.

---

## 68*.lua Probes (Full Review -- 6 files)

Note: three files share the name prefix `68a_` with different suffixes. This is a
naming collision and should be resolved to avoid confusion with `send_probe.py`.

### 68a_aio_uaf_readback.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE -- accurate for cross-type spray after double-free |
| Standard helpers | WARNING | Uses renamed helpers (`N`, `mk`, `rd`, `rq`, `wd`, `wq`, `get_hi_lo`). Functionally equivalent but names differ from template (`to_num`, `make_syscall`, `safe_rd`, etc.). Missing `safe_wq` return value (uses void pcall). |
| Lua 5.1 compliance | OK | No goto/labels, uint64 for addresses, pcall around risky ops |
| No hardcoded addresses | OK | All addresses derived from `dynlib_get_info(593)` + eboot offsets |
| make_syscall pattern | OK | Correct table copy + metatable transfer |
| No XO page reads | OK | Only reads eboot (RX) and heap memory |
| Double-free pattern | OK | Individual 669 submits (count=1), poll via 664 before delete, NO 670 call |
| **Would it work?** | **YES** | Functionally correct. |

**Issues:**
- (info) Helper names diverge from template convention -- not a functional problem
- (info) `wd`/`wq` discard pcall return value -- silently swallows write failures

---

### 68a_full_gadget_catalog.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | LOW -- read-only scan of eboot .text (RX), no kernel interaction |
| Standard helpers | WARNING | Minimal subset: only `N`, `mk`, `rd`, `wd`. Missing `rq`, `wq`, `get_hi_lo`, `safe_wq`. Acceptable for a read-only scan probe. |
| Lua 5.1 compliance | OK | No goto/labels, clean arithmetic bit extraction |
| No hardcoded addresses | OK | Base from `dynlib_get_info(593)`, text size from struct or fallback 0x494000 |
| make_syscall pattern | OK | Correct |
| No XO page reads | OK | Scans eboot .text which is RX, not XO |
| Double-free pattern | N/A | Not an AIO race probe |
| **Would it work?** | **YES** | Well-structured gadget scanner. |

**Issues:**
- (info) `collectgarbage("collect")` every 256KB is good practice for large scans
- (info) Naming collision with 68a_aio_uaf_readback.lua and 68a_doublefree_zone_overlap.lua

---

### 68a_doublefree_zone_overlap.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | HIGH -- deliberate kernel double-free exploitation with stale-pointer access |
| Standard helpers | WARNING | Same renamed pattern as other 68* probes. Functionally equivalent. |
| Lua 5.1 compliance | CRITICAL | **Line 66**: `put_str` calls `memory.write_byte(p + i - 1, ...)` where `p` is a userdata (from `memory.alloc`), NOT wrapped in `N(p)`. This passes a raw userdata to arithmetic, which may work if the Lua runtime coerces it, but is inconsistent with the pattern used everywhere else (`N(p) + offset`). Same issue at line 68. |
| No hardcoded addresses | OK | All derived from runtime |
| make_syscall pattern | OK | Correct |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669 submits, 664 poll before 662 delete, NO 670 init |
| **Would it work?** | **LIKELY YES** | The `put_str` arithmetic-on-userdata issue may work due to Lua coercion but is technically incorrect per the template pattern. The gated race with socketpair read() for synchronization is well-designed. |

**Issues:**
- (critical) `put_str` uses `p + i - 1` and `p + #s` where `p` is raw userdata -- should be `N(p) + i - 1` and `N(p) + #s`
- (warning) Missing `thr_param.child_tid` field at `+0x30` in some param structs (lines 291-301, 569-579) -- may cause child TID not to be written but does not prevent thread creation
- (info) Naming collision -- third file with `68a_` prefix

---

### 68b_aio_spray_pipes.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE -- sendmsg/setsockopt spray after double-free |
| Standard helpers | OK | Same renamed-but-equivalent pattern |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | All runtime-derived |
| make_syscall pattern | OK | Correct |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669, poll before delete, no 670 |
| **Would it work?** | **YES** | Comprehensive cross-type spray approach with sendmsg cmsg, IP_OPTIONS setsockopt, and getsockopt readback. |

**Issues:**
- (info) `cmsg_type = 0x1234` is an arbitrary/unknown type -- kernel may reject the cmsg silently without allocating. `SCM_TIMESTAMP` (0x02) or a known type would be more reliable for forcing kernel allocation.
- (info) IP_OPTIONS max is 44 bytes (MAX_IPOPTLEN) but sizes 48 is also tried -- will be rejected, which is handled gracefully.

---

### 68c_aio_spray_setsockopt.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE |
| Standard helpers | OK | Same renamed pattern |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669, poll before delete, no 670 |
| **Would it work?** | **YES** | Systematic size sweep is a sound approach. |

**Issues:**
- (warning) `SO_LABEL` (0x1009) is a MAC framework option -- likely returns -1 on PS5 without TrustedBSD MAC. The probe handles this gracefully but the allocation will not happen.
- (info) `/dev/rng` in section E may not exist on PS5 -- `open` failure is handled via `fd_rng >= 0` check.

---

### 68d_624_heap_oracle.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE -- measures sys 624 VM-op counter during AIO operations |
| Standard helpers | OK | Same pattern, includes `fmt` formatter |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669, poll before delete, no 670. Race section [C] uses proper two-child pattern. |
| **Would it work?** | **YES** | Excellent diagnostic probe. Well-structured timeline measurement with clear labels. |

**Issues:**
- (info) `submit_one()` sets `cmd=1` (read) at line 117 unlike other probes that use `cmd=0` -- both are valid but worth noting for consistency.
- (info) Section [F] mmap verification uses `uint64(0xFFFFFFFF)` for fd argument -- this is the correct -1 sentinel for anonymous mmap.

---

## 65-67*.lua Probes (Spot-Check -- 5 files)

### 65d_aio_multi_delete_race.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | HIGH -- first TOCTOU race probe |
| Standard helpers | OK | Full set with correct implementations |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | All runtime-derived |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | CRITICAL | **Calls 670 (AIO init) at line 108.** CLAUDE.md explicitly states the confirmed double-free pattern requires "NO 670 init (poisons delete path)." This probe was an early iteration before the correct pattern was discovered in 65l. |
| **Would it work?** | **NO** | The 670 call poisons the delete path. This is the known-bad pattern documented in CLAUDE.md. The probe was superseded by 65l. |

**Issues:**
- (critical) Calls `mk(670)()` at line 108 -- documented as breaking the double-free
- (warning) Uses single-ID race (main thread vs one child) rather than the confirmed two-child batch pattern
- (warning) Includes `sysarch(SET_FSBASE)` in child ROP but 662 works without it (per CLAUDE.md: "662 works without sysarch (no errno touch)")
- (info) This is a historical probe -- the issues were identified and fixed in subsequent iterations (65e through 65l)

---

### 65l_aio_race_fixed.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | HIGH -- the confirmed double-free probe |
| Standard helpers | OK | Correct implementations |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669 (count=1), poll via 664 before delete, NO 670 call. This is the confirmed working pattern. |
| **Would it work?** | **YES** | This is the reference implementation that confirmed the double-free (65/480 IDs, 26/30 iters). |

**Issues:**
- (info) No `sysarch(SET_FSBASE)` in child -- correct per finding that 662 does not touch errno
- (info) No signal masking for SIGPIPE (13) -- not needed since 662 does not involve pipes, but other probes include it defensively

---

### 66e_aio_evf_overlap.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE |
| Standard helpers | WARNING | Missing `rq` (uses `rq` indirectly via other patterns). Has non-standard `w64` helper. |
| Lua 5.1 compliance | WARNING | Line 81: `wq(uint64(N(sa) + 16), uint64(0))` wraps the address in `uint64()` before passing to `wq`. This is inconsistent -- `wq` expects a plain number address (see its implementation: `memory.write_qword(a, v)`). The `uint64()` wrapping may cause the address to be treated as a userdata object rather than a number, potentially failing silently. Same issue at line 109: `wq(uint64(N(reqs) + 8), uint64(16))`. |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | WARNING | Uses single 662 call from main + one child thread, rather than the confirmed two-child pattern. The child thread uses `sysarch(SET_FSBASE)` which is unnecessary for 662 but harmless. |
| **Would it work?** | **LIKELY YES** | The `uint64()` wrapping on addresses may cause issues depending on how `memory.write_qword` handles userdata vs number for the address parameter. Core logic is sound. |

**Issues:**
- (warning) `wq(uint64(addr), val)` pattern at lines 81, 109 -- address should be plain number, not uint64-wrapped
- (warning) Single main+child race pattern rather than confirmed two-child pattern
- (info) `put_str` uses `N(p) + i - 1` correctly (unlike 68a_doublefree_zone_overlap.lua)
- (info) Child ROP chain has incorrect ordering: pushes `uint64(165)` (sysarch number) to stack first, then sets up registers -- the `pop_rax` for sysarch number should come from the stack, but the chain starts with the raw value 165 pushed before `pop_rdi_ret`. This ROP chain structure is non-standard and may not execute correctly.

---

### 67d_synced_race.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | MODERATE |
| Standard helpers | OK | Correct implementations (renamed but equivalent) |
| Lua 5.1 compliance | OK | No violations |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | OK | Individual 669, poll before delete, no 670. Uses nanosleep synchronization for tighter race timing. |
| **Would it work?** | **YES** | Well-designed with nanosleep sync, variable sleep duration sweep, and overlap oracle. |

**Issues:**
- (info) `query_663` passes 5 arguments to syscall 663 (line 109: `uint64(0), uint64(0)` extras) -- syscall ignores extras, no harm
- (info) Section [C] varies nanosleep from 100us to 10ms to find optimal race window -- good methodology

---

### 67k_combined.lua

| Check | Status | Notes |
|-------|--------|-------|
| CRASH_CLASS | OK | HIGH |
| Standard helpers | OK | Compressed single-line format but functionally correct |
| Lua 5.1 compliance | WARNING | Line 41: `wq(uint64(N(sa)+16), uint64(0))` -- same `uint64()` address-wrapping issue as 66e. |
| No hardcoded addresses | OK | |
| make_syscall pattern | OK | |
| No XO page reads | OK | |
| Double-free pattern | OK | Gated race with socketpair synchronization (67i2 pattern). Individual submits, poll before delete, no 670. |
| **Would it work?** | **LIKELY YES** | The `uint64()` address wrapping at line 41 is the only concern. Core race + spray + CPU pinning logic is sound. |

**Issues:**
- (warning) `wq(uint64(N(sa)+16), uint64(0))` at line 41 -- address wrapped in uint64
- (warning) Missing `thr_param.child_tid` field at `+0x30` in both param structs (lines 163-168) -- thread still starts but TID is not captured
- (info) CPU pinning via `cpuset_setaffinity(488)` is a good approach for cross-CPU cache line testing
- (info) Compressed code style reduces readability but saves Lua parse time

---

## Summary of Findings

### Critical Issues (2)

| File | Issue |
|------|-------|
| `65d_aio_multi_delete_race.lua` | Calls `670` (AIO init), which poisons the delete path. Probe is superseded by 65l. |
| `68a_doublefree_zone_overlap.lua` | `put_str` does arithmetic directly on userdata (`p + i - 1`) instead of `N(p) + i - 1` |

### Warnings (7)

| File | Issue |
|------|-------|
| `66e_aio_evf_overlap.lua` | `wq(uint64(addr), val)` wraps address in uint64 -- may fail |
| `66e_aio_evf_overlap.lua` | Single main+child race, not confirmed two-child pattern |
| `66e_aio_evf_overlap.lua` | Child ROP chain has non-standard instruction ordering |
| `67k_combined.lua` | `wq(uint64(addr), val)` at line 41 |
| `67k_combined.lua` | Missing child_tid in thr_param |
| `68a_doublefree_zone_overlap.lua` | Missing child_tid in some thr_param structs |
| `68c_aio_spray_setsockopt.lua` | SO_LABEL likely rejected on PS5 (no TrustedBSD MAC) |

### Info (naming collision)

Three files share the `68a_` prefix:
- `68a_aio_uaf_readback.lua`
- `68a_full_gadget_catalog.lua`
- `68a_doublefree_zone_overlap.lua`

This will cause confusion with `send_probe.py --save` and should be resolved by
renaming two of them (e.g., `68a2_full_gadget_catalog.lua`, `68a3_doublefree_zone_overlap.lua`).

### Probes by Workability

| Would Work | Probes |
|------------|--------|
| YES | 65l, 67d, 68a_uaf_readback, 68a_full_gadget, 68b, 68c, 68d |
| LIKELY YES | 66e, 67k, 68a_doublefree_zone |
| NO | 65d (superseded -- calls 670) |
