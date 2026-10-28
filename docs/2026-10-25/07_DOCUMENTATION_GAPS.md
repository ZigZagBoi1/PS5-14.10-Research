# Documentation Gap Analysis

**Date:** 2026-10-25
**Source:** Agent 7 -- Documentation consolidation (max effort)

## 1. STRATEGY.md -- SEVERELY OUTDATED

- "Current position" is dated 2026-10-22 and does not mention the AIO double-free breakthrough (confirmed 2026-10-23, probe 65l)
- Line 85: "No threading -> no race conditions" -- directly contradicts reality. Threading works via both `thr_create(430)` and `thr_new(455)`. The double-free was confirmed through concurrent child threads.
- Priority list: Priority 1 is msync CVE-2026-49418, which is confirmed dead (probes 58a/58b). AIO double-free should be Priority 1.
- Missing primitives: thr_new(455), child thread ROP, fake TCB fix, EVFILT_TIMER+socketpair, POSIX shm, mlock, BSD-native range exhaustion, object table predictability, selector sanitization
- Sysent 677-734 still listed as "58 untested" but probes 275b-275d showed all return -1

## 2. FINDINGS.md -- MISSING CRITICAL FINDINGS

File ends at Finding 90. Missing entries:
- AIO double-free (65d-65l) -- the single most important discovery
- thr_new(455) with arg delivery (56l)
- Child thread ROP syscalls with 4-arg control (271g/272a)
- Fake TCB fix for child threads (384b)
- Child multi-arg confirmation (384b/386a)
- EVFILT_TIMER + socketpair pipeline (271i)
- Kqueue race exhaustion (271g/271h/271i)
- POSIX shm fully functional (391a-391d)
- mlock(203) heap pages (392f)
- Device inventory (259a-268a)
- Object table predictability (435a-445a)
- W^X precise measurement via mprotect bit scan (423a-424c)
- Selector sanitization (448a-455d)
- BSD-native range exhaustion (388a-392f)
- native.fcall_with_rax (129b)

**Duplicate numbering:** Finding 83 appears twice (SCM_RIGHTS AND POSIX shm). Finding 84 appears twice (msync AND sendfile).

## 3. PROBE_INDEX.md -- STRUCTURALLY BROKEN

- **Massive duplication:** entries 271a-278a repeat approximately 17 times across the file
- **Ends at probe 278a:** All probes after that are missing from the index
- ~100+ probes unindexed, including: AIO double-free series (65d-65l), child thread infrastructure (271g-272a, 384b-387c), BSD-native exhaustion (388a-392f), native chain (404a-433a), object table (435a-445a), selector probes (448a-455d)

## 4. ATTACK_SURFACE.md -- KEY CONTRADICTIONS

- `thr_new | 455 | Blocked` -- contradicts confirmed working (probe 383a/56l)
- `shm_open | 482 | Crashes loader` -- contradicts confirmed working (probes 391a-391d)
- Missing: AIO double-free, object table sections, full ioctl survey results (273a-287a, 387a/387c)

## 5. DEAD_ENDS.md -- PARTIALLY CURRENT

Missing many entries from CLAUDE.md:
- NET_RT_DUMP false positives (56e/56e2)
- CClosure deep Lua stack read (56d5-56d7)
- sys 624 side channel (56f)
- sysctl deep scan (56g3)
- timing KASLR (56h-56i2)
- ioctl overcopy full sweep (387a/387c)
- CVE-2026-49427/49428 posixshm largepage (391a-391d)
- CVE-2026-49419 jail refcount (392a)
- signal frame sendsig (56r)
- kqueue race ZDI-26-784 (271g/h/i)
- all 56o/56p/56q sub-section scans

## 6. CHANGELOG.md -- OUTDATED

Most recent entry covers 2026-10-23 WebKit corpus and msync, but does not mention: AIO double-free confirmation, child thread ROP chains, BSD-native range exhaustion, object table research, selector sanitization, ioctl overcopy full sweep.

## 7. Documentation Coverage

| Topic | Documented? | Location |
|-------|-------------|----------|
| AIO double-free exploit path | YES (basics) | `docs/AIO_DOUBLE_FREE_14_10.md` |
| Full exploit chain (kernel R/W) | **NO** | Not documented anywhere |
| Child thread ROP chain details | YES | `docs/CHAIN_14_10.md` |
| Gadget catalog | **PARTIAL** | Scattered in CHAIN_14_10.md and CLAUDE.md |
| thr_new(455) details | **NO standalone doc** | Only in CLAUDE.md |
| Fake TCB fix | **NO standalone doc** | Only in CLAUDE.md |
| Object table structure | YES | `docs/OBJECT_TABLE_14_10.md` |

## 8. Key Information Only in CLAUDE.md

- Complete gadget catalog with exact eboot offsets
- thr_new(455) struct thr_param layout and arg delivery mechanism
- Fake TCB fix (sysarch SET_FSBASE with self-referencing 4KB buffer)
- Max 4 controlled args (no pop_r8/r9 in 4.6MB eboot)
- EVFILT_TIMER(-7) at 1ms resolution + socketpair pipeline
- BSD-native range exhaustion summary
- Complete list of CVEs confirmed dead
