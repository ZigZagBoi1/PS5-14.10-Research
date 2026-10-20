# Syscall Mislabel Audit — 2026-10-19

Systematic audit of syscall number-to-name mismatches in the probe corpus, cross-referenced against `docs/sysent-names-13.60.csv` (the authoritative 13.60 sysent dump).

## Summary

Multiple probes use incorrect syscall names for given numbers. The root cause is a shifted label table in probe 02's original sweep and copy-paste propagation into later probes. Most mislabels do not affect the probe's actual behavior (the kernel dispatches by number, not name), but they produce misleading analysis and caused at least two dead-end misattributions.

## Critical Mislabels

### 1. make_syscall(588) labeled "munmap" — actually `mname`

**Scope:** ~35 probes across phases 7-12 use `make_syscall(588)` with comments calling it "munmap".

**Reality:** Per sysent-names-13.60.csv, syscall 588 is `mname` (Sony memory naming). Real FreeBSD `munmap` is **syscall 73**, which is already correctly used in ATTACK_SURFACE.md.

**Impact:** Low — no probe relies on 588 actually unmapping memory. The mmap cleanup paths that call it are cosmetic (process exit cleans up anyway).

### 2. make_syscall(585) labeled "mtypeprotect" / "memfd_create" — actually `is_in_sandbox`

**Scope:** Probes 42f, 43h, 43k, and ATTACK_SURFACE.md entry.

**Reality:** Per sysent-names-13.60.csv, syscall 585 is `is_in_sandbox`. Real `sceKernelMtypeprotect` is **syscall 379** (never tested via make_syscall). `memfd_create` does not appear in the Sony sysent at all.

**Impact:** HIGH — the "mtypeprotect returns 1" dead-end (probes 43h/44a) was testing `is_in_sandbox`, not mtypeprotect. The real mtypeprotect(379) has never been called. This potentially reopens the W^X bypass investigation via the correct syscall number.

**Status of real mtypeprotect(379):** UNTESTED. No probe has called make_syscall(379).

### 3. sc_umtx_op bound to 557 — actually `namedobj_create`

**Scope:** Phase 1/2 probes 04, 10, 11, 12, 13, and the first revision of 82a.

**Reality:** Per sysent-names-13.60.csv, syscall 557 is `namedobj_create` (Sony named object). Real `_umtx_op` is **syscall 454**.

**Impact:** HIGH — all phase 1/2 "umtx" findings (SHM behavior, robust lists, nwake oracle) are actually namedobj_create behavior. The real _umtx_op(454) was only exercised once (probe 56i2 section [F]: ops 5/21 ret=0). UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never tested on 454. Probe 110a corrects this. See `docs/UMTX_454_EVIDENCE.md`.

### 4. make_syscall(340) labeled "sigaction" — actually `sigprocmask`

**Scope:** Probe 25c and related signal probes.

**Reality:** Per sysent-names-13.60.csv, syscall 340 is `sigprocmask`. Real `sigaction` is **syscall 416**.

**Impact:** Low — probe 25c's finding "sigprocmask is a no-op" is actually correct by accident (it was calling the right number but with the wrong label in the source comment).

### 5. make_syscall(550) labeled "release_dmem" — actually `osem_delete`

**Scope:** dmem-related probes in phases 2-3.

**Reality:** Per sysent-names-13.60.csv, syscall 550 is `osem_delete` (Sony OS semaphore delete). The actual dmem release syscall has a different number.

**Impact:** Low — dmem operations were already confirmed dead via other evidence.

### 6. Probe 54b labels syscall 430 as "thr_new" — it's `thr_create`

**Scope:** Probe 54b's jail bypass section.

**Reality:** Syscall 430 is `thr_create` (Sony threading). Real `thr_new` is **syscall 455** (blocked). The probe's -1 result for a NULL-context call to 430 is a validation failure, not evidence about threading being blocked.

**Impact:** Medium — this mislabel was already corrected in PROBE_INDEX.md entry for 54b and the CLAUDE.md evidence correction section.

### 7. Probe 02 syscall sweep — shifted label table

**Scope:** Probe 02's label array maps ~30+ syscall numbers to wrong names due to an off-by-one or shifted index in the name table.

**Impact:** Low for probe 02 itself (the sweep tested reachability by number, not by name). HIGH for downstream analysis that cited probe 02's labels as ground truth for syscall identification.

## Reopened Investigation Paths

| Mislabel | Correct syscall | Status | Why it matters |
|----------|----------------|--------|----------------|
| "mtypeprotect" was 585 | Real mtypeprotect = 379 | **UNTESTED** | W^X bypass via correct mtypeprotect never attempted |
| "umtx" was 557 | Real _umtx_op = 454 | **UNDER-TESTED** | SHM/ROBUST_LISTS never exercised on correct number |
| "munmap" was 588 | Real munmap = 73 | Already correct in code | No impact — 73 is used correctly elsewhere |

## Verification Method

All number-to-name mappings verified against `docs/sysent-names-13.60.csv`, which was extracted from the 13.60 kernel dump's sysent table. The CSV maps each syscall number to its handler name. This is a 13.60 artifact; 14.10 sysent could differ, but Sony syscall numbers are stable across nearby firmware versions.

## Files Updated

- `CLAUDE.md` — corrected dead-end entries, removed duplicates
- `docs/ATTACK_SURFACE.md` — fixed syscall 585 label, added thr_create(430)
- `docs/PROBE_INDEX.md` — corrected 53b/58e status, added 76c-80n entries
- `docs/UMTX_454_EVIDENCE.md` — existing document covers the 557→454 correction
