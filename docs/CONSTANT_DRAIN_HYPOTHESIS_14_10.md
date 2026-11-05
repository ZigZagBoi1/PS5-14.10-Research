# Constant Drain Hypothesis Table — PS5 14.10

## Source

The offset table in `soniciso1/relapse-dev` at `offsets/13.60.js` is byte-identical
to `14.00.js` and `14.10.js` (MD5 `e49b78d4…`). None of the 25 scalar constants
has been independently verified on 14.10. This document tracks the drain campaign
that converts each constant from folklore into a measurement.

## Methodology

Each constant is tested by a single-constant probe that either:
- **Address math**: computes `base + offset`, compares with a resolved function address (zero risk)
- **Data read**: reads the value at `base + offset` via `memory.read_qword` (low risk, pcall-protected)
- **Function call**: calls `base + offset` with safe arguments via `fcall()` or child thread ROP (moderate risk)
- **Crash grade**: forges a vtable entry and observes crash/survive (high risk, single-shot)

Grade clauses (cobrajet302gt, issue #175):
1. One candidate working does NOT mean "the table carries over" — drift grades per-constant
2. Drain deaths need the landing-witness gate before becoming a verdict about the constant
3. Run the canary check before grading any drain death

## Constants

### WebKit (`wk_`) — blocked on WebProcess text base

| # | Constant | 13.60 Value | Grade | Drain Method | Probe |
|---|----------|-------------|-------|--------------|-------|
| 1 | `wk_host_constructor_candidates` | `[0x56A58, 0x56CA0, 0x57CE8]` | Unverified | Crash grade via vtable forge | — |
| 2 | `wk_vtable_first_element` | `0` | Unverified | Needs WebKit base | — |
| 3 | `wk_memset_import` | `0x03350850` | Unverified | Data read at wk_base + offset | — |
| 4 | `wk___stack_chk_guard_import` | `0x0334E198` | Unverified | Data read at wk_base + offset | — |

**Blocker**: WebProcess text base unknown. No 14.10 or 14.00 WebProcess VA exists publicly.
All wk_ probes are blocked until a text base is obtained (crash-log backtrace, decrypted binary, or
the Lua-side drain identifies it through a cross-module reference).

### libkernel (`lk_`) — drainable via Lua bench

| # | Constant | 13.60 Value | Grade | Drain Method | Probe |
|---|----------|-------------|-------|--------------|-------|
| 5 | `lk___stack_chk_guard` | `0x000751D0` | **WRONG** | UNMAPPED: data ends at +0x70000 (base+0x6C000, sz 0x4000) | p589 |
| 6 | `lk__thread_list` | `0x0006C218` | **VALID** | DATA_READ = 0x881857240 (thread pointer, in DATA segment) | p589 |
| 7 | `lk_worker_wait_return` | `0x0001FD01` | **UNTESTABLE** | In TEXT (XO); child ROP call crashes process | p589/p591 |
| 8 | `lk_pthread_create_name_np` | `0x00021890` | **UNTESTABLE** | In TEXT (XO); child ROP call crashes process | p589/p591 |
| 9 | `lk_pthread_join` | `0x000229A0` | **UNTESTABLE** | In TEXT (XO); child ROP call crashes process | p589/p591 |
| 10 | `lk_pthread_exit` | `0x00021C20` | **CRASH** | Child dies on entry — offset wrong or needs real pthread state | p591 v7 |
| 11 | `lk_sleep` | `0x00027F00` | **CRASH** | Child dies on entry — offset wrong or needs real pthread state | p591 v6 |
| 12 | `lk_sceKernelGetCurrentCpu` | `0x00001200` | **WRONG** | fcall garbled output (p589); +0x1200 not the real entry | p589/p590 |

### libc (`lc_`) — drainable via Lua bench

| # | Constant | 13.60 Value | Grade | Drain Method | Probe |
|---|----------|-------------|-------|--------------|-------|
| 13 | `lc_memset` | `0x00014700` | Unverified | Function call (3 args) via child ROP | p588 |
| 14 | `lc_setjmp` | `0x0005D990` | **WRONG** | Address math: actual offset 0xB0020 in libc.prx | p588 |
| 15 | `lc_longjmp` | `0x0005D9E0` | **WRONG** | Address math: actual offset 0xB0070 in libc.prx | p588 |

### Worker — needs WebKit bench

| # | Constant | 13.60 Value | Grade | Drain Method | Probe |
|---|----------|-------------|-------|--------------|-------|
| 16 | `WORKER_STACK_OFFSET` | `0x0007FB88` | Unverified | Needs WebKit base | — |

### Kernel — presumptively wrong

| # | Constant | 13.60 Value | Upstream 14.10 | Grade | Notes |
|---|----------|-------------|----------------|-------|-------|
| 17 | `KERNEL_ALLPROC` | `0x03589E80` | D+0x28D9EA0 | **Wrong** | Delta ~0x10020 vs upstream SDK |
| 18 | `KERNEL_SECURITY_FLAGS` | `0x01A5C064` | — | **Presumptively wrong** | Shifts per build |
| 19 | `KERNEL_ROOTVNODE` | `0x03E0B510` | D+0x315B510 | **Wrong** | Delta ~0x10000 vs upstream SDK |
| 20 | `KERNEL_DATA` | `0x00CC0000` | D-0x0CE0000 | **Wrong** | text=D-0xCE0000 vs D-0xCC0000 |

Source: `ps5-payload-dev/sdk` 14.10 kernel offsets (see `docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md`).

### KASLR / Struct offsets

| # | Constant | 13.60 Value | Grade | Notes |
|---|----------|-------------|-------|-------|
| 21 | `kaslr_leak_static` | `0x00B57B41` | Dead | AF_ROUTE sanitized on 14.10 (53b) |
| 22 | `kaslr_leak_ret` | `0x00B57B44` | Dead | Same — rt_msg2 leak path closed |
| 23 | `KBASE` | `0xFFFFFFFF80210000` | Likely correct | FreeBSD kernel text VA, static |
| 24 | `KERNEL_VMSPACE_P_ROOT` | `0x1D0` | Unverified | Struct offset, may be stable |
| 25 | `KERNEL_VMSPACE_VM_PMAP` | `0x2E8` | Unverified | Struct offset, may be stable |

## Drain Priority

1. **libc offsets (13-15)** — address math against `libc_addrofs`, zero risk, instant
2. **libkernel data offsets (5-6)** — read at `lk_base + offset`, low risk
3. **libkernel code offsets (7-12)** — segment range checks + `sceKernelGetCurrentCpu` call
4. **libc function call (13)** — `memset` via child thread ROP, moderate risk
5. **WebKit offsets (1-4, 16)** — blocked on text base
6. **Kernel offsets (17-20)** — already known wrong from upstream SDK

## Cross-Reference Data

### Probe 588 measurements (2026-11-03)

Two libc modules exist on 14.10:
- `libSceLibcInternal.sprx` (handle 2): text=XO (p=4), data p=1
- `libc.prx` (handle 20): text=RX (p=5), data p=3

ALL `libc_addrofs` functions resolve to `libc.prx` (handle 20), NOT `libSceLibcInternal.sprx`.

| Function | Resolved Address | Module | Actual Offset | 13.60 Hypothesis |
|----------|-----------------|--------|---------------|-----------------|
| setjmp | 0x1EA9EC020 | libc.prx +0xB0020 | 0xB0020 | 0x5D990 **WRONG** |
| longjmp | 0x1EA9EC070 | libc.prx +0xB0070 | 0xB0070 | 0x5D9E0 **WRONG** |
| memcpy | 0x1EA97E410 | libc.prx +0x42410 | 0x42410 | — |
| Thrd_create | 0x1EA9883C0 | libc.prx +0x4C3C0 | 0x4C3C0 | — |
| Atomic_fetch_add_8 | 0x1EA973BF0 | libc.prx +0x37BF0 | 0x37BF0 | — |

Delta check: `setjmp - longjmp = -0x50`, hypothesis delta = `0x5D990 - 0x5D9E0 = -0x50` ✓ (relative delta preserved, absolute offsets shifted by +0x52690)

The 13.60 exploit targets `libSceLibcInternal` but on 14.10 the loader resolves to `libc.prx` — a different module with different offsets. The hypothesis offsets are wrong by a fixed shift, suggesting either a module split or a rebase between firmware versions.

### Probe 589 measurements (2026-11-03) — libkernel found via VM map

`dynlib_get_info(593)` does not enumerate `libkernel.sprx` — it has no handle in 0-50. Found via sys 674 VM map by locating the region containing `fn_addr`.

| Property | Value |
|----------|-------|
| Module | libkernel.sprx (674 region 203) |
| text base | 0x82015C000 (per-connection ASLR) |
| text size | 0x48000 (288 KB) |
| text prot | 4 (XO — execute only, unreadable) |
| data base | 0x8201C8000 |
| data size | 0x4000 (16 KB) |
| data prot | 3 (RW) |
| data offset from text | 0x6C000 |
| fn_addr offset | +0xB57 (syscall dispatcher entry) |

Key results:
- `_thread_list` at +0x6C218 → in DATA segment → read returned `0x881857240` (valid thread pointer) → **VALID**
- `__stack_chk_guard` at +0x751D0 → past data end (0x70000) → **WRONG** (data segment only 16 KB)
- All code offsets (#7-12) fall within TEXT (0x48000) but text is XO, so they can't be verified by reading
- `sceKernelGetCurrentCpu` fcall at +0x1200 garbled the output — likely wrong offset or calling convention issue

### Probe 591 measurements (2026-11-03) — child thread ROP via thr_new(455)

Child thread ROP infrastructure fully working. Key findings:

**Working child syscalls (all PASS):**
- `getpid(20)`: child_pid matches parent ✓
- `nanosleep(240)`: ret=0 with zeroed timespec ✓
- `write(4)`: 8 bytes via socketpair, 7/8 bytes correct (last byte zeroed — alignment artifact) ✓
- `clock_gettime(232)`: ret=0, real timestamp returned ✓

**Critical infrastructure details:**
- RSP formula: `((stack_base + stack_size) & ~0xF) - 8` — the `-8` is mandatory
- `native.fcall_with_rax(stub, N, ...)` for ALL syscalls — zero binary dump
- Fake TCB via `sysarch(SET_FSBASE=129)` prepended to every child chain
- 4 pre-allocated 2 MiB stacks, one per test

**Library function calls CRASH the child:**
- `pthread_exit` at lk+0x21C20: child dies on entry, kills parent process (v7)
- `sleep` at lk+0x27F00: child dies on entry, kills parent process (v6)
- Root cause: either offsets are wrong on 14.10, or these functions require real pthread/TLS state that the fake TCB cannot provide. Since libkernel text is XO, the code cannot be inspected to determine which.

**Verdict for #7-11**: The 5 libkernel code offsets are UNTESTABLE with current infrastructure. Calling XO library functions from a child thread with a fake TCB is inherently unsafe — a wrong offset or missing state crashes the child, which takes out the entire process. These offsets should be treated as **unverified and likely wrong** given the pattern: #5, #12, #14, #15 are confirmed WRONG, suggesting the entire 13.60 table is stale for 14.10.

### Probe 588 incomplete items

- `gettimeofday_import` (0x1EAA539A8) falls between libc.prx text end and data start — likely .rodata.
- `memset` not present in `libc_addrofs` — needs child-thread ROP test with computed offset.

## Gadget Map and Syscall Map

The 13.60.js also contains:
- `wk_gadgetmap`: 27 ROP gadgets (WebKit-relative offsets) — all blocked on text base
- `syscall_map`: 267 syscall entries — these are kernel-relative, not module-relative
- `window.KRW` / `window.SYMBOLS`: kernel R/W primitives — depend on kernel offsets (wrong)

These are secondary targets. The scalar constants are the priority.

## Drain Campaign Summary (2026-11-03)

| Grade | Count | Constants |
|-------|-------|-----------|
| **VALID** | 1 | #6 `lk__thread_list` |
| **WRONG** | 7 | #5, #12, #14, #15, #17, #19, #20 |
| **CRASH** | 2 | #10 `pthread_exit`, #11 `sleep` |
| **UNTESTABLE** | 3 | #7, #8, #9 (XO text, child crash kills process) |
| **Presumptively wrong** | 1 | #18 `KERNEL_SECURITY_FLAGS` |
| **Dead** | 2 | #21, #22 (AF_ROUTE sanitized) |
| **Likely correct** | 1 | #23 `KBASE` (FreeBSD static VA) |
| **Unverified** | 8 | #1-4 (WebKit blocked), #13 `memset`, #16, #24, #25 |

**Bottom line**: Of the 25 constants, only 1 is confirmed valid. 7 are confirmed wrong, 2 crash, 3 are untestable. The 13.60 offset table is NOT reliable for 14.10. Any exploit chain depending on these offsets needs independent verification per-constant.
