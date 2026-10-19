# Probe 54b Phase 2 tested the wrong syscall for thr_new

Status: **label and argument-shape correction.** The 54b capture's `430 thr_new
ret=-1` row did not test `thr_new`. Upstream FreeBSD numbers 430 as
`thr_create` and 455 as `thr_new`, and the two calls take different arguments.
Phase 2 passed `thr_new`-shaped arguments to the `thr_create` number, so the
-1 is a guaranteed shape failure, not a threading verdict.

## What the probe did

Phase 2 of `probes/phase14_final_push/54b_jail_bypass.lua:133-155` retests
blocked syscalls with a uniform call shape, `(0, outbuf, 64, 0, 0, 0)`, and
labels number 430 `"thr_new"` (`:136`). The capture records
`430 thr_new  ret=-1` (`results/54b_jail_bypass_20261018_090446.txt:28`).

Two independent sources say 430 is not `thr_new`:

1. Upstream `sys/kern/syscalls.master` (stable/14): 430 is
   `thr_create(ucontext_t *ctx, long *id, int flags)`; 455 is
   `thr_new(struct thr_param *param, int param_size)`.
2. This repo's own probes: probe 27 maps `sc_thr_new = 455`
   (`probes/phase4_ipc_network/27_thread_and_fd.lua:19`) and probe 43e calls
   `make_syscall(455)` (`probes/phase10_untested_theories/43e_blocked_syscall_bypass.lua:162`).
   `docs/ATTACK_SURFACE.md:53` and `docs/UNTESTED_THEORIES.md:75` both pin
   `thr_new` at 455. No probe maps anything to 430.

## Why the -1 carries no information

The 13.60 handler bodies (from `kernel_text.bin` via the committed
`sysent_index.json` slots) show the two calls diverge immediately:

- 430 (slot `0x265c10`, body `0x437cf0`): loads `r15 = [rsi]` (arg0) and calls
  the 0x500-byte copyin path (`call 0x259280` with `edx=0x500`). With arg0 = 0
  the copyin faults, so -1 is the only possible answer.
- 455 (slot `0x265c50`, body `0x437de0`): checks `[rsi+8] <= 0x68`, zeroes a
  0x68-byte param block, and copies in `param_size` bytes — the `thr_param`
  shape probe 27 builds.

Phase 2 passed arg0 = 0 into a call whose first act is `copyin(arg0, 0x500
bytes)`. The -1 records an EFAULT on a NULL pointer, not a blocked thread
primitive. It neither confirms nor contradicts the probe 27 / 43e verdicts on
455.

## What this changes

1. The `430 thr_new ret=-1` row in the 54b capture must not be cited as
   threading evidence. It is a mislabeled `thr_create` call with NULL context.
2. `thr_create` (430) itself is now the interesting untested surface: it takes a
   full `ucontext_t` (0x500 = 1280 bytes: machine context plus signal mask) and
   the 14.10 corpus has never issued it with a valid pointer. The uniform
   `(0, outbuf, 64, ...)` shape used by Phase 2 cannot reach past its copyin.
3. The real `thr_new` (455) verdicts stand: -1 via the loader path (probe 27),
   crash via `make_syscall` (probe 43e). This note does not reopen 455.

## What this does not change

- No second thread has been created on 14.10 through any tested path.
- The 13.60 bodies are 13.60-only evidence; they establish what the numbers
  mean upstream, not what 14.10 does with them.
- Whether `thr_create` exists, is filtered, or behaves differently on 14.10 is
  unknown. The honest next step is one probe: a valid `ucontext_t` at 430 and a
  recorded return.
