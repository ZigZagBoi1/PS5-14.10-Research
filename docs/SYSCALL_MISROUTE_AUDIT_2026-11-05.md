# Syscall misroute audit — 2026-11-05

Static audit of probe syscall labels against `docs/sysent-names-13.60.csv` and
the saved captures. No probe was executed and no console was contacted.

Several probes named after one kernel object call a different syscall slot.
This does not by itself prove the kernel is safe; it means the saved result is
not evidence about the object in the probe's title.

## Correct map for the affected families

| Call | Correct slot | Current probe label |
|---|---|---|
| `pdfork` | Not exposed at 518 in the retained map; **518 = `obs_{`** | `120a` calls 518 as `pdfork` |
| `pdkill` / `pdgetpid` | **519 = `pdkill`**, **520 = `pdgetpid`** | `120a` has these reversed |
| `ktimer_create` | 235 | correct |
| `ktimer_delete` | 236 | `79c` / `105a` call it `settime` |
| `ktimer_settime` | 237 | `79c` / `105a` call it `gettime` |
| `ktimer_gettime` | 238 | `79c` / `105a` call it `delete` |
| `ktimer_getoverrun` | 239 | correct |
| `ksem_init` | 404 | correct |
| `ksem_open` | 405 | correct |
| `ksem_unlink` | 406 | `79d` calls it `getvalue` |
| `ksem_getvalue` | 407 | `79d` calls it `destroy` |
| `ksem_destroy` | 408 | `79d` calls it `unlink` |
| `kevent` | 363 | `125a` calls 560 |
| `debug_init` | 560 | `125a` calls it `kevent` |
| `kldnext` | 307 | `56h` / `56h2` call 304 |
| `kldload` | 304 | `56h` / `56h2` call it `kldnext` |
| `kldsym` | 337 | `102a` calls 309 |
| `kldfirstmod` | 309 | `102a` calls it `kldsym` |
| `fstat` | 189 | `88c` / `151c` call 551 |
| `osem_open` | 551 | `88c` / `151c` call it `fstat` |
| `pipe2` | Not in the retained map; 42 = `pipe` | `533a` / `152c` label 42 `pipe2` |
| `evf_wait` | 542 | `67b` / `105a` / `533e`–`533g` label it `pipe2` |

`pic`/`pipe2` is a FreeBSD native name; the Sony table can replace it. The
retained map is the authority used by the probes in this repository.

## Findings

### 67b — the advertised poll/select race is absent

`67b_poll_fd_uaf.lua` claims CVE-2026-45251 with two threads: one blocked in
`poll()`, one closing the fd (`67b:2-11`). The file contains no thread creation
and no close-while-blocked. It only checks that `poll()` and `select()` work,
polls four fd types, and calls `UMTX_OP_SHM`. The saved capture
`results/phase15_jailbreak/67b_poll_fd_uaf_20261023_184143.txt` ends after the
UMTX section.

The CVE was not tested. The probe cannot close it or show it is patched.

### 120a — 518 is `obs_{`, not pdfork

`120a_pdfork_capsicum.lua` documents `pdfork(518)`, `pdgetpid(519)`,
`pdkill(520)`, `pdwait4(521)` (`120a:5,71-72`). In the retained 13.60 map:

- **518 = `obs_{`**
- **519 = `pdkill`**
- **520 = `pdgetpid`**

The raw entries for 518–521 are the common `narg=0` unsupported stub
(`docs/PRIVATE_2026_FREEBSD_KERNEL_CVE_TRIAGE_2026-10-21.md`), so the generated
CSV labels alone do not make them callable. The saved capture
`results/phase17_new_vectors/120a_pdfork_capsicum_20261019_185541.txt` stops
after `[A1] pdfork(fdp, 0)...` with no return value, consistent with the first
call terminating the probe. `docs/LIVE_TEST_SESSION_2026-10-19.md` records the
same run as incomplete.

This is not a fork bypass. The pdfork/pdgetpid/pdkill arm should be closed, not
retested at 518–520.

### 79c / 105a — ktimer off by one

`79c:59-62` and `105a:312-315` define:

```text
235 create
236 settime   (real: delete)
237 gettime   (real: settime)
238 delete    (real: gettime)
239 getoverrun
```

`79c` therefore calls `ktimer_delete` when it believes it is arming the timer.
The saved `79c` capture shows `settime rv=0`, `gettime=0`,
`delete=-1`, `getoverrun=-1`, but no SIGEV_SIGNAL delivery and no timer expiry.
The callout-reentrancy premise is untested.

The correct sequence to test is `235 create`, `237 settime`, `238 gettime`,
`236 delete`, `239 getoverrun`.

### 79d — ksem lifecycle calls are shifted

`79d:76-78` defines `getvalue(406)`, `destroy(407)`, `unlink(408)`. The actual
map is `unlink(406)`, `getvalue(407)`, `destroy(408)`.

The saved capture `results/phase17_new_vectors/79d_shm_sem_mqueuee_20261019_185320.txt`
reports `ksem_getvalue=-1` and `ksem_destroy=-1`, then a successful
`post-after-destroy`. That is explained by the shift: “destroy” was
`getvalue`, so the semaphore was never destroyed. POSIX-semaphore lifecycle/UAF
is still unmeasured.

### 125a — 560 is `debug_init`, not `kevent`

`125a:65` binds `sc_kevent` to 560. The retained map has **560 = `debug_init`**
and **363 = `kevent`**. The saved capture
`results/phase21_kernel_leak/125a_thread_kevent_kptr_20261021_212757.txt`
records `kevent register rv=0xffff...` and “registration OK, 0 events.” That is
the wrong syscall returning an error, not a successful EVFILT_PROC registration.
The EVFILT_PROC pointer-leak vector is untested.

### 533a — the race target becomes fd 0

`533a_fd_close_race.lua:63` labels 42 `pipe2`; 42 is `pipe`. More importantly,
the setup calls `sc_pipe(pipe_fds, 0)` and then reads `target_wr` from
`pipe_fds+4`. The saved capture
`results/phase27_phys_memory/533a_fd_close_race_20261025_174926.txt` prints
`pipe: rd=0 wr=0`; the child closes fd 0 while the main thread races
`sendmsg(SCM_RIGHTS, fd)`. The intended pipe write end was never created, so
“No anomalies in 200 iterations” is not a close/sendmsg race result.

### KLD probes — wrong module slots

- `56h2:153` and `56h:489` bind `kldnext` to 304. **304 = `kldload`**;
  **307 = `kldnext`**. The saved 56h2 capture stops earlier at
  `[D] kldfirstmod(309)`, so the wrong 304 call did not run, but the probe as
  written cannot iterate modules.
- `102a:420` binds `kldsym` to 309. **309 = `kldfirstmod`**;
  **337 = `kldsym`**. The prepared kldsym arm is not kldsym.

KASLR conclusions from these arms are not supported. The existing direct
`kldsym(337)` work remains the relevant path.

### 88c / 151c — 551 is `osem_open`, not fstat

`88c:123` and `151c:54` bind `sc_fstat` to 551. **551 = `osem_open`**;
**189 = `fstat`**. Their fstat checks pass a stat buffer to `osem_open` and
return failures that say nothing about fd state.

### 55e — AIO labels are wrong

`55e:101-102` labels **664** `aio_cancel` and **665** `aio_error`. Actual:
**664 = `aio_multi_poll`**, **665 = `aio_get_data`**; `aio_cancel` is 666,
`aio_error` is 317. The calls hit 664/665, but any “cancel” or “error”
interpretation is mislabelled.

### 106a — 78 is `mincore`

`106a:301` labels 78 `getcontext (sigprocmask variant?)`. **78 = `mincore`**
in the retained map. The saved run did not execute Section B, so this is a
prepared-code error rather than a saved-result error.

## What this means

The following saved conclusions must not be used as closures:

- poll/select fd UAF: **67b did no race**; 533a used fd 0.
- pdfork/capsicum: **not exposed at 518**.
- ktimer signal reentrancy: **no timer was armed**.
- ksem lifecycle: **destroy was getvalue**.
- EVFILT_PROC: **debug_init was called**.
- KLD/KASLR via 304/309: **wrong slots**.
- fstat via 551: **osem_open**.
- AIO cancel/error via 664/665: **poll/get_data**.

Correcting a label does not require a console. Re-running a corrected probe
does.

## Reproduction

Static checks only:

```text
docs/sysent-names-13.60.csv
docs/PRIVATE_2026_FREEBSD_KERNEL_CVE_TRIAGE_2026-10-21.md
docs/LIVE_TEST_SESSION_2026-10-19.md
results/phase15_jailbreak/67b_poll_fd_uaf_20261023_184143.txt
results/phase17_new_vectors/120a_pdfork_capsicum_20261019_185541.txt
results/phase17_new_vectors/79c_ktimer_signal_reentrancy_20261028_222245.txt
results/phase17_new_vectors/79d_shm_sem_mqueuee_20261019_185320.txt
results/phase21_kernel_leak/125a_thread_kevent_kptr_20261021_212757.txt
results/phase27_phys_memory/533a_fd_close_race_20261025_174926.txt
```

No console was contacted.
