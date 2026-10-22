# An absent syscall slot terminates the caller (14.10)

## The measurement

`make_syscall(4095)` with six zero `uint64` arguments terminated the process inside the
call. 4095 is past the end of any sysent table this kernel can have, so no handler exists
for it.

Capture: `results/phase17_new_vectors/173a_unimplemented_syscall_slot_20261020_184436.txt`,
probe `probes/phase17_new_vectors/173a_unimplemented_syscall_slot.lua`.

## Why this matters for every earlier "lethal" verdict

A real FreeBSD stub returns `ENOSYS`; it cannot terminate its caller. The numbers that have
killed this process are:

| syscall | what it is | why the slot is plausible absent |
|---|---|---|
| 307 | `kldnext` | host-side module loader, meaningless on a console |
| 308 | `kldstat` | same |
| 337 | `kldsym` | same |
| 570 | `sysctlbyname` | the console keeps `sysctl` (202) but not the by-name entry |
| 661 | AIO submit | AIO compiled out |
| 665 | `nosys` stub in the 13.60 capture | literally labeled absent there |
| 668 | `nosys` stub in the 13.60 capture | same |
| 4095 | past the end of the table | absent by construction |

One rule explains all eight: a slot that is not present terminates the process. The
alternative — eight unrelated handlers each choosing to kill a caller that a normal kernel
would answer with `ENOSYS` — has no mechanism behind it.

## What the statuses mean now

- **KILLED_IN_CALL** — the slot is absent on 14.10. It is not a hostile handler and it is
  not exploit surface. The process death is the dispatcher's response to a missing entry.
- **RETURNED with `-1`** — the slot exists and rejected these arguments. This is a positive
  result: it proves the handler is present and reachable, which is where bug surface lives.
- **RETURNED with `0` or a value** — the slot exists and accepted the arguments.

The earlier reading treated `-1` as failure and a kill as the interesting case. It is the
other way round: `-1` means the handler is there, and a kill means it is not.

## Consequences for recorded verdicts

- The "AIO 661-670 hard wall" was 661 (and 665, 668) being absent, not hostile. The six
  numbers that returned `-1` — 662, 663, 664, 666, 667, 669 — are **present handlers** that
  rejected six zero arguments. That is the part of the range worth attacking with real
  structures, and it was written off as dead.
- `kldsym` (171a), `kldstat`/`kldnext` (56k4/56k5) and `sysctlbyname` (172a) are not
  "lethal Sony guards"; the console simply does not have them. No further argument shapes
  need testing on those numbers.
- The 13.60/14.10 "stub-path divergence" question disappears: 665 and 668 are absent in both.

## Rule for future sweeps

Before calling any number hostile, check whether it is absent: a call that returns anything
at all proves presence, and presence is required for a handler to be exploitable. A sweep
record whose only evidence is a kill carries no information about the handler, because
there is none.

## Present but gated: 662-669 (174a, 175a, 2026-10-20)

The six surviving numbers in 661-670 are present, and 162 calls say so:

- `174a` gave 662, 663, 664, 666, 667 and 669 a zeroed 0x400 page in `RDI` and `0x400` in
  `RSI`. All six returned `-1` and wrote nothing.
- `175a` swept selectors 0-8 in each of the first three argument positions, 27 calls per
  number, 162 in total. Every call returned `-1`.

Rejection is therefore independent of argument layout and of the buffer. The remaining
explanation is a state gate: an AIO context must exist, and the number that would create
one (661) is an absent slot. The range is unreachable by construction, which is a stronger
statement than "returns -1".

`175a`'s first run printed 162 "hits" because the probe compared the return against the Lua
number `-1` while `get_hi_lo` returns the low dword unsigned (`4294967295`). The comparison
now uses `0xFFFFFFFF`; the corrected run is the one recorded here.

## The death is process-wide, so the map costs a relaunch per gap (176a, 2026-10-20)

`176a` spawned a `thr_create` child with `RAX = 4095` at `syscall_address`, parked on a
`jmp $` slot, and busylooped the main thread on `getpid`. The capture ends at
`[1] spawning thread RAX=4095`: the print that follows `thr_create` never ran, so the child's
absent-slot call took the whole process with it.

The killer is not confined to the calling thread, which means a child thread cannot be used
to probe slots cheaply. Mapping an absent number always costs one game relaunch: the sweep
stops there, and the numbers after it need a fresh process.

## Correction: the game restarts the loader by itself (2026-10-20)

Earlier entries said an absent slot costs a game relaunch. It does not. A kill still takes
the whole process, but the game brings the loader straight back:

    before: PID 292  SW 0x807584B57
    call 4095 (absent)  -> connection dropped
    waited 9.31s        -> port 9026 accepting again
    after:  PID 299  SW 0x818C90B57

A new pid and a new module base, so this is a fresh process rather than a surviving one, and
nobody touched the console. The same thing happened during the 572-600 sweep: numbers 573, 589,
590 and 597 killed the process and the sweep continued without help, because
`--wait-for-loader` simply waited about nine seconds.

The relaunch prompts in the earlier entries were a measurement artefact: the sweeps aborted on
the first `CONNECT_FAILED` and never sat long enough to observe the recovery. The lesson is
that "the port refused" is not "the console needs a human" - poll before concluding.

## Not every kill recovers in nine seconds (2026-10-20)

The nine-second restart above is what happens when the loader process dies and the game
is still running. Some low numbers take more than the process with them:

    sys 1  exit        -> port refused, still down after 150s
    sys 8  compat.creat -> port refused, still down after 150s
    sys 9  munmap      -> port refused, still down after 240s (sweep of 9-537 aborted there)

Against 4095, which only ends the loader, the wait was 9.31s every time. The difference is
consistent with `exit` and the two copies that fault on a null argument doing more than
ending a thread: they end the game, so nothing is left to spawn a new loader. Treat a kill
that outlives four minutes as needing a human, and keep `--wait-for-loader` as the fast path
for the loader-only case rather than a guarantee.

## The recovery slows during a sweep, but not with the number of kills (2026-10-21)

Within one boot the wait climbed while a sweep was running, and a power cycle put it back to
nine seconds:

| Kills since boot | Window | Behaviour |
|---|---|---|
| 0-2 | 462-475 | 9s recoveries, finished in 80s |
| 3-5 | 476-500 | 37s, 54s, 66s, then over 90s twice; window aborted |
| (after a power cycle) 0-11 | 492-510 | back to 9s throughout, finished in 401s |
| 12-18 | 511-519 | 78s with no record and the port refusing; window aborted |

The natural reading was that the console accumulates something per lost process, since the
loader is a fresh process every time and the count is what grows. The measurement below
rejects that reading: the interval is a constant for repeated kills and no counter moves.

`tools/restart_pressure.py` measures exactly that, at the cost of one kill per round: it runs
`probes/phase17_new_vectors/217a_restart_pressure.lua`, which prints one `SAMPLE` line of
counters a fresh process starts with (624 VM operation counter, 593 module count, 674 VM
region count, 671 resource classes), kills the loader with 4095, times the recovery, and
samples again. If 624 or 671 climb across restarts the accumulation is system-wide and shows
up as a readable number; if every counter resets, it is invisible from userland and only the
clock sees it. The result also decides how the presence map can be finished: either in one
window after a power cycle, or with a reboot per handspan of absent slots.

### Result: no leak shows, and the recovery is flat at 24.7s (2026-10-21)

Three back-to-back kills, no gap between them, on a boot that had already lost more than
twenty processes (`results/phase17_new_vectors/restart_pressure_20261021_133337.txt`):

| Round | Recovery | 624 | 674 | 671 c1 |
|---|---|---|---|---|
| 0 (before any kill) | - | 3377 | 316 | 6144/3951 |
| 1 | 24.3s | 3376 | 317 | 6144/3950 |
| 2 | 24.9s | 3377 | 316 | 6144/3951 |
| 3 | 24.7s | 3376 | 317 | 6144/3949 |

Every counter is stable in the same way a fresh process is stable: 624 returns the same two
values it returns for any new process, 674 alternates by one region between runs, and the
second 671 field drifts by two out of 3951 without direction. Nothing accumulates.

Two facts follow, and the second one corrects the table above. The recovery for a *repeated
4095 kill* is a constant ~25s, not a number that grows with the kill count - three kills in a
row cost the same as the first. And the tens-of-seconds growth seen during the 476-500 window
was therefore not caused by the kills themselves; the difference between that window and this
run is that a sweep hammers the port (a connect or a script every two seconds while waiting)
between kills, while this driver kills and waits. The conservative rule stays - treat a kill
that outlives four minutes as needing a human - but a slow recovery is a property of the
waiting, not evidence of a leak, and no kernel resource loses a measurable amount per death.



## A positive return is the strongest evidence (2026-10-20)

The sweep ran 104-537 and 238 of the 328 numbers it reached returned something. Most of those
returned the all-ones value the loader prints as `-1`, but six returned a small positive number:
`125` -> 4, `141` -> 22, `310` -> 54, `330` -> 1, `362` -> 22 and `429` -> 14. Those are FreeBSD
errno values (EINTR, EINVAL, ECONNRESET, EPERM, EFAULT), which the kernel returns in `RAX` on
the error path; libc translates them to `-1` for ordinary programs, and a direct `syscall`
instruction sees the number itself.

That makes the three readings distinguishable for the first time:

| Return | What it shows |
|---|---|
| a positive errno | the handler ran, parsed the arguments and rejected them |
| `0` | the handler ran and accepted six zeros |
| `-1` | the handler refused, or Sony's filter refused before it; the sweep cannot separate the two |
| nothing | the loader died or stopped answering; says nothing about the handler |

Capture `results/phase15_native_sysent/syscall_isolation_sweep_20261020_213026.json`.

## The port coming back is not the loader coming back (2026-10-20)

Syscall 94 is labelled with the shared `nosys` stub in the 13.60 capture, and the 10-537 sweep
stopped on it: two probes connected, sent and received nothing, then the port refused
connections. A second run did the same at 95. That looked like a parked thread on a syscall
that should not be able to park anything.

`probes/phase17_new_vectors/188a_sys94_repeat.lua` (capture
`results/phase17_new_vectors/188a_sys94_repeat_20261020_210214.txt`) on a fresh loader settles
it. Three rounds of `(0,0,0,0,0,0)`, then fds 1, 2, 0 and 3, then `0x1000` in every slot, with
`getpid` between every call: every 94 call returns `-1`, every `getpid` after it returns
`0x334`, and the script reaches its last line. 94 neither parks nor kills; it refuses.

What did happen is a loader state the wait could not see. After 93's kill the listener accepted
again while the Lua thread never answered: probes were accepted, produced no output at all, and
the console stayed in that state for minutes across several sends. Only a relaunch cleared it.

`loader_is_up()` checks the socket, `loader_answers()` checks that a `print` comes back, and
both drivers now resume only on the second (`c9865fb`). A listener without a thread therefore
reaches a relaunch prompt instead of being swept into. The cost is that this state cannot be
waited out: the sweep stops with the loader open but silent.

## A kill does not prove the slot is absent (2026-10-20)

The rule above was written after 4095 showed that an unimplemented slot kills the process. It
is a one-way implication and it was read as two: an absent slot kills, therefore a kill means
an absent slot. The 601-660 sweep supplies the counterexample.

`622 ipmimgr_call` kills the process when called with six zero arguments. It cannot be absent:
`55c` called it through `make_syscall(622)` with `(cmd, 0, buf, buf, 0x100)` for 400+ command
values and got `ret=0` with `buf[0]=0x800E0001` every time. So a present handler took the
process down on zeros and worked on a real request.

The same ambiguity covers every "absent" reading taken from a zero-argument sweep: 561
`suspend_process`, 562 `resume_process`, 573 `mdbg_call`, 589 `dynlib_dlopen`, 590
`dynlib_dlclose`, 597 `dynlib_prepare_dlclose`, 609, 614, 621, 631, 650, 651 - and 661, 665,
668. All of them have a real handler RVA in the 13.60 capture (`docs/sysent-names-13.60.csv`),
none is the `nosys` stub at `0x265760`.

What survives: 4095 has no handler in any version and kills, so a kill is what an absent slot
looks like. What does not survive: concluding absence from a kill. The honest status is
"kills with zeros", and the follow-up is a probe with plausible arguments - a path string for
`dynlib_dlopen`, a pid for `suspend_process`, a command for `mdbg_call`.

The distinction matters for exploit work in both directions. A kill was being filed as "no
handler, nothing here", which discards the four AIO handlers and every dlopen-style call
without looking. And a `-1` was being read as "dead", when it means the opposite: the handler
ran and checked its arguments, which is the more interesting of the two answers.

## What the tail sweep adds (2026-10-20)

The 677-734 sweep is the first block where every number kills: 677 through 707, thirty-one
in a row, then the loader took more than two minutes to return. Thirty-one consecutive kills
is not thirty-one hostile handlers - the parsimonious reading is that those numbers are past
the end of the table, which is the same shape as 4095.

So there are three readings a kill can have and observation alone cannot separate them:

1. the slot is not implemented (4095, and 677+);
2. the slot is implemented and the zero arguments fault it (622 returns `0` to a real request);
3. the slot is implemented and the kernel kills the caller on purpose.

Case 3 is not hypothetical for this platform: a console kernel that kills on unimplemented
numbers is doing exactly that, and the same policy applied to a privileged call would look
identical from the outside. The practical consequence is the same for all three: a kill is a
result about the *call*, never a result about the *handler*.

## Resolved (2026-10-22): the kill is SIGSYS, not a policy

The three readings above are separable, and the instrument is the signal, because an
absent slot has a body: the shared `nosys` trampoline. Probes 561, 562, 631, 650, 651,
570 and 573 all decode to the same 4,096 bytes (SHA-256
`c22afc5c7cc3a6c3a1387f51b7dfa46b1ee55bb4b399853fd85ca6e05596c78e`, entry RVA
`0x265760`, `jmp 0x5620e0`). That body locks the process, builds a signal record with
**number 12** at `+0x10` and code `0x10006` at `+0x18`, delivers it, and returns `ENOSYS`.
Signal 12 is SIGSYS, whose default action is termination. The process does not die because
the kernel decided to shoot a caller - it dies because an uncaught signal is fatal.

Ignore SIGSYS (`sigaction`, syscall 416, handler `SIG_IGN` = 1) and the same calls return
(probe 353a, capture `results/phase17_new_vectors/353a_sigsys_nosys_20261022_163648.txt`):

| slot | with the default disposition | with SIGSYS ignored |
|---|---|---|
| 562 | terminated | `-1` |
| 650 | terminated | `-1` |
| 651 | terminated | `-1` |
| 665 | terminated | `-1` |
| 668 | terminated | `-1` |
| 631 | terminated | `-1` |
| 661 | terminated | `-1` |

The same flip holds for the rest of the death-on-touch set (probe 353b, capture
`..._353b_lethal_reclassify_20261022_163752.txt`): **189, 306, 307, 308, 337, 570 and 573**
each returned `-1` instead of ending the process, and so do the four that were still
unexplained - **568, 569, 571 and 621** - for six zeros and for three pointer-and-length
shapes each (probe 354a, capture `..._354a_unexplained_kills_20261022_164235.txt`).

### What this settles and what it does not

- **570 and 573 are absent by byte evidence as well as by the flip** - their 13.60 bodies
  are the shared `nosys` trampoline.
- **189 is present.** `fstat(fd, buf)` on an open `/app0/eboot.bin` descriptor returned `0`
  and wrote a stat record (`2909FFAA 00000017 0000816D ...`) **with the default
  disposition** - no signal was involved (probes 353c/353d, captures
  `..._353c_absent_or_rejecting_20261022_163852.txt` and
  `..._353d_fstat_kldstat_20261022_163923.txt`). The "fstat(189) kills the process" record
  from 152j does not reproduce: `189(0,0,0,0,0,0)` returns `-1` and the process survives
  (353d section E). That dead-end entry is wrong.
- **306, 307, 308 and 337 return `-1` for every shape tried** under SIG_IGN, including a
  `kld_file_stat` whose version field is `0x81C`, `0x60` or `0x1C`, and `kldnext(0)` /
  `kldfind(0)`. No dossier exists for them in the 13.60 set. The flip plus the absence of
  any accepted shape is consistent with them being the same trampoline; it is not byte
  evidence.
- The trampoline returns `-1` here, not the `78` its 13.60 dossier predicts. Either the
  14.10 body differs or the value does not survive the fcall path; this is left open rather
  than assumed.

### What the whole range looks like under `SIG_IGN`

Walking 400-676 with six zeros and SIGSYS ignored makes "kills" mean one thing only, because
an absent slot cannot kill any more: it returns `-1`. The walk was split where a call parks
or faults on purpose:

| range | result |
|---|---|
| 400-429 | every number `-1` except **429, which returned `14`** (`sigwait` in the 13.60 names) |
| 430 | `thr_create` with a zero context parks the caller for good - the probe wedged, not died |
| 451-454 | `-1` |
| **455** | **terminated the process** with six zeros - `thr_new`; with a real `thr_param` it returns 0 and starts a thread (383a) |

455 is not a faulting handler. Probe 383a gave it a real `struct thr_param` - `start_func`
at eboot's `jmp $`, `arg` at a mapped page, a mapped stack, and `tls`/`rtp` null - and it
returned 0 with the process still alive. A second call with `param_size = 0x100` returned
-1, so the size is bounded the way the FreeBSD source says it is. The kill with six zeros is
the child: a zeroed `thr_param` has `start_func = NULL`, the new thread begins at address 0
and its SIGSEGV takes the process down. **622 is therefore the only handler in this walk that
dies on its own.**

456-500 came back clean as well: every number `-1` except **475 and 478, which returned 0**
(`pread` and `lseek` in the 13.60 names - both accept a zero argument set). The walk then
stopped answering after 500 without dying, which is the signature of a call that blocks
rather than one that faults, so the blocking slot is inside 501-525. 522 `pselect` is the
obvious candidate: `pselect(0, NULL, NULL, NULL, NULL, NULL)` waits for ever by definition.
The bisect of that window is probe 354e (capture of 456-500: `..._354d_range_456_20261022_165436.txt`).

### The measured table under `SIG_IGN`

| range | what it returned |
|---|---|
| 400-429 | `-1` for every number except **429 = 14** (`sigwait`) |
| 430 | `thr_create` with a zero context parks the caller; the probe wedged, it did not die |
| 451-454 | `-1` |
| 455 | **terminated the process** with six zeros - `thr_new`; a real `thr_param` returns 0 (383a) |
| 456-500 | `-1` except **475 = 0** (`pread`) and **478 = 0** (`lseek`) |
| 501-521 | **every number `-1`**; 516 `cap_enter` was skipped because it would leave the process in capability mode |
| 522 | `pselect` blocked: this is the slot that ended the 456-500 walk |
| 523-620 | `-1` except **548 = 0, 563 / 564 / 565 / 566 = 0, 585 = 1, 596 = 0, 602 = 0, 606 = 0, 617 = 0, 620 = 0** |
| 621 | the shared nosys trampoline |
| 622 | **terminated the process**, and took the loader with it - the one real handler in the walk that dies on zeros |
| 623-676 | `-1` except **624 = 3376** (`get_vm_map_timestamp`, the counter probe 52b identified), **638 / 639 = 0** (`utc`/`localtime`), **640 = 0**, **643 = 0**, **653 = 22** (`blockpool_open` returning a descriptor), **657 = 0** and **675 = 0** |

Two results matter beyond the bookkeeping. `585 is_in_sandbox` answers **1**, which is the
first direct confirmation from the kernel that this process is sandboxed rather than merely
written off by a policy check. And 622 is the only number in the whole 400-676 span that kills on six
zeros with SIGSYS ignored, which makes it the only handler there whose death is a fault
rather than an unimplemented slot. The walk is complete apart from three slots that are
excluded for stated reasons: 430 (`thr_create` with a zero context parks the caller), 516
(`cap_enter` would change the process for good) and 522 (`pselect` waits by definition).

What 622's death is not: it is not a dereference of the struct it copies. Probe 355c filled
all 0x40 copied bytes with a pointer to the page they live on - a valid mapping - and the
call still terminated the process. A copy of a single byte also dies (245a). So the fault
happens before the copied data is used, which leaves a device lookup on arg1 that finds no
device and is dereferenced anyway. That is a denial of service and has no part we can aim.

### Re-testing the old negatives that were measured against dead calls

55a set all 32 chicken-switch bits with 643 and concluded they control nothing,
because `mprotect(RWX)`, `fork` and `kldstat` were unchanged. `kldstat` is the nosys
trampoline (353b), so a third of that test measured an absent slot. Probe 356a repeated the
switch against gates whose refusal is real:

| check | before 643 | after 643 |
|---|---|---|
| 585 `is_in_sandbox` | 1 | 1 |
| 618 (capability bit 62) | `-1` | `-1` |
| 646 (capability bit 62) | `-1` | `-1` |
| 532 cmd `0x00` (credential predicate) | `-1` | `-1` |
| `mprotect(RWX)` on a GPU mapping | `-1` | `-1` |

So the conclusion stands, and now it stands on gates that exist. The same probe found that
**482 `shm_open` works**: `/omp356a` with `O_CREAT|O_RDWR` returned a descriptor, `ftruncate`
succeeded, `mmap` mapped it and a write read back, `483 shm_unlink` returned 0. The jail
refuses `O_CREAT` under `/savedata0` (`openat` returned `-1` there) but the shared-memory
namespace is writable, which is the one new capability this round produced - storage, not
kernel access.

### The method this changes

Any slot that might be absent should be probed with SIGSYS ignored, because with the
default disposition the experiment destroys its own result. That retires the caution "a
kill is a result about the call, never about the handler" for the numbers measured here:
for them the kill was never about the handler at all.

Two exclusions. 677 and 678 take the *game* down rather than just the loader process, so
they are a different failure and remain untested this way. And a real handler that faults on
bad arguments still kills the process with SIGSYS ignored - 601's commands 0x03 and 0x04 do
exactly that - so the flip separates "absent" from "present and faulting", while a plain
`-1` under `SIG_IGN` still needs an argument shape before it means anything.
