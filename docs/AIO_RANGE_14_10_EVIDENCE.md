# The AIO 661-670 "hard wall" rests on one syscall

Status: **scope correction.** No new console evidence. This note re-reads the
captures the current verdict is built on and shows that nine of the ten
numbers in the range were never executed.

`CLAUDE.md`, `docs/STRATEGY.md` and `docs/ATTACK_SURFACE.md` all state that AIO
661-670 is a confirmed hard wall on 14.10. The supporting citations are probe
54c and section G of probe 54f. Both captures stop inside syscall 661.

---

## 1. What the captures actually contain

| capture | size | last line |
|---|---|---|
| `results/54c_aio_full_attack_20261018_090527.txt` | 190 bytes | `  [BEFORE] sys 661 (event_create, narg=4)` |
| `results/54f_kaslr_deep_20261018_090603.txt` | 15,257 bytes | `--- G: AIO event subsystem (661/662/668 — obfuscated kptr leak) ---` |

The 54c matrix prints `[BEFORE] sys N`, then calls, then prints either
`[RETURNED]` or `[ERROR]` (`probes/phase14_final_push/54c_aio_full_attack.lua:180-193`).
The capture contains the `[BEFORE]` line for 661 and no result line for it and
nothing at all for 662-670. Section G of 54f iterates `for num = 661, 670`
(`probes/phase14_final_push/54f_kaslr_deep.lua:461`) and prints a result line
per iteration; the capture ends at the section header, before the first result.

So the evidence is:

- 661 was entered and the process did not return a value — twice, with two
  different argument shapes (all-zero in 54c; `(0, outbuf, 0x200, 0, 0, 0)` in
  54f).
- 662, 663, 664, 665, 666, 667, 668, 669 and 670 were **never called** in probes 54c/54f.

**CORRECTION (2026-10-23):** The 352-series probes later called these successfully: 669 (aio_submit) works, 664 (aio_poll) cycles states, 666 (aio_cancel) works, 662 (aio_delete) works. Real data moves via AIO read of /dev/urandom and AIO write into socketpair. 661 stays lethal; 670 unknown. See `results/phase*_352*` captures.

This is not a subtle reading of 54c/54f specifically. The capture sizes make it unambiguous: 190 bytes
cannot hold a ten-number matrix, and section G has no output after its header.

The same truncation pattern appears in probe 52a
(`results/phase13_52batch/52a_survey_627_676_20261018_103436.txt`), whose
capture ends at `P1 num=631 calling now...` after 627-630 returned
`PCALL-FAIL`. One lethal number ends the connection, so every number after it
in that connection is unmeasured.

## 2. Why the truncation is structural, not bad luck

`tools/send_probe.py` opens one TCP connection per probe, and the loader spawns
a fresh process per connection (`docs/USERLAND_ENTRY.md`). A probe that walks a
range inside a single connection therefore has exactly one lifetime to spend.
The first number that terminates the process consumes it, and the remaining
numbers are never executed — no output, no error, no record that they were
skipped.

That is what happened twice. It will happen to every future in-connection
range walk over a range that contains a lethal number.

## 3. What this does and does not show about 14.10

**Shown:** syscall 661 terminates the process on 14.10 for at least the two
argument shapes tested. Two runs, two shapes, same result.

**Not shown:** anything about 662-670. The current verdict generalizes from 661
to the whole range on the assumption that the numbers form one subsystem with
uniform behaviour.

That assumption is already questionable from the 13.60 artifacts. Resolving
every thunk in `docs/dumps_13.60/sysent_index.json` gives:

| syscall | 13.60 body | first instructions | classification |
|---|---|---|---|
| 661 | `0x3af8f0` | `push rbp; mov rbp,rsp; xor esi,esi; pop rbp; jmp 0x265760` | nosys stub |
| 662 | `0x3af900` | arg shuffle from `[rsi]`/`[rsi+8]`/`[rsi+0x10]`, then `jmp 0x3af920` | AIO batch delete |
| 663 | `0x3b01f0` | arg shuffle, `jmp 0x3b0210` | AIO batch wait |
| 664 | `0x3b0fb0` | arg shuffle, `jmp 0x3b0fd0` | AIO batch poll |
| 665 | `0x3b1670` | `jmp 0x265760` | nosys stub |
| 666 | `0x3b1680` | arg shuffle, `jmp 0x3b16a0` | batch cancellation |
| 667 | `0x4a31a0` | own prologue, five callee-saved pushes | process/thread record enumeration |
| 668 | `0x3af8e0` | `jmp 0x265760` | nosys stub |
| 669 | `0x3b2060` | `mov eax,[rsi]; mov rdx,[rsi+8]; ...` | separate body |
| 670 | `0x3b28d0` | own prologue | separate body |

Three of the ten are unsupported-syscall stubs and one (667) is not part of the
AIO cluster at all. The range is not homogeneous in 13.60, so "AIO 661-670" is
a label, not a subsystem.

**The interesting inconsistency:** 661 is a stub that returns ENOSYS in 13.60,
and it kills the process on 14.10. Those are incompatible behaviours. Either
14.10's sysent layout differs from 13.60's at this index, or the number is
handled differently. Either way, the 13.60 map cannot be assumed to describe
14.10 — which is exactly the assumption the range-wide verdict depends on.

**Counter-check that the range is not simply unreachable:** high syscall
numbers do work on 14.10. Probe 55e calls 674 and gets `ret=0` with 316 VM
regions; probe 54f's section B calls 649 and gets `ret=0` with module
addresses. Lethality at 661 is specific to that entry, not a property of the
number being large.

## 4. The probe labels in 54c are also wrong

`probes/phase14_final_push/54c_aio_full_attack.lua:165-176` labels the range
`event_create`, `event_query`, `aio_multi_wait`, `event_signal`, and so on.
Those names came from the handler analysis that
[HANDLER_CLAIM_CORRECTIONS.md](HANDLER_CLAIM_CORRECTIONS.md) corrects. Per the
repo's own `results/kernel_handlers/INDEX.md:144-151`, the names are batch
delete / batch wait / batch poll / cancellation propagation, and 667 is not in
the cluster. Any follow-up sweep should use the index names, not the probe's.

## 5. What to do instead

Run one number per connection. `tools/syscall_isolation_sweep.py` does that:

```bash
python tools/syscall_isolation_sweep.py --ps5-ip 10.0.0.96 --range 661-670 --repeat 2 --save
```

Each number gets its own connection, its own sentinel line printed before the
call, and a classification:

| status | meaning |
|---|---|
| `RETURNED` | the call returned; the value is recorded |
| `RAISED` | `pcall` caught a Lua error |
| `KILLED_IN_CALL` | the sentinel printed and no result followed — the process died inside the call |
| `NO_OUTPUT` | connected and sent, nothing came back |
| `CONNECT_FAILED` | could not open a connection; the sweep stops rather than misreporting |

The sentinel is what makes `KILLED_IN_CALL` meaningful: it distinguishes "died
inside this syscall" from "never got this far", which a bare missing line
cannot do.

Expected outcomes worth distinguishing:

- 661 kills and the others return → the range was closed on one number; the
  rest are measurable and should be probed on their own terms.
- 661 kills and 662-670 also kill → the range verdict was right, and now it has
  ten data points instead of one.
- Some numbers return → the range verdict is wrong and there is a new attack
  surface.

## 6. Limits

- Static artifact analysis plus re-reading existing captures. No console was
  contacted; no probe was sent for this note.
- The 13.60 dumps are an unverified acquisition (`docs/dumps_13.60/README.md`),
  and no authenticated 14.10 kernel image exists in the repository.
- "661 kills" is established for two argument shapes. Whether a different
  argument shape returns is untested — the 54c matrix used all-zero arguments
  and section G used a single buffer layout.
- The classification table assumes a crash inside the call is the only way to
  lose the process. A loader-side timeout would also end a connection; the
  sweep's `NO_OUTPUT` status keeps that case separate from `KILLED_IN_CALL`,
  but a timeout on the *first* number looks the same as a slow handler.

## First isolation sweep: 662-664 return, 665 kills (2026-10-20)

`tools/syscall_isolation_sweep.py --range 662-670`, one minimal probe per number in
its own connection, six zero `uint64` arguments (54c's argument shape).

| syscall | status | detail |
|---|---|---|
| 662 | RETURNED | `-1` |
| 663 | RETURNED | `-1` |
| 664 | RETURNED | `-1` |
| 665 | KILLED_IN_CALL | process terminated inside the call |
| 666-670 | not measured | the process was already gone |

Three of the four numbers reached do not kill, which is the first direct evidence
against the range-wide "AIO hard wall" reading. 665 kills, and 665 is the number the
13.60 capture labeled a `nosys` stub (`jmp 0x265760`) — a stub that returns ENOSYS in
13.60 does not terminate the process, so either that label or the 14.10 handler differs.

Capture: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_182830.txt`.
Measuring 666-670 needs a relaunch before each lethal number, because the process does
not come back on its own.

## Reinterpretation: the kills were absent slots (2026-10-20)

Probe 173a shows `make_syscall(4095)` also terminates the process. 4095 cannot have a
handler, so a kill means the slot is absent rather than the handler being hostile. The
range's lethal numbers 661, 665 and 668 are therefore absent on 14.10 — 665 and 668 are
labeled `nosys` stubs in the 13.60 capture, which agrees.

That flips the reading of the survivors: 662, 663, 664, 666, 667 and 669 return `-1`,
which proves those handlers are **present and reachable** and rejected six zero arguments.
The part of this range worth attacking is the six present handlers, not the three that
killed the process. See `docs/SYSCALL_ABSENT_VS_LETHAL.md`.

## The batch calls work once they are given their own shape (2026-10-22)

`-1` to six zeros says a handler rejected an empty argument list, not that it cannot
work. The 13.60 contracts name the shape of three of the six present survivors: an id
array, a count and an output array.

| syscall | contract | 301a-303a result |
|---|---|---|
| 662 | `ids, count, results` | `ret=0`, one status dword per id |
| 663 | `ids, count, states, wait_mode, timeout_inout` | `ret=0`, same status |
| 664 | `ids, count, states` | `ret=0`, same status |

`probes/phase17_new_vectors/301a_thread_state_calls.lua` passed `count = 1` with a
mapped output page and got `ret = 0` with `0x80020000` in the first dword: an id this
process had invented (`thr_self` had been called with a null out-pointer, so the array
held `0xFFFFFFFFFFFFFFFF`). `302a` took the real kernel thread id (`0x18E65`) and got
`0x80020003` instead - a different Sony status, again per id. `303a` tried the process
id (`0x6A`) and got the same `0x80020003`.

So the three calls read `count` ids, look each one up, and write one status per entry.
The id they accept is not a kernel thread id and not a process id. In 13.60 the three
are labelled AIO batch delete, batch wait and batch poll, which makes the ids **AIO
request ids** - and those can only come from a submission path, which on 14.10 is 661,
the number that kills before it returns. The batch calls are therefore working code
guarded by an object this process cannot create.

The two bounds questions were measured and both came back bounded: `count = 0x400`
against a `0x1000` id page returned `-1` rather than reading out of the page, and
`count = 4` with the output array ending four bytes before the page boundary returned
`0` without faulting. Neither is a length the handler trusts past the memory it can
reach, so there is no overrun to aim.

Captures: `results/phase17_new_vectors/301a_thread_state_calls_20261022_115421.txt`,
`302a_thread_state_ids_20261022_115439.txt`,
`303a_thread_state_bounds_20261022_115517.txt`.
