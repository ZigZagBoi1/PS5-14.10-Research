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
- 662, 663, 664, 665, 666, 667, 668, 669 and 670 were **never called**.

This is not a subtle reading. The capture sizes make it unambiguous: 190 bytes
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

## 662 runs its delete body from a game process (2026-10-24)

Probe `probes/phase17_new_vectors/486a_aio662_gate.lua`, capture
`results/phase17_new_vectors/486a_aio662_gate_20261024_110855.txt`.

The 13.60 listing puts a process-mode test at `0x3af9c6` **before** the count
guard at `0x3af9f7`, and the guard accepts only `count ∈ [1, 0x80]`
(`lea eax,[r15-0x81]; cmp eax,0xffffff7f; ja body`).  Calling `662` in that
body-reachable range on 14.10 gives:

| count | return | results array |
|---|---|---|
| 1 | `0` | `80020003` |
| 4 | `0` | `80020003` ×4 |
| 0x10 | `0` | `80020003` per entry |
| 0x80 | `0` | `80020003` per entry |
| 0x81 | `-1` | untouched |
| 0 | — | binary garbage on the socket, process gone |

`0x80020003` is the per-entry status the 13.60 body writes for an id it cannot
resolve (`mov dword [rdx+rbp*4], 0x80020003` at `0x3afbe2`), and `ret=0` is the
body's success return. So on this firmware the delete body **is reachable from a
game process**: whatever the 13.60 gate does, 14.10 does not block the call
before the body. The `-1` at `0x81` is the count guard, and on 14.10 it returns
`-1` rather than the `0x16` the 13.60 listing implies.

The `count=0` row is unexplained. It produced no return and no clean end of
output, and the next connection was refused. Whether the handler wrote past the
results buffer or the loader died flushing its own output cannot be told from
this capture.

`probes/phase17_new_vectors/486b_aio_create_probe.lua` then called `668`
(`aio_create`) with `(page, 0x100, 0x10)` and got no return at all: the process
was gone and the next connection refused. So the create path is still lethal
while the delete path answers.

**Not established:** that the delete race can be won, that any id can be made
to resolve, or that a `count=0` corruption is real. What changed is the premise:
`662` is not walled off from a game process on 14.10.

## The id is (context << 16) | slot, and no context exists in this process (2026-10-24)

Probes `486e`, `486g`, `486h`, `486j` under `results/phase17_new_vectors/`.

`486e` sent dword ids `0..7`, `0..63` and `0xFFFF`; `486g` retried with qword
strides. Every entry came back `0x80020003` and the call returned `0`. The
13.60 loop at `0x3afbaa` explains why the id **value** looked irrelevant to us:

```
3afbaa  mov  r15d, dword [rsi + r13*4]   ; id = ids[i]
3afbb6  mov  r14d, r15d
3afbb9  sar  r14d, 0x10                 ; context = id >> 16
3afbbd  and  r15d, 0xffff               ; slot    = id & 0xffff
3afbc8  cmp  r14d, 0x80                 ; context must be < 0x80
3afbd5  je   0x3afb90                   ; otherwise status 0x80020003
3afbd7  cmp  r15d, r12d                 ; same slot as previous id -> cached object
3afbda  jne  0x3afc20                   ; else look the context up
3afbdc  test rax, rax
3afbdf  jne  0x3afc58                   ; no cached object -> 0x80020003
```

So an id is `(context << 16) | slot`, with `context < 0x80` and `slot != 0`.
Our ids were `0x41424344` (context `0x4142`, rejected outright), `0..7`
(context 0, slot 0..7) and `65535` (context 0, slot `0xffff`) — none of which
names a context the process owns.

`486h` then scanned **all 127 contexts with slot 1, then with slot 0**: zero
hits, every status `0x80020003`. On this console no AIO context is registered
for the game process, so the delete path has nothing to reach.

`486j` closed the other half: `668` (`aio_create`) dies with `(page, 0, 0)`,
just as it did with `(0,0,0)` and `(page, 0x100, 0x10)`. Three argument shapes,
three process deaths, no return. The create path cannot supply the missing
context from a game process, and `661` (`aio_submit`) dies on `(0,0,0)`.

**Not established:** whether a context appears when the game itself performs
I/O, and whether `662`'s lookup would then resolve. What is established is that
the reachable member of the family is a no-op on a freshly launched game.

## 669 create works on 14.10, and 662 deletes a polled object (2026-10-24)

The `661`-`670` family had been read as gated: `662` was reachable but its delete
body wrote `0x80020003` for every id, and no AIO object existed to delete. The
missing piece was not a privilege gate but the fifth argument of `669`.

| call | result |
| --- | --- |
| `669(1, data, 4, 1, 0)` | `-1` |
| `669(1, data, 4, 1, data)` | `0`, writes the new id to the fifth-argument page |
| `669(1, data, 1..0x80, 1..3, out)` | `0`, ids returned (`0x4206`, `0x0207`, `0x0208`, ...) |
| `662([id], 1, res)` on a fresh object | `ret=0`, status `0x80020010` |
| `662([id], 1, res)` after `664([id], 1, out)` | `ret=0`, status `0` |
| `662([id], 1, res)` a second time | `ret=0`, status `0x80020003` |
| `662([id, id], 2, res)` in one call | `[0]=0`, `[1]=0x80020003` |

`669` takes `uap[0x00]` flags (low 12 bits `1` or `2`), `uap[0x08]` user buffer,
`uap[0x10]` count `1..0x80`, `uap[0x18]` mode `1..3` and `uap[0x20]` an out
pointer; without a mapped out pointer it returns `-1`. The 13.60 body at
`0x3b2060` allocates an id-table entry (`0x3998e0`), mallocs `count*0x28`,
copyins the caller buffer and writes the id to `uap[0x20]`.

The two failing statuses are distinct and were measured separately:

* `0x80020003` comes from `0x3afce7` when the slot holds no object (every id in
  `486k`'s 16,256-id scan, and the second delete of a deleted id).
* `0x80020010` comes from `0x3aff61` when the object exists but the state gate at
  `0x3afd76` (`mov eax,[obj+8]; add eax,-3; cmp eax,2; jae`) fails, and also from
  `0x3afdd4`/`0x3afe0a`. `664` poll is what moves a request into the state the
  gate accepts; `666` cancel does not.

Consequences:

* the delete body is reachable with real objects, so the lock drop at `0x3afc67`
  followed by the unchecked re-read at `0x3afd0c` is a live code path on 14.10;
* the unlock is per call, not per list entry: one call carrying the same id twice
  reuses the ordinary lookup and reports `0x80020003` for the second entry, so a
  duplicate id cannot self-race;
* `664` writes 16 bytes to the pointer held at request `+0x18`
  (`{status 0x80020005, state 3}`); an unmapped user address (`0x1000`,
  `0x700000000000`) leaves the call returning `0` and the console alive, so the
  store is range-checked like a copyout and is not a raw kernel store.

Not established:

* whether 14.10 contains the 14.20 generation-id revalidation described in the
  public write-up - the object is found and freed, but no free/reuse is observed
  from a single thread;
* the race itself: it needs two concurrent `662` calls. The loader's
  `/savedata0/thread.lua` can start a second thread (`Thrd_create(..., longjmp,
  jmpbuf)` pivoting to a ROP chain) and accepts a `make_syscall` table, but its
  own source warns that running Lua in a new thread "has a chance to crash the
  game process because of unfixed race condition in native primitives" - it did,
  on the first spawn, and the process died;
* any use of a kernel address as the `+0x18` out pointer.
