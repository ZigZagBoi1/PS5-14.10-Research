# The AIO 661-670 "hard wall" rests on one syscall

Status: **scope correction.** No new console evidence. This note re-reads the
captures the current verdict is built on and shows that nine of the ten
numbers in the range were never executed.

`CLAUDE.md`, `docs/STRATEGY.md` and `docs/ATTACK_SURFACE.md` all state that AIO
661-670 is a confirmed hard wall on 14.10. The supporting citations are probe
54c and section G of probe 54f. Both captures stop inside syscall 661.

---

## Two deletes report success, but the free is guarded (2026-10-24)


### `aio_multi_wait` (663) validates like the others (2026-10-24)

Decoded from the 13.60 body (`0x8ad70384`-`0x8ad70576`, base
`0xffffffff8a9c0000`):

```
70384  rcx = [rbx+0x70]        ; count
70388  eax = rcx - 0x81
7038e  cmp eax,0xffffff7f / ja ; EINVAL unless 1 <= count <= 0x80
703b8  cmp r13d,3 / jae       ; EINVAL for the mode argument >= 3
703d4  lea eax,[rcx*4+0xf]    ; count >= 2: alloca count*4 on the kernel stack
70403  call 0x8ac18ff0        ; bzero of that buffer
70468  call 0x8ac19280        ; copyin(count*4) from the user id array
704f3  copyin(4)              ; a 4-byte mode/timeout field
70517  call 0x8b4c78d0        ; the same aio state gate as create/delete
70540  malloc(count*0x18)     ; one result record per id
70576  imul rdi,r14,0x38      ; and a count*0x38 block
```

The stack allocation is bounded by the same `0x80` count ceiling, so it is not
the block-mode copyout shape. The wait itself is `0x8b5b1770` on the object's
event, and on 14.10 a freshly created object is already state 3 (poll returns
`3` immediately), so a wait returns at once: the submit that would leave an
object pending is gated. `663` is therefore useful here only as an argument-4
test - its fourth argument is the timeout - which is what probe 559b uses it
for via the thread context.

### The re-lookup compares slot *and* generation (2026-10-24)

The delete's second lookup is `0x8ad5a2a0`, and it does not accept a stale id.
Decoded from the 13.60 text (`0x8ad5a2a0`, base `0xffffffff8a9c0000`):

```
a2b4  cmp esi,0xffff          ; id must fit 16 bits
a2d8  and ebx,0x1fff          ; slot   = id & 0x1fff   (13 bits)
a304  ...  shr eax,7          ; page   = slot >> 7
a363  r13 = [table + page*8]  ; 0x1800-byte page of 128 x 0x30 slots
a36b  eax = [r13 + rcx + 0x28]; the slot's generation
a370  shl eax,0xd             ; generation in id bits 13..15
a376  or  eax, ebx
a378  cmp eax, r14d           ; reconstructed id == requested id
a37b  jne -> not found
a384  cmp word [r13+0x26],3   ; slot state must be 3 (completed)
a395  cmp [rbp-0x38], eax     ; and the caller's expected count must match
```

So an id is `slot | generation << 13`, `0x8ad598e0` hands out pages of
`0x1800` bytes (128 slots of `0x30`), the generation lives at `slot+0x28` and
increments on every reuse - which is why successive creates in one slot give
`0x2234`, `0x4234`, `0x6234`. A delete that started on an old id cannot find a
slot that was recycled in between: the generation differs and the lookup
returns NULL, which is the `0x80020003` we measure.

The 14.20 note's "generation-ID check rejects a reused slot before freeing"
therefore describes a check this path already performs on 14.10. What 14.10
lacks is not a check but a second racing actor that could reuse the slot with
the *same* id inside the window, and that needs eight create/delete cycles
between the unlock (`0x8ad6fe63`) and the re-lookup (`0x8ad6fe7c`) - two
adjacent instructions.




### Simultaneous deletes still only produce a double success (probe 562a, 2026-10-24)

Spawn latency is about a millisecond, which is four orders of magnitude wider
than the free window, so 523c/556a never proved that two deletes cannot
overlap. `562a_aio_wake_burst_race.lua` removes the skew: every child blocks
in `_umtx_op` op 2 (`UMTX_OP_WAIT`, value 0) on a shared word and the parent
releases all of them with one op 3 (`UMTX_OP_WAKE`, n = 16), so the deletes
enter the kernel inside the same wake batch. (Op numbers matter: 2 is WAIT,
3 is WAKE, 5 is MUTEX_LOCK - the first revision of this probe used 5 and every
child simply took the mutex.)

Five children, one id, 100 rounds:

```
[C] rounds: none=0 one=61 two=13 three=26 spawnfail=false
    alive=true
```

A hit round prints the five statuses, for example
`st=00000000 00000000 80020003 80020003 80020003`. Up to five deletes of the
same id return success in one round, and 26 rounds had three or more. Every
one of those rounds was followed by a create/poll/delete health cycle, and
every hit round by six more; all of them returned `0`.

That health cycle is also the double-free detector. If `C` had been freed
twice the free list would hold the same `0x30` chunk twice, the next
`669` would take it for both `T` and `C`, `C`'s initialiser would overwrite
`[T+0x20]` (the status object `S`) with the CPU id, and the delete's
`mov r14,[r12+0x20]` would hand a CPU id to the event destructor. It never
happened in 100 rounds. The losers reach `0x8ad6feb7`, find `[W+0x18]`
already zero and take the `je` at `0x8ad6fec3`, which returns 0 without
freeing.

So the delete is a double *success* even under a wake burst, and the only
remaining shape the 14.20 note describes - a *create* slipping between the two
lookups - is blocked by the generation check measured in probe 561a.

### The window between the re-lookup and the free is ten instructions

The delete body at `0x8ad6fe7c` calls the id lookup (`0x8ad5a2a0`). Nine
instructions later it reads the slot again and, a few more on, the context it
is about to free:

```
8AD6FE7C  call 0x8ad5a2a0        ; re-lookup by id
8AD6FE81  test rax, rax / je    ; -> 0x80020003 when the id is gone
8AD6FE92  movzx r8d, word [rax+2]   ; entry count
8AD6FE9B  mov [rbx+0x20], rax       ; entry saved
8AD6FE9F  mov r12, [rcx + rdx*8]    ; work item for the slot, re-read here
8AD6FEA3  cmp r8w, 1 / jne ...      ; count-1 branch
8AD6FEB7  mov r14, [r12+0x18]       ; the 0x30 context
8AD6FEC3  test r14, r14 / je        ; already-cleared guard
```

Everything a racing thread could disturb - the slot pointer, the entry count,
the context pointer - is loaded inside those ten instructions. A create that
reused the slot before `0x8ad6fe9f` would have to carry the *same* generation
as the id being deleted for the re-lookup to return at all, and one create
advances the generation by one (probe 561a). That is the whole window: eight
create/delete cycles inside roughly ten instructions.

### A stale id cannot name a live object (probe 561a, 2026-10-24)

`561a_aio_generation_wrap.lua` runs twelve create/poll/delete cycles in one
process. Every cycle reuses the same slot and the generation walks `0..7` and
wraps: ids `00004205, 00006205, 00008205, 0000A205, 0000C205, 0000E205,
00000205, 00002205, 00004205, ...`. The ninth id is byte-identical to the
first, so the id space really does recycle after eight uses.

That is exactly the precondition the 14.20 note needs, and it still does not
produce a hit: with a live object at `0000C205`, deleting the stale
`00004205` returns `0x80020003` and leaves the live object deletable (`0`).
Because the id *is* `slot | generation << 13`, two objects in one slot can
never carry the same id at the same time - the id a stale delete holds can only
match the object that currently owns it. There is no stale-id handle to swap.

### The last-item race is serialised too (probe 557a)

`557a_aio_block_last_item_race.lua` builds a block group (`flags 0x1001,
count=4`) so all four items share one `0x30` context, deletes the first three
serially (`0`, `0`, `0`), then launches two children onto the fourth item -
the only delete that takes the `count == 1` branch and frees the shared
context. Result: `0` and `0x80020003`, four follow-up create/poll/delete
cycles clean. Two `thr_new` children start about a millisecond apart, so a
single-call race never overlaps; the earlier `both-zero` results come from
long chains, and the guard makes them harmless.


Probe `556a_aio_double_free_followup.lua` (48 polled ids, one 8-delete smoke
child, then two children each deleting the same 40 ids) produced the familiar
overlap:

| step | result |
|---|---|
| smoke, one child, 8 deletes | 8 x `0`, no other status |
| race, two children, 40 deletes each | `both-zero=25`, `one-zero=15`, `other=0` |
| four create / poll / delete / delete-again cycles | status `0`, then `0x80020003` every time |
| three fresh create/poll/delete cycles afterwards | `0` each |

The overlapping statuses are *not* two frees. The delete tail guards both
destructive operations with a test-and-clear of the same word:

```
3afeb7  mov  r14, [r12+0x18]        ; the 0x30 context
3afec3  test r14, r14
3afec6  je   0x3afefe               ; already cleared -> skip refdec and free
3afec8  mov  rdi, [r14+0x10]
3afed1  call 0x8ac69670             ; refdec
3afed6  mov  qword [r14+0x10], 0
3afee8  call 0x8b5c8df0             ; free(context)
3afef5  mov  qword [r12+0x18], 0    ; clear, after the free
3afefe  cmp  word [r8], 1
3aff09  mov  r14, [r12+0x20]        ; the 0x58 status object
3aff0e  test r14, r14
3aff11  je   0x3aff89               ; already cleared -> skip
3aff17  mov  qword [r12+0x20], 0    ; clear, before use
```

A caller that finds `[W+0x18]` already zero jumps to `0x3afefe` and returns
`0` without touching the context; the same shape protects `[W+0x20]`. Two
deleters therefore report success twice and free once, which is exactly what
the follow-up cycles show: the free list carries no duplicate, so the next
create/delete behaves normally.

What the 14.20 generation-ID check would close is the other window: the first
lookup at `0x3afd14` is followed by an unlock and a re-lookup at `0x3afe6c`,
and if the slot were freed and *reused by a new object* in between, the delete
would destroy the new object's context. Reaching that needs a create (five
arguments, so `R8`) to land inside the window from another thread. No readable
module carries `pop r8`, `pop r9` or `pop r10` (probes `548a`, `554a`), and the
loader's stub does not translate `RCX` into `R10` (probes `552a`, `553a`), so
the chain route cannot do it.

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

## Two threads can delete the same aio id and both report success, and nothing comes of it (2026-10-24)

Two `thr_new(455)` children deleting the same 100 aio ids returned status `0` for both
of them on 54 ids, while a serialized second delete returns `0x80020003` for all 64 ids
in the control (`498a`). The obvious reading is that both callers ran the last-item path
and both freed the `0x30` context `C`, a double free. That reading is wrong, and the
probes below show it.

What actually happens, from the 13.60 delete body (file offsets):

```
3afc2a  call 0x8ad59eb0          take the table lock
3afc67  call 0x8ad59e20          predicate: word[handle+0x22] & 1
3afd0c  rax = [r12+0x28]          slot array, first re-read
3afd14  r14 = [rax+rcx*8]         item for this index
3afd18  test r14,r14 / je        empty slot -> 0x80020003 (0x3aff34)
3afd72  r14 = [r14+0x20]          S
3afd76  eax = [r14+8]; add -3     state must be 3 or 4, else 0x80020010 (0x3aff61)
3afe63  call 0x8ad59eb0          LOCK again
3afe7c  rax = lookup2(id)         second lookup by id
3afe9f  r12 = [rcx + rdx*8]       item re-read under the lock
3afec8  rdi = [r14+0x10]          ref object
3afecc  test rdi,rdi / je 3afede  null -> skip the release, still free
3afed1  call 0x8ac69670           release
3afed6  [r14+0x10] = 0
3afee8  call 0x8b5c8df0           free(C)
3afef5  [r12+0x18] = 0            clear C under the lock
3aff09  r14 = [r12+0x20]          S
3aff17  [r12+0x20] = 0            clear S under the lock
```

Every free and every clear happens while the second lock is held, and the item is
re-read at `0x3afe9f` under that lock. A caller that loses the race therefore finds
`[W+0x18] = 0` and `[W+0x20] = 0` and frees nothing. Status `0` is not written by the
kernel on success - the caller's buffer is simply left as it was - so two `0` statuses
mean "two callers reached the end without an error", not "two frees".

Three probes were run to test the allocator directly:

| probe | what it does | result |
|---|---|---|
| `524a` | 25 attempts at a single-id double delete | never overlaps: every attempt one `0`, one `0x80020003` |
| `524b` | 100-id race, then four objects alive at once, deletes interleaved | 42 double zeros, four objects and their deletes all normal |
| `525a` | 100-id race while the parent runs 827 create/poll/delete cycles | 55 double zeros, no create/poll/delete anomaly |
| `525b` | 100-id race while the parent creates 200 objects and never deletes them | 55 double zeros, all 200 created, polled and deleted cleanly |

`524b` is the discriminator: after 42 double zeros, a duplicated `0x30` free entry would
have been consumed by the next creates' `T` and `C`, so two live requests would share a
context. Four concurrent requests behaved exactly as they do with zero doubles. The
allocator never saw a duplicate free.

The `0x80020003` in the serialized control comes from the first lookup (`0x3afca8`) or
from the empty-item check (`0x3aff34`), and `0x80020010` from the state gate
(`0x3aff61`). The three statuses are fully accounted for without any corruption.

What a racing thread *can* still do inside the unlocked window is free the slot and have
a new object take it, because the second lookup is by id and the item is re-read from the
new object's slot array. `525b` exercises exactly that: 200 creates while 100 shared ids
are being deleted, so freed slots are refilled continuously. Nothing observable followed.

What this rules out: a double free of `C` from a plain delete-vs-delete race, and any
allocator effect from the double status. What it does not rule out: a reallocation that
lands between the first lookup and the second *lock* specifically, with an object whose
count is 1 and whose id still resolves; that ordering was not hit in 1,027 creates and
200 deletes, and the lookup-by-id may reject a reused slot before the free is reached.

Captures: `results/phase17_new_vectors/523c_aio_delete_race_fixed_20261024_140951.txt`,
`524a_aio_double_delete_single_20261024_141445.txt`,
`524b_aio_double_free_allocator_20261024_141737.txt`,
`525a_aio_delete_create_swap_20261024_142104.txt`,
`525b_aio_fill_freed_slots_20261024_142127.txt`.
Stack rule for a `thr_new` child: `docs/THREADING_ALIVE_14_10.md`.

## Why the two-zero race never frees anything, and how wide the window is (2026-10-24)

Status `0` has two sources in the delete body, and only one of them is a deletion:

```
3afe7c  call 0x8ad5a2a0          second lookup by id, after the lock drop
3afe81  test rax,rax
3afe84  je 0x3affab
...
3affab  dword [status] = 0       second lookup failed -> SUCCESS, nothing freed
```

So a caller whose second lookup finds no item reports success and frees nothing. That,
not a shared free, is what the 42 and 55 "double zeros" were: the loser's second lookup
missed. It also explains why `524b`'s four concurrent requests after 42 doubles behaved
perfectly - no `0x30` chunk was ever freed twice.

The slot allocator makes reuse cheap enough to matter: 24 create/poll/delete cycles
returned the same eight ids in a fixed rotation -

```
000003F8 000023F8 000043F8 000063F8 000083F8 0000A3F8 0000C3F8 0000E3F8
```

- a freed id reappears after exactly **8 creates** (`526b`), about 20 us. So a delete's
  second lookup has a refilled slot available to it almost immediately.

Two probes then tried to land a create inside the unlocked gap:

| probe | shape | result |
|---|---|---|
| `526a` | 3 children x 100 deletes, parent create+poll 400 objects underneath | two-zero 42, `0`x153, `0x80020003`x147, **no `0x80020010`**, all 400 parent objects poll+delete clean |
| `526c` | 6 children x 100 deletes, parent create+poll 700 objects underneath | two-zero 31, `0`x133, `0x80020003`x467, **no `0x80020010`**, all 700 clean |

`0x80020010` is the signature of the second lookup resolving to a freshly created object
(state 1, not yet polled): the state gate at `0x3afd76` rejects it. It never appeared in
900 deletes against 1,100 concurrent creates, so the second lookup never observed a
swapped slot at all.

Reading: the code does free `[item2+0x18]` from the *second* lookup, so the path in the
14.20 note is real. But the delete takes the table lock at `0x3afc2a`, holds it through
the state gate, and drops it at `0x3afe67`; the gap between that drop and the second
lookup call at `0x3afe7c` is a handful of instructions. A create has to land inside it.
Racing syscalls cannot do that - 900 attempts with a deterministic 20 us reuse period
produced nothing. Only a scheduler tick landing in that gap could, which is why the fix
is described as a revalidation after the lock drop.

Not established: that the gap is unreachable under every scheduler state. A preemption
inside those few instructions was not observed and was not forced.

**The Lua harness cannot put two callers inside that gap (2026-10-24, `584a`).** The two
success statuses stop being interesting once the concurrency they need is attempted
deliberately. Two helper threads that spin on a shared word and release together, then
each call `662` over the same 96 ids, kill the process during the first round, before any
status is read - and so does the identical barrier run with the ids split into disjoint
halves, where no shared id exists at all. Two Lua threads executing at the same instant is
itself enough; the delete never gets to race because the harness dies first. Without the
barrier the spawn latency serialises them and the loser reports `0x80020003` on every id,
which is the same result `498a` gets with no threads at all.

Two more facts that make the earlier numbers easier to read: the status page has to be
pre-filled (`0x77777777`), because a call that fails before the copyout leaves it
untouched and a zeroed page then reads as a run of successes - `498a` did that and `568a`
did not. With pre-fill, thirty rounds of overlap-mode deletes return `two-zero = 0`; the
42 and 55 doubles in `524b`/`525a`/`525b` came from zeroed pages, not from shared frees.

Probe: `probes/phase17_new_vectors/584a_aio_race_stress.lua` (modes `overlap`,
`disjoint`, `stagger`; pre-filled status pages; per-round health cycle).

Captures: `results/phase17_new_vectors/526a_aio_slot_swap_window_20261024_144616.txt`,
`526b_aio_id_reuse_20261024_144701.txt`,
`526c_aio_swap_oversubscribed_20261024_144736.txt`.

## The table entry, the two lookups, and the eight-generation id wrap (2026-10-24)

The delete path's second lookup is not a bare array read. Both lookups
(`0x8ad59ee0` and `0x8ad5a2a0`) are the same algorithm:

```
399ecc  ...                       bucket lock 0x8ae86a00
399fc8  eax = dword [entry+0x28]  generation
399fcd  shl eax, 0xd
399fd0  movzx eax, ax             keep 3 bits above bit 13
399fd3  or eax, ecx               ecx = index (id & 0x1fff)
399fd5  cmp eax, r12d             compare with the requested id
399fd8  jne fail                  -> returns 0
399fe1  cmp word [entry+0x26], 3  entry type must be 3
399fed  cmp r14d, -1 / cmp r14d, word [entry+0x20]   caller's tag must match
399ffd  [entry+0x18] = gs:[0]     stamp the entry with the owning thread
39a019  bucket unlock
39a028  mtx_lock ([entry])        take the entry's own lock
39a036  bucket lock again
39a03b  cmp [entry+0x18], gs:[0]  revalidate ownership
39a03f  je success                otherwise unlock and retry the whole lookup
```

So an id is `(generation << 13) | index`, and the generation that reaches the id
is only **three bits** of `[entry+0x28]` (`shl 13; movzx ax`). That is why `526b`
saw exactly eight ids in rotation - `000003F8 000023F8 ... 0000E3F8` - and why a
deleted id reappears after exactly eight creates: the id space is 8 x 8192 and a
stale id becomes valid again after eight reuses of its slot.

Two consequences:

- the reused-slot substitution the 14.20 note describes cannot happen by id alone:
  both lookups compare the current entry's generation with the id, so a slot that
  was re-created fewer than eight times resolves to no object and the caller
  takes the `0x3affab` status-0 path;
- the entry's own mutex is taken *by the lookup* and revalidated after the bucket
  lock is retaken, so the delete's frees run with the entry locked. The two-zero
  statuses are two callers that serialised on that mutex, one of which then
  missed at the second lookup.

Measured agreement: `0x80020010` never appeared in 900 deletes against 1,100
creates (`526a`/`526c`). It would be the signature of this lookup resolving to a
fresh unpolled object.

Not established: that the 14.10 build has the same instruction sequence - the
capture is 13.60. The console behaviour matches it, but the firmware image is not
available to check byte for byte.

## Block mode writes `count` ids to the caller's out pointer (2026-10-24)

Block mode (`flags & 0x1000`) reports **one id per item**, not one id per call,
and the create tail copies the whole array to the pointer passed as the fifth
argument. My first probes sized that page for a single dword, so counts above
16 overwrote the probe's own Lua heap and the loader died with a fatal signal.
The 531a/532a deaths were probe defects, not a kernel fault.

The 13.60 tail at `0x3b25c9`:

```
03b25ec cmp  dword [rbx+0xc], 0   ; flags & 0x1000
03b25f3 jne  0x3b2604             ; block mode
03b25f5 mov  r14, [rbx+0x68]      ; user out pointer
03b25f9 lea  rdi, [rbx+0x7c]      ; &id on the kernel stack
03b25fd mov  edx, 4               ; one dword
03b2602 jmp  0x3b2657
03b2604 lea  rax, [r14*4 + 0xf]   ; r14 = count
03b260c mov  rdi, rsp
03b260f lea  rdx, [r14*4]         ; len = count*4
03b261a and  rax, ~0xf
03b261e sub  rdi, rax
03b2621 and  rdi, ~0x1f
03b2625 mov  rsp, rdi             ; alloca(count*4)
03b2640 mov  ecx, r15d            ; i << 16
03b2643 add  r15d, 0x10000
03b264a or   ecx, esi             ; id | (i<<16)
03b264c mov  [rdi + rax*4], ecx
03b2657 mov  rsi, r14             ; user out pointer
03b265a call 0x8ad73a40           ; copyout(src=rdi, dst=rsi, len=rdx)
```

A block create of `count` items fills `count` dwords with `id + i*0x10000` and
copies them out in one call. A caller that passes a four-byte page and a count
above 16 gets a 64-byte-and-up overwrite of its own address space, which is
what the `0x13371337` crash records were: the loader's signal handler printing
a context whose registers pointed into the damaged heap.

Consequences for the earlier probes:

| probe | shape | reading |
|---|---|---|
| 528a | block count 4, out page 0x20 | 4 dwords fit, clean |
| 531a | non-block 0x7F/0x80, out 0x40 | one dword written, clean |
| 531a | block 0x7F, out 0x40 | 508 bytes into a 64-byte page, process died |
| 532a | block 0x10, out 0x40 | 64 bytes, exactly fits, clean |
| 532a | block 0x20, out 0x40 | 128 bytes, overflows, process died |

The boundary 0x10 -> 0x20 is exactly 0x40/4 -> 0x80/4, the signature of the
undersized out page rather than any count limit in the handler.

What this does not establish: any defect in the block path itself. With an out
page of `count*4` bytes, block mode should behave like non-block mode and every
item id should be readable as `base + i*0x10000`.

## Non-block create makes one object, not `count` of them (2026-10-24)

`546a` creates with `flags=1, count=4` and polls every id the block-mode
numbering would predict:

| id | poll status |
|---|---|
| `0x00004205` | `0x00000003` |
| `0x00014205` | `0x80020003` |
| `0x00024205` | `0x80020003` |
| `0x00034205` | `0x80020003` |

`0x80020003` is the missing-object status from the first lookup, so ids
`base + i*0x10000` exist only in block mode, where the entry count equals the
item count. Deleting the single non-block id returns 0 and frees the context;
deleting the three phantom ids returns `0x80020003` and touches nothing. There
is no live work item left behind to dereference a freed context, so the shared
context is not a dangling-pointer surface in either mode.
