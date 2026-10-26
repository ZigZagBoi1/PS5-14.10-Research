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

## Allocating inside the delete window changes nothing (795a, 2026-10-26)

Every earlier race released only deleters, so the free window was never populated: a loser
that *did* land in it would have found the same freed chunks with no new owner. `795a` puts
creators into the window.

That needed a capability the thread harness did not have: a child could only issue the syscall
it entered with, because `669` takes five arguments and eboot has no `pop r8`. The missing
piece is that a child parked in `read(2)` can **pop `rcx` in its chain** (eboot has
`pop rcx; ret`, first hit `eboot+0xE64`) and `r8` survives a `syscall` (only `rcx` and `r11`
are clobbered), so `r8` can be seeded from the ucontext slot `ctx+0x068` while the chain sets
the other four. Probe `probes/phase17_new_vectors/795a_aio_alloc_during_free.lua`, capture
`results/phase17_new_vectors/795a_aio_alloc_during_free_20261026_104900.txt`:

- `[A]` a single parked creator built `id=006221`; `[B]` poll `3`, delete `0` - the five-argument
  chain create works from a child.
- `[C]`/`[D]` two rounds of 24 `count=1` blocks, polled, then **two parked deleters plus ten
  parked creators released back to back**. Deleter A deleted all 24 ids; deleter B returned `0`
  for 15 of them in round 1 and 16 in round 2, i.e. the overlap that `791d` measured.
- The ten creators allocated inside that walk, and their ids were all distinct (`dup=0`), all
  polled `3`, all deleted with `0` (`anomalies=0`), and the parent's health check after the
  rounds was `8/8`.

Reading: allocations that land during the walk do not take a chunk the second deleter then
frees. Either the loser's re-lookup still misses (its lock ordering is unchanged by the extra
traffic) or the chunks it would free are the entry `T` and context `C`, which the allocator
hands out only to the create path that this call is itself inside. Either way, populating the
window is not enough on 14.10: the loser's re-lookup must be delayed *between* its own
re-lookup and its frees, which no userland control reaches.

## The barrier race doubles the status, not the frees (791b-791f, 2026-10-26)

Every earlier race started its children with `thr_create` and hoped they would overlap. They never
did at single-call granularity (524a: 0 doubles in 25 attempts) because the second `thr_create`
returns only after the first child has finished a microsecond-long delete walk.

`791d`/`791e`/`791f` park the children instead. Each child enters `read(2)` on its own socketpair
and the parent releases both with two back-to-back `write(2)` calls, so the two deletes start within
microseconds on a 16-core console. Results, all on a fresh game process:

| probe | shape | two-zero ids |
|---|---|---|
| `791c` (run 2) | back-to-back `thr_create`, 48 ids | 0/48 |
| `791d` | socket barrier, 48 last items of 2-item blocks | **39/48** |
| `791e` | socket barrier, 48 `count=1` blocks | **42/48** |
| `791f` | 10 rounds of the same, accumulating | 395 total |

`791b` also fixed an earlier mistake: a block whose ids have never been polled fails the delete with
the state gate, which is why `791a` reported `zeros=0/24`. With the poll in place the serial walk is
exact (`48/48` zeros, both items of a two-item block, and `24/24` first-item deletes).

**What the code says about the second caller.** `8ad6fec3 test r14,r14 / je 8ad6fefe` does not exit:
the branch only skips the `C` free, and `8ad6fefe` onwards frees `S`, `D`, `P` and `T` for both
callers. The status-only reading in an earlier section is therefore wrong about *where* the second
caller stops. The stop is earlier, at the re-lookup:

```
8ad6fe7c  call 0x8ad5a2a0            ; re-lookup, takes the table lock
...
8ad6ffab  mov rdx, [rbx+8]
8ad6ffaf  mov dword [rdx+r13*4], 0   ; status 0 on a re-lookup miss
8ad6ffb7  jmp  8ad6fcf3              ; next id
```

A re-lookup miss writes `0` and continues, so a second `0` is exactly what a loser that arrives after
the winner cleared the slot produces. That is consistent with the allocator result below and needs no
duplicate free.

**The allocator never saw a duplicate.** After the ten rounds of `791f` (395 double-status deletes,
i.e. up to 1580 duplicated frees of `C`, `S`, `D`, `P` and `T` if the losers had freed), 96 fresh
`count=1` creates were allocated, polled and deleted: `poll3=48/48` twice, `anomalies=0`,
`duplicate ids=0`, health `0/8`. Two live objects sharing one chunk would have produced a duplicate
id or a delete that misses on the table-entry slot check; neither appeared. `791e`'s single-round
burst of 40 was equally clean.

Reading: on 14.10 the second caller reaches the miss path, not the free path. The winner's slot clear
at `8ad70003` lands before the loser's re-lookup takes the lock, so the loser writes `0` and frees
nothing. The race produces a **duplicate status**, which is what `568a`'s `100/100` and `523c`'s
`54/100` were measuring all along.

**The parent-only test was blind, so it was repeated from the children.** A per-CPU free cache
would hide a duplicate from a parent that allocates on a different CPU. `792b` first proved a
`thr_create` child can issue its own five-argument create straight from its ucontext - `RCX` at
`ctx+0x060` and `R8` at `ctx+0x068` both take effect (`spawn ok=true rv=0`, child create
`id=0000A214`, poll `3`, delete `0`). `792d` then ran three more barrier rounds (two-zero 40, 41,
42 of 48) and, immediately afterwards, sixteen **separate** children each issuing one `count=1`
create, so sixteen different CPUs allocate from whatever their cache holds: all sixteen ids are
distinct, all poll `3`, all delete with `0`, `alias suspects=0`.

Across `791d`-`791f` and `792d` that is **599 two-zero deletes** (up to ~2400 candidate duplicate
frees) followed by allocations from the parent, from one child, and from sixteen separate children,
with no aliased id, no failed delete and no duplicate id.

Residual uncertainty, stated plainly: if the kernel's `free` (0x8b5c8df0) were idempotent for the
same pointer, a genuine second free would look identical from outside. Nothing in these probes
separates those two readings, but only "no second free" is consistent with 152 fresh objects
behaving exactly as expected after the races (40 in `791e`, 96 in `791f`, 16 in `792d`).

## A kernel buffer is refused with EFAULT, and both lookups are generation-checked (755a, 2026-10-25)

Status: **narrows the pointer question.** The vnode path does not fail the way
the socket path does for a user address, but it does refuse a kernel address.

`probes/phase17_new_vectors/755a_aio_first_kernel_buf.lua`, capture
`results/phase17_new_vectors/755a_aio_first_kernel_buf_20261025_113510.txt`,
the first create of a fresh session, file read of `/savedata0/thread.lua`:

| buffer | poll | record | delete | process |
|---|---|---|---|---|
| `0xfffffe0000000000` (direct map base) | `00000003`, then `00010003` | `8002000E FFFFFFFF 3 0` | `0` | alive |
| our own page (control) | `00000003`, then `00010003` | `10 0 3 0` | `0` | alive, buffer `2D0A2D2D 6874202D …` |

So the transfer is refused with `0x8002000E` (EFAULT) rather than written, and a
successful control in the same session proves the refusal is address-specific.

The `0x00010003` poll word is the completed state with the reported bit set
(`0x10000`), the same value seen since 498e.

**Correction to a report that claimed otherwise.** `0x8ad5a2a0`, the second
lookup used after the delete drops its reference, does compare the generation:

```
8ad5a36b  mov  eax, dword [r13 + rcx + 0x28]   ; entry generation
8ad5a370  shl  eax, 0xd
8ad5a373  movzx eax, ax
8ad5a376  or   eax, ebx                        ; rebuilt id = gen<<13 | slot
8ad5a378  cmp  eax, r14d                       ; r14d = the requested id
8ad5a37b  jne  0x8ad5a413                      ; miss
8ad5a384  cmp  word [r13+0x26], 3              ; slot state must be 3
```

So a stale handle cannot name a newer generation through the second lookup
either, and the "free a newer object at the recycled index" hypothesis is not
available on this code.

---

## The aio state machine, and why a stuck job costs a relaunch (775a-777b, 2026-10-25)

Measured on 14.10 with block-mode creates (`669(0x1001, D, 1, 1, out)`):

| poll word | meaning |
|---|---|
| `00000001` | created, **not started** |
| `00000002` | in flight (socket read with no data yet) |
| `00000003` | complete |
| `00000004` | cancelled (`666`) |

`664` poll returns `0` in the syscall return slot every time; the state lives
in the status word it writes (`res[0]`). After a state has been reported once
the word gains `0x10000`, so `00010003` is still "complete".

The delete gate (`662`) accepts **state 3 only**. A job cancelled while pending
goes to state `4` and can no longer be deleted (`0x80020010`), and neither can
a job that never started (`0x80020010`). There is no userspace path back:

- `777a`: cancelling the wedged ids moved them to state 4 (`ret=0 out=4`),
  and a fresh create afterwards still polled `1`.
- `777b`: for 13 cancelled ids, delete returned `ret=0` with status
  `80020010` every time. `ret=0` here is only the syscall's success; the
  per-id status is the result.

So a job left in state 1 or 2 wedges the family: the submit queue holds about
two jobs (754a), and once it is full every later create parks at state 1. The
only recovery is a game relaunch. Two of my own probes wedged sessions this
way — the first because `write` was called as `(fd, len, buf)` instead of
`(fd, buf, len)`, which made every completion silent.

Design rule for every later aio probe: give each created job a feed that
completes it, and never leave a create without a matching write.

## The submit queue takes about two requests, and a request left in flight blocks the family (752a-754a, 2026-10-25)

Status: **operational constraint.** Every aio probe that leaves a request
pending poisons the aio family for the rest of the game session, including a
plain file read with a valid buffer.

Evidence that the loader is one process per game session, not one per
connection: the create id keeps climbing across separate TCP connections —
`00004205` in 744b, `00004205`/`00000206`/`00000207`/`00000208` in 752a,
`00000209`-`0000020B` in 753a, `0000020C`/`0000020D`/`0000020E` in 750a,
`0000020F`/`00000210` in 754a — and the value returned by `syscall 20` climbs
the same way within a run (22, 28, 38, 49). A new process per connection would
restart the slot allocator.

| probe | what it creates | state seen | delete |
|---|---|---|---|
| 752a op 0 | socket read, no peer feed | `2` | `80020010` |
| 752a op 1 | socket read, no peer feed | `2` | `80020010` |
| 752a op 2, op 3 | same descriptor, `+0x24` = 2 and 3 | `1` forever | `80020010` |
| 753a mode 1, 2, 3 | file/socket read after the two above | `1` forever | `80020010` |
| 750a control | file read, valid buffer, fresh connection | `1` forever | `80020010` |
| 754a control | file read, valid buffer, watched to 600 ms | `1` at 20/100/300/600 ms | `80020010` |

Readings:

- **Two requests submit and the rest queue.** 752a's first two creates reached
  state 2 (in flight); the third and fourth stayed at 1 and never moved. Every
  create after that, in every later connection, also stayed at 1 — the two
  in-flight reads had no peer feed and so never completed, and the queue never
  drained.
- **State 1 is "accepted, not started"**, and the delete gate rejects it
  exactly as it rejects state 2: `0x80020010` needs a completed object.
- **The lazy reading is wrong: the queue is a real resource limit**, not a
  timing artefact. A control watched for 600 ms never left state 1, while the
  same shape completed in 30 ms in 747a on a fresh session.
- **The descriptor dword at `+0x24` is not a direction selector**, and the mode
  argument does not change the direction either: op 0 and op 1 both behave as
  reads (pending until a peer feed) and op 2/3 never start. No aio request has
  ever moved data from the buffer into the socket or the file.
- **Consequence for every later probe**: the first aio request of a fresh game
  session is the only one that can be trusted to submit, and any probe that
  does not feed and delete its request blocks the family until a relaunch.

---

## The descriptor's operation field is not a handler index (792a, 2026-10-25)

`probes/phase17_new_vectors/792a_aio_op_matrix.lua` ran one block create per
value of the descriptor dword at `+0x24` (the op field), `0`-`0x10`, against
`/savedata0/thread.lua` with a valid 16-byte buffer and a valid result page.
Every value returned `0`, every poll read `3` on the first call, every
cancel returned `0` and every delete `0`, with health unchanged throughout.
On a file descriptor the op field selects nothing - values above 1 do not
reach a different handler, and none of them faults.

## Block creates do submit, and only the result pointer is unguarded (744b, 745a, 746a, 2026-10-25)

Status: **corrects the section below.** The `never submits` conclusion came from
the 13.60 gate at `0x8b4c78d0`. On 14.10 a block create submits a real socket
read and the work completes.

`probes/phase17_new_vectors/744b_aio_ptr_validation.lua`, capture
`results/phase17_new_vectors/744b_aio_ptr_validation_20261025_112008.txt`, block
create `669(0x1001, D, 1, 1, ids)` against one end of a `socketpair`:

| stage | create | poll before feed | feed | poll after | result record |
|---|---|---|---|---|---|
| control, valid buffer and result | `0`, id `00004205` | `00000002` | `write -> 16` | `00000003` | `10 0 3 0` |
| buffer `0x1000` | `0`, id `00006205` | `00000002` | `write -> 16` | `00000003` | `8002000E FFFFFFFF 3 0` |
| result `0x1000` | `0`, id `00008205` | `00000003` | `write -> 16` | — process died | — |

Readings:

- **State 2 is in flight and state 3 is complete**, and the caller buffer really
  receives the bytes: after the feed it reads `45454545 46464646 47474747 48484848`,
  the pattern written to the peer. The worker is not a bookkeeping artefact.
- **The result record is `{return, errno, state, pad}`** at the caller pointer:
  `10 0 3 0` for a 16-byte transfer, and `8002000E` (a Sony error carrying
  `EFAULT`, `14`) with `0xFFFFFFFF` beside it when the buffer cannot be written.
- **The descriptor buffer is validated.** An unmapped `0x1000` produces
  `0x8002000E` and the delete still returns `0`; the kernel survives.
- **The descriptor result pointer is not validated the same way.** The same
  `0x1000` there kills the process instead of reporting an error, so the record
  store is a raw write behind a range check rather than a `copyout` with a fault
  handler.
- `745a` (`results/phase17_new_vectors/745a_aio_res_kernel_va_20261025_112127.txt`)
  points that result pointer at `0xfffffe0000000000` (the FreeBSD direct-map
  base) and at `0xffffffffff000000`. Both complete to state `3`, delete `0`, and
  the process stays alive at `health=26` and `28`. A raw store to an unmapped
  kernel address would fault, so the address must be rejected before the store —
  the result pointer is range-checked and cannot reach kernel space. **It is not
  a kernel write.**
- `746a` (`results/phase17_new_vectors/746a_sys667_20261025_112159.txt`) tries
  `667` against a completed id in four layouts (`(ids,1,out)`, `(ids,1,out,0x400)`,
  `(out,id,0x400)`, `(id,out,0x400)`) and after the delete: `-1` every time, the
  0x4000 out page all zero, no kernel-shaped qword. `667` is not a getter.
- Non-block create (`flags=1`) never submits: 744a polled state `00000001` for a
  live non-block object. Submission is reached only through the block flag
  `0x1000`, which is also the flag that shares one `S` across `count` items.

The state gate on delete, which `743a`
(`results/phase17_new_vectors/743a_aio_delete_pending_20261025_112240.txt`)
measured directly: a pending id (`poll -> 00000002`) deletes to
`0x80020010`, so the free cannot run while the worker holds the object. Together
with the generation compare in both lookups (`0x8ad59fc8`, `0x8ad5a36b` in the
13.60 capture) this closes the pre-fix shape the 14.20 note describes: a racer
cannot free an object whose work is still in flight, and a reused slot cannot be
matched under the old id.

**Not established:** whether the `0x1000` death in the third row is a range
check that passes an unmapped user address or a write-protected mapping; whether
the raw store can reach a user address mapped by another process; and anything
about a kernel-address path, which the `745a` result rules out for this syscall.

---

## The delete race is reachable, and the allocator stays clean (719a, 720a, 2026-10-25)

Earlier attempts could not put two callers inside `aio_multi_delete` at once: the Lua harness serialises syscalls (509b) and a `thr_create` child could not issue one at all. Probe 712c removed the second limit by pointing a child's `RIP` at `syscall.pipe.fn_addr`, and 719a removed the first by parking both children in `_umtx_op` WAIT and releasing them with a single wake (see `docs/THREADING_ALIVE_14_10.md`).

| probe | arrangement | rounds | both statuses 0 | one 0 | misses | allocator anomalies |
|---|---|---|---|---|---|---|
| 719a | 2 children, one umtx wake, object polled first | 30 | **30** | 0 | 0 | not measured |
| 720a | 2 children, health cycle after each round | 40 | 39 | 1 | 0 | **0** |
| 720a | 4 children, health cycle after each round | 40 | 38 | 2 | 0 | **0** |

So two or four concurrent deletes of the same id return `0` essentially every time, which is far beyond what spawn-latency races achieved. The status still cannot show a double free, because 14.10 writes `0` on the miss path (`8ad6ffab`) *and* on the already-cleared-context path (`8ad6fec3` -> `8ad6fefe`).

What the allocator says: nothing. After 80 racing rounds the follow-up create/poll/delete cycle is clean every time (state `3`, delete status `0`), and the process never died. The count-1 path reads `C = [W+0x18]` at `8ad6feb7`, tests it at `8ad6fec3`, drops `C+0x10` and frees `C` at `8ad6fee8`, and only clears the field at `8ad6fef5` - so the window is real, roughly fifteen instructions - but a loser that re-takes the table lock after the winner's unlock at `8ad6fe63` still arrives after the clear in practice.

Two probe bugs are worth recording because both produced convincing-looking null results first:

- the object must be **polled before it can be deleted**; an unpolled object fails the state gate and the delete answers `0x80020010` for every caller (719a v2);
- after a `_umtx_op` the argument registers still hold the umtx arguments, so the delete ran with `count=2` and a **NULL** status pointer, and neither child wrote a status page (719a v1).

## The delete's re-lookup branch is opened by the poll, not by submit (corrected 2026-10-26)

> **Correction (2026-10-26).** This section originally concluded that `W+0xc` stays
> zero on 14.10 because only the gated submit writes it, and that the re-lookup
> branch was therefore unreachable. That is wrong: `664 aio_multi_poll` writes
> `mov byte ptr [rcx + 0xc], 1` at `0x3b1553`, so every object that has been polled
> takes the branch. Since the delete refuses an unpolled object with the state gate,
> **every delete that succeeds at all runs the unlock/re-lookup path**, and the
> benchmark races in the section above are measuring that path. The reasoning about
> `W+4` below still holds; the conclusion about `W+0xc` does not.

The 14.20 fix note describes a TOCTOU in `aio_multi_delete`: the delete drops the
lock, re-acquires the object, and frees sub-objects of whatever occupies the slot.
In the 13.60 body (`0xffffffff8ad6f900` onward, base `0xffffffff8a9c0000`) that
re-lookup exists, but it is conditional on two fields of the work item `W`:

```
8ad6fd0c  mov rax,[r12+0x28]        ; rax = entry P
8ad6fd14  mov r14,[rax+rcx*8]       ; r14 = W = P[index]
...
8ad6fe40  mov rcx,[rbx+0x20]        ; rcx = W
8ad6fe4f  cmp dword [rcx+4],0
8ad6fe53  jne 0x8ad6fb9b            ; W+4 != 0 -> next id, NO unlock
8ad6fe59  cmp byte [rcx+0xc],0
8ad6fe5d  je  0x8ad6fb9b            ; W+0xc == 0 -> next id, NO unlock
8ad6fe63  mov rdi,[rbx+0x78] / call 0x8ad59eb0   ; UNLOCK
8ad6fe7c  call 0x8ad5a2a0                        ; lockless second lookup
```

`W` is the `0x58`-byte work item allocated in the create body at `0x8ad72541` with
`edx=0x102` (`M_WAITOK|M_ZERO`), and the create writes only four fields:

```
8ad72552  mov dword [rax],ecx        ; W+0x00 id
8ad72554  mov [rax+0x10],r12         ; W+0x10 descriptor
8ad72558  mov [rax+0x18],rsi         ; W+0x18 context C
8ad7255c  mov [rax+0x20],r14         ; W+0x20 work object S
```

Nothing writes `W+4` or `W+0xc` in the create, and the submit at
`0xffffffff8aa636d0` sits behind the boot tunable `0x8b4c78d0`, which returns 0 on
14.10 (the "submission and record paths are gated by a boot tunable" section above,
measured by probe 500b: an invalid fd and a 1 GiB length both complete).

The field that matters is written by the **poll** instead: `664 aio_multi_poll` has
`0x3b1553 mov byte ptr [rcx + 0xc], 1` on the work item it just reported on. So for
any object this process can delete at all, `W+4 == 0` and `W+0xc == 1`: the delete
unlocks at `0x3afe63` (`call 0x8ad59eb0`) and re-looks the id up at `0x8ad5a2a0`.

### Consequence for the earlier race results

The `both=0` rows in `633c`, `635a`, `640a`, `641a` and `642a`, and the larger
barrier-race counts in the section above, **are** this window. The second caller
does not stop at the status array: it passes the first lookup, takes the same
unlock, and then loses at the re-lookup, which writes `0` at `0x8ad6ffaf`. That is
a status-only duplicate, and the allocator result (152 fresh objects, no duplicate
id, no aliased chunk) says the loser never lands between the winner's frees and its
slot clear.

Corrected conclusion: the branch is reachable and is exercised by every successful
delete on 14.10, but the loser is ordered behind the winner's own re-acquisition of
the bucket lock for the removal, so it always observes the slot already gone. The
race is real in the code and benign in this process; it is not a memory-safety
primitive without a way to delay the loser between its re-lookup and the frees.

## Poll is what completes a request, and the table caps at about 128 live objects (2026-10-24)

`probes/phase17_new_vectors/608a_aio_wedge_bisect.lua` ran 80 rounds of
create -> `664` poll -> `write(2)` to the peer -> `662` delete. **Every delete
returned `ret=0 status=0`**, every poll returned `3`, and the spray object's poll
also returned `3` in every round.

`probes/phase17_new_vectors/609a_aio_slot_leak.lua` ran the same loop **without the
poll**: every delete returned `status=0x80020010` from round 1 onward. The `664`
call is therefore not a read-only status query - it is the operation that drives
the request to the state `662` accepts (3 or 4). A create is not deletable until
something has polled it.

Because those deletes were refused, `609a` accumulated live objects: creates still
succeeded at round 100 (`health=00000272`), and the Lua thread stopped answering
around round 128, the same wedge as `498c`/`607a`. That gives the table a live
object cap near 128 (consistent with the "120 live objects kills the table" note
above).

`610a` (create -> poll -> write -> delete, 200 rounds, one health create every 10)
is written and was sent while the process was already wedged, so it produced no
output; it needs a fresh process.

## The worker is asynchronous, and racing its completion can wedge the table (2026-10-24)

`probes/phase17_new_vectors/603a_aio_pending_wait.lua` established that a submitted
request does wait for data: four descriptor layouts were created against an empty
`socketpair(2)` and every poll returned `3`; after one `write(2)` on the peer every
one of the four returned `0x10003`. A status therefore moves to `0x10003` only once
the worker has data to consume, so the request is submitted and parked.

`probes/phase17_new_vectors/604a_aio_delete_pending.lua` created a read on an empty
socket, deleted it, and then fed the peer. The delete returned `ret=0`, `status=0`
and the process survived the completion; later polls of the id returned
`0x80020003`. `605a` produced the opposite: two orderings returned
`status=0x80020010` and only `cancel` (666) wrote `0x00000003`. The difference
between those two runs was not isolated, so the state a delete sees on a parked
request is not yet predictable.

`probes/phase17_new_vectors/607a_aio_worker_reclaim.lua` ran 150 rounds of
create-parked-read → write to the peer → delete → three fresh creates as a reclaim
spray → poll and delete the spray. Through round 125 every delete returned
`status=0`, no spray poll was unusual, and every poll before the write returned
`3`. After that the Lua thread stopped answering: `print("PING-OK")` on a new
connection got no reply while port 9026 still accepted, which is the same wedge
observed after `498c`. A full game restart is required.

**Established:** a request is submitted and parked until data arrives; a parked id
is deletable; racing the completion with a delete plus a create spray runs 125
clean rounds and then wedges the aio subsystem.
**Not established:** whether any freed object is used by the worker, whether the
spray ever occupies the freed chunk, and which round wedges the table.

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

## The delete serializes against itself, and the residual window is delete versus wait (2026-10-24)

The delete body resolves the object under the id-table lock, checks the object's
generation word, and *releases the entry* before it uses the object:

```
0x3afc3f  call 0x399ee0        ; lookup(table, slot, 0x160, &out) -> object
0x3afc5b  movsx eax,[rax]      ; generation word
0x3afc5e  cmp r14d,eax / jge   ; id>>16 must be below it, else 0x80020003
0x3afc67  call 0x399e20        ; release the entry (nonzero -> 0x80020001)
0x3afd0c  mov rax,[r12+0x28]   ; post-release read of the sub-object array
0x3afd14  mov r14,[rax+rcx*8]  ; sub-object for this slot
0x3afddc  cmp qword [r14+0x50],0   ; wait-queue head must be empty
0x3afdeb  ... 0x80020010       ; refuse while a waiter is linked
0x3afe29  call 0x8b5b1770      ; wake
0x3afee8  call 0x8b5c8df0      ; free, after the wake
```

Because the entry is gone by the time a second caller looks it up, two `662`
calls on one id cannot overlap in the free path. Measured, not assumed:

* `495b` (parent opens the gate, then calls; thread follows): 12 rounds, parent
  `0` every round, thread `0x80020003`.
* `495c` (thread pre-builds its callable, publishes `gate+4`, then calls; parent
  follows): 40 rounds, thread `0` every round, parent `0x80020003`.
* `496a`: `a=525` deleted cleanly, `b=8717` took the same slot `0x20d` with a
  different tag (`0x0000` -> `0x0022`), and deleting `a` again returned
  `0x80020003`. The lookup-side generation check rejects a stale id, so reuse by
  itself is not the primitive.

The remaining window is the empty-queue check at `0x3afddc` against the enqueue
in the wait body: `0x3b080c mov [r13+0x50], r14` links the requester onto exactly
that head, and `0x3b07e9 call 0x8ae86fa0` / `0x3b077f call 0x8b5b1770` put it to
sleep with `esi = 0x80000`. A `663` that enqueues between the check and the free
is woken and then freed, which is the shape the 14.20 fix closes.

`497a` measured what `663` does with our objects:

| call | ret | status |
| --- | --- | --- |
| `663(ids,1,res,0,0)` on a never-polled id | 0 | `0x3` |
| `663(ids,1,res,1,0)` | 0 | `0x10003` |
| `663(ids,1,res,200,0)` | -1 | untouched |
| `664` poll | 0 | `0x10003` |
| `663` after poll, no timeout | 0 | `0x10003` |
| `663` after poll, 200 | -1 | untouched |
| `662` delete after poll | 0 | `0` |

So a wait on these zeroed request descriptors completes immediately: nothing in
this process leaves a request pending, so the waiter enqueues and is woken inside
the same call. Holding a waiter on the queue needs a request the backend does not
complete, and the `count*0x28` descriptor layout that would express one is not
known.

The helper thread limit is one. `494c`/`494d`/`495a` show a single
`run_lua_code_in_new_thread` state working (a body can call `662` and read and
write the parent's pages), and `496c` shows six gated threads that issue no
syscall at all dying, `496d` shows the death at the **second** spawn while the
first thread is parked on the gate, so `run_lua_code_in_new_thread` is not
reentrant and a multi-thread pile-up is not available from Lua.

Not established:

* any overlap between two delete calls, or between a delete and a wait, on one
  object;
* a request descriptor that stays pending, which is what a queued waiter needs;
* whether 14.10 differs from the 13.60 offsets above - every claim here is a
  13.60 model plus 14.10 behaviour, not a 14.10 disassembly.

## Two concurrent deletes of one id both return 0 (2026-10-24)

The serialized case is clean. `498a` creates 64 objects, polls each one, and then
deletes the whole list twice in a row from a single caller:

| pass | ret | statuses |
| --- | --- | --- |
| 0 | 0 | 64 x `0` |
| 1 | 0 | 64 x `0x80020003` |

So a second delete of an object that is already gone always fails the generation
check, and the earlier probe's `0x80020003` is not about ordering luck.

The concurrent case is not clean. `497e` and `497f` prepare the same 64 polled
ids and hand the list to two callers at once: the parent and one
`run_lua_code_in_new_thread` helper. Each caller deletes the whole list for a
fixed number of passes and writes its statuses into its own array
(`res1 = 0x3110f9960`, `res2 = 0x3110fa240`, `ids = 0x310f823c0` - separate pages,
so the two reports cannot overwrite each other).

`497f` (two passes each) reported a clean delete from **both** callers for 24 of
the 64 ids; the first 40 ids show only the helper's success. `497e` (ten passes
each) reported `ids-with-two = 20` and 84 successful deletes where at most 64 are
possible. The process survived both runs.

What this does and does not establish:

* a second delete against an object that is *already* gone returns
  `0x80020003`, and two deletes that overlap in the kernel can both return `0`
  for the same id;
* whether the object is freed twice, or the second `0` is a status-only path that
  skips the free, is **not** established - no observable corruption and no crash
  followed either run;
* the distribution (a contiguous tail of ids sharing the double success) is not
  explained by a simple timing model, so the per-id ordering inside the two
  concurrent walks matters and is not modelled here;
* nothing here is a kernel read or write.

The stronger shape - delete landing on a slot that another thread has already
freed and filled with a new object, which is what the 14.20 generation re-check
closes - was attempted as `498b` (helper loops delete/create/poll over the same
slots while the parent deletes the original list). That run stopped 8.9 s after
the spawn without the parent printing a single pass, which is either the known
helper-lifetime death near ten seconds or the parent blocking on the aio table
lock. `498c` is the control with the helper's delete removed, to separate those
two.

### The aio table can be wedged for the whole game process (2026-10-24)

Operational hazard, found while setting up the recycle race. The loader is a Lua
thread inside the game process, so a probe that "dies" kills that thread, not the
process. After `498b`'s helper created and polled objects and was then killed
mid-loop, a later connection in the **same** game process printed its header and
then blocked in its first `669` for 180 s; a plain `print("PING-OK")` over TCP was
also never answered, while the listening socket still accepted connections.

Two readings, not separated yet:

* the killed helper was inside the aio table critical section, so the table lock
  is held forever and every later `669` in that process waits;
* the objects the helper created and never deleted filled a fixed table, and
  `669` waits on an allocation instead of failing.

Either way, a restart of the game is required - reconnecting does not help.
Consequence for probing: any helper-thread probe that creates aio objects must
finish its own cleanup, and a kill inside the create path costs the session.

### The double status reproduces, and the table survives it (2026-10-24)

`497f` was repeated three times on a fresh game process with no edits:

| run | objects | clean deletes (max 128) | ids with two clean deletes |
| --- | --- | --- | --- |
| 1 | 64 | 84 | 20 |
| 2 | 64 | 78 | 14 |
| 3 | 64 | 86 | 22 |

So the overlapping-delete result is not a one-off. It depends on the two callers
actually being inside the kernel together: `498e`, where a bad edit left the
helper's ready word until after its deletes, produced `ids-with-two = 0` because
the parent's call only started once the helper had finished. A probe that shows
zero here is a probe that did not overlap, not a refutation.

`498d`/`498e` then checked what the double delete leaves behind. After the race,
64 fresh objects each went create -> poll -> delete with every delete returning
`0`. Nothing in the table was left half-freed where userland can see it.

One measurement corrected: poll does not always answer `0x10003`. In `498e` the
parent spun for 73 s before the fresh cycle, and every fresh poll answered `0x3`
instead. `0x3` is the same value `663` gives a never-polled id and is what a
request that has already completed reports; `0x10003` is the in-progress answer.
Either way the object is deletable with status `0`, so the difference is
completion timing, not damage.

Not established, and this is the honest end of the lead from userland:

* whether the second `0` frees the object a second time or only reports success;
* any userland-visible consequence - no crash, no corrupt status, no failed
  delete and no leaked id followed either run;
* a pending request descriptor, which is what a delete-versus-wait window needs;
* a delete that lands on a re-populated slot, which is the shape the 14.20
  generation re-check closes - the attempt (`498b`) killed the helper mid-create
  and wedged the aio table for that game process instead.

### The job object the delete frees (13.60 create body, offset `0x3b2080`)

Disassembling the create body shows what a delete is actually freeing. The
syscall wrapper at `0x3b2060` lifts five fields out of `uap` and jumps into the
body at `0x3b2080`:

| `uap` | meaning |
| --- | --- |
| `+0x00` | flags, low 12 bits must be 1 or 2 |
| `+0x08` | user buffer for the descriptor array |
| `+0x10` | count, 1..0x80 |
| `+0x18` | mode, 1..3 |
| `+0x20` | out pointer for the id |

The body then:

1. `0x8ad598e0` allocates the id;
2. `0x8b5c8b50(count * 0x28)` allocates the descriptor array, and `0x8ac19280`
   copies `count * 0x28` bytes straight from user - the descriptor contents are
   never interpreted on this path;
3. for each descriptor, when `flags & 0x1000` is clear, one `0x58` byte object is
   allocated (`0x8b5c8b50`) and initialised with `[obj] = 0x100000001`,
   `[obj+8] = 1`, `[obj+0x50] = 0`, plus an event init at `+0x20`
   (`0x8b5b1690`); with the bit set it allocates `count * 0x58` in one block and
   initialises each entry the same way;
4. a `0x30` byte job is allocated and filled: `[job+0x28]` = the pointer array,
   `[job+0x10]` = the descriptor array, `[job+8]` = id, `[job+0x20]` = count;
5. `0x8b4c78d0` then `0x8aa636d0` submit it.

So the array the delete walks at `0x3afd0c`/`0x3afd14` is `[job+0x28]`, and each
element is a `0x58` byte kernel object. Two clean deletes of one id means the
same `0x58` object is handed to `0x8b5c8df0` twice. That is the primitive the
status values describe; turning it into anything needs a way to reclaim that
object with controlled contents between the two frees, which this process has no
route to: `669` allocates the object but only ever initialises fixed fields, and
the descriptor bytes are copied verbatim into a different allocation.

That paragraph is superseded by the next section: the tail frees the `0x30`
context at `[work+0x18]`, not the `0x58` object, and `669` never submits work at
all.

> **Correction (2026-10-25):** this section is wrong for 14.10. A block create
> (`flags & 0x1000`) does submit, and the work completes — see "Block creates do
> submit, and only the result pointer is unguarded (744b, 745a, 746a, 2026-10-25)"
> above. The gate described here is a 13.60 read.

## The create never submits on 14.10: aio is a bookkeeping surface (2026-10-24)

> **Scope correction (744b-746b).** This section measured non-block creates
> (`flags = 1` only). A block create (`flags |= 0x1000`) does submit and the queue
> then holds real requests; what stays gated is only the result-record copyout.
> See "Block creates do submit, and only the result pointer is unguarded".

> **Superseded.** The submit gate returns 1 on this console: `566b` reads `/dev/urandom` through
> `669` and gets the bytes back, so create does submit. The "never submits" result came from the
> wrong descriptor field order in `500a`/`500b`/`566a`. See "The state gate passes at runtime".

The create body is `13.60` offset `0x3b2080` (`0xffffffff8ad72080`). Its whole
allocation sequence for one call is:

| allocation | size | contents |
| --- | --- | --- |
| `D` | `count * 0x28` | the user descriptor array, copied verbatim by `0x8ac19280` (offset `0x3b221c`) |
| `S` | `0x58` | state: `[0]=count`, `[4]=count`, `[8]=1`, `[0x50]=0`, event object at `+0x20` |
| `J` | `0x30` | job: `[0]=count`, `[4]=mode`, `[8]=id`, `[0x10]=S`, `[0x18]=S`, `[0x20]=D`, `[0x28]=P` |
| `P` | `count * 8` | pointer array, one element per descriptor |
| `C` | `0x30` | context: `[0]=gs:[0]+0x390`, `[8]=gs:[0]+8`, `[0x10]=0x8ac6b3a0(gs:[0]+0x140)`, `[0x20]=cpu`, `[0x28]=J` |
| `W` x `count` | `0x58` | work item: `[0]=id`, `[0x10]=&D[i]`, `[0x18]=C`, `[0x20]=S` |

Before the submit call the body calls `0x8b4c78d0` (offset `0x3b249c`). That
function takes no arguments and returns `1` only when one global equals `3` and
`0` otherwise (`0x8b4c78d0`: `cmp [rip+...],3 / je true`, else `cmp ...,4 /
sete`). The `test eax, eax / je 0x3b24bb` at `0x3b24a1` then **skips the submit
call entirely** when it returns `0`.

On 14.10 it returns `0`. `500a` and `500b`:

- four descriptor field orders (`op`/`fd`/`offset`/`buf`/`nbytes` in the orders a
  FreeBSD `aiocb` and a compact 0x28 record would use) against a real
  `/savedata0/thread.lua` fd all completed instantly with poll status `3` and
  the buffer untouched;
- fd `9999` and length `0x40000000` returned the same instant `3` as a valid fd
  and 64 bytes, in all three modes;
- no case ever showed an in-progress status, an error status, or a byte written
  into the caller buffer.

An invalid descriptor submitted for real would fail or block; a skipped submit
cannot. So `669` only builds bookkeeping objects on 14.10, and nothing ever
executes the descriptors.

The delete tail re-reads the slot after releasing the table lock and then frees
`[W+0x18]` - that is `C`, the `0x30` context - after calling `0x8ac69670` on
`[C+0x10]` and zeroing `[C+0x10]`; it clears `[W+0x18]` afterwards
(`0x3afee8` free, `0x3afef5` clear). A caller that finds `[W+0x18]` already zero
skips the free and still returns `0`.

That explains the double status without a second `0x58` free: both callers pass
the state gate because the state is `3` for a job that completed at create
time, and whichever caller reads `[W+0x18]` before the other clears it frees
`C`. The object at risk is therefore a `0x30` context with no user-controlled
field, and the only windows are the handful of instructions between the unlock
and the clear.

What this does not establish: that the second `0x58` object (or `S`) is freed
twice; that a `0x30` free can be paired with a reclaim that matters; and any
kernel read or write. The `14.20` fix described publicly for
`aio_multi_delete` targets this same post-unlock path, so the 14.10 code is the
pre-fix shape of a bug whose utilisation needs a reclaim route this surface does
not provide.

Probes: `probes/phase17_new_vectors/500a_aio_descriptor_layout.lua`,
`probes/phase17_new_vectors/500b_aio_submit_gate.lua`; captures under
`results/phase17_new_vectors/`.

## The free runs unlocked, so both deletes can free the same context (2026-10-24)

> **Correction (707a, 727a-728a).** The unlocked window is real and a follower does
> reach it, but the `[W+0x18]` guard at `8AD6FEC3` sends every follower down the
> status-only branch. 599 doubled statuses across 791f left the allocator clean, so
> the context is not in fact freed twice; see "The double status is a lie, and the
> allocator proves it".

`523c` gives 54 ids whose overlapping deletes both returned `0`, and the process survives it. The
13.60 delete body says why: the context free is guarded by a null test on the pointer it is about
to free.

```
8AD6FEB7  mov r14, [r12 + 0x18]      ; r14 = W->context
8AD6FEC3  test r14, r14
8AD6FEC6  je   0xffffffff8ad6fefe    ; already cleared -> status-only path
8AD6FEC8  mov rdi, [r14 + 0x10]
8AD6FED1  call 0xffffffff8ac69670    ; release [C+0x10]
8AD6FED6  mov qword [r14 + 0x10], 0
8AD6FEDE  mov rdi, r14
8AD6FEE8  call 0xffffffff8b5c8df0    ; free(C)
8AD6FEF5  mov qword [r12 + 0x18], 0  ; clear W->context
```

The null test at the top of that block only covers the **serialized** case: a delete that arrives
after `8AD6FEF5` has cleared `W->context` reads zero and writes statuses without freeing. Two deletes
that both reach `8AD6FEB7` before either writes zero at `8AD6FEF5` both call the decref and both call
`free(C)`.

That window is wide and unlocked. The entry lock is dropped at `8AD6FE67 call 0x8ad59eb0`; the
re-lookup at `8AD6FE7C call 0x8ad5a2a0` reads the slot again, and the decref plus free then run with
no lock held at all -- a decref call, a store, and a free call, several hundred nanoseconds of
window on a 16-core machine. So `523c`'s 54 double-`0` ids are consistent both with 54 real
duplicate frees and with 54 status-only losers; the status word cannot tell the two apart.

> **Measured outcome (see the 569a/570a/572a section):** the second caller exits through the
> status-only branch, so the overlap produces a duplicate `0` without a second free. The ordering
> below is what makes a second free *possible*, not what the console does.

`probes/phase17_new_vectors/568a_aio_alias_cycles.lua` discriminates by consequence: race two
helpers over the same ids, then run 40 create/poll/delete cycles and report any status outside `0` /
`0x80020003`. A duplicated chunk in that size class changes what the allocator hands back, which is
visible in the cycles even though it is invisible in the race statuses.

## The aio descriptor array is the caller-filled 48-byte allocation (2026-10-24)

A UAF of a 0x30 object is only useful if something can occupy the freed chunk with caller bytes.
Two scans of the 13.60 text (`tools/handler_alloc_map.py`, `tools/variable_alloc_scan.py`):

- 2348 calls to the kernel allocator `0xffffffff8b5c8b50`; 486 of them pass a constant size in
  `0x20..0x40`; of those, 4 have a copyin within 60 instructions. All four are false positives on
  inspection: `sys 601` copies into a stack buffer first (`copyin` at `0xca1733`, `[rbp-0xf0]`) and
  `sys 610`'s two 0x30 allocations are the name buffer of the `nmount`-style record builder, which
  receives the copied bytes, not the record itself.
- 11 variable-size allocations have a copyin nearby. `sys 587` reaches the heap only for lengths of
  `0x81` and above (`cmp r12d, 0x81; jb <stack buffer>`), so it cannot hand back a 0x30 chunk;
  `sys 603` and `sys 652` copy `count * 0x50` records into a buffer sized by a separate field;
  `sys 601` is the stack case above.

Those scans answer "which *other* syscalls keep caller bytes in a 0x30 chunk", and the answer is
none. They miss the surface the race already owns: `669` allocates
`D = malloc(count*0x28)` (`lea r13d,[rax+rax*4]` on `count*8` at `0x8ad721ed`, file offset `0x3b21ed`)
and copies the caller's `count*0x28` descriptor bytes into it verbatim (`copyin` `0x8ac19280` at
`0x8ad7221c`). With `count` 1 that is a 40-byte request, which a 48-byte size class serves, and the
same create call takes `T = malloc(0x30)` and `C = malloc(0x30)` from that same class.

So the reclaim primitive exists inside the family. After one duplicate free in the 48-byte class, a
later create can land `C1 == D2`: the descriptor bytes written for object 2 become the context of
object 1, still referenced by object 1's work item. The delete of object 1 then reads `[C+0x10]`,
which is descriptor offset `0x10` -- the **buffer** field -- and passes it to `0x8ac69670`, whose body
is `lock xadd dword [rdi], -1` plus, when the old value was 1, a free chain over `+0x20..+0x38` and
`+0x118`. That is a caller-addressed 4-byte decrement reachable from a caller-controlled field.

Not established: that the allocator actually duplicates the chunk after the race (568a answers
this), and that `C1 == D2` can be forced rather than left to allocation order.

## The state gate passes at runtime: aio submits real I/O (2026-10-24)

`503a_aio_out_record.lua` put a distinct canary page in the 4th, 5th and 6th argument
of `662` while deleting two completed ids. Every call returned `0` with both per-id
statuses `0`, and **no argument page changed** - so the delete never wrote a
per-id record.

The 13.60 delete body explains why. At offset `0x3afae9` it calls `0x8b4c78d0`
before allocating anything:

```
0x8b4c78d4: mov ecx, [rip + 0xddcb92]      ; global at 0xffffffff8c2a446c
0x8b4c78df: cmp ecx, 3   / je  -> return 1
0x8b4c78ec: cmp ecx, 4   / sete -> return 1
```

Only when that returns 1 does the body `malloc(count*0x18)` at `0x3afb12`, fill one
record per id at `0x3afd43`-`0x3afd6d`

```
out[3*i+0x00] = status
out[3*i+0x08] = [[slot+0x18]]        ; = [C], and [C] = [[gs:[0]]+0x390]
out[3*i+0x10] = ([slot+0x10]>>4) ^ [slot+0x10]   ; mangled descriptor-array pointer
```

and copy it to the user pointer in `[uap+0x68]` at `0x3b0141` (`copyout`, `0x8aa63960`).
The same helper gates the create's submit at `0x3b249c`.

**The gate returns 1 on 14.10.** `566b_aio_read_baseline.lua` reads `/dev/urandom` with the
descriptor layout `offset@0x00`, `len@0x08`, `buffer@0x10`, `result@0x18`, `fd@0x20`: the bytes land
in the caller buffer, the count lands in `result`, and the first poll reports `3`. The earlier
"create never submits" result was a probe defect -- `500a`/`500b` and `566a` used the wrong field
order, so the fd or length the kernel read was invalid and every request failed validation before it
could complete.

A byte scan of the whole captured 13.60 text found 17 references to
`0xffffffff8c2a446c` and **all of them are reads, `lea`s or jump-table bases inside
the aio module** (`0xffffffff8b4c6b00`-`0xffffffff8b4c79c0`); nothing in the captured
range writes it. Its accessors return `state == 1..6`
(`0x8b4c7926` state 2, `0x8b4c7940` state 5, `0x8b4c7960` state 6, ...), and the
handler at `0xffffffff8b4c7980` passes `&state` plus a zero to `0x8ac309e8`, the
shape of `sysctl_handle_int(oidp, &var, 0, req)`. In other words the aio state is a
**boot-time tunable exposed as a sysctl**, not a per-process field.

Consequences for 14.10, measured:

- create allocates and submits; the request runs in kernel context, so a socket read completes when
  the peer writes, without another poll (`566f`);
- poll reports `3` for a completed object and `0x10003` for a later poll of the same object;
- delete accepts state 3 or 4 and refuses a pending object with `0x80020010` (`566f`);
- the `count*0x18` record array is allocated whenever the gate returns 1, which it does here; `503a`
  simply passed its canary pages through argument slots the body does not read.

Both reads of the global use the same displacement target, `0xffffffff8c2a446c` (`[rip+0xddcb92]`
from `0x8b4c78d4` and `[rip+0xddcb82]` from `0x8b4c78e4` both resolve there), so there is one state
word and it is 3 or 4 on this console.

Not established: what sets that word (nothing in the captured text writes it), and whether its value
is fixed for the boot or varies per process.

### The concurrent second delete takes the status-only branch, it does not free (probes 572a, 2026-10-24)

`572a` reproduced the setup with a 32-id block and two helpers: `ids with two successes=0`, i.e.
every id received exactly one `0` and one `0x80020003`. The same probe's six 8-item blocks after the
race were clean in every round (`zeros=8 gone=0 other=0 second-zero=0`). Together with `568a`'s 40
clean cycles this fixes the ordering: the second caller resolves the slot while the first caller is
still inside the per-id path, reads a work item whose context is already zero, and exits through the
status-only branch at `8AD6FEC6`. The first caller then frees the work item and clears the slot, so
the second caller never touches freed memory and no duplicate free reaches the allocator.

That makes the double success a **benign duplicate status**, not a second free. The window is real
and the 14.20 generation check closes it, but on 14.10 the observable consequence is the extra `0`,
and the measured rate depends on how closely the two callers stay in step (100/100 for `568a`'s
100-id list, 0/32 for `572a`'s 32-id list) rather than on any memory effect.

For a second free to happen the second caller would have to load `[W+0x18]` *after* the first frees
W, which requires arriving later than the free but before the slot clear - a window on the order of
one function call, and no measured run has produced it.

## A second delete is refused unless it runs concurrently (probes 569a, 570a, 568a, 2026-10-24)

The serial control is exact at every block size:

| probe | object | first delete | second delete |
|---|---|---|---|
| `569a` | block create `count=4` | `0` / `00000000` | `0` / `80020003` |
| `570a` pair A | block create `count=2` | `0` / `00000000` | `0` / `80020003` |
| `570a` pair B | block create `count=4`, item1 | `0` / `00000000` | `0` / `80020003` |

So the slot does not linger after a delete: one caller repeating an id always gets
`0x80020003`. The double success therefore needs two callers inside the same per-id
iteration. `568a` supplied exactly that: it created **100 separate single-item objects**
(`669(1, REQ, 1, 1, ID)` in a loop, not one block), then ran two
`run_lua_code_in_new_thread` helpers, each issuing `662(ids, 1, status)` over the same
100 id array, and both status pages came back all zeros -- **100 of 100 ids reported
`0` in both helpers**.

The mechanism that fits both results is the ordering inside the delete body: the entry
re-lookup at `8AD6FE7C` succeeds while the first caller has already cleared
`[W+0x18]` at `8AD6FEF5` but not yet cleared the slot, so the second caller finds the
id still resolvable and reads a cleared context, which is the status-only branch. The
window between the context clear and the slot clear spans the work-item free loop, and
two threads walking the same array at the same rate enter it on every id.

What is *not* established: that the second caller ever passes the null test at
`8AD6FEC3` in these runs. A status-only second delete leaves the allocator untouched,
which is exactly what `568a`'s 40 subsequent create/poll/delete cycles showed
(`anomalies=0`: every poll reached `3`, every delete returned `0`, every repeat
returned `0x80020003`). If a duplicate free had happened, at least one of the 40
creates would have had its descriptor array and its context in the same chunk and
would have failed to complete.

## A 16-item block create kills the process (probe 570a, 2026-10-24)

`570a` walked block sizes 2, 4, 16, 100 with 16 KiB of descriptor page available:
`n=2` and `n=4` printed clean, and the process died inside case `C` (`n=16`) after 16
`664` polls of the 16 ids. The capture ends mid-line with binary bytes and the loader
refused further connections.

`568a` did **not** create a block: its 100 ids came from 100 single-item creates
(`count=1`, flags `1`), so the comparison is between two different kernel paths, not two
sizes. What survives both runs is the narrower statement: the **block path**
(`flags=0x1001`, `count>1`) has died at `count=16` and at `count=64`, while the
single-item path is stable at 100 objects. Not established: whether the kill comes from the create, the poll loop, or a
descriptor of one of the 16 items, and whether the `n=100` create survived only because
its polls ran one at a time over a longer period.

## The delete is item-refcounted, so the context is freed exactly once (2026-10-24)

> **Scope correction.** The refcounting below is real and explains the serialized probes: deleting
> item 0 of a multi-item object frees only that item, and a later delete of another item does not
> touch `C`. It does **not** make the context single-free under concurrency. The entry lock is
> dropped at `8AD6FE67` and the free runs unlocked from `8AD6FEB7`, so two deletes of the *same*
> item can both pass the null test and both free `C`. See "The free runs unlocked".

The earlier model in this document said every item of one `669` object shares the
context `C = [W+0x18]`, so deleting any item would free `C` and two deletes would
double-free it. That model is wrong, and the probes that were built on it
(`504b`, `504c`, `507a`, `508a`) are clean for a reason:

| probe | shape | result |
|---|---|---|
| `504b_aio_reclaim_ctx.lua` | create count=4, delete item0, create a filler with `D[0x10]=0`, delete item1, poll/delete the filler, delete items 2-3 | every call `ret=0`, status `0`, filler healthy, no crash |
| `504c_aio_decrement_probe.lua` | same, `D[0x10]` = a mapped page holding `0x41414141`, three fillers, delete item1 | canary reads `41414141`/`deadbeef` before and after: untouched |
| `507a_aio_fill_zone.lua` | create count=2, delete item0, 200 filler creates with `D[0x10]` = canary page, delete item1 | canary untouched |
| `508a_aio_filler_health.lua` | same as `507a` but the 200 fillers are polled and deleted afterwards | `polled ok=200 other=0`, `deletes clean=200 bad=0` |

The 13.60 delete body explains it. The word at `[obj+2]` is the object's **item
count**, not a generation:

- the first lookup validates `index < word [obj]` only;
- `0x3afd76` tests the *item's* state (`[S+8]`), not the object's;
- `0x3afea3` then branches on `movzx r8d, word [obj+2]; cmp r8w, 1; jne 0x3affbc`;
- `0x3affbc` is the per-item path:

  ```
  0x3affcd: dec  r8d
  0x3affd0: mov  word [rax+2], r8w      ; remaining items -= 1
  0x3affd5: cmp  qword [r12+0x20], 0
  0x3affdd: (if set) free the item's S
  0x3affef: call 0x8ad73e90             ; free the item W
  0x3afff7: mov  [P + index*8], 0       ; clear the slot
  ```

  No context free on this path.
- `0x3afea3`-`0x3afef5` is the **last-item** path (`[obj+2] == 1`): it reads
  `[W+0x18]` = `C`, releases `[C+0x10]` through `0x8ac69670`, zeroes it, frees
  `C` at `0x3afee8`, then frees the item.

So `C` is released once, when the last item is deleted, and the object is gone from
the table afterwards; a second delete of the same id returns `0x80020003` and
touches nothing. Serialized deletes cannot double-free, which matches `498a`
(pass 0 all `0`, pass 1 all `0x80020003`) and `497f`.

The race that the 14.20 note describes is still real - the second lookup at
`0x3afe6c` runs after the unlock at `0x3afe63`, so a *racing thread* can replace
the slot between the two lookups - but winning it needs the slot's object to be
replaced with an object whose `[obj+2]` is 1, and the free then targets `C`, a
`0x30` kernel-initialised context.

### The harness cannot run two syscalls at once (2026-10-24)

All of the race probes above were written on single-threaded timing control, so
the concurrency question had to be measured:

| measurement | value |
|---|---|
| one `getpid` through the loader's Lua path | **21.4 us** (`509a`: 20 000 calls in 428 893 us) |
| helper Lua thread, aio cycles per second | 4-11 after a ~7.8 s startup (`506a`-`506c`) |
| helper thread issuing `getpid` while the parent bursts | process dies within ~50 ms, before the first 2 000-call sample prints (`509b`) |

The loader builds one ROP chain per Lua state but serialises every call through a
shared path: a parent blocked in `nanosleep` starves the helper (`506b`/`506c`),
and a parent that keeps issuing syscalls kills the process as soon as a second
thread joins in (`509a`/`509b`). At 21.4 us per call and no parallelism, the
TOC-TOU window between `0x3afe63` and `0x3afe6c` (tens of nanoseconds) is not
reachable from Lua.

A raw syscall engine was attempted instead - `thr_create(430)` gives a child
thread with a controlled RIP, RSP and registers, which `510a` used to run a ROP
loop - but the eboot text map has no `syscall; ret` sequence in its first 4 MB
(`510b`: twelve `0F 05` bytes, all inside data), so the chain had no way back into
the kernel and was abandoned before a thread was created.

**Status of the aio family, corrected 2026-10-24:** create/poll/delete work and real I/O runs
(`566b`/`566f`). The context free is refcounted *serially* but not under concurrency: the free block
runs after the entry lock is dropped, so a duplicate free in the 48-byte class is reachable
(`523c`, and `568a` for the allocator consequence). The descriptor array `D = malloc(count*0x28)` is
caller-filled and lands in that same class, so the family carries its own reclaim primitive. What is
not yet established is that the duplicate free actually happens in a given race and that `C1 == D2`
can be forced.

## mdbg 601 commands 03 and 04 are lethal (2026-10-24)

With the corrected call shape `601(cmd, ptr, 0)` and a zeroed mapped 0x1000 page as `ptr`
(`567a`, then `.local/sweep601.py` running one command per connection):

| cmd | result |
|---|---|
| `00` | `ret=0`, `page[0]=0x100`, nothing else written |
| `01`, `02` | `ret=-1` |
| `03` | process dies; the loader dies with it |
| `04` | process dies inside the call; loader refused afterwards |

Each lethal command takes the whole game process, so the remaining commands `05`-`0x27`
can only be covered one relaunch at a time.

## Where the block crash comes from (probes 576a, 577a, 2026-10-24)

`576a` created pending socketpair reads in blocks of 8, 16 and 32 inside one process:
all three creates returned `0` (`base=00004205`, `00000206`, `00000207`), a single poll per
object read `2` then `1`, the full poll loops read `1` for every id, and the process
stayed alive. So **the create and the poll do not kill anything**: the earlier deaths at
`count=16` and `count=64` used `/dev/urandom`, whose reads complete immediately, so what
distinguishes them is the **completion** of many items at once.

`577a` tried to drive that on purpose (create pending reads, then feed the peer in one
shot) and instead exposed a harness fact: the FreeBSD numbers here are `3 = read` and
`4 = write`, so the first version called `read` on the empty peer and wedged the single
Lua thread in a blocking read (`IDLE_TIMEOUT`, then no answer to `PING-OK`; a game
relaunch is required). The probe now writes with `4`.

Pending states are `1` on this firmware for an unsubmitted/socketpait read; `2` is the
state `566f` saw for a pending socket read, and `3`/`0x10003` are the completed states.
### The block path is stable: the earlier kills were not a size threshold (probes 576a-578a, 2026-10-24)

Four controlled runs with one process each, all `alive=true` at the end:

| probe | shape | result |
|---|---|---|
| `576a` | block create 8 / 16 / 32 on a socketpair, no completions | all `ret=0`; polls read `1` (pending) |
| `577a` | same block, then the peer is fed so every read completes | all `3` for 8, 16 and 32 |
| `578a` | peer preloaded, so reads complete inside `669` | all `3` for 8, 16 and 32 |
| `574a` rerun | `/dev/urandom`, `count=64`, polled in blocks of 8 | all 64 read `3` |

So neither the create, the poll, the completion storm nor a completion that lands inside the
create kills anything at these sizes, and `570a`'s `count=16` death and `571a`/`574a`'s
`count=64` death did not reproduce on a fresh process. Those two captures are therefore
probe-local, not a block-size limit, and the "16-item block create kills the process"
heading above should be read as an unexplained one-off.

Pending states on 14.10: `1` for a socketpair read that the kernel has not started, `2` for
one in flight, `3` and `0x10003` for completed.

## Two threads now reach the delete at the same time (probes 633c/635a, 2026-10-24)

The harness limit recorded in PR #151 was a property of `thr_new` children, not of
the loader: the payload's own `thread` class drives a ROP chain per thread, and
two of them can issue syscalls concurrently (`631a`). Wrapping each delete chain
in a `_umtx_op` wait and releasing both with one wake removes the spawn jitter:

```
[A] create rv=0x0 base=16901     [B] polled=8/8
[C] chains built                 [D] wake rv=0x0
[F] A zeros=4 B zeros=7 both=3
[G] 0:0/0 1:2147614723/0 2:2147614723/0 3:2147614723/0
    4:0/0 5:0/2147614723 6:0/0 7:2147614723/0
[H] alive=356
```

`both=3` means three ids returned status `0` to *both* threads. Serially that
never happens (`498a`: the second caller always gets `0x80020003`), so the two
calls really were inside the delete path together.

### The free is unconditional, so the window is real

Re-read at `0x8ad6fea3`-`0x8ad6fef5` (base `0xffffffff8a9c0000`):

```
3afea3  cmp  r8w, 1
3afea8  jne  0x3affbc            ; count > 1 -> multi-item branch
3afeb7  mov  r14, [r12+0x18]     ; C = slot->ctx
3afec3  test r14, r14
3afec6  je   0x3afefe            ; C already gone -> status-only, returns 0
3afed1  call 0x8ac69670          ; refcount dec of C->[0x10], may free that object
3afed6  mov  qword [r14+0x10], 0
3afee8  call 0x8b5c8df0          ; free(C)  -- unconditional once C != 0
3afef5  mov  qword [r12+0x18], 0 ; the clear
```

The refcount protects `C->[0x10]`, not `C`. A second caller that reads
`[r12+0x18]` before `0x3afef5` frees the same `0x30` chunk again. The window
spans a full `free()` call, not ten instructions.

### `both=0` is still not proof

`635a` repeated the race and then ran 16 create/poll/delete cycles:
`both=3`, **`health bad=0`**, alive. A double free of one chunk with no
allocation in between leaves a self-referential freelist, and the two following
`malloc(0x30)` calls return the same chunk; the two `0x30` allocations in one
create (`T` and `C`) would then alias, and the next delete would walk the wrong
object. That never happened, so the observed `both=0` cases most likely exited
through `0x3afec6` - the second caller read the slot after the clear.

To force the read *before* the clear, the two threads have to be offset by the
length of the free path rather than released simultaneously. `633d` (32 ids in
one block) and `633b` crash inside the create, so the next attempt creates
single-count objects, which are stable up to 200 (`612a`), and pairs a
`nanosleep` in one chain with a sweep of the offset.

## The status array is zeroed before each item (2026-10-24)

Every `both=0` table above was measured with a status array pre-filled with
`0x77777777`, so a `0` looked like a status the handler had written. It is not.
At `0x8ad6fbae` the delete loop stores zero into the caller's status slot before
it does anything else:

```
8ad6fbaa  mov   r15d, [rsi+r13*4]      ; id
8ad6fbae  mov   dword [rdx+r13*4], 0   ; <-- status := 0, unconditionally
8ad6fbb6  mov   r14d, r15d / sar r14d, 0x10 / and r15d, 0xffff
8ad6fbc8  cmp   r14d, 0x80 / setb cl   ; generation range
8ad6fbd5  je    0x8ad6fb90             ; out of range -> 0x80020003 at 0x8ad6fb90
```

Only failures overwrite it: `0x80020003` at `0x8ad6fb90` and `0x8ad6fbe1`,
`0x80020010` at `0x8ad6fdd4` and `0x8ad6fe0a`. The multi-item branch
(`0x8ad6ffbc`-`0x8ad7000f`) writes no status at all, so a successful
multi-item delete and an item that was never looked at both read `0`.

Consequences:

- `498a` (serialised double pass), `568a`, `524b`, `525a`, `525b`, `633c`,
  `635a`, `640a`, `641a`, `642a`, `671a` and `672a` cannot show that a second
  caller completed a delete. Their `0` rows are the default value.
- The rows that do carry information are the non-zero ones: a second delete of
  the same id in the same call returns `0x80020003` (`498a` pass 1,
  `489c` `[1]=0x80020003`), and an unpolled object returns `0x80020010`
  (`642a` first run, `672a` four refusals).
- The double status reported in the 2026-10-23 section of this file is
  withdrawn, and PR #151 (`research/aio-race-harness-limit`) already publishes
  that retraction.

### The two windows the disassembly actually leaves open

1. **Same work item freed twice.** `W = P[index]` is read at `0x8ad6fe9f`,
   after the bucket lock is dropped at `0x8ad6fe67`. `free(W)` happens at
   `0x8ad6fff2` and `P[index]` is cleared only at `0x8ad70003`. A second caller
   that reads `P[index]` in that span frees the same `0x58` chunk twice.
2. **The entry count read is outside the lock.** Both callers read
   `movzx r8d, word [rax+2]` at `0x8ad6fe92` after the unlock, and the
   decrement is written at `0x8ad6ffd0`. When both read `1` - a one-item entry,
   or the last item of a two-item entry - both take the single path and free
   `S`, `D`, `P` and `T` (`0x8ad700a3`, `0x8ad700b4`, `0x8ad700c8`,
   `0x8ad700d3`).

### The double free does not reach userland (probe 674a)

`probes/phase17_new_vectors/674a_aio_alias_detect2.lua` races two chains over
16 two-item entries, then creates 12 fresh two-item entries and drives them one
item at a time:

```
[A] blocks=16
[B] polled=32/32
[C] both-zero items=22 of 32
[D] fresh blocks=12
[E] fresh blocks ready=12 of 12
[G] anomalies=0
[H] canary create=ok
[Z] alive=468
```

If `S` had been handed out twice, one of the fresh entries would have polled a
state of `1` (a `W+0x20` pointing at itself) or lost its sibling early; both
tests are silent. `probes/phase17_new_vectors/671b_nonblock_burst_control.lua`
is the control that shows the same burst shape is clean without the race.

What this establishes and what it does not:

- established: the delete path reads the status slot to zero, the two windows
  above exist in the 13.60 body, and no userland-visible aliasing followed a
  race that processed 22 of 32 items twice;
- not established: that the double free happens at all on 14.10, because every
  field the handler writes is kernel-owned and there is no kernel read to
  distinguish "duplicate chunk" from "allocator tolerated it";
- not established: any route from a duplicate `0x58` or `0x30` chunk to a
  controlled value. The only user bytes that land in kernel memory are the
  `count*0x28` descriptor array, and its size class does not intersect the
  `0x58`/`0x30` classes the race frees.

## The double status is a lie, and the allocator proves it (probe 707a, 2026-10-25)

The delete body zeroes `status[i]` at the top of every loop iteration (`0x8ad6fbae`), so a
code path that writes nothing still reads as success. The TOCTOU branch unlocks at
`0x8ad6fe63` and re-looks-up at `0x8ad6fe7c`, but the second lookup re-takes the same table
lock and rebuilds the stored id as `(generation << 13) | slot` before comparing it with the
requested id (`0x8ad5a36b`-`0x8ad5a37b`, identical to the first lookup at `0x8ad59fc8`). A
re-used slot is therefore rejected, the miss path writes 0 at `0x8ad6ffab`, and the iteration
moves on without freeing anything.

Probe `707a_aio_alias_after_race.lua` turns that into a measurement. Two native children
delete the same four ids at once, the status pages pre-filled with `0x77777777` so a written
zero cannot be confused with an untouched page; both children then return to the parent,
which immediately runs eight create/poll/delete pairs.

| run | both-zero ids | post-race pairs | anomalies |
|---|---|---|---|
| reversed iteration (children meet in the middle) | 0 | 8, every delete `0` | 0 |
| same iteration order | **1** (id 3) | 8, every delete `0` | 0 |

A real double free would put the same chunk in the allocator's free list twice, and the next
create would hand it to two different objects, so the second delete of a pair would stop
answering `0`. Eight pairs, forty allocations in the affected size classes, no anomaly, and
the ids keep advancing by `0x2000` per create (the generation stepping cleanly) - the table
and the heap are both intact.

Conclusion: on 14.10 the racing delete produces a **status lie**, not a second free. The
pre-fix shape the 14.20 note describes is present (unlock, re-lookup, free), but two
properties keep it inert here - the re-lookup re-validates the generation, and a miss reports
success without freeing. `633c`'s `both = 3` rows are that miss, and the earlier "54 of 100
deletes succeeded twice" reading is withdrawn.

## Block creates take a delete path with no context guard, and the race still leaves the allocator clean (727a-728a, 2026-10-25)

A non-block create sets the entry counts to 1, so every delete of it takes the count==1 path A
at `8ad6feae`, where the `[W+0x18]` context guard stops a second caller. A block create
(`flags 0x1001`) stores `count` in **both** words, so every delete of a block item takes path B
at `8ad6ffbc` instead:

```
8ad6fe92  movzx r8d, word [rax+2]      ; remaining items in the entry
8ad6fea3  cmp r8w, 1 / jne 8ad6ffbc    ; path A only when exactly one remains
8ad6ffc4  test r12, r12 / je 8ad6fb9b  ; path B: "slot still present"
8ad6ffcd  dec r8d
8ad6ffd0  mov word [rax+2], r8w
8ad6ffe1  call 0x8b5b1760              ; destroy the item's event
8ad6fff2  call 0x8ad73e90              ; free(W)  -- unconditional
8ad70003  mov qword [rcx+rdx*8], 0     ; clear the slot, AFTER the free
```

Path B has no context guard at all, and it clears the slot only after the free, so a caller that
captured its work item before that free would free the same 0x58 chunk. The measurements say the
second caller never gets there:

| probe | shape | result |
|---|---|---|
| `727b` | serial block delete of all 8 ids, no threads | all 8 statuses `0`, health clean, alive |
| `727d` | two children, **different** ids of one block | both `0`, walk `80020003` then `00010003` ×6, seven deletes `0`, health clean |
| `727c` | two children, **same** id | both `0`, walk all `00010003`, all `0`, health clean |
| `727a` | **8 children**, same id, 10 rounds | every round exactly two `0` and six `80020003`; walk clean 10/10; health clean |
| `728a` | 8 children + allocator alias detector, 6 rounds | `zeros=2` every round, **anomalies 0**, alive |

`728a`'s detector creates two non-block objects after the race, polls each once, deletes both, and
flags any poll that is not `3` or any delete that is not `0`. A real double free would leave two
live entries sharing one chunk, and the second poll or delete would show it. None did.

The six `80020003` in each round fail at the *first* lookup, and the second `0` is a caller that
passed the first lookup and reported success from a later branch. Two properties of 14.10 make that
indistinguishable from a real delete: the status array is zeroed at the top of every iteration
(`8ad6fbae`), and the miss path writes 0 (`8ad6ffab`).

**Consequence for block creates, independent of the race:** path A is the only path that frees `S`,
`P` and `T`, and it is gated on `cmp word [r8],1` where `r8 = T` and `[T]` is the *create* count.
A block create stores `count` there, so a block entry can never reach path A: every block create
leaks `0x58*count` (S), `8*count` (P) and `0x30` (T) for the lifetime of the process. `727a`'s ten
rounds leaked about 0x6000 bytes and nothing observable changed.

## 557 and 558 are a create/destroy pair with a 32-byte user payload (2026-10-25)

`779a` swept the low Sony range with four buffer shapes per number. Only 557
answered: `557(ptr, 0x1000)` returned `16901` (`0x4205`), the same id shape the
aio family hands out. The static decode (`results/kernel_handlers/asm/sys_557.asm`,
body at RVA `0xac7240`, base `0xffffffff8a9c0000`) explains why:

- `uap[0]` must be non-zero and is a user pointer (`cmp qword [rsi],0` / `jz`
  to the `eax=0x16` EINVAL path).
- the table is per process, `[td->td_proc + 0xc48]`; the id comes from
  `0x3998e0`, the allocator aio uses, so the two families share a counter but
  not a table.
- `malloc(0x20)` then `copyin(uap[0], payload, 0x20)`: **32 user bytes land in a
  kernel allocation**. A copyin failure frees the payload and returns the error.
- a `0x18` wrapper `{[0]=payload, [8]=uap[1]}` is registered with
  `0x399de0(id, flags, wrapper, payload)`, `uap[2]` is OR'd with `0x1000` into
  the flags, the aio state predicate `0xb078d0` gates a call to `0x1189d0`, and
  the id is stored to `[td+0x408]`.
- 558 (RVA `0xac73c0`) looks the id up (`0x39a2a0`), removes it (`0x399e30`),
  frees `[entry]` and then `entry`.

Measurements:

| probe | shape | result |
|---|---|---|
| `780a` | sizes `0x10`/`0x100`/`0x8000` | all accepted, ids 519-521 |
| `780a` | aio create right after | id `0x20D`, counter is shared |
| `780a` | `662`/`664` on a 557 id | `0x80020003`, different table |
| `781a` | `uap[0]` = `0` or `0x10000` | `-1` |
| `783a` | `558` over `0x207`-`0x225` | 13 hits; the aio id `0x20D` is **not** one |
| `784a` | payload zeros / all-`0xFF` / mixed | `16901` / `518` / `519`, no crash |
| `787a` | our page in each of the four qwords | page never written |
| `787b` | dword markers over the page | 0 changed dwords |
| `788a` | payload read back after create | unchanged, no writeback |
| `789a` | 0xFF payload freed immediately | family healthy, no stall |
| `790a` | `558` on the same id five times | `0`, then `-1` four times |
| `791a` | flags `0`..`0x10000` (12 values) x zero/all-`0xFF` payload | every create a fresh id, every destroy `0`; no value selects anything |

The flags word (`uap[2]`, OR'd with `0x1000`) is likewise inert: twelve
values including both payload shapes created and destroyed cleanly (`791a`).

So the 32 bytes are copied in and never interpreted: a payload of invalid
pointers does not fault, a payload of our own pointers never receives a write,
and the payload page is not modified. `558` is idempotent-safe, which rules out
a deterministic double free of the payload.

One operational note: after roughly fifteen creates with no destroys the family
answers `-1` for a while and then recovers on its own (`782a`, `785a`, `786a`).
That is congestion in the shared submit path, not a cap on the table - 786a
then created 32, destroyed 32, created 32 more and ran 40 create/destroy cycles
in one thread.

What it is worth: a reliable kernel allocation of `0x20` whose 32 bytes the
caller chooses, with a matching free and no other observable effect. That is
grooming, not a bug; it matters only if some freed object in that bucket is
still reachable, and no such path is known.

## The delete window is not reachable from userland (817a, 817b, 818a, 2026-10-26)

The 14.20 note describes the pre-fix path exactly: `aio_multi_delete` drops the
lock, a racing thread frees and reallocates the slot, and the delete then frees
sub-objects of the swapped object.  Everything up to that point reproduces
here.  What does not reproduce is a second caller arriving in time.

The guard is seven instructions.  From the 13.60 delete body (offset `0x3af920`,
base `0xffffffff8a9c0000`):

```
0xad6fe67  call 0x8ad59eb0          ; unlock
0xad6fe7c  call 0x8ad5a2a0          ; re-lookup (takes the lock again)
0xad6feb7  mov r14,[r12+0x18]       ; C from the work item
0xad6fec3  test r14,r14 / je        ; already-cleared test
0xad6fc8   mov rdi,[r14+0x10]       ; refcount page
0xad6fed1  call 0x8ac69670          ; lock xadd -1, release chain at zero
0xad6fee8  call 0x8b5c8df0          ; free C
0xad6fef5  mov qword [r12+0x18],0   ; window closes here
```

Two release mechanisms were measured against it, sixteen deleters aimed at a
single freshly polled id, six rounds each:

| probe | release | deleters | statuses of 16 | allocator after |
|---|---|---|---|---|
| `817a_aio_window_16.lua` | sixteen separate `write()`s, ~20 us apart | 16 | 1 zero, 15 `0x80020003` | 8 fresh objects, 0 anomalies |
| `817b_aio_shared_barrier.lua` | one `write()` of 16 bytes, all parked on the same fd | 16 | 1 zero, 15 `0x80020003` | 8 fresh objects, 0 anomalies |

`0x80020003` is the first lookup's miss code, so fifteen callers arrived after
the winner had already removed the entry.  Removing the release skew changed
nothing: the winner finishes its whole delete tens of microseconds before any
follower is scheduled, and the guard window is nanoseconds.

The re-lookup also refuses a swapped entry. `0x8ad5a2a0` rebuilds the stored id
as `(generation << 13) | slot` (`0xad5a36b`..`0xad5a376`) and compares it with
the requested id (`0xad5a378 cmp eax,r14d / jne miss`), then requires state 3
(`0xad5a384`) and type `0x160` (`0xad5a395`).  A slot can only carry the same id
again after eight create/delete cycles wrap the three-bit generation (probe
`561a`), which cannot happen inside the window.

The other candidate second halves are gated.  `664` frees `[uap+0x40]` only
behind the same boot tunable (`0x8b4c78d0` at `0x3b1586`), and `666`'s copyout
and free at `0x3b1dd4`-`0x3b1dde` sit behind it too.  Nothing else in the family
frees a work item.

`818a_aio_orphan_thread.lua` tested the one lifetime split that needs no race:
a helper thread creates an object and exits through `thr_exit(431)`, and the
Lua thread polls and deletes the orphan afterwards.  Sixteen rounds, sixteen
orphans, every delete `rv=0 status=0`, and an ordinary create/delete health
check after each round was clean.  The reference taken from the creating
thread's `gs:[0]+0x140` keeps whatever it points at alive.

Two automated audits over all 308 handler spans in the 13.60 table found
nothing either: `.local/malloc_copyin_precise.py` (allocation size against
`copyin` length, tracking the destination register) reported no case where the
copy exceeds the allocation, and `.local/free_then_use.py` (a freed register
read again before reassignment) reported no use-after-free.

Conclusion: the `aio_multi_delete` race is a real pre-14.20 defect and the local
disassembly matches the vendor description, but winning it from a CPL 3 thread
needs a second caller inside a seven-instruction window.  A thread pool,
a shared-barrier wake and a shared-object lifetime all fail by two orders of
magnitude, so this surface is closed for exploitation from the Lua loader even
though it is closed as a bug in 14.20.
