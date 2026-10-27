# The aio delete window is gated off on 14.10, and the storm cannot be built

Status: **structural conclusion plus two harness results.** No kernel access is
claimed. This note closes the 14.10 aio line: the delete path the 14.20 build
patches does not open on this firmware, and the native chain that would have
measured the race cannot be made to loop with the gadgets this eboot offers.

---

## The last-item storm is not yet measured (882a, 2026-10-27)

The shape worth trying at high volume: a 2-item block with item0 deleted serially so
`[T+2] == 1`, then two native spinners looping `662(item1, 1, st)`. A create naming a dead
fd is state 3 at once (`873b`), so a round needs no socketpair and no waiter - the plan was
~1e5 rounds at spin rate.

`probes/phase17_new_vectors/882a_aio_last_item_storm.lua` died on its **first spinner
spawn**: the wire turned to the loader's context dump (`CS 0x43`, `SS 0x3B`, RFLAGS
`0x202001`, RIP in the heap `0x3110B3E18`), i.e. the child jumped to a heap address instead
of the chain. This is the third chain-plumbing failure in this shape (after the missing
`thr_exit` and the `jmp rax` stack walk), and it was not diagnosed before stopping.

Diagnosis of the second failure (same probe, guarded rerun `results/phase17_new_vectors/882a_aio_last_item_storm_20261027_000506.txt`): the mmap succeeded (`block=0x31073C000 start=0x31074BE00`), so the chain was well formed; the fault is the loop itself. A `thr_create` child calls the loader stub `fn` with `RSP` pointing into the chain, and the stub's own frame grows **down** from that point, overwriting the chain words just below - including `[start]`, the word the final `ret` uses to restart. A straight-line chain never reads those words again (which is why `881a` works 120/120), but a loop does, so iteration two returns into clobbered data (observed RIP `0x3110B3E18`, a heap address).

Looping a stub call therefore needs either a stack switch around the call (`mov rsp` / `xchg rsp` gadget, not found in eboot yet) or two interleaved chain copies far enough apart that one copy's frame cannot reach the other's head.

The fix attempted in `probes/phase17_new_vectors/883a_aio_storm_loop_fixed.lua` pads the chain 0x400 bytes between the argument setup and the call (so the stub frame cannot reach the head word) and calls through a `call rax` gadget (`FF D0`, found at eboot+0x75C11) instead of placing the stub address in the chain. That version still killed the process on spawn, and the reason was a plain mistake: `call rax` was reached with `RAX = 662` (the syscall number), so it jumped to address 662. The stub must be entered by falling through the chain; the most likely cause is that both spinners were looping on **id 0** (`slot 0` in the aio table may be the header), which the probe now avoids by seeding `0xFFFF`. It has not been run on a live process yet.

`883b` isolates the construction from the loop and settles the plumbing question: the same padded chain, straight-line, **runs 40/40 rounds without a death**, and the child's `662` reaches the kernel - the status word comes back `0x80020010`, the state gate, i.e. a real kernel answer rather than a fault. So a `thr_create` child can call the loader stub from a padded fall-through chain with `RSP` 0x400 above the head; only the `pop rsp` reset is unproven.

`884a` then tried to sidestep the reset by repeating the delete 500 times linearly (72 bytes per repetition) instead of looping. It produced ~1.2 MB of binary output and died, i.e. the long chain itself is a hazard (the child's `RSP` walks 36 KB up the chain and the stub frames write below it).

`885a` then added the debug channel itself: markers written through a `mov [rdi],rax; ret` gadget, `w[1]` set to that gadget as the loop re-entry, the stub at `w[138]` after a 64-entry pad, and markers `0x4D31` (after the delete) and `0x4D32` (after the reset). It printed only `[0] mov=[rdi],rax=<addr>` and then died, so the fault happens on the child's first pass and before the first marker; the parent's round print never ran. With `883b` proving the same padded chain completes when it is straight-line, the remaining difference is the entry word and the reset, and neither can be bisected further without output from a dying child.

So the statistical arm remains **unmeasured**, and the honest blocker is measurement quality: a faulting child produces a register dump and nothing else, so each hypothesis costs a relaunch and a guess. A working child would need a debug channel (for example the child writing phase markers into a mapped page that the parent prints afterwards) before further chain work is worth doing. The arithmetic that motivates it: two callers
must both pass the first lookup before either clears the slot, a span of ~7 instructions out
of roughly 3,000 per call, so the per-round odds are ~1e-4 and the 4,000 rounds of 872a were
three orders of magnitude short.


### Why no storm could ever have won: the lock drop itself is gated (2026-10-27)

The delete drops the table lock only when the work item is flagged as in flight. From
`.local/del662.txt`:

    8ad6fe4f  cmp dword ptr [rcx + 4], 0     ; the in-flight flag
    8ad6fe54  jne 8ad6fe5d                   ; clear -> stay under the lock
    8ad6fe59  cmp byte ptr [rcx + 0xc], 0    ; the poll flag
    8ad6fe5d  je  ...                        ; not polled -> same
    8ad6fe63  call 0x8ad59eb0                ; unlock, only on this path
    8ad6fe6c  ... re-lookup at 0x8ad5a2a0

`664` sets `[W+0xc]` (poll), but nothing reachable sets `[W+4]`: the submit path that
would is behind the boot tunable (`0x3b249c call 0x8b4c78d0`), and on 14.10 that gate
reads a boot-time tunable that never equals 3 or 4. So on this firmware a delete is an
under-lock teardown, and the TOCTOU window that 14.20 patches does not exist here at
all - the race was not "hard to win", it was unreachable, which is why 817a, 817b,
847a, 871a and 872a each produced exactly one winner and a set of first-lookup misses.

Supporting measurement (`probes/phase17_new_vectors/886a_suspend_process.lua`,
capture `results/phase17_new_vectors/886a_suspend_process_20261027_134127.txt`): the
last candidate for forcing a second caller, `561 suspend_process`, kills the whole
process within milliseconds when called from a `thr_create` child (the parent never
reaches its first marker), so it cannot be used as a selective thread stop.

Consequence: the public 14.20 note describes a real pre-fix shape, but on 14.10 the
shape is disabled by the same boot tunable that disables submit. Any 14.10 kernel
exploit in the wild is therefore **not** this bug, and this file should not be cited as
the 14.10 vector.

## Live-thread measurements (2026-10-27)

Four probes from `probes/phase17_new_vectors/` put the gate claim on measured ground
and settle the one barrier the race would need.

`910a_child_self_exit.lua` - a child chain that ends with `thr_exit` (`pop_rax; 431;
fn`) returns cleanly: `[T1]..[T10] spawn ok rv=0 out=50`, `[Z] spawned=10 alive pid=80`,
COMPLETE. Without that tail the ceiling is a budget, not a leak: `907a`/`908a` (no aio
at all, and with the `fcall_stub` removed) print six children and never the seventh,
because a `jmp_g` child never exits.

`911a_aio_race_exiting_children.lua` - 20 rounds of owner delete against a self-exiting
child delete on the same ids: the owner wins 19 (`errs=0,0`), the child gets
`80020003,80020003`, one round the child wins. No round has both sides at `0`, and the
process is alive at the end.

`912a_aio_delete_storm.lua` - 8 passes x 8 ids with both sides deleting: the child
reports `zeros=0 busy=0 esrch=64`, the parent `zeros=8`. The child runs entirely after
the parent, so `thr_create` returns before the child's first instruction and the parent
cannot sleep and delete at the same moment.

`919a_sys663_returns.lua` - the wait syscall rejects every shape: `(ids,N,out,1e6)`,
`(ids,N,out,0)`, `(ids,N,out)`, `(ids,0,out,1e6)`, `(out,N,ids,1e6)` and the same call
after `666` all return `-1`, with the status buffer untouched; `918a` adds that the call
returns instantly rather than blocking, and closing the socketpair does not complete the
operations either (delete after close still `80020010`). **Withdrawal:** the earlier
reading that a waiter reaps the object before a delete can reach it (`915a`/`916a`/
`917a`) rested on a `663` call that was failing immediately; those captures are void and
are not cited here. What stands is the static gate plus 911a: no user-visible path holds
a completed operation while two threads delete it.

## The subsystem is inert, not just race-free

`926a`/`927a` point an aio read at `0xFFFFFFFF80000000` with the 4-byte payload
pre-queued on the socketpair. The **userland control never receives the bytes either**
(`[C2] poll st=1 buf0=0` with the write done before the submit), so no copyout happens
at all - and the kernel-address destination is therefore never dereferenced (the run is
COMPLETE, process alive). Taken with the static gate, the reading is that on 14.10 the
aio submit path is disabled by the same boot tunable that would set `[W+4]`: objects are
created, states move, deletes are refused or accepted, and no I/O is ever dispatched.
The family is bookkeeping, which is why every race probe returned exactly one winner.

The aligned second result: `925a` frees an id, re-creates in the same slot and gets
`21C -> 221C`, and the stale id is refused (`80020003`). Generation validation is
present on 14.10, so the gen-ID check the 14.20 note calls new is not new here.
