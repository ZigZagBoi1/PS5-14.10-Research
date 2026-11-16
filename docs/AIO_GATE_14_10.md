# AIO 662 lock-drop gate on 14.10: branch condition and open reachability

Status: **verified branch condition in one original 14.10 image; runtime reachability unresolved.** No kernel access is claimed. The tested native chain did not complete a high-volume race measurement. The static condition below does not establish that the lock-drop path is disabled on this firmware.

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


### Lock-drop condition in the original 14.10 image

The original `kernel_1410.elf` has SHA-256
`cc1572fcc91f27b7093a3a689b651c0cffeecbdd85dbf9a406a520fa8b945f0f`.
Its file-backed `PT_LOAD` maps analyzed VA `x` to original file offset
`x + 0x1000`. The relevant original bytes are:

| Analyzed VA | Original file offset | Bytes | Instruction |
| --- | --- | --- | --- |
| `0x3b8733` | `0x3b9733` | `83 79 04 00` | `cmp dword ptr [rcx+4], 0` |
| `0x3b8737` | `0x3b9737` | `0f 85 3e fd ff ff` | `jne 0x3b847b` |
| `0x3b873d` | `0x3b973d` | `80 79 0c 00` | `cmp byte ptr [rcx+0xc], 0` |
| `0x3b8741` | `0x3b9741` | `0f 84 34 fd ff ff` | `je 0x3b847b` |
| `0x3b874b` | `0x3b974b` | `e8 a0 9e fe ff` | `call 0x3a25f0` (lock release) |

Both branches bypass the release call: the `jne` is taken when `+4 != 0`,
and the `je` is taken when `+0xc == 0`. This path reaches the lock release
only when `+4 == 0` and `+0xc != 0`. The earlier excerpt from
`.local/del662.txt` describes the first branch with the opposite polarity.
That excerpt is not retained in this repository, so its image and branch
targets cannot be checked here.

This corrects the local branch interpretation. It does not establish that a
work item reaches the required state on a console. The boot-tunable claim,
work-item state producers, and the full handoff schedule require separate
verification against the same 14.10 image. The recorded race probes did not
observe a win; they do not establish that every possible handoff is unreachable.

Supporting measurement (`probes/phase17_new_vectors/886a_suspend_process.lua`,
capture `results/phase17_new_vectors/886a_suspend_process_20261027_134127.txt`): the
last candidate for forcing a second caller, `561 suspend_process`, kills the whole
process within milliseconds when called from a `thr_create` child (the parent never
reaches its first marker), so it cannot be used as a selective thread stop.

Consequence: the checked 14.10 bytes contain a conditional lock-release and
relookup path. They do not prove that the required state, timing, or shorter
replacement object occurs on a console, or that the path causes memory
corruption. The earlier conclusion that the boot tunable disables this entire
path is unresolved until its producer and runtime state are verified against
the same image.

## Live-thread measurements (2026-10-27)

Four probes from `probes/phase17_new_vectors/` characterize the tested harness
and inputs. They do not settle the reachability of every lock-release state.

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
are not cited here. What stands is the 911a measurement: its 20 rounds did not show two
successful deletes. It does not establish that no user-visible state can reach
the lock-release path.

## Submitted I/O was not observed in these probes

`926a`/`927a` point an aio read at `0xFFFFFFFF80000000` with the 4-byte payload
pre-queued on the socketpair. The **userland control never receives the bytes either**
(`[C2] poll st=1 buf0=0` with the write done before the submit), so no copyout happens
at all - and the kernel-address destination is therefore never dereferenced (the run is
COMPLETE, process alive). These runs show no copyout for the tested inputs. They do not establish that
all 14.10 submit paths are disabled or that `[W+4]` must be nonzero for the
lock release. The boot tunable and work-item state producers need
image-bound verification before calling the subsystem inert.

The aligned second result: `925a` frees an id, re-creates in the same slot and gets
`21C -> 221C`, and the stale id is refused (`80020003`). Generation validation is
present on 14.10, so the gen-ID check the 14.20 note calls new is not new here.
